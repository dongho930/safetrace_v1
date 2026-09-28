"""판단 모델 공급자. 모두 '텍스트 상태 + 선택지 → 선택·확률' 인터페이스를 따른다.

- JevProvider: TypeSafe System One API(POST /v1/systemone) 또는 OpenRouter 경유
- RuleProvider: 외부 호출 없는 규칙 기반 판단기(장애 대비·오프라인 개발용)

응답은 반드시 스키마 검증을 거친다. 제시하지 않은 선택지, 누락된 확률, 형식 오류는 모두 실패로 처리한다.
"""

from __future__ import annotations

import json
import re
import time
from typing import Protocol

import httpx

from ..masking import mask_pii


class ProviderError(Exception):
    pass


class ChoiceResult:
    def __init__(self, choice: str, probabilities: dict[str, float], confidence: float | None, model: str):
        self.choice = choice
        self.probabilities = probabilities
        self.confidence = confidence
        self.model = model


class Provider(Protocol):
    name: str

    def choose(self, state: dict, question: str, options: dict[str, str]) -> ChoiceResult: ...


def validate_choice(raw: dict, options: dict[str, str]) -> ChoiceResult:
    """Jev choice 응답을 검증한다. 형식: {"type":"choice","choice":k,"probabilities":{..},"confidence":x}"""
    if not isinstance(raw, dict) or raw.get("type") != "choice":
        raise ProviderError("answer is not a choice")
    choice = raw.get("choice")
    probs = raw.get("probabilities")
    if choice not in options:
        raise ProviderError("choice outside offered options")
    if not isinstance(probs, dict) or not probs:
        raise ProviderError("missing probabilities")
    clean: dict[str, float] = {}
    for k, v in probs.items():
        if k not in options or not isinstance(v, (int, float)) or not 0.0 <= float(v) <= 1.0:
            raise ProviderError("invalid probability entry")
        clean[k] = float(v)
    conf = raw.get("confidence")
    if conf is not None and (not isinstance(conf, (int, float)) or not 0.0 <= float(conf) <= 1.0):
        raise ProviderError("invalid confidence")
    return ChoiceResult(choice, clean, None if conf is None else float(conf), "")


class JevProvider:
    """TypeSafe Jev System One API 호출. 문서: https://docs.typesafe.ai/api.md

    OpenRouter 경로는 같은 요청 형식을 /v1/systemone 으로 받는다(모델 id만 다름).
    """

    MAX_OPTIONS = 255

    def __init__(self, name: str, base_url: str, api_key: str, model: str, timeout_s: float,
                 transport: httpx.BaseTransport | None = None):
        if not api_key:
            raise ProviderError(f"{name}: api key not configured")
        self.name = name
        self.model = model
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=httpx.Timeout(timeout_s),
            transport=transport,
            follow_redirects=False,
        )

    def choose(self, state: dict, question: str, options: dict[str, str]) -> ChoiceResult:
        if not 2 <= len(options) <= self.MAX_OPTIONS:
            raise ProviderError("option count out of range")
        body = {
            "model": self.model,
            "state": state,
            "questions": {"q": {"type": "choice", "instructions": question, "criteria": options}},
        }
        try:
            r = self._client.post("/v1/systemone", content=json.dumps(body, ensure_ascii=False).encode())
        except httpx.HTTPError as e:
            raise ProviderError(f"{self.name}: transport error {type(e).__name__}") from e
        if r.status_code != 200:
            raise ProviderError(f"{self.name}: http {r.status_code}")
        try:
            data = r.json()
            answer = data["answers"]["q"]
            model = str(data.get("model", self.model))[:64]
        except (ValueError, KeyError, TypeError) as e:
            raise ProviderError(f"{self.name}: malformed response") from e
        res = validate_choice(answer, options)
        res.model = model
        return res


# ── 규칙 기반 판단기 ─────────────────────────────────────────────

_PROGRESS = re.compile(
    r"신청|확인|다음|계속|시작|입장|이동|조회|참여|받기|수령|상담|바로가기|19세|성인|동의|enter|continue|next|start|apply|\bgo\b",
    re.I,
)
_NAV_NOISE = re.compile(r"개인정보처리방침|이용약관|고객센터|회사소개|privacy|terms|about", re.I)

_THREAT_SIGNS: dict[str, list[str]] = {
    "illegal_gambling": ["카지노", "베팅", "배팅", "충전", "환전", "토토", "슬롯", "바카라", "배당", "첫충", "콤프"],
    "phishing": ["비밀번호", "인증번호", "주민등록번호", "로그인", "본인인증", "보안카드", "otp", "계정 확인", "input:password"],
    "scam": ["입금", "송금", "수익률", "원금 보장", "투자", "환급", "지원금", "수수료", "계좌"],
    "malware": [".apk", "앱 설치", "설치 파일", "download:"],
}


class RuleProvider:
    name = "rules"
    model = "rules-1"

    def choose(self, state: dict, question: str, options: dict[str, str]) -> ChoiceResult:
        if set(options) >= {"phishing", "benign"}:
            return self._threat(state, options)
        return self._action(state, options)

    def _action(self, state: dict, options: dict[str, str]) -> ChoiceResult:
        history: list[str] = state.get("agent_history", [])
        # 이미 눌렀거나 게이트가 막은 요소(텍스트 기준)는 다시 고르지 않는다
        clicked = {h.split(":", 2)[2] for h in history if h.startswith(("click:", "blocked:")) and h.count(":") >= 2}
        scores: dict[str, float] = {}
        progress = False
        for key, label in options.items():
            s = 0.05
            if key.startswith("click_"):
                text = label.split("] ", 1)[-1].split(" → ")[0][:40]
                if text in clicked:
                    s = 0.01
                elif _NAV_NOISE.search(label):
                    s = 0.02
                elif _PROGRESS.search(label):
                    s, progress = 1.0, True
                else:
                    s = 0.1
            elif key == "close_popup":
                s, progress = 1.2, True
            elif key == "scroll":
                s = 0.03
            scores[key] = s
        text = state.get("page", {}).get("text", "")
        reached = sum(w in text for w in ("입금", "계좌", "충전", "비밀번호", "주민등록번호", "결제", "인증번호"))
        if "finish" in scores:
            scores["finish"] = 1.5 if reached >= 2 else (0.08 if progress else 0.9)
        return _normalize(scores, self.model)

    def _threat(self, state: dict, options: dict[str, str]) -> ChoiceResult:
        blob = " ".join([*state.get("pages", []), *state.get("forbidden_seen", [])]).lower()
        scores = {k: 0.2 for k in options}
        for threat, words in _THREAT_SIGNS.items():
            if threat in scores:
                scores[threat] += sum(3.0 for w in words if w.lower() in blob)
        if not blob.strip():
            scores["unknown"] = 5.0
        elif max(scores[t] for t in _THREAT_SIGNS if t in scores) < 3:
            scores["benign"] = 3.0
        return _normalize(scores, self.model)


def _normalize(scores: dict[str, float], model: str) -> ChoiceResult:
    total = sum(scores.values())
    probs = {k: round(v / total, 4) for k, v in scores.items()}
    best = max(probs, key=probs.get)
    return ChoiceResult(best, probs, probs[best], model)


def state_for_jev(state: dict) -> dict:
    """외부 전송 직전 마지막 마스킹. 문자열 값은 모두 개인정보 패턴을 가린다."""

    def walk(v):
        if isinstance(v, str):
            return mask_pii(v)
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        return v

    return walk(state)


def timed(fn, *args):
    t0 = time.perf_counter()
    out = fn(*args)
    return out, int((time.perf_counter() - t0) * 1000)

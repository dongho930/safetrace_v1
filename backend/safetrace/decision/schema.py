"""판단 서비스의 입출력 계약. 모델이 바뀌어도 이 인터페이스는 그대로다."""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

ELEMENT_ID = r"^e\d{1,4}$"


class ActionKind(StrEnum):
    CLICK = "click"
    SCROLL = "scroll"
    CLOSE_POPUP = "close_popup"
    BACK = "back"
    FINISH = "finish"


class Threat(StrEnum):
    PHISHING = "phishing"
    SCAM = "scam"
    ILLEGAL_GAMBLING = "illegal_gambling"
    MALWARE = "malware"
    BENIGN = "benign"
    UNKNOWN = "unknown"


THREAT_LABELS_KO = {
    Threat.PHISHING: "피싱",
    Threat.SCAM: "사기",
    Threat.ILLEGAL_GAMBLING: "불법 도박 의심",
    Threat.MALWARE: "악성코드",
    Threat.BENIGN: "정상",
    Threat.UNKNOWN: "판단 불가",
}

THREAT_CRITERIA = {
    Threat.PHISHING: "기관·기업을 사칭해 로그인 정보, 인증번호, 개인정보 입력을 유도한다",
    Threat.SCAM: "투자·환급·지원금·물품 거래 등을 미끼로 입금이나 송금을 요구한다",
    Threat.ILLEGAL_GAMBLING: (
        "정부 허가를 받지 않은 카지노·스포츠 베팅 등 도박 서비스를 제공하거나 홍보한다"
        "(충전·환전, 첫충·콤프 같은 보너스, 가입코드, 텔레그램·카카오톡 문의 등). "
        "해외 도박 브랜드(体育·娱乐·注册·彩票·棋牌·真人·博彩 등이 붙은 이름)를 제목·회사명 자리에 붙이고 "
        "본문은 다른 회사 사이트를 복제한 검색 노출용 페이지도 여기에 해당한다"
    ),
    Threat.MALWARE: "앱 설치 파일(apk 등)이나 실행 파일 다운로드를 유도한다",
    Threat.BENIGN: (
        "위 유형의 특징이 없는 일반적인 웹사이트다. "
        "정부 허가 사행사업자(스포츠토토·베트맨·동행복권·경마·경륜·경정)의 공식 도메인 사이트도 여기에 해당하며, "
        "공식 명칭만 내세우고 도메인이 다르면 해당하지 않는다"
    ),
    Threat.UNKNOWN: "화면 내용이 부족하거나 접속 불가로 판단할 수 없다",
}


class Candidate(BaseModel):
    id: str = Field(pattern=ELEMENT_ID)
    tag: str = Field(max_length=16)
    text: str = Field(max_length=120)
    href_host: str | None = Field(default=None, max_length=253)
    covered: bool = False  # 팝업 등 다른 레이어에 가려져 지금은 누를 수 없음


class PageState(BaseModel):
    """에이전트가 텍스트로 정리한 현재 화면. 스크린샷 원본은 포함하지 않는다."""

    step: int = Field(ge=0, le=100)
    url: str = Field(max_length=2048)
    title: str = Field(max_length=200)
    text: str = Field(max_length=4000)  # 마스킹된 가시 텍스트 요약
    candidates: list[Candidate] = Field(max_length=50)
    has_popup: bool = False
    history: list[str] = Field(default_factory=list, max_length=30)  # 지난 행동 요약


class ActionRequest(BaseModel):
    state: PageState


class Decision(BaseModel):
    choice: str
    probabilities: dict[str, float]
    confidence: float | None = None
    model: str
    provider: str
    latency_ms: int


class ActionDecision(Decision):
    action: ActionKind
    element_id: str | None = None

    @field_validator("element_id")
    @classmethod
    def _eid(cls, v):
        if v is not None and not re.fullmatch(ELEMENT_ID, v):
            raise ValueError("bad element id")
        return v


class BlockedDestination(BaseModel):
    """사이트가 이동시키려 했지만 열리지 않은 목적지. 피싱 도착지가 이미 사라진 경우 도메인 이름만 남는다."""

    host: str = Field(max_length=253)
    reason: str = Field(max_length=64)  # 예: "ssrf:dns_failure", "net:ERR_TUNNEL_CONNECTION_FAILED"


class ThreatRequest(BaseModel):
    url: str = Field(max_length=2048)
    final_url: str = Field(max_length=2048)
    redirect_count: int = Field(ge=0, le=100)
    domains: list[str] = Field(max_length=30)  # 실제로 열린 페이지의 도메인
    pages: list[str] = Field(max_length=20)  # 단계별 마스킹된 텍스트 요약
    forbidden_seen: list[str] = Field(default_factory=list, max_length=50)  # 예: "input:password", "download:apk"
    blocked_destinations: list[BlockedDestination] = Field(default_factory=list, max_length=20)


class ThreatDecision(Decision):
    threat: Threat
    hold: bool  # 확신 부족이면 True → REVIEW_REQUIRED
    # 코드 규칙이 모델 판단을 바꿨을 때: {"reason", "operators", "original": {"threat", "probability", "provider"}}
    override: dict | None = None


def _exhausted_actions(history: list[str]) -> set[str]:
    """기록을 뒤에서부터 보며, 화면을 바꾼 행동이 나오기 전까지 효과 없던 행동을 모은다.

    scroll·back 은 그 이름으로, 막혔거나 실패·효과 없던 클릭은 "click:<버튼 글자>" 로 담는다
    (요소 id 는 관찰마다 새로 붙으므로 글자로 비교한다).
    """
    dead: set[str] = set()
    for h in reversed(history):
        if h in ("scroll_no_effect", "back_no_effect"):
            dead.add(h.removesuffix("_no_effect"))
        elif h.startswith(("click_failed:", "click_no_effect:", "blocked:")):
            dead.add("click:" + h.split(":", 2)[2])
        else:
            break
    return dead


def action_options(state: PageState) -> dict[str, str]:
    """Jev choice 질문의 선택지. 여기 없는 행동은 고를 수 없다."""
    opts: dict[str, str] = {}
    dead = _exhausted_actions(state.history)
    for c in state.candidates:
        if c.text and f"click:{c.text[:40]}" in dead:
            continue
        label = c.text or "(텍스트 없음)"
        if c.href_host:
            label += f" → {c.href_host}"
        if c.covered:
            label += " (다른 레이어에 가려져 지금은 누를 수 없음)"
        opts[f"click_{c.id}"] = f"클릭: [{c.tag}] {label}"
    # 마지막 화면 변화 뒤에 효과가 없었던 스크롤·뒤로 가기는 다시 내놓지 않는다: 같은 행동 반복 방지
    if "scroll" not in dead:
        opts["scroll"] = "화면을 아래로 스크롤해 더 본다"
    if state.has_popup:
        opts["close_popup"] = "떠 있는 팝업·레이어를 닫는다"
    if state.step > 0 and "back" not in dead:
        opts["back"] = "이전 화면으로 돌아간다"
    opts["finish"] = "입금·개인정보 입력 화면 등 핵심 화면에 도달했거나 더 볼 것이 없어 조사를 끝낸다"
    return opts


def parse_action_key(key: str, state: PageState) -> tuple[ActionKind, str | None]:
    valid = action_options(state)
    if key not in valid:
        raise ValueError("choice outside offered options")
    if key.startswith("click_"):
        return ActionKind.CLICK, key.removeprefix("click_")
    return ActionKind(key), None

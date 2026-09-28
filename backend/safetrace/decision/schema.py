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
    Threat.ILLEGAL_GAMBLING: "카지노, 스포츠 베팅, 충전·환전, 배당 등 도박 서비스를 제공한다",
    Threat.MALWARE: "앱 설치 파일(apk 등)이나 실행 파일 다운로드를 유도한다",
    Threat.BENIGN: "위 유형의 특징이 없는 일반적인 웹사이트다",
    Threat.UNKNOWN: "화면 내용이 부족하거나 접속 불가로 판단할 수 없다",
}


class Candidate(BaseModel):
    id: str = Field(pattern=ELEMENT_ID)
    tag: str = Field(max_length=16)
    text: str = Field(max_length=120)
    href_host: str | None = Field(default=None, max_length=253)


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


class ThreatRequest(BaseModel):
    url: str = Field(max_length=2048)
    final_url: str = Field(max_length=2048)
    redirect_count: int = Field(ge=0, le=100)
    domains: list[str] = Field(max_length=30)
    pages: list[str] = Field(max_length=20)  # 단계별 마스킹된 텍스트 요약
    forbidden_seen: list[str] = Field(default_factory=list, max_length=50)  # 예: "input:password", "download:apk"


class ThreatDecision(Decision):
    threat: Threat
    hold: bool  # 확신 부족이면 True → REVIEW_REQUIRED


def action_options(state: PageState) -> dict[str, str]:
    """Jev choice 질문의 선택지. 여기 없는 행동은 고를 수 없다."""
    opts: dict[str, str] = {}
    for c in state.candidates:
        label = c.text or "(텍스트 없음)"
        if c.href_host:
            label += f" → {c.href_host}"
        opts[f"click_{c.id}"] = f"클릭: [{c.tag}] {label}"
    opts["scroll"] = "화면을 아래로 스크롤해 더 본다"
    if state.has_popup:
        opts["close_popup"] = "떠 있는 팝업·레이어를 닫는다"
    if state.step > 0:
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

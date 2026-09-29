"""안전 게이트: 실행 직전에 코드가 강제하는 규칙. Jev의 답을 그대로 실행하지 않는다.

금지 분류는 여기(Python)에서만 결정한다. 페이지 JS가 돌려준 원시 속성만 입력으로 쓰며,
클릭 직전에 요소를 다시 읽어 같은 규칙으로 재분류한다(관찰 뒤 요소를 바꿔치기하는 공격 대비).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..netguard import BlockedURL, check_url

_TEXT_INPUT_TYPES = {
    "text", "password", "email", "tel", "number", "search", "url", "date", "datetime-local",
    "month", "week", "time", "file", "color", "range", "hidden", "checkbox", "radio",
}
_DOWNLOAD_EXT = re.compile(
    r"\.(apk|aab|xapk|ipa|exe|msi|bat|cmd|scr|com|pif|jar|js|vbs|ps1|dmg|pkg|deb|rpm|sh|zip|rar|7z|iso|img|hta|lnk|dll|docm|xlsm)(?:$|[?#])",
    re.I,
)
_PAYMENT = re.compile(r"결제|송금|이체|입금\s*(하기|신청|완료|확인)|충전\s*(하기|신청)|구매\s*하기|pay\s*now|checkout|purchase|donate", re.I)
_LOGIN = re.compile(r"로그인|log\s*in|sign\s*in|인증\s*(하기|요청)|본인\s*인증", re.I)
_SUBMIT_TEXT = re.compile(r"제출|전송|등록\s*하기|submit|send", re.I)
_OK_SCHEMES = {"http", "https", "javascript", ""}


@dataclass(frozen=True)
class ElementInfo:
    """페이지에서 읽은 원시 속성. 모든 값은 신뢰하지 않는 데이터다."""

    tag: str
    type: str = ""
    in_form: bool = False
    has_download: bool = False
    href: str = ""
    text: str = ""
    role: str = ""
    editable: bool = False

    @classmethod
    def from_js(cls, d: dict) -> ElementInfo:
        def s(k, n=300):
            v = d.get(k) or ""
            return str(v)[:n]

        return cls(
            tag=s("tag", 16).lower(),
            type=s("type", 24).lower(),
            in_form=bool(d.get("inForm")),
            has_download=bool(d.get("hasDownload")),
            href=s("href", 2048),
            text=s("text", 200),
            role=s("role", 24).lower(),
            editable=bool(d.get("editable")),
        )

    def fingerprint(self) -> tuple:
        return (self.tag, self.type, self.href, self.text.strip()[:80])


def classify_forbidden(el: ElementInfo) -> str | None:
    """금지 사유를 돌려준다. None 이면 클릭 후보가 될 수 있다."""
    if el.editable or el.tag in {"textarea", "select", "option", "iframe", "object", "embed"}:
        return "input"
    if el.tag == "input":
        if el.type in _TEXT_INPUT_TYPES or el.type == "":
            return "input"
        if el.type in {"submit", "image"}:
            return "submit"
    if el.tag == "button" and el.in_form and el.type in {"submit", ""}:
        return "submit"
    if el.tag == "form":
        return "submit"
    if el.has_download:
        return "download"
    if el.href:
        scheme = urlsplit(el.href).scheme.lower()
        if scheme not in _OK_SCHEMES:
            return f"scheme:{scheme}"
        if _DOWNLOAD_EXT.search(urlsplit(el.href).path):
            return "download"
    if _PAYMENT.search(el.text):
        return "payment"
    if _LOGIN.search(el.text):
        return "login"
    if el.in_form and _SUBMIT_TEXT.search(el.text):
        return "submit"
    return None


@dataclass
class Budget:
    max_steps: int
    max_seconds: int
    max_same_state: int
    started: float = field(default_factory=time.monotonic)
    steps: int = 0
    seen: dict[str, int] = field(default_factory=dict)

    def exceeded(self) -> str | None:
        if self.steps >= self.max_steps:
            return "step_budget"
        if time.monotonic() - self.started > self.max_seconds:
            return "time_budget"
        return None

    def remaining(self) -> float:
        """남은 조사 시간(초). 음수면 이미 넘었다."""
        return self.max_seconds - (time.monotonic() - self.started)

    def observe_state(self, key: str) -> str | None:
        self.seen[key] = self.seen.get(key, 0) + 1
        if self.seen[key] > self.max_same_state:
            return "loop_detected"
        return None


@dataclass
class GateResult:
    allowed: bool
    reason: str = "ok"


class SafetyGate:
    def __init__(self, allowed_ports: list[int], test_allowlist: list[str], resolver=None):
        self.allowed_ports = allowed_ports
        self.test_allowlist = test_allowlist
        self._resolver = resolver

    def check_nav(self, url: str) -> GateResult:
        try:
            kw = {"resolver": self._resolver} if self._resolver else {}
            check_url(url, self.allowed_ports, self.test_allowlist, **kw)
            return GateResult(True)
        except BlockedURL as e:
            return GateResult(False, f"ssrf:{e.reason}")

    def check_click(self, offered_ids: set[str], element_id: str | None,
                    observed: ElementInfo | None, current: ElementInfo | None) -> GateResult:
        if element_id is None or element_id not in offered_ids:
            return GateResult(False, "not_offered")
        if observed is None or current is None:
            return GateResult(False, "element_gone")
        if observed.fingerprint() != current.fingerprint():
            return GateResult(False, "element_changed")
        reason = classify_forbidden(current)
        if reason:
            return GateResult(False, f"forbidden:{reason}")
        if current.href and urlsplit(current.href).scheme.lower() in {"http", "https"}:
            nav = self.check_nav(current.href)
            if not nav.allowed:
                return nav
        return GateResult(True)

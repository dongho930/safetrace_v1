"""외부(Jev)로 보내는 텍스트와 로그에서 개인정보 형태 문자열을 가린다."""

import re

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b\d{6}\s*-\s*[1-8]\d{6}\b"), "[주민번호]"),
    (re.compile(r"\b01[016789][-\s.]?\d{3,4}[-\s.]?\d{4}\b"), "[전화번호]"),
    (re.compile(r"\b0\d{1,2}[-\s.]\d{3,4}[-\s.]\d{4}\b"), "[전화번호]"),
    (re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), "[이메일]"),
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "[카드번호]"),
    # 계좌번호: 숫자 그룹 3~4개, 전체 10~16자리
    (re.compile(r"\b\d{2,6}-\d{2,6}-\d{2,6}(?:-\d{1,6})?\b"), "[계좌번호]"),
    (re.compile(r"\b\d{11,14}\b"), "[번호]"),
]

_SECRET_KEYS = re.compile(r"(?i)(authorization|api[_-]?key|token|secret|password)(\"?\s*[:=]\s*\"?)([^\s\",]+)")


def mask_pii(text: str) -> str:
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


def mask_secrets(text: str) -> str:
    return _SECRET_KEYS.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)

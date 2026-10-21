"""운영 정보와 키트 지문(분석가 업무): 화면에 적힌 운영자 연락 수단·입금 계좌·입력값을 보내는 곳과, 같은 피싱 키트를
알아볼 화면 구조 지문을 관찰 기록에 남긴다.

- 값은 조사 대상 페이지가 적은 것이다. 남의 연락처를 일부러 적어 둘 수 있으므로 '페이지에 적힌 값(확인 안 됨)'으로만
  쓰고 판단(위협 유형)·자동 연관 사건에는 쓰지 않는다. 사건을 잇는 참고 열쇠로만 쓴다
- 판단 모델(Jev)·외부 평판 조회로 보내지 않는다(판단 요청의 PageState 는 그대로)
- 실제로 운영자가 쓰는 모양만 뽑는다: 텔레그램·카카오톡 오픈채팅·라인·왓츠앱·디스코드 링크, 문의·입금 같은 말 바로
  뒤의 텔레그램 아이디·휴대전화(010·070)·은행 이름 바로 뒤의 계좌번호, 다른 호스트로 보내는 입력 양식. 대표번호
  (1588 등)·유선 번호는 피싱 키트가 진짜 회사 번호를 베껴 오는 경우가 많아 뽑지 않는다
- 키트 지문은 화면 요소 순서(태그·깊이)와 같은 출처의 빌드 산출물 경로(해시가 붙은 js·css)를 해시한 것이다.
  요소가 적은 화면(오류·주차·봇 확인 화면은 서로 다른 운영자도 같다)은 지문을 만들지 않는다
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qs, unquote, urlsplit

from ..decision.brands import SHARED_HOSTING, on_domain, site_of
from ..masking import mask_pii

MAX_ITEMS = 20       # 관찰 하나에서 남기는 운영 정보
KIT_MIN_ELEMENTS = 60  # 이보다 요소가 적은 화면은 키트 지문을 만들지 않는다
KIT_MIN_ASSETS = 1     # 빌드 산출물 경로가 이보다 적으면 산출물 지문을 만들지 않는다

KINDS = ("telegram", "kakao", "line", "whatsapp", "discord", "phone", "account", "form")
KIND_KO = {"telegram": "텔레그램", "kakao": "카카오톡", "line": "라인", "whatsapp": "왓츠앱", "discord": "디스코드",
           "phone": "휴대전화", "account": "입금 계좌", "form": "입력값을 보내는 곳"}

_TG_RESERVED = {"share", "addstickers", "addtheme", "setlanguage", "iv", "proxy", "socks", "login", "s"}
_LINK_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("telegram", re.compile(r"^https?://(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog)/(\+[A-Za-z0-9_-]{8,64}|joinchat/[A-Za-z0-9_-]{8,64}|[A-Za-z][A-Za-z0-9_]{3,31})(?:[/?#]|$)", re.I)),
    ("kakao", re.compile(r"^https?://(?:open\.kakao\.com/(o/[A-Za-z0-9]{4,32})|pf\.kakao\.com/(_[A-Za-z0-9]{3,32})|qr\.kakao\.com/talk/([A-Za-z0-9._-]{4,64}))(?:[/?#]|$)", re.I)),
    ("line", re.compile(r"^https?://line\.me/(?:R/)?ti/p/(~?@?[A-Za-z0-9._-]{3,32})(?:[/?#]|$)", re.I)),
    ("whatsapp", re.compile(r"^https?://wa\.me/(\d{7,15})(?:[/?#]|$)", re.I)),
    ("discord", re.compile(r"^https?://(?:www\.)?(?:discord\.gg|discord\.com/invite)/([A-Za-z0-9-]{2,32})(?:[/?#]|$)", re.I)),
)
_TG_APP = re.compile(r"^tg://resolve\?domain=([A-Za-z][A-Za-z0-9_]{3,31})(?:&|$)", re.I)

# 문의·입금 같은 말 바로 뒤(40자 안)의 값만 본다. 화면 아무 데나 있는 번호·영문 낱말은 보지 않는다
_TG_CUE = re.compile(r"(?:텔레그램|텔레|텔렘|telegram|텔레\s*ID|TG)\s*(?:아이디|ID|id|문의|상담|고객센터|:|：|-|\s)*\s*@?([A-Za-z][A-Za-z0-9_]{4,31})", re.I)
_KAKAO_CUE = re.compile(r"(?:카카오톡|카톡|카카오)\s*(?:아이디|ID|id|:|：|-|\s)+\s*([A-Za-z0-9][A-Za-z0-9_.-]{2,19})", re.I)
_PHONE_CUE = re.compile(r"(?:문의|상담|연락|연락처|고객센터|전화|문자|입금|카톡|텔레)[^0-9]{0,20}(0[17]0[-\s.]?\d{3,4}[-\s.]?\d{4})")
# 은행 이름 바로 뒤의 번호만 계좌로 본다. 지명·흔한 낱말과 같은 이름(우리·부산 등)은 '은행'이 붙어야 한다
_BANKS = ("국민", "KB", "신한", "하나", "농협", "NH", "기업", "IBK", "카카오뱅크", "카뱅", "토스뱅크", "케이뱅크", "우체국",
          "새마을", "신협", "수협", "SC제일", "씨티")
_BANKS_NEED_WORD = ("우리", "대구", "부산", "경남", "광주", "전북", "제주", "산업")
_ACCOUNT_CUE = re.compile(r"(" + "|".join(_BANKS) + r"|(?:" + "|".join(_BANKS_NEED_WORD) + r")(?=은행))\s*(?:은행)?\s*(?:계좌)?"
                          r"\s*[:：]?\s*(\d{2,6}(?:[-\s]\d{2,7}){1,3}|\d{10,14})")
_PHONE_SHAPE = re.compile(r"0\d{1,2}[-\s]\d{3,4}[-\s]\d{4}")  # 유선·휴대전화 모양(계좌가 아니다)
_WORDS_NOT_ID = {"telegram", "kakao", "kakaotalk", "official", "channel", "support", "contact", "admin", "username"}


def _norm_phone(s: str) -> str | None:
    d = re.sub(r"\D", "", s)
    if d.startswith("82") and len(d) in (11, 12):
        d = "0" + d[2:]
    return d if re.fullmatch(r"0[17]0\d{7,8}", d) else None


def _item(kind: str, value: str, src: str) -> dict:
    return {"kind": kind, "value": value[:200], "src": src}


def from_link(href: str) -> dict | None:
    """연락 링크 하나에서 운영 정보. 모르는 모양이면 None."""
    if not isinstance(href, str) or len(href) > 2048:
        return None
    h = href.strip()
    low = h.lower()
    if low.startswith(("tel:", "sms:")):
        p = _norm_phone(unquote(h.split(":", 1)[1].split("?", 1)[0]))
        return _item("phone", p, "link") if p else None
    m = _TG_APP.match(h)
    if m:
        return _item("telegram", m.group(1).lower(), "link")
    if low.startswith(("https://api.whatsapp.com/send", "http://api.whatsapp.com/send")):
        ph = (parse_qs(urlsplit(h).query).get("phone") or [""])[0]
        return _item("whatsapp", ph, "link") if re.fullmatch(r"\d{7,15}", ph) else None
    for kind, rx in _LINK_RULES:
        m = rx.match(h)
        if not m:
            continue
        v = next(g for g in m.groups() if g)
        if kind == "telegram":
            if v.lower() in _TG_RESERVED:
                return None
            v = v if v.startswith(("+", "joinchat/")) else v.lower()
        return _item(kind, v, "link")
    return None


def from_text(snippets: list) -> list[dict]:
    """문의·입금 같은 말 둘레의 화면 글자 조각에서 운영 정보."""
    out = []
    for s in snippets[:60] if isinstance(snippets, list) else []:
        if not isinstance(s, str):
            continue
        s = s[:300]
        for m in _TG_CUE.finditer(s):
            if m.group(1).lower() not in _WORDS_NOT_ID:
                out.append(_item("telegram", m.group(1).lower(), "text"))
        for m in _KAKAO_CUE.finditer(s):
            v = m.group(1)
            if v.lower() not in _WORDS_NOT_ID and not v.isdigit():
                out.append(_item("kakao", "id:" + v.lower(), "text"))
        for m in _PHONE_CUE.finditer(s):
            p = _norm_phone(m.group(1))
            if p:
                out.append(_item("phone", p, "text"))
        for m in _ACCOUNT_CUE.finditer(s):
            digits = re.sub(r"\D", "", m.group(2))
            if 10 <= len(digits) <= 16 and not _norm_phone(digits) and not _PHONE_SHAPE.fullmatch(m.group(2)):
                out.append(_item("account", f"{m.group(1)}:{digits}", "text"))
    return out


def from_forms(forms: list, page_url: str) -> list[dict]:
    """다른 사이트로 입력값을 보내는 양식(피싱 키트의 수집 서버). 같은 사이트(등록 도메인, 공용 호스팅은 호스트)로 보내는
    양식은 운영자를 가리키지 않는다(정상 사이트의 www → service 하위 도메인 양식, 2026-10-22 정상 16곳 평가에서 관찰)."""
    page_host = (urlsplit(page_url).hostname or "").lower()

    def same_site(host: str) -> bool:
        if host == page_host:
            return True
        if on_domain(host, SHARED_HOSTING) or on_domain(page_host, SHARED_HOSTING):
            return False
        return site_of(host) == site_of(page_host)

    out = []
    for f in forms[:10] if isinstance(forms, list) else []:
        a = f.get("action") if isinstance(f, dict) else None
        if not isinstance(a, str) or not a.startswith(("http://", "https://")) or len(a) > 2048:
            continue
        u = urlsplit(a)
        host = (u.hostname or "").lower()
        if host and not same_site(host):
            # 쿼리·사용자 정보에는 받는 사람·번호가 들어갈 수 있다(열람자에게도 보인다, Codex 지적): 주소만, 경로는 가려서
            port = f":{u.port}" if u.port else ""
            out.append(_item("form", f"{u.scheme}://{host}{port}{mask_pii(u.path or '/')[:200]}", "form"))
    return out


def extract(links: list, snippets: list, forms: list, page_url: str) -> list[dict]:
    """관찰 하나의 운영 정보(같은 값은 한 번, 최대 MAX_ITEMS)."""
    items = [x for x in (from_link(h) for h in (links[:60] if isinstance(links, list) else [])) if x]
    items += from_text(snippets) + from_forms(forms, page_url)
    seen, out = set(), []
    for x in items:
        k = (x["kind"], x["value"])
        if k in seen or not x["value"]:
            continue
        seen.add(k)
        out.append(x)
        if len(out) >= MAX_ITEMS:
            break
    return out


_ASSET = re.compile(r"[._-][A-Za-z0-9_-]{8,}\.(?:m?js|css)$")


def kit_fingerprint(raw: object) -> dict | None:
    """화면 구조 지문 {dom, n[, res, r]}. 요소가 적으면 None. raw 는 COLLECT_JS 의 kit(페이지가 정한 값)."""
    if not isinstance(raw, dict) or not isinstance(raw.get("dom"), str) or type(raw.get("n")) is not int:
        return None
    n = raw["n"]
    if n < KIT_MIN_ELEMENTS:
        return None
    out = {"dom": hashlib.sha256(raw["dom"][:200_000].encode()).hexdigest()[:32], "n": min(n, 100_000)}
    paths = sorted({p for p in raw.get("res", [])[:100] if isinstance(p, str) and len(p) <= 200 and _ASSET.search(p)}
                   ) if isinstance(raw.get("res"), list) else []
    if len(paths) >= KIT_MIN_ASSETS:
        out.update(res=hashlib.sha256("\n".join(paths).encode()).hexdigest()[:32], r=len(paths))
    return out


def mask(kind: str, value: str) -> str:
    """목록·묶음에 보일 값. 전화·계좌는 끝 4자리만, 나머지(운영자가 공개한 채널 아이디)는 그대로."""
    if kind == "phone":
        return f"{value[:3]}-****-{value[-4:]}" if len(value) >= 10 else "****"
    if kind == "account":
        bank, _, num = value.partition(":")
        return f"{bank} ****{num[-4:]}"
    if kind == "whatsapp":
        return f"+{value[:2]}****{value[-4:]}"
    return value

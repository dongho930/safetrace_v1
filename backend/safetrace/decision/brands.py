"""브랜드 사칭 도메인: 도메인 이름에 브랜드가 들어 있는데 그 브랜드의 공식 도메인이 아닌 경우(예: mi-telegram.com).

이름만으로 위협이라 단정하지 않는다. 화면 내용이 거의 없어(봇에게 'OK' 한 줄만 보여 주는 등) 판단 모델이
정상·판단 불가로 본 경우에만 판단 엔진이 근거로 쓴다(engine.decide_threat).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# 브랜드 → 공식 도메인(그 하위 도메인 포함). 문자 사칭에 자주 쓰이는 이름만 둔다
OFFICIAL_BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "telegram": ("telegram.org", "telegram.me", "t.me", "telegra.ph"),
    "naver": ("naver.com", "naver.net", "naver.me", "navercorp.com", "pstatic.net"),
    "kakao": ("kakao.com", "kakaocorp.com", "kakaobank.com", "kakaopay.com", "kakaopaysec.com", "kakaomobility.com",
              "kakaoenterprise.com", "kakaogames.com", "kakaostyle.com", "kakaocdn.net", "daum.net"),
    "coupang": ("coupang.com", "coupang.net", "coupangplay.com", "coupangeats.com"),
    "toss": ("toss.im", "toss.ai", "tossbank.com", "tosspayments.com", "tossinvest.com", "tosssecurities.com"),
    "kbstar": ("kbstar.com",),
    "shinhan": ("shinhan.com", "shinhancard.com", "shinhaninvest.com", "shinhansec.com", "shinhangroup.com",
                "shinhanlife.co.kr"),
    "hometax": ("hometax.go.kr",),
    "epost": ("epost.go.kr", "epost.kr"),
    "cjlogistics": ("cjlogistics.com",),
    "kbank": ("kbanknow.com",),                 # 케이뱅크
    "ilogen": ("ilogen.com",),                  # 로젠택배
    "lotteglo": ("lotteglogis.com",),           # 롯데글로벌로지스
}
THIN_TEXT_CHARS = 200  # 조사한 화면 글자를 다 합쳐 이보다 적으면 '내용이 거의 없음'
_TOKEN = re.compile(r"[.\-_]")


def lookalike_brand(host: str) -> str | None:
    """host 이름 조각(점·하이픈 기준)이 브랜드로 시작하는데 공식 도메인이 아니면 그 브랜드."""
    h = host.lower().rstrip(".")
    if any(h == d or h.endswith("." + d) for ds in OFFICIAL_BRAND_DOMAINS.values() for d in ds):
        return None  # 어느 브랜드든 공식 도메인이면 사칭이 아니다
    tokens = [t for t in _TOKEN.split(h) if t]
    return next((b for b in OFFICIAL_BRAND_DOMAINS if any(t.startswith(b) for t in tokens)), None)


def lookalike_in(url: str, final_url: str) -> str | None:
    """신고된 주소나 최종 주소가 브랜드 사칭 도메인이면 그 브랜드."""
    for u in (url, final_url):
        brand = lookalike_brand(urlsplit(u).hostname or "")
        if brand:
            return brand
    return None


def lookalike_destination(hosts: list[str]) -> tuple[str, str] | None:
    """열리지 않은 이동 목적지 중 브랜드 사칭 도메인이 있으면 (브랜드, 도메인)."""
    for h in hosts:
        brand = lookalike_brand(h)
        if brand:
            return brand, h
    return None


def thin_content(pages: list[str]) -> bool:
    """조사한 화면에 글이 거의 없는지. pages 는 '[단계] 제목 | 주소 | 글' 형식이다."""
    return sum(len(p.split(" | ", 2)[-1].strip()) for p in pages) < THIN_TEXT_CHARS

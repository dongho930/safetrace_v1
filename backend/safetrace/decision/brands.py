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
    # 해외 피싱이 봇을 진짜 사이트로 돌려보낸 곳(OpenPhish 2026-10-14: iCloud 사칭 → www.apple.com,
    # Meta 비즈니스 사칭 → www.facebook.com)
    "apple": ("apple.com",),
    "facebook": ("facebook.com",),
}
# 단축 URL 서비스: 평가 세트·KISA 신고 자료(var/probe)에서 실제로 본 것만. 남의 주소로 넘기는 것이 본업이라 넘긴 곳을
# 근거로 삼지 않는다(gourl.kr·vo.la 는 사라진 링크를 naver.com·쿠팡 검색으로 넘긴다)
SHORTENER_HOSTS: tuple[str, ...] = ("bit.ly", "tinyurl.com", "t.ly", "han.gl", "lrl.kr", "goo.su", "c11.kr", "go9.co",
                                    "iii.im", "xzx.kr", "muz.so", "tny.kr", "5du.pl", "gourl.kr", "vo.la")
THIN_TEXT_CHARS = 200  # 조사한 화면 글자를 다 합쳐 이보다 적으면 '내용이 거의 없음'
_TOKEN = re.compile(r"[.\-_]")


def on_domain(host: str, domains: tuple[str, ...]) -> bool:
    """host 가 domains 중 하나이거나 그 하위 도메인인지."""
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in domains)


def official_brand(host: str) -> str | None:
    """host 가 어느 브랜드의 공식 도메인(하위 포함)이면 그 브랜드."""
    return next((b for b, ds in OFFICIAL_BRAND_DOMAINS.items() if on_domain(host, ds)), None)


def official_redirect(url: str, page_urls: list[str]) -> tuple[str, str] | None:
    """신고된 주소가 에이전트가 아무것도 누르기 전에(첫 관찰 화면) 브랜드 공식 사이트로 넘겼으면 (브랜드, 도착 호스트).

    피싱 키트는 봇·조사 도구를 진짜 사이트로 돌려보내 화면을 숨긴다(관찰: iCloud 사칭 → www.apple.com, Meta 사칭
    pages.dev → www.facebook.com). 시작 주소가 공식 도메인이거나(공식끼리의 이동) 단축 서비스면 근거로 삼지 않는다.
    page_urls 는 화면마다 브라우저가 연 주소다(페이지가 정할 수 없는 값)."""
    if not page_urls:
        return None
    start = urlsplit(url).hostname or ""
    first = urlsplit(page_urls[0]).hostname or ""
    brand = official_brand(first)
    if not brand or official_brand(start) or on_domain(start, SHORTENER_HOSTS):
        return None
    return brand, first.lower().rstrip(".")


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

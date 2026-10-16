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
    # 오늘의 실사이트 세트(OpenPhish 2026-10-16)에서 본 게임·가상자산 지갑 사칭: Roblox 사칭 도메인의 프로필 화면,
    # Ledger·Trezor 사칭 GitBook·다운로드 사이트, Steam 사칭 로그인
    "roblox": ("roblox.com", "rbxcdn.com"),
    "trezor": ("trezor.io",),
    "ledger": ("ledger.com",),
    "steam": ("steampowered.com", "steamcommunity.com", "steamstatic.com", "steamusercontent.com"),
}
# 단축 URL 서비스: 평가 세트·KISA 신고 자료(var/probe)에서 실제로 본 것만. 남의 주소로 넘기는 것이 본업이라 넘긴 곳을
# 근거로 삼지 않는다(gourl.kr·vo.la 는 사라진 링크를 naver.com·쿠팡 검색으로 넘긴다)
SHORTENER_HOSTS: tuple[str, ...] = ("bit.ly", "tinyurl.com", "t.ly", "han.gl", "lrl.kr", "goo.su", "c11.kr", "go9.co",
                                    "iii.im", "xzx.kr", "muz.so", "tny.kr", "5du.pl", "gourl.kr", "vo.la")
# 공용 호스팅(누구나 하위 도메인에 사이트를 올린다): 하위 도메인이 다르면 다른 운영자다. 오늘의 실사이트 세트
# (OpenPhish 2026-10-14·15)·KISA 2024 자료에서 피싱이 올라와 있던 곳만 둔다
SHARED_HOSTING: tuple[str, ...] = (
    "pages.dev", "netlify.app", "vercel.app", "github.io", "webflow.io", "typedream.app", "framer.website",
    "weebly.com", "jimdofree.com", "blogspot.com", "gitbook.io", "replit.app", "craftum.io", "cleverapps.io",
    "azurefd.net", "amazonaws.com",  # OpenPhish 2026-10-15
    "framer.app",                    # OpenPhish 2026-10-16(브랜드 없는 로그인 화면)
    "dothome.co.kr",                 # OpenPhish 2026-10-14·15
    "creatorlink.net",               # KISA 2024
)
THIN_TEXT_CHARS = 200  # 조사한 화면 글자를 다 합쳐 이보다 적으면 '내용이 거의 없음'
_TOKEN = re.compile(r"[.\-_]")
_SECOND_LEVEL = {"co", "or", "go", "ne", "ac", "re", "pe", "com", "net", "org", "gov", "edu"}


def site_of(host: str) -> str:
    """등록 도메인을 어림한다(예: news.naver.com → naver.com, www.epost.go.kr → epost.go.kr, roblox.com.mu → roblox.com.mu)."""
    h = host.lower().rstrip(".")
    if h.replace(".", "").isdigit() or ":" in h:  # IP 주소는 그대로
        return h
    labels = [x for x in h.split(".") if x]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


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


def brand_name_domain(host: str) -> str | None:
    """등록 도메인 이름이 브랜드 이름 그대로인데 공식 도메인이 아니면 그 브랜드(최상위 도메인만 바꾼 사칭).

    관찰: 오늘의 실사이트 세트(OpenPhish 2026-10-14~16)의 Roblox 사칭 www.roblox.et·roblox.com.mu·roblox.rw 등,
    KISA 2024 자료의 telegram.lgbt·www.toss.club. 이름 조각이 브랜드로 '시작'하는 것(mi-telegram.com)보다 좁다.
    공용 호스팅(하위 도메인은 누구나 만들고 facebook.github.io 같은 공식 프로젝트도 있다)·단축 서비스는 보지 않는다."""
    h = host.lower().rstrip(".")
    if not h or official_brand(h) or on_domain(h, SHARED_HOSTING) or on_domain(h, SHORTENER_HOSTS):
        return None
    name = site_of(h).split(".")[0]  # IP 주소는 첫 숫자라 브랜드가 아니다
    return name if name in OFFICIAL_BRAND_DOMAINS else None


def brand_name_in(url: str, final_url: str) -> tuple[str, str] | None:
    """신고된 주소나 최종 주소가 브랜드 이름 그대로의 다른 도메인이면 (브랜드, 호스트)."""
    for u in (url, final_url):
        h = (urlsplit(u).hostname or "").lower().rstrip(".")
        brand = brand_name_domain(h)
        if brand:
            return brand, h
    return None


TYPO_MIN_BRAND = 6  # 오타 비교는 이 길이 이상 브랜드만(짧은 이름은 한두 글자 차이가 흔한 단어다: steam·stream, toss·boss)
TYPO_MAX_DISTANCE = 2


def _distance(a: str, b: str) -> int:
    """편집 거리(글자 넣기·빼기·바꾸기 횟수)."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def name_parts(host: str) -> list[str]:
    """운영자가 고른 이름 조각. 공용 호스팅은 그 아래 하위 도메인에서, 아니면 등록 도메인의 끝(.com·.co.kr)을 뺀 부분에서."""
    h = host.lower().rstrip(".")
    hosting = next((d for d in SHARED_HOSTING if on_domain(h, (d,))), None)
    if hosting:
        part = h[: -len(hosting)].rstrip(".")
    else:
        site = site_of(h)
        part = h[: -len(site)] + site.split(".")[0]
    return [t for t in _TOKEN.split(part) if t]


def typo_of(host: str, brand: str) -> bool:
    """이름 조각이 브랜드와 한두 글자 다른지(예: trzer → trezor). 브랜드로 시작하는 조각은 오타가 아니다
    (그쪽은 lookalike_brand·brand_name_domain 이 본다)."""
    n = len(brand)
    if n < TYPO_MIN_BRAND:
        return False
    for t in name_parts(host):
        if t.startswith(brand):
            continue
        windows = {t[:k] for k in (n - 1, n, n + 1) if len(t) >= k}
        if any(0 < _distance(w, brand) <= TYPO_MAX_DISTANCE for w in windows):
            return True
    return False


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def claimed_brands(title: str) -> list[str]:
    """제목이 내세우는 브랜드(영문 이름이 한 낱말로 들어 있음, 예: 'Steam Community', 'Trezor® Hardware').
    모두 돌려준다: 하나만 고르면 제목에 다른 브랜드를 덧붙여('Trezor Hardware | Naver') 규칙을 피할 수 있다(Codex 지적)."""
    t = title.lower()
    return [b for b in OFFICIAL_BRAND_DOMAINS if re.search(rf"(?<![a-z0-9]){b}(?![a-z0-9])", t)]


def brand_typo_claim(titles: list[str], page_urls: list[str]) -> tuple[str, str] | None:
    """화면 제목이 브랜드를 내세우는데 그 화면의 도메인 이름이 브랜드와 한두 글자 다르면 (브랜드, 호스트).
    titles·page_urls 는 화면마다 같은 순서다(제목은 페이지 값, 주소는 브라우저 값). 짝이 맞지 않으면 적용하지 않는다.
    관찰: 오늘의 실사이트 세트(OpenPhish 2026-10-16) Trezor 사칭 GitBook(하위 도메인 이름이 trezor 의 오타, 제목 'Trezor® Hardware')."""
    if len(titles) != len(page_urls):
        return None
    for title, url in zip(titles, page_urls, strict=True):
        host = _host(url)
        for brand in claimed_brands(title):
            if not official_brand(host) and typo_of(host, brand):
                return brand, host
    return None


def brand_login_on_shared_hosting(titles: list[str], page_urls: list[str],
                                  page_forbidden: list[list[str]]) -> tuple[str, str] | None:
    """공용 호스팅(누구나 하위 도메인을 만든다)의 화면이 제목으로 브랜드를 내세우고 그 화면에 로그인 요소(로그인 버튼·링크,
    비밀번호 입력)가 있으면 (브랜드, 호스트). 브랜드의 공식 서비스는 공용 호스팅에 로그인 화면을 두지 않는다.
    관찰: 오늘의 실사이트 세트(OpenPhish 2026-10-16) Steam 사칭 netlify('Steam Community', 'Sign in').
    page_forbidden 은 화면마다 에이전트가 본 금지 요소(사유:종류:글자)다. 다른 화면의 로그인 요소는 근거로 쓰지 않고,
    화면별 짝이 맞지 않으면 적용하지 않는다."""
    if not len(titles) == len(page_urls) == len(page_forbidden):
        return None
    for title, url, seen in zip(titles, page_urls, page_forbidden, strict=True):
        if not any(x.startswith(("login:", "input:password")) for x in seen):
            continue
        host = _host(url)
        brands = claimed_brands(title)
        if brands and on_domain(host, SHARED_HOSTING) and not official_brand(host):
            return brands[0], host
    return None


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

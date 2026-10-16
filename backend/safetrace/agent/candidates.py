"""연관 후보: 조사 중에 거친 경유 도메인과 페이지의 외부 링크 가운데 더 조사할 곳을 고른다(기획서 2.2 보조 기능).

목적은 신고 1건에서 같은 조직이 운영하는 다른 위험 사이트를 찾는 것이다(docs/related-sites.md). 원래 사건의 판정은
바꾸지 않는다.

후보 주소는 조사 대상 페이지에서 온 값이다(공격자가 고를 수 있다). 그래서
- http·https 와 허용 포트만, 길이를 제한해 받는다(목록은 최대 MAX_FOUND 개). 쿼리·조각은 버린다
- 사칭 대상이 되는 공식 도메인(브랜드·사행사업자)과 흔한 대형 사이트, 이미 조사한 사이트는 뺀다
- 앵커 글자는 호출하는 쪽이 개인정보를 가린 뒤 넘기고, 여기서 다시 길이를 자른다
- 실제로 열 때는 원래 조사와 같은 안전 게이트·검문 프록시를 거친다(여기서는 고르기만 한다)
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from ..decision.brands import OFFICIAL_BRAND_DOMAINS, SHARED_HOSTING, on_domain, site_of
from ..decision.official import official_operator
from ..decision.providers import _THREAT_SIGNS
from ..netguard import BlockedURL, parse_url
from .gate import ElementInfo, classify_forbidden

MAX_FOUND = 20  # 기록하는 후보 수(사건당)
TEXT_MAX = 80  # 후보에 남기는 앵커 글자

# 흔한 대형 사이트: 위협 사이트가 꾸밈으로 링크하는 정상 서비스. 하위 조사 3곳을 여기에 쓰지 않는다.
# 연관 후보로 나와 하위 조사 결과가 정상이었던 것만 둔다(평가 기록 var/eval/20261014-2355_related_baseline·
# 20261015-0028_fresh_20261015·20261015-1018_related_discovery 의 related)
GENERIC_SITES: frozenset[str] = frozenset({
    "facebook.com", "instagram.com", "x.com", "linkedin.com",   # SNS(KISA·실사이트)
    "youtube.com",                                              # 동영상(KISA 크리에이터링크 차단 화면)
    "rambler.ru", "liveinternet.ru",                            # 포털·방문 집계(KISA goo.su)
    "freestar.com", "ethyca.com",                               # 광고·개인정보 동의 업체(KISA tinyurl·bit.ly)
    "ethereum.org", "polkadot.network", "cosmos.network",       # 가짜 지갑 사이트가 꾸밈으로 단 공식 사이트(실사이트)
    "dhl.com",                                                  # 사칭 대상의 공식 사이트(실사이트)
})
# 서비스 홈: 그 서비스의 첫 화면(경로 '/')만 뺀다. 같은 도메인의 다른 경로는 단축 주소·사용자 페이지일 수 있어
# 목적지를 확인하기 전에 버리지 않는다(Codex 지적)
SERVICE_HOMES: frozenset[str] = frozenset({
    "bitly.com", "mu-star.net", "sdu.sk",                       # 단축 서비스 홈(정지 안내 화면의 링크, KISA)
    "typedream.com", "webflow.com", "gitbook.com", "jimdo.com",  # 사이트 빌더 홈(실사이트의 '만든 곳' 링크)
})
# 위협 단서: 판단 규칙(decision/providers.py)에 이미 있는 단어만 쓴다. 'input:'·'download:' 는 화면 요소 표시라 뺀다
_CLUES: tuple[str, ...] = tuple(w.lower() for ws in _THREAT_SIGNS.values() for w in ws if ":" not in w)
# 이름 조각: 하이픈·점·밑줄로 나눈 4글자 이상. 관찰한 피싱 호스트 이름에 흔히 붙던 낱말은 조각으로 치지 않는다
_FRAG_SPLIT = re.compile(r"[.\-_]")
_COMMON_FRAGS = frozenset({"shop", "online", "login", "live", "support", "docs", "static", "website", "server",
                           "page", "security", "secure", "auth", "sign", "mail", "service"})


def _official(host: str) -> bool:
    h = host.lower().rstrip(".")
    brand = any(h == d or h.endswith("." + d) for ds in OFFICIAL_BRAND_DOMAINS.values() for d in ds)
    return brand or official_operator(h) is not None


def name_fragments(host: str) -> set[str]:
    """운영자를 가리키는 이름 조각. 보통은 등록 도메인 이름(kc-telegram.com → telegram)에서, 공용 호스팅은 그 아래
    하위 도메인에서만 뽑는다(x-y.pages.dev 의 'pages' 는 호스팅 이름이라 운영자와 무관하다)."""
    h = host.lower().rstrip(".")
    site = site_of(h)
    if on_domain(h, SHARED_HOSTING):
        hosting = next(d for d in SHARED_HOSTING if on_domain(h, (d,)))
        part = h[: -len(hosting)].rstrip(".")
    else:
        part = site.split(".", 1)[0]
    return {t for t in _FRAG_SPLIT.split(part) if len(t) >= 4 and t not in _COMMON_FRAGS and not t.isdigit()}


# 주소 안에서는 짧은 영문 단어(otp)가 다른 낱말 속에 우연히 들어가므로 앵커 글자에서만 찾는다
_URL_CLUES: tuple[str, ...] = tuple(w for w in _CLUES if not (w.isascii() and len(w) < 4))


def _clue(url: str, text: str) -> bool:
    t, u = text.lower(), unquote(url).lower()
    return any(w in t for w in _CLUES) or any(w in u for w in _URL_CLUES)


def _score(url: str, host: str, text: str, source: str, frags: set[str]) -> int:
    """후보 순서 점수: 3 경유 도메인, 2 위협 단서가 있는 링크, 1 조사한 사이트와 이름 조각을 나눠 갖는 도메인, 0 나머지."""
    if source == "via":
        return 3
    if _clue(url, text):
        return 2
    return 1 if frags & name_fragments(host) else 0


def _clean(url: str, allowed_ports: list[int], test_allowlist: list[str]) -> tuple[str, str] | None:
    """(주소, 호스트). 쓸 수 없는 주소(다른 스킴·허용되지 않은 포트·계정 정보 포함 등)면 None."""
    if not isinstance(url, str) or len(url) > 2048:
        return None
    try:
        scheme, host, port = parse_url(url, allowed_ports)
    except BlockedURL:
        return None
    if scheme not in ("http", "https") or not host:
        return None
    if port not in allowed_ports and f"{host}:{port}" not in test_allowlist:
        return None
    # 쿼리·조각은 버린다: 페이지가 링크에 넣은 개인정보(이메일·전화번호·추적값)가 평판 조회·판단 모델로 나가지 않게
    p = urlsplit(url.strip())
    return f"{scheme}://{p.netloc}{p.path or '/'}", host.lower()


def select(start_url: str, final_url: str, nav_chain: list[str], links: list,
           allowed_ports: list[int], test_allowlist: list[str] | None = None) -> list[dict]:
    """후보 목록 {url, host, source, score, text}. source: via(경유 도메인) | link(페이지의 외부 링크).
    links 는 주소 문자열이나 {url, text}(text 는 개인정보를 가린 앵커 글자). 점수가 높은 것부터, 같으면 나온 순서로.

    - 경유 도메인: 시작·최종 사이트가 아닌, 거쳐 간 사이트의 첫 화면(같은 경로는 이미 조사했으므로)
    - 외부 링크: 조사한 사이트들과 다른 사이트를 가리키는 링크. 같은 사이트가 여러 번 나오면 점수가 높은 링크를 남긴다
    """
    visited = [h for h in (urlsplit(u).hostname for u in [start_url, final_url, *nav_chain]) if h]
    visited_sites = {site_of(h) for h in visited}
    end_hosts = [h for h in (urlsplit(start_url).hostname, urlsplit(final_url or start_url).hostname) if h]
    ends = {site_of(h) for h in end_hosts}
    frags = set().union(*(name_fragments(h) for h in end_hosts)) if end_hosts else set()
    best: dict[str, dict] = {}
    order: list[str] = []

    def add(url: str, text: str, source: str):
        c = _clean(url, allowed_ports, test_allowlist or [])
        if c is None:
            return
        url, host = c
        site = site_of(host)
        if _official(host) or site in GENERIC_SITES or (site in SERVICE_HOMES and urlsplit(url).path in ("", "/")):
            return
        if source == "via" and site in ends:
            return
        if source == "link" and site in visited_sites:
            return
        text = text[:TEXT_MAX] if isinstance(text, str) else ""
        if source == "link" and classify_forbidden(ElementInfo(tag="a", href=url, text=text)):
            return  # 결제·다운로드·로그인 링크는 하위 조사가 열지 않게 여기서도 한 번 더 뺀다(수집 쪽과 같은 규칙)
        item = {"url": url, "host": host, "source": source, "score": _score(url, host, text, source, frags),
                "text": text}
        if site not in best:
            order.append(site)
            best[site] = item
        elif item["score"] > best[site]["score"]:
            best[site] = item

    for u in nav_chain:
        p = urlsplit(u)
        if p.hostname:
            add(f"{p.scheme}://{p.netloc}/", "", "via")
    for x in links:
        if isinstance(x, dict):
            add(x.get("url"), x.get("text") or "", "link")
        else:
            add(x, "", "link")
    ranked = sorted(range(len(order)), key=lambda i: (-best[order[i]]["score"], i))
    return [best[order[i]] for i in ranked[:MAX_FOUND]]

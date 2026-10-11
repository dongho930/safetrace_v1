"""연관 후보: 조사 중에 거친 경유 도메인과 페이지의 외부 링크 가운데 더 조사할 곳을 고른다(기획서 2.2 보조 기능).

후보 주소는 조사 대상 페이지에서 온 값이다(공격자가 고를 수 있다). 그래서
- http·https 와 허용 포트만, 길이를 제한해 받는다(목록은 최대 MAX_FOUND 개)
- 사칭 대상이 되는 공식 도메인(브랜드·사행사업자)과 이미 조사한 사이트는 뺀다
- 실제로 열 때는 원래 조사와 같은 안전 게이트·검문 프록시를 거친다(여기서는 고르기만 한다)
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..decision.brands import OFFICIAL_BRAND_DOMAINS
from ..decision.official import official_operator
from ..netguard import BlockedURL, parse_url

MAX_FOUND = 20  # 기록하는 후보 수(사건당)
_SECOND_LEVEL = {"co", "or", "go", "ne", "ac", "re", "pe", "com", "net", "org", "gov", "edu"}


def site_of(host: str) -> str:
    """등록 도메인을 어림한다(예: news.naver.com → naver.com, www.epost.go.kr → epost.go.kr)."""
    h = host.lower().rstrip(".")
    if h.replace(".", "").isdigit() or ":" in h:  # IP 주소는 그대로
        return h
    labels = [x for x in h.split(".") if x]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _official(host: str) -> bool:
    h = host.lower().rstrip(".")
    brand = any(h == d or h.endswith("." + d) for ds in OFFICIAL_BRAND_DOMAINS.values() for d in ds)
    return brand or official_operator(h) is not None


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
    return url, host.lower()


def select(start_url: str, final_url: str, nav_chain: list[str], links: list[str],
           allowed_ports: list[int], test_allowlist: list[str] | None = None) -> list[dict]:
    """후보 목록 {url, host, source}. source: via(경유 도메인) | link(페이지의 외부 링크). 경유 도메인을 앞에 둔다.

    - 경유 도메인: 시작·최종 사이트가 아닌, 거쳐 간 사이트의 첫 화면(같은 경로는 이미 조사했으므로)
    - 외부 링크: 조사한 사이트들과 다른 사이트를 가리키는 링크
    """
    visited = [h for h in (urlsplit(u).hostname for u in [start_url, final_url, *nav_chain]) if h]
    visited_sites = {site_of(h) for h in visited}
    ends = {site_of(h) for h in (urlsplit(start_url).hostname, urlsplit(final_url or start_url).hostname) if h}
    out: list[dict] = []
    seen: set[str] = set()

    def add(url: str, source: str):
        c = _clean(url, allowed_ports, test_allowlist or [])
        if c is None or len(out) >= MAX_FOUND:
            return
        url, host = c
        site = site_of(host)
        if site in seen or _official(host):
            return
        if source == "via" and site in ends:
            return
        if source == "link" and site in visited_sites:
            return
        seen.add(site)
        out.append({"url": url, "host": host, "source": source})

    for u in nav_chain:
        p = urlsplit(u)
        if p.hostname:
            add(f"{p.scheme}://{p.netloc}/", "via")
    for u in links:
        add(u, "link")
    return out

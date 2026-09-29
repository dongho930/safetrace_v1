"""정부 허가 사행사업자 공식 도메인.

화면 글만으로는 공식 사이트와 사칭 사이트를 가릴 수 없으므로, 합법 여부는 도메인으로 코드가 판단한다.
조사 중 거친 도메인이 모두 이 목록에 있을 때만 불법 도박 판단을 정상으로 바꾼다.
"""

from __future__ import annotations

from urllib.parse import urlsplit

OFFICIAL_BETTING_DOMAINS: dict[str, str] = {
    "betman.co.kr": "베트맨(스포츠토토 공식 발매)",
    "sportstoto.co.kr": "스포츠토토",
    "dhlottery.co.kr": "동행복권",
    "kra.co.kr": "한국마사회(경마)",
    "kcycle.or.kr": "경륜",
    "kboat.or.kr": "경정",
}


def official_operator(host: str) -> str | None:
    """host 가 공식 도메인 자체이거나 그 하위 도메인이면 사업자 이름을 돌려준다."""
    h = host.lower().rstrip(".")
    for domain, name in OFFICIAL_BETTING_DOMAINS.items():
        if h == domain or h.endswith("." + domain):
            return name
    return None


def all_official(url: str, final_url: str, domains: list[str]) -> list[str] | None:
    """시작·최종 URL 과 거친 도메인이 모두 공식 도메인이면 사업자 이름 목록, 하나라도 아니면 None."""
    hosts = [urlsplit(url).hostname or "", urlsplit(final_url).hostname or "", *domains]
    names: list[str] = []
    for h in hosts:
        name = official_operator(h) if h else None
        if name is None:
            return None
        if name not in names:
            names.append(name)
    return names

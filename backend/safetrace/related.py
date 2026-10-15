"""연관 후보 자동 사건 생성의 선별 조건(related-sites PR 4b, docs/related-sites.md §6b.2).

원 사건 안의 빠른 하위 조사(최대 3곳, 4단계·40초)를 1차 선별로 쓰고, 아래 조건을 모두 통과한 후보만 API 가 새 사건
(source=related, auto)을 만들어 전체 예산으로 조사한다. 나머지 후보는 담당자가 버튼으로 접수한다(PR 4).

- 시점과 무관한 조건 1~6 은 여기의 순수 함수가 정한다(평가 도구도 같은 함수로 '자동 접수 대상 수'를 센다)
- 시점에 따라 바뀌는 조건 7~9(중복·한도)는 API 가 DB 를 보고 _intake_lock 안에서 정한다
- 후보 값은 조사 대상 페이지에서 온 것이다(공격자가 고를 수 있다). 자동 사건은 하위 조사에서 AI 가 위협으로 본
  후보(원래 사건과 같은 기준) 또는 외부 평판 위험만이라, 공격자가 심은 정상 사이트 링크는 여기서 걸러진다
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .decision.brands import SHARED_HOSTING, SHORTENER_HOSTS, on_domain

AUTO_ACTOR = "system:related"  # 자동 생성 주체(사람 계정·자동화 토큰 이름과 겹치지 않는 내부 이름)
_NOT_THREAT = (None, "benign", "unknown")
_NO_RESULT = ("UNREACHABLE", "BLOCKED", "FAILED")


def target_host(c: dict) -> str:
    """하위 조사가 도착한 호스트(없으면 후보 호스트). 중복 확인·단축 서비스 확인에 쓴다."""
    final = c.get("final_url") if isinstance(c.get("final_url"), str) else ""
    host = c.get("host") if isinstance(c.get("host"), str) else ""
    return ((urlsplit(final).hostname if final else None) or host or urlsplit(str(c.get("url") or "")).hostname
            or "").lower().rstrip(".")[:253]


def skip_reason(parent_source: str, c: dict, *, enabled: bool, threat_min_prob: float) -> str | None:
    """조건 1~6 중 처음 어긋난 이유 코드. 모두 통과하면 None.

    disabled 자동 접수 꺼짐 · depth 연관 사건의 후보(깊이 1) · not_threat 선별 결과가 위협이 아님 ·
    shortener 도착한 곳이 단축 서비스

    명세의 조건 5(이미 차단됨이면 만들지 않음)는 두지 않는다: 회선 차단은 조사 대상 서버가 흉내 낼 수 있는 '추정'이라
    (PR 2 Codex 지적), 그것만으로 자동 조사를 건너뛰면 공격자가 차단된 척해 자동 조사를 피할 수 있다. 정말 막힌 곳이면
    자동 사건이 '접속 불가 · 회선 차단 감지'로 담당자 검토에 간다(부모당 3·대기 10 한도 안)"""
    if not enabled:                                                   # 1
        return "disabled"
    if parent_source == "related":                                    # 2 자동·버튼 자식 모두 손자 사건을 만들지 않는다
        return "depth"
    if not c.get("sub") or c.get("status") in _NO_RESULT:            # 3 선별 결과가 있는 것만
        return "not_threat"
    prob = c.get("probability")
    threat = (c.get("threat") not in _NOT_THREAT and isinstance(prob, (int, float))
              and prob >= threat_min_prob and not c.get("hold"))
    if not (threat or c.get("reputation_match") is True):             # 4 원래 사건이 위협으로 보는 기준과 같게
        return "not_threat"
    if on_domain(target_host(c), SHORTENER_HOSTS):                    # 6 같은 단축 서비스는 같은 조직이 아니다
        return "shortener"
    return None


def auto_targets(parent_source: str, candidates: list, *, enabled: bool, threat_min_prob: float) -> list[tuple[dict, str]]:
    """조건 1~6 을 통과한 후보와 근거(threat | reputation). 순서는 후보 목록 순서."""
    out = []
    for c in candidates if isinstance(candidates, list) else []:
        if not isinstance(c, dict) or not isinstance(c.get("url"), str):
            continue
        if skip_reason(parent_source, c, enabled=enabled, threat_min_prob=threat_min_prob) is None:
            out.append((c, "reputation" if c.get("reputation_match") is True and c.get("threat") in _NOT_THREAT
                        else "threat"))
    return out


# ── 사건 간 연결(related-sites PR 5, §7) ─────────────────────────
SITES_PER_CASE = 30  # 사건 하나에서 남기는 호스트


def link_key(host: str) -> tuple[str, bool] | None:
    """사건을 잇는 열쇠와 공용 호스팅 여부. 잇지 않는 호스트면 None.

    - 단축 서비스는 잇지 않는다(같은 단축 서비스를 썼다고 같은 조직이 아니다)
    - 공식 브랜드·사행사업자 도메인, 흔한 대형 사이트, 서비스 홈도 잇지 않는다(피싱 키트가 봇을 진짜 사이트로 보내거나
      꾸밈으로 단다)
    - 공용 호스팅은 하위 도메인이 다르면 다른 운영자라 호스트가 정확히 같을 때만, 나머지는 등록 도메인으로 잇는다"""
    from .agent.candidates import GENERIC_SITES, SERVICE_HOMES, _official, site_of  # 사이트 계산은 후보 고르기와 같게

    h = (host or "").lower().rstrip(".")[:253]
    if not h or on_domain(h, SHORTENER_HOSTS) or _official(h):
        return None
    if on_domain(h, SHARED_HOSTING):
        return h, True
    site = site_of(h)
    # 서비스 홈(단축 서비스·사이트 빌더의 본 도메인)도 잇지 않는다: 같은 서비스를 썼다고 같은 조직이 아니다
    return None if site in GENERIC_SITES or site in SERVICE_HOMES else (site, False)


def case_sites(url: str, final_url: str | None, threat: dict | None, candidates: list | None) -> list[dict]:
    """끝난 사건 하나에서 이을 호스트 목록 {host, site, role, threat, blocked, generic}. role: start | final | via | link |
    candidate_final. 값은 조사 대상 페이지에서 온 것이라 길이를 자르고 정해진 모양으로만 만든다."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    main_threat = threat.get("threat") if isinstance(threat, dict) and isinstance(threat.get("threat"), str) else None

    def add(u, role, th=None, blocked=False):
        host = urlsplit(u).hostname if isinstance(u, str) and u else None
        key = link_key(host or "")
        if key is None or (host, role) in seen or len(out) >= SITES_PER_CASE:
            return
        seen.add((host, role))
        out.append({"host": host[:253], "site": key[0][:253], "role": role,
                    "threat": th[:32] if isinstance(th, str) else None, "blocked": blocked is True, "generic": key[1]})

    add(url, "start", main_threat)
    add(final_url, "final", main_threat)
    for c in candidates if isinstance(candidates, list) else []:
        if not isinstance(c, dict):
            continue
        role = "via" if c.get("source") == "via" else "link"
        add(c.get("url"), role, c.get("threat") if c.get("sub") else None, c.get("blocked"))
        if c.get("sub"):
            add(c.get("final_url"), "candidate_final", c.get("threat"), c.get("blocked"))
    return out


def groups(case_sites_rows: list[tuple[str, str, bool]], min_cases: int = 2) -> list[set[str]]:
    """(사건 id, 열쇠, 공용 호스팅) 목록을 열쇠로 이어(합집합 찾기) 사건이 min_cases 개 이상인 묶음."""
    parent: dict[str, str] = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    by_key: dict[str, str] = {}
    for cid, key, _ in case_sites_rows:
        find(cid)
        if key in by_key:
            parent[find(cid)] = find(by_key[key])
        else:
            by_key[key] = cid
    out: dict[str, set[str]] = {}
    for cid in parent:
        out.setdefault(find(cid), set()).add(cid)
    return [g for g in out.values() if len(g) >= min_cases]


def backfill(store) -> int:
    """종료된 사건 전부의 연결 호스트를 다시 쓴다(여러 번 돌려도 같은 결과). 반환: 쓴 사건 수."""
    from sqlalchemy import select

    from .store import TERMINAL, Case

    with store.session() as s:
        ids = list(s.scalars(select(Case.id).where(Case.status.in_(TERMINAL))))
    for cid in ids:
        store.write_sites(cid)
    return len(ids)


if __name__ == "__main__":
    import sys

    if sys.argv[1:] != ["backfill"]:
        raise SystemExit("사용법: python -m safetrace.related backfill")
    from .config import get_settings
    from .store import Store

    print(f"연결 호스트를 다시 쓴 사건: {backfill(Store(get_settings().database_url))}건")

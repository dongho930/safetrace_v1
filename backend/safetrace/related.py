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

from .decision.brands import SHORTENER_HOSTS, on_domain

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

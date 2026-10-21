"""연관 후보 자동 사건 생성의 선별 조건(related-sites PR 4b, docs/related-sites.md §6b.2).

원 사건 안의 빠른 하위 조사(최대 3곳, 4단계·40초)를 1차 선별로 쓰고, 아래 조건을 모두 통과한 후보만 API 가 새 사건
(source=related, auto)을 만들어 전체 예산으로 조사한다. 나머지 후보는 담당자가 버튼으로 접수한다(PR 4).

- 시점과 무관한 조건 1~6 은 여기의 순수 함수가 정한다(평가 도구도 같은 함수로 '자동 접수 대상 수'를 센다)
- 시점에 따라 바뀌는 조건 7~9(중복·한도)는 API 가 DB 를 보고 _intake_lock 안에서 정한다
- 후보 값은 조사 대상 페이지에서 온 것이다(공격자가 고를 수 있다). 자동 사건은 하위 조사에서 AI 가 위협으로 본
  후보(원래 사건과 같은 기준) 또는 외부 평판 위험만이라, 공격자가 심은 정상 사이트 링크는 여기서 걸러진다
"""

from __future__ import annotations

import hashlib
import hmac
import re
from urllib.parse import urlsplit

from .decision.brands import SHARED_HOSTING, SHORTENER_HOSTS, _plain, on_domain, site_of
from .netguard import is_public_ip

AUTO_ACTOR = "system:related"  # 자동 생성 주체(사람 계정·자동화 토큰 이름과 겹치지 않는 내부 이름)
_NOT_THREAT = (None, "benign", "unknown")
_HAS_RESULT = ("COMPLETED", "REVIEW_REQUIRED")  # 하위 조사가 화면을 보고 판단한 상태(접속 불가·차단·실패는 결과 없음)

# ── 피싱 키트가 링크한 진짜 브랜드 사이트(개선 후보 9) ─────────────────────────
# 피싱 키트는 사칭한 브랜드의 진짜 사이트를 링크한다(비밀번호 재설정·이용 약관 등). 하위 조사가 그 진짜 사이트를 위협으로
# 보면(OpenPhish 2026-10-20 OCA 사칭 → oca.com.uy 0.6, 10/21 Wells Fargo 사칭 → wellsfargo.com 0.61~0.64, 보류 없음)
# 진짜 사이트를 조사하는 자동 사건이 생긴다. 확률로는 가를 수 없다(진짜 위협 0.62 와 겹침).
# 자동 접수에서 뺄지는 페이지가 정할 수 없는 값(서버가 가진 목록)으로만 정한다. 원 사건 제목과 이름이 같다는 것은 페이지가
# 정한 값이라(Codex 1·2회차: 제목을 'Secure Portal' 로 하고 자기 피싱 사이트 secure.example 을 링크하면 빠졌다) 참고
# 표시(brand_name)로만 남기고, 평가 결과에서 그런 위협 후보를 사람이 확인해 진짜 사이트면 아래 목록에 보탠다
KIT_LINKED_REAL_SITES: tuple[str, ...] = (  # 공식 브랜드 목록(decision/brands.py) 밖, 관찰하고 진짜임을 확인한 것만
    "wellsfargo.com",               # 2026-10-21 Wells Fargo 사칭 키트 → oam.wellsfargo.com(하위 조사 피싱 0.61~0.64)
    "oca.com.uy", "ocablue.uy",     # 2026-10-20 OCA 사칭 키트 → ocablue.uy → micuentanuevo.oca.com.uy(피싱 0.6)
    "bancolombia.com",              # 2026-10-21 Bancolombia 사칭 키트 → www.bancolombia.com(하위 조사 정상)
)
BRAND_SITE_MAX_PROB = 0.7  # 목록의 사이트라도 이 확신 이상인 위협·평판 위험은 자동 접수(공식 도메인의 사용자 콘텐츠)
_NAME_WORD = re.compile(r"[a-z0-9]+")
_LABEL = re.compile(r"[a-z0-9]{3,63}")  # 하이픈 없는 등록 도메인 이름만(wells-fargo-login 같은 사칭 이름은 맞추지 않는다)
_NAME_SPAN = 3  # 이어 붙이는 낱말 수('Wells Fargo' → wellsfargo, 'Bank of America' → bankofamerica)


def _plain_host(host: str) -> str:
    """비교할 호스트. 내부·예약 IP·단축 서비스·공용 호스팅이면 빈 값(운영자를 가리키지 않는다)."""
    h = (host or "").lower().rstrip(".")[:253]
    if not h or _non_public_ip(h) or on_domain(h, SHORTENER_HOSTS) or on_domain(h, SHARED_HOSTING):
        return ""
    return h


def real_brand_site(host: str) -> bool:
    """도착한 호스트가 진짜 브랜드 사이트인지(서버가 가진 목록만): 공식 브랜드·사행사업자 도메인 또는
    KIT_LINKED_REAL_SITES. 자동 연관 사건 조건 10 이 쓴다."""
    from .agent.candidates import _official  # 공식 판정은 후보 고르기·사건 연결과 같게

    h = _plain_host(host)
    return bool(h) and (_official(h) or on_domain(h, KIT_LINKED_REAL_SITES))


def claimed_names(titles: object) -> frozenset[str]:
    """원 사건 화면 제목들이 내세우는 이름: 꾸민 글자를 풀고 영문·숫자 낱말과 이어진 낱말 2~3개를 붙인 것.
    'Wells Fargo - Sign On' → wells, fargo, sign, on, wellsfargo, fargosign, ... 제목은 조사 대상 페이지가 정한 값이다."""
    out: set[str] = set()
    for t in titles[-20:] if isinstance(titles, list) else []:
        if not isinstance(t, str):
            continue
        words = _NAME_WORD.findall(_plain(t[:200]))
        for i in range(len(words)):
            for j in range(i + 1, min(i + _NAME_SPAN, len(words)) + 1):
                out.add("".join(words[i:j]))
    return frozenset(out)


def brand_name(host: str, names: frozenset[str] | set[str], *, gambling: bool = False) -> bool:
    """참고 표시: 도착한 사이트의 등록 도메인 이름(하이픈 없는 3자 이상, 숫자뿐 아님)이 원 사건 제목이 내세운 이름과
    같은지(wellsfargo.com ← 'Wells Fargo', oca.com.uy ← 'OCA'). 이름을 품거나 하이픈 든 도메인(wellsfargo-login)은
    아니다. 원 사건이 불법 도박이면 보지 않는다(도박 복제가 내세우는 브랜드는 그 자체가 도박).
    제목은 페이지가 정하므로 자동 접수 결정에 쓰지 않는다 — 평가 도구가 이 표시가 붙은 위협 후보를 모아 보여 주고,
    사람이 진짜 사이트인지 확인해 KIT_LINKED_REAL_SITES 에 보탠다"""
    h = _plain_host(host)
    label = site_of(h).split(".")[0] if h else ""
    return not gambling and bool(_LABEL.fullmatch(label)) and not label.isdigit() and label in names


def target_host(c: dict) -> str:
    """하위 조사가 도착한 호스트(없으면 후보 호스트). 중복 확인·단축 서비스 확인에 쓴다."""
    final = c.get("final_url") if isinstance(c.get("final_url"), str) else ""
    host = c.get("host") if isinstance(c.get("host"), str) else ""
    return ((urlsplit(final).hostname if final else None) or host or urlsplit(str(c.get("url") or "")).hostname
            or "").lower().rstrip(".")[:253]


def skip_reason(parent_source: str, c: dict, *, enabled: bool, threat_min_prob: float) -> str | None:
    """조건 1~6 중 처음 어긋난 이유 코드. 모두 통과하면 None.

    disabled 자동 접수 꺼짐 · depth 연관 사건의 후보(깊이 1) · not_threat 선별 결과가 위협이 아님 ·
    shortener 도착한 곳이 단축 서비스 · brand_site 피싱 키트가 링크한 진짜 브랜드 사이트(조건 10)

    조건 10 은 서버가 가진 목록(real_brand_site)으로만 정한다. 원 사건 제목과 이름이 같다는 표시(brand_name)는 페이지가
    정한 값이라 쓰지 않는다(Codex 1·2회차). 목록의 사이트라도 위협 확신이 BRAND_SITE_MAX_PROB 이상이거나 외부 평판이
    위험이면 자동 접수한다(공식 도메인에 올라온 사용자 콘텐츠 — 설문 양식 피싱 등)

    명세의 조건 5(이미 차단됨이면 만들지 않음)는 두지 않는다: 회선 차단은 조사 대상 서버가 흉내 낼 수 있는 '추정'이라
    (PR 2 Codex 지적), 그것만으로 자동 조사를 건너뛰면 공격자가 차단된 척해 자동 조사를 피할 수 있다. 정말 막힌 곳이면
    자동 사건이 '접속 불가 · 회선 차단 감지'로 담당자 검토에 간다(부모당 3·대기 10 한도 안)"""
    if not enabled:                                                   # 1
        return "disabled"
    if parent_source == "related":                                    # 2 자동·버튼 자식 모두 손자 사건을 만들지 않는다
        return "depth"
    if not c.get("sub") or c.get("status") not in _HAS_RESULT:       # 3 선별 결과가 있는 것만(상태가 없어도 아님)
        return "not_threat"
    prob = c.get("probability")
    threat = (c.get("threat") not in _NOT_THREAT and isinstance(prob, (int, float))
              and prob >= threat_min_prob and not c.get("hold"))
    if not (threat or c.get("reputation_match") is True):             # 4 원래 사건이 위협으로 보는 기준과 같게
        return "not_threat"
    if on_domain(target_host(c), SHORTENER_HOSTS):                    # 6 같은 단축 서비스는 같은 조직이 아니다
        return "shortener"
    if (real_brand_site(target_host(c)) and c.get("reputation_match") is not True  # 10 피싱 키트가 링크한 진짜 사이트
            and isinstance(prob, (int, float)) and prob < BRAND_SITE_MAX_PROB):
        return "brand_site"
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
# 와일드카드 DNS(이름에 든 IP 로 해석되는 서비스): 하위 도메인마다 가리키는 서버가 달라 공용 호스팅처럼 호스트가 같을 때만
# 잇는다. 관찰한 것만: 로컬 DB 의 공격 시나리오 사건(127.0.0.1.nip.io·169.254.169.254.nip.io 24건이 nip.io 하나로 묶였다)
WILDCARD_DNS: tuple[str, ...] = ("nip.io",)


def _non_public_ip(host: str) -> bool:
    """내부·예약 IP 주소(127.0.0.1·10.x·169.254.x·::1 등, SSRF 검사와 같은 기준). 이름이면 False."""
    try:
        return not is_public_ip(host)
    except ValueError:
        return False


def link_key(host: str) -> tuple[str, bool] | None:
    """사건을 잇는 열쇠와 공용 호스팅 여부. 잇지 않는 호스트면 None.

    - 단축 서비스는 잇지 않는다(같은 단축 서비스를 썼다고 같은 조직이 아니다)
    - 공식 브랜드·사행사업자 도메인, 흔한 대형 사이트, 서비스 홈도 잇지 않는다(피싱 키트가 봇을 진짜 사이트로 보내거나
      꾸밈으로 단다)
    - 내부·예약 IP 주소도 잇지 않는다(피싱 키트에 남은 개발용 링크·내부망으로 넘기는 링크는 운영자의 흔적이 아니다)
    - 공용 호스팅·와일드카드 DNS 는 하위 도메인이 다르면 다른 운영자·서버라 호스트가 정확히 같을 때만, 나머지는 등록
      도메인으로 잇는다"""
    from .agent.candidates import GENERIC_SITES, SERVICE_HOMES, _official, site_of  # 사이트 계산은 후보 고르기와 같게

    h = (host or "").lower().rstrip(".")[:253]
    if not h or on_domain(h, SHORTENER_HOSTS) or _official(h) or _non_public_ip(h):
        return None
    if on_domain(h, SHARED_HOSTING) or on_domain(h, WILDCARD_DNS):
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


# ── 운영 정보·키트 지문으로 잇기(분석가 업무, agent/intel.py) ─────────────────────────
# 같은 텔레그램 아이디·계좌·수집 서버·화면 구조가 나온 사건끼리 잇는다. 값은 조사 대상 페이지가 적은 것이라(남의 연락처를
# 적어 둘 수 있다) 판단·자동 연관 사건에는 쓰지 않고 묶음을 보여 주는 데만 쓴다. case_sites 에 role contact·kit 으로 둔다
INTEL_ROLES = ("contact", "kit")
INTEL_PER_CASE = 24
# 입력 양식이 보내는 곳 중 운영자를 가리키지 않는 위젯(관찰한 것만): 2026-10-22 Meta 사칭 vercel 키트 화면의 Google 번역 위젯
WIDGET_FORM_HOSTS: tuple[str, ...] = ("translate.googleapis.com",)
# 열쇠는 서버 비밀키 HMAC, 보이는 값은 끝 4자리만(연관 묶음·CSV 는 열람자도 본다). 키 없는 해시면 가린 값과 함께 공개된
# 열쇠에 가운데 네 자리(1만 개)를 대입해 원래 번호를 찾을 수 있다(Codex 지적)
_PII_KINDS = ("phone", "account", "whatsapp")
_NO_KIT = (None, "benign", "unknown")  # 키트 지문은 위협으로 본 사건만(오류·주차·봇 확인 화면 같은 흔한 틀을 피한다)
HASH32 = re.compile(r"[0-9a-f]{32}")


def intel_key(kind: object, value: object, secret: bytes) -> tuple[str, str] | None:
    """운영 정보 하나의 (이을 열쇠, 보일 값). 잇지 않으면 None. 입력값을 보내는 곳은 주소 전체(쿼리 빼고)가 같을 때만
    잇는다: 등록 도메인으로 이으면 script.google.com·workers.dev 같은 공용 서비스로 남남끼리 묶인다. 내부 주소는 잇지 않는다."""
    from .agent.intel import KINDS, mask

    if kind not in KINDS or not isinstance(value, str) or not value:
        return None
    value = value[:200]
    if kind == "form":
        u = urlsplit(value)
        host = (u.hostname or "").lower()
        # 공식 브랜드·단축 서비스·흔한 대형 사이트·내부 주소(연결 열쇠가 없는 곳)와 위젯으로 보내는 양식은 잇지 않는다:
        # 피싱 키트가 진짜 facebook.com 으로 보내는 양식을 달아 두면 남남끼리 묶인다(2026-10-22 Meta 키트에서 관찰)
        if not host or link_key(host) is None or on_domain(host, WIDGET_FORM_HOSTS):
            return None
        # 열쇠는 주소 전체(쿼리 빼고)의 비밀키 HMAC, 보이는 값은 호스트만(경로에 개인정보가 들 수 있다, Codex 2회차)
        endpoint = f"{host}{u.path or '/'}"[:200]
        mac = hmac.new(secret, f"safetrace.intel-link/1|form|{endpoint}".encode(), hashlib.sha256).hexdigest()[:24]
        return f"form:{host}:{mac}", host
    if kind in _PII_KINDS:
        mac = hmac.new(secret, f"safetrace.intel-link/1|{kind}|{value}".encode(), hashlib.sha256).hexdigest()[:24]
        return f"{kind}:{mac}", mask(kind, value)
    return f"{kind}:{value}", value


def intel_rows(records: list[dict], threat: str | None, secret: bytes) -> list[dict]:
    """검증한 체인의 원래 조사 intel 기록에서 이을 열쇠 줄(case_sites 모양). 정상으로 본 사건은 잇지 않는다."""
    if threat == "benign":
        return []
    out: list[dict] = []
    seen: set[str] = set()

    def add(site: str, host: str, role: str) -> None:
        if site not in seen and len(out) < INTEL_PER_CASE:
            seen.add(site)
            out.append({"host": host[:253], "site": site[:253], "role": role, "threat": threat, "blocked": False,
                        "generic": False})

    for r in records:
        d = r.get("data") if isinstance(r, dict) else None
        if r.get("kind") != "intel" or not isinstance(d, dict) or isinstance(d.get("sub"), int):
            continue
        for x in d.get("items") if isinstance(d.get("items"), list) else []:
            k = intel_key(x.get("kind"), x.get("value"), secret) if isinstance(x, dict) else None
            if k:
                add(k[0], k[1], "contact")
        kit, url = d.get("kit"), d.get("url")
        host = (urlsplit(url).hostname or "").lower() if isinstance(url, str) else ""
        if threat in _NO_KIT or not isinstance(kit, dict) or link_key(host) is None:
            continue  # 공식·단축 서비스·흔한 대형 사이트 화면의 구조는 운영자를 가리키지 않는다
        for part in ("dom", "res"):
            h = kit.get(part)
            if isinstance(h, str) and HASH32.fullmatch(h):
                add(f"kit:{part}:{h}", host, "kit")
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

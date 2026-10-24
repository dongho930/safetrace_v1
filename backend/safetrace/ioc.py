"""IOC 내보내기(분석가 업무): 담당자가 위협으로 확정한 사건의 지표를 다른 기관·차단 장비가 읽는 형식(CSV·STIX 2.1)으로.

- 담당자의 **현재 판정이 위협**인 사건만 넣는다(AI 판단·보류·정상 확정은 넣지 않는다). 기간은 확정 시각 기준
- 지표: 신고 주소·최종 주소의 URL(쿼리·조각·사용자 정보 뺌)과 호스트(도메인·IP). 운영 정보(텔레그램·입력값을 보내는 곳·
  전화·계좌)는 따로 고를 때만, 검증한 증거 체인의 원래 조사 기록에서
- 운영자를 가리키지 않는 곳은 뺀다: 공식 브랜드·사행사업자 도메인(피싱 키트가 봇을 진짜 사이트로 보낸다), 흔한 대형 사이트,
  사이트 빌더·서비스 홈, 내부·예약 IP. 단축 서비스·공용 호스팅 본 도메인은 호스트 지표로 내지 않는다(단축 주소 자체는
  신고 주소일 때만 URL 로)
- 주소에 개인정보 모양(전화·이메일·계좌 등)이 있으면 그 지표는 내지 않는다(받는 쪽에 피해자 정보가 나가지 않게)
- 값은 조사 대상 페이지에서 온 것이라 CSV 는 수식 시작 문자를 막고(CWE-1236), STIX 패턴은 따옴표·역슬래시를 이스케이프한다
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import uuid
from collections import Counter
from datetime import UTC, datetime
from urllib.parse import unquote, urlsplit

from .decision.brands import SHARED_HOSTING, SHORTENER_HOSTS, on_domain, site_of
from .masking import mask_pii
from .related import WIDGET_FORM_HOSTS

DAYS_MAX = 90
CASES_MAX = 1000  # 한 번에 내보내는 사건(확정 시각 최신순)
CHAIN_CASES_MAX = 200  # 증거 체인을 검증해 읽는 사건(운영 정보·단축 URL 목적지, 검증에 파일 해시가 들어 비싸다)
INDICATORS_MAX = 5000
CASE_IDS_PER_ROW = 20
VALUE_MAX = 2048

NETWORK_TYPES = ("url", "domain", "ipv4", "ipv6")
CONTACT_TYPES = ("telegram", "kakao", "line", "whatsapp", "discord", "phone", "account", "form")  # agent/intel.KINDS
TYPE_KO = {"url": "URL", "domain": "도메인", "ipv4": "IPv4", "ipv6": "IPv6", "telegram": "텔레그램", "kakao": "카카오톡",
           "line": "라인", "whatsapp": "왓츠앱", "discord": "디스코드", "phone": "휴대전화", "account": "입금 계좌",
           "form": "입력값을 보내는 곳"}
ROLE_KO = {"start": "신고 주소", "landing": "단축 URL 목적지", "final": "최종 주소", "contact": "페이지에 적힌 운영 정보"}
EXCLUDED_KO = {"official": "공식 브랜드·사행사업자 도메인", "generic": "흔한 대형 사이트", "service": "사이트 빌더·서비스 홈",
               "internal": "내부·예약 IP", "shortener": "단축 서비스(호스트)", "shortener_page": "단축 서비스의 안내 화면",
               "shared_root": "공용 호스팅 본 도메인", "elsewhere": "다른 사이트의 최종 주소(누른 링크일 수 있음)",
               "unverified_destination": "단축 URL 목적지를 확인하지 못함", "widget": "입력 위젯(번역 등)",
               "pii": "개인정보 모양", "format": "형식 오류"}
CSV_HEADER = ["유형", "값", "위협 유형", "근거", "사건 수", "사건 id", "처음 확정(UTC)", "마지막 확정(UTC)", "연관 묶음"]

THREAT_KO = {"phishing": "피싱", "scam": "사기", "illegal_gambling": "불법 도박", "malware": "악성코드"}

_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://safetrace.invalid/stix")  # 같은 값은 내보낼 때마다 같은 STIX id
_IDENTITY_AT = "2026-10-24T00:00:00.000Z"
_BS = chr(92)  # 역슬래시(소스에 escape 로 쓰지 않는다)


def _host_reason(host: str) -> str | None:
    """이 호스트가 운영자를 가리키지 않는 까닭(뺄 이유). 내보내도 되면 None."""
    from .agent.candidates import GENERIC_SITES, PLATFORM_SITES, SERVICE_HOMES, _official
    from .related import _non_public_ip

    if _non_public_ip(host) or "." not in host.strip("[]").replace(":", "."):
        return "internal"  # 내부·예약 IP 와 점 없는 이름(시험 서버 testpages·localhost 같은 내부 이름)
    if _official(host):
        return "official"
    site = site_of(host)
    if site in GENERIC_SITES:
        return "generic"
    if site in SERVICE_HOMES or site in PLATFORM_SITES:
        return "service"
    return None


def _clean_value(v: str) -> str | None:
    """내보낼 값의 모양: 길이 상한, 보이는 글자만(공백·제어·방향 바꿈 문자 없음)."""
    if not v or len(v) > VALUE_MAX or not v.isprintable() or any(ch.isspace() for ch in v):
        return None
    return v


def _digest(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:16]


_DECODE_MAX = 3


def _has_pii(v: str) -> bool:
    """개인정보 모양이 있는지. URL 인코딩을 여러 번 한 값(alice%2540example.com)도 풀면서 본다(Codex 1회차 F3).
    _DECODE_MAX 번 풀어도 더 풀리는 값은 개인정보가 숨어 있을 수 있어 있다고 본다(내보내지 않는다)."""
    cur = v
    for _ in range(_DECODE_MAX):
        nxt = unquote(cur)
        if mask_pii(cur) != nxt:  # mask_pii 는 '%' 가 있으면 한 번 풀어서 본다(runner._has_pii 와 같다)
            return True
        if nxt == cur:
            return False
        cur = nxt
    return unquote(cur) != cur


def _ascii_host(host: str) -> str | None:
    h = host.lower().rstrip(".")
    try:
        return h.encode("idna").decode("ascii") if not h.isascii() else h
    except UnicodeError:
        return None


def _same_site_key(host: str) -> str:
    return host if on_domain(host, SHARED_HOSTING) else site_of(host)


def _host_of(u: object) -> str:
    try:
        return _ascii_host(urlsplit(u).hostname or "") or "" if isinstance(u, str) else ""
    except ValueError:
        return ""


def needs_landing(url: str | None, final_url: str | None) -> bool:
    """단축 URL 사건인데 최종 주소가 단축 서비스 밖이라 목적지(첫 화면)를 체인에서 확인해야 하는지."""
    start, final = _host_of(url), _host_of(final_url)
    return bool(start) and on_domain(start, SHORTENER_HOSTS) and bool(final) and final != start


def landing(records: list[dict]) -> str | None:
    """검증한 체인(판정이 본 범위)의 원래 조사 첫 관찰 화면 주소: 자동 이동이 끝나고 아무것도 누르기 전의 화면."""
    for r in records:
        d = r.get("data") if isinstance(r, dict) else None
        if r.get("kind") == "observe" and isinstance(d, dict) and not isinstance(d.get("sub"), int):
            return d["url"] if isinstance(d.get("url"), str) else None
    return None


def _plain_reason(host: str) -> str | None:
    return _host_reason(host) or ("shared_root" if host in SHARED_HOSTING else None)


def network_indicators(url: str | None, final_url: str | None,
                       landing: str | None = None) -> tuple[list[tuple[str, str, str]], set[tuple[str, str, str]]]:
    """신고 주소·최종 주소에서 (유형, 값, 근거) 목록과 뺀 것 {(이유, 유형, 값)}.

    최종 주소는 조사가 끝난 화면이라 에이전트가 누른 링크의 다른 사이트일 수 있다(로컬 사건에서 관찰: 피싱 화면의 연락
    버튼 → api.whatsapp.com, 가짜 거래소 화면의 링크 → 진짜 거래소). 그래서 기준 사이트와 같은 사이트(공용 호스팅은 같은
    호스트)일 때만 내고, 다른 사이트면 'elsewhere' 로 센다. 기준은 신고 주소, 신고 주소가 단축 URL 이면 그 목적지인
    landing(검증한 체인의 첫 관찰 화면, Codex 1회차 F2) — landing 이 없으면 목적지를 확인하지 못해 최종 주소를 내지 않는다."""
    out: list[tuple[str, str, str]] = []
    excluded: set[tuple[str, str, str]] = set()
    start_host = _host_of(url)
    anchor: str | None = start_host
    todo: list[tuple[str, str | None]] = [("start", url)]
    if start_host and on_domain(start_host, SHORTENER_HOSTS):
        lh = _host_of(landing)
        anchor = lh if lh and lh != start_host else None
        if anchor:
            todo.append(("landing", landing))
    fh = _host_of(final_url)
    if fh and fh != start_host and not _plain_reason(fh):  # 공식·흔한 사이트 등이면 아래에서 그 이유로 센다
        if anchor is None:
            excluded.add(("unverified_destination", "domain", fh))
        elif _same_site_key(fh) != _same_site_key(anchor):
            excluded.add(("elsewhere", "domain", fh))
        else:
            todo.append(("final", final_url))
    elif fh:
        todo.append(("final", final_url))
    for role, u in todo:
        if not isinstance(u, str) or not u:
            continue
        try:
            p = urlsplit(u.strip())
            port = p.port
        except ValueError:
            excluded.add(("format", "url", u[:200]))
            continue
        host = _ascii_host(p.hostname or "")
        if p.scheme not in ("http", "https") or not host:
            excluded.add(("format", "url", u[:200]))
            continue
        reason = _plain_reason(host)
        if reason:  # 공용 호스팅 본 도메인(pages.dev 자체)의 화면도 운영자의 것이 아니다
            excluded.add((reason, "domain", host))
            continue
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            ip = None
        shown = f"[{ip}]" if ip is not None and ip.version == 6 else host
        netloc = shown + (f":{port}" if port and port != {"http": 80, "https": 443}[p.scheme] else "")
        full = _clean_value(f"{p.scheme}://{netloc}{p.path or '/'}")
        shortener = on_domain(host, SHORTENER_HOSTS)
        if full is None:
            excluded.add(("format", "url", u[:200]))
        elif _has_pii(full):
            excluded.add(("pii", "url", _digest(full)))  # 개인정보가 든 값은 요약에도 남기지 않는다(해시로만 센다)
        elif shortener and role != "start":
            excluded.add(("shortener_page", "url", full))  # 단축 서비스의 경고·정지 화면 주소는 지표가 아니다
        else:
            out.append(("url", full, role))
        if shortener:
            excluded.add(("shortener", "domain", host))
        elif ip is not None:
            out.append((f"ipv{ip.version}", str(ip), role))
        elif _clean_value(host) is None:
            excluded.add(("format", "domain", host[:200]))
        elif _has_pii(host):
            excluded.add(("pii", "domain", _digest(host)))
        else:
            out.append(("domain", host, role))
    return out, excluded


def contact_indicators(items: list[dict]) -> tuple[list[tuple[str, str, str]], set[tuple[str, str, str]]]:
    """검증한 체인의 운영 정보(main._intel_of 의 items: kind·value)에서 (유형, 값, 근거) 목록과 뺀 것."""
    out: list[tuple[str, str, str]] = []
    excluded: set[tuple[str, str, str]] = set()
    for x in items if isinstance(items, list) else []:
        kind, value = (x.get("kind"), x.get("value")) if isinstance(x, dict) else (None, None)
        if kind not in CONTACT_TYPES or not isinstance(value, str) or _clean_value(value) is None:
            continue
        if kind == "form":  # 입력값을 보내는 곳: 공식·흔한 사이트·내부 주소로 보내는 양식은 운영자의 서버가 아니다
            try:
                host = _ascii_host(urlsplit(value).hostname or "")
            except ValueError:
                host = None
            reason = "format" if not host else _host_reason(host) or ("widget" if on_domain(host, WIDGET_FORM_HOSTS) else None)
            if reason:
                excluded.add((reason, "form", host or "-"))
                continue
            if _has_pii(value):  # 수집할 때 한 번 가렸지만 여러 번 인코딩한 값은 남을 수 있다(Codex 1회차 F3)
                excluded.add(("pii", "form", _digest(value)))
                continue
        out.append((kind, value, "contact"))
    return out, excluded


def contact_url(kind: str, value: str) -> str | None:
    """운영 정보를 STIX url 지표로 쓸 수 있는 주소. 표준 형식이 없는 전화·계좌·왓츠앱 번호, 카카오톡 아이디는 None(CSV 에만)."""
    if kind == "telegram":
        return f"https://t.me/{value}"
    if kind == "kakao" and value.startswith("o/"):
        return f"https://open.kakao.com/{value}"
    if kind == "kakao" and value.startswith("_"):
        return f"https://pf.kakao.com/{value}"
    if kind == "line":
        return f"https://line.me/ti/p/{value}"
    if kind == "discord":
        return f"https://discord.gg/{value}"
    if kind == "form" and value.startswith(("http://", "https://")):
        return value
    return None


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def stamp(dt: datetime) -> str:
    """STIX 시각(UTC, 밀리초)."""
    d = _utc(dt)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def collect(cases: list[dict]) -> tuple[list[dict], Counter, bool]:
    """사건 {id, url, final_url, threat, at, contacts(목록 또는 None)} 목록에서 값마다 하나로 모은 지표와 뺀 이유별 수.
    반환: (지표, 뺀 것, 지표 상한에서 잘랐는지). 지표: {type, value, roles, threats, cases, first, last}"""
    acc: dict[tuple[str, str], dict] = {}
    excluded: set[tuple[str, str, str]] = set()
    truncated = False
    for c in cases:
        found, ex = network_indicators(c["url"], c.get("final_url"), c.get("landing"))
        excluded |= ex
        if c.get("contacts") is not None:
            more, ex = contact_indicators(c["contacts"])
            found, excluded = found + more, excluded | ex
        for typ, value, role in found:
            x = acc.get((typ, value))
            if x is None:
                if len(acc) >= INDICATORS_MAX:
                    truncated = True
                    continue
                x = acc[(typ, value)] = {"type": typ, "value": value, "roles": set(), "threats": set(), "cases": [],
                                         "first": c["at"], "last": c["at"]}
            x["roles"].add(role)
            x["threats"].add(c["threat"])
            if c["id"] not in x["cases"]:
                x["cases"].append(c["id"])
            x["first"], x["last"] = min(x["first"], c["at"]), max(x["last"], c["at"])
    return list(acc.values()), Counter(r for r, _, _ in excluded), truncated


def group_keys(groups: list[set[str]]) -> dict[str, str]:
    """사건 id → 연관 묶음 열쇠(묶음 사건 id 들의 해시 16자리)."""
    out: dict[str, str] = {}
    for g in groups:
        key = hashlib.sha256("|".join(sorted(g)).encode()).hexdigest()[:16]
        for cid in g:
            out[cid] = key
    return out


def _cell(v: object) -> str:
    """CSV 칸: 수식 시작 문자 앞에 ' 를 붙인다(CWE-1236, api.main._csv_cell 과 같다)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(indicators: list[dict], case_group: dict[str, str]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(CSV_HEADER)
    for x in indicators:
        groups = sorted({case_group[c] for c in x["cases"] if c in case_group})
        w.writerow([_cell(v) for v in (
            x["type"], x["value"], " ".join(sorted(x["threats"])), " ".join(ROLE_KO[r] for r in sorted(x["roles"])),
            len(x["cases"]), " ".join(x["cases"][:CASE_IDS_PER_ROW]), stamp(x["first"]), stamp(x["last"]),
            " ".join(groups))])
    return chr(0xFEFF) + buf.getvalue()  # 표 계산 프로그램이 UTF-8 로 열게


def _quote(v: str) -> str:
    """STIX 패턴의 문자열 값: 역슬래시와 작은따옴표를 이스케이프한다(값이 패턴을 끝내고 조건을 덧붙이지 못하게)."""
    return "'" + v.replace(_BS, _BS + _BS).replace("'", _BS + "'") + "'"


def stix_pattern(typ: str, value: str) -> str | None:
    if typ == "url":
        return f"[url:value = {_quote(value)}]"
    if typ == "domain":
        return f"[domain-name:value = {_quote(value)}]"
    if typ in ("ipv4", "ipv6"):
        return f"[{typ}-addr:value = {_quote(value)}]"
    u = contact_url(typ, value)
    return f"[url:value = {_quote(u)}]" if u else None


def _sid(kind: str, *parts: str) -> str:
    """같은 값이면 늘 같은 STIX id(받는 쪽이 중복을 거른다). SDO·SRO 의 id 는 UUIDv4 모양이어야 해서(STIX 2.1 2.9)
    해시에서 만든 16바이트에 v4 의 판·변형 비트를 붙인다."""
    digest = hashlib.sha256("|".join((str(_NS), kind, *parts)).encode()).digest()
    return f"{kind}--{uuid.UUID(bytes=digest[:16], version=4)}"


IDENTITY_ID = _sid("identity", "safetrace")


def to_stix(indicators: list[dict], case_group: dict[str, str]) -> tuple[dict, int]:
    """STIX 2.1 묶음(identity·indicator·campaign·relationship). 반환: (묶음, STIX 형식이 없어 뺀 운영 정보 수)."""
    objects: list[dict] = [{"type": "identity", "spec_version": "2.1", "id": IDENTITY_ID, "created": _IDENTITY_AT,
                            "modified": _IDENTITY_AT, "name": "SafeTrace", "identity_class": "system"}]
    campaigns: dict[str, dict] = {}
    rels: list[dict] = []
    skipped = 0
    for x in indicators:
        pattern = stix_pattern(x["type"], x["value"])
        if pattern is None:
            skipped += 1
            continue
        iid = _sid("indicator", x["type"], x["value"])
        first, last = stamp(x["first"]), stamp(x["last"])
        threats = " · ".join(THREAT_KO.get(t, t) for t in sorted(x["threats"]))
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": iid, "created_by_ref": IDENTITY_ID,
            "created": first, "modified": last, "valid_from": first,
            "name": f"{TYPE_KO[x['type']]}: {x['value'][:200]}",
            "description": f"담당자가 위협({threats})으로 확정한 사건 {len(x['cases'])}건의 "
                           + "·".join(ROLE_KO[r] for r in sorted(x["roles"])),
            "indicator_types": ["malicious-activity"], "pattern": pattern, "pattern_type": "stix",
            "pattern_version": "2.1", "labels": sorted(x["threats"]),
            # 사용자 정의 속성(x_) 대신 표준 외부 참조로 사건 id 를 남긴다(받는 쪽이 이 사건을 되물을 수 있게)
            "external_references": [{"source_name": "safetrace-case", "external_id": c} for c in x["cases"][:CASE_IDS_PER_ROW]],
        })
        for key in sorted({case_group[c] for c in x["cases"] if c in case_group}):
            cmp = campaigns.get(key)
            if cmp is None:
                cmp = campaigns[key] = {"type": "campaign", "spec_version": "2.1", "id": _sid("campaign", key),
                                        "created_by_ref": IDENTITY_ID, "created": first, "modified": last,
                                        "name": f"SafeTrace 연관 묶음 {key[:8]}",
                                        "description": "같은 사이트·운영 정보·키트 지문으로 이어진, 담당자가 위협으로 확정한 사건들",
                                        "first_seen": first, "last_seen": last}
            cmp["created"] = cmp["first_seen"] = min(cmp["first_seen"], first)
            cmp["modified"] = cmp["last_seen"] = max(cmp["last_seen"], last)
            rels.append({"type": "relationship", "spec_version": "2.1", "id": _sid("relationship", iid, cmp["id"]),
                         "created_by_ref": IDENTITY_ID, "created": first, "modified": last,
                         "relationship_type": "indicates", "source_ref": iid, "target_ref": cmp["id"]})
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [*objects, *campaigns.values(), *rels]}
    return bundle, skipped


def summary(indicators: list[dict], excluded: Counter, stix_skipped: int | None = None) -> dict:
    by_type = Counter(x["type"] for x in indicators)
    threats = Counter(t for x in indicators for t in x["threats"])
    out = {"indicators": len(indicators), "by_type": {t: by_type[t] for t in (*NETWORK_TYPES, *CONTACT_TYPES) if by_type[t]},
           "by_threat": dict(sorted(threats.items())), "excluded": {k: excluded[k] for k in EXCLUDED_KO if excluded[k]}}
    if stix_skipped is not None:
        out["stix_skipped"] = stix_skipped
    return out

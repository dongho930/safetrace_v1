"""현황판(분석가·모니터링 담당자 업무): 기간 안에 접수한 사건의 접수·처리·판정·조치를 센다.

- 값(주소·연락처)은 내지 않고 수만 낸다(사칭 브랜드·호스팅·최상위 도메인은 이름표). 그래서 열람자도 본다
- 기간은 접수 시각 기준(1~90일), 사건은 최신 5,000건까지 세고 넘으면 잘렸다고 알린다
- '위협 사건'은 담당자 판정이 있으면 그 판정(위협 확정), 없으면 AI 판단(정상·판단 불가가 아닌 유형)으로 본다
- 날짜는 한국 시각(UTC+9)으로 나눈다(담당자가 보는 날짜)
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta, timezone
from urllib.parse import urlsplit

from .decision.brands import (SHARED_HOSTING, SHORTENER_HOSTS, brand_name_domain, lookalike_brand, on_domain,
                              site_of)

DAYS_MAX = 90
CASES_MAX = 5000
TOP = 10
KST = timezone(timedelta(hours=9))
THREATS = ("phishing", "scam", "illegal_gambling", "malware")
TERMINAL = ("COMPLETED", "REVIEW_REQUIRED", "FAILED", "UNREACHABLE", "BLOCKED")
ACTION_STATES = ("none", "requested", "blocked", "removed", "reappeared", "closed")


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _ai(c: dict) -> str | None:
    t = c["threat"].get("threat") if isinstance(c.get("threat"), dict) else None
    return t if isinstance(t, str) else None


def _host(u: object) -> str:
    try:
        return (urlsplit(u).hostname or "").lower().rstrip(".") if isinstance(u, str) else ""
    except ValueError:
        return ""


def _pct(xs: list[float], q: float) -> float | None:
    if not xs:
        return None
    s = sorted(xs)
    return round(s[min(len(s) - 1, int(q * len(s)))], 1)


def _top(c: Counter, n: int = TOP) -> list[list]:
    return [[k, v] for k, v in sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


def brand_of(c: dict) -> str | None:
    """사칭 브랜드: 코드 규칙이 남긴 브랜드, 없으면 신고·최종 주소 도메인 이름으로 본 브랜드(브랜드 목록의 것만)."""
    o = c["threat"].get("override") if isinstance(c.get("threat"), dict) else None
    b = o.get("brand") if isinstance(o, dict) else None
    if isinstance(b, str) and b:
        return b[:32]
    for u in (c.get("url"), c.get("final_url")):
        h = _host(u)
        if h and not on_domain(h, SHORTENER_HOSTS):
            b = lookalike_brand(h) or brand_name_domain(h)
            if b:
                return b
    return None


def hosting_of(host: str) -> str:
    """호스팅 이름표: 공용 호스팅이면 그 서비스 도메인(pages.dev 등), 아니면 '자체 도메인'."""
    for d in SHARED_HOSTING:
        if on_domain(host, (d,)):
            return d
    return "자체 도메인"


def tld_of(host: str) -> str:
    site = site_of(host)
    return "." + site.split(".", 1)[1] if "." in site else "(없음)"


def build(cases: list[dict], now: datetime, days: int, truncated: bool) -> dict:
    """cases: {id, url, final_url, source, status, main_status, threat, created_at, main_at, verdict(decision·threat·
    ai_threat·created_at 또는 None), first_verdict_at, auto(bool|None), action(state 또는 None)}."""
    now = _utc(now)
    since = now - timedelta(days=days)
    day0 = since.astimezone(KST).date()
    daily = {(day0 + timedelta(days=i)).isoformat(): {"received": 0, "ai_threat": 0, "confirmed": 0}
             for i in range((now.astimezone(KST).date() - day0).days + 1)}
    status, ai, decisions, confirmed, rules, rules_confirmed = (Counter() for _ in range(6))
    brands, hosting, tlds, actions = Counter(), Counter(), Counter(), Counter()
    to_main, to_verdict, waiting_age = [], [], []
    agree = {"pairs": 0, "same_class": 0, "both_threat": 0, "same_type": 0, "ai_threat_reviewer_benign": 0,
             "ai_benign_reviewer_threat": 0}
    related = {"auto": 0, "manual": 0, "auto_ai_threat": 0, "auto_confirmed": 0}
    for c in cases:
        created = _utc(c["created_at"])
        key = created.astimezone(KST).date().isoformat()
        main_status = c.get("main_status") or c["status"]
        status["pending" if c["status"] in ("QUEUED", "RUNNING") and not c.get("main_status") else main_status] += 1
        a, v = _ai(c), c.get("verdict")
        if key in daily:
            daily[key]["received"] += 1
        finished = main_status in TERMINAL
        if finished:
            ai[a or "none"] += 1
            if c.get("main_at") is not None:
                to_main.append((_utc(c["main_at"]) - created).total_seconds())
        decisions[v["decision"] if v else "none"] += 1
        is_threat = (v["decision"] == "threat") if v and v["decision"] in ("threat", "benign") else a in THREATS
        if v and v["decision"] == "threat":
            confirmed[v["threat"] or "unknown"] += 1
            if key in daily:
                daily[key]["confirmed"] += 1
        if finished and a in THREATS and key in daily:
            daily[key]["ai_threat"] += 1
        if c.get("first_verdict_at") is not None:
            to_verdict.append((_utc(c["first_verdict_at"]) - created).total_seconds())
        # 판정 대기(콘솔 '검토 필요'·'위협 의심 · 판정 전' 과 같은 기준)
        if (main_status == "REVIEW_REQUIRED" and (not v or v["decision"] == "hold")) or (
                main_status == "COMPLETED" and a in THREATS and not v):
            waiting_age.append((now - created).total_seconds() / 3600)
        o = c["threat"].get("override") if isinstance(c.get("threat"), dict) else None
        if isinstance(o, dict) and isinstance(o.get("reason"), str):
            rules[o["reason"][:40]] += 1
            if v and v["decision"] == "threat":
                rules_confirmed[o["reason"][:40]] += 1
        if v and v["decision"] in ("threat", "benign") and v.get("ai_threat") not in (None, "unknown"):
            ai_t, rv_t = v["ai_threat"] in THREATS, v["decision"] == "threat"
            agree["pairs"] += 1
            agree["same_class"] += ai_t == rv_t
            agree["ai_threat_reviewer_benign"] += ai_t and not rv_t
            agree["ai_benign_reviewer_threat"] += rv_t and not ai_t
            if ai_t and rv_t:
                agree["both_threat"] += 1
                agree["same_type"] += v["ai_threat"] == v["threat"]
        if is_threat and finished:
            h = _host(c.get("url"))
            if on_domain(h, SHORTENER_HOSTS):  # 단축 URL 은 그 목적지의 호스팅을 본다
                h = _host(c.get("final_url")) or h
            if h:
                hosting[hosting_of(h)] += 1
                tlds[tld_of(h)] += 1
            b = brand_of(c)
            if b:
                brands[b] += 1
        if c.get("source") == "related" and c.get("auto") is not None:
            related["auto" if c["auto"] else "manual"] += 1
            if c["auto"]:
                related["auto_ai_threat"] += a in THREATS
                related["auto_confirmed"] += bool(v and v["decision"] == "threat")
        if v and v["decision"] == "threat":
            actions[c.get("action") or "none"] += 1
    return {
        "days": days, "since": since.isoformat(), "generated_at": now.isoformat(), "truncated": truncated,
        "cases": len(cases),
        "kpi": {"received": len(cases), "finished": sum(v for k, v in status.items() if k in TERMINAL),
                "pending": status["pending"], "ai_threat": sum(ai[t] for t in THREATS),
                "confirmed": sum(confirmed.values()), "waiting": len(waiting_age),
                "reappeared": actions["reappeared"]},
        "daily": [{"date": d, **x} for d, x in daily.items()],
        "status": dict(status), "ai": dict(ai), "decisions": dict(decisions), "confirmed": dict(confirmed),
        "rules": _top(rules), "rules_confirmed": dict(rules_confirmed),
        "brands": _top(brands), "hosting": _top(hosting), "tlds": _top(tlds),
        "timing": {"to_main_s": {"n": len(to_main), "median": _pct(to_main, 0.5), "p90": _pct(to_main, 0.9)},
                   "to_verdict_h": {"n": len(to_verdict), "median": _pct([x / 3600 for x in to_verdict], 0.5),
                                    "p90": _pct([x / 3600 for x in to_verdict], 0.9)},
                   "waiting_h": {"n": len(waiting_age), "median": _pct(waiting_age, 0.5),
                                 "max": round(max(waiting_age), 1) if waiting_age else None}},
        "agreement": agree, "related": related,
        "actions": {s: actions[s] for s in ACTION_STATES},
    }

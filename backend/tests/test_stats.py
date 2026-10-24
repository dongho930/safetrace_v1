"""현황판 집계: 한국 날짜로 나누기, 판정 대기·위협 사건 기준, AI·담당자 일치, 코드 규칙·사칭 브랜드·호스팅, 조치 상태,
열람자도 보되 주소 값은 내지 않음."""

import json
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from safetrace import accounts, stats
from safetrace.store import Case, Verdict, now
from tests.conftest import INVESTIGATOR, VIEWER

NOW = datetime(2026, 10, 24, 3, 0, tzinfo=UTC)  # 한국 시각 12:00


def _c(i, url="https://evil.example/", status="COMPLETED", threat="phishing", verdict=None, hours_ago=1.0, **kw):
    created = NOW - timedelta(hours=hours_ago)
    return {"id": f"c{i}", "url": url, "final_url": kw.get("final_url"), "source": kw.get("source", "report"),
            "status": status, "main_status": kw.get("main_status"),
            "threat": {"threat": threat, "probability": 0.9, **({"override": kw["override"]} if "override" in kw else {})}
            if threat else None,
            "created_at": created, "main_at": kw.get("main_at", created + timedelta(seconds=20)),
            "verdict": verdict, "first_verdict_at": kw.get("first_verdict_at"), "auto": kw.get("auto"),
            "action": kw.get("action")}


def test_daily_buckets_use_korean_date():
    """UTC 로는 같은 날이어도 한국 시각으로는 다른 날(UTC 15:00 = 한국 자정)."""
    cases = [_c(1, hours_ago=11.5), _c(2, hours_ago=12.5)]  # UTC 15:30(한국 10/24 00:30), UTC 14:30(한국 10/23 23:30)
    d = {x["date"]: x for x in stats.build(cases, NOW, 7, False)["daily"]}
    assert d["2026-10-24"]["received"] == 1 and d["2026-10-23"]["received"] == 1
    assert list(d)[0] == "2026-10-17" and list(d)[-1] == "2026-10-24"  # 빈 날도 0 으로 채운다


def test_kpi_waiting_and_threat_basis():
    th = {"decision": "threat", "threat": "phishing", "ai_threat": "phishing"}
    cases = [
        _c(1),                                                      # AI 위협, 판정 전 → 판정 대기
        _c(2, status="REVIEW_REQUIRED", threat="benign"),           # 검토 필요 → 판정 대기
        _c(3, status="REVIEW_REQUIRED", verdict={"decision": "hold", "threat": None, "ai_threat": "phishing"}),  # 보류도 대기
        _c(4, verdict=th, first_verdict_at=NOW - timedelta(minutes=30), action="reappeared"),
        _c(5, threat="benign"),                                     # 정상
        _c(6, status="RUNNING", threat=None, main_at=None),          # 조사 중
        _c(7, status="RUNNING", main_status="COMPLETED"),           # 원래 결과 나옴(연관 조사 중) → 끝난 것으로
    ]
    out = stats.build(cases, NOW, 7, False)
    k = out["kpi"]
    assert (k["received"], k["pending"], k["finished"]) == (7, 1, 6)
    assert k["waiting"] == 4 and k["confirmed"] == 1 and k["reappeared"] == 1
    assert k["ai_threat"] == 4  # 1·3·4·7
    assert out["actions"]["reappeared"] == 1 and sum(out["actions"].values()) == 1  # 조치는 위협 확정 사건만
    assert out["timing"]["to_verdict_h"]["median"] == 0.5 and out["timing"]["to_main_s"]["median"] == 20.0


def test_agreement_rules_brands_hosting():
    v = lambda d, t, ai: {"decision": d, "threat": t, "ai_threat": ai}  # noqa: E731
    rule = {"reason": "brand_clone_title", "brand": "steam", "destination": "frytt.dev"}
    cases = [
        _c(1, url="https://x.pages.dev/", verdict=v("threat", "phishing", "phishing")),
        _c(2, url="https://naver-login.example/", verdict=v("threat", "scam", "phishing")),       # 유형만 다름
        _c(3, url="https://ok.example/", threat="phishing", verdict=v("benign", None, "phishing")),  # AI 위협·담당자 정상
        _c(4, url="https://frytt.dev/", override=rule, verdict=v("threat", "phishing", "benign")),  # 규칙이 보냄
        _c(5, url="https://bit.ly/abc", final_url="https://y.vercel.app/a"),                      # 단축 URL 은 목적지
        _c(6, url="https://www.roblox.et/x"),
    ]
    out = stats.build(cases, NOW, 7, False)
    a = out["agreement"]
    assert (a["pairs"], a["same_class"], a["both_threat"], a["same_type"]) == (4, 2, 2, 1)
    assert a["ai_threat_reviewer_benign"] == 1 and a["ai_benign_reviewer_threat"] == 1
    assert out["rules"] == [["brand_clone_title", 1]] and out["rules_confirmed"] == {"brand_clone_title": 1}
    assert dict(map(tuple, out["brands"])) == {"naver": 1, "steam": 1, "roblox": 1}
    assert dict(map(tuple, out["hosting"])) == {"pages.dev": 1, "자체 도메인": 3, "vercel.app": 1}  # 3 은 정상 확정
    assert dict(map(tuple, out["tlds"]))[".dev"] == 2


def test_related_counts():
    cases = [_c(1, source="related", auto=True), _c(2, source="related", auto=True, threat="benign"),
             _c(3, source="related", auto=False)]
    assert stats.build(cases, NOW, 7, False)["related"] == {"auto": 2, "manual": 1, "auto_ai_threat": 1, "auto_confirmed": 0}


# ── API ─────────────────────────
@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_stats_api_counts_without_values(client):
    from safetrace.api.main import store

    before = client.get("/api/stats?days=1", headers=h(VIEWER)).json()
    tag = secrets.token_hex(4)
    u = accounts.create_user(store, "st" + tag, "correct-horse-battery-9", "reviewer")
    with store.session() as s, s.begin():
        a = Case(url=f"https://stats-{tag}.pages.dev/login", source="test", status="COMPLETED", created_by="t",
                 threat={"threat": "phishing", "probability": 0.9})
        b = Case(url=f"https://stats2-{tag}.example/", source="test", status="REVIEW_REQUIRED", created_by="t",
                 threat={"threat": "unknown", "probability": 0.4})
        s.add_all([a, b])
        s.flush()
        s.add(Verdict(case_id=a.id, rev=1, decision="threat", threat="phishing", reviewer=u.username, user_id=u.id,
                      ai_threat="phishing", created_at=now()))
    r = client.get("/api/stats?days=1", headers=h(VIEWER))  # 수·이름표뿐이라 열람자도 본다
    assert r.status_code == 200
    after = r.json()
    assert after["kpi"]["received"] - before["kpi"]["received"] == 2
    assert after["kpi"]["confirmed"] - before["kpi"]["confirmed"] == 1
    assert after["kpi"]["waiting"] - before["kpi"]["waiting"] == 1
    assert tag not in json.dumps(after)  # 주소 값은 내지 않는다
    assert isinstance(after["ms"], int) and len(after["daily"]) == 2
    for q in ("days=0", "days=91", "days=x"):
        assert client.get(f"/api/stats?{q}", headers=h(INVESTIGATOR)).status_code == 422
    assert client.get("/api/stats").status_code == 401

"""사건 목록 화면(폴더 건수·거른 목록 한 쪽): 서버 기준이 콘솔이 쓰던 기준(App.tsx FOLDERS)과 같은지, 오래된 사건도 세는지."""

import itertools
import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from safetrace import accounts, caselist
from safetrace.store import Case, CaseLink, CasePhase, Store, Verdict, now
from tests.conftest import VIEWER

STATUSES = ["QUEUED", "RUNNING", "COMPLETED", "REVIEW_REQUIRED", "FAILED", "UNREACHABLE", "BLOCKED"]
THREATS = [None, {"threat": "benign"}, {"threat": "unknown"}, {"threat": "phishing", "hold": True}, {"threat": "illegal_gambling"}]
DECISIONS = [None, "hold", "threat", "benign"]
PHASES = [None, "COMPLETED", "REVIEW_REQUIRED", "UNREACHABLE"]  # 연관 사이트 조사 중이면 원래 결과 상태


def console_folder(f, status, threat, decision, main_status):
    """콘솔이 쓰던 기준(App.tsx)을 그대로 옮긴 것: 서버 SQL 과 같아야 한다."""
    related_running = main_status is not None and status == "RUNNING"
    eff = main_status if related_running else status
    suspect = bool(threat) and threat.get("threat") not in ("benign", "unknown")
    return {
        "review": eff == "REVIEW_REQUIRED" and decision in (None, "hold"),
        "running": status in ("RUNNING", "QUEUED") and not related_running,
        "suspect": eff == "COMPLETED" and suspect and decision is None,
        "decided": decision in ("threat", "benign"),
        "unreachable": eff in ("UNREACHABLE", "BLOCKED", "FAILED"),
        "all": True,
    }[f]


@pytest.fixture
def store(tmp_path):
    return Store(f"sqlite:///{tmp_path / 'list.db'}")


def _user(store):
    return accounts.create_user(store, "rev" + secrets.token_hex(3), "correct-horse-battery-9", "reviewer")


def _add(store, user, status, threat, decision, main_status, *, url=None, source="report", at=None, revs=1):
    with store.session() as s, s.begin():
        c = Case(url=url or f"https://e{secrets.token_hex(4)}.example/", source=source, status=status, threat=threat,
                 created_by="t", created_at=at or now())
        s.add(c)
        s.flush()
        if main_status:
            s.add(CasePhase(case_id=c.id, phase="related", main_status=main_status, main_head_seq=1, main_head_hash="0" * 64))
        if decision:
            # 판을 여러 번 쌓으면 마지막 판만 센다(앞 판은 다른 결정)
            for rev in range(1, revs + 1):
                d = decision if rev == revs else ("benign" if decision != "benign" else "threat")
                s.add(Verdict(case_id=c.id, rev=rev, decision=d, user_id=user.id, reviewer=user.username))
    return c


def test_folders_match_console_rules(store):
    """상태·AI 판단·판정·연관 조사 상태를 모두 조합한 사건(7×5×4×4=560건)에서 폴더 건수·목록이 콘솔 기준과 같다."""
    user = _user(store)
    expect = {f: set() for f in caselist.FOLDERS}
    for i, (st, th, dec, ms) in enumerate(itertools.product(STATUSES, THREATS, DECISIONS, PHASES)):
        c = _add(store, user, st, th, dec, ms, revs=1 + i % 3)
        for f in caselist.FOLDERS:
            if console_folder(f, st, th, dec, ms):
                expect[f].add(c.id)
    got = caselist.counts(store)
    assert got == {f: len(v) for f, v in expect.items()}
    assert got["all"] == 560 and all(got[f] > 0 for f in caselist.FOLDERS)
    for f in caselist.FOLDERS:
        rows, total = caselist.page(store, f, "", "", 0, caselist.PAGE_MAX)
        ids = {r.id for r in rows}
        more = 0
        while len(ids) < total:
            more += caselist.PAGE_MAX
            rows, _ = caselist.page(store, f, "", "", more, caselist.PAGE_MAX)
            ids |= {r.id for r in rows}
        assert ids == expect[f], f


def test_old_cases_are_counted_and_paged(store):
    """예전 콘솔은 최근 50건만 받아 셌다: 오래된 검토 필요 사건도 세고, 쪽을 넘기면 빠짐없이 한 번씩 나온다."""
    user = _user(store)
    t0 = now() - timedelta(days=60)
    ids = [_add(store, user, "REVIEW_REQUIRED", {"threat": "phishing", "hold": True}, None, None, at=t0 + timedelta(minutes=i)).id
           for i in range(130)]
    for i in range(80):  # 최근 사건 80건이 앞을 덮어도
        _add(store, user, "COMPLETED", {"threat": "benign"}, None, None, at=now() - timedelta(minutes=i))
    assert caselist.counts(store)["review"] == 130
    seen = []
    for off in range(0, 130, 50):
        rows, total = caselist.page(store, "review", "", "", off, 50)
        assert total == 130
        seen += [r.id for r in rows]
    assert seen == list(reversed(ids))  # 최신 접수 순, 겹치거나 빠지지 않음


def test_search_is_literal_and_source_filters(store):
    """검색은 주소에 그대로 포함되는지(대소문자 무시) — %·_ 는 SQL 와일드카드가 아니라 글자로 본다."""
    user = _user(store)
    a = _add(store, user, "COMPLETED", None, None, None, url="https://Shop-100%_off.example/x")
    b = _add(store, user, "COMPLETED", None, None, None, url="https://shop-1000ff.example/x", source="feed")
    assert [r.id for r in caselist.page(store, "all", "100%_OFF", "", 0, 50)[0]] == [a.id]
    assert {r.id for r in caselist.page(store, "all", "shop-100", "", 0, 50)[0]} == {a.id, b.id}
    assert [r.id for r in caselist.page(store, "all", "", "feed", 0, 50)[0]] == [b.id]
    assert caselist.page(store, "all", "%", "", 0, 50)[1] == 1


def test_live_prefers_human_case_then_oldest_queued(store):
    user = _user(store)
    q_old = _add(store, user, "QUEUED", None, None, None, at=now() - timedelta(minutes=5))
    _add(store, user, "QUEUED", None, None, None)
    running, queued = caselist.live(store)
    assert running is None and queued.id == q_old.id
    feed = _add(store, user, "RUNNING", None, None, None, source="feed")
    assert caselist.live(store)[0].id == feed.id
    parent = _add(store, user, "COMPLETED", None, None, None)
    auto = _add(store, user, "RUNNING", None, None, None, source="related")
    with store.session() as s, s.begin():
        s.add(CaseLink(child_id=auto.id, parent_id=parent.id, candidate_url="https://x.example/", target_host="x.example",
                       auto=True, created_by="system:related"))
    human = _add(store, user, "RUNNING", None, None, None, at=now() - timedelta(minutes=1))
    running, queued = caselist.live(store)
    assert running.id == human.id and queued is None  # 더 최근 자동·수집 사건보다 사람 신고 먼저


@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_page_api(client):
    from safetrace.api.main import store as api_store

    tag = "pg" + secrets.token_hex(5)
    # 접수 API 를 쓰면 조사 대기열에 들어가고 시험 계정의 접수 한도를 차지하므로, 끝난 사건을 직접 넣는다
    with api_store.session() as s, s.begin():
        for i in range(3):
            s.add(Case(url=f"https://{tag}-{i}.example/", source="test", status="COMPLETED", created_by="t"))
    assert client.get("/api/cases/page").status_code == 401
    r = client.get(f"/api/cases/page?q={tag}&limit=2", headers=h(VIEWER))
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3 and len(body["items"]) == 2 and body["limit"] == 2
    assert set(body["counts"]) == set(caselist.FOLDERS) and body["counts"]["all"] >= 3
    nxt = client.get(f"/api/cases/page?q={tag}&limit=2&offset=2", headers=h(VIEWER)).json()
    assert len(nxt["items"]) == 1 and not ({x["id"] for x in body["items"]} & {x["id"] for x in nxt["items"]})
    # 범위 밖 값은 거절(목록을 크게 받아 서버를 묶지 못하게)
    for bad in ("limit=201", "limit=0", "offset=-1", "offset=100001", "folder=nope", "source=FEED", "q=" + "a" * 201):
        assert client.get(f"/api/cases/page?{bad}", headers=h(VIEWER)).status_code == 422, bad
    # 예전 목록 API 는 그대로(다른 도구가 쓴다)
    assert client.get("/api/cases?limit=1", headers=h(VIEWER)).status_code == 200

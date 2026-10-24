"""자동 수집: 피드 글 파싱·고르기(형식·중복·키트·상한), 받기 결과는 API 가 만든 번호로 한 번만, 사람 신고가 막히지 않게
끝나지 않은 자동 사건 한도, 켜기·끄기는 사람 관리자만, 워커는 출처 이름으로만 받는다."""

import json
import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from safetrace import accounts, intake
from safetrace.agent import feeds, worker
from safetrace.store import AuditLog, Case, FeedFetch, FeedItem, now
from tests.conftest import INVESTIGATOR, SERVICE_ADMIN, VIEWER

PW = "correct-horse-battery-9"
PORTS = [80, 443]
PT_HEAD = "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target"


def _pt(rows: list[tuple[str, str, str]]) -> str:
    return "\n".join([PT_HEAD, *(f'{i},"{u}",http://www.phishtank.com/phish_detail.php?phish_id={i},2026-10-24T01:00:00+00:00,'
                                 f'{v},2026-10-24T01:01:00+00:00,{o},Other' for i, (u, v, o) in enumerate(rows, 1))])


# ── 파싱·고르기 ─────────────────────────
def test_parse_openphish_and_phishtank():
    assert intake.parse("openphish", "https://a.example/x\n\n  https://b.example/y  \n", False) == [
        "https://a.example/x", "https://b.example/y"]
    text = _pt([("https://ok.example/a", "yes", "yes"), ("https://off.example/", "yes", "no"),
                ("https://unverified.example/", "no", "yes"), ("https://ok2.example/b", "yes", "yes")])
    assert intake.parse("phishtank", text, False) == ["https://ok.example/a", "https://ok2.example/b"]
    # 상한에서 잘린 마지막 줄은 버린다(잘린 주소가 다른 주소처럼 들어가지 않게)
    assert intake.parse("phishtank", text + '\n99,"https://cut.exam', True) == ["https://ok.example/a", "https://ok2.example/b"]
    assert intake.parse("openphish", "https://a.example/x\nhttps://cut.exa", True) == ["https://a.example/x"]
    assert intake.parse("phishtank", "id,link\n1,https://x.example/", False) == []  # 모르는 머리글
    assert intake.parse("nope", "https://x.example/", False) == []


def test_choose_validates_dedupes_and_caps():
    urls = ["javascript:alert(1)", "https://user:pw@cred.example/", "https://" + "a" * 2100 + ".example/",
            "https://dup.example/1", "https://dup.example/2",          # 같은 호스트
            "https://seen.example/",                                    # 최근 며칠 안에 넣은 호스트
            "https://k1.pages.dev/appeal/x", "https://k2.pages.dev/appeal/y", "https://k3.pages.dev/appeal/z",  # 같은 키트 모양
            "https://other.pages.dev/login",                            # 같은 호스팅이라도 다른 경로 모양
            "https://a.evil.example/", "https://b.evil.example/", "https://c.evil.example/",  # 같은 등록 도메인
            "https://last1.example/", "https://last2.example/"]
    picked, skipped = intake.choose(urls, seen_hosts={"seen.example"}, allowed_ports=PORTS, cap=7, kit_max=2)
    assert [u for u, _ in picked] == ["https://dup.example/1", "https://k1.pages.dev/appeal/x", "https://k2.pages.dev/appeal/y",
                                      "https://other.pages.dev/login", "https://a.evil.example/", "https://b.evil.example/",
                                      "https://last1.example/"]
    assert dict(skipped) == {"format": 3, "same_host": 1, "seen_host": 1, "kit": 2, "over_cap": 1}


# ── 받기 번호 ─────────────────────────
def _store():
    from safetrace.api.main import store

    return store


@pytest.fixture
def clean_intake():
    """시험 DB 는 실행 사이에 남는다: 대기 중인 받기·대기열을 비우고, 끝나면 끈다."""
    store = _store()

    def reset():
        with store.session() as s, s.begin():
            for f in s.scalars(select(FeedFetch).where(FeedFetch.state == "pending")):
                f.state = "expired"
            for it in s.scalars(select(FeedItem).where(FeedItem.state == "queued")):
                it.state = "dropped"
            for c in s.scalars(select(Case).where(Case.created_by == intake.INTAKE_ACTOR, Case.status.in_(("QUEUED", "RUNNING")))):
                c.status = "FAILED"
        intake.set_enabled(store, False, "test")

    reset()
    yield store
    reset()


def test_fetch_result_only_once_for_own_pending_number(clean_intake):
    store = clean_intake
    f = intake.request_fetch(store, "openphish")
    assert f is not None and intake.request_fetch(store, "openphish") is None  # 같은 출처에 대기 중인 받기는 하나
    kw = {"seen_hosts": set(), "allowed_ports": PORTS, "cap": 30, "kit_max": 2}
    assert intake.record_fetch(store, 10**9, {"ok": True, "text": "https://x.example/"}, **kw) is None  # 모르는 번호
    assert intake.record_fetch(store, str(f.id), {"ok": True, "text": "https://x.example/"}, **kw) is None  # 정수만
    tag = secrets.token_hex(4)
    got = intake.record_fetch(store, f.id, {"ok": True, "text": f"https://a-{tag}.example/\nhttps://b-{tag}.example/"}, **kw)
    assert (got.state, got.got, got.picked) == ("done", 2, 2)
    assert intake.record_fetch(store, f.id, {"ok": True, "text": f"https://c-{tag}.example/"}, **kw) is None  # 한 번만
    with store.session() as s:
        assert sorted(i.host for i in s.scalars(select(FeedItem).where(FeedItem.fetch_id == f.id))) == [
            f"a-{tag}.example", f"b-{tag}.example"]
    g = intake.request_fetch(store, "openphish")
    assert intake.record_fetch(store, g.id, {"ok": False, "reason": "timeout"}, **kw).state == "failed"


def test_due_sources_intervals(clean_intake):
    store = clean_intake
    t0 = now() + timedelta(days=30)  # 다른 시험·실행이 남긴 받기보다 늦게
    f = intake.request_fetch(store, "phishtank", at=t0)
    assert "phishtank" not in intake.due_sources(store, ["phishtank"], at=t0 + timedelta(hours=7))  # 대기 중
    intake.record_fetch(store, f.id, {"ok": True, "text": PT_HEAD}, seen_hosts=set(), allowed_ports=PORTS, cap=1, kit_max=1)
    assert "phishtank" not in intake.due_sources(store, ["phishtank"], at=t0 + timedelta(hours=5))
    assert "phishtank" in intake.due_sources(store, ["phishtank"], at=t0 + timedelta(hours=6, minutes=1))
    g = intake.request_fetch(store, "phishtank", at=t0 + timedelta(hours=7))
    intake.record_fetch(store, g.id, {"ok": False, "reason": "http_429"}, seen_hosts=set(), allowed_ports=PORTS, cap=1, kit_max=1)
    assert "phishtank" in intake.due_sources(store, ["phishtank"], at=t0 + timedelta(hours=8, minutes=1))  # 실패는 1시간 뒤
    assert intake.due_sources(store, ["nope"], at=t0) == []
    # 결과가 오지 않은 받기는 만료되고, 1시간 뒤 다시 받는다
    h = intake.request_fetch(store, "phishtank", at=t0 + timedelta(hours=9))
    assert intake.expire_fetches(store, at=t0 + timedelta(hours=9, minutes=11)) >= 1
    with store.session() as s:
        assert s.get(FeedFetch, h.id).state == "expired"


# ── API ─────────────────────────
@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(scope="module")
def admin(client):
    name = "intk" + secrets.token_hex(3)
    accounts.create_user(_store(), name, PW, "admin")
    return name, client.post("/api/auth/login", json={"username": name, "password": PW}).json()["token"]


def test_toggle_is_admin_human_only(client, admin, clean_intake):
    name, tok = admin
    for t in (VIEWER, INVESTIGATOR, SERVICE_ADMIN):  # 자동화 토큰은 관리자 역할이어도 못 바꾼다
        assert client.post("/api/intake", json={"enabled": True}, headers=h(t)).status_code == 403
    assert client.get("/api/intake", headers=h(VIEWER)).json()["enabled"] is False
    r = client.post("/api/intake", json={"enabled": True}, headers=h(tok))
    assert r.status_code == 200 and r.json()["enabled"] is True and r.json()["updated_by"] == name
    assert client.post("/api/intake", json={"enabled": "yes"}, headers=h(tok)).status_code == 422
    assert client.post("/api/intake", json={"enabled": False}, headers=h(tok)).json()["enabled"] is False
    with _store().session() as s:
        acts = [a.action for a in s.scalars(select(AuditLog).where(AuditLog.actor == name).order_by(AuditLog.id))]
    assert acts[-2:] == ["intake.enable", "intake.disable"]


def test_tick_requests_fetch_and_creates_one_case_at_a_time(client, admin, clean_intake, monkeypatch):
    from safetrace.api import main as m

    store = clean_intake
    jobs, fetches = [], []
    monkeypatch.setattr(m, "enqueue", lambda cid, url: jobs.append((cid, url)))  # 실제 조사를 돌리지 않는다
    monkeypatch.setattr(m, "enqueue_feed", lambda fid, src: fetches.append((fid, src)))
    t = now() + timedelta(days=60)
    assert m.intake_tick(at=t) == 0 and fetches == []  # 꺼져 있으면 아무것도 하지 않는다
    client.post("/api/intake", json={"enabled": True}, headers=h(admin[1]))
    m.intake_tick(at=t)
    assert sorted(src for _, src in fetches) == ["openphish", "phishtank"]
    tag = secrets.token_hex(4)
    fid = dict((src, i) for i, src in fetches)["openphish"]
    m.record_feed(fid, {"ok": True, "text": "\n".join(f"https://n{i}-{tag}.example/login" for i in range(5)), "truncated": False})
    assert m.intake_tick(at=t) == 1  # 끝나지 않은 자동 사건 한도(1)
    assert m.intake_tick(at=t) == 0  # 앞 사건이 끝나기 전에는 더 만들지 않는다
    cid, url = jobs[0]
    with store.session() as s:
        c = s.get(Case, cid)
        assert (c.source, c.created_by, c.url) == ("feed", intake.INTAKE_ACTOR, f"https://n0-{tag}.example/login")
        c.status = "COMPLETED"
        s.commit()
    assert m.intake_tick(at=t) == 1 and jobs[1][1] == f"https://n1-{tag}.example/login"
    # 사람 신고는 자동 사건과 상관없이 받는다(전체 대기 한도에 자동 수집 사건을 세지 않는다)
    inv = "intkinv" + tag[:4]  # 시험 DB 에 남은 공용 시험 토큰의 접수 한도와 상관없게 새 계정으로
    accounts.create_user(store, inv, PW, "investigator")
    itok = client.post("/api/auth/login", json={"username": inv, "password": PW}).json()["token"]
    r = client.post("/api/cases", json={"url": "http://127.0.0.1:8900/smish/"},
                    headers={**h(itok), "Idempotency-Key": "intk-" + tag})
    assert r.status_code == 201
    with store.session() as s, s.begin():
        s.get(Case, r.json()["id"]).status = "FAILED"
    st = client.get("/api/intake", headers=h(VIEWER)).json()
    assert st["sources"]["openphish"]["picked"] == 5 and st["queued"] == 3 and st["pending"] == 1
    assert tag not in json.dumps(st)  # 상태에는 주소 값이 없다
    # 끄면 대기열이 남아 있어도 사건을 만들지 않는다
    client.post("/api/intake", json={"enabled": False}, headers=h(admin[1]))
    with store.session() as s, s.begin():
        s.get(Case, jobs[1][0]).status = "FAILED"
    assert m.intake_tick(at=t) == 0


def test_daily_cap(client, admin, clean_intake, monkeypatch):
    from safetrace.api import main as m

    monkeypatch.setattr(m, "enqueue", lambda cid, url: None)
    monkeypatch.setattr(m, "enqueue_feed", lambda fid, src: None)
    monkeypatch.setattr(m.settings, "intake_max_pending", 10)
    monkeypatch.setattr(m.settings, "intake_daily_max", 0)
    client.post("/api/intake", json={"enabled": True}, headers=h(admin[1]))
    f = intake.request_fetch(clean_intake, "openphish", at=now() + timedelta(days=90))
    m.record_feed(f.id, {"ok": True, "text": f"https://cap-{secrets.token_hex(4)}.example/"})
    assert m.intake_tick() == 0


# ── 워커 ─────────────────────────
class _FakeRedis:
    def __init__(self):
        self.added = []

    def xadd(self, stream, fields, maxlen=None):
        self.added.append((stream, fields))


def test_worker_fetches_only_named_sources(monkeypatch):
    calls = []
    monkeypatch.setattr(worker, "fetch_feed", lambda src, proxy, allow: calls.append(src) or {"ok": True, "text": "x"})
    r = _FakeRedis()
    s = type("S", (), {"egress_proxy": None, "test_allowlist": []})()
    worker.run_feed(r, s, {"fetch_id": "7", "source": "https://evil.example/feed"})  # 주소를 넘겨도 받지 않는다
    worker.run_feed(r, s, {"fetch_id": "x", "source": "openphish"})
    assert calls == [] and r.added == []
    worker.run_feed(r, s, {"fetch_id": "7", "source": "openphish"})
    assert calls == ["openphish"] and r.added[0][1]["feed_id"] == "7" and r.added[0][1]["case_id"] == ""


def test_feed_fetch_needs_egress_proxy():
    assert feeds.fetch("nope", None)["reason"] == "unknown_source"
    out = feeds.fetch("openphish", None, set())  # 검문 프록시가 없으면(개발 모드) 허용 목록 밖에 접속하지 않는다
    assert out["ok"] is False and out["reason"] == "no_egress_proxy"

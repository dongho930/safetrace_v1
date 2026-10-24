"""자동 수집: 피드 글 파싱·고르기(형식·중복·키트·상한), 받기 결과는 API 가 만든 번호로 한 번만, 사람 신고가 막히지 않게
끝나지 않은 자동 사건 한도, 켜기·끄기는 사람 관리자만, 워커는 출처 이름으로만 받는다."""

import json
import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select

from safetrace import accounts, intake
from safetrace.agent import feeder, feeds
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
    kw = {"seen_hosts": set(), "allowed_ports": PORTS, "cap": 30, "kit_max": 2, "key": None}
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
    intake.record_fetch(store, f.id, {"ok": True, "text": PT_HEAD}, seen_hosts=set(), allowed_ports=PORTS, cap=1, kit_max=1, key=None)
    assert "phishtank" not in intake.due_sources(store, ["phishtank"], at=t0 + timedelta(hours=5))
    assert "phishtank" in intake.due_sources(store, ["phishtank"], at=t0 + timedelta(hours=6, minutes=1))
    g = intake.request_fetch(store, "phishtank", at=t0 + timedelta(hours=7))
    intake.record_fetch(store, g.id, {"ok": False, "reason": "http_429"}, seen_hosts=set(), allowed_ports=PORTS, cap=1, kit_max=1, key=None)
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


KEY = b"k" * 32


@pytest.fixture
def feed_key(monkeypatch):
    from safetrace.api import main as m

    monkeypatch.setattr(m.settings, "feed_key", SecretStr(KEY.decode()))
    return KEY


def _signed(fid: int, source: str, text: str, **over) -> dict:
    res = {"ok": True, "text": text, "truncated": False, **over}
    return {**res, "mac": intake.feed_mac(KEY, fid, source, res)}


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


def test_tick_requests_fetch_and_creates_one_case_at_a_time(client, admin, clean_intake, monkeypatch, feed_key):
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
    m.record_feed(fid, _signed(fid, "openphish", "\n".join(f"https://n{i}-{tag}.example/login" for i in range(5))))
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


def test_daily_cap(client, admin, clean_intake, monkeypatch, feed_key):
    from safetrace.api import main as m

    monkeypatch.setattr(m, "enqueue", lambda cid, url: None)
    monkeypatch.setattr(m, "enqueue_feed", lambda fid, src: None)
    monkeypatch.setattr(m.settings, "intake_max_pending", 10)
    monkeypatch.setattr(m.settings, "intake_daily_max", 0)
    client.post("/api/intake", json={"enabled": True}, headers=h(admin[1]))
    f = intake.request_fetch(clean_intake, "openphish", at=now() + timedelta(days=90))
    m.record_feed(f.id, _signed(f.id, "openphish", f"https://cap-{secrets.token_hex(4)}.example/"))
    assert m.intake_tick() == 0


# ── 수집 컨테이너(feeder) ─────────────────────────
class _FakeRedis:
    def __init__(self):
        self.added = []

    def xadd(self, stream, fields, maxlen=None):
        self.added.append((stream, fields))


def _req(fid: str, source: str = "openphish") -> dict:
    return {"fetch_id": fid, "source": source, "mac": intake.request_mac(KEY, int(fid), source)}


def test_feeder_fetches_only_named_sources_and_signs(monkeypatch):
    calls = []
    monkeypatch.setattr(feeder, "fetch", lambda src, proxy, allow: calls.append(src) or {"ok": True, "text": "https://x.example/"})
    r, st = _FakeRedis(), feeder.State()
    s = type("S", (), {"egress_proxy": None, "test_allowlist": []})()
    assert feeder.run_one(r, s, KEY, {**_req("7"), "source": "https://evil.example/feed"}, st) == "bad_request"
    assert feeder.run_one(r, s, KEY, {**_req("7"), "fetch_id": "x"}, st) == "bad_request"
    assert calls == [] and r.added == []
    assert feeder.run_one(r, s, KEY, _req("7"), st) == "fetched"
    assert calls == ["openphish"] and r.added[0][1]["feed_id"] == "7" and r.added[0][1]["case_id"] == ""
    res = json.loads(r.added[0][1]["payload"])
    assert res["mac"] == intake.feed_mac(KEY, 7, "openphish", {k: v for k, v in res.items() if k != "mac"})


def test_browser_worker_does_not_take_feed_jobs():
    """피드 받기는 수집 컨테이너만: 조사 대상 페이지를 여는 브라우저 워커는 st:feeds 를 읽지 않는다."""
    import inspect

    from safetrace.agent import worker

    assert "st:feeds" not in inspect.getsource(worker)


def test_feed_fetch_needs_egress_proxy():
    assert feeds.fetch("nope", None)["reason"] == "unknown_source"
    out = feeds.fetch("openphish", None, set())  # 검문 프록시가 없으면(개발 모드) 허용 목록 밖에 접속하지 않는다
    assert out["ok"] is False and out["reason"] == "no_egress_proxy"


def test_next_case_starts_when_one_finishes(client, admin, clean_intake, monkeypatch, feed_key):
    """자동 수집 사건이 끝나면 바퀴를 기다리지 않고 바로 다음 것을 접수한다(조사 컨테이너가 쉬지 않게)."""
    from safetrace.api import main as m

    jobs = []
    monkeypatch.setattr(m, "enqueue", lambda cid, url: jobs.append(cid))
    monkeypatch.setattr(m, "enqueue_feed", lambda fid, src: None)
    client.post("/api/intake", json={"enabled": True}, headers=h(admin[1]))
    f = intake.request_fetch(clean_intake, "openphish", at=now() + timedelta(days=120))
    tag = secrets.token_hex(4)
    m.record_feed(f.id, _signed(f.id, "openphish", f"https://x1-{tag}.example/\nhttps://x2-{tag}.example/"))
    assert m._intake_drip() == 1
    m.record_event(jobs[0], {"type": "status", "status": "COMPLETED", "reason": "agent_finished"})
    assert len(jobs) == 2  # 끝난 이벤트를 받자마자 다음 사건
    client.post("/api/intake", json={"enabled": False}, headers=h(admin[1]))
    m.record_event(jobs[1], {"type": "status", "status": "COMPLETED", "reason": "agent_finished"})
    assert len(jobs) == 2  # 꺼져 있으면 만들지 않는다


# ── Codex 1회차 정탐 재현 ─────────────────────────
def test_forged_feed_result_is_rejected(client, admin, clean_intake, monkeypatch, feed_key):
    """F1: 브라우저 워커도 Redis 이벤트를 쓸 수 있다. feeder 의 서명이 없거나 다른 번호·출처·본문의 서명이면 받지 않고,
    대기 줄은 그대로 두어 진짜 결과를 받는다."""
    from safetrace.api import main as m

    jobs = []
    monkeypatch.setattr(m, "enqueue", lambda cid, url: jobs.append(url))
    monkeypatch.setattr(m, "enqueue_feed", lambda fid, src: None)
    client.post("/api/intake", json={"enabled": True}, headers=h(admin[1]))
    f = intake.request_fetch(clean_intake, "openphish", at=now() + timedelta(days=150))
    other = intake.request_fetch(clean_intake, "phishtank", at=now() + timedelta(days=150))
    tag = secrets.token_hex(4)
    evil, real = f"https://target-{tag}.example/", f"https://real-{tag}.example/"
    m.record_feed(f.id, {"ok": True, "text": evil})                                                         # 서명 없음
    m.record_feed(f.id, {"ok": True, "text": evil, "mac": "0" * 64})                                        # 틀린 서명
    m.record_feed(f.id, {"ok": True, "text": evil, "mac": intake.feed_mac(KEY, other.id, "phishtank", {"ok": True, "text": evil})})  # 다른 번호
    m.record_feed(f.id, {"ok": True, "text": evil, "mac": intake.feed_mac(KEY, f.id, "phishtank", {"ok": True, "text": evil})})      # 다른 출처
    m.record_feed(f.id, {**_signed(f.id, "openphish", real), "text": evil})                                 # 본문 바꿈
    monkeypatch.setattr(m.settings, "feed_key", SecretStr(""))
    m.record_feed(f.id, {"ok": True, "text": evil, "mac": intake.feed_mac(b"", f.id, "openphish", {"ok": True, "text": evil})})     # 키가 없는 API
    monkeypatch.setattr(m.settings, "feed_key", SecretStr(KEY.decode()))
    assert m._intake_drip() == 0 and jobs == []
    with clean_intake.session() as s:
        assert s.get(FeedFetch, f.id).state == "pending"  # 진짜 결과를 기다린다
    m.record_feed(f.id, _signed(f.id, "openphish", real))
    assert m._intake_drip() == 1 and jobs == [real]


def test_disabled_intake_creates_nothing_even_if_queued(client, admin, clean_intake, monkeypatch, feed_key):
    """F2: 끈 뒤에는 대기열에 주소가 있어도, 이미 시작한 바퀴·끝난 사건의 다음 접수가 새 사건을 만들지 않는다(잠금 안에서 다시 봄)."""
    from safetrace.api import main as m

    jobs = []
    monkeypatch.setattr(m, "enqueue", lambda cid, url: jobs.append(url))
    monkeypatch.setattr(m, "enqueue_feed", lambda fid, src: None)
    client.post("/api/intake", json={"enabled": True}, headers=h(admin[1]))
    f = intake.request_fetch(clean_intake, "openphish", at=now() + timedelta(days=180))
    m.record_feed(f.id, _signed(f.id, "openphish", f"https://q-{secrets.token_hex(4)}.example/"))
    client.post("/api/intake", json={"enabled": False}, headers=h(admin[1]))
    assert m._intake_drip() == 0 and jobs == []


# ── Codex 2회차 정탐 재현 ─────────────────────────
def test_signature_covers_success_and_truncation(clean_intake):
    """F1: 서명이 본문만 덮으면 실패 결과를 빈 성공으로(재시도가 12시간 밀림), 잘림 여부를 바꿔(마지막 줄 처리) 쓸 수 있었다."""
    store = clean_intake
    kw = {"seen_hosts": set(), "allowed_ports": PORTS, "cap": 30, "kit_max": 2, "key": KEY}
    f = intake.request_fetch(store, "openphish", at=now() + timedelta(days=200))
    failed = _signed(f.id, "openphish", "", ok=False, reason="timeout")
    assert intake.record_fetch(store, f.id, {**failed, "ok": True}, **kw) is None  # 실패를 성공으로
    tag = secrets.token_hex(4)
    good = _signed(f.id, "openphish", f"https://a-{tag}.example/\nhttps://b-{tag}.example/", truncated=False)
    assert intake.record_fetch(store, f.id, {**good, "truncated": True}, **kw) is None  # 잘림 여부 바꿈
    with store.session() as s:
        assert s.get(FeedFetch, f.id).state == "pending"
    assert intake.record_fetch(store, f.id, good, **kw).picked == 2


def test_feeder_takes_only_signed_fresh_requests(monkeypatch):
    """F2: 브라우저 워커도 st:feeds 에 쓸 수 있다. API 서명이 없는 요청·같은 번호 재전송·간격 안의 다른 번호로는 외부에서 받지 않는다."""
    calls = []
    monkeypatch.setattr(feeder, "fetch", lambda src, proxy, allow: calls.append(src) or {"ok": True, "text": ""})
    r, st = _FakeRedis(), feeder.State()
    s = type("S", (), {"egress_proxy": None, "test_allowlist": []})()
    for i in range(5):  # 서명 없는 가짜 요청
        assert feeder.run_one(r, s, KEY, {"fetch_id": str(999999 + i), "source": "openphish"}, st) == "unsigned"
    assert feeder.run_one(r, s, KEY, {**_req("12"), "mac": intake.request_mac(b"x" * 32, 12, "openphish")}, st) == "unsigned"
    assert calls == []
    assert feeder.run_one(r, s, KEY, _req("12"), st) == "fetched"
    assert feeder.run_one(r, s, KEY, _req("12"), st) == "duplicate"   # 서명된 요청을 다시 넣어도
    assert feeder.run_one(r, s, KEY, _req("13"), st) == "too_soon"    # 간격 안의 다른 번호
    assert feeder.run_one(r, s, KEY, _req("14", "phishtank"), st) == "fetched"  # 출처마다 따로
    assert calls == ["openphish", "phishtank"]

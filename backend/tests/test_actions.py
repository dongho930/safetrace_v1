"""조치 추적·재확인: 위협 확정 사건에만 조치, 판 번호 잠금, 재확인은 API 가 만든 대기 번호로만 결과를 받고, 차단·삭제를
확인한 사건이 다시 접속되면 '다시 나타남'."""

import secrets
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from safetrace import accounts, actions
from safetrace.agent import recheck
from safetrace.store import Case, CaseCheck, Verdict, now
from tests.conftest import INVESTIGATOR, VIEWER

PW = "correct-horse-battery-9"


@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


def _store():
    from safetrace.api.main import store

    return store


@pytest.fixture
def no_pending():
    """시험 DB 는 실행 사이에 남는다: 대기 상한을 재는 시험 전에 남은 대기 줄을 만료시킨다."""
    store = _store()
    with store.session() as s:
        for ck in s.scalars(select(CaseCheck).where(CaseCheck.state == "pending")):
            ck.state = "expired"
        s.commit()


def _case(status="COMPLETED", verdict: str | None = "threat") -> str:
    store = _store()
    u = accounts.create_user(store, "v" + secrets.token_hex(4), PW, "reviewer") if verdict else None
    with store.session() as s, s.begin():
        c = Case(url="http://127.0.0.1:8900/smish/", source="test", status=status, created_by="t",
                 threat={"threat": "phishing", "probability": 0.9})
        s.add(c)
        s.flush()
        if verdict:
            s.add(Verdict(case_id=c.id, rev=1, decision=verdict, threat="phishing" if verdict == "threat" else None,
                          reviewer=u.username, user_id=u.id))
    return c.id


def test_save_rules_and_conflict():
    store = _store()
    cid = _case()
    with pytest.raises(actions.ActionError):  # 요청함에는 기관이 필요
        actions.save(store, cid, expected_rev=0, state="requested", agency=None, ref=None, note=None, actor="a")
    with pytest.raises(actions.ActionError):  # 다시 나타남은 시스템만
        actions.save(store, cid, expected_rev=0, state="reappeared", agency=None, ref=None, note=None, actor="a")
    a = actions.save(store, cid, expected_rev=0, state="requested", agency="kisa", ref=" 접수-123\n\t ", note="메모", actor="a")
    assert (a.rev, a.state, a.agency, a.ref) == (1, "requested", "kisa", "접수-123")
    with pytest.raises(actions.ActionConflict):  # 같은 판을 보고 다시 저장
        actions.save(store, cid, expected_rev=0, state="blocked", agency=None, ref=None, note=None, actor="b")
    assert actions.save(store, cid, expected_rev=1, state="blocked", agency=None, ref=None, note=None, actor="b").rev == 2
    assert [x.rev for x in actions.history(store, cid)] == [2, 1]
    assert actions.latest_for(store, [cid])[cid].state == "blocked"
    for bad in (_case(verdict=None), _case(verdict="benign"), _case(verdict="hold"), _case(status="RUNNING")):
        with pytest.raises(actions.ActionError):  # 위협으로 확정한 끝난 사건에만
            actions.save(store, bad, expected_rev=0, state="requested", agency="kisa", ref=None, note=None, actor="a")


def test_check_queue_rules_and_reappeared():
    store = _store()
    cid = _case()
    t0 = now()
    ck = actions.request_check(store, cid, "a", at=t0)
    with pytest.raises(actions.ActionError):  # 진행 중
        actions.request_check(store, cid, "a", at=t0 + timedelta(seconds=30))
    # 그 사건의 대기 번호가 아니거나 결과 모양이 틀리면 받지 않는다(조사 컨테이너가 보낸 값)
    other = _case()
    assert actions.record_check(store, other, ck.id, {"result": "alive"}) is None
    assert actions.record_check(store, cid, ck.id, {"result": "hacked"}) is None
    assert actions.record_check(store, cid, str(ck.id), {"result": "alive"}) is None
    got = actions.record_check(store, cid, ck.id, {"result": "gone", "reason": "http_404", "http_status": 404,
                                                    "final_host": "X.example", "title": " a \n b ", "seconds": 1.5})
    assert got is not None and got[1] is None
    assert (got[0].state, got[0].result, got[0].final_host, got[0].title) == ("done", "gone", "x.example", "a b")
    assert actions.record_check(store, cid, ck.id, {"result": "alive"}) is None  # 한 번만
    with pytest.raises(actions.ActionError):  # 방금 재확인함
        actions.request_check(store, cid, "a", at=t0 + timedelta(seconds=60))
    # 차단을 확인한 사건이 재확인에서 다시 접속되면 '다시 나타남'(요청만 한 상태면 기록하지 않음)
    actions.save(store, cid, expected_rev=0, state="requested", agency="kcsc", ref=None, note=None, actor="a")
    ck2 = actions.request_check(store, cid, "a", at=t0 + timedelta(minutes=3))
    assert actions.record_check(store, cid, ck2.id, {"result": "alive", "http_status": 200})[1] is None
    actions.save(store, cid, expected_rev=1, state="blocked", agency=None, ref=None, note=None, actor="a")
    ck3 = actions.request_check(store, cid, "a", at=t0 + timedelta(minutes=6))
    _, added = actions.record_check(store, cid, ck3.id, {"result": "alive", "http_status": 200, "final_host": "x.example"})
    assert added is not None and (added.rev, added.state, added.actor, added.check_id) == (3, "reappeared", actions.SYSTEM_ACTOR, ck3.id)


def test_expire_and_due():
    store = _store()
    cid = _case()
    long_ago = now() - timedelta(days=3)
    ck = actions.request_check(store, cid, "a", at=long_ago)
    assert actions.expire_pending(store) >= 1
    with store.session() as s:
        assert s.get(CaseCheck, ck.id).state == "expired"
    assert cid not in [x for x, _ in actions.due(store, interval=timedelta(hours=24), limit=1000)]  # 조치 없음
    actions.save(store, cid, expected_rev=0, state="requested", agency="kisa", ref=None, note=None, actor="a")
    assert cid in [x for x, _ in actions.due(store, interval=timedelta(hours=24), limit=1000)]
    actions.request_check(store, cid, "a")
    assert cid not in [x for x, _ in actions.due(store, interval=timedelta(hours=24), limit=1000)]  # 방금 함
    actions.save(store, cid, expected_rev=1, state="closed", agency=None, ref=None, note=None, actor="a")
    later = now() + timedelta(days=2)
    assert cid not in [x for x, _ in actions.due(store, interval=timedelta(hours=24), limit=1000, at=later)]  # 종결


def test_recheck_results(testpages):
    allow = {"127.0.0.1:8900"}
    r = recheck.check("http://127.0.0.1:8900/smish/", None, allow)
    assert r["result"] == "alive" and r["http_status"] == 200 and r["final_host"] == "127.0.0.1"
    assert recheck.check("http://127.0.0.1:8900/no-such-page-404", None, allow)["result"] == "gone"
    # 검문 프록시가 없으면(개발 모드) 시험 허용 목록 밖으로는 접속하지 않는다
    assert recheck.check("http://10.0.0.1/", None, allow) | {"seconds": 0} == {
        "result": "refused", "reason": "no_egress_proxy", "http_status": None, "final_host": "10.0.0.1", "title": "", "seconds": 0}
    assert recheck.check("http://example.com/", None, allow)["result"] == "refused"
    assert recheck.check("ftp://x.example/", None, allow)["result"] == "error"


def test_recheck_reads_refusal_from_proxy_connect():
    """검문 프록시가 CONNECT 에 답한 거부 사유로 사라짐(도메인 없음)·정책 거부를 가른다."""
    for reason, want in (("dns_failure", "gone"), ("non_public_ip", "refused")):
        crlf = chr(13) + chr(10)
        port = _serve_once(lambda c, r=reason, nl=crlf: c.sendall(
            f"HTTP/1.1 403 Forbidden{nl}X-SafeTrace-Egress: {r}{nl}Connection: close{nl}{nl}".encode()))
        got = recheck.check("https://gone.example/", f"http://127.0.0.1:{port}")
        assert (got["result"], got["reason"]) == (want, reason)


def test_api_actions_and_recheck(client, testpages):
    store = _store()
    cid = _case()
    name = "act" + secrets.token_hex(3)
    accounts.create_user(store, name, PW, "investigator")
    tok = client.post("/api/auth/login", json={"username": name, "password": PW}).json()["token"]
    body = {"rev": 0, "state": "requested", "agency": "kisa", "ref": "KISA-2026-1"}
    assert client.post(f"/api/cases/{cid}/actions", json=body, headers=h(INVESTIGATOR)).status_code == 403  # 자동화 토큰
    assert client.post(f"/api/cases/{cid}/actions", json=body, headers=h(VIEWER)).status_code == 403
    r = client.post(f"/api/cases/{cid}/actions", json=body, headers=h(tok))
    assert r.status_code == 201 and r.json()["rev"] == 1
    assert client.post(f"/api/cases/{cid}/actions", json=body, headers=h(tok)).status_code == 409
    assert client.post(f"/api/cases/{cid}/actions", json={**body, "rev": 1, "state": "reappeared", "agency": None},
                       headers=h(tok)).status_code == 422
    c = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert c["action"]["state"] == "requested" and c["action"]["agency"] == "kisa"
    assert any(x["id"] == cid and x["action"]["state"] == "requested"
               for x in client.get("/api/cases?limit=200", headers=h(VIEWER)).json() if x.get("action"))

    assert client.post(f"/api/cases/{cid}/recheck", headers=h(VIEWER)).status_code == 403
    r = client.post(f"/api/cases/{cid}/recheck", headers=h(INVESTIGATOR))
    assert r.status_code == 202 and r.json()["state"] == "pending"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:  # 개발 모드: 같은 프로세스 스레드가 접속해 결과를 넣는다
        v = client.get(f"/api/cases/{cid}/actions", headers=h(VIEWER)).json()
        if v["checks"][0]["state"] == "done":
            break
        time.sleep(0.3)
    assert v["checks"][0]["result"] == "alive" and v["checks"][0]["http_status"] == 200
    assert client.post(f"/api/cases/{cid}/recheck", headers=h(INVESTIGATOR)).status_code == 409  # 방금 함
    # 조사 컨테이너가 거짓 대기 번호로 결과를 보내면 받지 않는다
    from safetrace.api.main import record_event

    record_event(cid, {"type": "check", "check_id": 999999, "result": {"result": "alive"}})
    with store.session() as s:
        assert s.get(CaseCheck, 999999) is None


def test_scheduler_round(client, no_pending):
    from safetrace.api import main as m

    store = _store()
    cid = _case()
    actions.save(store, cid, expected_rev=0, state="blocked", agency=None, ref=None, note=None, actor="a")
    sent, asked = [], {}
    real_enqueue, real_due = m.enqueue_check, m.actions.due
    m.enqueue_check = lambda case_id, check_id, url: sent.append((case_id, check_id, url))
    # 시험 DB 에는 이전 실행의 추적 사건이 남는다: 고르는 규칙(due)은 따로 시험하고 여기서는 한 바퀴의 연결만 본다
    m.actions.due = lambda store, **kw: (asked.update(kw), [(cid, "http://127.0.0.1:8900/smish/")])[1]
    try:
        n = m.recheck_due()
    finally:
        m.enqueue_check, m.actions.due = real_enqueue, real_due
    assert n == 1 and sent[0][0] == cid and sent[0][2] == "http://127.0.0.1:8900/smish/"
    assert asked["interval"] == timedelta(hours=m.settings.recheck_interval_hours) and asked["limit"] == m.settings.recheck_batch
    with store.session() as s:
        ck = s.get(CaseCheck, sent[0][1])
        assert (ck.case_id, ck.state, ck.requested_by) == (cid, "pending", actions.SYSTEM_ACTOR)
        ck.state = "expired"  # 다음 실행의 상한 계산에 남지 않게
        s.commit()


# ── Codex 1회차 정탐 재현 ─────────────────────────
import socket  # noqa: E402
import threading  # noqa: E402


def _serve_once(handler) -> int:
    """연결 하나를 받아 handler(conn) 를 부르는 작은 서버. 반환: 포트."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def run():
        try:
            conn, _ = srv.accept()
            with conn:
                conn.recv(4096)
                handler(conn)
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def test_no_proxy_recheck_cannot_be_rebound(testpages, monkeypatch):
    """F1: 검문 프록시 없이 재확인하면 검사(공인 주소)와 연결(내부 주소)이 DNS 를 따로 풀어 rebinding 으로 내부에 닿는다."""
    real = socket.getaddrinfo

    def fake(host, *a, **k):
        return real("127.0.0.1" if host == "rebind.example" else host, *a, **k)

    monkeypatch.setattr(recheck, "resolve", lambda h, p: ("93.184.216.34",), raising=False)  # 검사할 때는 공인 주소(예전 코드)
    monkeypatch.setattr(socket, "getaddrinfo", fake)  # 연결할 때는 내부 주소(시험 서버)
    r = recheck.check("http://rebind.example:8900/smish/", None, {"127.0.0.1:8900"})
    assert r["result"] == "refused" and r["http_status"] is None


def test_target_cannot_forge_egress_refusal():
    """F2: 대상 서버가 검문 프록시의 거부 머리(X-SafeTrace-Egress: dns_failure)를 흉내 내 '사라짐'으로 보이게 할 수 없다."""
    port = _serve_once(lambda c: c.sendall(b"HTTP/1.1 200 OK\r\nX-SafeTrace-Egress: dns_failure\r\nContent-Length: 2\r\n"
                                           b"Connection: close\r\n\r\nok"))
    r = recheck.check(f"http://127.0.0.1:{port}/", None, {f"127.0.0.1:{port}"})
    assert r["result"] == "alive" and r["http_status"] == 200


def test_slow_headers_respect_budget():
    """F4: 응답 머리를 조금씩 보내는 서버가 재확인 시간 예산(budget)을 넘겨 워커를 붙잡지 못한다."""
    def drip(c):
        c.sendall(b"HTTP/1.1 200 OK\r\n")
        for _ in range(16):
            time.sleep(0.5)
            try:
                c.sendall(b"X: y\r\n")
            except OSError:
                return

    port = _serve_once(drip)
    t0 = time.monotonic()
    r = recheck.check(f"http://127.0.0.1:{port}/", None, {f"127.0.0.1:{port}"}, budget=2.0)
    assert time.monotonic() - t0 < 4.5 and r["result"] == "unreachable"


def test_recheck_queue_has_global_cap_and_one_pending_per_case(no_pending):
    """F3: 재확인 대기에 전체 상한이 있고, 한 사건에는 동시에 하나만(DB 제약)."""
    store = _store()
    got, refused, actor = [], 0, "flood-" + secrets.token_hex(3)
    for _ in range(actions.MAX_PENDING_PER_ACTOR + 3):
        try:
            got.append(actions.request_check(store, _case(), actor).id)
        except actions.ActionError:
            refused += 1
    with store.session() as s:  # 다음 실행의 상한 계산에 남지 않게
        for i in got:
            s.get(CaseCheck, i).state = "expired"
        s.commit()
    assert len(got) == actions.MAX_PENDING_PER_ACTOR and refused == 3
    cid = _case()
    with store.session() as s, s.begin():
        s.add(CaseCheck(case_id=cid, state="pending", requested_by="x"))
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError), store.session() as s, s.begin():
        s.add(CaseCheck(case_id=cid, state="pending", requested_by="y"))


# ── Codex 2회차 정탐 재현 ─────────────────────────
def test_concurrent_requests_cannot_exceed_actor_cap(no_pending, monkeypatch):
    """2회차 F1: 서로 다른 사건에 동시에 재확인을 요청해도 주체별 상한을 넘지 않는다(상한 검사와 접수를 한 잠금으로)."""
    store = _store()
    actor = "race-" + secrets.token_hex(3)
    made = [actions.request_check(store, _case(), actor).id for _ in range(actions.MAX_PENDING_PER_ACTOR - 1)]
    a, b = _case(), _case()
    barrier = threading.Barrier(2)
    real_scalar = None

    from sqlalchemy.orm import Session

    real_scalar = Session.scalar

    def slow_scalar(self, stmt, *args, **kw):  # 대기 수를 읽은 직후 두 요청이 서로를 기다린다
        out = real_scalar(self, stmt, *args, **kw)
        if "count" in str(stmt).lower():
            try:
                barrier.wait(timeout=1)
            except threading.BrokenBarrierError:
                pass
        return out

    monkeypatch.setattr(Session, "scalar", slow_scalar)
    results = {}

    def go(cid):
        try:
            results[cid] = actions.request_check(store, cid, actor).id
        except actions.ActionError:
            results[cid] = None

    ts = [threading.Thread(target=go, args=(c,)) for c in (a, b)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(10)
    monkeypatch.setattr(Session, "scalar", real_scalar)
    got = [x for x in results.values() if x]
    with store.session() as s:  # 다음 실행의 상한 계산에 남지 않게
        for i in [*made, *got]:
            s.get(CaseCheck, i).state = "expired"
        s.commit()
    assert len(got) == 1  # 9 + 1 = 상한 10


def test_compressed_body_is_not_inflated_without_limit():
    """2회차 F2: 이중 gzip 으로 크게 풀리는 응답을 상한 없이 풀지 않는다(재확인은 제목만 읽는다)."""
    import gzip
    import tracemalloc

    inner = gzip.compress(b"\0" * (64 << 20))  # 64MiB 가 약 65KB 로
    body = gzip.compress(inner)
    head = (f"HTTP/1.1 200 OK{chr(13)}{chr(10)}Content-Encoding: gzip, gzip{chr(13)}{chr(10)}Content-Length: {len(body)}"
            f"{chr(13)}{chr(10)}Connection: close{chr(13)}{chr(10)}{chr(13)}{chr(10)}").encode()
    port = _serve_once(lambda c: c.sendall(head + body))
    tracemalloc.start()
    try:
        r = recheck.check(f"http://127.0.0.1:{port}/", None, {f"127.0.0.1:{port}"})
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert r["result"] == "alive" and peak < (16 << 20), peak


def test_single_gzip_title_still_read():
    """압축 없이 달라고 해도 gzip 으로 보내는 서버의 제목은 한 단계 풀어 읽는다."""
    import gzip

    body = gzip.compress("<html><title>Blue Tick Verified</title></html>".encode())
    nl = chr(13) + chr(10)
    head = f"HTTP/1.1 200 OK{nl}Content-Encoding: gzip{nl}Content-Length: {len(body)}{nl}Connection: close{nl}{nl}".encode()
    port = _serve_once(lambda c: c.sendall(head + body))
    r = recheck.check(f"http://127.0.0.1:{port}/", None, {f"127.0.0.1:{port}"})
    assert (r["result"], r["title"]) == ("alive", "Blue Tick Verified")

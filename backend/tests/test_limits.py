"""접속 주소별 로그인 실패 제한, 접수 한도. 브라우저 없이 돈다."""

import secrets
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from starlette.requests import Request

from safetrace import accounts
from safetrace.ratelimit import FailureLimiter
from safetrace.store import AuditLog, Case

PW = "correct-horse-battery-9"


@pytest.fixture(scope="module")
def main():
    from safetrace.api import main

    return main


@pytest.fixture(scope="module")
def client(main):
    with TestClient(main.app) as c:
        yield c


def new_user(store, role):
    name = f"l{role[:3]}{secrets.token_hex(4)}"
    accounts.create_user(store, name, PW, role)
    return name


def login(client, name, pw=PW):
    return client.post("/api/auth/login", json={"username": name, "password": pw})


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


# ── 제한기 ─────────────────────────────────────────────
def test_limiter_blocks_after_max_until_window_ends():
    clock = Clock()
    lim = FailureLimiter(3, 900, clock=clock)
    assert [lim.take("a")[0] for _ in range(3)] == [0, 0, 0]
    assert lim.take("a") == (900, True)  # 처음 막힘만 알린다
    clock.t += 300
    assert lim.take("a") == (600, False)
    assert lim.take("b") == (0, False)  # 다른 주소는 따로 센다
    clock.t += 600
    assert lim.take("a") == (0, False)  # 창이 끝나면 다시 센다


def test_limiter_give_back_only_returns_own_slot():
    lim = FailureLimiter(2, 900, clock=Clock())
    lim.take("a")  # 실패
    lim.take("a")  # 성공 → 돌려줌
    lim.give_back("a")
    assert lim.take("a")[0] == 0  # 실패 1 + 이번 1 = 2
    assert lim.take("a")[0] > 0


def test_limiter_concurrent_takes_never_exceed_max():
    lim = FailureLimiter(30, 900)
    ok = []
    barrier = threading.Barrier(64)

    def go():
        barrier.wait()
        ok.append(lim.take("a")[0] == 0)

    threads = [threading.Thread(target=go) for _ in range(64)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(ok) == 30


def test_limiter_memory_bounded():
    clock = Clock()
    lim = FailureLimiter(3, 900, max_keys=100, clock=clock)
    for i in range(1000):
        lim.take(f"10.0.{i // 256}.{i % 256}")
        clock.t += 0.01
    assert len(lim._windows) <= 100


# ── 로그인 ─────────────────────────────────────────────
@pytest.fixture
def small_limiter(main, monkeypatch):
    lim = FailureLimiter(3, 900)
    monkeypatch.setattr(main, "login_limiter", lim)
    return lim


def test_login_ip_limit_blocks_spray_even_with_correct_password(client, main, small_limiter):
    store = main.store
    good = new_user(store, "viewer")
    others = [new_user(store, "viewer") for _ in range(3)]
    for name in others:  # 아이디를 바꿔 가며 한 번씩(계정별 잠금에는 걸리지 않는 스프레이)
        assert login(client, name, "wrong-password-123").status_code == 401
    r = login(client, good)
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    assert "token" not in r.text
    assert login(client, "nobody-" + secrets.token_hex(3)).status_code == 429  # 계정이 있든 없든 같은 응답
    assert not accounts.is_locked(accounts.get_user(store, good))  # 계정은 잠기지 않았다(주소만 막힘)
    with store.session() as s:
        limited = s.scalars(select(AuditLog).where(AuditLog.action == "auth.ip_limited")
                            .order_by(AuditLog.id.desc()).limit(2)).all()
    assert limited[0].detail == "ip=testclient failures=3"


def test_successful_logins_do_not_use_up_the_limit(client, main, small_limiter):
    name = new_user(main.store, "viewer")
    for _ in range(10):
        assert login(client, name).status_code == 200
    assert login(client, name, "wrong-password-123").status_code == 401


def test_blocked_login_skips_password_check(client, main, small_limiter, monkeypatch):
    for _ in range(3):
        small_limiter.take("testclient")
    called = []
    monkeypatch.setattr(accounts, "_verify", lambda *a: called.append(1) or False)
    assert login(client, "nobody").status_code == 429
    assert called == []  # Argon2id 계산을 시키지 않는다


def _req(peer: str, xff: str | None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return Request({"type": "http", "client": (peer, 5000), "headers": headers})


def test_client_ip_trusts_forwarded_only_from_proxy(main, monkeypatch):
    monkeypatch.setattr(main.settings, "trusted_proxies", ["web"])
    monkeypatch.setattr(main.socket, "getaddrinfo", lambda name, port: [(0, 0, 0, "", ("172.18.0.9", 0))])
    monkeypatch.setattr(main, "_proxy_ips", (0.0, frozenset()))
    assert main._client_ip(_req("172.18.0.9", "203.0.113.7")) == "203.0.113.7"
    assert main._client_ip(_req("172.18.0.9", "1.1.1.1, 203.0.113.7")) == "203.0.113.7"  # 프록시가 붙인 마지막 값
    assert main._client_ip(_req("172.18.0.9", "not-an-ip")) == "172.18.0.9"
    assert main._client_ip(_req("172.18.0.5", "203.0.113.7")) == "172.18.0.5"  # 다른 컨테이너(예: 에이전트)가 보낸 값은 무시
    monkeypatch.setattr(main.settings, "trusted_proxies", [])
    assert main._client_ip(_req("172.18.0.9", "203.0.113.7")) == "172.18.0.9"  # 설정이 없으면 믿지 않는다


def test_client_ip_follows_restarted_proxy(main, monkeypatch):
    ip = ["172.18.0.9"]
    monkeypatch.setattr(main.settings, "trusted_proxies", ["web"])
    monkeypatch.setattr(main.socket, "getaddrinfo", lambda name, port: [(0, 0, 0, "", (ip[0], 0))])
    monkeypatch.setattr(main, "_proxy_ips", (0.0, frozenset()))
    assert main._client_ip(_req("172.18.0.9", "203.0.113.7")) == "203.0.113.7"
    ip[0] = "172.18.0.12"  # web 을 다시 띄워 주소가 바뀜
    monkeypatch.setattr(main, "_proxy_ips", (0.0, main._proxy_ips[1]))  # 다시 찾기 간격이 지났다고 치고
    assert main._client_ip(_req("172.18.0.12", "203.0.113.7")) == "203.0.113.7"


# ── 접수 한도 ───────────────────────────────────────────
@pytest.fixture
def intake(main, monkeypatch):
    """조사를 실제로 돌리지 않고(사건이 대기로 남게) 시험이 만든 사건은 끝에 정리한다."""
    monkeypatch.setattr(main, "enqueue", lambda cid, url: None)
    made = []
    yield made
    for cid in made:
        main.store.add_event(cid, {"type": "status", "status": "FAILED", "reason": "test_cleanup"})


def _submit(client, main, token, made, url="http://127.0.0.1:8900/benign/"):
    r = client.post("/api/cases", json={"url": url}, headers={"Authorization": f"Bearer {token}"})
    if r.status_code == 201:
        made.append(r.json()["id"])
    return r


def test_pending_cases_limited_per_principal(client, main, intake, monkeypatch):
    monkeypatch.setattr(main.settings, "case_max_pending_per_principal", 3)
    store = main.store
    a = login(client, new_user(store, "investigator")).json()["token"]
    b = login(client, new_user(store, "investigator")).json()["token"]
    assert [_submit(client, main, a, intake).status_code for _ in range(3)] == [201, 201, 201]
    r = _submit(client, main, a, intake)
    assert r.status_code == 429 and r.headers["retry-after"] == "60"
    assert _submit(client, main, b, intake).status_code == 201  # 다른 담당자는 막히지 않는다
    store.add_event(intake[0], {"type": "status", "status": "COMPLETED"})  # 하나가 끝나면 다시 넣을 수 있다
    assert _submit(client, main, a, intake).status_code == 201
    with store.session() as s:
        rejected = s.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "case.rejected",
                                                                            AuditLog.detail.like("limit=principal%")))
    assert rejected >= 1


def test_unknown_status_does_not_hold_a_slot(client, main, intake, monkeypatch):
    monkeypatch.setattr(main.settings, "case_max_pending_per_principal", 1)
    name = new_user(main.store, "investigator")
    tok = login(client, name).json()["token"]
    with main.store.session() as s:  # 상태 전이 검사 전에 남은 옛 기록(실제 로컬 DB 에 'DONE' 이 있었다)
        s.add(Case(url="http://127.0.0.1:8900/benign/", source="test", created_by=name, status="DONE"))
        s.commit()
    assert _submit(client, main, tok, intake).status_code == 201


def test_idempotent_retry_not_blocked_by_limit(client, main, intake, monkeypatch):
    monkeypatch.setattr(main.settings, "case_max_pending_per_principal", 1)
    tok = login(client, new_user(main.store, "investigator")).json()["token"]
    hdr = {"Authorization": f"Bearer {tok}", "Idempotency-Key": "k-" + secrets.token_hex(4)}
    r1 = client.post("/api/cases", json={"url": "http://127.0.0.1:8900/benign/"}, headers=hdr)
    intake.append(r1.json()["id"])
    r2 = client.post("/api/cases", json={"url": "http://127.0.0.1:8900/benign/"}, headers=hdr)
    assert r2.status_code == 201 and r2.json()["id"] == r1.json()["id"]  # 네트워크 재시도는 한도와 무관하게 같은 사건


def test_pending_cases_limited_in_total(client, main, intake, monkeypatch):
    with main.store.session() as s:
        pending = s.scalar(select(func.count()).select_from(Case).where(Case.status.in_(main.PENDING)))
    monkeypatch.setattr(main.settings, "case_max_pending_total", pending + 1)
    a = login(client, new_user(main.store, "investigator")).json()["token"]
    b = login(client, new_user(main.store, "investigator")).json()["token"]
    assert _submit(client, main, a, intake).status_code == 201
    r = _submit(client, main, b, intake)
    assert r.status_code == 503 and r.headers["retry-after"] == "60"


def test_concurrent_submissions_respect_limit(client, main, intake, monkeypatch):
    monkeypatch.setattr(main.settings, "case_max_pending_per_principal", 5)
    tok = login(client, new_user(main.store, "investigator")).json()["token"]
    codes = []
    barrier = threading.Barrier(12)

    def go():
        barrier.wait()
        codes.append(_submit(client, main, tok, intake).status_code)

    threads = [threading.Thread(target=go) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(codes) == [201] * 5 + [429] * 7

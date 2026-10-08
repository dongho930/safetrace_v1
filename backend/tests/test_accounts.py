"""담당자 계정(Argon2id)·세션·RBAC 시험. 브라우저 없이 돈다."""

import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from safetrace import accounts
from safetrace.store import AuthSession, User, now
from tests.conftest import INVESTIGATOR, SERVICE_ADMIN, VIEWER

PW = "correct-horse-battery-9"


@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def store():
    from safetrace.api.main import store

    return store


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


def new_user(store, role="viewer"):
    # 시험 DB 가 실행 사이에 남으므로 아이디를 매번 새로 만든다
    name = f"t{role[:3]}{secrets.token_hex(4)}"
    accounts.create_user(store, name, PW, role)
    return name


def login(client, name, pw=PW):
    return client.post("/api/auth/login", json={"username": name, "password": pw})


def test_password_policy(store):
    for bad in ["short-1", "a" * 20, "x" * 129]:
        with pytest.raises(accounts.AccountError):
            accounts.check_password(bad, "alice")
    with pytest.raises(accounts.AccountError):
        accounts.check_password("my-alice-password-1", "alice")
    with pytest.raises(accounts.AccountError):
        accounts.create_user(store, "Bad Name", PW, "viewer")
    name = new_user(store)
    with pytest.raises(accounts.AccountError):
        accounts.create_user(store, name, PW, "viewer")  # 같은 아이디


def test_stored_as_argon2id_and_token_hash_only(client, store):
    name = new_user(store)
    r = login(client, name)
    assert r.status_code == 200
    token = r.json()["token"]
    with store.session() as s:
        u = s.scalar(select(User).where(User.username == name))
        sessions = list(s.scalars(select(AuthSession).where(AuthSession.user_id == u.id)))
    assert u.password_hash.startswith("$argon2id$") and PW not in u.password_hash
    assert [x.token_hash for x in sessions] == [accounts.token_digest(token)]


def test_login_me_logout(client, store):
    name = new_user(store, "reviewer")
    r = login(client, name)
    assert r.status_code == 200
    body = r.json()
    assert body["user"] == {"name": name, "role": "reviewer", "kind": "user"}
    tok = body["token"]
    assert client.get("/api/auth/me", headers=h(tok)).json()["name"] == name
    assert client.get("/api/cases", headers=h(tok)).status_code == 200
    assert client.post("/api/auth/logout", headers=h(tok)).status_code == 204
    assert client.get("/api/auth/me", headers=h(tok)).status_code == 401


def test_failed_login_same_answer_and_lockout(client, store):
    name = new_user(store)
    unknown = login(client, "nobody-" + secrets.token_hex(3))
    wrong = login(client, name, "wrong-password-123")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()  # 계정이 있는지 알 수 없다
    for _ in range(accounts.MAX_FAILED - 1):
        assert login(client, name, "wrong-password-123").status_code == 401
    # 잠긴 뒤에는 맞는 비밀번호도 거부, 응답은 같다
    locked = login(client, name)
    assert locked.status_code == 401 and locked.json() == wrong.json()
    assert accounts.is_locked(accounts.get_user(store, name))
    accounts.update_user(store, name, unlock=True)
    assert login(client, name).status_code == 200


def test_inactive_and_role_change_revoke_sessions(client, store):
    name = new_user(store, "investigator")
    tok = login(client, name).json()["token"]
    accounts.update_user(store, name, role="viewer")
    assert client.get("/api/auth/me", headers=h(tok)).status_code == 401  # 역할이 바뀌면 다시 로그인
    tok = login(client, name).json()["token"]
    assert client.get("/api/auth/me", headers=h(tok)).json()["role"] == "viewer"
    accounts.update_user(store, name, active=False)
    assert client.get("/api/auth/me", headers=h(tok)).status_code == 401
    assert login(client, name).status_code == 401


def test_idle_and_absolute_expiry(client, store):
    name = new_user(store)
    tok = login(client, name).json()["token"]
    with store.session() as s, s.begin():
        s.get(AuthSession, accounts.token_digest(tok)).last_seen = now() - accounts.SESSION_IDLE - timedelta(seconds=1)
    assert client.get("/api/auth/me", headers=h(tok)).status_code == 401
    tok = login(client, name).json()["token"]
    with store.session() as s, s.begin():
        s.get(AuthSession, accounts.token_digest(tok)).expires_at = now() - timedelta(seconds=1)
    assert client.get("/api/auth/me", headers=h(tok)).status_code == 401


def test_change_password(client, store):
    name = new_user(store)
    tok = login(client, name).json()["token"]
    bad = client.post("/api/auth/password", json={"current": "wrong-password-123", "new": "another-good-pass-7"},
                      headers=h(tok))
    assert bad.status_code == 403
    weak = client.post("/api/auth/password", json={"current": PW, "new": "short"}, headers=h(tok))
    assert weak.status_code == 422
    ok = client.post("/api/auth/password", json={"current": PW, "new": "another-good-pass-7"}, headers=h(tok))
    assert ok.status_code == 204
    assert client.get("/api/auth/me", headers=h(tok)).status_code == 401  # 세션이 모두 끊김
    assert login(client, name).status_code == 401
    assert login(client, name, "another-good-pass-7").status_code == 200


def test_rbac(client, store):
    viewer = login(client, new_user(store, "viewer")).json()["token"]
    investigator = login(client, new_user(store, "investigator")).json()["token"]
    admin_name = new_user(store, "admin")
    admin = login(client, admin_name).json()["token"]

    # 조회는 모두, 접수는 조사관 이상
    assert client.get("/api/cases", headers=h(viewer)).status_code == 200
    assert client.post("/api/cases", json={"url": "https://example.com/"}, headers=h(viewer)).status_code == 403
    # 계정 관리는 사람 관리자만: 조사관·관리자 역할 자동화 토큰 모두 거부
    assert client.get("/api/users", headers=h(investigator)).status_code == 403
    assert client.get("/api/users", headers=h(SERVICE_ADMIN)).status_code == 403
    assert client.post("/api/users", json={"username": "svcmade", "password": PW, "role": "admin"},
                       headers=h(SERVICE_ADMIN)).status_code == 403
    assert client.get("/api/users", headers=h(admin)).status_code == 200

    name = "made" + secrets.token_hex(4)
    r = client.post("/api/users", json={"username": name, "password": PW, "role": "investigator"}, headers=h(admin))
    assert r.status_code == 201 and r.json()["role"] == "investigator"
    assert "password" not in r.text and "hash" not in r.text
    assert client.post("/api/users", json={"username": name + "x", "password": "short", "role": "viewer"},
                       headers=h(admin)).status_code == 422
    assert client.patch(f"/api/users/{name}", json={"role": "reviewer"}, headers=h(admin)).json()["role"] == "reviewer"
    # 자기 관리자 권한은 내리거나 끌 수 없다(관리자가 사라지는 사고 방지)
    assert client.patch(f"/api/users/{admin_name}", json={"role": "viewer"}, headers=h(admin)).status_code == 422
    assert client.patch(f"/api/users/{admin_name}", json={"active": False}, headers=h(admin)).status_code == 422
    assert client.patch("/api/users/no-such-user", json={"unlock": True}, headers=h(admin)).status_code == 404


def test_service_tokens_still_work(client):
    assert client.get("/api/auth/me", headers=h(INVESTIGATOR)).json() == {
        "name": "investigator-0", "role": "investigator", "kind": "service"}
    assert client.get("/api/cases", headers=h(VIEWER)).status_code == 200
    # 자동화 토큰은 로그아웃할 세션이 없고, 비밀번호도 없다
    assert client.post("/api/auth/logout", headers=h(VIEWER)).status_code == 204
    assert client.get("/api/cases", headers=h(VIEWER)).status_code == 200
    assert client.post("/api/auth/password", json={"current": "x" * 12, "new": "y" * 12},
                       headers=h(VIEWER)).status_code == 403


def test_audit_log(client, store):
    from safetrace.store import AuditLog

    name = new_user(store)
    login(client, name, "wrong-password-123")
    login(client, name)
    with store.session() as s:
        rows = list(s.scalars(select(AuditLog).where(AuditLog.actor == name).order_by(AuditLog.id)))
    assert [(r.action, r.detail) for r in rows] == [("auth.login_failed", "bad_password"), ("auth.login", "")]
    assert all(PW not in (r.detail or "") for r in rows)


def test_cli_add_and_passwd(store, monkeypatch, capsys):
    name = "cli" + secrets.token_hex(4)
    answers = iter([PW, PW, "new-good-password-5", "new-good-password-5"])
    monkeypatch.setattr(accounts.getpass, "getpass", lambda _prompt: next(answers))
    assert accounts.main(["add", name, "--role", "admin"]) == 0
    assert accounts.get_user(store, name).role == "admin"
    assert accounts.main(["passwd", name]) == 0
    assert accounts.login(store, name, "new-good-password-5") is not None
    monkeypatch.setattr(accounts.getpass, "getpass", lambda _prompt: "short")
    assert accounts.main(["add", name + "b", "--role", "viewer"]) == 1
    assert "오류" in capsys.readouterr().err


def test_cli_password_stdin(store, monkeypatch):
    import io

    name = "std" + secrets.token_hex(4)
    monkeypatch.setattr(accounts.sys, "stdin", io.StringIO(PW + "\n"))
    assert accounts.main(["add", name, "--role", "viewer", "--password-stdin"]) == 0
    assert accounts.login(store, name, PW) is not None

"""담당자 판정 저장 시험: 권한(검토관 이상·사람 계정만), 판 쌓기, 낙관적 잠금, 감사로그. 브라우저 없이 돈다."""

import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from safetrace import accounts, verdicts
from safetrace.store import AuditLog, Case, Verdict
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


def user_token(client, store, role):
    name = f"v{role[:3]}{secrets.token_hex(4)}"
    accounts.create_user(store, name, PW, role)
    return name, client.post("/api/auth/login", json={"username": name, "password": PW}).json()["token"]


def new_case(store, status="REVIEW_REQUIRED"):
    with store.session() as s, s.begin():
        c = Case(url="https://example.test/login", source="test", status=status, created_by="t",
                 threat={"threat": "scam", "probability": 0.55, "hold": True}, head_seq=7, head_hash="ab" * 32)
        s.add(c)
    return c.id


def post(client, tok, cid, **body):
    return client.post(f"/api/cases/{cid}/verdicts", headers=h(tok), json=body)


def test_reviewer_saves_and_case_shows_verdict(client, store):
    name, tok = user_token(client, store, "reviewer")
    cid = new_case(store)
    r = post(client, tok, cid, rev=0, decision="threat", threat="phishing", note="  국세청 사칭\r\n로그인 유도 ")
    assert r.status_code == 201, r.text
    v = r.json()
    assert (v["rev"], v["decision"], v["threat"], v["reviewer"]) == (1, "threat", "phishing", name)
    assert v["note"] == "국세청 사칭\n로그인 유도"
    assert (v["ai_threat"], v["head_seq"]) == ("scam", 7)  # 판정 당시 AI 의견·증거 체인 끝을 함께 남긴다
    with store.session() as s:
        assert s.scalar(select(Verdict.head_hash).where(Verdict.case_id == cid)) == "ab" * 32
    assert client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()["verdict"]["rev"] == 1
    listed = {c["id"]: c for c in client.get("/api/cases?limit=200", headers=h(VIEWER)).json()}
    assert listed[cid]["verdict"]["threat"] == "phishing"
    with store.session() as s:
        a = s.scalars(select(AuditLog).where(AuditLog.case_id == cid, AuditLog.action == "verdict.save")).one()
    assert a.actor == name and "rev=1 decision=threat threat=phishing ai=scam head=7" in a.detail


def test_only_human_reviewers_can_decide(client, store):
    cid = new_case(store)
    body = {"rev": 0, "decision": "benign"}
    assert client.post(f"/api/cases/{cid}/verdicts", json=body).status_code == 401
    for role in ("viewer", "investigator"):
        _, tok = user_token(client, store, role)
        assert post(client, tok, cid, **body).status_code == 403
    for svc in (VIEWER, INVESTIGATOR, SERVICE_ADMIN):  # 자동화 토큰은 관리자 역할이어도 확정할 수 없다
        assert post(client, svc, cid, **body).status_code == 403
    _, admin = user_token(client, store, "admin")
    assert post(client, admin, cid, **body).status_code == 201
    assert client.get(f"/api/cases/{cid}/verdicts", headers=h(VIEWER)).status_code == 200  # 기록 열람은 열람자도


def test_revisions_and_optimistic_lock(client, store):
    a, ta = user_token(client, store, "reviewer")
    b, tb = user_token(client, store, "reviewer")
    cid = new_case(store)
    assert post(client, ta, cid, rev=0, decision="hold", note="추가 확인 필요").status_code == 201
    # 둘 다 1판을 보고 있다가 a 가 먼저 저장
    assert post(client, ta, cid, rev=1, decision="threat", threat="scam").json()["rev"] == 2
    r = post(client, tb, cid, rev=1, decision="benign")
    assert r.status_code == 409 and a in r.json()["detail"]
    assert post(client, tb, cid, rev=0, decision="benign").status_code == 409  # 처음 판도 마찬가지
    assert post(client, tb, cid, rev=5, decision="benign").status_code == 409  # 없는 판
    # 최신 판을 보고 다시 저장하면 들어간다. 이전 판은 그대로 남는다
    assert post(client, tb, cid, rev=2, decision="benign").json()["rev"] == 3
    hist = client.get(f"/api/cases/{cid}/verdicts", headers=h(VIEWER)).json()
    assert [(x["rev"], x["decision"], x["reviewer"]) for x in hist] == [(3, "benign", b), (2, "threat", a), (1, "hold", a)]
    with store.session() as s:
        n = len(s.scalars(select(AuditLog).where(AuditLog.case_id == cid, AuditLog.action == "verdict.conflict")).all())
    assert n == 3


def test_concurrent_save_same_rev_only_one_wins(store, monkeypatch):
    """판 번호 확인과 저장 사이에 다른 요청이 끼어들어도 (case_id, rev) 유일 제약이 막는다."""
    cid = new_case(store)
    u = accounts.create_user(store, f"vrace{secrets.token_hex(4)}", PW, "reviewer")
    verdicts.save(store, cid, expected_rev=0, decision="hold", threat=None, note=None, reviewer="x", user_id=u.id)
    real = verdicts._latest
    calls = iter([None])  # 첫 확인은 '판정 없음'을 본 것처럼 만든다(이미 1판이 있음)
    monkeypatch.setattr(verdicts, "_latest", lambda s, c: next(calls, None) or real(s, c))
    with pytest.raises(verdicts.VerdictConflict) as e:
        verdicts.save(store, cid, expected_rev=0, decision="benign", threat=None, note=None, reviewer="y", user_id=u.id)
    assert e.value.current.rev == 1 and len(verdicts.history(store, cid)) == 1


def test_validation(client, store):
    _, tok = user_token(client, store, "reviewer")
    cid = new_case(store)
    assert post(client, tok, cid, rev=0, decision="threat").status_code == 422  # 유형 없음
    assert post(client, tok, cid, rev=0, decision="benign", threat="scam").status_code == 422
    assert post(client, tok, cid, rev=0, decision="confirm").status_code == 422
    assert post(client, tok, cid, rev=0, decision="threat", threat="benign").status_code == 422
    assert post(client, tok, cid, rev=-1, decision="benign").status_code == 422
    assert post(client, tok, cid, rev=0, decision="hold", note="x" * 1001).status_code == 422
    r = post(client, tok, cid, rev=0, decision="hold", note="a\x00b\x1b[31m\n\t")
    assert r.status_code == 201 and r.json()["note"] == "ab[31m"
    assert post(client, tok, "0" * 36, rev=0, decision="benign").status_code == 404
    running = new_case(store, status="RUNNING")
    r = post(client, tok, running, rev=0, decision="benign")
    assert r.status_code == 422 and "조사가 끝난 뒤" in r.json()["detail"]

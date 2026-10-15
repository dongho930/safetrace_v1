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


# ── related-sites PR 3: 원래 결과 먼저 ─────────────────────────
_MAIN_THREAT = {"threat": "phishing", "probability": 0.9, "hold": False}


def _running_case_with_chain(store):
    """조사 중인 사건과 아직 열린 체인(개발 모드: 같은 프로세스가 쓴 체인)."""
    from safetrace.agent.runner import make_sealer
    from safetrace.api.main import settings
    from safetrace.evidence import EvidenceWriter

    with store.session() as s, s.begin():
        c = Case(url="https://example.test/related", source="test", status="RUNNING", created_by="t")
        s.add(c)
    w = EvidenceWriter(settings.evidence_dir, c.id, make_sealer(settings))
    w.append("start", {"url": c.url})
    w.append("threat", dict(_MAIN_THREAT))
    return c.id, w


def _main_result(cid, **over):
    from safetrace.api.main import record_event

    ev = {"type": "status", "status": "RUNNING", "phase": "related",
          "main": {"status": "COMPLETED", "reason": "agent_finished"}, "threat": dict(_MAIN_THREAT),
          "final_url": "https://example.test/related", "candidates": [{"url": "https://c1.example/", "host": "c1.example"}]}
    record_event(cid, {**ev, **over})


def test_verdict_after_main_result_while_related_running(client, store):
    """원래 결과 전 조사 중은 거절, 원래 결과 뒤는 받고 그때까지의 증거 끝을 묶는다. 종료 뒤에도 판정은 그대로다."""
    from safetrace.api.main import record_event

    _, tok = user_token(client, store, "reviewer")
    cid, w = _running_case_with_chain(store)
    r = post(client, tok, cid, rev=0, decision="threat", threat="phishing")
    assert r.status_code == 422 and "조사가 끝난 뒤" in r.json()["detail"]
    _main_result(cid)
    c = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert (c["status"], c["phase"], c["main_status"]) == ("RUNNING", "related", "COMPLETED")
    assert c["threat"]["threat"] == "phishing" and c["candidates"][0]["host"] == "c1.example"
    listed = {x["id"]: x for x in client.get("/api/cases?limit=200", headers=h(VIEWER)).json()}
    assert listed[cid]["phase"] == "related"
    r = post(client, tok, cid, rev=0, decision="threat", threat="phishing")
    assert r.status_code == 201, r.text
    seen = w.head
    assert r.json()["head_seq"] == seen.seq
    with store.session() as s:
        assert s.scalar(select(Verdict.head_hash).where(Verdict.case_id == cid)) == seen.hash
    for svc in (INVESTIGATOR, SERVICE_ADMIN):  # 자동화 토큰은 여전히 확정할 수 없다
        assert post(client, svc, cid, rev=1, decision="benign").status_code == 403
    # 하위 조사 기록이 더 쌓이고 사건이 끝나도 판정과 그때의 증거 끝은 그대로
    w.append("candidate_results", {"results": []})
    record_event(cid, {"type": "status", "status": "COMPLETED", "reason": "agent_finished", "threat": dict(_MAIN_THREAT)})
    c = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert (c["status"], c["phase"], c["main_status"]) == ("COMPLETED", None, "COMPLETED")
    assert (c["verdict"]["rev"], c["verdict"]["head_seq"]) == (1, seen.seq) and w.head.seq == seen.seq + 1


def test_verdict_refused_when_running_head_unknown(client, store, monkeypatch):
    from safetrace.api import main

    _, tok = user_token(client, store, "reviewer")
    cid, _ = _running_case_with_chain(store)
    _main_result(cid)
    monkeypatch.setattr(main, "_running_head", lambda case_id: None)
    r = post(client, tok, cid, rev=0, decision="benign")
    assert r.status_code == 422 and "증거 끝" in r.json()["detail"]


def test_main_result_event_needs_running_and_threat(store):
    cid, _ = _running_case_with_chain(store)
    base = {"type": "status", "status": "RUNNING", "phase": "related",
            "main": {"status": "COMPLETED", "reason": "agent_finished"}, "threat": dict(_MAIN_THREAT)}
    assert not store.add_event(cid, {**base, "threat": None})                        # 위협 판단 없음
    assert not store.add_event(cid, {**base, "status": "COMPLETED"})                 # 종료 상태에 phase
    assert not store.add_event(cid, {**base, "main": {"status": "RUNNING"}})         # 원래 결과가 종료 상태가 아님
    assert not store.add_event(cid, {**base, "main": {"status": "COMPLETED", "reason": 5}})
    assert not store.add_event(cid, {**base, "phase": "other"})
    assert store.phases_for([cid]) == {}
    assert store.add_event(cid, base)
    assert store.phases_for([cid])[cid].main_status == "COMPLETED"
    assert store.add_event(cid, {"type": "status", "status": "COMPLETED", "reason": "agent_finished"})
    assert not store.add_event(cid, base)  # 끝난 사건에는 다시 받지 않는다

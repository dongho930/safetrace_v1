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


def _running_case_with_chain(store, threat=None, before=(), main=None):
    """조사 중인 사건과 아직 열린 체인(개발 모드: 같은 프로세스가 쓴 체인). 원래 조사는 연관 후보 기록(candidates)으로
    끝난다(runner 와 같은 순서). 판정 대상이 되는 위협 판단·최종 주소는 이 체인의 threat·finish 기록이다."""
    from safetrace.agent.runner import make_sealer
    from safetrace.api.main import settings
    from safetrace.evidence import EvidenceWriter

    with store.session() as s, s.begin():
        c = Case(url="https://example.test/related", source="test", status="RUNNING", created_by="t")
        s.add(c)
    w = EvidenceWriter(settings.evidence_dir, c.id, make_sealer(settings))
    w.append("start", {"url": c.url})
    w.append("finish", {"reason": "agent_finished", "final_url": c.url})
    w.append("threat", dict(threat or _MAIN_THREAT))
    for kind, data in before:  # 평판·승격 기록 등(runner 와 같은 순서: threat 뒤, candidates 앞)
        w.append(kind, data)
    w.append("candidates", {"found": [{"url": "https://c1.example/"}], "followup": True, "investigated": 1,
                            "main": main or {"status": "COMPLETED", "reason": "agent_finished"}})
    return c.id, w


def _main_result(cid, main_head, **over):
    from safetrace.api.main import record_event

    ev = {"type": "status", "status": "RUNNING", "phase": "related", "main_head": main_head,
          "main": {"status": "COMPLETED", "reason": "agent_finished"}, "threat": dict(_MAIN_THREAT),
          "final_url": "https://example.test/related", "candidates": [{"url": "https://c1.example/", "host": "c1.example"}]}
    record_event(cid, {**ev, **over})


def test_verdict_after_main_result_while_related_running(client, store):
    """원래 결과 전 조사 중은 거절, 원래 결과 뒤는 받고 원래 조사의 증거 끝에 묶는다. 하위 조사 기록이 더 쌓여도
    (저장 직전이라도) 판정의 증거 끝은 원래 조사의 끝이고, 종료 뒤에도 그대로다(Codex 지적)."""
    from safetrace.api.main import record_event

    _, tok = user_token(client, store, "reviewer")
    cid, w = _running_case_with_chain(store)
    r = post(client, tok, cid, rev=0, decision="threat", threat="phishing")
    assert r.status_code == 422 and "조사가 끝난 뒤" in r.json()["detail"]
    main = w.head
    _main_result(cid, main.seq)
    c = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert (c["status"], c["phase"], c["main_status"], c["main_head_seq"]) == ("RUNNING", "related", "COMPLETED", main.seq)
    assert c["threat"]["threat"] == "phishing" and c["candidates"][0]["host"] == "c1.example"
    listed = {x["id"]: x for x in client.get("/api/cases?limit=200", headers=h(VIEWER)).json()}
    assert listed[cid]["phase"] == "related"
    w.append("observe", {"sub": 1, "url": "https://c1.example/"})  # 저장 직전에 하위 조사 기록이 들어옴
    r = post(client, tok, cid, rev=0, decision="threat", threat="phishing")
    assert r.status_code == 201, r.text
    assert r.json()["head_seq"] == main.seq
    with store.session() as s:
        assert s.scalar(select(Verdict.head_hash).where(Verdict.case_id == cid)) == main.hash
    for svc in (INVESTIGATOR, SERVICE_ADMIN):  # 자동화 토큰은 여전히 확정할 수 없다
        assert post(client, svc, cid, rev=1, decision="benign").status_code == 403
    w.append("candidate_results", {"results": []})
    record_event(cid, {"type": "status", "status": "COMPLETED", "reason": "agent_finished", "threat": dict(_MAIN_THREAT)})
    c = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert (c["status"], c["phase"], c["main_status"]) == ("COMPLETED", None, "COMPLETED")
    assert (c["verdict"]["rev"], c["verdict"]["head_seq"]) == (1, main.seq) and w.head.seq == main.seq + 2


def test_main_result_cannot_change_after_verdict(client, store):
    """Codex(PR 3): 원래 결과는 한 번만 받는다. 담당자가 정상으로 판정한 뒤 워커가 원래 결과를 다시 보내거나 종료
    이벤트에 다른 상태·위협을 실어도, 판정 대상(원래 결과)은 바뀌지 않는다."""
    from safetrace.api.main import record_event

    _, tok = user_token(client, store, "reviewer")
    benign = {"threat": "benign", "probability": 0.95, "hold": False}
    cid, w = _running_case_with_chain(store, threat=benign)
    _main_result(cid, w.head.seq, threat=benign)
    assert post(client, tok, cid, rev=0, decision="benign").status_code == 201
    forged = {"main": {"status": "REVIEW_REQUIRED", "reason": "reputation_match"},
              "threat": {"threat": "phishing", "probability": 0.99, "hold": True}}
    _main_result(cid, w.head.seq, **forged)  # 원래 결과를 다시 보냄 → 거절
    c = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert (c["threat"]["threat"], c["main_status"]) == ("benign", "COMPLETED")
    record_event(cid, {"type": "status", "status": "REVIEW_REQUIRED", "reason": "reputation_match",
                       "threat": forged["threat"], "final_url": "https://evil.example/", "candidates": []})
    c = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert (c["status"], c["finish_reason"], c["threat"]["threat"], c["final_url"]) == (
        "COMPLETED", "agent_finished", "benign", "https://example.test/related")
    assert c["verdict"]["decision"] == "benign"
    with store.session() as s:
        actions = set(s.scalars(select(AuditLog.action).where(AuditLog.case_id == cid)))
    assert {"event.rejected", "event.main_result_kept"} <= actions


def test_main_result_comes_from_signed_records(client, store):
    """Codex(PR 3~5) F1: 판정 대상이 되는 위협 판단·최종 주소는 이벤트 값이 아니라 검증한 서명 기록(threat·finish)에서
    가져온다. 체인에는 피싱으로 남기고 이벤트에는 정상·다른 최종 주소를 실어도, 담당자에게는 체인의 결과가 보인다."""
    cid, w = _running_case_with_chain(store)
    _main_result(cid, w.head.seq, threat={"threat": "benign", "probability": 0.99, "hold": False},
                 final_url="https://evil.example/")
    c = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert (c["phase"], c["threat"]["threat"], c["threat"]["probability"]) == ("related", "phishing", 0.9)
    assert c["final_url"] == "https://example.test/related"


def test_main_status_and_reputation_come_from_signed_records(client, store):
    """Codex 3회차 F1: 원래 결과의 상태·사유·평판도 서명 기록에서 가져온다. 체인에는 평판 위험으로 검토 필요 승격을
    남기고 이벤트에는 정상 완료·평판 없음을 보내도, 원래 결과는 검토 필요·평판 위험이고 종료 뒤에도 그대로다."""
    from safetrace.api.main import record_event

    sb = {"status": "match", "matches": [{"url": "https://example.test/related", "threat_type": "SOCIAL_ENGINEERING"}]}
    esc = {"from": "COMPLETED", "to": "REVIEW_REQUIRED", "reason": "reputation_match", "threat_types": ["SOCIAL_ENGINEERING"]}
    cid, w = _running_case_with_chain(store, threat={"threat": "benign", "probability": 0.97, "hold": False},
                                      before=[("safebrowsing", sb), ("escalation", esc)],
                                      main={"status": "REVIEW_REQUIRED", "reason": "reputation_match"})
    _main_result(cid, w.head.seq, main={"status": "COMPLETED", "reason": "agent_finished"},
                 safebrowsing={"status": "no_match", "matches": []})
    c = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert (c["phase"], c["main_status"], c["safebrowsing"]["status"]) == ("related", "REVIEW_REQUIRED", "match")
    record_event(cid, {"type": "status", "status": "COMPLETED", "reason": "agent_finished"})
    c = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert (c["status"], c["finish_reason"], c["safebrowsing"]["status"]) == ("REVIEW_REQUIRED", "reputation_match", "match")


def test_main_result_needs_signed_main_status(store):
    """원래 조사의 마지막 기록에 결과 상태(main)가 없거나 종료 상태가 아니면 원래 결과를 받지 않는다."""
    for main in ({"status": "RUNNING", "reason": "x"}, {"status": "COMPLETED", "reason": 5}):
        cid, w = _running_case_with_chain(store, main=main)
        _main_result(cid, w.head.seq)
        assert store.phases_for([cid]) == {}


@pytest.mark.parametrize("bad", ["past_end", "not_candidates", "tampered", "not_int"])
def test_main_head_must_verify(client, store, bad):
    """원래 조사의 끝은 워커가 말한 번호를 믿지 않고 체인 앞부분을 서명까지 검증한다. 검증하지 못하면 원래 결과를 받지
    않는다(판정도 열리지 않는다)."""
    from safetrace.api.main import settings

    cid, w = _running_case_with_chain(store)
    seq = {"past_end": w.head.seq + 5, "not_candidates": w.head.seq - 1, "tampered": w.head.seq, "not_int": "2"}[bad]
    if bad == "tampered":
        p = settings.evidence_dir / cid / "chain.jsonl"
        p.write_text(p.read_text(encoding="utf-8").replace('"threat": "phishing"', '"threat": "benign"'), encoding="utf-8")
    _main_result(cid, seq)
    assert store.phases_for([cid]) == {}
    _, tok = user_token(client, store, "reviewer")
    assert post(client, tok, cid, rev=0, decision="benign").status_code == 422


def test_main_result_event_needs_running_and_threat(store):
    cid, _ = _running_case_with_chain(store)
    base = {"type": "status", "status": "RUNNING", "phase": "related", "main_head": {"seq": 2, "hash": "ab" * 32},
            "main": {"status": "COMPLETED", "reason": "agent_finished"}, "threat": dict(_MAIN_THREAT)}
    assert not store.add_event(cid, {**base, "threat": None})                        # 위협 판단 없음
    assert not store.add_event(cid, {**base, "status": "COMPLETED"})                 # 종료 상태에 phase
    assert not store.add_event(cid, {**base, "main": {"status": "RUNNING"}})         # 원래 결과가 종료 상태가 아님
    assert not store.add_event(cid, {**base, "main": {"status": "COMPLETED", "reason": 5}})
    assert not store.add_event(cid, {**base, "phase": "other"})
    assert not store.add_event(cid, {**base, "main_head": None})                     # 검증한 증거 끝 없음
    assert store.phases_for([cid]) == {}
    assert store.add_event(cid, base)
    assert store.phases_for([cid])[cid].main_status == "COMPLETED"
    assert not store.add_event(cid, base)  # 원래 결과는 한 번만
    assert store.add_event(cid, {"type": "status", "status": "COMPLETED", "reason": "agent_finished"})
    assert not store.add_event(cid, base)  # 끝난 사건에는 다시 받지 않는다

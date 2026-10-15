"""서명 서비스: 에이전트는 키 없이 기록을 추가만 하고, seq·ts·prev 와 체인 열고 닫기는 서비스·API 가 정한다."""

import json
import secrets
import uuid

import pytest
from fastapi.testclient import TestClient

from safetrace.config import Settings
from safetrace.evidence import EvidenceWriter, Head, Signer, verify_case
from safetrace.signer.client import ChainAdmin, RemoteSealer, SignerError
from safetrace.signer.service import create_app


@pytest.fixture
def svc(tmp_path):
    key = secrets.token_hex(32)
    s = Settings(evidence_hmac_key=key, evidence_key_id="k1", signer_agent_token="agent-" + secrets.token_hex(16),
                 signer_api_token="api-" + secrets.token_hex(16), signer_state_path=tmp_path / "signer.db",
                 _env_file=None)
    app = create_app(s)
    # 같은 클라이언트를 나누어 쓰면 인증 헤더가 섞이므로 역할마다 따로 만든다
    agent = RemoteSealer("", s.signer_agent_token.get_secret_value(), client=TestClient(app))
    admin = ChainAdmin("", s.signer_api_token.get_secret_value(), client=TestClient(app))
    return {"settings": s, "app": app, "agent": agent, "admin": admin, "signer": Signer(key.encode(), "k1"),
            "root": tmp_path / "evidence", "tokens": (s.signer_agent_token.get_secret_value(),
                                                      s.signer_api_token.get_secret_value())}


def _write(svc, cid, n=3):
    w = EvidenceWriter(svc["root"], cid, svc["agent"])
    for i in range(n):
        name = f"shot_{i}.png"
        w.file_path(name).write_bytes(secrets.token_bytes(64))
        w.append("observe", {"step": i, "text": "택배 조회"}, [name])
    return w


def test_remote_chain_verifies_with_api_key_only(svc):
    cid = str(uuid.uuid4())
    svc["admin"].open(cid)
    w = _write(svc, cid)
    h = svc["admin"].close(cid)
    assert (h["seq"], h["hash"], h["closed"]) == (w.head.seq, w.head.hash, True)
    res = verify_case(svc["root"], cid, svc["signer"], Head(h["seq"], h["hash"]))
    assert res.ok, res.errors
    # 다른 키로는 검증되지 않는다(에이전트 쪽에는 키가 없다)
    assert not verify_case(svc["root"], cid, Signer(secrets.token_bytes(32), "k1"), None).ok


def test_roles_are_separated(svc):
    agent_tok, api_tok = svc["tokens"]
    c = TestClient(svc["app"])
    cid = str(uuid.uuid4())
    for tok, method, path in [
        (agent_tok, "POST", f"/v1/chains/{cid}/open"),   # 에이전트는 체인을 열 수 없다
        (agent_tok, "POST", f"/v1/chains/{cid}/close"),  # 닫을 수도 없다
        (agent_tok, "GET", f"/v1/chains/{cid}/head"),
        ("", "POST", f"/v1/chains/{cid}/open"),
    ]:
        assert c.request(method, path, headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    svc["admin"].open(cid)
    r = c.post(f"/v1/chains/{cid}/records", json={"seq": 0, "kind": "start", "data": {}},
               headers={"Authorization": f"Bearer {api_tok}"})  # API 토큰으로는 기록하지 못한다
    assert r.status_code == 401


def test_append_only_while_open(svc):
    cid = str(uuid.uuid4())
    with pytest.raises(SignerError, match="404"):  # API 가 열지 않은 사건
        _write(svc, cid, 1)
    svc["admin"].open(cid)
    w = _write(svc, cid, 1)
    svc["admin"].close(cid)
    with pytest.raises(SignerError, match="409"):  # 닫힌 사건
        w.append("finish", {"forged": True})
    assert svc["admin"].head(cid)["seq"] == 0


def test_cannot_resign_earlier_records_or_set_time(svc):
    agent_tok, _ = svc["tokens"]
    c = TestClient(svc["app"], headers={"Authorization": f"Bearer {agent_tok}"})
    cid = str(uuid.uuid4())
    svc["admin"].open(cid)
    w = _write(svc, cid, 3)
    url = f"/v1/chains/{cid}/records"
    # 앞 기록(seq 1)을 다른 내용으로 다시 서명받지 못한다
    assert c.post(url, json={"seq": 1, "kind": "observe", "data": {"step": 1, "text": "정상"}}).status_code == 409
    # 마지막 기록과 같은 내용의 재전송(응답 유실)은 같은 기록을 돌려주고, 다른 내용이면 거절
    last = json.loads(w.chain_path.read_text(encoding="utf-8").splitlines()[-1])
    same = {"seq": 2, "kind": last["kind"], "data": last["data"], "files": last["files"]}
    assert c.post(url, json=same).json()["hash"] == last["hash"]
    assert c.post(url, json={**same, "data": {"step": 2}}).status_code == 409
    # 수집 시각은 서비스가 정한다
    assert c.post(url, json={"seq": 3, "kind": "finish", "data": {}, "ts": "2000-01-01T00:00:00Z"}).status_code == 422
    # 파일 이름 검사
    bad = {"seq": 3, "kind": "finish", "data": {}, "files": {"../../x.png": "0" * 64}}
    assert c.post(url, json=bad).status_code == 422
    assert svc["admin"].head(cid)["seq"] == 2


def test_truncation_detected_against_signer_head(svc):
    cid = str(uuid.uuid4())
    svc["admin"].open(cid)
    w = _write(svc, cid, 3)
    h = svc["admin"].close(cid)
    lines = w.chain_path.read_text(encoding="utf-8").splitlines()
    w.chain_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")  # 뚫린 에이전트가 끝을 잘라 냄
    res = verify_case(svc["root"], cid, svc["signer"], Head(h["seq"], h["hash"]))
    assert not res.ok and any("head_mismatch" in e for e in res.errors)


def test_api_uses_signer_head_not_agent_report(svc, monkeypatch):
    from safetrace.api import main
    from safetrace.store import AuditLog, Case

    with main.store.session() as s, s.begin():
        c = Case(url="http://example.test/", source="manual", created_by="test")
        s.add(c)
    monkeypatch.setattr(main, "_chains", svc["admin"])
    svc["admin"].open(c.id)
    w = _write(svc, c.id, 2)
    main.record_event(c.id, {"type": "status", "status": "COMPLETED", "reason": "done",
                             "head": {"seq": 0, "hash": "f" * 64}})  # 에이전트가 거짓 head 를 보고
    with main.store.session() as s:
        got = s.get(Case, c.id)
        assert (got.head_seq, got.head_hash) == (w.head.seq, w.head.hash)
        assert s.query(AuditLog).filter_by(case_id=c.id, action="evidence.head_mismatch").count() == 1
    assert svc["admin"].head(c.id)["closed"]


# ── Codex 시범 검토(#37) 지적 재현 ─────────────────────────────
@pytest.fixture
def api_svc(tmp_path, monkeypatch):
    """API(main)와 같은 키·증거 폴더를 쓰는 서명 서비스. record_event → verify 를 실제 경로로 확인한다."""
    from safetrace.api import main
    from safetrace.store import Case

    s = Settings(evidence_hmac_key=main.settings.evidence_hmac_key.get_secret_value(), evidence_key_id=main.settings.evidence_key_id,
                 signer_agent_token="agent-" + secrets.token_hex(16), signer_api_token="api-" + secrets.token_hex(16),
                 signer_state_path=tmp_path / "signer.db", _env_file=None)
    app = create_app(s)
    agent = RemoteSealer("", s.signer_agent_token.get_secret_value(), client=TestClient(app))
    admin = ChainAdmin("", s.signer_api_token.get_secret_value(), client=TestClient(app))
    monkeypatch.setattr(main, "_chains", admin)
    with main.store.session() as ses, ses.begin():
        c = Case(url="http://example.test/", source="manual", created_by="test")
        ses.add(c)
    admin.open(c.id)
    return {"main": main, "case_id": c.id, "agent": agent, "admin": admin, "root": main.settings.evidence_dir}


def _api_write(api_svc, n=3):
    w = EvidenceWriter(api_svc["root"], api_svc["case_id"], api_svc["agent"])
    for i in range(n):
        w.append("observe", {"step": i}, [])
    return w


def _truncate(w):
    lines = w.chain_path.read_text(encoding="utf-8").splitlines()
    w.chain_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    last = json.loads(lines[-2])
    return {"seq": last["seq"], "hash": last["hash"]}


def _verify(api_svc):
    from safetrace.api.main import Principal

    return api_svc["main"].verify(api_svc["case_id"], Principal(name="t", role="viewer"))


def _case(api_svc):
    from safetrace.store import Case

    with api_svc["main"].store.session() as s:
        return s.get(Case, api_svc["case_id"])


@pytest.mark.parametrize("status", ["DONE", "RUNNING", "COMPLETED"])
def test_agent_event_cannot_replace_head_after_finish(api_svc, status):
    """F1: 끝난 사건에 뚫린 에이전트가 head 를 실은 상태 이벤트를 보내 잘라 낸 체인을 정상으로 만들 수 없다."""
    main, cid = api_svc["main"], api_svc["case_id"]
    w = _api_write(api_svc)
    main.record_event(cid, {"type": "status", "status": "COMPLETED", "reason": "done"})
    fake = _truncate(w)
    main.record_event(cid, {"type": "status", "status": status, "reason": "x", "head": fake})
    c = _case(api_svc)
    assert (c.head_seq, c.status) == (2, "COMPLETED")
    res = _verify(api_svc)
    assert not res["ok"] and any("head_mismatch" in e for e in res["errors"])


def test_agent_reported_head_ignored_while_running(api_svc):
    """F1: 조사 중에도 에이전트가 보낸 head 는 DB 에 들어가지 않는다(허용 목록 밖 상태도 거절)."""
    main, cid = api_svc["main"], api_svc["case_id"]
    _api_write(api_svc, 1)
    main.record_event(cid, {"type": "status", "status": "RUNNING", "head": {"seq": 0, "hash": "f" * 64}})
    main.record_event(cid, {"type": "status", "status": "PWNED"})
    c = _case(api_svc)
    assert (c.status, c.head_seq) == ("RUNNING", None)


def test_close_failure_does_not_verify(api_svc, monkeypatch):
    """F2: 체인 닫기가 실패해 head 가 없으면 무결성을 성공으로 표시하지 않고, 서명 서비스가 돌아오면 head 를 받아 대조한다."""
    main, cid, admin = api_svc["main"], api_svc["case_id"], api_svc["admin"]
    w = _api_write(api_svc)
    real_close = admin.close
    monkeypatch.setattr(main, "_CLOSE_RETRY_S", ())

    def down(_cid):
        raise SignerError("signer unreachable: ConnectError")

    monkeypatch.setattr(admin, "close", down)
    _truncate(w)
    main.record_event(cid, {"type": "status", "status": "COMPLETED", "reason": "done"})
    res = _verify(api_svc)
    assert not res["ok"] and any("head_unknown" in e for e in res["errors"])
    monkeypatch.setattr(admin, "close", real_close)
    res = _verify(api_svc)
    assert not res["ok"] and any("head_mismatch" in e for e in res["errors"])
    assert _case(api_svc).head_seq == 2


# ── Codex(related-sites PR 3~5) F1: 다른 사건의 서명 기록으로 원래 결과의 끝을 고정 ─────
_BENIGN = {"threat": "benign", "probability": 0.99, "hold": False}


def _main_chain(api_svc, cid):
    """runner 와 같은 순서로 끝나는 원래 조사(마지막이 연관 후보 기록)."""
    w = EvidenceWriter(api_svc["root"], cid, api_svc["agent"])
    w.append("start", {"url": "http://example.test/"})
    w.append("finish", {"reason": "agent_finished", "final_url": "http://example.test/"})
    w.append("threat", dict(_BENIGN))
    w.append("candidates", {"found": [], "followup": True, "investigated": 1})
    return w


def _main_event(seq):
    return {"type": "status", "status": "RUNNING", "phase": "related", "main_head": seq,
            "main": {"status": "COMPLETED", "reason": "agent_finished"}, "threat": dict(_BENIGN)}


@pytest.mark.parametrize("b_records", [1, 4])
def test_main_head_rejects_other_case_chain(api_svc, b_records):
    """서명에는 사건 id 가 없어서, 다른 사건(A)의 서명된 원래 조사 기록을 이 사건(B) 폴더에 복사해 넣으면 체인 앞부분
    검증만으로는 통과했다. 이 사건의 서명 서비스 head 까지 이어지는지 대조해 거절한다(B 의 기록이 더 짧을 때·같은 길이일 때)."""
    import shutil

    from safetrace.store import Case

    main, b = api_svc["main"], api_svc["case_id"]
    with main.store.session() as s, s.begin():
        a = Case(url="http://example.test/", source="manual", created_by="test", status="RUNNING")
        s.add(a)
    api_svc["admin"].open(a.id)
    wa = _main_chain(api_svc, a.id)
    main.record_event(b, {"type": "status", "status": "RUNNING"})
    wb = EvidenceWriter(api_svc["root"], b, api_svc["agent"])
    for i in range(b_records):
        wb.append("observe", {"step": i}, [])
    shutil.copyfile(wa.chain_path, wb.chain_path)  # 뚫린 워커가 A 의 체인을 B 에 넣음
    main.record_event(b, _main_event(wa.head.seq))
    assert main.store.phases_for([b]) == {}
    main.record_event(a.id, _main_event(wa.head.seq))  # 자기 사건의 체인이면 받는다
    assert main.store.phases_for([a.id])[a.id].main_head_seq == wa.head.seq


def test_oversized_body_rejected_while_streaming(svc):
    """F3: 1MiB 를 넘는 본문은 다 받기 전에 413 으로 끊는다."""
    import asyncio

    from safetrace.signer.service import MAX_BODY

    agent_tok, _ = svc["tokens"]
    cid = str(uuid.uuid4())
    svc["admin"].open(cid)
    chunk = b"x" * 65536
    total = MAX_BODY * 4 // len(chunk)
    calls = {"n": 0}
    sent: list[dict] = []

    async def receive():
        calls["n"] += 1
        return {"type": "http.request", "body": chunk, "more_body": calls["n"] < total}

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
             "path": f"/v1/chains/{cid}/records", "raw_path": f"/v1/chains/{cid}/records".encode(), "query_string": b"",
             "root_path": "", "headers": [(b"authorization", f"Bearer {agent_tok}".encode()),
                                          (b"content-type", b"application/json")],
             "client": ("127.0.0.1", 1), "server": ("signer", 8200)}
    asyncio.run(svc["app"](scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    assert status == 413
    assert calls["n"] <= MAX_BODY // len(chunk) + 2, calls["n"]


def test_oversized_content_length_rejected_early(svc):
    agent_tok, _ = svc["tokens"]
    c = TestClient(svc["app"], headers={"Authorization": f"Bearer {agent_tok}"})
    cid = str(uuid.uuid4())
    svc["admin"].open(cid)
    r = c.post(f"/v1/chains/{cid}/records", content=b"{" + b" " * (2 << 20) + b"}",
               headers={"Content-Type": "application/json"})
    assert r.status_code == 413

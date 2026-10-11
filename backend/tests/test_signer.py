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

"""증거 볼륨의 링크·특수 파일(Codex related-sites PR 3~5 F3 와 같은 함수에서 찾은 링크 문제).

증거 볼륨은 에이전트(조사 대상 페이지를 다루므로 침해될 수 있다)가 쓴다. API 가 링크를 따라가면 API 컨테이너의 다른
파일이 검토 패키지·파일 응답으로 나가고, FIFO 를 열면 이벤트 처리가 멈춘다. 리눅스에서만 돈다(Windows 에는 FIFO 가 없고
링크에 권한이 필요하다). CI 와 컨테이너에서 확인한다.
"""

import io
import os
import secrets
import threading
import zipfile

import pytest
from fastapi.testclient import TestClient

from safetrace.store import Case
from tests.conftest import INVESTIGATOR, VIEWER

pytestmark = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO·링크 시험은 리눅스에서")
SECRET = b"ST_EVIDENCE_HMAC_KEY=not-for-export-" + secrets.token_hex(8).encode()


@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture
def secret_file(tmp_path):
    p = tmp_path / "environ"  # API 컨테이너의 /proc/self/environ 같은 파일 대신
    p.write_bytes(SECRET)
    return p


def _case(status="RUNNING"):
    from safetrace.agent.runner import make_sealer
    from safetrace.api.main import settings, store
    from safetrace.evidence import EvidenceWriter

    with store.session() as s, s.begin():
        c = Case(url="https://example.test/u", source="test", status=status, created_by="t")
        s.add(c)
    w = EvidenceWriter(settings.evidence_dir, c.id, make_sealer(settings))
    w.file_path("s001_observe.png").write_bytes(b"\x89PNG not really")
    w.append("observe", {"step": 0, "url": c.url, "title": "", "candidates": []}, ["s001_observe.png"])
    w.append("finish", {"reason": "agent_finished", "final_url": c.url})
    w.append("threat", {"threat": "phishing", "probability": 0.9, "hold": False})
    w.append("candidates", {"found": [], "followup": True, "investigated": 1,
                            "main": {"status": "COMPLETED", "reason": "agent_finished"}})
    return c.id, w


def _finish(cid):
    from safetrace.api.main import record_event

    record_event(cid, {"type": "status", "status": "COMPLETED", "reason": "agent_finished",
                       "threat": {"threat": "phishing", "probability": 0.9, "hold": False}})


def test_open_evidence_refuses_links_fifos_and_redirected_dirs(tmp_path, secret_file):
    from safetrace.evidence import UnsafeEvidence, open_evidence, read_evidence, sha256_evidence

    root = tmp_path / "ev"
    cid = "c" * 8
    (root / cid / "files").mkdir(parents=True)
    (root / cid / "files" / "a.png").write_bytes(b"png")
    assert read_evidence(root, cid, "files", "a.png", max_bytes=10) == b"png"
    with pytest.raises(UnsafeEvidence):
        read_evidence(root, cid, "files", "a.png", max_bytes=2)  # 너무 큼
    os.symlink(secret_file, root / cid / "files" / "b.png")
    with pytest.raises(UnsafeEvidence):
        read_evidence(root, cid, "files", "b.png", max_bytes=1 << 20)
    os.mkfifo(root / cid / "files" / "c.png")
    with pytest.raises(UnsafeEvidence):  # 쓰는 쪽을 기다리지 않는다
        sha256_evidence(root, cid, "files", "c.png")
    os.symlink(tmp_path, root / ("d" * 8))  # 사건 폴더가 다른 곳을 가리킴
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "a.png").write_bytes(b"x")
    with pytest.raises(UnsafeEvidence):
        open_evidence(root, "d" * 8, "files", "a.png")
    with pytest.raises(FileNotFoundError):
        open_evidence(root, cid, "files", "none.png")


def test_package_zip_does_not_follow_chain_link(client, secret_file):
    """chain.jsonl 을 링크로 바꿔도 ZIP 에 링크가 가리키는 파일 내용이 담기지 않고, 무결성은 실패로 표시된다."""
    from safetrace.api.main import settings

    cid, w = _case()
    _finish(cid)
    chain = settings.evidence_dir / cid / "chain.jsonl"
    chain.unlink()
    os.symlink(secret_file, chain)
    r = client.get(f"/api/cases/{cid}/package.zip", headers=h(INVESTIGATOR))
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert all(SECRET not in z.read(n) for n in z.namelist())
    pkg = client.get(f"/api/cases/{cid}/package", headers=h(VIEWER)).json()
    assert pkg["integrity"]["verified"] is False


def test_case_file_does_not_follow_link(client, secret_file):
    from safetrace.api.main import settings

    cid, _ = _case()
    link = settings.evidence_dir / cid / "files" / "s999_observe.png"
    os.symlink(secret_file, link)
    r = client.get(f"/api/cases/{cid}/files/s999_observe.png", headers=h(VIEWER))
    assert r.status_code == 404 and SECRET not in r.content
    r = client.get(f"/api/cases/{cid}/files/s999_observe.png?preview=1", headers=h(VIEWER))
    assert r.status_code == 404 and SECRET not in r.content
    ok = client.get(f"/api/cases/{cid}/files/s001_observe.png", headers=h(VIEWER))  # 일반 파일은 그대로
    assert ok.status_code == 200 and ok.content == b"\x89PNG not really"
    assert ok.headers["content-length"] == str(len(ok.content))


def test_main_result_with_fifo_chain_does_not_block_events():
    """F3: 조사 중 사건의 chain.jsonl 을 FIFO 로 바꾸고 원래 결과 이벤트를 보내도 이벤트 처리가 멈추지 않는다."""
    from safetrace.api.main import record_event, settings, store

    cid, w = _case()
    chain = settings.evidence_dir / cid / "chain.jsonl"
    chain.unlink()
    os.mkfifo(chain)
    ev = {"type": "status", "status": "RUNNING", "phase": "related", "main_head": w.head.seq,
          "main": {"status": "COMPLETED", "reason": "agent_finished"},
          "threat": {"threat": "phishing", "probability": 0.9, "hold": False}}
    t = threading.Thread(target=record_event, args=(cid, ev), daemon=True)
    t.start()
    t.join(timeout=5)
    blocked = t.is_alive()
    if blocked:  # 고치기 전: 쓰는 쪽이 올 때까지 기다린다. 풀어 주고 실패로 적는다
        fd = os.open(chain, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        t.join(timeout=5)
    assert not blocked
    assert store.phases_for([cid]) == {}

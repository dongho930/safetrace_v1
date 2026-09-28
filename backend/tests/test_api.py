import json
import secrets
import time

import pytest
from fastapi.testclient import TestClient

from tests.conftest import INVESTIGATOR, VIEWER

pytestmark = pytest.mark.browser


@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_auth_required(client):
    assert client.get("/api/cases").status_code == 401
    assert client.get("/api/cases", headers=h("wrong-token-xxxxxxxxxxxxxxxxxxxx")).status_code == 401
    assert client.post("/api/cases", json={"url": "http://127.0.0.1:8900/benign/"}, headers=h(VIEWER)).status_code == 403


def test_url_validation(client):
    for bad in ["javascript:alert(1)", "file:///etc/passwd", "http://a:b@x.example/"]:
        r = client.post("/api/cases", json={"url": bad}, headers=h(INVESTIGATOR))
        assert r.status_code == 422, bad


def test_security_headers(client):
    r = client.get("/api/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_case_flow_sse_and_verify(client, testpages):
    # 시험 DB 가 실행 사이에 남으므로 멱등 키를 실행마다 새로 만든다(지난 실행의 사건을 돌려받지 않게)
    idem = "req-" + secrets.token_hex(8)
    r = client.post("/api/cases", json={"url": "http://127.0.0.1:8900/gamble/"},
                    headers={**h(INVESTIGATOR), "Idempotency-Key": idem})
    assert r.status_code == 201
    cid = r.json()["id"]
    # 같은 멱등 키로 다시 요청하면 같은 사건
    r2 = client.post("/api/cases", json={"url": "http://127.0.0.1:8900/gamble/"},
                     headers={**h(INVESTIGATOR), "Idempotency-Key": idem})
    assert r2.json()["id"] == cid

    events = []
    with client.stream("GET", f"/api/cases/{cid}/events", headers=h(VIEWER)) as s:
        for line in s.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
    assert events[-1]["type"] == "status" and events[-1]["status"] in {"COMPLETED", "REVIEW_REQUIRED"}
    kinds = {e.get("kind") for e in events}
    assert {"observe", "decision", "gate", "action", "threat", "recording"} <= kinds

    case = client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()
    assert case["threat"]["threat"] == "illegal_gambling"
    shot = next(f for e in events for f in e.get("files", []) if f.endswith(".png"))
    img = client.get(f"/api/cases/{cid}/files/{shot}", headers=h(VIEWER))
    assert img.status_code == 200 and img.headers["content-type"] == "image/png"
    assert client.get(f"/api/cases/{cid}/files/..%2Fchain.jsonl", headers=h(VIEWER)).status_code == 404
    assert client.get(f"/api/cases/{cid}/files/recording.webm", headers=h(VIEWER)).status_code == 200
    # 표시용 미리보기: 원본보다 크지 않음(단순 화면은 원본 PNG 그대로), 원본 PNG 는 바뀌지 않음
    pv = client.get(f"/api/cases/{cid}/files/{shot}?preview=1", headers=h(VIEWER))
    assert pv.status_code == 200 and pv.headers["content-type"] in {"image/jpeg", "image/png"}
    assert len(pv.content) <= len(img.content)
    assert client.get(f"/api/cases/{cid}/files/{shot}", headers=h(VIEWER)).content == img.content

    v = client.post(f"/api/cases/{cid}/verify", headers=h(VIEWER)).json()
    assert v["ok"], v
    from safetrace.config import get_settings

    (get_settings().evidence_dir / cid / "files" / shot).write_bytes(b"x")
    v = client.post(f"/api/cases/{cid}/verify", headers=h(VIEWER)).json()
    assert not v["ok"] and any("file_modified" in e for e in v["errors"])


def test_unknown_case_404(client):
    assert client.get("/api/cases/../../etc", headers=h(VIEWER)).status_code == 404
    assert client.get("/api/cases/00000000-0000-0000-0000-000000000000", headers=h(VIEWER)).status_code == 404


def test_live_websocket_auth(client):
    from starlette.websockets import WebSocketDisconnect

    with client.websocket_connect("/api/cases/00000000-0000-0000-0000-000000000000/live") as ws:
        ws.send_json({"token": "wrong-token-xxxxxxxxxxxxxxxxxxxx"})
        with pytest.raises(WebSocketDisconnect) as e:
            ws.receive_bytes()
        assert e.value.code == 4401
    with client.websocket_connect("/api/cases/00000000-0000-0000-0000-000000000000/live") as ws:
        ws.send_json({"token": VIEWER})
        with pytest.raises(WebSocketDisconnect) as e:
            ws.receive_bytes()
        assert e.value.code == 4404


def test_live_websocket_streams_frames(client, testpages):
    """조사 중인 사건을 열면 JPEG 프레임이 연속으로 온다(보기용, 증거 아님)."""
    from safetrace.agent.recorder import find_ffmpeg

    if not find_ffmpeg():
        pytest.skip("ffmpeg not available (live frames come from the screencast recorder)")
    from starlette.websockets import WebSocketDisconnect

    r = client.post("/api/cases", json={"url": "http://127.0.0.1:8900/smish/"}, headers=h(INVESTIGATOR))
    cid = r.json()["id"]
    frames = []
    with client.websocket_connect(f"/api/cases/{cid}/live") as ws:
        ws.send_json({"token": VIEWER})
        with pytest.raises(WebSocketDisconnect) as e:  # 조사가 끝나면 서버가 정상 종료한다
            while True:
                frames.append(ws.receive_bytes())
        assert e.value.code == 1000
    assert len(frames) >= 10, len(frames)
    assert all(f[:3] == bytes([0xFF, 0xD8, 0xFF]) for f in frames)  # JPEG
    assert client.get(f"/api/cases/{cid}", headers=h(VIEWER)).json()["status"] in {"COMPLETED", "REVIEW_REQUIRED"}
    # 끝난 사건은 라이브 없이 바로 닫힌다
    with client.websocket_connect(f"/api/cases/{cid}/live") as ws:
        ws.send_json({"token": VIEWER})
        with pytest.raises(WebSocketDisconnect) as e:
            ws.receive_bytes()
        assert e.value.code == 1000

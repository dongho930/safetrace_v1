"""검토 패키지 시험: 실제 시험 페이지 조사 1건이 탐색→판단→패키지까지 이어지는지, ZIP 을 받은 쪽에서 다시 검증할 수 있는지."""

import hashlib
import io
import json
import secrets
import zipfile

import pytest
from fastapi.testclient import TestClient

from safetrace import accounts, package
from safetrace.evidence import GENESIS, canonical
from safetrace.store import Case
from tests.conftest import INVESTIGATOR, VIEWER

PW = "correct-horse-battery-9"


@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(scope="module")
def case_id(client, testpages):
    """스미싱 시험 페이지: 에이전트가 버튼을 눌러 다음 화면으로 간다."""
    r = client.post("/api/cases", json={"url": "http://127.0.0.1:8900/smish/"},
                    headers={**h(INVESTIGATOR), "Idempotency-Key": "pkg-" + secrets.token_hex(8)})
    cid = r.json()["id"]
    with client.stream("GET", f"/api/cases/{cid}/events", headers=h(VIEWER)) as s:
        for _ in s.iter_lines():
            pass
    return cid


@pytest.fixture(scope="module")
def reviewer(client):
    from safetrace.api.main import store

    name = f"pkg{secrets.token_hex(4)}"
    accounts.create_user(store, name, PW, "reviewer")
    return name, client.post("/api/auth/login", json={"username": name, "password": PW}).json()["token"]


def test_package_json_has_exploration_assessment_review(client, case_id, reviewer):
    name, tok = reviewer
    r = client.post(f"/api/cases/{case_id}/verdicts", headers=h(tok),
                    json={"rev": 0, "decision": "threat", "threat": "phishing", "note": "택배 사칭"})
    assert r.status_code == 201
    pkg = client.get(f"/api/cases/{case_id}/package", headers=h(VIEWER)).json()
    assert pkg["format"] == package.FORMAT and pkg["case"]["id"] == case_id
    assert pkg["integrity"]["verified"] is True and pkg["integrity"]["errors"] == []

    ex = pkg["exploration"]
    assert ex["start"]["url"] == "http://127.0.0.1:8900/smish/" and ex["browser"]["version"]
    assert ex["path"][0].startswith("http://127.0.0.1:8900/smish/") and ex["final_url"]
    first = ex["steps"][0]
    assert first["observe"]["screenshot"].endswith(".png") and first["observe"]["candidates"]
    assert first["decision"]["probabilities"] and first["decision"]["provider"]
    # 클릭한 단계: Jev 선택 → 게이트 통과 → 전후 화면, 누른 요소의 글자까지
    click = next(s for s in ex["steps"] if s.get("action", {}).get("action") == "click")
    assert click["gate"]["allowed"] is True
    assert click["action"]["before"].endswith("_before.png") and click["action"]["after"].endswith("_after.png")
    assert click["action"]["element_text"] and click["decision"]["element_text"] == click["action"]["element_text"]
    assert ex["recording"]["files"] == ["recording.webm"]

    a = pkg["assessment"]
    assert a["threat"]["threat"] == client.get(f"/api/cases/{case_id}", headers=h(VIEWER)).json()["threat"]["threat"]
    assert a["threat"]["evidence_seqs"] and a["safebrowsing"]["status"]
    # 담당자 영역: 판정·사유·담당자·시각, 감사로그
    cur = pkg["review"]["current"]
    assert (cur["decision"], cur["threat"], cur["note"], cur["reviewer"]) == ("threat", "phishing", "택배 사칭", name)
    actions = [x["action"] for x in pkg["review"]["audit"]]
    assert "case.create" in actions and "verdict.save" in actions
    # 파일 목록은 체인에 적힌 sha256 그대로
    assert {f["name"] for f in pkg["files"]} >= {first["observe"]["screenshot"], "recording.webm"}


def test_zip_can_be_verified_by_receiver(client, case_id):
    """README 에 적은 방법만으로 받은 쪽이 체인·파일을 다시 계산해 확인할 수 있어야 한다."""
    r = client.get(f"/api/cases/{case_id}/package.zip", headers=h(INVESTIGATOR))
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert f"safetrace-{case_id[:8]}-" in r.headers["content-disposition"]
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {"package.json", "chain.jsonl", "SHA256SUMS", "package.sig", "README.txt", "files/recording.webm"} <= names

    # 1) SHA256SUMS
    for line in z.read("SHA256SUMS").decode().splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256(z.read(name)).hexdigest() == digest, name
    # 2) 해시 체인, 3) 파일 해시
    prev, seq = GENESIS, -1
    for line in z.read("chain.jsonl").decode().splitlines():
        rec = json.loads(line)
        body = {k: rec[k] for k in ("seq", "ts", "kind", "data", "files")}
        assert rec["seq"] == seq + 1 and rec["prev"] == prev
        assert hashlib.sha256(prev.encode() + canonical(body)).hexdigest() == rec["hash"]
        for n, fh in rec["files"].items():
            assert hashlib.sha256(z.read(f"files/{n}")).hexdigest() == fh
        prev, seq = rec["hash"], rec["seq"]
    pkg = json.loads(z.read("package.json"))
    assert (pkg["integrity"]["head_seq"], pkg["integrity"]["head_hash"]) == (seq, prev)
    assert "package.export" in [x["action"] for x in pkg["review"]["audit"]]  # 이번 내보내기도 기록됨

    # 서명은 서버 키로만 확인된다. package.json 을 한 글자라도 바꾸면 실패
    from safetrace.api.main import _signer

    sig = json.loads(z.read("package.sig"))
    assert package.verify_sig(z.read("package.json"), sig, _signer())
    assert not package.verify_sig(z.read("package.json").replace(b"phishing", b"benign!!"), sig, _signer())


def test_package_permissions_and_state(client, case_id, testpages):
    assert client.get(f"/api/cases/{case_id}/package").status_code == 401
    assert client.get(f"/api/cases/{case_id}/package.zip", headers=h(VIEWER)).status_code == 403  # 내보내기는 조사관 이상
    assert client.get(f"/api/cases/{'0' * 36}/package", headers=h(VIEWER)).status_code == 404
    from safetrace.api.main import store

    with store.session() as s, s.begin():
        running = Case(url="http://127.0.0.1:8900/smish/", source="test", status="RUNNING", created_by="t")
        s.add(running)
    assert client.get(f"/api/cases/{running.id}/package", headers=h(VIEWER)).status_code == 409
    assert client.get(f"/api/cases/{running.id}/package.zip", headers=h(INVESTIGATOR)).status_code == 409


def test_tampered_evidence_is_reported_not_hidden(client, case_id):
    """증거가 바뀌면 패키지는 만들되 검증 실패를 그대로 적는다(이 시험은 증거를 망가뜨리므로 마지막에 둔다)."""
    from safetrace.config import get_settings

    pkg = client.get(f"/api/cases/{case_id}/package", headers=h(VIEWER)).json()
    shot = pkg["exploration"]["steps"][0]["observe"]["screenshot"]
    (get_settings().evidence_dir / case_id / "files" / shot).write_bytes(b"tampered")
    pkg = client.get(f"/api/cases/{case_id}/package", headers=h(VIEWER)).json()
    assert pkg["integrity"]["verified"] is False
    assert any("file_modified" in e for e in pkg["integrity"]["errors"])

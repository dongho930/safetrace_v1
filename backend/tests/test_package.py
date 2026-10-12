"""검토 패키지 시험: 실제 시험 페이지 조사 1건이 탐색→판단→패키지까지 이어지는지, ZIP 을 받은 쪽에서 다시 검증할 수 있는지."""

import hashlib
import io
import json
import secrets
import zipfile

import pytest
from fastapi.testclient import TestClient

from safetrace import accounts, package, report
from safetrace.evidence import GENESIS, canonical
from safetrace.store import Case, now
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


def test_unsafe_file_names_from_chain_are_not_exported(tmp_path):
    """체인은 에이전트 컨테이너(조사 대상 페이지를 다루는 쪽)가 쓰고 API 는 읽기만 한다. 체인에 경로 이동 이름이
    들어 있어도 API 가 증거 폴더 밖 파일을 패키지에 담지 않아야 한다(서명 검증과 별개인 심층 방어)."""
    from safetrace.evidence import EvidenceWriter, Signer, verify_case

    signer = Signer(secrets.token_bytes(32), "k1")
    cid = "cccccccc-0000-0000-0000-000000000000"
    (tmp_path / "secret.txt").write_text("server secret")
    w = EvidenceWriter(tmp_path / "ev", cid, signer)
    w.file_path("s001_observe.png").write_bytes(b"png")
    w.append("observe", {"step": 0, "url": "http://x/", "title": "", "candidates": []}, ["s001_observe.png"])
    w.append("finish", {"reason": "agent_finished"})
    lines = w.chain_path.read_text(encoding="utf-8").splitlines()
    bad = json.loads(lines[-1])
    bad["files"] = {"../../secret.txt": hashlib.sha256(b"server secret").hexdigest()}
    w.chain_path.write_text("\n".join([*lines[:-1], json.dumps(bad)]) + "\n", encoding="utf-8")

    case = Case(id=cid, url="http://x/", source="test", status="COMPLETED", created_by="t", created_at=now())
    res = verify_case(tmp_path / "ev", cid, signer, None)
    pkg = package.build(case, package.read_chain(tmp_path / "ev", cid), res, [], [], generated_by="t", key_id="k1")
    assert [f["name"] for f in pkg["files"]] == ["s001_observe.png"]
    assert not pkg["integrity"]["verified"]  # 이상한 이름은 검증 실패로 드러난다
    z = zipfile.ZipFile(io.BytesIO(package.export_zip(pkg, tmp_path / "ev", cid, signer)))
    assert all(".." not in n for n in z.namelist())
    assert b"server secret" not in b"".join(z.read(n) for n in z.namelist() if n != "chain.jsonl")


def _images(pdf: bytes) -> int:
    return pdf.count(b"/Subtype /Image")


def test_report_json_and_pdf(client, case_id):
    """보고서 초안: 패키지에서 뽑은 요약(JSON)과 같은 내용의 PDF. 내보내기는 조사관 이상, 감사로그."""
    r = client.get(f"/api/cases/{case_id}/report.json", headers=h(INVESTIGATOR))
    assert r.status_code == 200 and f"safetrace-report-{case_id[:8]}-" in r.headers["content-disposition"]
    rep = r.json()
    pkg = client.get(f"/api/cases/{case_id}/package", headers=h(VIEWER)).json()
    assert rep["format"] == report.FORMAT and rep["case"]["url"] == "http://127.0.0.1:8900/smish/"
    inv = rep["investigation"]
    assert inv["started_at"] and inv["finished_at"] and inv["duration_seconds"] > 0
    assert inv["status"] == pkg["case"]["status"] and inv["final_url"] == pkg["exploration"]["final_url"]
    click = next(s for s in inv["steps"] if s["action"] == "click")
    assert click["element_text"]
    assert rep["assessment"]["ai"]["threat"] == pkg["assessment"]["threat"]["threat"]
    assert rep["assessment"]["safebrowsing"]["status"]
    # 판정이 있으면 확정 여부에 따라 초안 표시
    cur = pkg["review"]["current"]
    assert rep["draft"] == (not cur or cur["decision"] == "hold")
    # 주요 화면은 체인에 적힌 파일과 해시 그대로
    files = {f["name"]: f["sha256"] for f in pkg["files"]}
    assert rep["key_screens"] and all(files[x["file"]] == x["sha256"] for x in rep["key_screens"])
    assert rep["integrity"]["verified"] is True and rep["integrity"]["head_hash"] == pkg["integrity"]["head_hash"]

    r = client.get(f"/api/cases/{case_id}/report.pdf", headers=h(INVESTIGATOR))
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF") and _images(r.content) == len(rep["key_screens"])

    pkg = client.get(f"/api/cases/{case_id}/package", headers=h(VIEWER)).json()
    assert [x["detail"] for x in pkg["review"]["audit"] if x["action"] == "report.export"][-2:] == ["json", "pdf"]
    assert client.get(f"/api/cases/{case_id}/report.pdf", headers=h(VIEWER)).status_code == 403
    assert client.get(f"/api/cases/{case_id}/report.html", headers=h(INVESTIGATOR)).status_code == 404

    z = zipfile.ZipFile(io.BytesIO(client.get(f"/api/cases/{case_id}/package.zip", headers=h(INVESTIGATOR)).content))
    sums = z.read("SHA256SUMS").decode()
    assert "  report.json" in sums and "  report.pdf" in sums
    assert json.loads(z.read("report.json"))["integrity"]["head_hash"] == rep["integrity"]["head_hash"]


def test_report_pdf_does_not_interpret_page_markup(tmp_path):
    """페이지 제목·버튼 글자는 공격자 값이다. reportlab 문단 마크업(<img src> 등)으로 해석되면 서버의 로컬 파일을
    PDF 에 넣을 수 있다. 글자 그대로만 들어가야 한다."""
    from PIL import Image

    secret = tmp_path / "secret.png"
    Image.new("RGB", (40, 40), "red").save(secret)
    evil = f'<img src="{secret.as_posix()}" width="40" height="40"/><font color="red">x</font> &amp;'
    rep = {
        "format": report.FORMAT, "generated_at": "2026-10-12T00:00:00+00:00", "generated_by": evil, "draft": True,
        "notice": report.NOTICE,
        "case": {"id": "c" * 36, "url": evil, "source": evil, "received_at": "2026-10-12T00:00:00+00:00",
                 "received_by": evil},
        "investigation": {"started_at": None, "finished_at": None, "duration_seconds": None, "status": "COMPLETED",
                          "status_ko": evil, "finish_reason": None, "finish_reason_ko": evil, "final_url": evil,
                          "path": [evil], "browser": evil,
                          "steps": [{"step": 0, "url": evil, "title": evil, "action": "click", "element_text": evil,
                                     "outcome": None, "result_url": evil, "screenshot": None}],
                          "steps_total": 1, "forbidden_elements": 0, "blocked_navigations": [],
                          "blocked_navigations_total": 0, "unreachable": None},
        "assessment": {"ai": {"threat": "phishing", "threat_ko": evil, "probability": 0.9, "hold": False,
                              "override": evil, "provider": "x", "model": "x"},
                       "error": False, "escalation": evil,
                       "safebrowsing": {"status": "match", "status_ko": evil, "matches": [{"url": evil, "type": evil}]}},
        "related": {"found": 1, "investigated": [{"sub": 1, "url": evil, "final_url": evil, "threat": "scam",
                                                  "threat_ko": evil, "probability": 0.5, "hold": False,
                                                  "reputation_match": False, "reputation_unchecked": True,
                                                  "status": "COMPLETED", "error": False}]},
        "verdict": {"rev": 1, "decision": "hold", "decision_ko": evil, "threat": None, "threat_ko": None,
                    "note": evil + "<b> 닫히지 않은 태그", "reviewer": evil, "at": "2026-10-12T00:00:00+00:00"},
        "key_screens": [],
        "integrity": {"verified": True, "records": 1, "errors": 0, "head_seq": 0, "head_hash": evil, "key_id": evil,
                      "method": evil},
    }
    pdf = report.render_pdf(rep, tmp_path)
    assert pdf.startswith(b"%PDF") and _images(pdf) == 0


def test_tampered_evidence_is_reported_not_hidden(client, case_id):
    """증거가 바뀌면 패키지는 만들되 검증 실패를 그대로 적는다(이 시험은 증거를 망가뜨리므로 마지막에 둔다)."""
    from safetrace.config import get_settings

    pkg = client.get(f"/api/cases/{case_id}/package", headers=h(VIEWER)).json()
    shot = pkg["exploration"]["steps"][0]["observe"]["screenshot"]
    (get_settings().evidence_dir / case_id / "files" / shot).write_bytes(b"tampered")
    pkg = client.get(f"/api/cases/{case_id}/package", headers=h(VIEWER)).json()
    assert pkg["integrity"]["verified"] is False
    assert any("file_modified" in e for e in pkg["integrity"]["errors"])
    # 보고서도 검증 실패를 적고, 해시가 맞지 않는 화면은 PDF 에 넣지 않는다
    rep = client.get(f"/api/cases/{case_id}/report.json", headers=h(INVESTIGATOR)).json()
    assert rep["integrity"]["verified"] is False and rep["integrity"]["errors"] >= 1
    assert shot in [x["file"] for x in rep["key_screens"]]
    pdf = client.get(f"/api/cases/{case_id}/report.pdf", headers=h(INVESTIGATOR)).content
    assert _images(pdf) == len(rep["key_screens"]) - 1

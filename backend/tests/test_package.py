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
    assert package.verify_sig(z.read("package.json"), z.read("SHA256SUMS"), sig, _signer())
    assert not package.verify_sig(z.read("package.json").replace(b"phishing", b"benign!!"), z.read("SHA256SUMS"), sig, _signer())
    assert package.verify_zip(r.content, _signer())


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


def test_report_pdf_with_many_note_lines(client, case_id, reviewer):
    """판정 메모는 1,000자까지 줄 수 제한이 없다. 줄바꿈 500개(999자) 메모도 PDF 가 만들어져야 한다
    (메모를 표 한 칸에 넣으면 칸이 페이지보다 높아져 LayoutError → 그 사건의 보고서를 아무도 받지 못함)."""
    _, tok = reviewer
    cur = client.get(f"/api/cases/{case_id}", headers=h(VIEWER)).json().get("verdict") or {}
    note = (("x" + chr(10)) * 499) + "x"
    r = client.post(f"/api/cases/{case_id}/verdicts", headers=h(tok),
                    json={"rev": cur.get("rev", 0), "decision": "hold", "threat": None, "note": note})
    assert r.status_code == 201
    r = client.get(f"/api/cases/{case_id}/report.pdf", headers=h(INVESTIGATOR))
    assert r.status_code == 200 and r.content.startswith(b"%PDF")


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
                    "note": evil + chr(10) + evil + "<b> 닫히지 않은 태그", "reviewer": evil, "at": "2026-10-12T00:00:00+00:00"},
        "key_screens": [],
        "integrity": {"verified": True, "records": 1, "errors": 0, "head_seq": 0, "head_hash": evil, "key_id": evil,
                      "method": evil},
    }
    pdf = report.render_pdf(rep, tmp_path)
    assert pdf.startswith(b"%PDF") and _images(pdf) == 0


def test_report_uses_verified_snapshot(client, case_id, monkeypatch):
    """Codex F1: 검증한 체인과 보고서를 만든 체인이 같아야 한다. 에이전트가 증거 볼륨에 쓸 수 있으므로,
    API 가 읽는 순간에만 바뀐 체인을 두었다가 검증 직전에 되돌려도 '검증 통과 + 바뀐 의견'이 나오면 안 된다."""
    from safetrace.api import main
    from safetrace.config import get_settings

    chain = get_settings().evidence_dir / case_id / "chain.jsonl"
    original = chain.read_text(encoding="utf-8")
    lines = []
    for line in original.splitlines():
        rec = json.loads(line)
        if rec["kind"] == "threat" and "sub" not in rec["data"]:
            rec["data"]["threat"] = "benign"
        lines.append(json.dumps(rec, ensure_ascii=False))
    tampered = "\n".join(lines) + "\n"
    real = main.verify_case

    def swap_back(*a, **k):  # 검증하는 순간에는 원래 체인
        chain.write_text(original, encoding="utf-8")
        return real(*a, **k)

    monkeypatch.setattr(main, "verify_case", swap_back)
    try:
        chain.write_text(tampered, encoding="utf-8")
        rep = client.get(f"/api/cases/{case_id}/report.json", headers=h(INVESTIGATOR)).json()
        assert not (rep["assessment"]["ai"]["threat"] == "benign" and rep["integrity"]["verified"])
        chain.write_text(tampered, encoding="utf-8")
        z = zipfile.ZipFile(io.BytesIO(client.get(f"/api/cases/{case_id}/package.zip", headers=h(INVESTIGATOR)).content))
        pkg = json.loads(z.read("package.json"))
        assert not (pkg["assessment"]["threat"]["threat"] == "benign" and pkg["integrity"]["verified"])
    finally:
        chain.write_text(original, encoding="utf-8")


def test_zip_signature_covers_report(client, case_id):
    """Codex F2: ZIP 의 보고서를 바꾸고 SHA256SUMS 를 다시 계산해도 서명 검증에서 드러나야 한다."""
    from safetrace.api.main import _signer

    data = client.get(f"/api/cases/{case_id}/package.zip", headers=h(INVESTIGATOR)).content
    assert package.verify_zip(data, _signer())

    src = zipfile.ZipFile(io.BytesIO(data))
    for target in ("report.json", "report.pdf", "SHA256SUMS"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as out:
            items = {n: src.read(n) for n in src.namelist()}
            if target == "report.json":
                items[target] = items[target].replace(b'"draft": true', b'"draft": false').replace(b"phishing", b"benign")
            elif target == "report.pdf":
                items[target] = items[target] + b"%tampered"
            else:
                items[target] = items[target].replace(b"report.pdf", b"report.PDF")
            if target != "SHA256SUMS":
                items["SHA256SUMS"] = "".join(
                    f"{hashlib.sha256(items[n]).hexdigest()}  {n}\n" for n in items if n != "SHA256SUMS").encode()
            for n, b in items.items():
                out.writestr(n, b)
        assert not package.verify_zip(buf.getvalue(), _signer()), target


def test_malformed_signed_records_do_not_break_exports(tmp_path, client, case_id, monkeypatch):
    """Codex F3: 서명은 자료형을 보장하지 않는다. 침해된 에이전트가 이상한 자료형을 서명받아 넣어도
    보고서는 500 없이 만들어지거나, 적어도 원본 증거 ZIP 내보내기는 막히지 않아야 한다."""
    from safetrace.evidence import EvidenceWriter, Signer, verify_case

    signer = Signer(secrets.token_bytes(32), "k1")
    cid = "dddddddd-0000-0000-0000-000000000000"
    w = EvidenceWriter(tmp_path / "ev", cid, signer)
    w.append("start", {"url": ["x"]})
    w.append("observe", {"step": 0, "url": {"a": 1}, "title": ["t"], "candidates": "x", "forbidden": 3})
    w.append("decision", {"step": 0, "choice": ["click_e1"], "probability": "high"})
    w.append("action", {"step": 0, "action": {"x": 1}, "element": [1], "result_url": 5})
    w.append("finish", {"reason": "agent_finished", "nav_chain": "abc", "final_url": ["u"]})
    w.append("threat", {"threat": ["benign"], "probability": "1", "hold": "no", "override": {"x": 1}})
    w.append("safebrowsing", {"status": ["match"], "matches": "abc"})
    w.append("candidates", {"found": 3})
    w.append("candidate_results", {"results": [1, "x", {"sub": [1], "threat": ["scam"]}]})
    case = Case(id=cid, url="http://x/", source="test", status="COMPLETED", created_by="t", created_at=now())
    res = verify_case(tmp_path / "ev", cid, signer, None)
    assert res.ok
    pkg = package.build(case, package.read_chain(tmp_path / "ev", cid), res, [], [], generated_by="t", key_id="k1")
    assert pkg["assessment"]["threat"].get("threat") is None and any("threat.threat" in m for m in pkg["integrity"]["malformed"])
    rep = report.build(pkg, package.read_chain(tmp_path / "ev", cid) + [{"seq": 99, "ts": 1, "kind": "x", "data": []}])
    json.dumps(rep)
    assert report.render_pdf(rep, tmp_path / "ev").startswith(b"%PDF")

    # 그래도 보고서를 만들지 못하는 경우: 보고서 요청은 오류로 알리고 ZIP 은 보고서 없이 나간다
    def boom(*a, **k):
        raise TypeError("bad record")

    monkeypatch.setattr(report, "build", boom)
    assert client.get(f"/api/cases/{case_id}/report.json", headers=h(INVESTIGATOR)).status_code == 422
    r = client.get(f"/api/cases/{case_id}/package.zip", headers=h(INVESTIGATOR))
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert "report.json" not in z.namelist() and "package.json" in z.namelist()


@pytest.mark.parametrize("override, label", [
    ({"reason": "link_takedown", "original": {"threat": "benign", "probability": 0.65, "provider": "jev_typesafe"}},
     "단축·호스팅 서비스의 링크 정지 안내 → 담당자 검토 · 모델 원래 판단 정상 65%"),
    ({"reason": "brand_lookalike", "brand": "kbank", "destination": "g.kbank.mywire.org",
      "original": {"threat": "unknown", "probability": 0.5, "provider": "jev_typesafe"}},
     "열리지 않은 목적지가 브랜드 사칭 도메인(kbank · g.kbank.mywire.org) → 담당자 검토 · 모델 원래 판단 판단 불가 50%"),
    ({"reason": "brand_name_domain", "brand": "roblox", "destination": "www.roblox.et",
      "original": {"threat": "benign", "probability": 0.85, "provider": "jev_typesafe"}},
     "브랜드 이름 그대로의 다른 도메인(roblox · www.roblox.et) → 담당자 검토 · 모델 원래 판단 정상 85%"),
    ({"reason": "brand_typo_domain", "brand": "trezor", "destination": "web-trzerwallet.gitbook.io",
      "original": {"threat": "benign", "probability": 0.55, "provider": "jev_typesafe"}},
     "브랜드를 내세운 화면인데 도메인이 그 이름의 오타(trezor · web-trzerwallet.gitbook.io) → 담당자 검토 · 모델 원래 판단 정상 55%"),
    ({"reason": "brand_login_shared_hosting", "brand": "steam", "destination": "x.netlify.app",
      "original": {"threat": "benign", "probability": 0.49, "provider": "jev_typesafe"}},
     "공용 호스팅의 브랜드·로그인 표지(steam · x.netlify.app) → 담당자 검토 · 모델 원래 판단 정상 49%"),
    ({"reason": "brand_clone_title", "brand": "steam", "destination": "sample-clone-42.dev",
      "original": {"threat": "benign", "probability": 0.83, "provider": "jev_typesafe"}},
     "공식 도메인 밖에서 브랜드 공식 화면 제목을 그대로 쓴 로그인 화면(steam · sample-clone-42.dev) → 담당자 검토"
     " · 모델 원래 판단 정상 83%"),
    ({"reason": "official_betting_domain", "operators": ["betman"],
      "original": {"threat": "illegal_gambling", "probability": 0.9, "provider": "jev_typesafe"}},
     "공식 사행사업자 도메인 · betman · 모델 원래 판단 불법 도박 90%"),
    ({"reason": ["x"], "original": "y"}, "코드 규칙"),  # 자료형이 어긋난 값은 글자로만, 지어내지 않는다
])
def test_code_rule_override_kept_in_package_and_report(tmp_path, override, label):
    """판단 엔진의 코드 규칙(override)은 사전이다. 패키지가 자료형 오류로 버리거나 malformed 로 적지 않고,
    보고서에는 사람이 읽는 설명으로 나온다."""
    from safetrace.evidence import EvidenceWriter, Signer, verify_case

    signer = Signer(secrets.token_bytes(32), "k1")
    cid = "eeeeeeee-0000-0000-0000-000000000000"
    w = EvidenceWriter(tmp_path / "ev", cid, signer)
    w.append("start", {"url": "https://tny.kr/tzsy0"})
    w.append("threat", {"threat": "phishing", "probability": 1.0, "probabilities": {"phishing": 1.0}, "hold": True,
                        "provider": "link_takedown", "model": "jev-1.13.0", "evidence_seqs": [], "override": override})
    case = Case(id=cid, url="https://tny.kr/tzsy0", source="test", status="REVIEW_REQUIRED", created_by="t",
                created_at=now())
    res = verify_case(tmp_path / "ev", cid, signer, None)
    records = package.read_chain(tmp_path / "ev", cid)
    pkg = package.build(case, records, res, [], [], generated_by="t", key_id="k1")
    assert pkg["integrity"]["malformed"] == []
    assert pkg["assessment"]["threat"]["override"] == override
    rep = report.build(pkg, records)
    assert rep["assessment"]["ai"]["override"] == label
    assert report.render_pdf(rep, tmp_path / "ev").startswith(b"%PDF")


def test_zip_uses_verified_file_bytes(client, case_id, monkeypatch):
    """Codex 2회차 F1: 검증 뒤(보고서 PDF 를 만드는 사이) 증거 파일을 바꿔도, 바뀐 파일이 '검증 통과'·서명된 ZIP 에
    들어가면 안 된다. 받은 쪽 확인(verify_zip)도 체인의 파일 해시와 대조해 잡아야 한다."""
    from safetrace.api import main
    from safetrace.config import get_settings

    pkg = client.get(f"/api/cases/{case_id}/package", headers=h(VIEWER)).json()
    shot = pkg["exploration"]["steps"][0]["observe"]["screenshot"]
    path = get_settings().evidence_dir / case_id / "files" / shot
    original = path.read_bytes()
    real = main._report_pdf

    def swap_after_pdf(rep):
        out = real(rep)
        path.write_bytes(b"swapped after verification")
        return out

    monkeypatch.setattr(main, "_report_pdf", swap_after_pdf)
    try:
        data = client.get(f"/api/cases/{case_id}/package.zip", headers=h(INVESTIGATOR)).content
    finally:
        path.write_bytes(original)
    z = zipfile.ZipFile(io.BytesIO(data))
    got = json.loads(z.read("package.json"))
    exported = f"files/{shot}" in z.namelist() and z.read(f"files/{shot}") != original
    assert not (exported and got["integrity"]["verified"])
    assert not exported  # 검증한 해시와 다른 파일은 담지 않는다

    # 받은 쪽 확인: SHA256SUMS·서명이 맞아도 체인의 파일 해시와 다르면 실패
    from safetrace.api.main import _signer
    from safetrace.evidence import Signer

    s2 = Signer(secrets.token_bytes(32), "k1")
    pkg2 = {"generated_at": "t", "case": {"id": case_id}, "files": []}
    chain = '{"seq":0,"files":{"a.png":"' + hashlib.sha256(b"right").hexdigest() + '"}}\n'
    bad = package.export_zip(pkg2, get_settings().evidence_dir, case_id, s2, [("files/a.png", b"wrong")], chain_text=chain)
    assert not package.verify_zip(bad, s2)
    assert package.verify_zip(client.get(f"/api/cases/{case_id}/package.zip", headers=h(INVESTIGATOR)).content, _signer())


def test_out_of_range_probability_keeps_zip_exportable(tmp_path, client, case_id, monkeypatch):
    """Codex 2회차 F2: 확률이 범위 밖(거대한 수·음수)이면 버리고 malformed 에 적는다. PDF 를 그리다 실패해도 ZIP 은 나간다."""
    from safetrace.evidence import EvidenceWriter, Signer, verify_case

    signer = Signer(secrets.token_bytes(32), "k1")
    cid = "eeeeeeee-0000-0000-0000-000000000000"
    w = EvidenceWriter(tmp_path / "ev", cid, signer)
    w.append("decision", {"step": 0, "choice": "finish", "probability": -3})
    w.append("threat", {"threat": "phishing", "probability": 10**400, "hold": False})
    case = Case(id=cid, url="http://x/", source="test", status="COMPLETED", created_by="t", created_at=now())
    pkg = package.build(case, package.read_chain(tmp_path / "ev", cid), verify_case(tmp_path / "ev", cid, signer, None),
                        [], [], generated_by="t", key_id="k1")
    assert "probability" not in pkg["assessment"]["threat"]
    assert {"seq 0: decision.probability", "seq 1: threat.probability"} <= set(pkg["integrity"]["malformed"])
    assert report.render_pdf(report.build(pkg, package.read_chain(tmp_path / "ev", cid)), tmp_path).startswith(b"%PDF")
    assert report._pct(10**400) == "-"

    def boom(rep):
        raise OverflowError("render")

    monkeypatch.setattr(report, "render_pdf", boom)
    assert client.get(f"/api/cases/{case_id}/report.pdf", headers=h(INVESTIGATOR)).status_code == 422
    r = client.get(f"/api/cases/{case_id}/package.zip", headers=h(INVESTIGATOR))
    assert r.status_code == 200 and "report.pdf" not in zipfile.ZipFile(io.BytesIO(r.content)).namelist()


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

"""증거 무결성: 변조·삭제·순서 변경·절단·키 없는 재계산을 모두 탐지해야 한다."""

import json
import secrets
import uuid

import pytest

from safetrace.evidence import EvidenceWriter, Head, Signer, _record_hash, verify_case


@pytest.fixture
def case(tmp_path):
    signer = Signer(secrets.token_bytes(32), "k1")
    cid = str(uuid.uuid4())
    w = EvidenceWriter(tmp_path, cid, signer)
    for i in range(5):
        name = f"s{i:03d}_observe.png"
        w.file_path(name).write_bytes(b"PNG" + bytes([i]) * 100)
        w.append("observe", {"step": i, "url": f"https://x.example/{i}"}, [name])
    return tmp_path, cid, signer, Head(w.head.seq, w.head.hash)


def lines(root, cid):
    return (root / cid / "chain.jsonl").read_text(encoding="utf-8").splitlines()


def write(root, cid, ls):
    (root / cid / "chain.jsonl").write_text("\n".join(ls) + "\n", encoding="utf-8")


def test_clean_chain_verifies(case):
    root, cid, signer, head = case
    r = verify_case(root, cid, signer, head)
    assert r.ok, r.errors
    assert r.records == 5


def test_file_modified(case):
    root, cid, signer, head = case
    (root / cid / "files" / "s002_observe.png").write_bytes(b"tampered")
    r = verify_case(root, cid, signer, head)
    assert not r.ok and any("file_modified" in e for e in r.errors)


def test_file_deleted(case):
    root, cid, signer, head = case
    (root / cid / "files" / "s001_observe.png").unlink()
    assert any("file_missing" in e for e in verify_case(root, cid, signer, head).errors)


def test_record_edited(case):
    root, cid, signer, head = case
    ls = lines(root, cid)
    rec = json.loads(ls[2])
    rec["data"]["url"] = "https://innocent.example/"
    ls[2] = json.dumps(rec, ensure_ascii=False)
    write(root, cid, ls)
    assert any("hash_mismatch" in e for e in verify_case(root, cid, signer, head).errors)


def test_record_deleted(case):
    root, cid, signer, head = case
    ls = lines(root, cid)
    del ls[2]
    write(root, cid, ls)
    r = verify_case(root, cid, signer, head)
    assert not r.ok and any("gap_or_reorder" in e or "prev_mismatch" in e for e in r.errors)


def test_records_reordered(case):
    root, cid, signer, head = case
    ls = lines(root, cid)
    ls[1], ls[2] = ls[2], ls[1]
    write(root, cid, ls)
    assert not verify_case(root, cid, signer, head).ok


def test_tail_truncated(case):
    root, cid, signer, head = case
    write(root, cid, lines(root, cid)[:-1])
    r = verify_case(root, cid, signer, head)
    assert not r.ok and any("head_mismatch" in e for e in r.errors)


def test_insider_recomputes_hashes_without_key(case):
    """저장소 권한자가 파일과 해시를 함께 고쳐도 서명 키가 없으면 탐지된다."""
    root, cid, signer, head = case
    (root / cid / "files" / "s000_observe.png").write_bytes(b"fake screenshot")
    from safetrace.evidence import GENESIS, sha256_file

    prev = GENESIS
    new = []
    for line in lines(root, cid):
        rec = json.loads(line)
        rec["files"] = {n: sha256_file(root / cid / "files" / n) for n in rec["files"]}
        body = {k: rec[k] for k in ("seq", "ts", "kind", "data", "files")}
        rec["prev"] = prev
        rec["hash"] = _record_hash(prev, body)
        prev = rec["hash"]
        new.append(json.dumps(rec, ensure_ascii=False))
    write(root, cid, new)
    r = verify_case(root, cid, signer, Head(4, prev))  # DB head 까지 고쳤다고 가정
    assert not r.ok and any("bad_signature" in e for e in r.errors)


def test_wrong_key_fails(case):
    root, cid, _, head = case
    other = Signer(secrets.token_bytes(32), "k2")
    assert not verify_case(root, cid, other, head).ok


def test_unsafe_file_names_rejected(tmp_path):
    w = EvidenceWriter(tmp_path, str(uuid.uuid4()), Signer(secrets.token_bytes(32), "k"))
    for bad in ["../x.png", "a/b.png", "x.html", "X.PNG", ""]:
        with pytest.raises(ValueError):
            w.file_path(bad)


def test_short_key_rejected():
    with pytest.raises(ValueError):
        Signer(b"short", "k")

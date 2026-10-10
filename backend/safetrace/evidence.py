"""증거 해시 체인 + 분리된 키의 HMAC 서명.

사건마다 evidence/<case_id>/ 아래에
  chain.jsonl        기록 한 줄 = {"seq", "ts", "kind", "data", "files": {이름: sha256}, "prev", "hash", "sig"}
  files/             스크린샷·영상 등 원본 파일
을 둔다.

hash = sha256(prev || canonical(seq, ts, kind, data, files))
sig  = HMAC-SHA256(key, hash)   ← 키는 증거 저장소와 분리 보관(환경 변수). 서명하는 에이전트와 검증하는 API 만 가진다

파일과 해시를 함께 고쳐도, 키가 없으면 서명을 다시 만들 수 없으므로 검증에서 드러난다.
기록 삭제·순서 변경은 prev 연결과 seq 연속성 검사로, 끝부분 절단은 DB에 따로 둔
head(마지막 seq·hash)와 비교해 탐지한다.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

GENESIS = "0" * 64
_SAFE_NAME = re.compile(r"^[a-z0-9_\-]{1,64}\.(png|webm|json|txt)$")


def canonical(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _record_hash(prev: str, body: dict) -> str:
    return sha256_bytes(prev.encode() + canonical(body))


class Signer:
    def __init__(self, key: bytes, key_id: str):
        if len(key) < 32:
            raise ValueError("HMAC 키는 32바이트 이상이어야 한다")
        self._key = key
        self.key_id = key_id

    def sign(self, digest: str) -> str:
        return hmac.new(self._key, digest.encode(), hashlib.sha256).hexdigest()

    def verify(self, digest: str, sig: str) -> bool:
        return hmac.compare_digest(self.sign(digest), sig)


@dataclass
class Head:
    seq: int
    hash: str


class EvidenceWriter:
    """한 사건의 증거를 순서대로 추가한다. 스레드 안전."""

    def __init__(self, root: Path, case_id: str, signer: Signer):
        if not re.fullmatch(r"[a-f0-9\-]{8,64}", case_id):
            raise ValueError("invalid case id")
        self.dir = root / case_id
        self.files_dir = self.dir / "files"
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.chain_path = self.dir / "chain.jsonl"
        self._signer = signer
        self._lock = threading.Lock()
        self.head = Head(-1, GENESIS)

    def file_path(self, name: str) -> Path:
        if not _SAFE_NAME.match(name):
            raise ValueError("invalid evidence file name")
        return self.files_dir / name

    def append(self, kind: str, data: dict, files: list[str] | None = None) -> dict:
        with self._lock:
            file_hashes = {n: sha256_file(self.file_path(n)) for n in (files or [])}
            body = {
                "seq": self.head.seq + 1,
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "kind": kind,
                "data": data,
                "files": file_hashes,
            }
            digest = _record_hash(self.head.hash, body)
            rec = {**body, "prev": self.head.hash, "hash": digest, "sig": self._signer.sign(digest),
                   "key_id": self._signer.key_id}
            with self.chain_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.head = Head(body["seq"], digest)
            return rec


@dataclass
class VerifyResult:
    ok: bool
    records: int
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "records": self.records, "errors": self.errors}


def verify_case(root: Path, case_id: str, signer: Signer, expected_head: Head | None) -> VerifyResult:
    d = root / case_id
    chain = d / "chain.jsonl"
    errors: list[str] = []
    if not chain.exists():
        return VerifyResult(False, 0, ["chain_missing"])
    prev = GENESIS
    seq = -1
    lines = chain.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        try:
            rec = json.loads(line)
            body = {k: rec[k] for k in ("seq", "ts", "kind", "data", "files")}
        except (ValueError, KeyError):
            errors.append(f"line {i}: malformed")
            break
        if rec["seq"] != seq + 1:
            errors.append(f"seq {rec['seq']}: gap_or_reorder (expected {seq + 1})")
        if rec.get("prev") != prev:
            errors.append(f"seq {rec['seq']}: prev_mismatch")
        digest = _record_hash(prev, body)
        if digest != rec.get("hash"):
            errors.append(f"seq {rec['seq']}: hash_mismatch")
        if not signer.verify(rec.get("hash", ""), rec.get("sig", "")):
            errors.append(f"seq {rec['seq']}: bad_signature")
        for name, h in body["files"].items():
            try:
                p = d / "files" / name
                if not _SAFE_NAME.match(name) or not p.exists():
                    errors.append(f"seq {rec['seq']}: file_missing {name}")
                elif sha256_file(p) != h:
                    errors.append(f"seq {rec['seq']}: file_modified {name}")
            except OSError:
                errors.append(f"seq {rec['seq']}: file_unreadable {name}")
        prev = rec.get("hash", "")
        seq = rec["seq"]
    if expected_head is not None and (seq != expected_head.seq or prev != expected_head.hash):
        errors.append(f"head_mismatch (chain seq {seq}, expected {expected_head.seq})")
    return VerifyResult(not errors, len(lines), errors)

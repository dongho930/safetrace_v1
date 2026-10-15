"""증거 해시 체인 + 분리된 키의 HMAC 서명.

사건마다 evidence/<case_id>/ 아래에
  chain.jsonl        기록 한 줄 = {"seq", "ts", "kind", "data", "files": {이름: sha256}, "prev", "hash", "sig"}
  files/             스크린샷·영상 등 원본 파일
을 둔다.

hash = sha256(prev || canonical(seq, ts, kind, data, files))
sig  = HMAC-SHA256(key, hash)   ← 키는 증거 저장소와 분리 보관(환경 변수). 서명 서비스와 검증하는 API 만 가진다

운영에서 에이전트는 키를 갖지 않는다. 기록 내용을 서명 서비스(safetrace.signer)에 보내면 서비스가 seq·ts·prev 를
직접 정하고 서명해 돌려준다(RemoteSealer). 개발 모드(서명 서비스 없음)에서는 같은 프로세스에서 서명한다(LocalSealer).

파일과 해시를 함께 고쳐도, 키가 없으면 서명을 다시 만들 수 없으므로 검증에서 드러난다.
기록 삭제·순서 변경은 prev 연결과 seq 연속성 검사로, 끝부분 절단은 DB에 따로 둔
head(마지막 seq·hash)와 비교해 탐지한다.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import re
import stat
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

GENESIS = "0" * 64
_SAFE_NAME = re.compile(r"^[a-z0-9_\-]{1,64}\.(png|webm|json|txt)$")
CHAIN_MAX_BYTES = 64 << 20  # 체인 원문(기록 수천 건도 수 MB)
FILE_MAX_BYTES = 512 << 20  # 증거 파일 하나(녹화가 가장 크다)


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


# ── 증거 볼륨 읽기(API·검증 쪽) ─────────────────────────────
# 증거 볼륨은 에이전트(조사 대상 페이지를 다루므로 침해될 수 있다)가 쓴다. 읽는 쪽이 링크를 따라가면 API 컨테이너의
# 다른 파일(/proc/self/environ 등)이 패키지·파일 응답으로 나가고, FIFO 를 열면 쓰는 쪽이 올 때까지 기다리며 이벤트
# 처리가 멈춘다(Codex 지적). 그래서 API 는 증거 파일을 아래 함수로만 연다.
class UnsafeEvidence(OSError):
    """링크·특수 파일·너무 큰 파일, 또는 사건 폴더가 다른 곳을 가리킴."""


def open_evidence(root: Path, case_id: str, *parts: str) -> tuple[int, os.stat_result]:
    """증거 파일을 열어 (fd, fstat) 를 돌려준다. 사건 폴더·files 폴더가 링크면 거절하고, 마지막 이름은 링크를 따라가지
    않으며(O_NOFOLLOW), 특수 파일에서 기다리지 않고(O_NONBLOCK) 연 뒤 일반 파일인지 fstat 으로 확인한다.
    없으면 FileNotFoundError, 안전하지 않으면 UnsafeEvidence. fd 는 호출한 쪽이 닫는다."""
    base = Path(os.path.realpath(root))
    path = base.joinpath(case_id, *parts)
    if Path(os.path.realpath(path.parent)) != path.parent:
        raise UnsafeEvidence("evidence_dir_redirected")
    if not hasattr(os, "O_NOFOLLOW") and path.is_symlink():  # Windows(개발·시험)에는 O_NOFOLLOW 가 없다
        raise UnsafeEvidence("symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise UnsafeEvidence("symlink") from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafeEvidence("not_regular_file")
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def read_evidence(root: Path, case_id: str, *parts: str, max_bytes: int) -> bytes:
    """open_evidence 로 열어 max_bytes 까지 읽는다. 넘으면 UnsafeEvidence."""
    fd, st = open_evidence(root, case_id, *parts)
    with os.fdopen(fd, "rb") as f:
        if st.st_size > max_bytes:
            raise UnsafeEvidence("too_large")
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UnsafeEvidence("too_large")
    return data


def iter_evidence(fd: int, size: int, chunk: int = 1 << 16) -> Iterator[bytes]:
    """open_evidence 로 연 fd 에서 연 시점의 크기만큼만 읽어 내보낸다(그 뒤 덧붙은 내용은 내보내지 않는다)."""
    with os.fdopen(fd, "rb") as f:
        left = size
        while left > 0:
            b = f.read(min(chunk, left))
            if not b:
                return
            left -= len(b)
            yield b


def sha256_evidence(root: Path, case_id: str, *parts: str) -> str:
    fd, st = open_evidence(root, case_id, *parts)
    h = hashlib.sha256()
    for b in iter_evidence(fd, st.st_size):
        h.update(b)
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


def make_record(prev: Head, kind: str, data: dict, files: dict[str, str], signer: Signer,
                ts: str | None = None) -> dict:
    """prev 다음에 올 기록을 만들고 서명한다. 서명 서비스와 개발 모드가 같은 함수를 쓴다."""
    body = {
        "seq": prev.seq + 1,
        "ts": ts or datetime.now(UTC).isoformat(timespec="milliseconds"),
        "kind": kind,
        "data": data,
        "files": files,
    }
    digest = _record_hash(prev.hash, body)
    return {**body, "prev": prev.hash, "hash": digest, "sig": signer.sign(digest), "key_id": signer.key_id}


class Sealer(Protocol):
    def seal(self, case_id: str, head: Head, kind: str, data: dict, files: dict[str, str]) -> dict: ...


class LocalSealer:
    """개발 모드: 같은 프로세스에서 서명한다."""

    def __init__(self, signer: Signer):
        self._signer = signer

    def seal(self, case_id: str, head: Head, kind: str, data: dict, files: dict[str, str]) -> dict:
        return make_record(head, kind, data, files, self._signer)


class EvidenceWriter:
    """한 사건의 증거를 순서대로 추가한다. 스레드 안전."""

    def __init__(self, root: Path, case_id: str, sealer: Signer | Sealer):
        if not re.fullmatch(r"[a-f0-9\-]{8,64}", case_id):
            raise ValueError("invalid case id")
        self.case_id = case_id
        self.dir = root / case_id
        self.files_dir = self.dir / "files"
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.chain_path = self.dir / "chain.jsonl"
        self._sealer = LocalSealer(sealer) if isinstance(sealer, Signer) else sealer
        self._lock = threading.Lock()
        self.head = Head(-1, GENESIS)

    def file_path(self, name: str) -> Path:
        if not _SAFE_NAME.match(name):
            raise ValueError("invalid evidence file name")
        return self.files_dir / name

    def append(self, kind: str, data: dict, files: list[str] | None = None) -> dict:
        with self._lock:
            file_hashes = {n: sha256_file(self.file_path(n)) for n in (files or [])}
            rec = self._sealer.seal(self.case_id, self.head, kind, data, file_hashes)
            # 서명 서비스가 돌려준 기록이 이 체인에 이어지는지 확인한다(서명은 키가 없어 확인하지 못함)
            body = {k: rec[k] for k in ("seq", "ts", "kind", "data", "files")}
            if (rec["seq"] != self.head.seq + 1 or rec["prev"] != self.head.hash
                    or rec["hash"] != _record_hash(self.head.hash, body)):
                raise ValueError("sealed record does not extend the chain")
            with self.chain_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.head = Head(rec["seq"], rec["hash"])
            return rec


@dataclass
class VerifyResult:
    ok: bool
    records: int
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "records": self.records, "errors": self.errors}


def verify_case(root: Path, case_id: str, signer: Signer, expected_head: Head | None,
                text: str | None = None) -> VerifyResult:
    """text: 이미 읽은 체인 내용. 검증한 내용과 쓰는 내용이 같아야 할 때(패키지·보고서) 같은 스냅숏을 넘긴다."""
    errors: list[str] = []
    if text is None:
        try:
            text = read_evidence(root, case_id, "chain.jsonl", max_bytes=CHAIN_MAX_BYTES).decode("utf-8", "replace")
        except FileNotFoundError:
            return VerifyResult(False, 0, ["chain_missing"])
        except UnsafeEvidence as e:
            return VerifyResult(False, 0, [f"chain_unsafe {e}"])
        except OSError:
            return VerifyResult(False, 0, ["chain_unreadable"])
    prev = GENESIS
    seq = -1
    lines = text.splitlines()
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
                if not _SAFE_NAME.match(name):
                    errors.append(f"seq {rec['seq']}: file_missing {name}")
                elif sha256_evidence(root, case_id, "files", name) != h:
                    errors.append(f"seq {rec['seq']}: file_modified {name}")
            except FileNotFoundError:
                errors.append(f"seq {rec['seq']}: file_missing {name}")
            except UnsafeEvidence:
                errors.append(f"seq {rec['seq']}: file_unsafe {name}")
            except OSError:
                errors.append(f"seq {rec['seq']}: file_unreadable {name}")
        prev = rec.get("hash", "")
        seq = rec["seq"]
    if expected_head is not None and (seq != expected_head.seq or prev != expected_head.hash):
        errors.append(f"head_mismatch (chain seq {seq}, expected {expected_head.seq})")
    return VerifyResult(not errors, len(lines), errors)

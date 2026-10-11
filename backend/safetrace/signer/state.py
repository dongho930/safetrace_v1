"""서명 서비스의 사건별 체인 상태(열림·닫힘, 마지막 seq·hash).

에이전트는 기록 내용만 보낸다. seq·ts·prev 는 여기서 정하므로, 에이전트가 뚫려도
- 이미 서명한 기록을 다른 내용으로 다시 서명받을 수 없고(seq 는 앞으로만 간다)
- API 가 열지 않은 사건, 이미 닫은 사건에는 기록을 더할 수 없으며
- 수집 시각을 바꿀 수 없다.
조사가 끝나면 API 가 체인을 닫고 여기 있는 head 를 DB 에 둔다(에이전트가 보고한 head 를 믿지 않는다).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from ..evidence import GENESIS, Head, Signer, make_record


class NotOpen(Exception):
    pass


class Closed(Exception):
    pass


class SeqConflict(Exception):
    def __init__(self, head: Head):
        super().__init__(f"expected seq {head.seq + 1}")
        self.head = head


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class ChainState:
    def __init__(self, path: Path, signer: Signer):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("""CREATE TABLE IF NOT EXISTS chains (
            case_id TEXT PRIMARY KEY, seq INTEGER NOT NULL, hash TEXT NOT NULL, closed INTEGER NOT NULL,
            opened_at TEXT NOT NULL, closed_at TEXT, last_rec TEXT)""")
        self._signer = signer
        self._lock = threading.Lock()

    def _row(self, case_id: str):
        return self._db.execute("SELECT seq, hash, closed, last_rec FROM chains WHERE case_id = ?",
                                (case_id,)).fetchone()

    def open(self, case_id: str) -> dict:
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO chains (case_id, seq, hash, closed, opened_at) VALUES (?, -1, ?, 0, ?)",
                             (case_id, GENESIS, _now()))
            return self._head(case_id)

    def close(self, case_id: str) -> dict:
        with self._lock:
            if self._row(case_id) is None:
                raise NotOpen(case_id)
            self._db.execute("UPDATE chains SET closed = 1, closed_at = COALESCE(closed_at, ?) WHERE case_id = ?",
                             (_now(), case_id))
            return self._head(case_id)

    def head(self, case_id: str) -> dict:
        with self._lock:
            if self._row(case_id) is None:
                raise NotOpen(case_id)
            return self._head(case_id)

    def _head(self, case_id: str) -> dict:
        seq, h, closed, _ = self._row(case_id)
        return {"seq": seq, "hash": h, "closed": bool(closed)}

    def append(self, case_id: str, seq: int, kind: str, data: dict, files: dict[str, str]) -> dict:
        """seq 는 에이전트가 기대하는 다음 번호. 응답이 끊겨 같은 내용을 다시 보내면 앞서 만든 기록을 돌려준다."""
        with self._lock:
            row = self._row(case_id)
            if row is None:
                raise NotOpen(case_id)
            cur_seq, cur_hash, closed, last = row
            if closed:
                raise Closed(case_id)
            if seq == cur_seq and last:
                rec = json.loads(last)
                if (rec["kind"], rec["data"], rec["files"]) == (kind, data, files):
                    return rec
            if seq != cur_seq + 1:
                raise SeqConflict(Head(cur_seq, cur_hash))
            rec = make_record(Head(cur_seq, cur_hash), kind, data, files, self._signer)
            self._db.execute("UPDATE chains SET seq = ?, hash = ?, last_rec = ? WHERE case_id = ?",
                             (rec["seq"], rec["hash"], json.dumps(rec, ensure_ascii=False), case_id))
            return rec

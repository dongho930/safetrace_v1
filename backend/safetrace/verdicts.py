"""담당자 판정 저장.

- 판정은 검토관 이상의 담당자 계정만 한다(API 의 need("reviewer", human=True)). AI·자동화 토큰은 확정할 수 없다
- 판정은 덮어쓰지 않고 판(rev)을 쌓는다. 누가 언제 무엇을 무엇으로 바꿨는지 그대로 남는다
- 낙관적 잠금: 요청에 '보고 있던 판 번호'를 함께 보낸다. 그사이 다른 담당자가 저장했으면 거절한다(409)
- 판정에는 당시 증거 체인 끝(head)과 AI 의견을 함께 묶어, 어떤 증거를 보고 정했는지 나중에 확인할 수 있다
"""

from __future__ import annotations

import re

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from .store import Case, Store, Verdict

DECISIONS = ("threat", "benign", "hold")  # 위협 확정 | 정상 | 보류
THREATS = ("phishing", "scam", "illegal_gambling", "malware")
NOTE_MAX = 1000
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # 줄바꿈(\n)만 남긴다
_UNFINISHED = {"QUEUED", "RUNNING"}


class VerdictError(ValueError):
    """사용자에게 그대로 보여 줘도 되는 판정 오류."""


class VerdictConflict(Exception):
    """보고 있던 판 이후에 다른 담당자가 판정을 저장했다."""

    def __init__(self, current: Verdict | None):
        super().__init__("conflict")
        self.current = current


def clean_note(note: str | None) -> str | None:
    if note is None:
        return None
    note = _CONTROL.sub("", note.replace("\r\n", "\n")).strip()
    if len(note) > NOTE_MAX:
        raise VerdictError(f"메모는 {NOTE_MAX}자까지 쓸 수 있습니다")
    return note or None


def check(decision: str, threat: str | None) -> None:
    if decision not in DECISIONS:
        raise VerdictError("알 수 없는 판정입니다")
    if decision == "threat" and threat not in THREATS:
        raise VerdictError("위협 확정에는 유형(피싱·사기·불법 도박·악성 앱)이 필요합니다")
    if decision != "threat" and threat is not None:
        raise VerdictError("유형은 위협 확정에만 붙입니다")


def _latest(s, case_id: str) -> Verdict | None:
    return s.scalar(select(Verdict).where(Verdict.case_id == case_id).order_by(Verdict.rev.desc()).limit(1))


def save(store: Store, case_id: str, *, expected_rev: int, decision: str, threat: str | None, note: str | None,
         reviewer: str, user_id: int) -> Verdict:
    """expected_rev: 담당자가 보고 있던 판 번호(판정이 없었으면 0). 저장한 새 판을 돌려준다."""
    check(decision, threat)
    note = clean_note(note)
    with store.session() as s:
        c = s.get(Case, case_id)
        if c is None:
            raise LookupError(case_id)
        if c.status in _UNFINISHED:
            raise VerdictError("조사가 끝난 뒤에 판정할 수 있습니다")
        cur = _latest(s, case_id)
        if (cur.rev if cur else 0) != expected_rev:
            raise VerdictConflict(cur)
        v = Verdict(case_id=case_id, rev=expected_rev + 1, decision=decision, threat=threat, note=note,
                    reviewer=reviewer, user_id=user_id, ai_threat=(c.threat or {}).get("threat"),
                    head_seq=c.head_seq, head_hash=c.head_hash)
        s.add(v)
        try:
            s.commit()
        except IntegrityError:  # 같은 판을 보고 동시에 저장한 다른 요청이 먼저 들어갔다
            s.rollback()
            raise VerdictConflict(_latest(s, case_id)) from None
    return v


def history(store: Store, case_id: str) -> list[Verdict]:
    with store.session() as s:
        return list(s.scalars(select(Verdict).where(Verdict.case_id == case_id).order_by(Verdict.rev.desc())))


def latest_for(store: Store, case_ids: list[str]) -> dict[str, Verdict]:
    """사건 여러 개의 현재 판정을 한 번에 가져온다(목록용)."""
    if not case_ids:
        return {}
    with store.session() as s:
        top = (select(Verdict.case_id, func.max(Verdict.rev).label("rev"))
               .where(Verdict.case_id.in_(case_ids)).group_by(Verdict.case_id).subquery())
        rows = s.scalars(select(Verdict).join(top, (Verdict.case_id == top.c.case_id) & (Verdict.rev == top.c.rev)))
        return {v.case_id: v for v in rows}

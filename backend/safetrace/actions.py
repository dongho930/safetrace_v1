"""조치 추적과 재확인(모니터링 담당자 업무).

- 조치는 담당자가 위협으로 확정한 사건에만 기록한다: 기관에 요청함(기관·접수 번호) → 차단 확인·삭제 확인 → 종결.
  판정처럼 판(rev)을 쌓고, 보고 있던 판 번호로 동시 저장을 막는다(409)
- 재확인은 조치를 추적 중인 사건의 신고 주소에 다시 접속해 본다(살아 있음·사라짐·회선 차단 등). 접속은 격리된 조사
  컨테이너가 검문 프록시를 거쳐 하고(agent/recheck.py), API 가 먼저 만든 대기 줄의 번호로만 결과를 받는다
- 차단·삭제를 확인한 사건이 재확인에서 다시 접속되면 '다시 나타남'을 시스템이 기록한다(담당자가 다시 요청하도록).
  재확인 결과는 조사 컨테이너가 보낸 값이라 상태를 정하는 데는 '다시 나타남' 표시에만 쓰고, 차단·삭제 확인은 사람이 한다
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from .store import TERMINAL, Case, CaseAction, CaseCheck, Store, Verdict, now
from .verdicts import clean_note

STATES = ("requested", "blocked", "removed", "reappeared", "closed")
HUMAN_STATES = ("requested", "blocked", "removed", "closed")  # 다시 나타남은 재확인(시스템)만 기록한다
TRACKED = ("requested", "blocked", "removed", "reappeared")  # 재확인 대상
CONFIRMED = ("blocked", "removed")
AGENCIES = ("kisa", "kcsc", "ngcc", "police", "fss", "other")  # referral.py 의 기관 표와 같은 이름 + 기타
RESULTS = ("alive", "gone", "filtered", "refused", "unreachable", "error")
SYSTEM_ACTOR = "system:recheck"
REF_MAX = 100
PENDING_TTL = timedelta(minutes=15)  # 이보다 오래 결과가 없는 대기 줄은 만료(조사 컨테이너가 죽었거나 밀렸다)
MIN_GAP = timedelta(minutes=2)  # 같은 사건을 이보다 자주 재확인하지 않는다(담당자 버튼)
# 재확인은 조사와 같은 워커가 한다: 쌓아 두면 사람 신고 조사가 밀린다(Codex 지적). 주체별·전체 대기 상한
MAX_PENDING_PER_ACTOR = 10
MAX_PENDING_TOTAL = 30
# 상한 검사와 접수를 한 번에: 서로 다른 사건의 동시 요청이 같은 대기 수를 읽고 함께 통과하지 않게(Codex 2회차).
# 사건 접수 한도(_intake_lock)처럼 API 프로세스 하나 기준이다
_queue_lock = threading.Lock()


class ActionError(ValueError):
    """사용자에게 그대로 보여 줘도 되는 조치 오류."""


class ActionConflict(Exception):
    def __init__(self, current: CaseAction | None):
        super().__init__("conflict")
        self.current = current


def _latest(s, case_id: str) -> CaseAction | None:
    return s.scalar(select(CaseAction).where(CaseAction.case_id == case_id).order_by(CaseAction.rev.desc()).limit(1))


def _one_line(v: str | None, n: int) -> str | None:
    if v is None:
        return None
    v = " ".join((clean_note(v.replace("\n", " ")) or "").split())
    if len(v) > n:
        raise ActionError(f"접수 번호는 {n}자까지 쓸 수 있습니다")
    return v or None


def save(store: Store, case_id: str, *, expected_rev: int, state: str, agency: str | None, ref: str | None,
         note: str | None, actor: str) -> CaseAction:
    """담당자의 조치 기록. 위협 확정 판정이 있는 끝난 사건만. 저장한 새 판을 돌려준다."""
    if state not in HUMAN_STATES:
        raise ActionError("알 수 없는 조치 상태입니다")
    if state == "requested" and agency not in AGENCIES:
        raise ActionError("요청한 기관을 고르세요")
    if state != "requested" and agency is not None:
        raise ActionError("기관은 '요청함'에만 붙입니다")
    ref, note = _one_line(ref, REF_MAX), clean_note(note)
    with store.session() as s:
        c = s.get(Case, case_id)
        if c is None:
            raise LookupError(case_id)
        if c.status not in TERMINAL:
            raise ActionError("조사가 끝난 뒤에 조치를 기록할 수 있습니다")
        v = s.scalar(select(Verdict).where(Verdict.case_id == case_id).order_by(Verdict.rev.desc()).limit(1))
        if v is None or v.decision != "threat":
            raise ActionError("담당자가 위협으로 확정한 사건에만 조치를 기록할 수 있습니다")
        cur = _latest(s, case_id)
        if (cur.rev if cur else 0) != expected_rev:
            raise ActionConflict(cur)
        a = CaseAction(case_id=case_id, rev=expected_rev + 1, state=state, agency=agency, ref=ref, note=note, actor=actor)
        s.add(a)
        try:
            s.commit()
        except IntegrityError:
            s.rollback()
            raise ActionConflict(_latest(s, case_id)) from None
    return a


def history(store: Store, case_id: str, limit: int = 50) -> list[CaseAction]:
    with store.session() as s:
        return list(s.scalars(select(CaseAction).where(CaseAction.case_id == case_id)
                              .order_by(CaseAction.rev.desc()).limit(limit)))


def latest_for(store: Store, case_ids: list[str]) -> dict[str, CaseAction]:
    """사건 여러 개의 현재 조치(목록용)."""
    if not case_ids:
        return {}
    with store.session() as s:
        top = (select(CaseAction.case_id, func.max(CaseAction.rev).label("rev"))
               .where(CaseAction.case_id.in_(case_ids)).group_by(CaseAction.case_id).subquery())
        rows = s.scalars(select(CaseAction).join(top, (CaseAction.case_id == top.c.case_id) & (CaseAction.rev == top.c.rev)))
        return {a.case_id: a for a in rows}


def checks(store: Store, case_id: str, limit: int = 20) -> list[CaseCheck]:
    with store.session() as s:
        return list(s.scalars(select(CaseCheck).where(CaseCheck.case_id == case_id)
                              .order_by(CaseCheck.id.desc()).limit(limit)))


def request_check(store: Store, case_id: str, actor: str, *, at: datetime | None = None) -> CaseCheck:
    """재확인 대기 줄을 만든다(접속은 조사 컨테이너가). 끝나지 않은 재확인이 있거나 방금 했거나 대기가 많으면 ActionError.
    사건 줄을 잠그고 검사·접수하며, 한 사건에 대기 줄은 하나만이라는 것을 DB 제약(부분 유일 색인)으로도 막는다(Codex 지적)."""
    at = at or now()
    fresh = at - PENDING_TTL
    with _queue_lock, store.session() as s:
        c = s.get(Case, case_id, with_for_update=True)
        if c is None:
            raise LookupError(case_id)
        if c.status not in TERMINAL:
            raise ActionError("조사가 끝난 뒤에 재확인할 수 있습니다")
        last = s.scalar(select(CaseCheck).where(CaseCheck.case_id == case_id).order_by(CaseCheck.id.desc()).limit(1))
        if last is not None and last.state == "pending" and _aware(last.requested_at) > fresh:
            raise ActionError("재확인이 이미 진행 중입니다")
        if last is not None and _aware(last.requested_at) > at - MIN_GAP:
            raise ActionError("방금 재확인했습니다. 잠시 뒤 다시 시도하세요")
        pending = select(func.count()).select_from(CaseCheck).where(CaseCheck.state == "pending",
                                                                    CaseCheck.requested_at > fresh)
        mine = pending.where(CaseCheck.requested_by == actor[:64])
        if (s.scalar(pending) or 0) >= MAX_PENDING_TOTAL or (s.scalar(mine) or 0) >= MAX_PENDING_PER_ACTOR:
            raise ActionError("재확인 대기가 많습니다. 잠시 뒤 다시 시도하세요")
        for old in s.scalars(select(CaseCheck).where(CaseCheck.case_id == case_id, CaseCheck.state == "pending")):
            old.state = "expired"  # 오래된 대기 줄(위에서 결과를 기다리는 것은 거절했다)
        s.flush()
        ck = CaseCheck(case_id=case_id, state="pending", requested_by=actor[:64], requested_at=at)
        s.add(ck)
        try:
            s.commit()
        except IntegrityError:  # 같은 순간 다른 요청이 먼저 대기 줄을 만들었다
            s.rollback()
            raise ActionError("재확인이 이미 진행 중입니다") from None
        return ck


def _aware(t: datetime) -> datetime:
    """SQLite 는 시간대를 버린다: 시간대 없는 값은 UTC 로 본다."""
    from datetime import UTC

    return t if t.tzinfo else t.replace(tzinfo=UTC)


def clean_result(r: object) -> dict | None:
    """조사 컨테이너가 보낸 재확인 결과(믿지 않는 값)를 정해진 항목·길이로만 받는다. 모양이 틀리면 None."""
    if not isinstance(r, dict) or r.get("result") not in RESULTS:
        return None
    st = r.get("http_status")
    sec = r.get("seconds")
    return {"result": r["result"],
            "reason": r["reason"][:64] if isinstance(r.get("reason"), str) else None,
            "http_status": st if type(st) is int and 100 <= st <= 599 else None,
            "final_host": r["final_host"][:253].lower() if isinstance(r.get("final_host"), str) else None,
            "title": " ".join(r["title"].split())[:200] if isinstance(r.get("title"), str) else None,
            "seconds": float(sec) if isinstance(sec, (int, float)) and not isinstance(sec, bool) and 0 <= sec < 3600 else None}


def record_check(store: Store, case_id: str, check_id: object, result: object) -> tuple[CaseCheck, CaseAction | None] | None:
    """재확인 결과를 대기 줄에 채운다. 그 사건의 대기 중인 번호가 아니거나 모양이 틀리면 None(받지 않는다).
    차단·삭제를 확인한 사건이 다시 접속되면 '다시 나타남'을 기록해 함께 돌려준다."""
    r = clean_result(result)
    if r is None or type(check_id) is not int:
        return None
    with store.session() as s:
        ck = s.get(CaseCheck, check_id, with_for_update=True)
        if ck is None or ck.case_id != case_id or ck.state != "pending":
            return None
        for k, v in r.items():
            setattr(ck, k, v)
        ck.state, ck.done_at = "done", now()
        cur = _latest(s, case_id)
        added = None
        if r["result"] == "alive" and cur is not None and cur.state in CONFIRMED:
            added = CaseAction(case_id=case_id, rev=cur.rev + 1, state="reappeared", actor=SYSTEM_ACTOR, check_id=ck.id,
                               note=f"재확인에서 다시 접속됨({r['http_status'] or '-'} · {r['final_host'] or '-'})")
            s.add(added)
        try:
            s.commit()
        except IntegrityError:  # 같은 순간 담당자가 조치를 저장했다: 결과만 남기고 표시는 다음 재확인에 맡긴다
            s.rollback()
            ck = s.get(CaseCheck, check_id)
            if ck is None or ck.state != "pending":
                return None
            for k, v in r.items():
                setattr(ck, k, v)
            ck.state, ck.done_at = "done", now()
            s.commit()
            added = None
        return ck, added


def expire_pending(store: Store, at: datetime | None = None) -> int:
    """결과가 오지 않은 오래된 대기 줄을 만료한다. 반환: 만료한 수."""
    at = at or now()
    with store.session() as s:
        rows = list(s.scalars(select(CaseCheck).where(CaseCheck.state == "pending")))
        n = 0
        for ck in rows:
            if _aware(ck.requested_at) <= at - PENDING_TTL:
                ck.state = "expired"
                n += 1
        s.commit()
        return n


def due(store: Store, *, interval: timedelta, limit: int, at: datetime | None = None) -> list[tuple[str, str]]:
    """정기 재확인할 사건 (id, 신고 주소): 현재 조치가 추적 상태이고 interval 안에 재확인(대기 포함)이 없는 것. 오래된 것부터."""
    at = at or now()
    with store.session() as s:
        top = (select(CaseAction.case_id, func.max(CaseAction.rev).label("rev")).group_by(CaseAction.case_id).subquery())
        tracked = list(s.execute(select(Case.id, Case.url).join(top, top.c.case_id == Case.id)
                                 .join(CaseAction, (CaseAction.case_id == top.c.case_id) & (CaseAction.rev == top.c.rev))
                                 .where(CaseAction.state.in_(TRACKED)).order_by(Case.created_at)))
        out = []
        for cid, url in tracked:
            last = s.scalar(select(func.max(CaseCheck.requested_at)).where(CaseCheck.case_id == cid))
            if last is None or _aware(last) <= at - interval:
                out.append((cid, url))
                if len(out) >= limit:
                    break
        return out

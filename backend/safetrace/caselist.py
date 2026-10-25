"""사건 목록 화면용: 분류 폴더 건수와 폴더·검색·출처로 거른 목록 한 쪽을 DB 에서 바로 계산한다.

콘솔이 최근 사건 몇십 건만 받아 폴더 숫자를 세면 그보다 오래된 사건이 숫자·검색에서 빠진다. 그래서 폴더 기준을
SQL 로 옮겨 전체 사건을 센다. 기준은 콘솔이 쓰던 것과 같다(App.tsx 의 FOLDERS).

- 원래 결과가 나왔고 연관 사이트를 조사하는 중(phase=related, 상태 RUNNING)인 사건은 원래 결과 상태로 분류한다.
- 담당자 판정은 사건마다 가장 큰 판 번호의 것을 쓴다.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import and_, case, func, literal, or_, select
from sqlalchemy.sql.elements import ColumnElement

from .store import Case, CaseLink, CasePhase, Store, Verdict

FOLDERS = ("review", "running", "suspect", "decided", "unreachable", "all")
PAGE_MAX = 200
OFFSET_MAX = 100_000
QUERY_MAX = 200
LIVE_RUNNING_MAX = 50


def _latest_decision():
    """사건별 현재 판정(가장 큰 판 번호)의 결정."""
    top = select(Verdict.case_id, func.max(Verdict.rev).label("rev")).group_by(Verdict.case_id).subquery()
    return (select(Verdict.case_id.label("case_id"), Verdict.decision.label("decision"))
            .join(top, and_(Verdict.case_id == top.c.case_id, Verdict.rev == top.c.rev)).subquery())


@dataclass
class _Cols:
    related_running: ColumnElement
    eff: ColumnElement
    dec: ColumnElement
    threat: ColumnElement


def _cols(vd) -> _Cols:
    # NULL 비교가 NULL 이 되어 NOT 이 빠지지 않게 coalesce 로 참·거짓만 남긴다
    related_running = and_(func.coalesce(CasePhase.phase, "") == "related", Case.status == "RUNNING",
                           CasePhase.main_status.is_not(None))
    eff = case((related_running, CasePhase.main_status), else_=Case.status)
    return _Cols(related_running, eff, vd.c.decision, func.coalesce(Case.threat["threat"].as_string(), ""))


def folder_condition(folder: str, c: _Cols) -> ColumnElement:
    undecided_or_hold = or_(c.dec.is_(None), c.dec == "hold")
    if folder == "review":
        return and_(c.eff == "REVIEW_REQUIRED", undecided_or_hold)
    if folder == "running":
        return and_(Case.status.in_(("RUNNING", "QUEUED")), ~c.related_running)
    if folder == "suspect":
        return and_(c.eff == "COMPLETED", c.threat.not_in(("", "benign", "unknown")), c.dec.is_(None))
    if folder == "decided":
        return c.dec.in_(("threat", "benign"))
    if folder == "unreachable":
        return c.eff.in_(("UNREACHABLE", "BLOCKED", "FAILED"))
    return literal(True)


def _base(vd):
    return (select(Case).outerjoin(CasePhase, CasePhase.case_id == Case.id)
            .outerjoin(vd, vd.c.case_id == Case.id))


def counts(store: Store) -> dict[str, int]:
    """폴더마다 전체 사건 수(검색·출처와 관계없이, 콘솔이 쓰던 숫자와 같은 뜻)."""
    vd = _latest_decision()
    c = _cols(vd)
    cols = [func.coalesce(func.sum(case((folder_condition(f, c), 1), else_=0)), 0).label(f) for f in FOLDERS]
    q = (select(*cols).select_from(Case).outerjoin(CasePhase, CasePhase.case_id == Case.id)
         .outerjoin(vd, vd.c.case_id == Case.id))
    with store.session() as s:
        row = s.execute(q).one()
    return {f: int(row._mapping[f] or 0) for f in FOLDERS}


def page(store: Store, folder: str, query: str, source: str, offset: int, limit: int) -> tuple[list[Case], int]:
    """폴더·검색(주소에 포함, 대소문자 무시)·출처로 거른 사건 한 쪽과 그 조건의 전체 수. 최신 접수 순."""
    vd = _latest_decision()
    c = _cols(vd)
    conds = [folder_condition(folder, c)]
    if query:
        conds.append(func.lower(Case.url).contains(query.lower(), autoescape=True))
    if source:
        conds.append(Case.source == source)
    where = and_(*conds)
    with store.session() as s:
        total = s.scalar(select(func.count()).select_from(_base(vd).where(where).subquery())) or 0
        rows = s.scalars(_base(vd).where(where).order_by(Case.created_at.desc(), Case.id.desc())
                         .offset(offset).limit(limit)).all()
    return list(rows), int(total)


def live(store: Store) -> tuple[Case | None, Case | None]:
    """실시간 화면에 띄울 사건: 조사 중인 것(사람이 접수한 것 먼저), 없으면 가장 오래 기다린 대기 사건."""
    with store.session() as s:
        running = s.execute(select(Case, CaseLink.auto).outerjoin(CaseLink, CaseLink.child_id == Case.id)
                            .where(Case.status == "RUNNING").order_by(Case.created_at.desc())
                            .limit(LIVE_RUNNING_MAX)).all()
        if running:
            human = [r for r, auto in running if not auto and r.source != "feed"]
            return (human[0] if human else running[0][0]), None
        queued = s.scalars(select(Case).where(Case.status == "QUEUED").order_by(Case.created_at.asc()).limit(1)).first()
        return None, queued

"""상태 저장(PostgreSQL 운영 / SQLite 개발). 모든 쿼리는 ORM 파라미터 바인딩을 쓴다."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine,
                        select)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


def now() -> datetime:
    return datetime.now(UTC)


TERMINAL = frozenset({"COMPLETED", "REVIEW_REQUIRED", "FAILED", "UNREACHABLE", "BLOCKED"})
# 상태는 QUEUED → RUNNING → 종료 상태로만 간다. 끝난 사건의 상태는 다시 바뀌지 않는다(워커가 보낸 이벤트라도)
_NEXT_STATUS = {"QUEUED": {"RUNNING", *TERMINAL}, "RUNNING": {"RUNNING", *TERMINAL}}


class Base(DeclarativeBase):
    pass


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    url: Mapped[str] = mapped_column(String(2048))
    source: Mapped[str] = mapped_column(String(32), default="report")  # report | kisa | test
    status: Mapped[str] = mapped_column(String(24), default="QUEUED", index=True)
    finish_reason: Mapped[str | None] = mapped_column(String(64))
    final_url: Mapped[str | None] = mapped_column(String(2048))
    threat: Mapped[dict | None] = mapped_column(JSON)
    safebrowsing: Mapped[dict | None] = mapped_column(JSON)
    candidates: Mapped[list | None] = mapped_column(JSON)
    head_seq: Mapped[int | None] = mapped_column(Integer)
    head_hash: Mapped[str | None] = mapped_column(String(64))
    idempotency_key: Mapped[str | None] = mapped_column(String(64), unique=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    version: Mapped[int] = mapped_column(Integer, default=1)
    __mapper_args__ = {"version_id_col": version}  # 낙관적 잠금


class CaseEvent(Base):
    __tablename__ = "case_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class CasePhase(Base):
    """원래 결과가 나온 뒤 연관 사이트를 조사하는 중인 사건(related-sites PR 3). cases 표에 열을 보태지 않는다
    (Store 는 create_all 만 써서 기존 DB 에 반영되지 않는다). 원래 결과의 상태는 종료 상태가 이와 같아야 한다."""

    __tablename__ = "case_phase"
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), primary_key=True)
    phase: Mapped[str] = mapped_column(String(16))  # related
    main_status: Mapped[str] = mapped_column(String(24))  # 원래 결과의 상태(종료 상태 중 하나)
    main_reason: Mapped[str | None] = mapped_column(String(64))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class CaseLink(Base):
    """연관 후보로 만든 사건(자식)과 그 후보가 나온 사건(부모)의 연결(related-sites PR 4). 같은 부모의 같은 후보로는
    한 번만 만든다. target_host·auto 는 자동 생성(PR 4b)의 중복 확인·표시에 쓴다."""

    __tablename__ = "case_links"
    __table_args__ = (UniqueConstraint("parent_id", "candidate_url"),)
    child_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), primary_key=True)
    parent_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    candidate_url: Mapped[str] = mapped_column(String(2048))
    target_host: Mapped[str] = mapped_column(String(253), index=True)  # 하위 조사가 도착한 호스트(없으면 후보 호스트)
    auto: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    case_id: Mapped[str | None] = mapped_column(String(36))
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Verdict(Base):
    """담당자 판정. 고치지 않고 새 판(rev)을 쌓는다. 마지막 판이 현재 판정이다.
    (case_id, rev) 가 유일해서, 같은 판을 보고 동시에 저장하면 한쪽만 들어간다(낙관적 잠금)."""

    __tablename__ = "verdicts"
    __table_args__ = (UniqueConstraint("case_id", "rev"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    rev: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(16))  # threat | benign | hold
    threat: Mapped[str | None] = mapped_column(String(32))  # decision=threat 일 때 확정한 유형
    note: Mapped[str | None] = mapped_column(Text)
    reviewer: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    ai_threat: Mapped[str | None] = mapped_column(String(32))  # 판정 당시 AI 의견(비교용)
    head_seq: Mapped[int | None] = mapped_column(Integer)  # 판정 당시 증거 체인 끝
    head_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class User(Base):
    """담당자 계정. 비밀번호는 Argon2id 해시로만 저장한다(accounts.py)."""

    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # viewer | investigator | reviewer | admin
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuthSession(Base):
    """로그인 세션. 토큰 원문은 저장하지 않고 SHA-256 으로만 찾는다."""

    __tablename__ = "auth_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Store:
    def __init__(self, url: str):
        if url.startswith("sqlite:///"):
            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
            self.engine = create_engine(url, connect_args={"check_same_thread": False})
        else:
            self.engine = create_engine(url, pool_pre_ping=True)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(self.engine, expire_on_commit=False)

    def session(self) -> Session:
        return self.Session()

    def add_event(self, case_id: str, payload: dict) -> bool:
        """이벤트를 남긴다. 상태 이벤트가 허용된 전이가 아니면(끝난 사건, 모르는 상태) 남기지 않고 False.

        원래 결과 이벤트(phase=related)는 조사 중(RUNNING)이고 위협 판단과 원래 결과의 종료 상태가 있을 때만 받는다."""
        with self.session() as s, s.begin():
            if payload.get("type") == "status":
                c = s.get(Case, case_id, with_for_update=True)
                if c is None or payload.get("status") not in _NEXT_STATUS.get(c.status, ()):
                    return False
                if "phase" in payload:
                    main = payload.get("main") if isinstance(payload.get("main"), dict) else {}
                    reason = main.get("reason")
                    if (payload["phase"] != "related" or payload["status"] != "RUNNING"
                            or not isinstance(payload.get("threat"), dict) or main.get("status") not in TERMINAL
                            or not (reason is None or isinstance(reason, str))):
                        return False
                    ph = s.get(CasePhase, case_id) or CasePhase(case_id=case_id)
                    ph.phase, ph.main_status, ph.at = "related", main["status"], now()
                    ph.main_reason = reason[:64] if reason else None
                    s.add(ph)
                c.status = payload["status"]
                c.finish_reason = payload.get("reason")
                if payload.get("threat") is not None:
                    c.threat = payload["threat"]
                head = payload.get("head") or {}
                if "seq" in head:
                    c.head_seq, c.head_hash = head["seq"], head["hash"]
                for k in ("final_url", "candidates", "safebrowsing"):
                    if k in payload:
                        setattr(c, k, payload[k])
            s.add(CaseEvent(case_id=case_id, payload=payload))
        return True

    def phases_for(self, case_ids: list[str]) -> dict[str, CasePhase]:
        """사건 여러 개의 원래 결과 표시를 한 번에 가져온다(목록용)."""
        if not case_ids:
            return {}
        with self.session() as s:
            return {p.case_id: p for p in s.scalars(select(CasePhase).where(CasePhase.case_id.in_(case_ids)))}

    def parents_for(self, case_ids: list[str]) -> dict[str, tuple[CaseLink, str]]:
        """자식 사건 id → (연결, 부모 사건의 신고 URL). 목록용."""
        if not case_ids:
            return {}
        with self.session() as s:
            rows = s.execute(select(CaseLink, Case.url).join(Case, Case.id == CaseLink.parent_id)
                             .where(CaseLink.child_id.in_(case_ids)))
            return {link.child_id: (link, url) for link, url in rows}

    def children_of(self, parent_id: str, limit: int = 50) -> list[tuple[CaseLink, Case]]:
        with self.session() as s:
            rows = s.execute(select(CaseLink, Case).join(Case, Case.id == CaseLink.child_id)
                             .where(CaseLink.parent_id == parent_id).order_by(CaseLink.created_at).limit(limit))
            return [(link, c) for link, c in rows]

    def set_head(self, case_id: str, seq: int, hash_: str) -> None:
        """head 가 비어 있는 사건에 서명 서비스의 head 를 채운다(닫기에 실패했다가 나중에 다시 닫아 받은 값)."""
        with self.session() as s, s.begin():
            c = s.get(Case, case_id, with_for_update=True)
            if c is not None and c.head_seq is None:
                c.head_seq, c.head_hash = seq, hash_

    def events_after(self, case_id: str, after_id: int, limit: int = 200) -> list[CaseEvent]:
        with self.session() as s:
            q = (select(CaseEvent).where(CaseEvent.case_id == case_id, CaseEvent.id > after_id)
                 .order_by(CaseEvent.id).limit(limit))
            return list(s.scalars(q))

    def audit(self, actor: str, action: str, case_id: str | None = None, detail: str | None = None) -> None:
        with self.session() as s, s.begin():
            s.add(AuditLog(actor=actor, action=action, case_id=case_id, detail=(detail or "")[:2000]))

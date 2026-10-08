"""상태 저장(PostgreSQL 운영 / SQLite 개발). 모든 쿼리는 ORM 파라미터 바인딩을 쓴다."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


def now() -> datetime:
    return datetime.now(UTC)


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


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    case_id: Mapped[str | None] = mapped_column(String(36))
    detail: Mapped[str | None] = mapped_column(Text)
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

    def add_event(self, case_id: str, payload: dict) -> None:
        with self.session() as s, s.begin():
            s.add(CaseEvent(case_id=case_id, payload=payload))
            if payload.get("type") == "status":
                c = s.get(Case, case_id)
                if c:
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

    def events_after(self, case_id: str, after_id: int, limit: int = 200) -> list[CaseEvent]:
        with self.session() as s:
            q = (select(CaseEvent).where(CaseEvent.case_id == case_id, CaseEvent.id > after_id)
                 .order_by(CaseEvent.id).limit(limit))
            return list(s.scalars(q))

    def audit(self, actor: str, action: str, case_id: str | None = None, detail: str | None = None) -> None:
        with self.session() as s, s.begin():
            s.add(AuditLog(actor=actor, action=action, case_id=case_id, detail=(detail or "")[:2000]))

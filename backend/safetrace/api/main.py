"""SafeTrace API: 사건 접수·조회, 실시간 진행(SSE), 증거 파일·무결성 검증.

실행: uvicorn safetrace.api.main:app --port 8000
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..config import get_settings
from ..evidence import Head, Signer, verify_case
from ..masking import mask_secrets
from ..netguard import BlockedURL, parse_url
from ..store import Case, Store

log = logging.getLogger("safetrace.api")
settings = get_settings()
store = Store(settings.database_url)

ROLES = {"viewer": 0, "investigator": 1, "reviewer": 2, "admin": 3}
_FILE_NAME = re.compile(r"^[a-z0-9_\-]{1,64}\.(png|webm)$")
_CASE_ID = re.compile(r"^[a-f0-9\-]{36}$")
TERMINAL = {"COMPLETED", "REVIEW_REQUIRED", "FAILED", "UNREACHABLE", "BLOCKED"}


def _token_table() -> dict[str, tuple[str, str]]:
    """토큰 원문은 메모리에도 해시로만 둔다. 반환: sha256(token) -> (role, 주체 이름)"""
    out = {}
    for i, entry in enumerate(settings.api_tokens):
        token, _, role = entry.rpartition(":")
        if token and role in ROLES and len(token) >= 24:
            out[hashlib.sha256(token.encode()).hexdigest()] = (role, f"{role}-{i}")
    return out


TOKENS = _token_table()


class Principal(BaseModel):
    name: str
    role: str


def auth(authorization: Annotated[str, Header()] = "") -> Principal:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "unauthorized", headers={"WWW-Authenticate": "Bearer"})
    digest = hashlib.sha256(token.encode()).hexdigest()
    for known, (role, name) in TOKENS.items():
        if hmac.compare_digest(known, digest):
            return Principal(name=name, role=role)
    raise HTTPException(401, "unauthorized", headers={"WWW-Authenticate": "Bearer"})


def need(role: str):
    def dep(p: Annotated[Principal, Depends(auth)]) -> Principal:
        if ROLES[p.role] < ROLES[role]:
            raise HTTPException(403, "forbidden")
        return p

    return dep


# ── 작업 실행: Redis(운영) 또는 스레드(개발) ─────────────────────
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="agent")
_redis = None
if settings.redis_url:
    import redis as _redis_mod

    _redis = _redis_mod.Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=30)  # XREADGROUP block(5초)보다 길게


def enqueue(case_id: str, url: str):
    if _redis is not None:
        _redis.xadd("st:jobs", {"case_id": case_id, "url": url})
        return

    from ..agent.runner import investigate  # 개발 모드에서만 Playwright 로드

    def job():
        try:
            investigate(case_id, url, settings, lambda ev: store.add_event(case_id, ev))
        except Exception as e:
            log.exception("inline investigation failed")
            store.add_event(case_id, {"type": "status", "status": "FAILED", "reason": f"error:{type(e).__name__}"})

    _executor.submit(job)


def _consume_events_forever():
    """워커가 Redis 로 보낸 이벤트를 DB 에 반영한다(워커는 DB 에 직접 접근하지 않음)."""
    group = "api"
    try:
        _redis.xgroup_create("st:events", group, id="0", mkstream=True)
    except Exception:
        pass
    while True:
        try:
            resp = _redis.xreadgroup(group, "api-1", {"st:events": ">"}, count=50, block=5000)
            for _, msgs in resp or []:
                for mid, f in msgs:
                    cid = f.get("case_id", "")
                    if _CASE_ID.match(cid):
                        store.add_event(cid, json.loads(f.get("payload", "{}")))
                    _redis.xack("st:events", group, mid)
        except Exception:
            log.exception("event consumer error")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if _redis is not None:
        threading.Thread(target=_consume_events_forever, daemon=True).start()
    yield


app = FastAPI(title="SafeTrace API", docs_url=None, redoc_url=None, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST"],
                   allow_headers=["Authorization", "Content-Type", "Idempotency-Key"], allow_credentials=False)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    return resp


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    log.error("unhandled %s on %s: %s", type(exc).__name__, request.url.path, mask_secrets(str(exc))[:300])
    return JSONResponse({"detail": "internal error"}, status_code=500)


# ── 스키마 ─────────────────────────────────────────────
class CaseCreate(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    source: str = Field(default="report", pattern=r"^(report|kisa|test)$")


class CaseOut(BaseModel):
    id: str
    url: str
    source: str
    status: str
    finish_reason: str | None
    final_url: str | None
    threat: dict | None
    safebrowsing: dict | None
    candidates: list | None
    head_seq: int | None
    created_at: str

    @classmethod
    def of(cls, c: Case) -> CaseOut:
        return cls(id=c.id, url=c.url, source=c.source, status=c.status, finish_reason=c.finish_reason,
                   final_url=c.final_url, threat=c.threat, safebrowsing=c.safebrowsing, candidates=c.candidates,
                   head_seq=c.head_seq, created_at=c.created_at.isoformat())


def _get_case(case_id: str) -> Case:
    if not _CASE_ID.match(case_id):
        raise HTTPException(404, "not found")
    with store.session() as s:
        c = s.get(Case, case_id)
    if not c:
        raise HTTPException(404, "not found")
    return c


# ── 엔드포인트 ─────────────────────────────────────────
@app.get("/api/healthz")
def healthz():
    return {"ok": True}


@app.post("/api/cases", response_model=CaseOut, status_code=201)
def create_case(body: CaseCreate, p: Annotated[Principal, Depends(need("investigator"))],
                idempotency_key: Annotated[str | None, Header(max_length=64)] = None):
    try:
        parse_url(body.url, settings.allowed_ports)  # 형식 검사. IP 검사는 에이전트가 접속 시점에 수행
    except BlockedURL as e:
        raise HTTPException(422, f"url rejected: {e.reason}") from None
    key = None
    if idempotency_key:
        key = hashlib.sha256(f"{p.name}:{idempotency_key}".encode()).hexdigest()
    with store.session() as s:
        if key:
            existing = s.scalar(select(Case).where(Case.idempotency_key == key))
            if existing:
                return CaseOut.of(existing)
        c = Case(url=body.url.strip(), source=body.source, created_by=p.name, idempotency_key=key)
        s.add(c)
        try:
            s.commit()
        except IntegrityError:
            s.rollback()
            raise HTTPException(409, "duplicate request") from None
    store.audit(p.name, "case.create", c.id, f"source={body.source}")
    enqueue(c.id, c.url)
    return CaseOut.of(c)


@app.get("/api/cases", response_model=list[CaseOut])
def list_cases(p: Annotated[Principal, Depends(need("viewer"))], limit: int = Query(50, ge=1, le=200)):
    with store.session() as s:
        rows = s.scalars(select(Case).order_by(Case.created_at.desc()).limit(limit)).all()
    return [CaseOut.of(c) for c in rows]


@app.get("/api/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: str, p: Annotated[Principal, Depends(need("viewer"))]):
    return CaseOut.of(_get_case(case_id))


@app.get("/api/cases/{case_id}/events")
async def case_events(case_id: str, p: Annotated[Principal, Depends(need("viewer"))],
                      after: int = Query(0, ge=0)):
    """SSE: 기존 이벤트를 먼저 보내고, 이후 새 이벤트를 이어서 보낸다. 종료 상태면 스트림을 닫는다."""
    _get_case(case_id)

    async def gen():
        last = after
        idle = 0
        while True:
            evs = await asyncio.to_thread(store.events_after, case_id, last)
            for e in evs:
                last = e.id
                yield f"id: {e.id}\ndata: {json.dumps(e.payload, ensure_ascii=False)}\n\n"
                if e.payload.get("type") == "status" and e.payload.get("status") in TERMINAL:
                    return
            idle = 0 if evs else idle + 1
            if idle and idle % 30 == 0:
                yield ": keepalive\n\n"
            if idle > 1800:
                return
            await asyncio.sleep(0.5)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


@app.get("/api/cases/{case_id}/files/{name}")
def case_file(case_id: str, name: str, p: Annotated[Principal, Depends(need("viewer"))]):
    _get_case(case_id)
    if not _FILE_NAME.match(name):
        raise HTTPException(404, "not found")
    path = settings.evidence_dir / case_id / "files" / name
    if not path.is_file():
        raise HTTPException(404, "not found")
    media = "image/png" if name.endswith(".png") else "video/webm"
    return FileResponse(path, media_type=media, headers={"Content-Security-Policy": "sandbox; default-src 'none'"})


@app.post("/api/cases/{case_id}/verify")
def verify(case_id: str, p: Annotated[Principal, Depends(need("viewer"))]):
    c = _get_case(case_id)
    head = Head(c.head_seq, c.head_hash) if c.head_seq is not None else None
    signer = Signer(settings.evidence_hmac_key.get_secret_value().encode(), settings.evidence_key_id)
    res = verify_case(settings.evidence_dir, case_id, signer, head)
    store.audit(p.name, "evidence.verify", case_id, "ok" if res.ok else ";".join(res.errors[:5]))
    return res.as_dict()

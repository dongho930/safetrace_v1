"""SafeTrace API: 로그인·계정, 사건 접수·조회, 실시간 진행(SSE), 증거 파일·무결성 검증, 담당자 판정, 검토 패키지.

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
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .. import accounts, package, report, verdicts
from ..accounts import ROLES, AccountError
from ..config import get_settings
from ..evidence import Head, Signer, VerifyResult, verify_case
from ..live import CHANNEL as LIVE_CHANNEL
from ..live import END as LIVE_END
from ..live import WATCH_KEY as LIVE_WATCH_KEY
from ..live import WATCH_TTL_S as LIVE_WATCH_TTL_S
from ..live import LocalLive
from ..masking import mask_secrets
from ..netguard import BlockedURL, parse_url
from ..preview import preview_image
from ..signer.client import ChainAdmin, SignerError
from ..store import TERMINAL, AuditLog, Case, Store, Verdict

log = logging.getLogger("safetrace.api")
settings = get_settings()
store = Store(settings.database_url)

_FILE_NAME = re.compile(r"^[a-z0-9_\-]{1,64}\.(png|webm)$")
_CASE_ID = re.compile(r"^[a-f0-9\-]{36}$")


def _token_table() -> dict[str, tuple[str, str]]:
    """자동화(서비스) 토큰. 원문은 메모리에도 해시로만 둔다. 반환: sha256(token) -> (role, 주체 이름)
    사람은 계정으로 로그인하고(accounts.py), 이 토큰은 스크립트·연동용이다. 서비스 주체는 계정 관리를 할 수 없다."""
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
    kind: str = "user"  # user(담당자 계정) | service(자동화 토큰)
    user_id: int | None = None


def _principal(token: str) -> Principal | None:
    if not token:
        return None
    u = accounts.resolve(store, token)
    if u is not None:
        return Principal(name=u.username, role=u.role, kind="user", user_id=u.user_id)
    digest = hashlib.sha256(token.encode()).hexdigest()
    for known, (role, name) in TOKENS.items():
        if hmac.compare_digest(known, digest):
            return Principal(name=name, role=role, kind="service")
    return None


def auth(authorization: Annotated[str, Header()] = "") -> Principal:
    scheme, _, token = authorization.partition(" ")
    p = _principal(token) if scheme.lower() == "bearer" else None
    if p is None:
        raise HTTPException(401, "unauthorized", headers={"WWW-Authenticate": "Bearer"})
    return p


def need(role: str, human: bool = False):
    """역할 검사. human=True 면 담당자 계정만 허용한다(자동화 토큰은 역할과 관계없이 거부)."""

    def dep(p: Annotated[Principal, Depends(auth)]) -> Principal:
        if ROLES[p.role] < ROLES[role] or (human and p.kind != "user"):
            raise HTTPException(403, "forbidden")
        return p

    return dep


# ── 작업 실행: Redis(운영) 또는 스레드(개발) ─────────────────────
_live_local = LocalLive()  # 개발 모드: 같은 프로세스의 에이전트 스레드 → WebSocket
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="agent")
_redis = None
if settings.redis_url:
    import redis as _redis_mod

    _redis = _redis_mod.Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=30)  # XREADGROUP block(5초)보다 길게


# 서명 서비스(운영): 접수 때 체인을 열고 조사가 끝나면 닫는다. 비어 있으면 개발 모드(같은 프로세스에서 서명)
_chains = ChainAdmin(settings.signer_url, settings.signer_api_token.get_secret_value()) if settings.signer_url else None


_CLOSE_RETRY_S = (0.5, 1.0)  # 닫기가 실패하면 이만큼 기다렸다가 다시 시도한다(잠깐 끊긴 경우)


def _close_chain(case_id: str) -> dict | None:
    """체인을 닫고 서명 서비스의 head 를 받는다. 끝내 실패하면 None(감사 로그를 남긴다)."""
    for wait in (*_CLOSE_RETRY_S, None):
        try:
            return _chains.close(case_id)
        except SignerError as e:
            err = e
        if wait is not None:
            time.sleep(wait)
    store.audit("system", "evidence.close_failed", case_id, str(err))
    return None


_CAND_STR = {"url": 2048, "final_url": 2048, "host": 253, "source": 8, "status": 24, "reason": 64, "threat": 32}


def _clean_candidates(v) -> list[dict]:
    """워커가 보낸 연관 후보 목록(믿지 않는 값)을 정해진 항목·길이·개수로만 받는다(화면에는 글자로만 표시)."""
    out = []
    for c in v if isinstance(v, list) else []:
        if not isinstance(c, dict) or not isinstance(c.get("url"), str):
            continue
        d = {k: c[k][:n] for k, n in _CAND_STR.items() if isinstance(c.get(k), str)}
        for k in ("reputation_match", "reputation_unchecked", "hold"):
            if isinstance(c.get(k), bool):
                d[k] = c[k]
        if isinstance(c.get("sub"), int) and 0 < c["sub"] <= 10:
            d["sub"] = c["sub"]
        if isinstance(c.get("probability"), (int, float)) and 0 <= c["probability"] <= 1:
            d["probability"] = float(c["probability"])
        out.append(d)
        if len(out) >= 20:
            break
    return out


def record_event(case_id: str, payload: dict) -> None:
    """에이전트 이벤트를 DB 에 반영한다. 조사가 끝나면 체인을 닫고 서명 서비스의 head 를 쓴다.

    운영(서명 서비스)에서는 에이전트가 보고한 head 를 어떤 상태 이벤트에서도 받지 않는다: 에이전트가 뚫려 체인 끝을
    잘라 내도 서명 서비스의 head 와 어긋나 검증에서 드러난다. 상태 전이는 store 가 검사한다(끝난 사건·모르는 상태는 거절).
    닫기에 실패하면 head 를 비워 두고, 검증·패키지에서 다시 닫아 받기 전까지 무결성을 성공으로 표시하지 않는다.
    """
    if payload.get("type") == "status" and "candidates" in payload:
        payload = {**payload, "candidates": _clean_candidates(payload["candidates"])}
    if _chains is not None and payload.get("type") == "status":
        reported = payload.get("head")
        payload = {k: v for k, v in payload.items() if k != "head"}
        if payload.get("status") in TERMINAL:
            h = _close_chain(case_id)
            if h is not None:
                payload["head"] = {"seq": h["seq"], "hash": h["hash"]}
                if isinstance(reported, dict) and (reported.get("seq"), reported.get("hash")) != (h["seq"], h["hash"]):
                    store.audit("system", "evidence.head_mismatch", case_id,
                                f"agent={str(reported.get('seq'))[:12]} signer={h['seq']}")
    if not store.add_event(case_id, payload):
        store.audit("system", "event.rejected", case_id, f"status={str(payload.get('status'))[:24]}")


def enqueue(case_id: str, url: str):
    if _chains is not None:
        try:
            _chains.open(case_id)
        except SignerError as e:
            log.error("signer open failed: %s", e)
            store.add_event(case_id, {"type": "status", "status": "FAILED", "reason": "error:signer_unavailable"})
            return
    if _redis is not None:
        _redis.xadd("st:jobs", {"case_id": case_id, "url": url})
        return

    from ..agent.runner import investigate  # 개발 모드에서만 Playwright 로드

    def job():
        try:
            investigate(case_id, url, settings, lambda ev: record_event(case_id, ev), live=_live_local)
        except Exception as e:
            log.exception("inline investigation failed")
            record_event(case_id, {"type": "status", "status": "FAILED", "reason": f"error:{type(e).__name__}"})

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
                        record_event(cid, json.loads(f.get("payload", "{}")))
                    _redis.xack("st:events", group, mid)
        except Exception:
            log.exception("event consumer error")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if _redis is not None:
        threading.Thread(target=_consume_events_forever, daemon=True).start()
    yield


app = FastAPI(title="SafeTrace API", docs_url=None, redoc_url=None, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST", "PATCH"],
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


class VerdictOut(BaseModel):
    rev: int
    decision: str
    threat: str | None
    note: str | None
    reviewer: str
    ai_threat: str | None
    head_seq: int | None
    created_at: str

    @classmethod
    def of(cls, v: Verdict) -> VerdictOut:
        return cls(rev=v.rev, decision=v.decision, threat=v.threat, note=v.note, reviewer=v.reviewer,
                   ai_threat=v.ai_threat, head_seq=v.head_seq, created_at=v.created_at.isoformat())


class VerdictIn(BaseModel):
    rev: int = Field(ge=0, description="보고 있던 판 번호(판정이 없었으면 0)")
    decision: str = Field(pattern=r"^(threat|benign|hold)$")
    threat: str | None = Field(default=None, pattern=r"^(phishing|scam|illegal_gambling|malware)$")
    note: str | None = Field(default=None, max_length=verdicts.NOTE_MAX * 2)


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
    verdict: VerdictOut | None = None  # 담당자의 현재 판정

    @classmethod
    def of(cls, c: Case, v: Verdict | None = None) -> CaseOut:
        return cls(id=c.id, url=c.url, source=c.source, status=c.status, finish_reason=c.finish_reason,
                   final_url=c.final_url, threat=c.threat, safebrowsing=c.safebrowsing, candidates=c.candidates,
                   head_seq=c.head_seq, created_at=c.created_at.isoformat(), verdict=VerdictOut.of(v) if v else None)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=accounts.PASSWORD_MAX)


class Me(BaseModel):
    name: str
    role: str
    kind: str


class LoginOut(BaseModel):
    token: str
    expires_at: str
    user: Me


class PasswordChange(BaseModel):
    current: str = Field(min_length=1, max_length=accounts.PASSWORD_MAX)
    new: str = Field(min_length=1, max_length=accounts.PASSWORD_MAX)


class UserOut(BaseModel):
    username: str
    role: str
    active: bool
    locked: bool
    created_at: str

    @classmethod
    def of(cls, u) -> UserOut:
        return cls(username=u.username, role=u.role, active=u.active, locked=accounts.is_locked(u),
                   created_at=u.created_at.isoformat())


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=accounts.PASSWORD_MAX)
    role: str = Field(pattern=r"^(viewer|investigator|reviewer|admin)$")


class UserPatch(BaseModel):
    role: str | None = Field(default=None, pattern=r"^(viewer|investigator|reviewer|admin)$")
    active: bool | None = None
    password: str | None = Field(default=None, min_length=1, max_length=accounts.PASSWORD_MAX)
    unlock: bool = False


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


# ── 로그인·계정 ─────────────────────────────────────────
def _safe_name(username: str) -> str:
    # 감사로그에는 형식에 맞는 아이디만 그대로 남긴다(공격자가 넣은 임의 문자열이 로그에 섞이지 않게)
    return username if accounts.USERNAME.match(username) else "-"


@app.post("/api/auth/login", response_model=LoginOut)
def login(body: LoginIn):
    res = accounts.login(store, body.username, body.password)
    if res is None:
        store.audit(_safe_name(body.username), "auth.login_failed",
                    detail=accounts.login_failure_reason(store, body.username))
        raise HTTPException(401, "아이디 또는 비밀번호가 올바르지 않습니다")
    token, u, expires = res
    store.audit(u.username, "auth.login")
    return LoginOut(token=token, expires_at=expires.isoformat(), user=Me(name=u.username, role=u.role, kind="user"))


@app.post("/api/auth/logout", status_code=204)
def logout(p: Annotated[Principal, Depends(auth)], authorization: Annotated[str, Header()] = ""):
    if p.kind == "user":
        accounts.logout(store, authorization.partition(" ")[2])
        store.audit(p.name, "auth.logout")
    return Response(status_code=204)


@app.get("/api/auth/me", response_model=Me)
def me(p: Annotated[Principal, Depends(auth)]):
    return Me(name=p.name, role=p.role, kind=p.kind)


@app.post("/api/auth/password", status_code=204)
def change_password(body: PasswordChange, p: Annotated[Principal, Depends(need("viewer", human=True))]):
    try:
        ok = accounts.change_password(store, p.user_id, body.current, body.new)
    except AccountError as e:
        raise HTTPException(422, str(e)) from None
    if not ok:
        store.audit(p.name, "auth.password_change_failed")
        raise HTTPException(403, "현재 비밀번호가 올바르지 않습니다")
    store.audit(p.name, "auth.password_change")
    return Response(status_code=204)


@app.get("/api/users", response_model=list[UserOut])
def list_users(p: Annotated[Principal, Depends(need("admin", human=True))]):
    return [UserOut.of(u) for u in accounts.list_users(store)]


@app.post("/api/users", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, p: Annotated[Principal, Depends(need("admin", human=True))]):
    try:
        u = accounts.create_user(store, body.username, body.password, body.role)
    except AccountError as e:
        raise HTTPException(422, str(e)) from None
    store.audit(p.name, "user.create", detail=f"user={u.username} role={u.role}")
    return UserOut.of(u)


@app.patch("/api/users/{username}", response_model=UserOut)
def patch_user(username: str, body: UserPatch, p: Annotated[Principal, Depends(need("admin", human=True))]):
    if not accounts.USERNAME.match(username):
        raise HTTPException(404, "not found")
    if username == p.name and (body.role not in (None, "admin") or body.active is False):
        raise HTTPException(422, "자기 계정의 관리자 권한은 내리거나 끌 수 없습니다")
    try:
        u = accounts.update_user(store, username, role=body.role, active=body.active, password=body.password,
                                 unlock=body.unlock)
    except AccountError as e:
        raise HTTPException(422, str(e)) from None
    except LookupError:
        raise HTTPException(404, "not found") from None
    changes = [f"role={body.role}"] if body.role else []
    changes += [f"active={body.active}"] if body.active is not None else []
    changes += ["password_reset"] if body.password is not None else []
    changes += ["unlock"] if body.unlock else []
    store.audit(p.name, "user.update", detail=f"user={username} " + " ".join(changes))
    return UserOut.of(u)


# ── 사건 ─────────────────────────────────────────────
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
    latest = verdicts.latest_for(store, [c.id for c in rows])
    return [CaseOut.of(c, latest.get(c.id)) for c in rows]


@app.get("/api/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: str, p: Annotated[Principal, Depends(need("viewer"))]):
    c = _get_case(case_id)
    return CaseOut.of(c, verdicts.latest_for(store, [c.id]).get(c.id))


# ── 담당자 판정 ─────────────────────────────────────────
@app.get("/api/cases/{case_id}/verdicts", response_model=list[VerdictOut])
def list_verdicts(case_id: str, p: Annotated[Principal, Depends(need("viewer"))]):
    _get_case(case_id)
    return [VerdictOut.of(v) for v in verdicts.history(store, case_id)]


@app.post("/api/cases/{case_id}/verdicts", response_model=VerdictOut, status_code=201)
def save_verdict(case_id: str, body: VerdictIn, p: Annotated[Principal, Depends(need("reviewer", human=True))]):
    """판정 저장. 검토관 이상의 담당자 계정만 할 수 있다(자동화 토큰·AI 는 확정 불가)."""
    _evidence_head(_get_case(case_id))  # 판정에 묶을 head 가 비어 있으면(닫기 실패) 먼저 받아 둔다
    try:
        v = verdicts.save(store, case_id, expected_rev=body.rev, decision=body.decision, threat=body.threat,
                          note=body.note, reviewer=p.name, user_id=p.user_id)
    except verdicts.VerdictError as e:
        raise HTTPException(422, str(e)) from None
    except verdicts.VerdictConflict as e:
        cur = e.current
        store.audit(p.name, "verdict.conflict", case_id, f"seen={body.rev} current={cur.rev if cur else 0}")
        who = f"{cur.reviewer} 님이 " if cur else ""
        raise HTTPException(409, f"그사이 {who}판정을 바꿨습니다. 최신 판정을 확인한 뒤 다시 저장하세요") from None
    except LookupError:
        raise HTTPException(404, "not found") from None
    detail = f"rev={v.rev} decision={v.decision}" + (f" threat={v.threat}" if v.threat else "")
    store.audit(p.name, "verdict.save", case_id, f"{detail} ai={v.ai_threat or '-'} head={v.head_seq}")
    return VerdictOut.of(v)


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
def case_file(case_id: str, name: str, p: Annotated[Principal, Depends(need("viewer"))], preview: bool = False):
    _get_case(case_id)
    if not _FILE_NAME.match(name):
        raise HTTPException(404, "not found")
    path = settings.evidence_dir / case_id / "files" / name
    if not path.is_file():
        raise HTTPException(404, "not found")
    # 증거 파일은 한 번 쓰이면 바뀌지 않는다(바뀌면 검증 실패) → 브라우저가 캐시해도 된다(인증 필요하므로 private)
    headers = {"Content-Security-Policy": "sandbox; default-src 'none'", "Cache-Control": "private, max-age=3600"}
    if preview and name.endswith(".png"):
        # 화면 표시용 JPEG(증거 아님). 원본은 preview 없이 요청
        data, media = preview_image(path)
        return Response(data, media_type=media, headers=headers)
    media = "image/png" if name.endswith(".png") else "video/webm"
    return FileResponse(path, media_type=media, headers=headers)


@app.websocket("/api/cases/{case_id}/live")
async def case_live(ws: WebSocket, case_id: str):
    """실시간 화면(보기용, 증거 아님). 브라우저 WebSocket 은 인증 헤더를 못 붙이고 주소의 토큰은 접속 기록에 남으므로,
    연결 뒤 첫 메시지 {"token": ...} 로 인증한다. 이후 서버는 JPEG 프레임(바이너리)만 보낸다."""
    await ws.accept()
    try:
        msg = await asyncio.wait_for(ws.receive_json(), 5)
        p = _principal(str(msg.get("token", ""))) if isinstance(msg, dict) else None
    except (TimeoutError, ValueError, WebSocketDisconnect):
        p = None
    if p is None or ROLES[p.role] < ROLES["viewer"]:
        await ws.close(code=4401)
        return
    try:
        c = _get_case(case_id)
    except HTTPException:
        await ws.close(code=4404)
        return
    if c.status in TERMINAL:  # 이미 끝난 사건은 라이브가 없다(증거 스크린샷·녹화로 본다)
        await ws.close(code=1000)
        return
    store.audit(p.name, "live.watch", case_id)

    def finished() -> bool:
        try:
            return _get_case(case_id).status in TERMINAL
        except HTTPException:
            return True

    async def until_client_leaves():
        try:
            while True:
                await ws.receive()
        except (WebSocketDisconnect, RuntimeError):
            return

    async def forward_local():
        async with _live_local.subscribe(case_id) as q:
            while True:
                try:
                    frame = await asyncio.wait_for(q.get(), 5)
                except TimeoutError:
                    if await asyncio.to_thread(finished):  # 끝 신호 없이 끝난 경우 대비
                        return
                    continue
                if frame == LIVE_END:
                    return
                await ws.send_bytes(frame)

    async def forward_redis():
        import redis.asyncio as aioredis  # noqa: PLC0415

        r = aioredis.from_url(settings.redis_url)
        ps = r.pubsub()
        await ps.subscribe(LIVE_CHANNEL.format(case_id))

        async def keep_watching():  # 에이전트는 이 표시가 있을 때만 프레임을 보낸다
            while True:
                await r.set(LIVE_WATCH_KEY.format(case_id), "1", ex=LIVE_WATCH_TTL_S)
                await asyncio.sleep(2)

        watch = asyncio.create_task(keep_watching())
        try:
            while True:
                m = await ps.get_message(ignore_subscribe_messages=True, timeout=5)
                if m is None:
                    if await asyncio.to_thread(finished):  # 끝 신호 없이 끝난 경우 대비
                        return
                    continue
                if m["data"] == LIVE_END:
                    return
                await ws.send_bytes(m["data"])
        finally:
            watch.cancel()
            await ps.aclose()
            await r.aclose()

    leave = asyncio.create_task(until_client_leaves())
    fwd = asyncio.create_task(forward_redis() if _redis is not None else forward_local())
    done, pending = await asyncio.wait({leave, fwd}, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    try:
        await ws.close()
    except RuntimeError:
        pass


def _evidence_head(c: Case) -> Head | None:
    """사건의 증거 체인 끝(서명 서비스가 정한 값). 끝난 사건인데 비어 있으면(닫기 실패) 다시 닫아 받아 둔다."""
    if c.head_seq is not None:
        return Head(c.head_seq, c.head_hash)
    if _chains is None or c.status not in TERMINAL:
        return None
    try:
        h = _chains.close(c.id)
    except SignerError:
        return None
    store.set_head(c.id, h["seq"], h["hash"])
    store.audit("system", "evidence.head_recovered", c.id, f"seq={h['seq']}")
    c.head_seq, c.head_hash = h["seq"], h["hash"]
    return Head(h["seq"], h["hash"])


def _verify_case(c: Case, signer: Signer, text: str | None = None) -> VerifyResult:
    """끝난 사건은 체인 끝을 대조할 head 가 있어야 성공이다(없으면 끝부분을 잘라 내도 알 수 없다).
    text: 패키지·보고서를 만들 체인 스냅숏. 검증한 내용 그대로 쓰도록 한 번만 읽어 넘긴다."""
    head = _evidence_head(c)
    res = verify_case(settings.evidence_dir, c.id, signer, head, text=text)
    if head is None and c.status in TERMINAL:
        res = VerifyResult(False, res.records, [*res.errors, "head_unknown (서명 서비스에서 체인 끝을 받지 못함)"])
    return res


@app.post("/api/cases/{case_id}/verify")
def verify(case_id: str, p: Annotated[Principal, Depends(need("viewer"))]):
    c = _get_case(case_id)
    signer = Signer(settings.evidence_hmac_key.get_secret_value().encode(), settings.evidence_key_id)
    res = _verify_case(c, signer)
    store.audit(p.name, "evidence.verify", case_id, "ok" if res.ok else ";".join(res.errors[:5]))
    return res.as_dict()


# ── 검토 패키지 ─────────────────────────────────────────
def _signer() -> Signer:
    return Signer(settings.evidence_hmac_key.get_secret_value().encode(), settings.evidence_key_id)


def _package_snapshot(c: Case, who: str) -> tuple[dict, list[dict], str]:
    """체인을 한 번만 읽고, 그 내용을 검증한 뒤 같은 내용으로 패키지를 만든다(에이전트가 증거 볼륨에 쓸 수 있어서
    따로 읽으면 검증한 체인과 내보내는 체인이 달라질 수 있다). 반환: (패키지, 기록, 체인 원문)"""
    if c.status not in TERMINAL:
        raise HTTPException(409, "조사가 끝난 뒤에 패키지를 만들 수 있습니다")
    signer = _signer()
    text = package.read_chain_text(settings.evidence_dir, c.id)
    res = _verify_case(c, signer, text)
    with store.session() as s:
        audit = list(s.scalars(select(AuditLog).where(AuditLog.case_id == c.id)))
    records = package.parse_chain(text or "")
    pkg = package.build(c, records, res, verdicts.history(store, c.id), audit, generated_by=who, key_id=signer.key_id)
    return pkg, records, text or ""


def _package(c: Case, who: str) -> dict:
    return _package_snapshot(c, who)[0]


def _report_of(pkg: dict, records: list[dict]) -> dict:
    try:
        return report.build(pkg, records)
    except (TypeError, ValueError, KeyError, AttributeError) as e:  # 자료형이 어긋난 기록(서명은 자료형을 보장하지 않음)
        log.warning("report build failed: %s", type(e).__name__)
        raise HTTPException(422, "이 사건의 기록으로는 보고서를 만들 수 없습니다(검토 패키지로 원본 확인)") from e


def _report_pdf(rep: dict) -> bytes:
    try:
        return report.render_pdf(rep, settings.evidence_dir)
    except report.FontMissing as e:
        log.error("report font missing")
        raise HTTPException(503, "보고서를 만들 수 없습니다(서버 설정)") from e


@app.get("/api/cases/{case_id}/package")
def get_package(case_id: str, p: Annotated[Principal, Depends(need("viewer"))]):
    """검토 패키지(JSON). 콘솔에서 보는 내용과 같은 범위라 열람자도 볼 수 있다."""
    return _package(_get_case(case_id), p.name)


@app.get("/api/cases/{case_id}/package.zip")
def export_package(case_id: str, p: Annotated[Principal, Depends(need("investigator"))]):
    """검토 패키지 내려받기(ZIP: package.json·체인 원본·파일·SHA256SUMS·서명). 밖으로 나가는 자료라 조사관 이상, 감사로그."""
    c = _get_case(case_id)
    if c.status not in TERMINAL:
        raise HTTPException(409, "조사가 끝난 뒤에 패키지를 만들 수 있습니다")
    store.audit(p.name, "package.export", case_id)  # 먼저 남겨서 패키지의 감사로그에도 이번 내보내기가 들어가게
    pkg, records, text = _package_snapshot(c, p.name)
    try:  # 보고서를 만들지 못해도 원본 증거 내보내기는 막지 않는다
        rep = _report_of(pkg, records)
        extra = [("report.json", json.dumps(rep, ensure_ascii=False, indent=2).encode()), ("report.pdf", _report_pdf(rep))]
    except HTTPException:
        extra = []
    data = package.export_zip(pkg, settings.evidence_dir, case_id, _signer(), extra, chain_text=text)
    name = f"safetrace-{case_id[:8]}-{pkg['generated_at'][:10]}.zip"
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/cases/{case_id}/report.{fmt}")
def export_report(case_id: str, fmt: str, p: Annotated[Principal, Depends(need("investigator"))]):
    """보고서 초안(JSON·PDF). 기관 양식으로 옮기기 쉬운 요약본. 밖으로 나가는 자료라 조사관 이상, 감사로그."""
    if fmt not in ("json", "pdf"):
        raise HTTPException(404, "not found")
    c = _get_case(case_id)
    if c.status not in TERMINAL:
        raise HTTPException(409, "조사가 끝난 뒤에 보고서를 만들 수 있습니다")
    store.audit(p.name, "report.export", case_id, fmt)
    pkg, records, _ = _package_snapshot(c, p.name)
    rep = _report_of(pkg, records)
    name = f"safetrace-report-{case_id[:8]}-{rep['generated_at'][:10]}.{fmt}"
    headers = {"Content-Disposition": f'attachment; filename="{name}"'}
    if fmt == "json":
        return JSONResponse(rep, headers=headers)
    return Response(_report_pdf(rep), media_type="application/pdf", headers=headers)

"""SafeTrace API: 로그인·계정, 사건 접수·조회, 실시간 진행(SSE), 증거 파일·무결성 검증, 담당자 판정, 검토 패키지.

실행: uvicorn safetrace.api.main:app --port 8000
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import hmac
import ipaddress
import json
import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from PIL import Image
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from .. import accounts, package, related, report, verdicts
from ..accounts import ROLES, AccountError
from ..config import get_settings
from ..evidence import Head, Signer, VerifyResult, iter_evidence, open_evidence, verify_case
from ..live import CHANNEL as LIVE_CHANNEL
from ..live import END as LIVE_END
from ..live import WATCH_KEY as LIVE_WATCH_KEY
from ..live import WATCH_TTL_S as LIVE_WATCH_TTL_S
from ..live import ForwardLimit, LocalLive
from ..masking import mask_secrets
from ..netguard import BlockedURL, parse_url
from ..preview import preview_image
from ..ratelimit import FailureLimiter
from ..signer.client import ChainAdmin, SignerError
from ..store import TERMINAL, AuditLog, Case, CaseLink, CasePhase, CaseSite, Store, Verdict
from ..store import now as now_utc

log = logging.getLogger("safetrace.api")
settings = get_settings()
store = Store(settings.database_url)

_FILE_NAME = re.compile(r"^[a-z0-9_\-]{1,64}\.(png|webm)$")
PREVIEW_MAX_BYTES = 64 << 20  # 미리보기로 줄일 원본 PNG 상한(페이지 전체 캡처보다 넉넉히)
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


_CAND_STR = {"url": 2048, "final_url": 2048, "host": 253, "source": 8, "status": 24, "reason": 64, "threat": 32,
             "text": 80}


def _clean_candidates(v) -> list[dict]:
    """워커가 보낸 연관 후보 목록(믿지 않는 값)을 정해진 항목·길이·개수로만 받는다(화면에는 글자로만 표시)."""
    out = []
    for c in v if isinstance(v, list) else []:
        if not isinstance(c, dict) or not isinstance(c.get("url"), str):
            continue
        d = {k: c[k][:n] for k, n in _CAND_STR.items() if isinstance(c.get(k), str)}
        for k in ("reputation_match", "reputation_unchecked", "hold", "blocked", "brand_name"):
            if isinstance(c.get(k), bool):
                d[k] = c[k]
        if isinstance(c.get("sub"), int) and 0 < c["sub"] <= 10:
            d["sub"] = c["sub"]
        if type(c.get("score")) is int and 0 <= c["score"] <= 3:
            d["score"] = c["score"]
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
    if payload.get("type") == "status" and "phase" in payload:
        # 원래 결과: 워커가 말한 '원래 조사의 마지막 기록'을 믿지 않고 체인 앞부분을 서명까지 검증한 끝으로 바꾼다
        mh = _verify_main_head(case_id, payload.get("main_head"))
        payload = {k: v for k, v in payload.items() if k not in ("main_head", "threat", "final_url", "main", "safebrowsing")}
        if mh is None:
            store.audit("system", "event.rejected", case_id, "main_head_unverified")
            return
        # 판정 대상이 되는 원래 결과(상태·사유·위협 판단·최종 주소·평판)는 이벤트가 아니라 검증한 서명 기록에서 가져온다
        payload.update(main_head={"seq": mh["seq"], "hash": mh["hash"]}, threat=mh["threat"], final_url=mh["final_url"],
                       main=mh["main"], safebrowsing=mh["safebrowsing"])
    elif payload.get("type") == "status" and payload.get("status") in TERMINAL:
        ph = store.phases_for([case_id]).get(case_id)
        if ph is not None and (payload.get("status"), payload.get("reason")) != (ph.main_status, ph.main_reason):
            store.audit("system", "event.main_result_kept", case_id,
                        f"main={ph.main_status} sent={str(payload.get('status'))[:24]}")
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
    elif payload.get("type") == "status" and payload.get("status") in TERMINAL:
        try:
            store.write_sites(case_id)  # 사건 간 연결(PR 5). 실패해도 원 사건 처리는 계속
        except Exception as e:
            log.exception("write sites failed")
            store.audit("system", "case.sites_failed", case_id, type(e).__name__)
        recs = _verified_records(case_id)  # 닫고 검증한 체인(한 번만 읽고 검증해 아래 둘이 함께 쓴다)
        _write_intel(case_id, recs)
        _auto_related(case_id, recs)


def _verified_records(case_id: str) -> list[dict] | None:
    """닫고 검증한 체인의 기록. 검증하지 못하면 None(그 기록으로는 아무것도 만들지 않는다)."""
    try:
        with store.session() as s:
            c = s.get(Case, case_id)
        if c is None or c.status not in TERMINAL:
            return None
        text = package.read_chain_text(settings.evidence_dir, c.id)
        if text is None or not _verify_case(c, _signer(), text).ok:
            return None
        return package.clean_records(package.parse_chain(text))[0]
    except Exception as e:  # 검증 실패가 이벤트 소비를 멈추지 않게
        log.exception("verify chain after finish failed")
        store.audit("system", "evidence.verify_failed", case_id, type(e).__name__)
        return None


def _write_intel(case_id: str, recs: list[dict] | None) -> None:
    """운영 정보·키트 지문으로 이을 줄(related.intel_rows)을 검증한 체인에서 쓴다. 워커가 보낸 이벤트 값은 쓰지 않는다."""
    if recs is None:
        store.audit("system", "case.intel_skipped", case_id, "chain_unverified")
        return
    try:
        with store.session() as s:
            c = s.get(Case, case_id)
        th = c.threat.get("threat") if c is not None and isinstance(c.threat, dict) else None
        store.write_intel_sites(case_id, related.intel_rows(recs, th if isinstance(th, str) else None))
    except Exception as e:  # 실패해도 원 사건 처리는 계속
        log.exception("write intel sites failed")
        store.audit("system", "case.intel_failed", case_id, type(e).__name__)


def _auto_limit(s, parent_id: str, host: str) -> str | None:
    """선별 조건 7~9(시점에 따라 바뀌는 중복·한도). 어긋난 조건 이름, 모두 맞으면 None. _intake_lock 안에서 부른다."""
    since = now_utc() - timedelta(days=settings.related_auto_dedup_days)
    if s.scalar(select(func.count()).select_from(CaseLink)
                .where(CaseLink.target_host == host, CaseLink.created_at >= since)):
        return "duplicate"  # 7 여러 신고에서 같은 사이트가 반복될 때
    if s.scalar(select(func.count()).select_from(CaseLink)
                .where(CaseLink.parent_id == parent_id, CaseLink.auto.is_(True))) >= settings.related_auto_per_case:
        return "per_case"  # 8 신고 1건이 불어나지 않게
    if s.scalar(select(func.count()).select_from(Case)
                .where(Case.created_by == related.AUTO_ACTOR, Case.status.in_(PENDING))) >= settings.related_auto_max_pending:
        return "max_pending"  # 9 사람 신고의 대기 시간 보호
    return None


def _signed_candidates(recs: list[dict]) -> list[dict]:
    """자동 연관 사건의 선별 근거(Codex 지적): 워커가 종료 이벤트로 보고한 후보 목록이 아니라, 닫고 검증한 체인의 원래
    조사 후보 기록(candidates)과 하위 조사 결과 기록(candidate_results)을 runner 와 같은 방식으로 합친 것.
    체인을 검증하지 못하면 None(만들지 않는다). 워커는 조사 중인 사건에 거짓 기록을 서명받을 수 있으므로 이것으로 거짓
    선별을 모두 막지는 못하지만, 자동 사건을 만든 근거가 원 사건의 서명된 증거에 그대로 남고(감사·패키지) 이벤트와 증거가
    다를 때 증거를 따른다. 남는 위험은 부모당 3·대기 10·깊이 1 한도로 묶는다(docs/threat-model.md).
    recs: 닫고 검증한 체인의 기록(_verified_records)."""

    def last(kind: str) -> dict:
        for r in reversed(recs):
            d = r.get("data")
            if r.get("kind") == kind and isinstance(d, dict) and "sub" not in d:
                return d
        return {}

    found, results = last("candidates").get("found"), last("candidate_results").get("results")
    by_url = {r["url"]: r for r in results if isinstance(r, dict) and isinstance(r.get("url"), str)}         if isinstance(results, list) else {}
    out = []
    for f in found if isinstance(found, list) else []:
        if not isinstance(f, dict) or not isinstance(f.get("url"), str):
            continue
        r = by_url.get(f["url"], {})
        out.append({**f, **{k: v for k, v in r.items() if k != "reputation_match"},
                    "reputation_match": f.get("reputation_match") is True or r.get("reputation_match") is True})
    return _clean_candidates(out)


_UNREAD = object()


def _auto_related(case_id: str, recs: list[dict] | None | object = _UNREAD) -> None:
    """원 사건이 끝나면(체인을 닫고 반영한 뒤) 선별 조건을 모두 통과한 연관 후보로 새 사건을 만든다(PR 4b).
    격리망 안의 워커가 아니라 API 가 만든다. 후보는 이벤트가 아니라 검증한 체인에서 고른다(_signed_candidates).
    실패해도 원 사건 처리와 이벤트 소비는 멈추지 않는다."""
    try:
        with store.session() as s:
            c = s.get(Case, case_id)
            if c is None or c.status not in TERMINAL or not settings.related_auto or c.source == "related":
                return
        if recs is _UNREAD:
            recs = _verified_records(case_id)  # 체인 검증은 접수 잠금 밖에서
        signed = _signed_candidates(recs) if isinstance(recs, list) else None
        if signed is None:
            store.audit(related.AUTO_ACTOR, "case.create_related_auto_skipped", case_id, "chain_unverified")
            return
        with _intake_lock, store.session() as s:  # 동시에 끝난 두 사건이 같은 호스트로 두 사건을 만들지 않게
            parent = s.get(Case, case_id)
            if parent is None or parent.status not in TERMINAL:
                return
            targets = related.auto_targets(parent.source, signed, enabled=settings.related_auto,
                                           threat_min_prob=settings.threat_min_prob)
            for cand, why in targets:
                host = related.target_host(cand)
                dup = s.scalar(select(CaseLink).where(CaseLink.parent_id == parent.id, CaseLink.candidate_url == cand["url"]))
                if dup is not None:
                    continue  # 같은 종료 이벤트를 다시 받았거나 담당자가 이미 버튼으로 만든 후보
                skip = _auto_limit(s, parent.id, host)
                if skip:
                    store.audit(related.AUTO_ACTOR, "case.create_related_auto_skipped", parent.id,
                                f"{skip} host={host} url={cand['url'][:200]}")
                    continue
                prob = cand.get("probability")
                note = f" host={host} why={why} threat={cand.get('threat') or '-'}" + (
                    f" p={prob:.2f}" if isinstance(prob, (int, float)) else "")
                try:
                    create_related_case(s, parent, cand, related.AUTO_ACTOR, auto=True, principal=None, note=note)
                except BlockedURL as e:
                    store.audit(related.AUTO_ACTOR, "case.create_related_auto_skipped", parent.id,
                                f"url_rejected:{e.reason} url={cand['url'][:200]}")
    except Exception as e:  # 자동 생성 실패가 이벤트 소비를 멈추지 않게(원 사건 상태·체인 닫기는 이미 끝났다)
        log.exception("auto related case failed")
        store.audit(related.AUTO_ACTOR, "case.create_related_auto_failed", case_id, type(e).__name__)


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


class ChildOut(BaseModel):
    """연관 후보로 만든 사건(부모 사건 상세에 붙는 요약)."""
    id: str
    url: str
    candidate_url: str
    status: str
    threat: str | None
    verdict: str | None  # 담당자의 현재 판정(threat | benign | hold)
    auto: bool


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
    # 원래 결과가 나온 뒤 연관 사이트를 조사하는 중이면 "related"(조사 중일 때만). main_status: 원래 결과의 상태
    phase: str | None = None
    main_status: str | None = None
    main_head_seq: int | None = None  # 원래 조사의 증거 끝(조사 중 판정은 여기에 묶는다)
    # 연관 사건(source=related)이면 그 후보가 나온 부모 사건. children: 이 사건의 후보로 만든 사건(상세에만)
    parent_id: str | None = None
    parent_url: str | None = None
    auto: bool | None = None
    children: list[ChildOut] | None = None
    # 하위 조사했지만 자동 사건이 없는 후보와 이유(disabled|depth|not_threat|blocked|shortener|limit_or_duplicate, 상세에만)
    auto_skipped: list[dict] | None = None

    @classmethod
    def of(cls, c: Case, v: Verdict | None = None, ph: CasePhase | None = None,
           parent: tuple[CaseLink, str] | None = None, children: list[ChildOut] | None = None) -> CaseOut:
        return cls(id=c.id, url=c.url, source=c.source, status=c.status, finish_reason=c.finish_reason,
                   final_url=c.final_url, threat=c.threat, safebrowsing=c.safebrowsing, candidates=c.candidates,
                   head_seq=c.head_seq, created_at=c.created_at.isoformat(), verdict=VerdictOut.of(v) if v else None,
                   phase=ph.phase if ph and c.status == "RUNNING" else None,
                   main_status=ph.main_status if ph else None, main_head_seq=ph.main_head_seq if ph else None,
                   parent_id=parent[0].parent_id if parent else None, parent_url=parent[1] if parent else None,
                   auto=parent[0].auto if parent else None, children=children)


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


login_limiter = FailureLimiter(settings.login_ip_max_failed, settings.login_ip_window_s)


_proxy_ips: tuple[float, frozenset[str]] = (0.0, frozenset())
_PROXY_REFRESH_S = 5.0


def _trusted_proxy_ips(refresh: bool = False) -> frozenset[str]:
    """settings.trusted_proxies(예: Compose 의 web)의 현재 주소. 컨테이너를 다시 띄우면 주소가 바뀌므로 모르는 주소가 오면
    5초에 한 번까지 다시 찾는다."""
    global _proxy_ips
    t, ips = _proxy_ips
    if (refresh or not ips) and time.monotonic() - t >= _PROXY_REFRESH_S:
        found = set()
        for name in settings.trusted_proxies:
            try:
                found |= {ai[4][0] for ai in socket.getaddrinfo(name, None)}
            except OSError:
                pass
        _proxy_ips = (time.monotonic(), frozenset(found))
    return _proxy_ips[1]


def _client_ip(request: Request) -> str:
    """로그인 제한에 쓰는 접속 주소. 믿는 프록시(web)에서 온 요청만 X-Forwarded-For 를 쓴다. nginx 는 이 머리글을 접속
    주소($remote_addr) 하나로 덮어쓰므로 사용자가 보낸 값은 버려지고, 다른 컨테이너(예: 에이전트)가 직접 보낸 값은 믿지 않는다."""
    peer = request.client.host if request.client else ""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd and settings.trusted_proxies and (peer in _trusted_proxy_ips() or peer in _trusted_proxy_ips(refresh=True)):
        try:
            return str(ipaddress.ip_address(fwd.rsplit(",", 1)[-1].strip()))
        except ValueError:
            pass
    return peer[:64] or "-"


@app.post("/api/auth/login", response_model=LoginOut)
def login(body: LoginIn, request: Request):
    ip = _client_ip(request)
    wait, first = login_limiter.take(ip)
    if wait:  # 비밀번호를 확인하지 않는다(Argon2id 계산도 시키지 않음). 계정이 있는지도 드러나지 않는다
        if first:
            store.audit("system", "auth.ip_limited", detail=f"ip={ip} failures={login_limiter.max_failures}")
        raise HTTPException(429, "로그인 시도가 너무 많습니다. 잠시 뒤 다시 시도하세요",
                            headers={"Retry-After": str(wait)})
    res = accounts.login(store, body.username, body.password)
    if res is None:
        store.audit(_safe_name(body.username), "auth.login_failed",
                    detail=f"{accounts.login_failure_reason(store, body.username)} ip={ip}")
        raise HTTPException(401, "아이디 또는 비밀번호가 올바르지 않습니다")
    login_limiter.give_back(ip)
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
_intake_lock = threading.Lock()  # API 는 프로세스 하나(Dockerfile CMD)
PENDING = ("QUEUED", "RUNNING")


def _check_intake_limits(s, p: Principal) -> None:
    """끝나지 않은 사건이 한도를 넘으면 접수를 거절한다. 무한 스크립트처럼 워커를 오래 붙잡는 페이지를 한 주체가
    대량으로 넣어 대기열을 막지 못하게 한다(끝난 사건은 세지 않으므로 처리되는 만큼 다시 넣을 수 있다)."""
    pending = Case.status.in_(PENDING)  # 모르는 상태값(옛 기록 등)이 영영 한 칸을 차지하지 않게 명시한다
    mine = s.scalar(select(func.count()).select_from(Case).where(pending, Case.created_by == p.name))
    if mine >= settings.case_max_pending_per_principal:
        store.audit(p.name, "case.rejected", detail=f"limit=principal pending={mine}")
        raise HTTPException(429, "끝나지 않은 사건이 너무 많습니다. 조사가 끝난 뒤 다시 접수하세요",
                            headers={"Retry-After": "60"})
    # 자동 연관 사건(system:related)은 자기 전용 한도(related_auto_max_pending)만 받는다: 사람 신고를 막지 않게
    total = s.scalar(select(func.count()).select_from(Case).where(pending, Case.created_by != related.AUTO_ACTOR))
    if total >= settings.case_max_pending_total:
        store.audit(p.name, "case.rejected", detail=f"limit=total pending={total}")
        raise HTTPException(503, "대기열이 가득 찼습니다. 잠시 뒤 다시 접수하세요", headers={"Retry-After": "60"})


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
    with _intake_lock, store.session() as s:  # 세기와 넣기 사이에 다른 접수가 끼어 한도를 넘지 않게
        if key:
            existing = s.scalar(select(Case).where(Case.idempotency_key == key))
            if existing:
                return CaseOut.of(existing)
        _check_intake_limits(s, p)
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
    ids = [c.id for c in rows]
    latest, phases, parents = verdicts.latest_for(store, ids), store.phases_for(ids), store.parents_for(ids)
    return [CaseOut.of(c, latest.get(c.id), phases.get(c.id), parents.get(c.id)) for c in rows]


@app.get("/api/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: str, p: Annotated[Principal, Depends(need("viewer"))]):
    c = _get_case(case_id)
    return _case_detail(c)


def _case_detail(c: Case) -> CaseOut:
    kids = store.children_of(c.id)
    kv = verdicts.latest_for(store, [k.id for _, k in kids])
    children = [ChildOut(id=k.id, url=k.url, candidate_url=link.candidate_url, status=k.status,
                         threat=(k.threat or {}).get("threat") if isinstance(k.threat, dict) else None,
                         verdict=kv[k.id].decision if k.id in kv else None, auto=link.auto) for link, k in kids]
    out = CaseOut.of(c, verdicts.latest_for(store, [c.id]).get(c.id), store.phases_for([c.id]).get(c.id),
                     store.parents_for([c.id]).get(c.id), children)
    if c.status in TERMINAL:  # 자동 생성은 원 사건이 끝난 뒤에 한다
        made = {k.candidate_url for k in children}
        out.auto_skipped = [
            {"url": x["url"][:2048], "reason": related.skip_reason(c.source, x, enabled=settings.related_auto,
                                                                   threat_min_prob=settings.threat_min_prob)
             or "limit_or_duplicate"}
            for x in (c.candidates or []) if isinstance(x, dict) and isinstance(x.get("url"), str)
            and x.get("sub") and x["url"] not in made][:20]
    return out


# ── 연관 사이트를 새 사건으로(related-sites PR 4) ─────────────────────────
class RelatedIn(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


def create_related_case(s, parent: Case, cand: dict, actor: str, *, auto: bool,
                        principal: Principal | None, note: str = "") -> tuple[Case, bool]:
    """연관 후보로 새 사건을 만든다(담당자 버튼과 자동 생성이 같이 쓴다): 형식 검사·접수 한도·사건·연결·감사·대기열.
    같은 부모의 같은 후보는 한 번만 만들고, 이미 있으면 그 사건을 돌려준다. 반환: (자식 사건, 새로 만들었는지).
    호출하는 쪽이 _intake_lock 안에서 부른다(세기와 넣기 사이에 다른 접수가 끼지 않게).
    cand 는 부모 사건에 저장된 후보(API 가 _clean_candidates 로 받은 값)여야 한다."""
    url = cand["url"]
    q = select(Case).join(CaseLink, CaseLink.child_id == Case.id).where(CaseLink.parent_id == parent.id,
                                                                         CaseLink.candidate_url == url)
    existing = s.scalar(q)
    if existing:
        return existing, False
    parse_url(url, settings.allowed_ports)  # 형식 검사(BlockedURL). IP 검사는 에이전트가 접속 시점에 한다
    if principal is not None:
        _check_intake_limits(s, principal)  # 담당자가 만든 연관 사건은 그 담당자의 한도에 든다
    final = cand.get("final_url") if isinstance(cand.get("final_url"), str) else ""
    target = (urlsplit(final).hostname or (cand.get("host") if isinstance(cand.get("host"), str) else "")
              or urlsplit(url).hostname or "")
    c = Case(url=url, source="related", created_by=actor)
    s.add(c)
    s.flush()
    s.add(CaseLink(child_id=c.id, parent_id=parent.id, candidate_url=url, target_host=target.lower()[:253],
                   auto=auto, created_by=actor))
    try:
        s.commit()
    except IntegrityError:  # 같은 후보로 동시에 만든 다른 요청이 먼저 들어갔다
        s.rollback()
        existing = s.scalar(q)
        if existing:
            return existing, False
        raise
    store.audit(actor, "case.create_related_auto" if auto else "case.create_related", c.id,
                f"parent={parent.id} url={url[:200]}{note}")
    enqueue(c.id, c.url)
    return c, True


@app.post("/api/cases/{case_id}/related", response_model=CaseOut, status_code=201)
def create_related(case_id: str, body: RelatedIn, response: Response,
                   p: Annotated[Principal, Depends(need("investigator"))]):
    """사건의 연관 후보 하나를 새 사건으로 접수한다(전체 조사). 후보 목록에 정확히 있는 주소만 받는다(출처가 분명한
    연결만 만든다). 이미 만든 후보면 그 사건을 돌려준다(200)."""
    with _intake_lock, store.session() as s:
        parent = s.get(Case, case_id)
        if parent is None:
            raise HTTPException(404, "not found")
        cand = next((x for x in (parent.candidates or []) if isinstance(x, dict) and x.get("url") == body.url), None)
        if cand is None:
            raise HTTPException(422, "이 사건의 연관 후보가 아닌 주소입니다")
        try:
            child, created = create_related_case(s, parent, cand, p.name, auto=False, principal=p)
        except BlockedURL as e:
            raise HTTPException(422, f"url rejected: {e.reason}") from None
    if not created:
        response.status_code = 200
    return _case_detail(child)


# ── 사건 간 연결(related-sites PR 5) ─────────────────────────
LINKS_MAX = 50
GROUP_CASES_MAX, GROUP_SITES_MAX = 500, 5000  # 묶음 계산 범위(최근 종료 사건)·호스트 줄 상한
_GROUP_KEY = re.compile(r"^[0-9a-f]{16}$")


def _briefs(ids: list[str]) -> dict[str, dict]:
    """사건 요약(id·신고 URL·상태·AI 위협 유형·담당자 판정). 연결 목록·묶음에 쓴다."""
    if not ids:
        return {}
    with store.session() as s:
        cases = list(s.scalars(select(Case).where(Case.id.in_(ids))))
    latest = verdicts.latest_for(store, ids)
    return {c.id: {"id": c.id, "url": c.url, "status": c.status,
                   "threat": c.threat.get("threat") if isinstance(c.threat, dict) else None,
                   "verdict": latest[c.id].decision if c.id in latest else None} for c in cases}


@app.get("/api/cases/{case_id}/links")
def case_links(case_id: str, p: Annotated[Principal, Depends(need("viewer"))]):
    """연결된 사건: 부모·자식(연관 후보로 만든 사건)과, 같은 사이트가 나온 다른 사건(사이트별, 최대 50건)."""
    c = _get_case(case_id)
    parent = store.parents_for([c.id]).get(c.id)
    kids = store.children_of(c.id, limit=LINKS_MAX)
    with store.session() as s:
        keys = set(s.scalars(select(CaseSite.site).where(CaseSite.case_id == c.id)))
        rows = s.execute(select(CaseSite).join(Case, Case.id == CaseSite.case_id)
                         .where(CaseSite.site.in_(keys), CaseSite.case_id != c.id)
                         .order_by(Case.created_at.desc()).limit(GROUP_SITES_MAX)).scalars().all() if keys else []
    shared: dict[str, dict] = {}
    others: list[str] = []
    for r in rows:
        if r.case_id not in others:
            if len(others) >= LINKS_MAX:
                continue
            others.append(r.case_id)
        g = shared.setdefault(r.site, {"site": r.site, "hosts": set(), "roles": set(), "cases": []})
        g["hosts"].add(r.host)
        g["roles"].add(r.role)
        if r.case_id not in g["cases"]:
            g["cases"].append(r.case_id)
    info = _briefs([*others, *([parent[0].parent_id] if parent else []), *(k.id for _, k in kids)])
    return {
        "parent": info.get(parent[0].parent_id) if parent else None,
        "children": [{**info[k.id], "auto": link.auto} for link, k in kids if k.id in info],
        "shared": [{"site": g["site"], "kind": _site_kind(g["roles"]), "hosts": sorted(g["hosts"])[:10],
                    "roles": sorted(g["roles"]), "cases": [info[x] for x in g["cases"] if x in info]}
                   for g in shared.values()],
    }


def _intel_of(recs: list[dict]) -> tuple[list[dict], list[dict]]:
    """검증한 체인의 원래 조사 intel 기록을 값마다 하나로: (운영 정보, 키트 지문). 각 항목의 key 는 이을 열쇠."""
    steps = {r["seq"]: r["data"].get("step") for r in recs if r.get("kind") == "observe"}
    items: dict[tuple[str, str], dict] = {}
    kits: dict[str, dict] = {}
    for r in recs:
        d = r.get("data")
        if r.get("kind") != "intel" or not isinstance(d, dict) or isinstance(d.get("sub"), int):
            continue
        step = steps.get(d.get("obs")) if type(d.get("obs")) is int else None
        step = step if type(step) is int else None
        for x in d.get("items") if isinstance(d.get("items"), list) else []:
            if not isinstance(x, dict) or not isinstance(x.get("kind"), str) or not isinstance(x.get("value"), str):
                continue
            k = (x["kind"][:16], x["value"][:200])
            if k not in items and len(items) < 50:
                key = related.intel_key(*k)
                items[k] = {"kind": k[0], "value": k[1], "src": x.get("src") if isinstance(x.get("src"), str) else None,
                            "step": step, "key": key[0] if key else None}
        kit, url = d.get("kit"), d.get("url")
        host = (urlsplit(url).hostname or "")[:253] if isinstance(url, str) else ""
        for part in ("dom", "res"):
            h = kit.get(part) if isinstance(kit, dict) else None
            if isinstance(h, str) and related.HASH32.fullmatch(h) and f"kit:{part}:{h}" not in kits and len(kits) < 20:
                kits[f"kit:{part}:{h}"] = {"kind": part, "hash": h, "host": host, "step": step, "key": f"kit:{part}:{h}"}
    return list(items.values()), list(kits.values())


@app.get("/api/cases/{case_id}/intel")
def case_intel(case_id: str, p: Annotated[Principal, Depends(need("investigator"))]):
    """운영 정보(페이지에 적힌 연락처·계좌·수집 서버)와 키트 지문, 같은 열쇠가 나온 다른 사건. 원래 값이라 조사관 이상,
    감사로그. 값은 검증한 체인의 원래 조사 기록에서만 꺼낸다(DB 의 연결 줄은 '다른 사건' 찾기에만)."""
    c = _get_case(case_id)
    if c.status not in TERMINAL:
        raise HTTPException(409, "조사가 끝난 뒤에 볼 수 있습니다")
    recs = _verified_records(c.id)
    if recs is None:
        raise HTTPException(422, "증거 체인을 검증하지 못해 보여 줄 수 없습니다(검토 패키지로 원본 확인)")
    store.audit(p.name, "intel.view", case_id)
    items, kits = _intel_of(recs)
    keys = {x["key"] for x in [*items, *kits] if x["key"]}
    with store.session() as s:
        rows = s.execute(select(CaseSite.site, CaseSite.case_id).join(Case, Case.id == CaseSite.case_id)
                         .where(CaseSite.site.in_(keys), CaseSite.role.in_(related.INTEL_ROLES), CaseSite.case_id != c.id)
                         .order_by(Case.created_at.desc()).limit(GROUP_SITES_MAX)).all() if keys else []
    others: dict[str, list[str]] = {}
    for site, cid in rows:
        lst = others.setdefault(site, [])
        if cid not in lst and len(lst) < LINKS_MAX:
            lst.append(cid)
    info = _briefs(list({cid for lst in others.values() for cid in lst}))

    def out(x: dict) -> dict:
        return {**{k: v for k, v in x.items() if k != "key"},
                "others": [info[i] for i in others.get(x["key"] or "", []) if i in info]}

    return {"items": [out(x) for x in items], "kits": [out(x) for x in kits]}


def _site_kind(roles: set[str]) -> str:
    """이은 열쇠의 종류: contact(운영 정보) | kit(키트 지문) | site(사이트)."""
    return "contact" if "contact" in roles else "kit" if "kit" in roles else "site"


def _related_groups(min_cases: int) -> tuple[list[dict], bool]:
    """최근 종료 사건(최대 500)에서 같은 사이트로 이어지는 사건 묶음. 반환: (묶음, 계산 범위를 잘랐는지)."""
    with store.session() as s:
        recent = list(s.scalars(select(Case.id).where(Case.status.in_(TERMINAL))
                                .order_by(Case.created_at.desc()).limit(GROUP_CASES_MAX + 1)))
        truncated = len(recent) > GROUP_CASES_MAX
        recent = recent[:GROUP_CASES_MAX]
        rows = list(s.scalars(select(CaseSite).where(CaseSite.case_id.in_(recent)).order_by(CaseSite.id)
                              .limit(GROUP_SITES_MAX + 1))) if recent else []
    if len(rows) > GROUP_SITES_MAX:
        truncated, rows = True, rows[:GROUP_SITES_MAX]
    found = related.groups([(r.case_id, r.site, r.generic) for r in rows], min_cases)
    by_case: dict[str, list[CaseSite]] = {}
    for r in rows:
        by_case.setdefault(r.case_id, []).append(r)
    info = _briefs([cid for g in found for cid in g])
    out = []
    for g in found:
        sites: dict[str, dict] = {}
        for cid in g:
            for r in by_case.get(cid, []):
                x = sites.setdefault(r.site, {"site": r.site, "hosts": set(), "threat": None, "blocked": False,
                                              "cases": set(), "candidate": None, "roles": set()})
                x["hosts"].add(r.host)
                x["roles"].add(r.role)
                x["cases"].add(cid)
                if r.threat and r.threat not in ("benign", "unknown"):
                    x["threat"] = r.threat
                x["blocked"] = x["blocked"] or r.blocked
                if r.role in ("via", "link") and x["candidate"] is None:
                    x["candidate"] = {"case_id": cid, "host": r.host}
        key = hashlib.sha256("|".join(sorted(sites)).encode()).hexdigest()[:16]
        listed = sorted(sites.values(), key=lambda x: (-len(x["cases"]), x["site"]))
        out.append({
            "key": key,
            "cases": [info[c] for c in sorted(g) if c in info],
            "sites": [{"site": x["site"], "kind": _site_kind(x["roles"]), "hosts": sorted(x["hosts"])[:10],
                       "threat": x["threat"], "blocked": x["blocked"], "cases": len(x["cases"]),
                       "candidate": x["candidate"]} for x in listed],
            # 운영 정보·키트 지문 열쇠는 사이트가 아니라 위협 사이트 수에 넣지 않는다
            "threat_sites": sum(1 for x in listed if x["threat"] and _site_kind(x["roles"]) == "site"),
            # 회선 차단은 조사 대상 서버가 흉내 낼 수 있는 추정이라 위협 집계에서 빼지 않고 따로 센다(Codex 지적)
            "blocked_estimate_sites": sum(1 for x in listed if x["blocked"]),
        })
    out.sort(key=lambda g: (-len(g["cases"]), g["key"]))
    return out, truncated


@app.get("/api/related-groups")
def related_groups(p: Annotated[Principal, Depends(need("viewer"))], min: int = Query(2, ge=2, le=50),  # noqa: A002
                   limit: int = Query(50, ge=1, le=50)):
    """연관 묶음: 같은 사이트로 이어지는 사건들(단축 서비스·공식·흔한 대형 사이트로는 잇지 않고, 공용 호스팅은 호스트가
    같을 때만). 계산 범위(최근 종료 사건 500건·호스트 5,000줄)를 넘으면 잘라서 truncated."""
    t0 = time.monotonic()
    groups, truncated = _related_groups(min)
    return {"groups": groups[:limit], "truncated": truncated, "ms": round((time.monotonic() - t0) * 1000)}


def _csv_cell(v: object) -> str:
    """CSV 칸: 페이지가 정한 글자가 표 계산 프로그램에서 수식으로 읽히지 않게 수식 시작 문자 앞에 ' 를 붙인다(CWE-1236)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@app.get("/api/related-groups/{group_key}.csv")
def related_group_csv(group_key: str, p: Annotated[Principal, Depends(need("investigator"))]):
    """연관 묶음 하나의 사이트·사건 표(조사관 이상, 감사로그). 묶음이 바뀌었으면 404(목록을 새로 받는다)."""
    if not _GROUP_KEY.match(group_key):
        raise HTTPException(404, "not found")
    groups, _ = _related_groups(2)
    g = next((x for x in groups if x["key"] == group_key), None)
    if g is None:
        raise HTTPException(404, "묶음이 바뀌었습니다. 연관 묶음 목록을 다시 불러오세요")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["구분", "사이트", "호스트", "AI 판단", "회선 차단 추정", "사건 수", "사건 id", "신고 URL", "사건 상태", "담당자 판정"])
    kind_ko = {"site": "사이트", "contact": "운영 정보", "kit": "키트 지문"}
    for x in g["sites"]:
        w.writerow([_csv_cell(v) for v in (kind_ko.get(x["kind"], "사이트"), x["site"], " ".join(x["hosts"]), x["threat"],
                                           x["blocked"], x["cases"], "", "", "", "")])
    for c in g["cases"]:
        w.writerow([_csv_cell(v) for v in ("사건", "", "", c["threat"], "", "", c["id"], c["url"], c["status"], c["verdict"])])
    store.audit(p.name, "related.export", None, f"group={group_key} cases={len(g['cases'])} sites={len(g['sites'])}")
    name = f"safetrace-related-{now_utc().strftime('%Y%m%d')}-{group_key[:8]}.csv"
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


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


def _masked_event(payload: dict) -> dict:
    """열람자에게 보내는 이벤트: 운영 정보 기록(페이지에 적힌 전화·계좌)은 끝 4자리만 남긴다."""
    if payload.get("type") != "evidence" or payload.get("kind") != "intel" or not isinstance(payload.get("data"), dict):
        return payload
    return {**payload, "data": {**payload["data"], "items": package.masked_intel(payload["data"].get("items"))}}


@app.get("/api/cases/{case_id}/events")
async def case_events(case_id: str, p: Annotated[Principal, Depends(need("viewer"))],
                      after: int = Query(0, ge=0)):
    """SSE: 기존 이벤트를 먼저 보내고, 이후 새 이벤트를 이어서 보낸다. 종료 상태면 스트림을 닫는다."""
    _get_case(case_id)
    raw_intel = ROLES[p.role] >= ROLES["investigator"]  # 열람자에게는 운영 정보의 전화·계좌를 가려 보낸다

    async def gen():
        last = after
        idle = 0
        while True:
            evs = await asyncio.to_thread(store.events_after, case_id, last)
            for e in evs:
                last = e.id
                payload = e.payload if raw_intel else _masked_event(e.payload)
                yield f"id: {e.id}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
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
    # 증거 볼륨은 에이전트가 쓴다: 링크를 따라가거나 FIFO 에서 기다리지 않게 안전하게 연 fd 로만 내보낸다(Codex 지적)
    try:
        fd, st = open_evidence(settings.evidence_dir, case_id, "files", name)
    except FileNotFoundError:
        raise HTTPException(404, "not found") from None
    except OSError as e:
        store.audit("system", "evidence.unsafe_file", case_id, f"{name} {type(e).__name__}: {str(e)[:60]}")
        raise HTTPException(404, "not found") from None
    # 증거 파일은 한 번 쓰이면 바뀌지 않는다(바뀌면 검증 실패) → 브라우저가 캐시해도 된다(인증 필요하므로 private)
    headers = {"Content-Security-Policy": "sandbox; default-src 'none'", "Cache-Control": "private, max-age=3600"}
    if preview and name.endswith(".png"):
        # 화면 표시용 JPEG(증거 아님). 원본은 preview 없이 요청
        try:
            raw = b"".join(iter_evidence(fd, min(st.st_size, PREVIEW_MAX_BYTES)))
            data, media = preview_image(raw, (case_id, name, st.st_mtime_ns, st.st_size))
        except (OSError, ValueError, Image.DecompressionBombError):
            raise HTTPException(404, "not found") from None
        return Response(data, media_type=media, headers=headers)
    media = "image/png" if name.endswith(".png") else "video/webm"
    return StreamingResponse(iter_evidence(fd, st.st_size), media_type=media,
                             headers={**headers, "Content-Length": str(st.st_size)})


@app.websocket("/api/cases/{case_id}/live")
async def case_live(ws: WebSocket, case_id: str):
    """실시간 화면(보기용, 증거 아님). 브라우저 WebSocket 은 인증 헤더를 못 붙이고 주소의 토큰은 접속 기록에 남으므로,
    연결 뒤 첫 메시지 {"token": ...} 로 인증한다. 이후 서버는 JPEG 프레임과 클릭 표시({"click": [x, y, 폭, 높이]} JSON)를
    바이너리로 그대로 보낸다(에이전트가 보낸 값이라 콘솔이 다시 검사한다)."""
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

    limit = ForwardLimit()  # 너무 크거나 몰려오는 메시지는 넘기지 않는다

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
                if limit.ok(frame):
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
                if isinstance(m["data"], bytes) and limit.ok(m["data"]):
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


def _verify_main_head(case_id: str, seq: object) -> dict | None:
    """원래 조사의 증거 끝과 그 결과. 반환 {seq, hash, threat, final_url} 또는 None.

    - 0..seq 번 기록을 해시·HMAC 서명·파일까지 검증하고, seq 번이 원래 조사의 연관 후보 기록(candidates)이며 그 앞에
      하위 조사 기록(data.sub)이 없어야 한다
    - 운영(서명 서비스)에서는 파일의 체인이 **이 사건의** 서명 서비스 head 까지 그대로 이어져야 한다. 서명에는 사건 id 가
      없어서, 다른 사건의 서명된 기록을 이 사건 폴더에 복사해 넣는 것을 이것으로 막는다(Codex 지적)
    - 판정 대상이 되는 원래 결과는 이 검증한 기록에서 꺼낸다(이벤트 값을 믿지 않는다): 상태·사유는 마지막 candidates
      기록의 main(러너가 평판 승격까지 반영한 값), 위협 판단은 threat, 최종 주소는 finish, 평판은 safebrowsing"""
    if type(seq) is not int or not 0 <= seq < 100_000:
        return None
    top, top_hash = seq, None
    for _ in range(5):  # 서명 직후 파일에 쓰기 전이면 잠깐 기다린다
        if _chains is not None:
            try:
                h = _chains.head(case_id)
            except SignerError:
                return None
            if type(h.get("seq")) is not int or not isinstance(h.get("hash"), str) or h["seq"] < seq:
                return None
            top, top_hash = h["seq"], h["hash"]
        lines = (package.read_chain_text(settings.evidence_dir, case_id) or "").splitlines()
        if len(lines) > top:
            break
        time.sleep(0.2)
    else:
        return None
    prefix = "\n".join(lines[: top + 1])
    expect = Head(top, top_hash) if top_hash is not None else None
    if not verify_case(settings.evidence_dir, case_id, _signer(), expect, text=prefix).ok:
        return None
    recs = package.parse_chain(prefix)[: seq + 1]
    if len(recs) != seq + 1 or recs[-1].get("kind") != "candidates" or not isinstance(recs[-1].get("hash"), str):
        return None
    if any(not isinstance(r.get("data"), dict) or isinstance(r["data"].get("sub"), int) for r in recs):
        return None
    threat = next((r["data"] for r in reversed(recs) if r.get("kind") == "threat"), None)
    finish = next((r["data"] for r in reversed(recs) if r.get("kind") == "finish"), {})
    sb = next((r["data"] for r in reversed(recs) if r.get("kind") == "safebrowsing"), None)
    main = recs[-1]["data"].get("main")
    if not isinstance(threat, dict) or not isinstance(main, dict):
        return None
    if main.get("status") not in TERMINAL or not isinstance(main.get("reason"), str):
        return None
    final = finish.get("final_url") if isinstance(finish.get("final_url"), str) else None
    return {"seq": seq, "hash": recs[-1]["hash"][:64], "threat": threat, "final_url": final,
            "main": {"status": main["status"], "reason": main["reason"][:64]},
            "safebrowsing": sb if isinstance(sb, dict) else None}


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
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError) as e:  # 자료형이 어긋난 기록(서명은 자료형을 보장하지 않음)
        log.warning("report build failed: %s", type(e).__name__)
        raise HTTPException(422, "이 사건의 기록으로는 보고서를 만들 수 없습니다(검토 패키지로 원본 확인)") from e


def _report_pdf(rep: dict) -> bytes:
    try:
        return report.render_pdf(rep, settings.evidence_dir)
    except report.FontMissing as e:
        log.error("report font missing")
        raise HTTPException(503, "보고서를 만들 수 없습니다(서버 설정)") from e
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, report.LayoutError) as e:
        log.warning("report render failed: %s", type(e).__name__)
        raise HTTPException(422, "이 사건의 기록으로는 보고서를 만들 수 없습니다(검토 패키지로 원본 확인)") from e


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


@app.get("/api/cases/{case_id}/referral")
def get_referral(case_id: str, p: Annotated[Principal, Depends(need("investigator"))]):
    """처리 기관 안내와 요청서 초안(보고서 요약에서 만든다). 기관에 옮겨 쓰는 글이라 조사관 이상, 감사로그."""
    c = _get_case(case_id)
    if c.status not in TERMINAL:
        raise HTTPException(409, "조사가 끝난 뒤에 요청서를 만들 수 있습니다")
    store.audit(p.name, "referral.view", case_id)
    pkg, records, _ = _package_snapshot(c, p.name)
    return _report_of(pkg, records)["referral"]

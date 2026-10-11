"""증거 서명 서비스(내부 전용). HMAC 키는 이 서비스와 검증하는 API 만 가진다.

- 에이전트(signer_agent_token): 열린 사건 체인에 기록 추가만
- API(signer_api_token): 체인 열기(접수 때), 닫기(조사가 끝났을 때), head 조회

실행: uvicorn --factory safetrace.signer.service:create_app --port 8200
"""

from __future__ import annotations

import hmac
import logging
import re
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..config import Settings, get_settings
from ..evidence import _SAFE_NAME, Signer
from .state import ChainState, Closed, NotOpen, SeqConflict

log = logging.getLogger("safetrace.signer")

MAX_BODY = 1 << 20  # 기록 1건 최대 1MiB(가장 큰 관찰 기록도 수십 KB)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
CaseId = Annotated[str, Path(pattern=r"^[a-f0-9\-]{36}$")]


class AppendIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # seq·ts·prev·hash 는 서비스가 정한다. 에이전트가 보낸 ts 는 받지 않는다

    seq: int = Field(ge=0, le=100_000)
    kind: str = Field(pattern=r"^[a-z_]{1,32}$")
    data: dict
    files: dict[str, str] = Field(default_factory=dict, max_length=32)

    @field_validator("files")
    @classmethod
    def _files(cls, v: dict[str, str]) -> dict[str, str]:
        for name, h in v.items():
            if not _SAFE_NAME.match(name) or not _HEX64.match(h):
                raise ValueError("invalid evidence file entry")
        return v


async def _read_limited(request: Request) -> bytes:
    """본문을 받으면서 크기를 센다. 한도를 넘으면 나머지는 받지 않고 413(다 받은 뒤 재면 메모리가 먼저 찬다)."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY:
        raise HTTPException(413, "record too large")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > MAX_BODY:
            raise HTTPException(413, "record too large")
    return bytes(buf)


def _bearer(expected: str, authorization: str) -> None:
    if not expected:
        raise HTTPException(503, "signer token not configured")
    if not hmac.compare_digest(authorization.encode(), f"Bearer {expected}".encode()):
        raise HTTPException(401, "unauthorized")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    state = ChainState(settings.signer_state_path,
                       Signer(settings.evidence_hmac_key.get_secret_value().encode(), settings.evidence_key_id))
    app = FastAPI(title="SafeTrace Signer", docs_url=None, redoc_url=None, openapi_url=None)

    def agent_only(authorization: str = Header(default="")) -> None:
        _bearer(settings.signer_agent_token.get_secret_value(), authorization)

    def api_only(authorization: str = Header(default="")) -> None:
        _bearer(settings.signer_api_token.get_secret_value(), authorization)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "key_id": settings.evidence_key_id}

    @app.post("/v1/chains/{case_id}/records", dependencies=[Depends(agent_only)])
    async def append(case_id: CaseId, request: Request):
        raw = await _read_limited(request)
        try:
            req = AppendIn.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(422, "invalid record") from None
        try:
            return state.append(case_id, req.seq, req.kind, req.data, req.files)
        except NotOpen:
            raise HTTPException(404, "chain not open") from None
        except Closed:
            raise HTTPException(409, "chain closed") from None
        except SeqConflict as e:
            raise HTTPException(409, f"seq conflict: expected {e.head.seq + 1}") from None

    @app.post("/v1/chains/{case_id}/open", dependencies=[Depends(api_only)])
    def open_chain(case_id: CaseId):
        return state.open(case_id)

    @app.post("/v1/chains/{case_id}/close", dependencies=[Depends(api_only)])
    def close_chain(case_id: CaseId):
        try:
            return state.close(case_id)
        except NotOpen:
            raise HTTPException(404, "chain not open") from None

    @app.get("/v1/chains/{case_id}/head", dependencies=[Depends(api_only)])
    def head(case_id: CaseId):
        try:
            return state.head(case_id)
        except NotOpen:
            raise HTTPException(404, "chain not open") from None

    return app

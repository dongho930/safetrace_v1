"""판단 서비스(내부 전용). Jev API 키는 이 서비스만 가진다.

실행: uvicorn safetrace.decision.service:app --port 8100
"""

from __future__ import annotations

import hmac
import logging

from fastapi import Depends, FastAPI, Header, HTTPException

from ..config import get_settings
from .engine import Engine, NoProviderAvailable, build_providers
from .schema import ActionDecision, ActionRequest, ThreatDecision, ThreatRequest

log = logging.getLogger("safetrace.decision")
settings = get_settings()
engine = Engine(build_providers(settings), settings.action_min_prob, settings.threat_min_prob)

app = FastAPI(title="SafeTrace Decision", docs_url=None, redoc_url=None, openapi_url=None)


def require_internal(authorization: str = Header(default="")) -> None:
    expected = settings.decision_token.get_secret_value()
    if not expected:
        raise HTTPException(503, "decision token not configured")
    if not hmac.compare_digest(authorization.encode(), f"Bearer {expected}".encode()):
        raise HTTPException(401, "unauthorized")


@app.get("/healthz")
def healthz():
    return {"ok": True, "providers": [p.name for p in engine.providers]}


@app.post("/v1/decide/action", response_model=ActionDecision, dependencies=[Depends(require_internal)])
def decide_action(req: ActionRequest):
    try:
        return engine.decide_action(req)
    except NoProviderAvailable:
        raise HTTPException(503, "decision unavailable") from None


@app.post("/v1/decide/threat", response_model=ThreatDecision, dependencies=[Depends(require_internal)])
def decide_threat(req: ThreatRequest):
    try:
        return engine.decide_threat(req)
    except NoProviderAvailable:
        raise HTTPException(503, "decision unavailable") from None

"""에이전트 쪽 판단 클라이언트. HTTP(운영) 또는 같은 프로세스의 엔진(개발·테스트)을 쓴다."""

from __future__ import annotations

from typing import Protocol

import httpx
from pydantic import ValidationError

from .engine import Engine, NoProviderAvailable
from .schema import ActionDecision, ActionRequest, PageState, ThreatDecision, ThreatRequest, action_options


class DecisionUnavailable(Exception):
    pass


class Decider(Protocol):
    def action(self, state: PageState) -> ActionDecision: ...
    def threat(self, req: ThreatRequest) -> ThreatDecision: ...


class HttpDecider:
    def __init__(self, base_url: str, token: str, timeout_s: float = 20.0):
        self._c = httpx.Client(base_url=base_url, timeout=timeout_s, follow_redirects=False,
                               headers={"Authorization": f"Bearer {token}"})

    def _post(self, path: str, body: dict, model):
        try:
            r = self._c.post(path, json=body)
            if r.status_code != 200:
                raise DecisionUnavailable(f"http {r.status_code}")
            return model.model_validate(r.json())
        except (httpx.HTTPError, ValidationError, ValueError) as e:
            raise DecisionUnavailable(type(e).__name__) from e

    def action(self, state: PageState) -> ActionDecision:
        d = self._post("/v1/decide/action", ActionRequest(state=state).model_dump(), ActionDecision)
        # 판단 서비스도 믿지 않는다: 제시한 선택지 안인지 다시 확인
        if d.choice not in action_options(state):
            raise DecisionUnavailable("choice outside options")
        return d

    def threat(self, req: ThreatRequest) -> ThreatDecision:
        return self._post("/v1/decide/threat", req.model_dump(), ThreatDecision)


class LocalDecider:
    def __init__(self, engine: Engine):
        self.engine = engine

    def action(self, state: PageState) -> ActionDecision:
        try:
            return self.engine.decide_action(ActionRequest(state=state))
        except (NoProviderAvailable, ValueError) as e:
            raise DecisionUnavailable(str(e)) from e

    def threat(self, req: ThreatRequest) -> ThreatDecision:
        try:
            return self.engine.decide_threat(req)
        except (NoProviderAvailable, ValueError) as e:
            raise DecisionUnavailable(str(e)) from e

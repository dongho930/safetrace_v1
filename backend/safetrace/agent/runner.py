"""사건 1건을 조사한다. 워커(Redis Streams)와 개발 모드(API 내부 스레드)가 같은 함수를 쓴다."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

import httpx

from ..config import Settings
from ..decision.client import Decider, HttpDecider, LocalDecider
from ..decision.engine import Engine, build_providers
from ..evidence import EvidenceWriter, Signer
from ..netguard import remote_resolver
from ..safebrowsing import lookup
from .loop import AgentRun

log = logging.getLogger("safetrace.runner")


def make_signer(s: Settings) -> Signer:
    key = s.evidence_hmac_key.get_secret_value().encode()
    return Signer(key, s.evidence_key_id)


def make_decider(s: Settings) -> Decider:
    token = s.decision_token.get_secret_value()
    if s.decision_url and token:
        return HttpDecider(s.decision_url, token)
    # 개발 모드: 같은 프로세스에서 엔진 사용
    return LocalDecider(Engine(build_providers(s), s.action_min_prob, s.threat_min_prob))


def investigate(case_id: str, url: str, s: Settings, emit: Callable[[dict], None],
                decider: Decider | None = None, resolver=None) -> dict:
    writer = EvidenceWriter(s.evidence_dir, case_id, make_signer(s))
    emit({"type": "status", "status": "RUNNING", "reason": None})
    if resolver is None and s.resolver_url:
        resolver = remote_resolver(s.resolver_url)
    run = AgentRun(url, s, decider or make_decider(s), writer, emit, resolver=resolver)
    result = asyncio.run(run.run())

    # Safe Browsing: 시작·경유·최종 URL 조회. 결과도 증거로 남긴다.
    # 격리망에서는 이 조회도 검문 프록시를 거친다
    transport = httpx.HTTPTransport(proxy=s.egress_proxy) if s.egress_proxy else None
    sb = lookup([url, *result.nav_chain[-10:]], s.safebrowsing_api_key.get_secret_value(), transport=transport)
    rec = writer.append("safebrowsing", sb)
    emit({"type": "evidence", "seq": rec["seq"], "kind": "safebrowsing", "data": sb, "files": [], "hash": rec["hash"]})

    final = {
        "type": "status", "status": result.status, "reason": result.finish_reason, "threat": result.threat,
        "final_url": result.final_url, "candidates": result.candidates_found, "safebrowsing": sb,
        "head": {"seq": writer.head.seq, "hash": writer.head.hash},
    }
    emit(final)
    return final

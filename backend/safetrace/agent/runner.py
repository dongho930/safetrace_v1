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
from ..live import LivePublisher, LiveSink
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
                decider: Decider | None = None, resolver=None, live: LivePublisher | None = None) -> dict:
    writer = EvidenceWriter(s.evidence_dir, case_id, make_signer(s))
    emit({"type": "status", "status": "RUNNING", "reason": None})
    if resolver is None and s.resolver_url:
        resolver = remote_resolver(s.resolver_url)
    sink = LiveSink(live, case_id, s.live_max_fps) if live else None
    run = AgentRun(url, s, decider or make_decider(s), writer, emit, resolver=resolver, live=sink)
    try:
        result = asyncio.run(run.run())
    finally:
        if sink:
            sink.close()

    # Safe Browsing: 시작·경유·최종 URL 조회. 결과도 증거로 남긴다.
    # 격리망에서는 이 조회도 검문 프록시를 거친다
    transport = httpx.HTTPTransport(proxy=s.egress_proxy) if s.egress_proxy else None
    sb = lookup([url, *result.nav_chain[-10:]], s.safebrowsing_api_key.get_secret_value(), transport=transport)
    rec = writer.append("safebrowsing", sb)
    emit({"type": "evidence", "seq": rec["seq"], "kind": "safebrowsing", "data": sb, "files": [], "hash": rec["hash"]})

    # 페이지는 못 열었지만 평판 DB 가 위험 URL 로 표시한 경우: 사건을 묻지 않고 담당자 검토로 올린다.
    # 근거가 외부 평판 하나뿐이므로 위협 유형은 확정하지 않는다(threat 없음).
    status, reason = result.status, result.finish_reason
    if status == "UNREACHABLE" and sb.get("status") == "match":
        status, reason = "REVIEW_REQUIRED", "unreachable_reputation_match"
        esc = {"from": result.status, "to": status, "reason": reason,
               "threat_types": sorted({m["threat_type"] for m in sb["matches"]})}
        rec = writer.append("escalation", esc)
        emit({"type": "evidence", "seq": rec["seq"], "kind": "escalation", "data": esc, "files": [], "hash": rec["hash"]})

    final = {
        "type": "status", "status": status, "reason": reason, "threat": result.threat,
        "final_url": result.final_url, "candidates": result.candidates_found, "safebrowsing": sb,
        "head": {"seq": writer.head.seq, "hash": writer.head.hash},
    }
    emit(final)
    return final

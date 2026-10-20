"""사건 1건을 조사한다. 워커(Redis Streams)와 개발 모드(API 내부 스레드)가 같은 함수를 쓴다."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from urllib.parse import unquote

import httpx

from ..config import Settings
from ..decision.client import Decider, HttpDecider, LocalDecider
from ..decision.engine import Engine, build_providers
from ..evidence import EvidenceWriter, LocalSealer, Sealer, Signer
from ..live import LivePublisher, LiveSink
from ..masking import mask_pii
from ..netguard import remote_resolver
from ..safebrowsing import lookup
from ..signer.client import RemoteSealer
from .loop import AgentRun

log = logging.getLogger("safetrace.runner")


def make_signer(s: Settings) -> Signer:
    return Signer(s.evidence_hmac_key.get_secret_value().encode(), s.evidence_key_id)


def make_sealer(s: Settings) -> Sealer:
    # 운영: 서명 서비스에 맡긴다(에이전트에는 키가 없다). 개발 모드: 같은 프로세스에서 서명
    if s.signer_url:
        return RemoteSealer(s.signer_url, s.signer_agent_token.get_secret_value())
    return LocalSealer(make_signer(s))


def make_decider(s: Settings) -> Decider:
    token = s.decision_token.get_secret_value()
    if s.decision_url and token:
        return HttpDecider(s.decision_url, token)
    # 개발 모드: 같은 프로세스에서 엔진 사용
    return LocalDecider(Engine(build_providers(s), s.action_min_prob, s.threat_min_prob))


def _append(writer: EvidenceWriter, emit: Callable[[dict], None], kind: str, data: dict) -> None:
    rec = writer.append(kind, data)
    emit({"type": "evidence", "seq": rec["seq"], "kind": kind, "data": data, "files": [], "hash": rec["hash"]})


def _needs_followup(status: str, threat: dict | None, sb_hit: bool) -> bool:
    """연관 후보까지 하위 조사할지. 원래 주소가 '확신 있는 정상'이면 하지 않는다(정상 사이트는 외부 링크가 많아
    조사 시간만 늘고, 후보를 근거로 정상 사이트를 잘못 보류할 수 있다). 열지 못했거나 실패한 사건도 하지 않는다."""
    if status in ("UNREACHABLE", "BLOCKED", "FAILED"):
        return False
    benign = bool(threat) and threat.get("threat") == "benign" and not threat.get("hold")
    return status == "REVIEW_REQUIRED" or not benign or sb_hit


def _investigate_candidates(cands: list[dict], s: Settings, decider: Decider, writer: EvidenceWriter,
                            emit: Callable[[dict], None], resolver, sink) -> list[dict]:
    """후보마다 새 브라우저에서 작은 예산으로 같은 탐색 루프를 돌린다. 같은 안전 게이트·검문 프록시를 거치고,
    같은 증거 체인에 sub 번호를 붙여 기록한다. 후보 하나가 실패해도 기록만 하고 다음 후보로 간다."""
    sub_s = s.model_copy(update={"max_steps": s.candidate_max_steps, "max_seconds": s.candidate_max_seconds})
    out = []
    for i, c in enumerate(cands, 1):
        res = {**c, "sub": i}
        try:
            r = asyncio.run(AgentRun(c["url"], sub_s, decider, writer, emit, resolver=resolver, live=sink, sub=i).run())
        except Exception as e:  # 브라우저를 띄우지 못한 경우 등. 원래 조사 결과는 그대로 둔다
            log.exception("candidate investigation failed")
            _append(writer, emit, "candidate_error", {"sub": i, "url": c["url"], "error": type(e).__name__})
            out.append({**res, "status": "FAILED", "reason": f"error:{type(e).__name__}", "_urls": [c["url"]]})
            continue
        th = r.threat or {}
        urls = list(dict.fromkeys(u for u in [c["url"], *r.nav_chain[-5:], r.final_url] if u))
        # blocked: 회선이 도메인 이름을 보고 막았다(warning.or.kr 화면·이름 기준 연결 리셋, 원래 조사의 회선 차단 감지와
        # 같은 값). 이미 차단된 사이트라 담당자가 따로 차단 요청할 필요가 적다
        out.append({**res, "status": r.status, "reason": r.finish_reason, "final_url": r.final_url[:2048],
                    "threat": th.get("threat"), "probability": th.get("probability"), "hold": th.get("hold"),
                    "blocked": bool(r.network_filtered), "_urls": urls})
    return out


_SB_LIMIT = 10  # 하위 조사 뒤 평판 조회 주소 수


def _has_pii(url: str) -> bool:
    """주소(경로 포함)에 개인정보 형태 문자열이 있는지. 있으면 외부 평판 조회로 보내지 않는다."""
    return mask_pii(url) != unquote(url)


def _reputation_order(results: list[dict]) -> list[str]:
    """조회 순서: 후보마다 최종 주소 → 시작 주소 → 경유 주소(후보끼리 번갈아). 앞 후보의 긴 이동 경로가
    뒤 후보의 목적지를 한도 밖으로 밀어내지 않게 한다. 개인정보가 든 주소는 뺀다."""
    order = [r.get("final_url") for r in results] + [r["url"] for r in results]
    navs = [r["_urls"] for r in results]
    for i in range(max((len(n) for n in navs), default=0)):
        order += [n[i] for n in navs if i < len(n)]
    return [u for u in dict.fromkeys(u for u in order if u) if not _has_pii(u)]


def _check_candidate_reputation(results: list[dict], first_hits: set[str], first_checked: set[str], s: Settings,
                                transport, writer: EvidenceWriter, emit: Callable[[dict], None]) -> None:
    """하위 조사에서 넘어간 경유·최종 주소도 평판을 조회한다(첫 조회는 후보 주소만 봤다).
    - 위험 일치는 첫 조회와 이번 조회를 합쳐 본다(이번 조회가 실패해도 앞서 확인한 위험은 지우지 않는다)
    - 일치하는데 AI 가 정상으로 봤으면 그 후보를 보류로 표시한다(원래 조사의 규칙과 같다)
    - 조회하지 못한 주소(실패·한도·개인정보)가 있으면 reputation_unchecked 로 표시한다(정상의 근거로 쓰지 않게)"""
    urls = _reputation_order(results)[:_SB_LIMIT]
    sb = lookup(urls, s.safebrowsing_api_key.get_secret_value(), transport=transport) if urls else {"status": "no_match", "matches": []}
    ok = sb.get("status") in ("match", "no_match")
    hits = {m.get("url") for m in sb.get("matches", [])} if sb.get("status") == "match" else set()
    checked = first_checked | (set(urls) if ok else set())
    _append(writer, emit, "candidate_safebrowsing", {**sb, "urls": urls})
    for r in results:
        mine = set(r.pop("_urls"))
        if (hits | first_hits) & mine:
            r["reputation_match"] = True
        if mine - checked:
            r["reputation_unchecked"] = True
        if r.get("reputation_match") and r.get("threat") == "benign":
            r["hold"] = True


def investigate(case_id: str, url: str, s: Settings, emit: Callable[[dict], None],
                decider: Decider | None = None, resolver=None, live: LivePublisher | None = None) -> dict:
    writer = EvidenceWriter(s.evidence_dir, case_id, make_sealer(s))
    emit({"type": "status", "status": "RUNNING", "reason": None})
    if resolver is None and s.resolver_url:
        resolver = remote_resolver(s.resolver_url)
    decider = decider or make_decider(s)
    sink = LiveSink(live, case_id, s.live_max_fps) if live else None
    try:
        return _investigate(case_id, url, s, emit, decider, resolver, sink, writer)
    finally:
        if sink:
            sink.close()


def _investigate(case_id: str, url: str, s: Settings, emit: Callable[[dict], None], decider: Decider, resolver, sink,
                 writer: EvidenceWriter) -> dict:
    result = asyncio.run(AgentRun(url, s, decider, writer, emit, resolver=resolver, live=sink).run())
    cands = result.candidates_found

    # Safe Browsing: 시작·경유·최종 URL 과 연관 후보 조회. 결과도 증거로 남긴다.
    # 격리망에서는 이 조회도 검문 프록시를 거친다
    transport = httpx.HTTPTransport(proxy=s.egress_proxy) if s.egress_proxy else None
    # 후보 주소 가운데 개인정보가 든 것은 외부로 보내지 않는다(페이지가 링크에 넣은 값이다)
    cand_urls = [c["url"] for c in cands[:10] if not _has_pii(c["url"])]
    # 시작·경유 주소도 같다: 연관 후보가 새 사건이 되면 페이지가 정한 주소가 시작 주소가 된다(Codex 지적)
    own = [u for u in dict.fromkeys([url, *result.nav_chain[-10:]]) if u]
    own_ok = [u for u in own if not _has_pii(u)]
    if sink:
        sink.activity("reputation")
    sb = lookup([*own_ok, *cand_urls], s.safebrowsing_api_key.get_secret_value(), transport=transport)
    _append(writer, emit, "safebrowsing", {**sb, "excluded_pii": sum(1 for c in cands[:10] if _has_pii(c["url"]))
                                           + len(own) - len(own_ok)})
    matched = sb.get("status") == "match"
    hits = {m.get("url") for m in sb.get("matches", [])} if matched else set()
    first_checked = set(cand_urls) if sb.get("status") in ("match", "no_match") else set()
    cand_hits = sorted(hits & {c["url"] for c in cands})

    # 페이지는 못 열었지만 평판 DB 가 위험 URL 로 표시한 경우: 사건을 묻지 않고 담당자 검토로 올린다.
    # 근거가 외부 평판 하나뿐이므로 위협 유형은 확정하지 않는다(threat 없음).
    # 회선이 도메인 이름을 보고 막은 경우(통신사·기관 차단)도 같다: 이미 차단 목록에 오른 사이트라는 근거다.
    # AI 가 정상으로 봤는데 평판 DB 가 이 주소나 연관 후보를 위험으로 표시하면 정상으로 끝내지 않고 보류한다
    status, reason = result.status, result.finish_reason
    benign = bool(result.threat) and result.threat.get("threat") == "benign"
    esc = None
    if status == "UNREACHABLE" and matched:
        status, reason = "REVIEW_REQUIRED", "unreachable_reputation_match"
        esc = {"from": result.status, "to": status, "reason": reason,
               "threat_types": sorted({m["threat_type"] for m in sb["matches"]})}
    elif status == "UNREACHABLE" and result.network_filtered:
        status, reason = "REVIEW_REQUIRED", "unreachable_network_filtered"
        esc = {"from": result.status, "to": status, "reason": reason, "threat_types": []}
    elif status == "COMPLETED" and benign and matched:
        only_cands = bool(cand_hits) and hits <= set(cand_hits)
        status, reason = "REVIEW_REQUIRED", "candidate_reputation_match" if only_cands else "reputation_match"
        esc = {"from": result.status, "to": status, "reason": reason,
               "threat_types": sorted({m["threat_type"] for m in sb["matches"]}), "urls": sorted(hits)[:10]}
    if esc:
        _append(writer, emit, "escalation", esc)

    # 연관 후보 하위 조사(1단계). 후보 목록·선택 이유를 먼저 남기고, 결과를 모아 다시 남긴다
    followup = _needs_followup(status, result.threat, matched)
    chosen = cands[:s.candidate_max] if followup else []
    # main: 원래 조사의 결과 상태. 원래 결과 이벤트의 상태·사유는 API 가 이 서명 기록에서 꺼낸다(이벤트 값을 믿지 않는다)
    _append(writer, emit, "candidates", {
        "found": [{**c, "reputation_match": c["url"] in hits} for c in cands], "followup": followup,
        "investigated": len(chosen), "main": {"status": status, "reason": reason}})
    if chosen and isinstance(result.threat, dict):
        # 원래 결과 먼저(related-sites PR 3): 하위 조사 전에 원래 사건의 결과를 보낸다. 담당자는 이때부터 판정할 수 있고,
        # 연관 사이트 조사는 뒤에서 계속한다. 종료 상태는 이 원래 결과와 같다(하위 조사는 판정을 바꾸지 않는다)
        # main_head: 원래 조사의 마지막 기록(바로 앞의 candidates). API 가 그 앞부분을 서명까지 검증해 판정에 묶는다
        emit({"type": "status", "status": "RUNNING", "phase": "related", "main": {"status": status, "reason": reason},
              "main_head": writer.head.seq,
              "threat": result.threat, "final_url": result.final_url, "safebrowsing": sb,
              "candidates": [{**c, "reputation_match": c["url"] in hits,
                              "reputation_unchecked": c["url"] not in first_checked} for c in cands]})
    results = _investigate_candidates(chosen, s, decider, writer, emit, resolver, sink) if chosen else []
    if results:
        if sink:
            sink.activity("reputation")
        _check_candidate_reputation(results, hits, first_checked, s, transport, writer, emit)
        _append(writer, emit, "candidate_results", {"results": results})
    by_url = {r["url"]: r for r in results}
    summary = []
    for c in cands:
        r = by_url.get(c["url"], {})
        summary.append({**c, "reputation_match": c["url"] in hits or bool(r.get("reputation_match")),
                        "reputation_unchecked": c["url"] not in first_checked or bool(r.get("reputation_unchecked")),
                        **{k: v for k, v in r.items() if k not in ("reputation_match", "reputation_unchecked")}})

    final = {
        "type": "status", "status": status, "reason": reason, "threat": result.threat,
        "final_url": result.final_url, "candidates": summary, "safebrowsing": sb,
        "head": {"seq": writer.head.seq, "hash": writer.head.hash},
    }
    emit(final)
    return final

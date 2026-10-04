"""실제 Chromium 으로 시험 페이지를 조사한다(사전준비 검증 항목).

- 버튼을 눌러 숨겨진 입금·개인정보 화면 도달
- 금지 요소 선택·실행 0건 (에이전트 로그 + 시험 서버 요청 기록 양쪽에서 확인)
- 사설 IP 이동 차단
- 증거 수정 시 검증 실패
"""

import json
import os
import uuid
from urllib.parse import urlsplit

import pytest

from safetrace.agent.runner import investigate, make_signer
from safetrace.evidence import Head, verify_case

pytestmark = pytest.mark.browser
BASE = "http://127.0.0.1:8900"


def run(url, settings, testpages):
    testpages.clear()
    cid = str(uuid.uuid4())
    events: list[dict] = []
    final = investigate(cid, url, settings, events.append)
    chain = [json.loads(x) for x in (settings.evidence_dir / cid / "chain.jsonl").read_text(encoding="utf-8").splitlines()]
    return cid, final, chain, events


def executed_clicks(chain):
    return [r for r in chain if r["kind"] == "action"]


def assert_no_forbidden(chain, testpages):
    for r in chain:
        if r["kind"] == "gate" and r["data"]["allowed"]:
            assert not r["data"]["reason"].startswith("forbidden")
    assert testpages.forbidden_hits() == []


def test_gamble_reaches_hidden_deposit_screen(settings, testpages):
    cid, final, chain, events = run(f"{BASE}/gamble/", settings, testpages)
    urls = [urlsplit(r["data"]["url"]).path for r in chain if r["kind"] == "observe"]
    assert "/gamble/deposit.html" in urls, urls
    assert final["threat"]["threat"] == "illegal_gambling"
    # 127.0.0.1 → localhost 로 넘어간 경유 도메인이 후보로 기록
    assert "localhost" in final["candidates"]
    # 팝업 닫기 수행
    assert any(r["kind"] == "action" and r["data"]["action"] == "close_popup" for r in chain)
    # 입력칸·제출·결제 버튼은 선택지에 없음
    deposit_obs = next(r for r in chain if r["kind"] == "observe" and r["data"]["url"].endswith("deposit.html"))
    texts = [c["text"] for c in deposit_obs["data"]["candidates"]]
    assert not any("결제" in t or "충전 신청" in t for t in texts)
    assert any(f.startswith("input") for f in deposit_obs["data"]["forbidden"])
    assert_no_forbidden(chain, testpages)
    # 계좌번호 원문은 증거의 텍스트 발췌에도 마스킹
    assert "123-456-789012" not in json.dumps([r["data"] for r in chain], ensure_ascii=False)
    # 증거 무결성
    head = Head(final["head"]["seq"], final["head"]["hash"])
    assert verify_case(settings.evidence_dir, cid, make_signer(settings), head).ok
    assert any(e["type"] == "status" and e["status"] == "RUNNING" for e in events)


def test_phishing_flow(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/phish/", settings, testpages)
    assert any(r["kind"] == "observe" and r["data"]["url"].endswith("track.html") for r in chain)
    assert final["threat"]["threat"] == "phishing"
    assert_no_forbidden(chain, testpages)


def test_scam_hidden_layer(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/scam/", settings, testpages)
    last_obs = [r for r in chain if r["kind"] == "observe"][-1]
    assert "가입비" in last_obs["data"]["text_excerpt"]
    assert "010-9876-5432" not in last_obs["data"]["text_excerpt"]
    assert final["threat"]["threat"] == "scam"


def test_benign_not_flagged(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/benign/", settings, testpages)
    assert final["threat"]["threat"] == "benign"
    assert_no_forbidden(chain, testpages)


def test_image_button_ocr(settings, testpages):
    from safetrace.agent.ocr import get_ocr

    if not get_ocr().available:
        pytest.skip("local OCR not installed")
    _, final, chain, _ = run(f"{BASE}/imgbtn/", settings, testpages)
    first = next(r for r in chain if r["kind"] == "observe")
    assert any("ENTER" in c["text"].upper() for c in first["data"]["candidates"]), first["data"]["candidates"]
    assert any(r["kind"] == "observe" and r["data"]["url"].endswith("next.html") for r in chain)


def test_hidden_image_button_does_not_stall_observe(settings, testpages):
    """관찰 뒤 숨는 이미지 버튼(캐러셀), 숨은 이미지가 먼저 오는 버튼: 요소마다 30초씩 멈추지 않는다."""
    from datetime import datetime

    from safetrace.agent.ocr import get_ocr

    if not get_ocr().available:
        pytest.skip("local OCR not installed")
    settings.max_steps = 1
    _, _, chain, _ = run(f"{BASE}/imgbtn/hidden.html", settings, testpages)
    ts = {r["kind"]: datetime.fromisoformat(r["ts"]) for r in reversed(chain)}
    first = next(r for r in chain if r["kind"] == "observe")
    assert (ts["observe"] - ts["navigation"]).total_seconds() < 15, "관찰이 숨은 요소 스크린샷에서 멈췄다"
    texts = [c["text"].upper() for c in first["data"]["candidates"]]
    assert any("ENTER" in t for t in texts), first["data"]  # (나) 보이는 두 번째 이미지를 읽는다
    assert "unreadable_image:a" in first["data"]["forbidden"], first["data"]  # (가) 숨은 버튼은 누르지 않는다


def _slow_capture(monkeypatch, seconds=0.5):
    """이미지 버튼 캡처를 일부러 느리게: 시험 PC 속도와 관계없이 OCR 이 조사 시간을 넘기는 상황을 만든다.
    (창 단위 스크롤 한 번과 요소별 캡처 한 번을 각각 seconds 만큼 늦춘다)"""
    import asyncio

    from safetrace.agent import loop as loopmod

    ms = int(seconds * 1000)
    monkeypatch.setattr(loopmod, "_SCROLL_TO_JS",
                        "(y) => new Promise((r) => { window.scrollTo(0, y); setTimeout(r, %d); })" % ms)
    orig = loopmod.AgentRun._capture_element

    async def slow(self, *a, **k):
        await asyncio.sleep(seconds)
        return await orig(self, *a, **k)

    monkeypatch.setattr(loopmod.AgentRun, "_capture_element", slow)


def test_time_budget_holds_on_many_image_buttons(settings, testpages, monkeypatch):
    """이미지 버튼이 아주 많아도 조사 제한 시간을 크게 넘지 않는다: 마감이 되면 OCR 을 멈추고 그 관찰로 끝낸다.
    읽지 못한 이미지 버튼은 선택지에 올리지 않는다."""
    from datetime import datetime

    from safetrace.agent.ocr import get_ocr

    if not get_ocr().available:
        pytest.skip("local OCR not installed")
    settings.max_seconds = 12
    _slow_capture(monkeypatch)  # 60개 × 0.5초 > 12초
    _, final, chain, _ = run(f"{BASE}/imgbtn/many.html", settings, testpages)
    ts = lambda kind: datetime.fromisoformat(next(r for r in chain if r["kind"] == kind)["ts"])  # noqa: E731
    assert (ts("finish") - ts("start")).total_seconds() < settings.max_seconds + 8
    finish = next(r for r in chain if r["kind"] == "finish")
    assert finish["data"]["reason"] == "time_budget", finish["data"]
    obs = [r for r in chain if r["kind"] == "observe"]
    assert obs and obs[-1]["data"]["ocr_skipped"] > 0, obs[-1]["data"]
    # 읽은 버튼만 선택지(화면 안 큰 배너부터 읽음), 판단·행동 없이 끝남
    first = obs[0]["data"]
    assert first["candidates"] and all("ENTER" in c["text"].upper() for c in first["candidates"]), first
    assert not any(r["kind"] == "decision" and r["data"]["step"] == obs[-1]["data"]["step"] for r in chain)


def test_many_image_buttons_read_in_one_pass(settings, testpages):
    """이미지 버튼 60개: 캡처를 모자이크로 한 번에 읽어 관찰당 상한 안에 모두 읽는다(한 장씩 읽을 때는 약 48초)."""
    from datetime import datetime

    from safetrace.agent.ocr import get_ocr

    if not get_ocr().available:
        pytest.skip("local OCR not installed")
    settings.max_steps = 1
    _, _, chain, _ = run(f"{BASE}/imgbtn/many.html", settings, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    nav = next(r for r in chain if r["kind"] == "navigation")
    took = (datetime.fromisoformat(obs["ts"]) - datetime.fromisoformat(nav["ts"])).total_seconds()
    assert obs["data"]["ocr_skipped"] == 0, obs["data"]
    texts = [c["text"].upper() for c in obs["data"]["candidates"]]
    assert len(texts) == settings.max_candidates and all("ENTER" in t for t in texts), texts
    assert took < settings.ocr_observe_max_seconds, took


def test_ocr_capped_per_observation(settings, testpages, monkeypatch):
    """관찰 한 번의 OCR 상한: 첫 화면이 조사 시간을 다 쓰지 않고 다음 단계로 넘어간다."""
    from datetime import datetime

    from safetrace.agent.ocr import get_ocr

    if not get_ocr().available:
        pytest.skip("local OCR not installed")
    settings.max_steps = 1
    settings.ocr_observe_max_seconds = 2
    _slow_capture(monkeypatch)  # 60개 × 0.5초 > 2초
    _, _, chain, _ = run(f"{BASE}/imgbtn/many.html", settings, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    nav = next(r for r in chain if r["kind"] == "navigation")
    took = (datetime.fromisoformat(obs["ts"]) - datetime.fromisoformat(nav["ts"])).total_seconds()
    assert took < 2 + 8, took
    assert obs["data"]["ocr_skipped"] > 0 and obs["data"]["candidates"], obs["data"]


def test_korean_image_button_ocr(settings, testpages):
    """한국어 OCR 모델(ST_OCR_REC_MODEL)이 있을 때: 한글 이미지 버튼을 읽고, 이미지 '결제' 버튼은 선택지에서 뺀다."""
    from safetrace.agent.ocr import get_ocr

    if not get_ocr().available or not os.environ.get("ST_OCR_REC_MODEL"):
        pytest.skip("Korean OCR model not configured (tools/fetch_ocr_model.py)")
    _, final, chain, _ = run(f"{BASE}/imgbtn/ko.html", settings, testpages)
    first = next(r for r in chain if r["kind"] == "observe")
    texts = [c["text"] for c in first["data"]["candidates"]]
    assert any("다음" in t for t in texts), first["data"]
    assert not any("결제" in t for t in texts), texts
    assert any(r["kind"] == "observe" and r["data"]["url"].endswith("next.html") for r in chain)
    assert_no_forbidden(chain, testpages)


# ── 공격 시나리오 ────────────────────────────────────────
def test_prompt_injection_cannot_cause_forbidden_action(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/injection.html", settings, testpages)
    assert_no_forbidden(chain, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    assert not any("결제" in c["text"] for c in obs["data"]["candidates"])


def test_internal_links_blocked(settings, testpages):
    settings.max_steps = 6
    _, final, chain, _ = run(f"{BASE}/attack/ssrf.html", settings, testpages)
    gates = [r["data"] for r in chain if r["kind"] == "gate"]
    assert gates and all(not g["allowed"] and g["reason"].startswith("ssrf") for g in gates), gates
    assert not any(r["kind"] == "action" for r in chain)
    # 1x1 추적 이미지(192.168.0.1)도 네트워크 단에서 차단
    assert not any(urlsplit(r["data"]["url"]).hostname in {"169.254.169.254", "10.0.0.1"}
                   for r in chain if r["kind"] == "observe")


def test_internal_auto_redirect_blocked(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/redirect-internal.html", settings, testpages)
    blocked = [r["data"] for r in chain if r["kind"] == "blocked_request"]
    assert any("169.254.169.254" in b["url"] and b["reason"].startswith("ssrf") for b in blocked)


@pytest.fixture
def egress_proxy():
    """운영과 같은 검문 프록시(시험 서버만 허용). 주소를 돌려준다."""
    import asyncio
    import threading

    from safetrace.proxy.egress import EgressProxy, Policy

    loop = asyncio.new_event_loop()
    box, ready = {}, threading.Event()

    async def start():
        box["srv"] = await asyncio.start_server(EgressProxy(Policy({80, 443}, {"127.0.0.1:8900"})).handle,
                                                "127.0.0.1", 0)
        box["port"] = box["srv"].sockets[0].getsockname()[1]
        ready.set()

    threading.Thread(target=lambda: (loop.run_until_complete(start()), loop.run_forever()), daemon=True).start()
    ready.wait(5)
    yield f"http://127.0.0.1:{box['port']}"
    loop.call_soon_threadsafe(box["srv"].close)
    loop.call_soon_threadsafe(loop.stop)


@pytest.mark.parametrize("page, host, reason, proxied", [
    ("short.html", "name.n-payost.invalid", "net:ERR_NAME_NOT_RESOLVED", False),  # 서버 리다이렉트 → 연결 실패
    ("short.html", "name.n-payost.invalid", "egress:dns_failure", True),         # 같은 경우, 검문 프록시가 거부 응답
    ("short-js.html", "name.n-payviv.invalid", "ssrf:", False),                    # 스크립트 이동 → 요청 검사에서 차단
    ("short-link.html", "name.n-paycaro.invalid", "ssrf:", False),                 # 링크 목적지가 게이트에서 막혀 누르지 않음
    ("check.html", "name.n-paypak.invalid", "ssrf:", False),                       # 확인 화면의 버튼이 스크립트로 이동 → 차단
])
def test_dead_destination_reaches_threat_judgment(settings, testpages, request, page, host, reason, proxied):
    """이미 사라진 피싱 도착지는 화면이 없어도 도메인 이름을 위협 판단에 넘긴다(단축 URL 경유 사례)."""
    from safetrace.agent.runner import make_decider

    if proxied:
        settings.egress_proxy = request.getfixturevalue("egress_proxy")

    class Capture:
        def __init__(self):
            self.inner, self.req = make_decider(settings), None

        def action(self, state):
            return self.inner.action(state)

        def threat(self, req):
            self.req = req
            return self.inner.threat(req)

    settings.max_steps = 4
    testpages.clear()
    cid, d = str(uuid.uuid4()), Capture()
    investigate(cid, f"{BASE}/phish/{page}", settings, lambda e: None, decider=d)
    got = [(b.host, b.reason) for b in d.req.blocked_destinations]
    assert len(got) == 1 and got[0][0] == host and got[0][1].startswith(reason), got
    # 열리지 않은 목적지는 열린 페이지 도메인(리다이렉트 수 계산)과 섞지 않는다(프록시 거부 화면도 열린 페이지가 아니다)
    assert host not in d.req.domains
    chain = [json.loads(x) for x in (settings.evidence_dir / cid / "chain.jsonl").read_text(encoding="utf-8").splitlines()]
    fin = next(r["data"] for r in chain if r["kind"] == "finish")
    assert [b["host"] for b in fin["blocked_destinations"]] == [host]
    # 막다른 곳(오류 화면·프록시 거부 화면)은 관찰하지 않고, 같은 목적지를 오가며 반복하지 않는다
    observed = [r["data"]["url"] for r in chain if r["kind"] == "observe"]
    assert all(u.startswith(BASE) for u in observed), observed
    assert fin["reason"] != "loop_detected"
    assert fin["final_url"].startswith(f"{BASE}/phish/"), fin["final_url"]
    assert all(urlsplit(u).hostname in {"127.0.0.1", "localhost"} for u in fin["nav_chain"]), fin["nav_chain"]


def test_dead_end_link_is_not_retried(settings, testpages):
    """확인 화면에서 누른 버튼이 사라진 목적지로 가면 원래 화면으로 돌아오고, 그 버튼은 다시 내놓지 않는다."""
    settings.max_steps = 6
    _, final, chain, _ = run(f"{BASE}/phish/check.html", settings, testpages)
    dead = [r["data"] for r in chain if r["kind"] == "dead_end"]
    assert len(dead) == 1 and dead[0]["destinations"] == ["name.n-paypak.invalid"], dead
    obs = [r["data"] for r in chain if r["kind"] == "observe"]
    assert [urlsplit(o["url"]).path for o in obs] == ["/phish/check.html"] * len(obs) and len(obs) == 2, obs
    assert not any("계속 이동하기" in c["text"] for c in obs[-1]["candidates"])
    assert len(executed_clicks(chain)) == 1


def test_site_moving_itself_to_dead_end_finishes(settings, testpages):
    """첫 화면이 스스로 사라진 목적지로 옮기면 오류 화면에서 헛되이 움직이지 않고 끝낸다."""
    _, final, chain, _ = run(f"{BASE}/phish/short-js.html", settings, testpages)
    fin = next(r["data"] for r in chain if r["kind"] == "finish")
    assert fin["reason"] in {"dead_end", "agent_finished"}, fin
    assert not any(r["kind"] == "action" and "chrome-error" in r["data"]["result_url"] for r in chain)


@pytest.mark.parametrize("decision", ["low_confidence", "finish"])
def test_waits_for_auto_redirect_before_finishing(settings, testpages, decision):
    """단축 URL 의 대기 화면("Redirecting... Please wait")에서 끝내려 하면 스스로 넘어갈 때까지 잠시 기다려
    목적지를 기록한다(goo.su: 몇 초 뒤 사라진 피싱 도메인으로 이동)."""
    from safetrace.decision.schema import ActionDecision, ActionKind, Threat, ThreatDecision

    class Stopper:
        req = None

        def action(self, state):
            if decision == "finish":
                return ActionDecision(choice="finish", probabilities={"finish": 0.9}, model="t", provider="t",
                                      latency_ms=0, action=ActionKind.FINISH)
            return ActionDecision(choice="scroll", probabilities={"scroll": 0.3, "finish": 0.25}, model="t",
                                  provider="t", latency_ms=0, action=ActionKind.SCROLL)

        def threat(self, req):
            self.req = req
            return ThreatDecision(choice="unknown", probabilities={"unknown": 0.5}, model="t", provider="t",
                                  latency_ms=0, threat=Threat.UNKNOWN, hold=True)

    testpages.clear()
    cid, d = str(uuid.uuid4()), Stopper()
    final = investigate(cid, f"{BASE}/phish/short-wait.html", settings, lambda e: None, decider=d)
    assert final["reason"] == "dead_end", final
    assert [b.host for b in d.req.blocked_destinations] == ["name.n-paywait.invalid"]
    chain = [json.loads(x) for x in (settings.evidence_dir / cid / "chain.jsonl").read_text(encoding="utf-8").splitlines()]
    waits = [r["data"] for r in chain if r["kind"] == "wait_redirect"]
    assert len(waits) == 1 and waits[0]["moved"] and waits[0]["destinations"] == ["name.n-paywait.invalid"], waits


def test_no_wait_on_ordinary_page(settings, testpages):
    """대기 문구가 없는 화면에서 끝낼 때는 기다리지 않는다(조사가 길어지지 않게)."""
    _, final, chain, _ = run(f"{BASE}/benign/", settings, testpages)
    assert not any(r["kind"] == "wait_redirect" for r in chain)


def test_shortener_warning_judged_threat_with_review(settings, testpages):
    """단축 URL 서비스가 위험 링크라며 자동 이동을 막은 화면: 목적지를 못 봐도 위협(담당자 검토)으로 본다."""
    settings.max_steps = 3
    _, final, chain, _ = run(f"{BASE}/phish/short-warn.html", settings, testpages)
    assert final["threat"]["threat"] == "phishing" and final["threat"]["hold"], final["threat"]
    assert final["status"] == "REVIEW_REQUIRED"
    assert_no_forbidden(chain, testpages)


@pytest.mark.parametrize("proxied", [False, True])
def test_first_load_redirect_to_dead_destination_is_judged(settings, testpages, request, proxied):
    """단축 URL 이 첫 접속에서 바로 사라진 목적지로 넘기면 접속 불가가 아니라 막다른 곳: 목적지 이름으로 판단한다."""
    if proxied:
        settings.egress_proxy = request.getfixturevalue("egress_proxy")
    _, final, chain, _ = run(f"{BASE}/r/npay", settings, testpages)
    assert final["status"] != "UNREACHABLE" and final["reason"] == "dead_end", final
    assert final["threat"] is not None
    fin = next(r["data"] for r in chain if r["kind"] == "finish")
    assert [b["host"] for b in fin["blocked_destinations"]] == ["name.n-payost.invalid"]
    assert fin["final_url"] == f"{BASE}/r/npay"
    assert not any(r["kind"] == "unreachable" for r in chain)


def test_start_url_private_blocked(settings, testpages):
    _, final, chain, _ = run("http://169.254.169.254/latest/meta-data/", settings, testpages)
    assert final["status"] == "BLOCKED"
    assert [r["kind"] for r in chain][:1] == ["start"]


def test_loop_ends_by_budget(settings, testpages):
    settings.max_steps = 8
    _, final, chain, _ = run(f"{BASE}/attack/loop.html", settings, testpages)
    assert final["status"] in {"COMPLETED", "REVIEW_REQUIRED"}
    assert len(executed_clicks(chain)) <= 8


def test_big_dom_candidates_capped(settings, testpages):
    settings.max_steps = 2
    _, final, chain, _ = run(f"{BASE}/attack/bigdom.html", settings, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    assert len(obs["data"]["candidates"]) <= 50


def test_download_lure_blocked(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/download.html", settings, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    assert obs["data"]["candidates"] == [] or all("설치" not in c["text"] for c in obs["data"]["candidates"])
    assert any(f.startswith("download") for f in obs["data"]["forbidden"])
    assert_no_forbidden(chain, testpages)


def test_auto_post_blocked(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/autopost.html", settings, testpages)
    assert any(r["kind"] == "blocked_request" and r["data"]["reason"].startswith("method") for r in chain)
    assert testpages.forbidden_hits() == []


def test_slow_first_screen_is_investigated_not_unreachable(settings, testpages):
    """응답은 왔지만 화면 구성이 첫 접속 제한보다 늦는 사이트는 접속 불가로 끝내지 않고 조사한다."""
    import server

    settings.nav_timeout_ms = int(server.SLOW_SECONDS * 1000 / 2)
    settings.max_steps = 2
    _, final, chain, _ = run(f"{BASE}/slow/dom.html", settings, testpages)
    assert final["status"] != "UNREACHABLE", final
    nav = next(r["data"] for r in chain if r["kind"] == "navigation")
    assert nav["status"] == 200 and nav["dom_ready"] is False
    obs = next(r["data"] for r in chain if r["kind"] == "observe")
    assert "당첨금 수령하기" in [c["text"] for c in obs["candidates"]]  # 늦게 온 나머지도 결국 본다


def test_no_response_within_limit_is_unreachable(settings, testpages):
    import server

    settings.nav_timeout_ms = int(server.SLOW_SECONDS * 1000 / 2)
    _, final, chain, _ = run(f"{BASE}/slow/noresp", settings, testpages)
    assert (final["status"], final["reason"]) == ("UNREACHABLE", "goto_failed")
    assert next(r["data"] for r in chain if r["kind"] == "unreachable")["category"] == "timeout"


def test_dialogs_dismissed(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/dialogs.html", settings, testpages)
    assert final["status"] in {"COMPLETED", "REVIEW_REQUIRED"}
    assert any(r["kind"] == "dialog" for r in chain)


def test_swap_after_observe_blocked(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/swap.html", settings, testpages)
    gates = [r["data"] for r in chain if r["kind"] == "gate"]
    assert any(g["reason"] in {"element_changed", "forbidden:payment"} and not g["allowed"] for g in gates), gates
    assert_no_forbidden(chain, testpages)


def test_non_http_schemes_excluded(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/scheme.html", settings, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    assert obs["data"]["candidates"] == []
    assert {f.split(":")[1] for f in obs["data"]["forbidden"]} >= {"tel", "intent", "file", "sms"}


def test_tampered_evidence_detected_end_to_end(settings, testpages):
    cid, final, chain, _ = run(f"{BASE}/benign/", settings, testpages)
    head = Head(final["head"]["seq"], final["head"]["hash"])
    shot = next(n for r in chain for n in r["files"])
    (settings.evidence_dir / cid / "files" / shot).write_bytes(b"edited")
    res = verify_case(settings.evidence_dir, cid, make_signer(settings), head)
    assert not res.ok and any("file_modified" in e for e in res.errors)


# ── 접속 불가 + 평판 일치 → 담당자 검토 ─────────────────────
CLOSED = "127.0.0.1:8909"  # 아무것도 듣지 않는 포트(시험 허용 목록에만 넣음)


@pytest.mark.parametrize("sb, status, reason", [
    ({"status": "match", "matches": [{"url": f"http://{CLOSED}/", "threat_type": "SOCIAL_ENGINEERING"}]},
     "REVIEW_REQUIRED", "unreachable_reputation_match"),
    ({"status": "no_match", "matches": []}, "UNREACHABLE", "goto_failed"),
    ({"status": "not_configured", "matches": []}, "UNREACHABLE", "goto_failed"),
])
def test_unreachable_escalates_only_on_reputation_match(settings, testpages, monkeypatch, sb, status, reason):
    from safetrace.agent import runner

    monkeypatch.setattr(runner, "lookup", lambda *a, **k: sb)
    settings.test_allowlist = [*settings.test_allowlist, CLOSED]
    _, final, chain, _ = run(f"http://{CLOSED}/", settings, testpages)
    assert (final["status"], final["reason"]) == (status, reason)
    assert final["threat"] is None  # 평판만으로 위협 유형을 확정하지 않는다
    unreachable = next(r for r in chain if r["kind"] == "unreachable")["data"]
    assert unreachable["net_error"] == "ERR_CONNECTION_REFUSED" and unreachable["category"] == "connection_refused"
    esc = [r for r in chain if r["kind"] == "escalation"]
    if status == "REVIEW_REQUIRED":
        assert esc and esc[0]["data"]["threat_types"] == ["SOCIAL_ENGINEERING"]
    else:
        assert not esc


def test_unreachable_by_name_blocking_escalates(settings, testpages, monkeypatch):
    """도메인 이름만 보고 연결을 끊는 회선(통신사 차단): 접속 불가로 묻지 않고 담당자 검토로 올린다."""
    from safetrace.agent import runner
    from tests.test_netfilter import _serve

    monkeypatch.setattr(runner, "lookup", lambda *a, **k: {"status": "no_match", "matches": []})
    srv, port = _serve("name_block", tls=False)
    try:
        settings.test_allowlist = [*settings.test_allowlist, f"localhost:{port}"]
        _, final, chain, _ = run(f"http://localhost:{port}/", settings, testpages)
    finally:
        srv.close()
    assert (final["status"], final["reason"]) == ("REVIEW_REQUIRED", "unreachable_network_filtered"), final
    assert final["threat"] is None  # 차단 사실만으로 위협 유형을 확정하지 않는다
    unreachable = next(r for r in chain if r["kind"] == "unreachable")["data"]
    assert unreachable["network_filter"]["filtered"], unreachable
    assert [r["data"]["reason"] for r in chain if r["kind"] == "escalation"] == ["unreachable_network_filtered"]


def test_unreadable_image_button_not_offered(settings, testpages):
    """OCR 로 글자를 읽지 못한 이미지 버튼(여기서는 OCR 꺼짐)은 선택지에 오르지 않는다: 이미지 '결제' 버튼 대비."""
    settings.ocr_enabled = False
    _, final, chain, _ = run(f"{BASE}/imgbtn/ko.html", settings, testpages)
    first = next(r for r in chain if r["kind"] == "observe")
    assert first["data"]["candidates"] == []
    assert sum(f.startswith("unreadable_image") for f in first["data"]["forbidden"]) == 2
    assert_no_forbidden(chain, testpages)


def test_popup_covered_button_marked(settings, testpages):
    """팝업에 가려진 버튼은 covered 로 표시되고, Jev 선택지 문구에도 드러난다."""
    from safetrace.decision.schema import Candidate, PageState, action_options

    _, final, chain, _ = run(f"{BASE}/gamble/", settings, testpages)
    casino = next(r["data"] for r in chain if r["kind"] == "observe" and r["data"]["url"].endswith("casino.html"))
    start = next(c for c in casino["candidates"] if "게임 시작" in c["text"])
    close = next(c for c in casino["candidates"] if "닫기" in c["text"])
    assert start["covered"] is True and close["covered"] is False
    opts = action_options(PageState(step=1, url="http://x.example/", title="", text="",
                                    candidates=[Candidate(**start)], has_popup=True))
    assert "가려져" in opts[f"click_{start['id']}"]


@pytest.mark.parametrize("threat_prob, hold, status", [(0.92, False, "COMPLETED"), (0.40, True, "REVIEW_REQUIRED")])
def test_low_confidence_action_status_follows_threat(settings, testpages, threat_prob, hold, status):
    """행동 확신도 부족은 탐색만 멈추고, 최종 상태는 위협 판단(hold)이 정한다."""
    from safetrace.decision.schema import ActionDecision, ActionKind, Threat, ThreatDecision

    class LowConfidence:
        def action(self, state):
            return ActionDecision(choice="scroll", probabilities={"scroll": 0.3, "finish": 0.25}, model="t",
                                  provider="t", latency_ms=0, action=ActionKind.SCROLL)

        def threat(self, req):
            return ThreatDecision(choice="benign", probabilities={"benign": threat_prob}, model="t", provider="t",
                                  latency_ms=0, threat=Threat.BENIGN, hold=hold)

    testpages.clear()
    cid = str(uuid.uuid4())
    final = investigate(cid, f"{BASE}/benign/", settings, lambda e: None, decider=LowConfidence())
    assert (final["status"], final["reason"]) == (status, "low_confidence_action")


@pytest.fixture
def slow_testpages():
    """페이지 응답이 1.2초씩 느린 시험 서버(/smish/ 만). 느린 사이트에서 새 창·이동을 놓치지 않는지 본다."""
    import server  # testpages/server.py

    srv, rec = server.start(8901, smish_delay=1.2)
    yield rec
    srv.shutdown()


def test_long_smishing_flow(settings, slow_testpages):
    """긴 스미싱 시나리오(시연용, 느린 응답): 팝업 닫기 → 도메인 경유 → 숨은 안내 → 새 창 → 앱 설치 유도 → 카드 입력 화면."""
    testpages = slow_testpages
    settings.max_steps = 15
    settings.test_allowlist = ["127.0.0.1:8901", "localhost:8901"]
    _, final, chain, _ = run("http://127.0.0.1:8901/smish/", settings, testpages)
    paths = [urlsplit(r["data"]["url"]).path for r in chain if r["kind"] == "observe"]
    for p in ("/smish/track.html", "/smish/address.html", "/smish/notice.html", "/smish/carrier.html",
              "/smish/app.html", "/smish/guide.html", "/smish/fee.html"):
        assert p in paths, (p, paths)
    assert any(r["kind"] == "new_window" for r in chain)
    assert "localhost" in final["candidates"]  # 127.0.0.1 → localhost 경유 도메인
    app = next(r["data"] for r in chain if r["kind"] == "observe" and r["data"]["url"].split("?")[0].endswith("app.html"))
    assert any(f.startswith("download") for f in app["forbidden"])  # apk 링크는 선택지에서 빠짐
    assert_no_forbidden(chain, testpages)


def _png_size(path):
    b = path.read_bytes()[16:24]
    return int.from_bytes(b[:4], "big"), int.from_bytes(b[4:], "big")


def test_observe_screenshot_is_full_page_and_capped(settings, testpages):
    """관찰 화면은 페이지 전체를 캡처하고(보이는 창 800px 보다 김), 설정한 최대 높이에서 자른다."""
    cid, final, chain, _ = run(f"{BASE}/smish/guide.html", settings, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    w, h = _png_size(settings.evidence_dir / cid / "files" / next(iter(obs["files"])))
    assert w == 1280 and h > 800, (w, h)

    settings.screenshot_max_height = 900
    cid, final, chain, _ = run(f"{BASE}/smish/guide.html", settings, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    assert _png_size(settings.evidence_dir / cid / "files" / next(iter(obs["files"])))[1] == 900
    act = next(r for r in chain if r["kind"] == "action")  # 클릭 전후는 보이는 창만
    assert all(_png_size(settings.evidence_dir / cid / "files" / f)[1] == 800 for f in act["files"])


def test_recording_is_full_size_and_follows_new_window(settings, testpages):
    """조사 녹화: 1280×800 그대로, 새 창으로 옮겨도 한 영상에 이어서 담긴다(화면 전송 → ffmpeg)."""
    from safetrace.agent.recorder import find_ffmpeg

    if not find_ffmpeg():
        pytest.skip("ffmpeg not available")
    settings.record_video = True
    settings.max_steps = 15
    cid, final, chain, _ = run(f"{BASE}/smish/", settings, testpages)
    rec = next(r for r in chain if r["kind"] == "recording")
    assert rec["data"]["source"] == "cdp-screencast"
    assert (rec["data"]["width"], rec["data"]["height"]) == (1280, 800)
    assert any(r["kind"] == "new_window" for r in chain)
    path = settings.evidence_dir / cid / "files" / "recording.webm"
    assert path.stat().st_size > 10_000
    # 가변 프레임률: 바뀐 화면 + 1초 heartbeat + 끝 프레임만 담고, 시각은 브라우저 캡처 시각을 쓴다
    data = rec["data"]
    assert data["fps_mode"] == "vfr"
    assert data["frames"] == data["screencast_frames"] + data["heartbeat_frames"] + 1, data
    assert data["cdp_timestamps"] == data["screencast_frames"] > 0, data
    from datetime import datetime

    from .test_recorder import probe

    duration, times = probe(path)
    assert len(times) == data["frames"] and times == sorted(times)
    assert duration == pytest.approx(data["duration_s"], abs=0.01)
    # 영상 길이 = 녹화 시간(조사 시간과 어긋나지 않음). 녹화는 브라우저를 띄운 뒤 시작해 finish 뒤에 끝난다
    ts = lambda kind: datetime.fromisoformat(next(r for r in chain if r["kind"] == kind)["ts"])  # noqa: E731
    investigated = (ts("finish") - ts("start")).total_seconds()
    until_saved = (ts("recording") - ts("start")).total_seconds()
    assert investigated - 5 <= duration <= until_saved, (data, investigated, until_saved)
    verify = verify_case(settings.evidence_dir, cid, make_signer(settings), None)
    assert verify.ok, verify.errors

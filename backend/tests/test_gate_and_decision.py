import json

import httpx
import pytest

from safetrace.agent.gate import Budget, ElementInfo, SafetyGate, classify_forbidden
from safetrace.decision.engine import Engine, NoProviderAvailable
from safetrace.decision.providers import JevProvider, ProviderError, RuleProvider, validate_choice
from safetrace.decision.schema import ActionRequest, Candidate, PageState, ThreatRequest, action_options
from safetrace.masking import mask_pii, mask_secrets


# ── 금지 요소 분류 ─────────────────────────────────────
@pytest.mark.parametrize("el,reason", [
    (ElementInfo(tag="input", type="text"), "input"),
    (ElementInfo(tag="input", type="password"), "input"),
    (ElementInfo(tag="input", type="file"), "input"),
    (ElementInfo(tag="input", type=""), "input"),
    (ElementInfo(tag="textarea"), "input"),
    (ElementInfo(tag="select"), "input"),
    (ElementInfo(tag="div", editable=True), "input"),
    (ElementInfo(tag="input", type="submit", in_form=True), "submit"),
    (ElementInfo(tag="button", type="submit", in_form=True, text="확인"), "submit"),
    (ElementInfo(tag="a", href="https://x.example/app.apk", text="앱 받기"), "download"),
    (ElementInfo(tag="a", href="https://x.example/f", has_download=True), "download"),
    (ElementInfo(tag="a", href="tel:0101234", text="상담"), "scheme:tel"),
    (ElementInfo(tag="a", href="intent://x#Intent;end", text="앱"), "scheme:intent"),
    (ElementInfo(tag="a", href="file:///etc/passwd", text="다음"), "scheme:file"),
    (ElementInfo(tag="button", type="button", text="결제하기"), "payment"),
    (ElementInfo(tag="div", text="충전 신청"), "payment"),
    (ElementInfo(tag="button", type="button", text="송금"), "payment"),
    (ElementInfo(tag="a", href="https://x.example/", text="로그인"), "login"),
    (ElementInfo(tag="button", type="button", text="본인인증 하기"), "login"),
])
def test_forbidden(el, reason):
    assert classify_forbidden(el) == reason


@pytest.mark.parametrize("el", [
    ElementInfo(tag="a", href="https://x.example/next", text="신청하기"),
    ElementInfo(tag="button", type="submit", in_form=False, text="다음"),  # 폼 밖 button 은 제출 불가
    ElementInfo(tag="div", text="19세 이상 입장"),
    ElementInfo(tag="button", type="button", in_form=True, text="닫기"),
])
def test_allowed(el):
    assert classify_forbidden(el) is None


def test_gate_rejects_unoffered_changed_and_private():
    gate = SafetyGate([80, 443], [], resolver=lambda h, p: ("10.0.0.1",) if h == "internal.example" else ("93.184.216.34",))
    a = ElementInfo(tag="a", href="https://ok.example/", text="다음")
    assert gate.check_click({"e1"}, "e2", a, a).reason == "not_offered"
    assert gate.check_click({"e1"}, "e1", a, None).reason == "element_gone"
    swapped = ElementInfo(tag="a", href="https://ok.example/pay", text="결제하기")
    assert gate.check_click({"e1"}, "e1", a, swapped).reason == "element_changed"
    internal = ElementInfo(tag="a", href="https://internal.example/", text="다음")
    assert gate.check_click({"e1"}, "e1", internal, internal).reason == "ssrf:non_public_ip"
    assert gate.check_click({"e1"}, "e1", a, a).allowed


def test_budget():
    b = Budget(max_steps=2, max_seconds=100, max_same_state=1)
    assert b.observe_state("k") is None
    assert b.observe_state("k") == "loop_detected"
    b.steps = 2
    assert b.exceeded() == "step_budget"
    assert 99 < b.remaining() <= 100
    b.started -= 101
    assert b.remaining() < 0


# ── 선택지·응답 검증 ─────────────────────────────────────
def _state(n=3, popup=False, step=1):
    return PageState(step=step, url="https://x.example/", title="t", text="본문",
                     candidates=[Candidate(id=f"e{i}", tag="a", text=f"버튼{i}") for i in range(n)],
                     has_popup=popup)


def test_action_options_are_closed_set():
    opts = action_options(_state(popup=True))
    assert set(opts) == {"click_e0", "click_e1", "click_e2", "scroll", "close_popup", "back", "finish"}
    assert "back" not in action_options(_state(step=0))


@pytest.mark.parametrize("raw", [
    {"type": "choice", "choice": "type_text", "probabilities": {"type_text": 1.0}},  # 제시 안 한 행동
    {"type": "choice", "choice": "finish"},  # 확률 누락
    {"type": "choice", "choice": "finish", "probabilities": {"finish": 1.7}},
    {"type": "noul", "noul": 0.9},
    {"type": "choice", "choice": "finish", "probabilities": {"finish": 0.9, "evil": 0.1}},
    "click_e0",
])
def test_validate_choice_rejects(raw):
    with pytest.raises(ProviderError):
        validate_choice(raw, action_options(_state()))


def _jev_transport(answer, status=200, capture=None):
    def handler(req: httpx.Request):
        if capture is not None:
            capture.append(json.loads(req.content))
        return httpx.Response(status, json={"model": "jev-1.13.0", "answers": {"q": answer},
                                            "usage": {"input_tokens": 1, "output_tokens": 1}})
    return httpx.MockTransport(handler)


def test_jev_request_format_and_parse():
    sent = []
    p = JevProvider("jev_typesafe", "https://api.typesafe.ai", "k", "jev-1.13.0", 5,
                    transport=_jev_transport({"type": "choice", "choice": "click_e1",
                                              "probabilities": {"click_e1": 0.9, "finish": 0.1},
                                              "confidence": 0.8}, capture=sent))
    eng = Engine([p], 0.45, 0.6)
    st = _state()
    st.text = "연락처 010-1234-5678 로 입금"
    d = eng.decide_action(ActionRequest(state=st))
    assert d.action == "click" and d.element_id == "e1" and d.model == "jev-1.13.0"
    body = sent[0]
    assert body["model"] == "jev-1.13.0"
    q = body["questions"]["q"]
    assert q["type"] == "choice" and "click_e0" in q["criteria"]
    assert "010-1234-5678" not in json.dumps(body, ensure_ascii=False)  # 외부 전송 전 마스킹


def test_failover_to_next_provider():
    bad = JevProvider("jev_typesafe", "https://api.typesafe.ai", "k", "m", 5, transport=_jev_transport({}, 529))
    worse = JevProvider("jev_openrouter", "https://openrouter.ai/api", "k", "m", 5,
                        transport=_jev_transport({"type": "choice", "choice": "rm -rf", "probabilities": {}}))
    eng = Engine([bad, worse, RuleProvider()], 0.45, 0.6)
    d = eng.decide_action(ActionRequest(state=_state()))
    assert d.provider == "rules"
    with pytest.raises(NoProviderAvailable):
        Engine([bad, worse], 0.45, 0.6).decide_action(ActionRequest(state=_state()))


def test_threat_hold_when_unsure():
    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                    transport=_jev_transport({"type": "choice", "choice": "scam",
                                              "probabilities": {"scam": 0.4, "phishing": 0.35, "benign": 0.25}}))
    d = Engine([p], 0.45, 0.6).decide_threat(ThreatRequest(url="https://x", final_url="https://x",
                                                           redirect_count=0, domains=["x"], pages=["p"]))
    assert d.hold and d.threat == "scam"


def test_masking():
    t = mask_pii("주민 900101-1234567 전화 010-1234-5678 메일 a.b@c.co.kr 계좌 123-456-789012")
    for raw in ["900101-1234567", "010-1234-5678", "a.b@c.co.kr", "123-456-789012"]:
        assert raw not in t
    assert "sk-abc" not in mask_secrets('api_key="sk-abc" x')


def test_scroll_not_offered_after_no_effect():
    from safetrace.decision.schema import PageState, action_options

    base = dict(step=2, url="http://x.example/", title="", text="", candidates=[], has_popup=False)
    assert "scroll" in action_options(PageState(**base, history=["scroll"]))
    assert "scroll" not in action_options(PageState(**base, history=["scroll_no_effect"]))
    # 효과 없던 행동들 사이에 실패한 클릭이 끼어도 계속 빠지고, 화면을 바꾼 행동 뒤에는 다시 나온다
    o = action_options(PageState(**base, history=["scroll_no_effect", "click_failed:e1:x", "back_no_effect"]))
    assert "scroll" not in o and "back" not in o and "finish" in o
    o = action_options(PageState(**base, history=["scroll_no_effect", "click:e1:다음"]))
    assert "scroll" in o and "back" in o


def test_blocked_or_failed_click_not_reoffered_until_page_changes():
    from safetrace.decision.schema import Candidate, PageState, action_options

    cands = [Candidate(id="e0", tag="a", text="관리자 콘솔로 이동"), Candidate(id="e1", tag="a", text="다음")]
    base = dict(step=1, url="http://x.example/", title="", text="", candidates=cands, has_popup=False)
    o = action_options(PageState(**base, history=["blocked:e0:관리자 콘솔로 이동"]))
    assert "click_e0" not in o and "click_e1" in o
    o = action_options(PageState(**base, history=["click_failed:e1:다음", "scroll_no_effect"]))
    assert "click_e1" not in o and "scroll" not in o
    # 화면을 바꾼 행동 뒤에는 다시 고를 수 있다
    o = action_options(PageState(**base, history=["blocked:e0:관리자 콘솔로 이동", "click:e1:다음"]))
    assert "click_e0" in o


def test_only_finish_left_skips_model():
    from safetrace.decision.engine import Engine
    from safetrace.decision.schema import ActionRequest, PageState

    class Boom:
        name = "boom"

        def choose(self, *a):
            raise AssertionError("model must not be called")

    st = PageState(step=3, url="http://x.example/", title="", text="", candidates=[], has_popup=False,
                   history=["scroll_no_effect", "back_no_effect"])
    d = Engine([Boom()], 0.45, 0.6).decide_action(ActionRequest(state=st))
    assert d.choice == "finish" and d.provider == "exhausted"


def test_live_sink_keeps_30fps_with_jittery_frames(monkeypatch):
    """프레임이 30fps 근처로 들쑥날쑥 와도(31~36ms 간격) 발행이 크게 줄지 않는다."""
    import random

    from safetrace import live

    class Pub:
        def __init__(self):
            self.n = 0

        def watching(self, case_id):
            return True

        def publish(self, case_id, jpeg):
            self.n += 1

        def end(self, case_id):
            pass

    clock = [100.0]
    monkeypatch.setattr(live.time, "monotonic", lambda: clock[0])
    sink = live.LiveSink(Pub(), "c", max_fps=30)
    offered = []
    monkeypatch.setattr(sink, "_offer", lambda f: offered.append(f))
    rnd = random.Random(1)
    for _ in range(300):  # 약 10초
        clock[0] += rnd.uniform(0.031, 0.036)
        sink.on_frame(b"x")
    seconds = clock[0] - 100.0
    assert len(offered) / seconds >= 27, len(offered) / seconds
    sink.close()


# ── 정부 허가 사행사업자 공식 도메인 ───────────────────────
def _gambling_jev():
    return JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                       transport=_jev_transport({"type": "choice", "choice": "illegal_gambling",
                                                 "probabilities": {"illegal_gambling": 0.84, "benign": 0.16}}))


def _threat_req(url, final_url=None, domains=None):
    host = url.split("/")[2]
    return ThreatRequest(url=url, final_url=final_url or url, redirect_count=0,
                         domains=domains if domains is not None else [host], pages=["스포츠토토 베팅 배당"])


def test_official_betting_domain_judged_benign_with_original_kept():
    d = Engine([_gambling_jev()], 0.45, 0.6).decide_threat(_threat_req("https://www.sportstoto.co.kr/"))
    assert d.threat == "benign" and not d.hold and d.provider == "official_domain"
    assert d.override["operators"] == ["스포츠토토"]
    assert d.override["original"] == {"threat": "illegal_gambling", "probability": 0.84, "provider": "jev_typesafe"}


def test_official_domains_chain_across_operators():
    d = Engine([_gambling_jev()], 0.45, 0.6).decide_threat(
        _threat_req("https://www.sportstoto.co.kr/", "https://www.betman.co.kr/",
                    ["www.sportstoto.co.kr", "www.betman.co.kr"]))
    assert d.threat == "benign" and d.override["operators"] == ["스포츠토토", "베트맨(스포츠토토 공식 발매)"]


@pytest.mark.parametrize("url,final_url,domains", [
    ("https://sportstoto.co.kr.evil.example/", None, None),       # 공식 도메인을 앞에 붙인 사칭
    ("https://fakesportstoto.co.kr/", None, None),                 # 접미사만 같은 다른 도메인
    ("https://www.sportstoto.co.kr/", "https://toto-bet.example/", # 공식 사이트에서 다른 곳으로 넘어감
     ["www.sportstoto.co.kr", "toto-bet.example"]),
    ("https://toto-bet.example/", "https://www.betman.co.kr/",     # 불법 사이트가 공식 사이트로 넘김
     ["toto-bet.example", "www.betman.co.kr"]),
])
def test_non_official_domains_stay_illegal_gambling(url, final_url, domains):
    d = Engine([_gambling_jev()], 0.45, 0.6).decide_threat(_threat_req(url, final_url, domains))
    assert d.threat == "illegal_gambling" and d.override is None


def test_official_domain_does_not_hide_other_threats():
    # 공식 도메인이라도 피싱 등 다른 판단은 그대로 둔다(변조된 공식 사이트 대비)
    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                    transport=_jev_transport({"type": "choice", "choice": "phishing",
                                              "probabilities": {"phishing": 0.9, "benign": 0.1}}))
    d = Engine([p], 0.45, 0.6).decide_threat(_threat_req("https://www.betman.co.kr/"))
    assert d.threat == "phishing" and d.override is None


# ── OCR 스레드 수(컨테이너 CPU 한도) ────────────────────────
def test_ocr_threads_follow_container_cpu_limit(tmp_path, monkeypatch):
    from safetrace.agent.ocr import ocr_threads

    monkeypatch.delenv("ST_OCR_THREADS", raising=False)
    monkeypatch.setattr("os.cpu_count", lambda: 8)
    monkeypatch.setattr("os.sched_getaffinity", lambda _: set(range(8)), raising=False)
    cpu_max = tmp_path / "cpu.max"
    cpu_max.write_text("200000 100000\n")  # compose 의 cpus: "2"
    assert ocr_threads(cpu_max) == 2
    cpu_max.write_text("max 100000\n")  # 한도 없음: 코어 수, 최대 4
    assert ocr_threads(cpu_max) == 4
    cpu_max.write_text("50000 100000\n")  # 0.5 코어여도 1
    assert ocr_threads(cpu_max) == 1
    assert ocr_threads(tmp_path / "none") == 4  # cgroup 없음(Windows 등)
    monkeypatch.setenv("ST_OCR_THREADS", "3")
    assert ocr_threads(cpu_max) == 3


def test_ocr_cache_reuses_same_image(monkeypatch):
    import safetrace.agent.ocr as ocrmod

    calls = []

    def fake_engine(img):
        calls.append(img)
        return [[None, "충전하기", "0.93"], [None, "흐림", "0.2"]], None

    ocr = ocrmod.LocalOCR.__new__(ocrmod.LocalOCR)
    ocr.__init__()
    ocr._engine, ocr.available = fake_engine, True
    monkeypatch.setattr(ocrmod, "_pad", lambda png: png)
    assert ocr.read(b"img-a") == "충전하기"  # 점수 0.5 미만은 버림
    assert ocr.read(b"img-a") == "충전하기" and len(calls) == 1 and ocr.cache_hits == 1
    assert ocr.read(b"img-a", max_len=2) == "충전"
    assert ocr.read(b"img-b") == "충전하기" and len(calls) == 2  # 다른 이미지는 새로 읽는다
    monkeypatch.setattr(ocrmod, "_CACHE_SIZE", 1)
    ocr.read(b"img-c")  # 가장 오래된 것부터 버림
    ocr.read(b"img-a")
    assert len(calls) == 4

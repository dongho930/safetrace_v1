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

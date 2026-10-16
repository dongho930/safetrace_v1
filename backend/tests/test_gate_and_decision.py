import json

import httpx
import pytest

from safetrace.agent.gate import Budget, ElementInfo, SafetyGate, classify_forbidden
from safetrace.decision.engine import Engine, NoProviderAvailable
from safetrace.decision.providers import JevProvider, ProviderError, RuleProvider, validate_choice
from safetrace.decision.schema import (
    ActionRequest,
    BlockedDestination,
    Candidate,
    PageState,
    ThreatRequest,
    action_options,
)
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


def test_masking_keeps_dates():
    # 뉴스 날짜를 계좌번호로 가리면 판단 모델이 금융 화면으로 오해한다
    t = mask_pii("2025-11-13 공지 · 계좌 3333-01-1234567 · 사업자 123-45-67890")
    assert "2025-11-13" in t
    assert "3333-01-1234567" not in t and "123-45-67890" not in t


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


def test_live_click_survives_slow_viewer():
    """클릭 표시는 밀려도 버리지 않고(프레임만 버림) 받은 순서대로 보낸다. 시청자가 없으면 보내지 않는다."""
    import threading

    from safetrace import live

    gate = threading.Event()

    class Pub:
        def __init__(self):
            self.got, self.watch = [], True

        def watching(self, case_id):
            return self.watch

        def publish(self, case_id, item):
            gate.wait(2)  # 느린 시청자: 첫 발행이 풀릴 때까지 밀린다
            self.got.append(item)

        def end(self, case_id):
            pass

    pub = Pub()
    sink = live.LiveSink(pub, "c")
    for i in range(5):
        sink._offer(b"\xff" + bytes([i]))
        if i == 1:
            sink.click([10, 20, 30, 40])
    gate.set()
    sink.close()
    assert b'{"click":[10,20,30,40]}' in pub.got
    frames = [x for x in pub.got if x[:1] == b"\xff"]
    assert frames[-1] == b"\xff\x04" and len(frames) <= 3, pub.got  # 처음 1장(밀린 동안) + 최신 2장
    pub2 = Pub()
    pub2.watch = False
    s2 = live.LiveSink(pub2, "c")
    s2.click([1, 2, 3, 4])
    s2.close()
    assert pub2.got == []


def test_forward_limit_drops_oversized_and_flood(monkeypatch):
    """Codex 지적: 침해된 에이전트가 통로로 쏟아내도 API 는 너무 큰 메시지와 1초에 60개를 넘는 메시지를 넘기지 않는다."""
    from safetrace import live

    clock = [10.0]
    monkeypatch.setattr(live.time, "monotonic", lambda: clock[0])
    lim = live.ForwardLimit()
    assert not lim.ok(b"x" * (live.MAX_MESSAGE_BYTES + 1))
    passed = sum(lim.ok(b"frame") for _ in range(1000))
    assert passed == live.MAX_MESSAGES_PER_S
    clock[0] += 1.0  # 다음 1초에는 다시 넘긴다
    assert lim.ok(b"frame")


def test_local_live_keeps_click_and_end_for_slow_viewer():
    import asyncio

    from safetrace import live

    async def go():
        q = asyncio.Queue()
        for item in (b"\xff1", b'{"click":[1,2,3,4]}', b"\xff2", b"\xff3", b"\xff4", live.END):
            live._put_latest(q, item)
        return [q.get_nowait() for _ in range(q.qsize())]

    got = asyncio.run(go())
    assert got == [b'{"click":[1,2,3,4]}', b"\xff3", b"\xff4", live.END], got


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


def test_blocked_destination_counts_against_official_domain():
    # 공식 사이트 화면이었어도 사라진 다른 도메인으로 넘기려 했다면 공식 도메인 예외를 두지 않는다
    req = _threat_req("https://www.sportstoto.co.kr/")
    req.blocked_destinations = [BlockedDestination(host="toto-bet.example", reason="ssrf:dns_failure")]
    d = Engine([_gambling_jev()], 0.45, 0.6).decide_threat(req)
    assert d.threat == "illegal_gambling" and d.override is None


def test_blocked_destinations_sent_to_model():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"answers": {"q": {"type": "choice", "choice": "phishing",
                                                           "probabilities": {"phishing": 0.8, "unknown": 0.2}}}})

    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5, transport=httpx.MockTransport(handler))
    req = ThreatRequest(url="https://lrl.kr/HlEG", final_url="https://lrl.kr/check/url", redirect_count=1,
                        domains=["lrl.kr"], pages=["페이지 이동중"],
                        blocked_destinations=[BlockedDestination(host="name.n-payost.shop", reason="ssrf:dns_failure")])
    Engine([p], 0.45, 0.6).decide_threat(req)
    assert seen["state"]["blocked_destinations"] == [{"host": "name.n-payost.shop", "reason": "ssrf:dns_failure"}]
    assert "blocked_destinations" in seen["questions"]["q"]["instructions"]


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


def test_ocr_mosaic_assigns_text_to_its_own_image(monkeypatch):
    """모자이크로 한 번에 읽고, 글자 중심이 들어간 이미지에만 배정한다. 못 읽은 것만 한 장씩 다시 읽는다."""
    import io

    from PIL import Image

    import safetrace.agent.ocr as ocrmod

    def png(w, h, color):
        buf = io.BytesIO()
        Image.new("RGB", (w, h), color).save(buf, "PNG")
        return buf.getvalue()

    a, b, c = png(300, 80, "red"), png(200, 60, "blue"), png(120, 40, "green")
    placed = {}

    def batch_engine(canvas):
        # 캔버스에서 각 색 상자의 위치를 찾아, 빨강·파랑 상자 안에만 글자를 돌려준다(초록은 못 읽은 것으로)
        out = []
        for name, rgb in (("red", (0, 0, 255)), ("blue", (255, 0, 0))):  # cv2 는 BGR
            ys, xs = ((canvas == rgb).all(axis=2)).nonzero()
            placed[name] = (xs.min(), ys.min())
            cx, cy = (xs.min() + xs.max()) / 2, (ys.min() + ys.max()) / 2
            poly = [[cx - 5, cy - 5], [cx + 5, cy - 5], [cx + 5, cy + 5], [cx - 5, cy + 5]]
            out.append([poly, {"red": "충전하기", "blue": "다음"}[name], "0.9"])
        return out, None

    single = []
    ocr = ocrmod.LocalOCR.__new__(ocrmod.LocalOCR)
    ocr.__init__()
    ocr.available = True
    ocr._batch_engine = batch_engine
    ocr._engine = lambda img: (single.append(1) or [[None, "결제", "0.95"]], None)
    monkeypatch.setattr(ocrmod, "_pad", lambda p: p)
    assert ocr.read_many([a, b, c]) == ["충전하기", "다음", "결제"]  # 초록은 한 장씩 다시 읽음
    assert len(single) == 1 and placed["red"] != placed["blue"]
    assert ocr.read_many([b, a]) == ["다음", "충전하기"] and ocr.cache_hits == 2  # 캐시
    # 마감이 지났으면 한 장씩 다시 읽지 않는다
    d = png(90, 30, "yellow")
    assert ocr.read_many([d], deadline=0.0) == [""] and len(single) == 1


def test_rules_see_chinese_gambling_words():
    d = Engine([RuleProvider()], 0.45, 0.6).decide_threat(ThreatRequest(
        url="http://x.example/", final_url="http://x.example/", redirect_count=0, domains=["x.example"],
        pages=["[0] 米兰体育 | http://x.example/ | 真人娱乐 体育投注 彩票"]))
    assert d.threat == "illegal_gambling"


# ── 단축 URL 서비스의 위험 경고 화면 ──────────────────────
_IIIM_KO = ("[0] iii.im URL 단축 서비스 | https://iii.im/ZujV | 경고 지금 접속하신 주소는 단축된 주소이지만 사용자에게 "
            "위험한 콘텐츠를 포함 할 수도 있는 것으로 확인이 되어 자동 이동이 막혀 있습니다. 위험할 수 있는 URL 보기")
_IIIM_EN = ("[0] iii.im URL Shortener | https://iii.im/ZujV | Warning The link you followed is a shortened URL. However, "
            "we cannot automatically redirect you as the full URL may be unsafe.")


def _url_of(page: str) -> str:
    """시험용 요약 '[단계] 제목 | 주소 | 글' 에서 주소(실제로는 에이전트가 page_urls 로 따로 보낸다)."""
    return page.split(" | ")[1]


@pytest.mark.parametrize("page, expected", [
    (_IIIM_KO, True),
    (_IIIM_EN, True),
    ("[0] Warning! | https://bit.ly/3GWIQhx | Warning: This URL has been blocked by Bitly's systems as potentially "
     "harmful. We recommend you close your browser window and notify the person who sent you the link.", True),
    # Bitly 의 다른 문구(KISA 2024 bit.ly/4bXhEwR 에서 관찰)
    ("[0] Warning! | https://bit.ly/4bXhEwR | Warning: This URL has been flagged by Bitly's systems as potentially "
     "harmful. We recommend you close your browser window and notify the person who sent you the link.", True),
    # 같은 경고 글을 다른 사이트가 흉내 내면 아니다(경고는 그 단축 서비스의 화면에 있어야 한다)
    (_IIIM_KO.replace("https://iii.im/ZujV", "https://attacker.example/"), False),
    ("[0] 로그인 | https://bank.example/ | 비밀번호 5회 오류로 로그인이 차단되었습니다. 피싱에 주의하세요", False),
    ("[0] Bitly | https://bit.ly/1TV4K | 다음은 귀하의 목적지에 대한 미리보기입니다. 현재 위협이 감지되지 않았습니다", False),
    ("[0] 링크 이동 | https://me2.kr/a | 외부 사이트로 이동합니다. 계속하려면 이동하기를 누르세요", False),
    ("[0] 외부 링크 | https://link.naver.com/b | 네이버가 운영하지 않으며 안전을 보장하지 않습니다. 주의 계속 이동", False),
    ("[0] 이동중 | https://x/ | 잠시 후 자동으로 이동합니다. 피싱 예방 안내", False),
])
def test_shortener_warning_detected(page, expected):
    from safetrace.decision.engine import shortener_warning

    assert shortener_warning([page], [_url_of(page)]) is expected
    assert not shortener_warning([page], [])  # 화면 주소가 없으면(예전 에이전트) 적용하지 않는다


def test_shortener_warning_threat_goes_to_review():
    # 판단 모델이 판단 불가·정상으로 봐도 단축 서비스의 위험 경고가 있으면 피싱(담당자 검토)으로, 원래 판단은 남긴다
    req = ThreatRequest(url="https://iii.im/ZujV", final_url="https://iii.im/ZujV", redirect_count=0,
                        domains=["iii.im"], pages=[_IIIM_KO], page_urls=["https://iii.im/ZujV"])
    for choice in ("unknown", "benign"):
        p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                        transport=_jev_transport({"type": "choice", "choice": choice,
                                                  "probabilities": {choice: 0.6, "phishing": 0.4}}))
        d = Engine([p], 0.45, 0.6).decide_threat(req)
        assert d.threat == "phishing" and d.hold and d.provider == "shortener_warning"
        assert d.override["original"]["threat"] == choice
    d = Engine([RuleProvider()], 0.45, 0.6).decide_threat(req)
    assert d.threat == "phishing" and d.hold


def test_shortener_warning_keeps_other_threats():
    # 판단 모델이 이미 위협 유형을 골랐으면 그대로 둔다
    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                    transport=_jev_transport({"type": "choice", "choice": "illegal_gambling",
                                              "probabilities": {"illegal_gambling": 0.9, "benign": 0.1}}))
    d = Engine([p], 0.45, 0.6).decide_threat(ThreatRequest(
        url="https://iii.im/x", final_url="https://iii.im/x", redirect_count=0, domains=["iii.im"], pages=[_IIIM_KO],
        page_urls=["https://iii.im/x"]))
    assert d.threat == "illegal_gambling" and d.override is None


# ── 단축·호스팅 서비스가 링크를 정지·차단한 안내 화면(KISA 신고 URL 에서 관찰한 문구, 2026-10-14) ──
_TINY_KR = "[0] 링크 접속불가 | https://tny.kr/tzsy0 | 링크 접속불가 이 페이지는 영구정지 되었거나 리디렉트가 차단된 상태입니다. 뒤로가기"
_TAKEDOWNS = [  # (그 화면을 연 주소(브라우저 값), 화면 요약)
    ("https://xzx.kr/warning.php", "[0] xzx.kr warning :: MU-star.net | https://xzx.kr/warning.php | < 단축URL 생성 단축URL 풀기 > "
     "xzx.krWARNING 등록된 단축URL 접속차단 안내 귀하가 접속하려고 단축URL는 불법·유해 내용이 제공되거나 "
     "이용약관에 위반되어 접속차단이 되었음을 알려드립니다."),
    ("https://muz.so/warning.php", "[0] muz.so warning :: MU-star.net | https://muz.so/warning.php | unShorten URL > muz.soWARNING URL "
     "Access Suspended We inform you that the shortened URL you have accessed has been suspended due to illegal or "
     "harmful contents or violation of the Terms of Use."),
    ("https://5du.pl/1341", "[0] Link zablokovaný | SDU.sk | https://5du.pl/1341 | Domov Prihlásiť Registrovať LINK ZABLOKOVANÝ "
     "Objaviť viac Tento link bol zablokovaný z dôvodu porušovania Podmienok SDU. Menu O SDU"),
    ("https://tinyurl.com/app/nospam/tinyurl.com/fgr5DF", "[0] URL Shortener, Branded Short Links & Analytics | TinyURL | "
     "https://tinyurl.com/app/nospam/tinyurl.com/fgr5DF | TinyURL Visit TinyURL.com URL Terminated The TinyURL link you "
     "are visiting was used by its creator in violation of our Terms of Use. TinyURL has a strict no-abuse policy"),
    ("https://tny.kr/tzsy0", _TINY_KR),
    ("https://taxservice.creatorlink.net/",
     "[0] Server Blacklist Site | https://taxservice.creatorlink.net/ | 불법 / 유해 사이트 접속 차단 안내 BACK TO CREATORLINK"),
]


@pytest.mark.parametrize("page_url, page, expected", [
    *((d, p, True) for d, p in _TAKEDOWNS),
    # 같은 서비스의 보통 화면, 정지 안내가 아닌 차단·위반 문구
    ("https://sdu.sk/sk", "[0] Skracovač dlhých URL adries a linkov | SDU.sk | https://sdu.sk/sk | Skrátiť link Podmienky", False),
    ("https://tinyurl.com/", "[0] TinyURL | https://tinyurl.com/ | Shorten a long URL. By clicking you agree to our Terms of Use",
     False),
    ("https://tny.kr/", "[0] tny.kr | https://tny.kr/ | 단축 URL 만들기 긴 주소를 짧게 줄여 드립니다. 이용약관 개인정보처리방침", False),
    ("https://news.example/", "[0] 뉴스 | https://news.example/ | 방심위, 불법 도박 사이트 접속 차단 확대… 유해 정보 신고 급증", False),
    ("https://shop.example/", "[0] 로그인 | https://shop.example/ | 이용약관 위반으로 계정이 정지되었습니다. 고객센터로 문의하세요", False),
    ("https://tinyurl.com/x", "[0] Error | https://tinyurl.com/x | URL Terminated", False),  # 이유 없이 '종료'만 있는 화면
    # 다른 서비스의 안내 문구: 문구를 관찰한 그 서비스의 도메인이어야 한다
    ("https://tny.kr/x", _TAKEDOWNS[3][1], False),
    ("https://notcreatorlink.net/", _TAKEDOWNS[5][1], False),
])
def test_link_takedown_detected(page_url, page, expected):
    from safetrace.decision.engine import link_takedown

    assert link_takedown([page], [page_url]) is expected
    assert not link_takedown([page], [])  # 화면 주소가 없으면(예전 에이전트) 적용하지 않는다


def test_link_takedown_threat_goes_to_review():
    # 판단 모델이 정상·판단 불가로 봐도 서비스의 정지 안내가 있으면 피싱(담당자 검토)으로, 원래 판단은 남긴다
    req = ThreatRequest(url="https://tny.kr/tzsy0", final_url="https://tny.kr/tzsy0", redirect_count=0,
                        domains=["tny.kr"], pages=[_TINY_KR], page_urls=["https://tny.kr/tzsy0"])
    for choice in ("unknown", "benign"):
        sent = []
        p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                        transport=_jev_transport({"type": "choice", "choice": choice,
                                                  "probabilities": {choice: 0.7, "phishing": 0.3}}, capture=sent))
        d = Engine([p], 0.45, 0.6).decide_threat(req)
        assert d.threat == "phishing" and d.hold and d.provider == "link_takedown"
        assert d.override["reason"] == "link_takedown" and d.override["original"]["threat"] == choice
        assert "page_urls" not in json.dumps(sent[0])  # 화면별 주소는 코드 규칙만 쓴다(Jev 입력은 그대로)
    d = Engine([RuleProvider()], 0.45, 0.6).decide_threat(req)
    assert d.threat == "phishing" and d.hold


@pytest.mark.parametrize("page", [
    "[0] 일반 안내 | https://attacker.example/ | URL Terminated illegal",
    # 페이지 제목으로 서비스 주소를 흉내 내도(요약의 주소 칸은 제목 뒤에 붙는다) 실제로 거친 도메인이 아니면 아니다
    "[0] x | https://tinyurl.com/app/nospam/x | URL Terminated The TinyURL link you are visiting was used by its "
    "creator in violation of our Terms of Use | https://attacker.example/ | 안내",
])
def test_link_takedown_needs_visited_service_domain(page):
    # Codex F1: 페이지 글자만으로 '서비스가 링크를 정지했다'고 단정하지 않는다. 그 문구가 서비스 도메인의
    # 화면에 있을 때(그 화면을 브라우저가 연 주소, page_urls)만 적용한다
    d = Engine([RuleProvider()], 0.45, 0.6).decide_threat(ThreatRequest(
        url="https://attacker.example/", final_url="https://attacker.example/", redirect_count=0,
        domains=["attacker.example"], pages=[page], page_urls=["https://attacker.example/"]))
    assert d.override is None or d.override["reason"] != "link_takedown"


def test_link_takedown_needs_notice_on_service_page():
    # Codex 2회차 F1: 서비스 도메인을 거쳤어도 안내 문구는 그 서비스의 화면에 있어야 한다. 정상 단축 링크가
    # 공격자 페이지로 넘기고 그 본문에 정지 문구를 적은 경우는 아니다
    req = ThreatRequest(url="https://tinyurl.com/demo", final_url="https://attacker.example/", redirect_count=1,
                        domains=["tinyurl.com", "attacker.example"],
                        pages=["[0] 안내 | https://attacker.example/ | URL Terminated illegal"],
                        page_urls=["https://attacker.example/"])
    d = Engine([RuleProvider()], 0.45, 0.6).decide_threat(req)
    assert d.override is None or d.override["reason"] != "link_takedown"
    # 같은 문구가 서비스 도메인의 화면에 있으면 적용한다
    req = req.model_copy(update={"page_urls": ["https://tinyurl.com/app/nospam/tinyurl.com/demo"]})
    d = Engine([RuleProvider()], 0.45, 0.6).decide_threat(req)
    assert d.override and d.override["reason"] == "link_takedown"


def test_link_takedown_keeps_other_threats():
    # 판단 모델이 이미 위협 유형을 골랐으면 그대로 둔다
    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                    transport=_jev_transport({"type": "choice", "choice": "illegal_gambling",
                                              "probabilities": {"illegal_gambling": 0.9, "benign": 0.1}}))
    d = Engine([p], 0.45, 0.6).decide_threat(ThreatRequest(
        url="https://tny.kr/x", final_url="https://tny.kr/x", redirect_count=0, domains=["tny.kr"], pages=[_TINY_KR],
        page_urls=["https://tny.kr/x"]))
    assert d.threat == "illegal_gambling" and d.override is None


# ── 신고 주소가 조사 전에 브랜드 공식 사이트로 넘김(피싱 키트의 봇 회피) ─────
# 관찰(OpenPhish 2026-10-14): iCloud 사칭 → 서버가 www.apple.com 으로, Meta 비즈니스 사칭 pages.dev → JS 로
# www.facebook.com 으로. 살아 있는 피싱 주소는 저장소에 두지 않으므로 시작 주소는 example 로 바꿔 쓴다
@pytest.mark.parametrize("url, page_urls, expected", [
    ("https://phish.example/theme/cmd", ["https://www.apple.com/"], ("apple", "www.apple.com")),
    ("https://x-y-z.pages.dev/", ["https://www.facebook.com/", "https://www.facebook.com/reg/"],
     ("facebook", "www.facebook.com")),
    # 첫 화면은 신고 사이트였고 에이전트가 링크를 눌러 공식 사이트로 간 경우: 정상 사이트도 공식 SNS 를 링크한다
    ("https://phish.example/", ["https://phish.example/", "https://www.facebook.com/"], None),
    ("https://bit.ly/abc", ["https://www.apple.com/"], None),  # 단축 서비스는 남의 주소로 넘기는 것이 본업
    ("http://gourl.kr/abc", ["https://www.naver.com/"], None),  # 사라진 링크를 naver.com 으로(KISA 자료에서 관찰)
    ("https://naver.me/abc", ["https://www.naver.com/"], None),  # 공식 도메인끼리의 이동
    ("https://www.apple.com/", ["https://www.apple.com/kr/"], None),
    ("https://phish.example/", [], None),
    ("https://ornate.netlify.app/", ["https://steamcommunity.com/"], ("steam", "steamcommunity.com")),
    ("https://x.typedream.app/", ["https://www.ledger.com/start"], ("ledger", "www.ledger.com")),
])
def test_official_redirect(url, page_urls, expected):
    from safetrace.decision.brands import official_redirect

    assert official_redirect(url, page_urls) == expected


def test_official_redirect_not_on_normal_eval_set():
    # 평가 세트 정상 사이트는 자기 도메인에서 시작해 자기 화면을 보여 준다
    import csv
    from pathlib import Path

    from safetrace.decision.brands import official_redirect

    rows = csv.DictReader((Path(__file__).resolve().parents[2] / "data" / "eval_set.csv").open(encoding="utf-8"))
    for r in rows:
        if r["group"] == "normal":
            assert official_redirect(r["url"], [r["url"]]) is None, r["url"]


def test_official_redirect_threat_goes_to_review():
    sent = []
    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                    transport=_jev_transport({"type": "choice", "choice": "benign",
                                              "probabilities": {"benign": 0.55, "phishing": 0.45}}, capture=sent))
    req = ThreatRequest(url="https://x-y-z.pages.dev/", final_url="https://www.facebook.com/reg/", redirect_count=2,
                        domains=["x-y-z.pages.dev", "www.facebook.com"],
                        pages=["[0] Facebook | https://www.facebook.com/ | Facebook에 로그인"],
                        page_urls=["https://www.facebook.com/"])
    d = Engine([p], 0.45, 0.6).decide_threat(req)
    assert d.threat == "phishing" and d.hold and d.provider == "official_redirect"
    assert d.override == {"reason": "official_redirect", "brand": "facebook", "destination": "www.facebook.com",
                          "original": {"threat": "benign", "probability": 0.55, "provider": "jev_typesafe"}}
    # 모델이 위협 유형을 골랐으면 그대로 둔다
    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                    transport=_jev_transport({"type": "choice", "choice": "phishing",
                                              "probabilities": {"phishing": 0.9, "benign": 0.1}}))
    assert Engine([p], 0.45, 0.6).decide_threat(req).override is None


# ── 브랜드 사칭 도메인 ───────────────────────────────────
@pytest.mark.parametrize("host, brand", [
    ("mi-telegram.com", "telegram"),
    ("tel-telegram.com", "telegram"),
    ("telegram-kr.xyz", "telegram"),
    ("naver-pay.help", "naver"),
    ("kakaotalk-event.shop", "kakao"),
    ("g.kbank.mywire.org", "kbank"),  # 케이뱅크 사칭(KISA goo.su/E7i5QDl 의 목적지)
    ("gkk.ilogenskns.com", "ilogen"),
    ("kks.lotteglo.com", "lotteglo"),
    ("www.kbanknow.com", None),
    ("www.ilogen.com", None),
    ("www.lotteglogis.com", None),
    ("name.n-payost.shop", None),
    ("hometax-go.kr.refund.top", "hometax"),
    # 오늘의 실사이트 세트(OpenPhish 2026-10-14~16)에서 본 게임·지갑 사칭
    ("www.roblox.et", "roblox"),
    ("roblox.com.mu", "roblox"),
    ("ledgernload.gitbook.io", "ledger"),
    ("ledgerdownloads.com", "ledger"),
    ("en--help-trezor-wallet-cdn-en.typedream.app", "trezor"),
    ("www.roblox.com", None),
    ("tr.rbxcdn.com", None),
    ("trezor.io", None),
    ("shop.ledger.com", None),
    ("store.steampowered.com", None),
    ("steamcommunity.com", None),
    ("shared.akamai.steamstatic.com", None),
])
def test_lookalike_brand(host, brand):
    from safetrace.decision.brands import lookalike_brand

    assert lookalike_brand(host) == brand


def test_eval_normal_sites_are_not_lookalikes():
    # 평가 세트의 정상 사이트(공식 도메인)와 그 하위 도메인은 사칭으로 보지 않는다
    import csv
    from pathlib import Path
    from urllib.parse import urlsplit

    from safetrace.decision.brands import lookalike_brand

    rows = csv.reader((Path(__file__).resolve().parents[2] / "data" / "eval_set.csv").open(encoding="utf-8"))
    hosts = [urlsplit(r[2]).hostname for r in rows if r and r[0] == "normal"]
    assert len(hosts) >= 16
    extra = ["nid.naver.com", "accounts.kakao.com", "web.telegram.org", "t.me", "login.coupang.com", "obank.kbstar.com"]
    assert [h for h in [*hosts, *extra] if lookalike_brand(h)] == []


def _brand_req(url, text):
    host = url.split("/")[2]
    return ThreatRequest(url=url, final_url=url, redirect_count=0, domains=[host],
                         pages=[f"[0]  | {url} | {text}"])


@pytest.mark.parametrize("choice, text, overridden", [
    ("benign", "OK", True),                       # 봇에게 'OK' 만 보여 주는 사칭 도메인
    ("unknown", "OK", True),
    ("benign", "텔레그램 사용 안내 " * 30, False),  # 내용이 있는 정상 화면이면 모델 판단을 따른다
    ("illegal_gambling", "OK", False),            # 모델이 고른 위협 유형은 그대로
])
def test_brand_lookalike_with_no_content_goes_to_review(choice, text, overridden):
    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                    transport=_jev_transport({"type": "choice", "choice": choice,
                                              "probabilities": {choice: 0.6, "phishing": 0.4}}))
    d = Engine([p], 0.45, 0.6).decide_threat(_brand_req("https://mi-telegram.com/", text))
    if overridden:
        assert d.threat == "phishing" and d.hold and d.override["brand"] == "telegram"
        assert d.override["original"]["threat"] == choice
    else:
        assert d.threat == choice and d.override is None


def test_official_brand_domain_with_no_content_kept():
    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                    transport=_jev_transport({"type": "choice", "choice": "benign",
                                              "probabilities": {"benign": 0.9, "unknown": 0.1}}))
    d = Engine([p], 0.45, 0.6).decide_threat(_brand_req("https://t.me/somechannel", "OK"))
    assert d.threat == "benign" and d.override is None


@pytest.mark.parametrize("choice, overridden", [("unknown", True), ("benign", True), ("scam", False)])
def test_brand_lookalike_dead_destination_goes_to_review(choice, overridden):
    # 목적지가 이미 사라졌어도 그 이름이 브랜드 사칭이면 피싱(담당자 검토). 모델이 고른 위협 유형은 그대로
    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                    transport=_jev_transport({"type": "choice", "choice": choice,
                                              "probabilities": {choice: 0.6, "phishing": 0.4}}))
    req = ThreatRequest(url="https://goo.su/E7i5QDl", final_url="https://goo.su/E7i5QDl", redirect_count=0,
                        domains=["goo.su"], pages=["[0] goo.su | https://goo.su/E7i5QDl | 이동 중입니다 " * 10],
                        blocked_destinations=[BlockedDestination(host="g.kbank.mywire.org", reason="ssrf:dns_failure")])
    d = Engine([p], 0.45, 0.6).decide_threat(req)
    if overridden:
        assert d.threat == "phishing" and d.hold
        assert (d.override["brand"], d.override["destination"]) == ("kbank", "g.kbank.mywire.org")
    else:
        assert d.threat == choice and d.override is None


def test_meaningless_dead_destination_kept():
    p = JevProvider("jev_typesafe", "https://x", "k", "m", 5,
                    transport=_jev_transport({"type": "choice", "choice": "unknown",
                                              "probabilities": {"unknown": 0.7, "phishing": 0.3}}))
    req = ThreatRequest(url="http://goo.su/PUPst", final_url="http://goo.su/PUPst", redirect_count=0,
                        domains=["goo.su"], pages=["[0] goo.su | http://goo.su/PUPst | 이동 중"],
                        blocked_destinations=[BlockedDestination(host="ven.nibyol.fun", reason="ssrf:dns_failure")])
    d = Engine([p], 0.45, 0.6).decide_threat(req)
    assert d.threat == "unknown" and d.override is None


def test_boxes_from_maps_viewport_rects_to_capture(tmp_path):
    """창 기준 상자 + 스크롤(원점) → 캡처 픽셀. 캡처 범위로 자르고, 밖이거나 작으면 None. 크기는 실제 PNG 에서."""
    import struct
    import zlib

    from safetrace.agent.loop import boxes_from, png_size

    root = {"x": 0, "y": -900}  # 900 만큼 스크롤
    rects = [{"x": 300, "y": -500, "width": 160, "height": 50},   # 문서 y=400
             {"x": 1270, "y": 10, "width": 40, "height": 20},     # 오른쪽이 잘림
             {"x": 10, "y": 1800, "width": 40, "height": 20},     # 캡처(높이 2600) 밖
             None,
             {"x": 10.4, "y": -899.6, "width": 1.0, "height": 30}]  # 너무 좁음
    out = boxes_from(root, rects, (1280, 2600), ["e1", "e2", "e3"], 2)
    assert out == {"size": [1280, 2600], "cand": {"e1": [300, 400, 160, 50], "e2": [1270, 910, 10, 20]}, "forbidden": [None, None]}
    assert boxes_from(None, rects, (1280, 2600), ["e1", "e2", "e3"], 2) is None
    assert boxes_from(root, rects, None, ["e1", "e2", "e3"], 2) is None
    assert boxes_from(root, rects[:2], (1280, 2600), ["e1", "e2", "e3"], 2) is None
    assert boxes_from(root, [None, None], (1280, 2600), ["e1"], 1) is None

    def png(w, h):
        ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
        return bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + struct.pack(">I", 13) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    (tmp_path / "a.png").write_bytes(png(1280, 2600))
    (tmp_path / "b.png").write_bytes(b"not a png at all, 24 bytes+")
    assert png_size(tmp_path / "a.png") == (1280, 2600)
    assert png_size(tmp_path / "b.png") is None
    assert png_size(tmp_path / "missing.png") is None

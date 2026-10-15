"""연관 후보: 고르기(순수 함수), API 가 받는 후보 목록 검증, 하위 조사 여부."""

from safetrace.agent.candidates import MAX_FOUND, select, site_of
from safetrace.agent.runner import _needs_followup

PORTS = [80, 443]


def test_site_of():
    assert site_of("news.naver.com") == "naver.com"
    assert site_of("www.epost.go.kr") == "epost.go.kr"
    assert site_of("a.b.example.co.uk") == "example.co.uk"
    assert site_of("127.0.0.1") == "127.0.0.1"


def test_select_via_and_links():
    got = select("https://short.example/abc", "https://pay-fake.shop/login",
                 ["https://short.example/abc", "https://hop.example.net/r?x=1", "https://pay-fake.shop/login"],
                 ["https://pay-fake.shop/help", "https://other-scam.top/", "https://www.naver.com/",
                  "https://sub.hop.example.net/x", "javascript:alert(1)", "ftp://files.example/"], PORTS)
    assert got == [
        {"url": "https://hop.example.net/", "host": "hop.example.net", "source": "via", "score": 3, "text": ""},  # 경유: 첫 화면
        {"url": "https://other-scam.top/", "host": "other-scam.top", "source": "link", "score": 0, "text": ""},
    ]  # 같은 사이트·공식 도메인(naver)·이미 고른 사이트·다른 스킴은 뺀다


def test_select_rejects_untrusted_urls():
    links = ["http://user:pw@evil.example/", "http://evil2.example:8080/", "https://" + "a" * 2100 + ".com/",
             "https://hometax.go.kr.evil.example/"]
    got = select("https://start.example/", "https://start.example/", [], links, PORTS)
    assert [c["host"] for c in got] == ["hometax.go.kr.evil.example"]  # 공식 도메인 흉내는 공식이 아니다
    allowed = select("http://127.0.0.1:8900/", "http://127.0.0.1:8900/", [], ["http://localhost:8900/a"], PORTS,
                     ["localhost:8900"])
    assert [c["host"] for c in allowed] == ["localhost"]


def test_select_limit():
    links = [f"https://s{i}.example{i}.com/" for i in range(50)]
    assert len(select("https://start.example/", "", [], links, PORTS)) == MAX_FOUND


# ── related-sites PR 2: 후보 고르는 순서 ─────────────────────────
def test_select_orders_by_score():
    """경유 3 → 위협 단서 링크 2 → 이름 조각을 나눠 갖는 도메인 1 → 나머지 0. 같은 점수는 나온 순서."""
    links = [
        {"url": "https://plain-a.example/", "text": "회사 소개"},
        {"url": "https://km-telegram.com/", "text": "텔레그램"},             # 'telegram' 조각을 나눠 가짐
        {"url": "https://plain-b.example/", "text": "공지"},
        {"url": "https://dgjlc.com/", "text": "카지노 바로가기"},            # 위협 단서(판단 규칙의 단어)
        {"url": "https://bet.example/%EB%B0%94%EC%B9%B4%EB%9D%BC/", "text": ""},  # 주소의 단서(인코딩된 '바카라')
    ]
    got = select("http://kc-telegram.com/", "http://kc-telegram.com/", ["http://kc-telegram.com/", "https://hop.example/"],
                 links, PORTS)
    assert [(c["host"], c["score"]) for c in got] == [
        ("hop.example", 3), ("dgjlc.com", 2), ("bet.example", 2), ("km-telegram.com", 1),
        ("plain-a.example", 0), ("plain-b.example", 0)]
    assert got[1]["text"] == "카지노 바로가기"


def test_select_excludes_generic_sites_and_keeps_best_link():
    links = [{"url": "https://www.facebook.com/somepage", "text": "페이스북"},
             {"url": "https://ethereum.org/en/", "text": "Ethereum"},
             {"url": "https://www.typedream.com/", "text": "Made with Typedream"},
             {"url": "https://camp.example/about", "text": "안내"},
             {"url": "https://camp.example/event", "text": "첫충 이벤트"}]  # 같은 사이트는 점수가 높은 링크를 남긴다
    got = select("https://start.example/", "", [], links, PORTS)
    assert [(c["url"], c["score"]) for c in got] == [("https://camp.example/event", 2)]


def test_service_home_excluded_only_at_root():
    """Codex(PR 2) F3: 단축 서비스·사이트 빌더의 '홈'만 뺀다. 같은 도메인의 다른 경로(단축 주소·사용자 페이지)는
    목적지를 확인하기 전이라 후보로 남긴다."""
    got = select("https://start.example/", "", [],
                 [{"url": "https://sdu.sk/campaign", "text": "카지노"}, {"url": "https://bitly.com/", "text": "Bitly"},
                  {"url": "https://www.webflow.com", "text": "Made in Webflow"},
                  {"url": "https://ethereum.org/en/wallets/", "text": "지갑"}], PORTS)
    assert [c["url"] for c in got] == ["https://sdu.sk/campaign"]  # 공식 사이트(ethereum.org)는 경로와 관계없이 뺀다


def test_select_keeps_clue_link_past_limit():
    """기록 20개도 점수 순으로 채운다: 평범한 링크 50개 뒤의 단서 링크가 빠지지 않는다."""
    links = [f"https://s{i}.example{i}.com/" for i in range(50)] + [{"url": "https://late.example/", "text": "환전 안내"}]
    got = select("https://start.example/", "", [], links, PORTS)
    assert len(got) == MAX_FOUND and got[0]["host"] == "late.example"


def test_name_fragments():
    from safetrace.agent.candidates import name_fragments

    assert name_fragments("kc-telegram.com") == {"telegram"}
    assert name_fragments("www.kc-telegram.com") == {"telegram"}
    # 공용 호스팅은 하위 도메인에서만(호스팅 이름 'pages'·'netlify' 는 운영자와 무관)
    assert name_fragments("sp21ct-ravur-biz-melo-kazi.pages.dev") == {"sp21ct", "ravur", "melo", "kazi"}
    assert name_fragments("pages.dev") == set()
    assert name_fragments("netcoins-login-sso-ca.webflow.io") == {"netcoins"}  # 흔한 낱말·짧은 조각은 뺀다
    assert name_fragments("127.0.0.1") == set()


def test_framer_badge_link_is_not_a_fragment_match():
    """공용 호스팅에 올린 사이트의 '만든 곳' 링크(플랫폼 홈)는 이름 조각이 같다고 앞에 두지 않는다."""
    got = select("https://3322abc.framer.website/", "", [],
                 [{"url": "https://other.example/", "text": "x"}, {"url": "https://www.framer.com/", "text": "Made in Framer"}],
                 PORTS)
    assert [(c["host"], c["score"]) for c in got] == [("other.example", 0), ("www.framer.com", 0)]


def test_page_state_has_no_links():
    """링크 목록은 판단 모델 입력(PageState)에 넣지 않는다: 원래 사건의 탐색·판단은 그대로여야 한다."""
    from safetrace.decision.schema import PageState

    assert "links" not in PageState.model_fields


def test_page_links_shape():
    from safetrace.agent.loop import _page_links

    raw = [{"href": "https://a.example/", "text": "문의 010-1234-5678", "visible": True},
           {"href": "javascript:alert(1)", "text": "x"}, {"href": "https://b.example/" + "a" * 3000},
           {"href": 5}, "str", {"href": "http://c.example/", "text": None, "visible": "yes"}] + \
          [{"href": f"https://f{i}.example/"} for i in range(300)]
    got = _page_links(raw)
    assert len(got) == 200
    assert got[0]["url"] == "https://a.example/" and "1234-5678" not in got[0]["text"] and got[0]["visible"] is True
    assert got[1] == {"url": "http://c.example/", "text": "", "visible": False}
    assert _page_links("not a list") == []


def test_candidate_text_is_cut():
    got = select("https://start.example/", "", [], [{"url": "https://a.example/", "text": "가" * 300}], PORTS)
    assert len(got[0]["text"]) == 80


def test_needs_followup():
    benign = {"threat": "benign", "hold": False}
    assert not _needs_followup("COMPLETED", benign, False)          # 확신 있는 정상은 하위 조사하지 않음
    assert _needs_followup("COMPLETED", benign, True)               # 평판 DB 가 위험으로 표시
    assert _needs_followup("REVIEW_REQUIRED", benign, False)
    assert _needs_followup("COMPLETED", {"threat": "phishing", "hold": False}, False)
    assert _needs_followup("COMPLETED", {"threat": "benign", "hold": True}, False)
    assert _needs_followup("COMPLETED", None, False)
    assert not _needs_followup("UNREACHABLE", None, True)
    assert not _needs_followup("FAILED", None, False)


def test_api_cleans_candidates():
    from safetrace.api.main import _clean_candidates

    raw = [{"url": "https://a.example/", "host": "a.example", "sub": 1, "threat": "phishing", "probability": 0.9,
            "hold": False, "evil": "<script>", "status": "x" * 500, "score": 2, "text": "t" * 300, "blocked": True},
           {"url": 5}, "string", {"url": "https://b.example/", "sub": 99, "probability": 7, "score": True, "blocked": "yes"},
           {"url": "https://c.example/", "score": 9}]
    got = _clean_candidates(raw * 10)
    assert len(got) == 20
    assert got[0] == {"url": "https://a.example/", "host": "a.example", "status": "x" * 24, "threat": "phishing",
                      "text": "t" * 80, "hold": False, "blocked": True, "sub": 1, "probability": 0.9, "score": 2}
    assert got[1] == {"url": "https://b.example/"}  # 범위 밖 sub·확률, 정수가 아닌 점수, 참거짓이 아닌 blocked 는 버림
    assert got[2] == {"url": "https://c.example/"}
    assert _clean_candidates("not a list") == []


# ── Codex 검토(후보 하위 조사) 지적 재현 ─────────────────────────
def test_candidate_url_drops_query_and_fragment():
    """F1: 페이지 링크의 쿼리·조각에 든 개인정보는 후보 주소에 남기지 않는다(평판 조회·Jev 로 나가지 않게)."""
    got = select("https://start.example/", "https://start.example/", [],
                 ["https://candidate.example/help?email=alice%40example.com&phone=010-1234-5678#me"], PORTS)
    assert [c["url"] for c in got] == ["https://candidate.example/help"]


def test_mask_pii_url_encoded():
    """F1: URL 인코딩된 이메일·전화번호도 가린다(주소 문자열이 Jev 로 갈 때)."""
    from safetrace.masking import mask_pii

    out = mask_pii("https://x.example/a?e=alice%40example.com&p=010%2D1234%2D5678")
    assert "alice" not in out and "1234" not in out, out


def _fake_runs(monkeypatch, results: dict):
    from safetrace.agent import runner
    from safetrace.agent.loop import RunResult

    class FakeRun:
        def __init__(self, url, s, decider, writer, emit, resolver=None, live=None, sub=0):
            self.url = url

        async def run(self):
            return RunResult(**results[self.url])

    monkeypatch.setattr(runner, "AgentRun", FakeRun)


def test_candidate_redirect_destination_reputation_checked(settings, monkeypatch, tmp_path):
    """F2: 하위 조사에서 넘어간 목적지도 평판을 조회하고, AI 가 정상으로 봐도 일치하면 그 후보를 보류로 표시한다."""
    import uuid

    from safetrace.agent import runner

    _fake_runs(monkeypatch, {
        "https://start.example/": dict(status="COMPLETED", finish_reason="agent_finished", final_url="https://start.example/",
                                       threat={"threat": "phishing", "probability": 0.9, "hold": False},
                                       candidates_found=[{"url": "https://hop.example/", "host": "hop.example", "source": "link"}]),
        "https://hop.example/": dict(status="COMPLETED", finish_reason="agent_finished", final_url="https://bad.example/x",
                                     nav_chain=["https://hop.example/", "https://bad.example/x"],
                                     threat={"threat": "benign", "probability": 0.99, "hold": False}),
    })
    seen: list[list[str]] = []

    def fake_lookup(urls, key, transport=None):
        seen.append(list(urls))
        bad = [u for u in urls if "bad.example" in u]
        return {"status": "match" if bad else "no_match", "matches": [{"url": u, "threat_type": "MALWARE"} for u in bad]}

    monkeypatch.setattr(runner, "lookup", fake_lookup)
    final = runner.investigate(str(uuid.uuid4()), "https://start.example/", settings, lambda e: None, decider=object())
    assert any("https://bad.example/x" in urls for urls in seen), seen
    c = final["candidates"][0]
    assert c["sub"] == 1 and c["threat"] == "benign" and c["reputation_match"] is True and c["hold"] is True, c


# ── Codex 2회차 지적 재현 ─────────────────────────────
def _phish_main(cands):
    return dict(status="COMPLETED", finish_reason="agent_finished", final_url="https://start.example/",
                threat={"threat": "phishing", "probability": 0.9, "hold": False}, candidates_found=cands)


def _benign_sub(final, nav=()):
    return dict(status="COMPLETED", finish_reason="agent_finished", final_url=final, nav_chain=list(nav),
                threat={"threat": "benign", "probability": 0.99, "hold": False})


def _run(settings, monkeypatch, runs, lookup_fn):
    import uuid

    from safetrace.agent import runner

    _fake_runs(monkeypatch, runs)
    monkeypatch.setattr(runner, "lookup", lookup_fn)
    cid = str(uuid.uuid4())
    final = runner.investigate(cid, "https://start.example/", settings, lambda e: None, decider=object())
    import json
    chain = [json.loads(x) for x in (settings.evidence_dir / cid / "chain.jsonl").read_text(encoding="utf-8").splitlines()]
    return final, chain


def test_candidate_path_pii_not_sent_to_reputation(settings, monkeypatch):
    """2회차 F1: 경로에 개인정보가 든 후보 주소는 평판 조회로 보내지 않고, 조회하지 못했다고 표시한다."""
    pii = "https://candidate.example/u/alice%40example.com/010-1234-5678"
    cands = select("https://start.example/", "https://start.example/", [], [pii], PORTS)
    sent: list[str] = []

    def lookup(urls, key, transport=None):
        sent.extend(urls)
        return {"status": "no_match", "matches": []}

    final, _ = _run(settings, monkeypatch, {"https://start.example/": _phish_main(cands),
                                            cands[0]["url"]: _benign_sub(cands[0]["url"])}, lookup)
    assert not any("alice" in u or "1234" in u for u in sent), sent
    assert final["candidates"][0]["reputation_unchecked"] is True


def test_first_match_survives_failed_followup_lookup(settings, monkeypatch):
    """2회차 F2: 첫 조회에서 위험이 일치한 후보는 두 번째 조회가 실패해도 보류로 남는다."""
    cand = {"url": "https://hop.example/", "host": "hop.example", "source": "link"}
    calls = {"n": 0}

    def lookup(urls, key, transport=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"status": "match", "matches": [{"url": "https://hop.example/", "threat_type": "MALWARE"}]}
        return {"status": "error", "matches": []}

    final, chain = _run(settings, monkeypatch, {"https://start.example/": _phish_main([cand]),
                                                "https://hop.example/": _benign_sub("https://hop.example/")}, lookup)
    c = final["candidates"][0]
    assert (c["reputation_match"], c["hold"]) == (True, True), c
    res = next(r["data"] for r in chain if r["kind"] == "candidate_results")["results"][0]
    assert res["hold"] is True


def test_blocked_candidate_marked(settings, monkeypatch):
    """related-sites PR 2: 하위 조사에서 회선이 이름을 보고 막은 후보는 '이미 차단됨'(blocked)으로 남는다."""
    cands = [{"url": f"https://c{i}.example/", "host": f"c{i}.example", "source": "link", "score": 0, "text": ""}
             for i in (1, 2)]
    blocked = dict(status="UNREACHABLE", finish_reason="goto_failed", final_url="https://c1.example/",
                   network_filtered=True)
    final, chain = _run(settings, monkeypatch, {"https://start.example/": _phish_main(cands),
                                                "https://c1.example/": blocked,
                                                "https://c2.example/": _benign_sub("https://c2.example/")},
                        lambda urls, key, transport=None: {"status": "no_match", "matches": []})
    assert [c["blocked"] for c in final["candidates"]] == [True, False]
    res = next(r["data"] for r in chain if r["kind"] == "candidate_results")["results"]
    assert [r["blocked"] for r in res] == [True, False]


def test_package_keeps_new_candidate_fields():
    from safetrace.package import clean_records

    recs = [{"seq": 1, "kind": "candidates", "ts": "t", "files": {},
             "data": {"found": [{"url": "https://a.example/", "host": "a.example", "source": "link", "score": 2,
                                 "text": "충전"}], "followup": True}},
            {"seq": 2, "kind": "candidate_results", "ts": "t", "files": {},
             "data": {"results": [{"sub": 1, "url": "https://a.example/", "blocked": True, "score": 2}]}},
            {"seq": 3, "kind": "observe", "ts": "t", "files": {}, "data": {"links_seen": 200}}]
    out, bad = clean_records(recs)
    assert bad == []
    assert out[0]["data"]["found"][0]["score"] == 2 and out[1]["data"]["results"][0]["blocked"] is True
    assert out[2]["data"]["links_seen"] == 200


def test_every_candidate_destination_checked(settings, monkeypatch):
    """2회차 F3: 앞 후보의 긴 이동 경로가 뒤 후보의 최종 목적지를 조회 한도 밖으로 밀어내지 않는다."""
    cands = [{"url": f"https://c{i}.example/", "host": f"c{i}.example", "source": "link"} for i in (1, 2, 3)]
    runs = {"https://start.example/": _phish_main(cands)}
    for i in (1, 2):
        nav = [f"https://c{i}.example/"] + [f"https://c{i}-hop{j}.example/" for j in range(5)]
        runs[f"https://c{i}.example/"] = _benign_sub(nav[-1], nav)
    runs["https://c3.example/"] = _benign_sub("https://bad.example/x", ["https://c3.example/", "https://bad.example/x"])

    def lookup(urls, key, transport=None):
        bad = [u for u in urls if "bad.example" in u]
        return {"status": "match" if bad else "no_match", "matches": [{"url": u, "threat_type": "MALWARE"} for u in bad]}

    final, _ = _run(settings, monkeypatch, runs, lookup)
    c3 = next(c for c in final["candidates"] if c["host"] == "c3.example")
    assert (c3["reputation_match"], c3["hold"]) == (True, True), c3


def test_blocked_is_shown_as_estimate():
    """Codex(PR 2) F2: 회선 차단 감지는 조사 대상 서버가 흉내 낼 수 있는 동작이라 '확정'으로 적지 않는다."""
    from safetrace.report import related_opinion

    got = related_opinion({"threat_ko": "피싱", "probability": 0.9, "hold": False, "blocked": True, "error": False})
    assert got.endswith("회선 차단 추정") and "이미 차단됨" not in got


def test_select_drops_forbidden_links():
    """Codex(PR 2) 2회차: 수집 쪽을 지나온 링크라도 결제·다운로드 링크는 후보로 고르지 않는다."""
    got = select("https://start.example/", "", [],
                 [{"url": "https://pay.example/x", "text": "카지노 결제하기"}, {"url": "https://app.example/a.apk", "text": "받기"},
                  {"url": "https://ok.example/", "text": "카지노"}], PORTS)
    assert [c["host"] for c in got] == ["ok.example"]


# ── related-sites PR 3: 원래 결과 먼저 ─────────────────────────
def test_main_result_sent_before_subinvestigation(settings, monkeypatch):
    """하위 조사 전에 원래 결과(phase=related)를 보내고, 종료 상태의 상태·사유·위협은 그것과 같다."""
    import uuid

    from safetrace.agent import runner

    cands = [{"url": "https://c1.example/", "host": "c1.example", "source": "link", "score": 0, "text": ""}]
    order: list[str] = []

    class FakeRun:
        def __init__(self, url, s, decider, writer, emit, resolver=None, live=None, sub=0):
            self.url, self.sub = url, sub

        async def run(self):
            from safetrace.agent.loop import RunResult

            order.append(f"run:{self.sub}")
            if self.sub:
                return RunResult(**_benign_sub(self.url))
            return RunResult(**_phish_main(cands))

    monkeypatch.setattr(runner, "AgentRun", FakeRun)
    monkeypatch.setattr(runner, "lookup", lambda urls, key, transport=None: {"status": "no_match", "matches": []})
    events: list[dict] = []

    def emit(e):
        events.append(e)
        if e.get("type") == "status":
            order.append(f"status:{e['status']}:{e.get('phase')}")

    final = runner.investigate(str(uuid.uuid4()), "https://start.example/", settings, emit, decider=object())
    assert order == ["status:RUNNING:None", "run:0", "status:RUNNING:related", "run:1", f"status:{final['status']}:None"]
    main = next(e for e in events if e.get("phase") == "related")
    assert (main["main"]["status"], main["main"]["reason"]) == (final["status"], final["reason"])
    assert main["threat"] == final["threat"] and main["final_url"] == final["final_url"]
    assert [c["url"] for c in main["candidates"]] == ["https://c1.example/"] and "sub" not in main["candidates"][0]


def test_no_main_result_event_without_subinvestigation(settings, monkeypatch):
    """확신 있는 정상(하위 조사 안 함)은 지금처럼 종료 상태 하나만 보낸다."""
    import uuid

    from safetrace.agent import runner

    benign = dict(status="COMPLETED", finish_reason="agent_finished", final_url="https://start.example/",
                  threat={"threat": "benign", "probability": 0.99, "hold": False},
                  candidates_found=[{"url": "https://c1.example/", "host": "c1.example", "source": "link"}])
    _fake_runs(monkeypatch, {"https://start.example/": benign})
    monkeypatch.setattr(runner, "lookup", lambda urls, key, transport=None: {"status": "no_match", "matches": []})
    events: list[dict] = []
    runner.investigate(str(uuid.uuid4()), "https://start.example/", settings, events.append, decider=object())
    assert not any(e.get("phase") for e in events)

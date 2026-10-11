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
        {"url": "https://hop.example.net/", "host": "hop.example.net", "source": "via"},  # 경유: 사이트 첫 화면
        {"url": "https://other-scam.top/", "host": "other-scam.top", "source": "link"},
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
            "hold": False, "evil": "<script>", "status": "x" * 500},
           {"url": 5}, "string", {"url": "https://b.example/", "sub": 99, "probability": 7}]
    got = _clean_candidates(raw * 10)
    assert len(got) == 20
    assert got[0] == {"url": "https://a.example/", "host": "a.example", "status": "x" * 24, "threat": "phishing",
                      "hold": False, "sub": 1, "probability": 0.9}
    assert got[1] == {"url": "https://b.example/"}  # 범위 밖 sub·확률은 버림
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

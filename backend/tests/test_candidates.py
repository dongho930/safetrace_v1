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

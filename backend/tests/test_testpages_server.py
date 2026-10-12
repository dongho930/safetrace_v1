"""시험 페이지 서버: 공격 시나리오 판정에 쓰는 금지 도달 기록은 조사 대상 페이지가 지울 수 없어야 한다(Codex F1)."""

import json
import urllib.error
import urllib.request

import pytest


@pytest.fixture
def srv():
    import server  # testpages/server.py

    s, rec = server.start(8902)
    yield rec
    s.shutdown()


def hit(path):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:8902{path}").read()  # noqa: S310
    except urllib.error.HTTPError:
        pass  # 없는 파일이어도 요청은 기록된다


def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:8902{path}") as r:  # noqa: S310
        return json.loads(r.read())


def test_page_cannot_clear_forbidden_hits(srv):
    hit("/gamble/pay.html")  # 금지 도달 1건
    start = get("/__hits")
    assert start["total"] >= 1 and any(p.startswith("/gamble/pay.html") for _, p in start["hits"])
    # 조사 대상 페이지가 <img src="/__hits?clear=1"> 로 기록을 지우려 해도 남는다
    hit("/__hits?clear=1")
    assert any(p.startswith("/gamble/pay.html") for _, p in get("/__hits")["hits"])
    # 시험 도구는 지우지 않고 시작 위치(since) 이후만 읽는다
    cursor = get("/__hits")["total"]
    assert get(f"/__hits?since={cursor}")["hits"] == []
    hit("/smish/pay.html")
    assert [p for _, p in get(f"/__hits?since={cursor}")["hits"]] == ["/smish/pay.html"]

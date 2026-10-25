"""자동 수집 피드 받기(agent/feeds.py)의 접속 안전장치. 지운 재확인(조치 추적, 2026-10-25)과 같이 쓰던 HTTP 도우미를 자동
수집이 넘겨받아, 그때 Codex 정탐으로 만든 시험(프록시 거부 사유·rebinding·느린 응답·압축 폭탄)을 이쪽으로 옮겼다."""

import gzip
import socket
import threading
import time
import tracemalloc

from safetrace.agent import feeds

NL = chr(13) + chr(10)


def _serve_once(handler) -> int:
    """연결 하나를 받아 handler(conn) 를 부르는 작은 서버. 반환: 포트."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def run():
        try:
            conn, _ = srv.accept()
            with conn:
                conn.recv(4096)
                handler(conn)
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def _feed(monkeypatch, url: str) -> None:
    monkeypatch.setitem(feeds.FEEDS, "openphish", url)


def test_refusal_reason_comes_from_proxy_connect(monkeypatch):
    """검문 프록시가 CONNECT 에 답한 거부 사유를 그대로 쓴다(도메인 없음·정책 거부)."""
    _feed(monkeypatch, "https://gone.example/feed.txt")
    for reason in ("dns_failure", "non_public_ip"):
        port = _serve_once(lambda c, r=reason: c.sendall(
            f"HTTP/1.1 403 Forbidden{NL}X-SafeTrace-Egress: {r}{NL}Connection: close{NL}{NL}".encode()))
        got = feeds.fetch("openphish", f"http://127.0.0.1:{port}")
        assert (got["ok"], got["reason"]) == (False, reason)


def test_target_cannot_forge_egress_refusal(monkeypatch):
    """대상 서버가 검문 프록시의 거부 머리(X-SafeTrace-Egress)를 흉내 내도 거부로 읽지 않는다(CONNECT 응답만 믿는다)."""
    port = _serve_once(lambda c: c.sendall(f"HTTP/1.1 200 OK{NL}X-SafeTrace-Egress: dns_failure{NL}Content-Length: 2{NL}"
                                           f"Connection: close{NL}{NL}ok".encode()))
    _feed(monkeypatch, f"http://127.0.0.1:{port}/feed.txt")
    got = feeds.fetch("openphish", None, {f"127.0.0.1:{port}"})
    assert got["ok"] and got["text"] == "ok"


def test_no_proxy_only_allowlisted_host_port(monkeypatch):
    """검문 프록시가 없으면(개발 모드) 허용 목록의 '호스트:포트' 에만 접속한다. 이름을 따로 풀어 검사하면 rebinding 으로
    내부 주소에 닿을 수 있어서, 내부 주소로 풀리는 이름도 목록에 없으면 접속하지 않는다."""
    real = socket.getaddrinfo
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, *a, **k: real("127.0.0.1" if host == "rebind.example" else host, *a, **k))
    _feed(monkeypatch, "http://rebind.example:8900/feed.txt")
    got = feeds.fetch("openphish", None, {"127.0.0.1:8900"})
    assert (got["ok"], got["reason"]) == (False, "no_egress_proxy")


def test_slow_headers_respect_budget(monkeypatch):
    """응답 머리를 조금씩 보내는 서버가 시간 예산(budget)을 넘겨 수집 컨테이너를 붙잡지 못한다."""
    def drip(c):
        c.sendall(f"HTTP/1.1 200 OK{NL}".encode())
        for _ in range(16):
            time.sleep(0.5)
            try:
                c.sendall(f"X: y{NL}".encode())
            except OSError:
                return

    port = _serve_once(drip)
    _feed(monkeypatch, f"http://127.0.0.1:{port}/feed.txt")
    t0 = time.monotonic()
    got = feeds.fetch("openphish", None, {f"127.0.0.1:{port}"}, budget=2.0)
    assert time.monotonic() - t0 < 4.5 and (got["ok"], got["reason"]) == (False, "timeout")


def test_double_gzip_is_not_inflated_without_limit(monkeypatch):
    """이중 gzip 으로 크게 풀리는 응답을 상한 없이 풀지 않는다(한 단계만, MAX_BYTES 까지)."""
    body = gzip.compress(gzip.compress(b"\0" * (64 << 20)))  # 64MiB 가 약 65KB 로
    head = (f"HTTP/1.1 200 OK{NL}Content-Encoding: gzip, gzip{NL}Content-Length: {len(body)}{NL}Connection: close{NL}{NL}")
    port = _serve_once(lambda c: c.sendall(head.encode() + body))
    _feed(monkeypatch, f"http://127.0.0.1:{port}/feed.txt")
    tracemalloc.start()
    try:
        got = feeds.fetch("openphish", None, {f"127.0.0.1:{port}"})
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert got["ok"] and len(got["text"]) <= feeds.MAX_BYTES and peak < (16 << 20), peak


def test_single_gzip_feed_is_read(monkeypatch):
    """압축 없이 달라고 해도 gzip 으로 보내는 서버의 피드는 한 단계 풀어 읽는다."""
    body = gzip.compress(b"https://a.example/x\nhttps://b.example/y\n")
    head = f"HTTP/1.1 200 OK{NL}Content-Encoding: gzip{NL}Content-Length: {len(body)}{NL}Connection: close{NL}{NL}"
    port = _serve_once(lambda c: c.sendall(head.encode() + body))
    _feed(monkeypatch, f"http://127.0.0.1:{port}/feed.txt")
    got = feeds.fetch("openphish", None, {f"127.0.0.1:{port}"})
    assert got["ok"] and got["text"].split() == ["https://a.example/x", "https://b.example/y"]

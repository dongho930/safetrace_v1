"""회선의 도메인 이름 차단 감지: 같은 주소에 진짜 이름만 끊기고 무관한 이름에는 답하는지."""

import socket
import struct
import threading

import pytest

from safetrace.agent import netfilter

TLS_ALERT = b"\x15\x03\x03\x00\x02\x02\x28"  # handshake_failure: 서버가 '답은 한' 경우


def _serve(mode: str, tls: bool):
    """mode: name_block(이름 'localhost' 가 보이면 끊음) | down(모두 끊음) | up(모두 답함)"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                c.settimeout(3)
                data = c.recv(4096)
                if mode == "down" or (mode == "name_block" and b"localhost" in data):
                    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))  # RST
                else:
                    c.sendall(TLS_ALERT if tls else b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                c.close()

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


@pytest.mark.parametrize("tls", [True, False])
@pytest.mark.parametrize("mode, filtered", [("name_block", True), ("down", False), ("up", False)])
def test_probe_detects_name_based_blocking(tls, mode, filtered):
    srv, port = _serve(mode, tls)
    try:
        url = f"{'https' if tls else 'http'}://localhost:{port}/"
        got = netfilter.probe(url, allow={f"localhost:{port}"})
    finally:
        srv.close()
    assert got["filtered"] is filtered, got
    if mode == "up":
        assert got["target"] == "responded" and got["control"] == "skipped"


def test_probe_refuses_private_address_without_allowlist():
    srv, port = _serve("name_block", False)
    try:
        got = netfilter.probe(f"http://localhost:{port}/")
    finally:
        srv.close()
    assert got["target"] == "error" and not got["filtered"]


@pytest.mark.parametrize("url, expected", [
    ("http://warning.or.kr/i1.html", True),
    ("https://www.warning.or.kr/", True),
    ("https://warning.or.kr.evil.example/", False),
    ("https://example.com/?u=warning.or.kr", False),
])
def test_warning_page(url, expected):
    assert netfilter.is_warning_page(url) is expected

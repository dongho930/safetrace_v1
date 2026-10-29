"""회선의 도메인 이름 차단 감지: 같은 주소에 진짜 이름만 끊기고 무관한 이름에는 답하는지."""

import shutil
import socket
import ssl
import struct
import subprocess
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


@pytest.fixture(scope="module")
def self_signed(tmp_path_factory):
    """이름 localhost 의 자체 서명 인증서. 조사 컨테이너가 믿지 않는 인증서라 검증에서 떨어진다."""
    if not shutil.which("openssl"):
        pytest.skip("openssl 없음")
    d = tmp_path_factory.mktemp("tls")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True, timeout=30)
    return cert, key


def _serve_tls(mode: str, cert, key):
    """진짜 TLS 서버. mode: name_block(첫 인사에 'localhost' 가 보이면 끊음) | up(모두 인증서를 보냄)"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
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
                if mode == "name_block" and b"localhost" in c.recv(4096, socket.MSG_PEEK):
                    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))  # RST
                else:
                    with ctx.wrap_socket(c, server_side=True):
                        pass
            except (OSError, ssl.SSLError):
                pass  # 조사기 쪽이 인증서를 믿지 않아 끊는다
            finally:
                c.close()

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


@pytest.mark.parametrize("mode, target, filtered", [("name_block", "dropped", True), ("up", "responded", False)])
def test_probe_with_untrusted_certificate(self_signed, mode, target, filtered):
    """인증서 검증을 켜도 결과가 같다: 믿지 않는 인증서·맞지 않는 이름도 서버가 답한 것으로 본다."""
    srv, port = _serve_tls(mode, *self_signed)
    try:
        got = netfilter.probe(f"https://localhost:{port}/", allow={f"localhost:{port}"})
    finally:
        srv.close()
    assert got["target"] == target and got["filtered"] is filtered, got
    if mode == "name_block":
        assert got["control"] == "responded"


def test_probe_keeps_certificate_verification(self_signed, monkeypatch):
    """조사기가 TLS 인증서·이름 검증을 끄지 않는다. 믿는 인증서면 이름 검증까지 통과해 끝까지 연결한다."""
    cert, key = self_signed
    made: list[ssl.SSLContext] = []
    default = ssl.create_default_context

    def trusting():
        ctx = default(cafile=str(cert))
        made.append(ctx)
        return ctx

    monkeypatch.setattr(netfilter.ssl, "create_default_context", trusting)
    srv, port = _serve_tls("up", cert, key)
    try:
        got = netfilter.probe(f"https://localhost:{port}/", allow={f"localhost:{port}"})
    finally:
        srv.close()
    assert got["target"] == "responded", got
    assert made and all(c.verify_mode == ssl.CERT_REQUIRED and c.check_hostname for c in made)


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

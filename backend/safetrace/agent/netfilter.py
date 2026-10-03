"""네트워크 차단(통신사·기관의 도메인 이름 차단) 감지.

국내 회선은 차단 목록에 오른 사이트를 두 방식으로 막는다.
- 연결 끊기: TLS SNI·HTTP Host 에 그 도메인 이름이 실리면 응답 없이 연결을 끊는다(같은 IP 의 다른 이름은 정상)
- 안내 화면: warning.or.kr 차단 안내 페이지로 보낸다

첫 접속이 연결 끊김으로 실패하면 같은 주소에 한 번은 진짜 이름으로, 한 번은 무관한 이름으로 다시 연결해 본다.
진짜 이름만 끊기고 무관한 이름에는 서버가 답하면 사이트가 내려간 것이 아니라 이름을 보고 막은 것이다.
보내는 것은 TLS 첫 인사(ClientHello) 또는 'GET /' 한 줄뿐이고, 받은 내용은 읽지 않는다.
"""

from __future__ import annotations

import socket
import ssl
from urllib.parse import urlsplit

from ..netguard import BlockedURL, is_public_ip, resolve

CONTROL_NAME = "www.example.com"  # 비교용 무관한 이름
WARNING_HOSTS = ("warning.or.kr",)  # 국내 차단 안내 페이지
# 첫 접속 실패 중 '연결은 됐는데 끊긴' 경우만 확인한다(DNS 실패·연결 거부·시간 초과는 사이트 쪽 문제로 본다)
DROPPED_ERRORS = {"ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED", "ERR_EMPTY_RESPONSE"}
_TIMEOUT = 6.0


def is_warning_page(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return any(host == h or host.endswith("." + h) for h in WARNING_HOSTS)


def _open(host: str, port: int, proxy: str | None, allow: set[str]) -> socket.socket:
    """대상에 TCP 로 연결한다. 검문 프록시가 있으면 CONNECT 로(프록시가 IP 를 검사), 없으면 공인 IP 만."""
    if proxy:
        p = urlsplit(proxy)
        s = socket.create_connection((p.hostname, p.port or 3128), _TIMEOUT)
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 4096:
            chunk = s.recv(1024)
            if not chunk:
                break
            head += chunk
        if not head.startswith((b"HTTP/1.1 200", b"HTTP/1.0 200")):
            s.close()
            raise OSError("proxy_refused")
        return s
    ips = resolve(host, port)
    if f"{host}:{port}" not in allow and not all(is_public_ip(ip) for ip in ips):
        raise BlockedURL("non_public_ip", host)
    err: OSError = OSError("no_address")
    for ip in ips:  # 검사한 주소에만, 차례로
        try:
            return socket.create_connection((ip, port), _TIMEOUT)
        except OSError as e:
            err = e
    raise err


def _attempt(host: str, port: int, tls: bool, name: str, proxy: str | None, allow: set[str]) -> str:
    """name 을 SNI/Host 로 실어 연결해 본다. dropped(응답 없이 끊김) | responded(서버가 무엇이든 답함) | error"""
    try:
        s = _open(host, port, proxy, allow)
    except (OSError, BlockedURL):
        return "error"
    try:
        s.settimeout(_TIMEOUT)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with ctx.wrap_socket(s, server_hostname=name):
                    return "responded"  # 핸드셰이크 완료
            except (ssl.SSLEOFError, ConnectionError):
                return "dropped"
            except ssl.SSLError as e:
                # 서버가 경고(alert)로 거절한 것도 답한 것이다. 상대가 그냥 끊으면 EOF 로 나온다
                return "dropped" if "EOF" in str(e).upper() else "responded"
        s.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
        return "responded" if s.recv(1) else "dropped"
    except ConnectionError:
        return "dropped"
    except OSError:  # 시간 초과 등: 판단하지 않는다
        return "error"
    finally:
        s.close()


def probe(url: str, proxy: str | None = None, allow: set[str] | None = None) -> dict:
    """같은 주소에 진짜 이름과 무관한 이름으로 연결해 본 결과. filtered=True 면 이름을 보고 막은 것이다."""
    u = urlsplit(url)
    tls = u.scheme == "https"
    host, port = u.hostname or "", u.port or (443 if tls else 80)
    allow = allow or set()
    target = _attempt(host, port, tls, host, proxy, allow)
    control = _attempt(host, port, tls, CONTROL_NAME, proxy, allow) if target == "dropped" else "skipped"
    return {"method": "name_probe", "port": port, "target": target, "control": control,
            "filtered": target == "dropped" and control == "responded"}

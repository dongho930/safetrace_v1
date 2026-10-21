"""재확인(조치 추적): 조치를 추적 중인 사건의 신고 주소에 다시 접속해 지금 상태를 본다.

격리된 조사 컨테이너 안에서 검문 프록시(내부망·예약 주소를 막는다)를 거쳐 GET 만 한다. 브라우저를 띄우지 않고 화면을
기록하지 않는다(증거 수집이 아니라 '아직 살아 있나'만 본다). 본문은 제목을 읽을 만큼(256KB)만, 리다이렉트는 직접
5번까지, 전체 20초 안에서.

결과: alive(서버가 답함) · gone(도메인 없음·404·410) · filtered(회선이 이름을 보고 막음·warning.or.kr 안내) ·
refused(검문 프록시 정책 거부) · unreachable(연결 실패·시간 초과) · error
"""

from __future__ import annotations

import html
import re
import socket
import time
from urllib.parse import urljoin, urlsplit

import httpx

from ..masking import mask_pii
from ..netguard import BlockedURL, is_public_ip, resolve
from ..proxy.egress import EGRESS_HEADER
from . import netfilter

MAX_BODY = 256 * 1024
BUDGET_S = 20.0
MAX_REDIRECTS = 5
_REDIRECT = {301, 302, 303, 307, 308}
_GONE = {404, 410}
_TITLE = re.compile(r"<title\b[^<>]*>([^<]{0,500})", re.I)  # 앞으로만 찾는다(닫히지 않은 '<' 가 이어져도 선형)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"


def _connect_reason(host: str, port: int, proxy: str) -> tuple[int, str]:
    """검문 프록시에 CONNECT 만 보내 연결할 수 있는지와 거부 사유(머리 X-SafeTrace-Egress)를 본다. (상태 코드, 사유)."""
    p = urlsplit(proxy)
    with socket.create_connection((p.hostname, p.port or 3128), 8) as s:
        s.settimeout(12)
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 4096:
            chunk = s.recv(1024)
            if not chunk:
                break
            head += chunk
    lines = head.decode("latin-1", "replace").split("\r\n")
    parts = lines[0].split(" ")
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    reason = next((ln.split(":", 1)[1].strip() for ln in lines[1:] if ln.lower().startswith(EGRESS_HEADER.lower() + ":")), "")
    return code, reason[:64]


def _guard(url: str, allow: set[str]) -> None:
    """검문 프록시가 없을 때(개발 모드) 접속 전에 공인 주소인지 본다. 운영은 검문 프록시가 연결 시점에 다시 검사한다."""
    u = urlsplit(url)
    host, port = (u.hostname or "").lower(), u.port or (443 if u.scheme == "https" else 80)
    if f"{host}:{port}" in allow:
        return
    if not all(is_public_ip(ip) for ip in resolve(host, port)):
        raise BlockedURL("non_public_ip", host)


def _get(url: str, proxy: str | None, deadline: float, allow: set[str]) -> dict:
    out = {"http_status": None, "final_url": url, "title": "", "refused": ""}
    transport = httpx.HTTPTransport(proxy=proxy) if proxy else None
    with httpx.Client(transport=transport, follow_redirects=False, timeout=8, verify=False,  # nosec B501 피싱 사이트 인증서
                      headers={"User-Agent": UA}) as client:
        cur = url
        for _hop in range(MAX_REDIRECTS + 1):
            if time.monotonic() > deadline:
                raise TimeoutError
            if not proxy:
                _guard(cur, allow)
            with client.stream("GET", cur) as r:
                loc = r.headers.get("location")
                out["http_status"], out["final_url"] = r.status_code, str(r.url)
                out["refused"] = r.headers.get(EGRESS_HEADER, "")[:64]
                if r.status_code in _REDIRECT and loc and not out["refused"]:
                    nxt = urljoin(str(r.url), loc)
                    if urlsplit(nxt).scheme not in ("http", "https"):
                        return out
                    cur = nxt
                    continue
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf += chunk[: MAX_BODY - len(buf)]
                    if len(buf) >= MAX_BODY or time.monotonic() > deadline:
                        break
                m = _TITLE.search(bytes(buf).decode(r.encoding or "utf-8", errors="replace"))
                if m:
                    out["title"] = mask_pii(" ".join(html.unescape(m.group(1)).split()))[:200]
                return out
    return out


def check(url: str, proxy: str | None, allow: set[str] | None = None, budget: float = BUDGET_S) -> dict:
    """신고 주소의 지금 상태. {result, reason, http_status, final_host, title, seconds}"""
    t0 = time.monotonic()
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    out = {"result": "error", "reason": "", "http_status": None, "final_host": host, "title": ""}

    def done(result: str, reason: str = "") -> dict:
        out.update(result=result, reason=reason[:64], seconds=round(time.monotonic() - t0, 2))
        return out

    if u.scheme not in ("http", "https") or not host:
        return done("error", "bad_url")
    tls = u.scheme == "https"
    port = u.port or (443 if tls else 80)
    if proxy and tls:  # HTTPS 는 CONNECT 거부 사유로 도메인 없음·정책 거부·연결 실패를 먼저 가른다
        try:
            code, reason = _connect_reason(host, port, proxy)
        except OSError:
            return done("error", "proxy_unavailable")
        if code == 403:
            return done("gone" if reason == "dns_failure" else "refused", reason or "egress_403")
        if code != 200:
            return done("unreachable", reason or f"egress_{code}")
    try:
        r = _get(url, proxy, t0 + budget, allow or set())
    except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError, ConnectionError):
        # 연결은 됐는데 끊김: 회선이 이름을 보고 막은 것인지 진짜 이름·무관한 이름으로 다시 연결해 본다(netfilter)
        nf = netfilter.probe(url, proxy, allow or set())
        return done("filtered", "name_filtered") if nf.get("filtered") else done("unreachable", "connection_dropped")
    except (httpx.TimeoutException, TimeoutError):
        return done("unreachable", "timeout")
    except BlockedURL as e:
        return done("gone" if e.reason == "dns_failure" else "refused", e.reason)
    except httpx.HTTPError as e:
        return done("error", type(e).__name__)
    out.update(http_status=r["http_status"], final_host=(urlsplit(r["final_url"]).hostname or host).lower()[:253],
               title=r["title"])
    if r["refused"]:
        return done("gone" if r["refused"] == "dns_failure" else
                    "unreachable" if r["refused"] == "upstream_unreachable" else "refused", r["refused"])
    if netfilter.is_warning_page(r["final_url"]):
        return done("filtered", "warning_page")
    if r["http_status"] in _GONE:
        return done("gone", f"http_{r['http_status']}")
    return done("alive", f"http_{r['http_status']}")

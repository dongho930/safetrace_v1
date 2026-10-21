"""재확인(조치 추적): 조치를 추적 중인 사건의 신고 주소에 다시 접속해 지금 상태를 본다.

격리된 조사 컨테이너 안에서 검문 프록시(내부망·예약 주소를 막는다)를 거쳐 GET 만 한다. 브라우저를 띄우지 않고 화면을
기록하지 않는다(증거 수집이 아니라 '아직 살아 있나'만 본다). 본문은 제목을 읽을 만큼(256KB)만, 리다이렉트는 직접
5번까지, 접속 전체(프록시 확인·머리·본문)에 시간 예산을 두고 넘으면 연결을 닫는다(머리를 조금씩 보내는 서버, Codex 지적).

- 검문 프록시의 거부 사유는 CONNECT 응답(프록시가 직접 답한 것)에서만 읽는다. GET 응답의 같은 이름 머리는 대상 서버가
  흉내 낼 수 있어 쓰지 않는다(Codex 지적). 리다이렉트로 다른 곳에 갈 때마다 다시 CONNECT 로 확인한다
- 검문 프록시가 없으면(개발 모드) 시험 허용 목록의 주소에만 접속한다. 이름 검사와 연결이 DNS 를 따로 풀면 rebinding 으로
  내부 주소에 닿을 수 있어서다(Codex 지적)

결과: alive(서버가 답함) · gone(도메인 없음·404·410) · filtered(회선이 이름을 보고 막음·warning.or.kr 안내) ·
refused(정책상 접속 안 함) · unreachable(연결 실패·시간 초과) · error
"""

from __future__ import annotations

import asyncio
import html
import re
import time
from urllib.parse import urljoin, urlsplit

import httpx

from ..masking import mask_pii
from ..proxy.egress import EGRESS_HEADER
from . import netfilter

MAX_BODY = 256 * 1024
BUDGET_S = 20.0
MAX_REDIRECTS = 5
_REDIRECT = {301, 302, 303, 307, 308}
_GONE = {404, 410}
_TITLE = re.compile(r"<title\b[^<>]*>([^<]{0,500})", re.I)  # 앞으로만 찾는다(닫히지 않은 '<' 가 이어져도 선형)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"


class _Stop(Exception):
    """접속하지 않고(또는 더 가지 않고) 끝낼 결과."""

    def __init__(self, result: str, reason: str):
        super().__init__(reason)
        self.result, self.reason = result, reason


async def _connect_reason(host: str, port: int, proxy: str) -> tuple[int, str]:
    """검문 프록시에 CONNECT 만 보내 연결할 수 있는지와 거부 사유를 본다. 이 응답은 프록시가 직접 쓴 것이다."""
    p = urlsplit(proxy)
    reader, writer = await asyncio.open_connection(p.hostname, p.port or 3128)
    try:
        writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        await writer.drain()
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 4096:
            chunk = await reader.read(1024)
            if not chunk:
                break
            head += chunk
    finally:
        writer.close()
    lines = head.decode("latin-1", "replace").split("\r\n")
    parts = lines[0].split(" ")
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    reason = next((ln.split(":", 1)[1].strip() for ln in lines[1:] if ln.lower().startswith(EGRESS_HEADER.lower() + ":")), "")
    return code, reason[:64]


async def _allowed(url: str, proxy: str | None, allow: set[str]) -> None:
    """이 주소에 접속해도 되는지. 안 되면 _Stop."""
    u = urlsplit(url)
    host, port = (u.hostname or "").lower(), u.port or (443 if u.scheme == "https" else 80)
    if u.scheme not in ("http", "https") or not host:
        raise _Stop("error", "bad_url")
    if not proxy:
        if f"{host}:{port}" not in allow:
            raise _Stop("refused", "no_egress_proxy")
        return
    try:
        code, reason = await _connect_reason(host, port, proxy)
    except OSError:
        raise _Stop("error", "proxy_unavailable") from None
    if code == 403:
        raise _Stop("gone" if reason == "dns_failure" else "refused", reason or "egress_403")
    if code != 200:
        raise _Stop("unreachable", reason or f"egress_{code}")


async def _get(url: str, proxy: str | None, allow: set[str]) -> dict:
    out = {"http_status": None, "final_url": url, "title": ""}
    transport = httpx.AsyncHTTPTransport(proxy=proxy) if proxy else None
    async with httpx.AsyncClient(transport=transport, follow_redirects=False, timeout=8, verify=False,  # nosec B501
                                 headers={"User-Agent": UA}) as client:  # 피싱 사이트 인증서는 검증하지 않는다
        cur = url
        for _hop in range(MAX_REDIRECTS + 1):
            await _allowed(cur, proxy, allow)
            async with client.stream("GET", cur) as r:
                loc = r.headers.get("location")
                out["http_status"], out["final_url"] = r.status_code, str(r.url)
                if r.status_code in _REDIRECT and loc:
                    nxt = urljoin(str(r.url), loc)
                    if urlsplit(nxt).scheme not in ("http", "https"):
                        return out
                    cur = nxt
                    continue
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    buf += chunk[: MAX_BODY - len(buf)]
                    if len(buf) >= MAX_BODY:
                        break
                m = _TITLE.search(bytes(buf).decode(r.encoding or "utf-8", errors="replace"))
                if m:
                    out["title"] = mask_pii(" ".join(html.unescape(m.group(1)).split()))[:200]
                return out
    return out


def check(url: str, proxy: str | None, allow: set[str] | None = None, budget: float = BUDGET_S) -> dict:
    """신고 주소의 지금 상태. {result, reason, http_status, final_host, title, seconds}"""
    t0 = time.monotonic()
    allow = allow or set()
    host = (urlsplit(url).hostname or "").lower()
    out = {"result": "error", "reason": "", "http_status": None, "final_host": host, "title": ""}

    def done(result: str, reason: str = "") -> dict:
        out.update(result=result, reason=reason[:64], seconds=round(time.monotonic() - t0, 2))
        return out

    try:
        r = asyncio.run(asyncio.wait_for(_get(url, proxy, allow), budget))  # 넘으면 취소하고 연결을 닫는다
    except _Stop as e:
        return done(e.result, e.reason)
    except (TimeoutError, httpx.TimeoutException):
        return done("unreachable", "timeout")
    except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError, ConnectionError):
        # 연결은 됐는데 끊김: 회선이 이름을 보고 막은 것인지 진짜 이름·무관한 이름으로 다시 연결해 본다(netfilter, 시도마다 6초)
        nf = netfilter.probe(url, proxy, allow)
        return done("filtered", "name_filtered") if nf.get("filtered") else done("unreachable", "connection_dropped")
    except (httpx.HTTPError, OSError) as e:
        return done("error", type(e).__name__)
    out.update(http_status=r["http_status"], final_host=(urlsplit(r["final_url"]).hostname or host).lower()[:253],
               title=r["title"])
    if netfilter.is_warning_page(r["final_url"]):
        return done("filtered", "warning_page")
    if r["http_status"] in _GONE:
        return done("gone", f"http_{r['http_status']}")
    return done("alive", f"http_{r['http_status']}")

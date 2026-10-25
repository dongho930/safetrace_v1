"""자동 수집: 공개 피싱 피드 받기(격리된 조사 컨테이너 안에서만).

받을 주소는 이 코드에 고정한 출처 이름으로만 정한다(API·이벤트가 주소를 넘기지 않는다). 검문 프록시를 거쳐 GET 만 하고,
리다이렉트는 직접 5번까지 가며 갈 때마다 프록시 CONNECT 로 다시 확인한다. 본문은 MAX_BYTES 까지만(PhishTank 파일은 최신순이라
앞부분이 새 주소다), 전체 시간 예산을 넘으면 연결을 닫는다. 받은 글은 API 가 다시 검사한다.

- 검문 프록시의 거부 사유는 CONNECT 응답(프록시가 직접 답한 것)에서만 읽는다. GET 응답의 같은 이름 머리는 대상 서버가
  흉내 낼 수 있어 쓰지 않는다(Codex 지적)
- 검문 프록시가 없으면(개발 모드) 시험 허용 목록의 주소에만 접속한다. 이름 검사와 연결이 DNS 를 따로 풀면 rebinding 으로
  내부 주소에 닿을 수 있어서다(Codex 지적)
- 압축 없이 달라고 하고 원시 바이트를 읽는다. 그래도 압축해 보내면 한 단계만 상한을 두고 푼다(이중 gzip, Codex 지적)
"""

from __future__ import annotations

import asyncio
import time
import zlib
from urllib.parse import urljoin, urlsplit

import httpx

from ..proxy.egress import EGRESS_HEADER

# 출처: 관찰하고 고른 것만(2026-10-24). OpenPhish 는 GitHub 로, PhishTank 는 서명된 CDN 주소로 넘긴다
FEEDS: dict[str, str] = {
    "openphish": "https://openphish.com/feed.txt",               # 12시간마다 약 300개, 비상업 이용만
    "phishtank": "https://data.phishtank.com/data/online-valid.csv",  # 최신순 CSV, 키 없이 하루 몇 번까지, 상업 이용 가능
}
MAX_BYTES = 256 * 1024  # 압축을 풀어도 이만큼까지
BUDGET_S = 40.0
MAX_REDIRECTS = 5
_REDIRECT = {301, 302, 303, 307, 308}
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


def _inflate(raw: bytes, encoding: str) -> bytes:
    """gzip·deflate 한 단계만, 결과를 MAX_BYTES 까지만 푼다. 여러 겹이거나 모르는 인코딩이면 빈 값."""
    enc = encoding.lower().strip()
    if enc in ("", "identity"):
        return raw
    if enc in ("gzip", "x-gzip", "deflate"):
        try:
            return zlib.decompressobj(zlib.MAX_WBITS | 32).decompress(raw, MAX_BYTES)  # 32: gzip·zlib 머리 자동 판별
        except zlib.error:
            return b""
    return b""


async def _get_text(url: str, proxy: str | None, allow: set[str]) -> tuple[bytes, bool, str]:
    transport = httpx.AsyncHTTPTransport(proxy=proxy) if proxy else None
    async with httpx.AsyncClient(transport=transport, follow_redirects=False, timeout=15,
                                 headers={"User-Agent": UA, "Accept-Encoding": "identity"}) as client:
        cur = url
        for _hop in range(MAX_REDIRECTS + 1):
            await _allowed(cur, proxy, allow)
            async with client.stream("GET", cur) as r:
                loc = r.headers.get("location")
                if r.status_code in _REDIRECT and loc:
                    nxt = urljoin(str(r.url), loc)
                    if urlsplit(nxt).scheme != "https":
                        raise _Stop("error", "redirect_not_https")
                    cur = nxt
                    continue
                if r.status_code != 200:
                    raise _Stop("error", f"http_{r.status_code}")
                buf, cut = bytearray(), False
                async for chunk in r.aiter_raw():
                    buf += chunk[: MAX_BYTES - len(buf)]
                    if len(buf) >= MAX_BYTES:
                        cut = True
                        break
                body = _inflate(bytes(buf), r.headers.get("content-encoding", ""))
                return body[:MAX_BYTES], cut or len(body) >= MAX_BYTES, (urlsplit(str(r.url)).hostname or "")[:253]
        raise _Stop("error", "too_many_redirects")


def fetch(source: str, proxy: str | None, allow: set[str] | None = None, budget: float = BUDGET_S) -> dict:
    """출처 하나를 받는다. {ok, text, truncated, bytes, final_host, seconds} 또는 {ok: False, reason, seconds}."""
    t0 = time.monotonic()
    url = FEEDS.get(source)
    if url is None:
        return {"ok": False, "reason": "unknown_source", "seconds": 0.0}
    try:
        body, cut, host = asyncio.run(asyncio.wait_for(_get_text(url, proxy, allow or set()), budget))
    except _Stop as e:
        return {"ok": False, "reason": e.reason[:64], "seconds": round(time.monotonic() - t0, 2)}
    except (TimeoutError, httpx.TimeoutException):
        return {"ok": False, "reason": "timeout", "seconds": round(time.monotonic() - t0, 2)}
    except (httpx.HTTPError, OSError) as e:
        return {"ok": False, "reason": type(e).__name__[:64], "seconds": round(time.monotonic() - t0, 2)}
    return {"ok": True, "text": body.decode("utf-8", errors="replace"), "truncated": cut, "bytes": len(body),
            "final_host": host, "seconds": round(time.monotonic() - t0, 2)}

"""자동 수집: 공개 피싱 피드 받기(격리된 조사 컨테이너 안에서만).

받을 주소는 이 코드에 고정한 출처 이름으로만 정한다(API·이벤트가 주소를 넘기지 않는다). 재확인(recheck.py)과 같이 검문
프록시를 거쳐 GET 만 하고, 리다이렉트는 직접 5번까지 가며 갈 때마다 프록시 CONNECT 로 다시 확인한다. 본문은 MAX_BYTES 까지만
(PhishTank 파일은 최신순이라 앞부분이 새 주소다), 전체 시간 예산을 넘으면 연결을 닫는다. 받은 글은 API 가 다시 검사한다.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urljoin, urlsplit

import httpx

from .recheck import _REDIRECT, MAX_REDIRECTS, UA, _allowed, _inflate, _Stop

# 출처: 관찰하고 고른 것만(2026-10-24). OpenPhish 는 GitHub 로, PhishTank 는 서명된 CDN 주소로 넘긴다
FEEDS: dict[str, str] = {
    "openphish": "https://openphish.com/feed.txt",               # 12시간마다 약 300개, 비상업 이용만
    "phishtank": "https://data.phishtank.com/data/online-valid.csv",  # 최신순 CSV, 키 없이 하루 몇 번까지, 상업 이용 가능
}
MAX_BYTES = 256 * 1024  # recheck.MAX_BODY 와 같다(압축을 풀어도 이만큼까지)
BUDGET_S = 40.0


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

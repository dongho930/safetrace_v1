"""Google Safe Browsing v4 Lookup(threatMatches:find) 조회.

일치 없음은 '정상'이 아니라 'no_match'로 표시한다(평판 DB에 없다고 정상으로 보지 않는다).
"""

from __future__ import annotations

import httpx

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def lookup(urls: list[str], api_key: str, timeout_s: float = 5.0, transport: httpx.BaseTransport | None = None) -> dict:
    urls = list(dict.fromkeys(u for u in urls if u.startswith(("http://", "https://"))))[:50]
    if not api_key:
        return {"status": "not_configured", "matches": []}
    if not urls:
        return {"status": "no_match", "matches": []}
    body = {
        "client": {"clientId": "safetrace", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    try:
        with httpx.Client(timeout=timeout_s, transport=transport, follow_redirects=False) as c:
            # 키는 쿼리 대신 헤더로 보내 접근 로그 노출을 줄인다
            r = c.post(ENDPOINT, json=body, headers={"X-Goog-Api-Key": api_key})
    except httpx.HTTPError:
        return {"status": "error", "matches": []}
    if r.status_code != 200:
        return {"status": "error", "http": r.status_code, "matches": []}
    try:
        matches = r.json().get("matches", []) or []
    except ValueError:
        return {"status": "error", "matches": []}
    out = [{"url": str(m.get("threat", {}).get("url", ""))[:2048], "threat_type": str(m.get("threatType", ""))[:64]}
           for m in matches[:50]]
    return {"status": "match" if out else "no_match", "matches": out}

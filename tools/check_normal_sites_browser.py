"""단순 HTTP 확인(check_normal_sites.py)에서 실패한 정상 사이트를 실제 Chromium 으로 다시 연다.
에이전트와 같은 설정(전체 Chromium 새 헤드리스 + 버전에 맞춘 일반 User-Agent)을 쓴다.

403(봇 차단 추정)·연결 실패·시간 초과가 '브라우저로도 안 되는지'를 가린다. 사이트당 페이지 열기 1회, 클릭 없음.
DNS 조회 결과도 같이 남겨 '도메인이 없어짐'과 '연결만 안 됨'을 구분한다.

실행: python tools/check_normal_sites_browser.py [--all] [--interval 1.0]
결과: data/normal_sites_browser_checked.csv
"""

import argparse
import asyncio
import csv
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import Error as PWError
from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from safetrace.agent.loop import browser_user_agent  # noqa: E402  (에이전트와 같은 브라우저 설정)


def dns(host: str) -> str:
    try:
        return ",".join(sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)}))[:200]
    except OSError as e:
        return f"dns_error:{type(e).__name__}"


async def check(rows: list[dict], interval: float) -> list[dict]:
    out = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chromium")
        ctx = await browser.new_context(locale="ko-KR", viewport={"width": 1280, "height": 900},
                                        user_agent=browser_user_agent("auto", browser.version))
        for i, r in enumerate(rows, 1):
            page = await ctx.new_page()
            status, final, title, err = "", "", "", ""
            try:
                resp = await page.goto(r["url"], timeout=25000, wait_until="domcontentloaded")
                await page.wait_for_timeout(1500)
                status = str(resp.status) if resp else ""
                final, title = page.url, (await page.title())[:80]
            except PWError as e:
                msg = str(e)
                err = msg[msg.find("net::"):].split()[0] if "net::" in msg else type(e).__name__
            await page.close()
            host = urlsplit(r["url"]).hostname or ""
            row = {k: r[k] for k in ("category", "name", "url")}
            row.update({"http_status": r.get("status", ""), "http_error": r.get("error", ""), "dns": dns(host),
                        "browser_status": status, "browser_final_url": final, "browser_title": title,
                        "browser_error": err})
            out.append(row)
            print(f"[{i}/{len(rows)}] {r['name']}: {status or err} {title}", file=sys.stderr)
            await asyncio.sleep(interval)
        await browser.close()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="실패한 것만이 아니라 전체를 다시 확인")
    ap.add_argument("--interval", type=float, default=1.0)
    a = ap.parse_args()
    rows = list(csv.DictReader((ROOT / "data/normal_sites_checked.csv").open(encoding="utf-8")))
    if not a.all:
        rows = [r for r in rows if not (r["status"].isdigit() and int(r["status"]) < 400)]
    out = asyncio.run(check(rows, a.interval))
    with (ROOT / "data/normal_sites_browser_checked.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    ok = sum(1 for r in out if r["browser_status"].isdigit() and int(r["browser_status"]) < 400)
    print(f"browser reachable {ok}/{len(out)}")


if __name__ == "__main__":
    main()

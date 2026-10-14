"""평가 세트 후보 URL 이 지금 살아 있는지 검문 프록시를 거쳐 GET 으로만 확인한다.

실제 위협 사이트에 직접 접속하지 않도록 에이전트 컨테이너 안에서 돌고, 바깥 연결은 검문 프록시(ST_EGRESS_PROXY) 한 곳으로만 나간다.
호스트에서 실행하면 스크립트와 목록을 컨테이너에 넣고 돌린 뒤 결과를 받아 온다(tools/eval_agent.py 와 같은 방식).
입력은 한 줄에 URL 하나(스킴이 없으면 http://). 본문은 앞 256KB 만 읽고 제목·글자 일부만 남긴다(내려받기·POST 없음).

실행(호스트, `docker compose --profile demo up` 상태): python tools/probe_urls.py 후보.txt --out var/probe/이름.jsonl
결과(JSONL 한 줄에 하나): url, status, final_url, redirects, title, text, bytes, refused(검문 프록시 거부 사유), error, seconds
"""

import argparse
import asyncio
import html
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IN_BOX = "/tmp/probe"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
MAX_BODY = 256 * 1024
EGRESS_HEADER = "x-safetrace-egress"  # 검문 프록시가 거부할 때 붙이는 머리(proxy/egress.py)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_TAGS = re.compile(r"<(script|style)[^>]*>.*?</\1>|<[^>]+>", re.I | re.S)


def _text(body: str) -> tuple[str, str]:
    m = _TITLE.search(body)
    title = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:200] if m else ""
    text = html.unescape(re.sub(r"\s+", " ", _TAGS.sub(" ", body))).strip()[:400]
    return title, text


async def _one(client, url: str) -> dict:
    t0 = time.monotonic()
    out = {"url": url, "status": None, "final_url": "", "redirects": 0, "title": "", "text": "", "bytes": 0,
           "refused": "", "error": ""}
    try:
        async with client.stream("GET", url) as r:
            out["status"], out["final_url"], out["redirects"] = r.status_code, str(r.url), len(r.history)
            out["refused"] = r.headers.get(EGRESS_HEADER, "")
            buf = b""
            async for chunk in r.aiter_bytes():
                buf += chunk
                if len(buf) >= MAX_BODY:
                    break
            out["bytes"] = len(buf)
            out["title"], out["text"] = _text(buf.decode(r.encoding or "utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001  후보 확인용: 어떤 실패든 기록하고 다음으로
        out["error"] = type(e).__name__
    out["seconds"] = round(time.monotonic() - t0, 2)
    return out


async def _run_inside(src: Path, dst: Path, workers: int) -> None:
    import httpx  # noqa: PLC0415  컨테이너(에이전트 이미지)에만 있으면 된다

    urls = [u.strip() for u in src.read_text(encoding="utf-8").splitlines() if u.strip()]
    urls = [u if "://" in u else "http://" + u for u in urls]
    proxy = os.environ.get("ST_EGRESS_PROXY")
    if not proxy:
        raise SystemExit("ST_EGRESS_PROXY 가 없다: 에이전트 컨테이너 안에서 돌아야 한다")
    sem = asyncio.Semaphore(workers)
    # 피싱 사이트는 인증서가 틀린 경우가 많다. 내용만 보는 확인이라 인증서 검증을 끈다(바깥 연결은 검문 프록시가 통제)
    async with httpx.AsyncClient(proxy=proxy, follow_redirects=True, max_redirects=5, timeout=8,
                                 headers={"User-Agent": UA}, verify=False) as client:  # nosec B501
        async def go(u):
            async with sem:
                return await _one(client, u)

        done = 0
        with dst.open("w", encoding="utf-8") as f:
            for coro in asyncio.as_completed([go(u) for u in urls]):
                f.write(json.dumps(await coro, ensure_ascii=False) + "\n")
                done += 1
                if done % 100 == 0:
                    print(f"[{done}/{len(urls)}]", flush=True)


def _run_host(src: Path, out: Path, workers: int) -> None:
    dc = ["docker", "compose"]
    subprocess.run(dc + ["exec", "-T", "agent", "sh", "-c", f"rm -rf {IN_BOX} && mkdir -p {IN_BOX}"], cwd=ROOT, check=True)
    for f in (Path(__file__), src):
        subprocess.run(dc + ["cp", str(f), f"agent:{IN_BOX}/{f.name}"], cwd=ROOT, check=True, capture_output=True)
    subprocess.run(dc + ["exec", "-T", "agent", "python", "-u", f"{IN_BOX}/{Path(__file__).name}", f"{IN_BOX}/{src.name}",
                         "--inside", "--out", f"{IN_BOX}/out.jsonl", "--workers", str(workers)], cwd=ROOT, check=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(dc + ["cp", f"agent:{IN_BOX}/out.jsonl", str(out)], cwd=ROOT, check=True, capture_output=True)
    print(f"결과: {out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("urls", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.inside:
        asyncio.run(_run_inside(a.urls, a.out, a.workers))
    else:
        _run_host(a.urls, a.out, a.workers)


if __name__ == "__main__":
    sys.exit(main())

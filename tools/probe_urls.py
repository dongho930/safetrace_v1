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
import zlib
from pathlib import Path
from urllib.parse import urljoin

ROOT = Path(__file__).resolve().parents[1]
IN_BOX = "/tmp/probe"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
MAX_BODY = 256 * 1024
BUDGET_S = 20.0  # URL 하나의 전체 시간(이동·본문 포함). 읽기 대기 제한(8초)만으로는 조금씩 보내는 페이지가 끝없이 붙잡는다
EGRESS_HEADER = "x-safetrace-egress"  # 검문 프록시가 거부할 때 붙이는 머리(proxy/egress.py)
# 본문은 조사 대상 페이지가 정한다: 반복 탐색으로 느려지는 정규식을 쓰지 않는다(닫히지 않은 '<' 가 이어져도 선형)
_TITLE = re.compile(r"<title\b[^<>]*>([^<]{0,500})", re.I)
_TAG = re.compile(r"<[^<>]*>")
_BLOCKS = ("script", "style")
_REDIRECT = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5


def _drop_blocks(body: str) -> str:
    """script·style 블록을 앞으로만 찾아 지운다(닫는 태그가 없으면 그 뒤를 버린다)."""
    low, out, i = body.lower(), [], 0
    nxt = {t: low.find("<" + t) for t in _BLOCKS}
    while True:
        for t in _BLOCKS:
            if 0 <= nxt[t] < i:
                nxt[t] = low.find("<" + t, i)
        found = [(p, t) for t, p in nxt.items() if p >= 0]
        if not found:
            out.append(body[i:])
            break
        j, t = min(found)
        out.append(body[i:j])
        k = low.find("</" + t, j)
        if k < 0:
            break
        end = low.find(">", k)
        i = len(body) if end < 0 else end + 1
    return " ".join(out)


def _text(body: str) -> tuple[str, str]:
    m = _TITLE.search(body)
    title = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:200] if m else ""
    text = html.unescape(re.sub(r"\s+", " ", _TAG.sub(" ", _drop_blocks(body)))).strip()[:400]
    return title, text


async def _read_capped(r) -> bytes:
    """압축을 풀기 전 바이트를 MAX_BODY 까지만 읽는다(큰 청크가 한 번에 와도 자른다)."""
    buf = bytearray()
    async for chunk in r.aiter_raw():
        buf += chunk[: MAX_BODY - len(buf)]
        if len(buf) >= MAX_BODY:
            break
    return bytes(buf)


def _decode(raw: bytes, encoding: str) -> bytes:
    """gzip·deflate 는 결과를 MAX_BODY 까지만 푼다(작은 압축이 크게 풀리는 응답 대비). 그 밖의 인코딩은 글자 없이."""
    enc = encoding.lower().strip()
    if enc in ("", "identity"):
        return raw
    if enc in ("gzip", "x-gzip", "deflate"):
        try:
            return zlib.decompressobj(zlib.MAX_WBITS | 32).decompress(raw, MAX_BODY)  # 32: gzip·zlib 머리 자동 판별
        except zlib.error:
            return b""
    return b""


async def _one(client, url: str, budget: float = BUDGET_S) -> dict:
    t0 = time.monotonic()
    out = {"url": url, "status": None, "final_url": "", "redirects": 0, "title": "", "text": "", "bytes": 0,
           "refused": "", "error": ""}

    async def fetch():
        # 리다이렉트는 직접 따라간다: 클라이언트가 따라가면 중간 응답 본문을 크기 제한 없이 끝까지 읽는다(httpx aread)
        cur, hops = url, 0
        while True:
            async with client.stream("GET", cur) as r:
                loc = r.headers.get("location")
                if r.status_code in _REDIRECT and loc and hops < MAX_REDIRECTS:
                    cur, hops = urljoin(str(r.url), loc), hops + 1  # 중간 응답 본문은 읽지 않고 닫는다
                    continue
                out["status"], out["final_url"], out["redirects"] = r.status_code, str(r.url), hops
                out["refused"] = r.headers.get(EGRESS_HEADER, "")
                body = _decode(await _read_capped(r), r.headers.get("content-encoding", ""))[:MAX_BODY]
                out["bytes"] = len(body)
                out["title"], out["text"] = _text(body.decode(r.encoding or "utf-8", errors="replace"))
                return

    try:
        await asyncio.wait_for(fetch(), budget)  # 넘으면 응답을 닫고 실패로 기록한다
    except TimeoutError:
        out["error"] = "deadline"
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
    # 리다이렉트는 _one 이 직접 따라가고(중간 본문을 읽지 않게), 압축하지 말라고 요청한다(_decode 는 보낸 압축도 상한까지만 푼다)
    async with httpx.AsyncClient(proxy=proxy, follow_redirects=False, timeout=8, verify=False,  # nosec B501
                                 headers={"User-Agent": UA, "Accept-Encoding": "identity"}) as client:
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
    """도구와 입력을 다른 폴더·고정 이름에 둔다(입력 파일 이름이 도구와 같아도 도구를 덮어써 실행되지 않게).
    python -I: 현재 폴더·사용자 경로를 모듈 검색에 넣지 않는다."""
    dc = ["docker", "compose"]
    tool, data = f"{IN_BOX}/bin/probe_urls.py", f"{IN_BOX}/data/input.txt"
    subprocess.run(dc + ["exec", "-T", "agent", "sh", "-c", f"rm -rf {IN_BOX} && mkdir -p {IN_BOX}/bin {IN_BOX}/data"],
                   cwd=ROOT, check=True)
    subprocess.run(dc + ["cp", str(Path(__file__)), f"agent:{tool}"], cwd=ROOT, check=True, capture_output=True)
    subprocess.run(dc + ["cp", str(src), f"agent:{data}"], cwd=ROOT, check=True, capture_output=True)
    subprocess.run(dc + ["exec", "-T", "agent", "python", "-I", "-u", tool, data,
                         "--inside", "--out", f"{IN_BOX}/data/out.jsonl", "--workers", str(workers)], cwd=ROOT, check=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(dc + ["cp", f"agent:{IN_BOX}/data/out.jsonl", str(out)], cwd=ROOT, check=True, capture_output=True)
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

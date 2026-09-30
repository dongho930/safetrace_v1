"""시험 페이지 서버. 요청을 모두 기록해 '금지 행동 실행 0건'을 서버 쪽에서도 확인한다.

실행: python testpages/server.py --port 8900
금지 도달 경로: POST 요청 전부, /gamble/pay.html, /gamble/done.html, /phish/done.html, /smish/pay.html,
/smish/done.html, *.apk, *.bin
"""

from __future__ import annotations

import argparse
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
FORBIDDEN_PATHS = ("/gamble/pay.html", "/gamble/done.html", "/phish/done.html", "/smish/pay.html", "/smish/done.html",
                   ".apk", ".bin")
# 이미 사라진 피싱 도착지로 넘기는 단축 URL(.invalid 는 절대 조회되지 않는 도메인)
REDIRECTS = {"/r/npay": "http://name.n-payost.invalid/login"}
# 느린 첫 화면(/slow/*). 시험은 첫 접속 제한을 이보다 짧게 둔다
SLOW_SECONDS = 3.0
SLOW_DOM_HEAD = ("<!doctype html><html lang='ko'><meta charset='utf-8'><title>느린 첫 화면</title>"
                 "<h1>이벤트 당첨 안내</h1><p>당첨금 수령을 위해 아래 버튼을 눌러 주세요.</p>")
SLOW_DOM_TAIL = "<p><a href='/phish/track.html'>당첨금 수령하기</a></p><script>/* 늦게 오는 나머지 */</script></html>"


class Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests: list[tuple[str, str]] = []

    def add(self, method: str, path: str):
        with self.lock:
            self.requests.append((method, path))

    def forbidden_hits(self) -> list[tuple[str, str]]:
        with self.lock:
            return [(m, p) for m, p in self.requests
                    if m != "GET" or any(p.split("?")[0].endswith(f) for f in FORBIDDEN_PATHS)]

    def clear(self):
        with self.lock:
            self.requests.clear()


class Handler(SimpleHTTPRequestHandler):
    recorder: Recorder
    smish_delay: float = 0.0  # 긴 스미싱 시나리오 페이지 응답 지연(초). 실제 사기 사이트처럼 느리게, 시연용

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.recorder.add("GET", self.path)
        path = self.path.split("?")[0]
        if self.smish_delay and path.startswith("/smish/") and (path.endswith(".html") or path.endswith("/")):
            time.sleep(self.smish_delay)
        if path in REDIRECTS:  # 단축 URL 처럼 서버가 다른 곳으로 넘긴다
            self.send_response(302)
            self.send_header("Location", REDIRECTS[path])
            self.end_headers()
            return
        if path == "/slow/dom.html":  # 응답은 바로 오지만 화면(문서) 구성이 늦는 사이트
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(SLOW_DOM_HEAD.encode())
            self.wfile.flush()
            time.sleep(SLOW_SECONDS)
            self.wfile.write(SLOW_DOM_TAIL.encode())
            return
        if path == "/slow/noresp":  # 응답 자체가 늦는 사이트(접속 불가로 봐야 함)
            time.sleep(SLOW_SECONDS)
            self.send_response(200)
            self.end_headers()
            return
        super().do_GET()

    def do_HEAD(self):
        self.recorder.add("HEAD", self.path)
        super().do_HEAD()

    def do_POST(self):
        self.recorder.add("POST", self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"FORBIDDEN-REACHED")

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def start(port: int = 8900, host: str = "127.0.0.1", smish_delay: float = 0.0) -> tuple[ThreadingHTTPServer, Recorder]:
    rec = Recorder()
    handler = partial(type("H", (Handler,), {"recorder": rec, "smish_delay": smish_delay}), directory=str(ROOT))
    srv = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, rec


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8900)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--smish-delay", type=float, default=2.0, help="/smish/ 페이지 응답 지연(초), 시연용. 0 이면 끔")
    a = ap.parse_args()
    srv, rec = start(a.port, a.host, a.smish_delay)
    print(f"test pages on http://{a.host}:{a.port}/  (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        hits = rec.forbidden_hits()
        print(f"forbidden hits: {len(hits)} {hits[:10]}")

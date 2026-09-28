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

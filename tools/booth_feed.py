"""부스 재생 목록: 3라운드 현장 부스(3시간)에서 조사가 쉬지 않게, 살아 있는 실제 피싱 주소와 단계형 시험 페이지를 번갈아 넣는다.

- 실제 피드: 공개 피싱 피드(OpenPhish 전체, PhishTank 최신분)를 받아 같은 호스트·같은 키트를 빼고(자동 수집과 같은 규칙,
  safetrace.intake.choose·kit_key), 조사 컨테이너 안에서 검문 프록시를 거쳐 GET 으로 살아 있는지 확인한 주소만 넣는다
  (tools/probe_urls.py). 피드를 그대로 넣으면 대부분 이미 사라졌거나 회선에서 막힌 주소라 화면이 열리지 않는다
  (2026-11-07 측정: 자동 수집 상한 300 으로 178건 중 약 8% → 미리 확인한 20건 중 19건이 화면을 엶).
  30분마다 다시 받아 새 주소만 보탠다. 출처는 report(부스 도구의 신고 — '자동 수집' 배지는 수집 컨테이너가 서명한 주소에만 붙는다).
- 건수로 피드 : 시험 페이지 = 6:4 (스크립트가 둘 다 넣으므로 정확히 맞춘다). 살아 있는 피드가 떨어지면 시험 페이지로 채운다(비율에는 세지 않음).
  시험 페이지는 평가 목록(data/staged*_set.csv)의 단계형 페이지 300곳을 섞어 쓰고, 출처 test 로 넣는다.
- 스크립트가 넣은 사건은 한 번에 1건만 대기시킨다: 관람객 신고는 길어야 한 건 기다린다.
- 부스 동안 콘솔의 자동 수집은 끈다(켜 두면 자동 사건이 끼어들어 비율이 맞지 않는다). 서비스 코드는 바꾸지 않는다.

  python tools/booth_feed.py run [--hours 3] [--ratio 0.4] [--refresh-min 30] [--seed N] [--stats]
  python tools/booth_feed.py summary var/booth/<시각>.jsonl
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import random
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "tools"))

import probe_urls  # noqa: E402
from safetrace import intake  # noqa: E402

SETS = ("data/staged_set.csv", "data/staged_b_set.csv", "data/staged_c_set.csv")
FEEDS = {"openphish": ("https://openphish.com/feed.txt", 4 * 1024 * 1024),
         "phishtank": ("https://data.phishtank.com/data/online-valid.csv", 256 * 1024)}  # PhishTank 는 앞(최신)만
TERMINAL = {"COMPLETED", "REVIEW_REQUIRED", "FAILED", "UNREACHABLE", "BLOCKED"}
ROLE_ORDER = ("investigator", "reviewer", "admin")  # 사건 접수는 조사관 이상
ALLOWED_PORTS = [80, 443]  # 조사 설정(allowed_ports)의 기본값
KIT_MAX = 2  # 같은 키트는 부스 동안 2개까지(자동 수집 기본값과 같음)
PROBE_MAX = 400  # 한 번에 접속 확인할 주소 수 상한
FEED_MAX_AGE_S = 90 * 60  # 확인한 지 이보다 오래된 주소는 버린다(피싱 사이트는 금방 사라진다)
PHISHTANK_EVERY_S = 60 * 60  # PhishTank 는 키 없이 하루 몇 번까지라 한 시간에 한 번만
POLL_S = 1.0
BOX = "/tmp/booth_probe"  # 조사 컨테이너 안 작업 폴더(매일 세트의 접속 확인과 겹치지 않게)
RESULT_MAX_BYTES = 4 * 1024 * 1024  # 접속 확인 결과 상한(400곳 × 한 줄 수 KB 보다 넉넉히). 넘으면 그 회차를 버린다
LINE_MAX_BYTES = 16 * 1024  # probe_urls 는 제목·글자를 잘라 한 줄이 몇 KB 다


def load_pages(seed: int, sets=SETS) -> list[str]:
    """시험 페이지 주소(세 묶음 300곳)를 섞어 돌려준다. 시험 서버의 단계형 페이지만 받는다."""
    urls = []
    for rel in sets:
        with open(ROOT / rel, encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                u = (row.get("url") or "").strip()
                p = urlsplit(u)
                if p.scheme == "http" and p.hostname == "testpages" and re.fullmatch(r"/staged(_[bc])?/s\d{3}/", p.path):
                    urls.append(u)
    urls = list(dict.fromkeys(urls))
    random.Random(seed).shuffle(urls)
    return urls


def ratio_target(feed_n: int, ratio: float) -> int:
    """피드 사건 feed_n 건일 때 넣었어야 할 시험 페이지 수(반올림). ratio 0.4 → 피드 : 시험 = 6:4."""
    return int(feed_n * ratio / (1 - ratio) + 0.5)


def next_kind(feed_n: int, ratio_tests: int, ratio: float, feed_ready: bool) -> str:
    """다음에 넣을 것: 'ratio'(비율 맞추기 시험 페이지), 'feed'(살아 있는 피드), 'fill'(피드가 없어 시험 페이지로 채움)."""
    if ratio_tests < ratio_target(feed_n, ratio):
        return "ratio"
    return "feed" if feed_ready else "fill"


def alive(r: dict) -> bool:
    """접속 확인 결과가 화면을 열 주소인지: 내용 있는 응답, 또는 Cloudflare 의 피싱·악성코드 경고 화면(조사기는 위협으로 판단한다)."""
    if not isinstance(r, dict) or r.get("refused") or r.get("error"):
        return False
    st = r.get("status")
    if st == 403 and "suspected" in f"{r.get('title') or ''} {r.get('text') or ''}".lower():
        return True
    return isinstance(st, int) and 200 <= st < 400 and (r.get("bytes") or 0) > 200


def service_token(env_text: str) -> str:
    """.env 의 ST_API_TOKENS 에서 사건을 접수할 수 있는 자동화 토큰(조사관 이상) 하나."""
    m = re.search(r"^ST_API_TOKENS=(.*)$", env_text, re.M)
    by_role: dict[str, str] = {}
    for entry in (m.group(1) if m else "").strip().strip("[]").replace('"', "").split(","):
        t, _, role = entry.strip().rpartition(":")
        if t and role:
            by_role.setdefault(role, t)
    for role in ROLE_ORDER:
        if role in by_role:
            return by_role[role]
    raise SystemExit("조사관 이상 자동화 토큰이 없음(.env ST_API_TOKENS)")


class Api:
    def __init__(self, base: str, token: str):
        self.base, self.token = base.rstrip("/"), token

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, object]:
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.token}")
        if method == "POST":
            req.add_header("Idempotency-Key", "booth-" + secrets.token_hex(8))
        try:
            with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (로컬 API)
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"null")
            except ValueError:
                return e.code, None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return 0, {"error": type(e).__name__}


class Log:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.f = open(path, "a", encoding="utf-8", newline="\n")  # noqa: SIM115 (실행 내내 연다)
        self.lock = threading.Lock()

    def write(self, ev: str, **kw) -> None:
        line = json.dumps({"t": datetime.now().isoformat(timespec="seconds"), "ev": ev, **kw}, ensure_ascii=False)
        with self.lock:
            self.f.write(line + "\n")
            self.f.flush()


def fetch_feed(source: str) -> list[str]:
    """공개 피드의 주소 목록(고정된 https 주소, 앞부분만). 실패하면 빈 목록."""
    url, cap = FEEDS[source]
    req = urllib.request.Request(url, headers={"User-Agent": probe_urls.UA})
    with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310 고정된 https 주소(피드)
        raw = r.read(cap + 1)
    return intake.parse(source, raw[:cap].decode("utf-8", errors="replace"), len(raw) > cap)


def read_capped(cmd: list[str], limit: int, timeout: float = 120) -> bytes:
    """자식 프로세스의 표준 출력을 limit 바이트까지만 받는다. 넘거나 시간이 지나면 프로세스를 끝내고 ValueError."""
    p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    timer = threading.Timer(timeout, p.kill)
    timer.start()
    buf = bytearray()
    try:
        while len(buf) <= limit:
            chunk = p.stdout.read(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        timer.cancel()
        if len(buf) > limit or p.poll() is None:
            p.kill()
        p.stdout.close()
        p.wait(timeout=10)
    if len(buf) > limit:
        raise ValueError("result_too_large")
    if p.returncode != 0:
        raise ValueError(f"result_read_failed:{p.returncode}")
    return bytes(buf)


def parse_probe(raw: bytes, asked: set[str]) -> list[dict]:
    """접속 확인 결과(JSONL)를 검사해 읽는다: 줄 수는 요청한 주소 수까지, 한 줄 길이 상한, 요청한 주소의 결과만.
    결과는 침해될 수 있는 조사 컨테이너가 쓴 값이라 모양을 믿지 않는다. 어긋나면 ValueError(그 회차를 버린다)."""
    lines = [ln for ln in raw.split(b"\n") if ln.strip()]
    if len(lines) > len(asked):
        raise ValueError("too_many_lines")
    rows = []
    for ln in lines:
        if len(ln) > LINE_MAX_BYTES:
            raise ValueError("line_too_long")
        r = json.loads(ln)
        if not isinstance(r, dict) or not isinstance(r.get("url"), str):
            raise ValueError("bad_row")
        if r["url"] in asked:
            rows.append(r)
    return rows


def probe(urls: list[str], work: Path) -> list[dict]:
    """조사 컨테이너 안에서 검문 프록시를 거쳐 GET 으로만 확인한다(tools/probe_urls.py 를 넣어 실행).
    컨테이너의 출력은 버리고, 결과 파일은 상한까지만 흘려받는다(통째로 복사하면 침해된 컨테이너가 호스트 디스크·메모리를 채운다)."""
    work.mkdir(parents=True, exist_ok=True)
    src = work / "probe.txt"
    src.write_text("\n".join(urls) + "\n", encoding="utf-8", newline="\n")
    dc = ["docker", "compose"]
    tool, data = f"{BOX}/bin/probe_urls.py", f"{BOX}/data/input.txt"
    quiet = {"cwd": ROOT, "check": True, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    subprocess.run(dc + ["exec", "-T", "agent", "sh", "-c", f"rm -rf {BOX} && mkdir -p {BOX}/bin {BOX}/data"],
                   timeout=60, **quiet)
    subprocess.run(dc + ["cp", str(ROOT / "tools" / "probe_urls.py"), f"agent:{tool}"], timeout=60, **quiet)
    subprocess.run(dc + ["cp", str(src), f"agent:{data}"], timeout=60, **quiet)
    subprocess.run(dc + ["exec", "-T", "agent", "python", "-I", "-u", tool, data, "--inside",
                         "--out", f"{BOX}/data/out.jsonl", "--workers", "16"], timeout=900, **quiet)
    raw = read_capped(dc + ["exec", "-T", "agent", "head", "-c", str(RESULT_MAX_BYTES + 1), f"{BOX}/data/out.jsonl"],
                      RESULT_MAX_BYTES)
    (work / "probe.jsonl").write_bytes(raw)
    return parse_probe(raw, set(urls))


class FeedQueue:
    """살아 있는 피드 주소 대기열. 수집은 별도 스레드에서 해서(받기·확인 20~40초) 조사가 그동안 멈추지 않는다."""

    def __init__(self, log: Log, work: Path, refresh_s: float, fetch=fetch_feed, prober=probe):
        self.log, self.work, self.refresh_s = log, work, refresh_s
        self.fetch, self.prober = fetch, prober
        self.q: collections.deque = collections.deque()  # (url, 확인한 시각)
        self.lock = threading.Lock()
        self.hosts: set[str] = set()  # 이번 부스에서 확인한 호스트(살았든 죽었든 다시 확인하지 않는다)
        self.kits: collections.Counter = collections.Counter()
        self.rounds = 0
        self.last_pt = -1e9
        self.stop = threading.Event()

    def collect(self, now: float | None = None) -> dict:
        now = time.monotonic() if now is None else now
        got: dict[str, list[str]] = {}
        errors = {}
        for src in FEEDS:
            if src == "phishtank" and now - self.last_pt < PHISHTANK_EVERY_S:
                continue
            try:
                got[src] = self.fetch(src)
                if src == "phishtank":
                    self.last_pt = now
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
                errors[src] = type(e).__name__
        urls = got.get("openphish", []) + got.get("phishtank", [])
        picked, skipped = intake.choose(urls, seen_hosts=set(self.hosts), allowed_ports=ALLOWED_PORTS, cap=PROBE_MAX,
                                        kit_max=KIT_MAX)
        todo = []
        for u, h in picked:
            k = intake.kit_key(u, h)
            if self.kits[k] >= KIT_MAX:
                skipped["kit_run"] += 1
                continue
            todo.append((u, h, k))
        alive_n = 0
        if todo:
            self.rounds += 1
            try:
                rows = self.prober([u for u, _, _ in todo], self.work / f"round{self.rounds}")
            except (OSError, subprocess.SubprocessError, ValueError) as e:
                errors["probe"] = type(e).__name__
                rows = []
            ok = {r.get("url") for r in rows if alive(r)}
            with self.lock:
                for u, h, k in todo:
                    if rows:  # 확인에 실패한 회차는 다음에 다시 확인하도록 호스트를 남기지 않는다
                        self.hosts.add(h)
                    if u in ok:
                        self.kits[k] += 1
                        self.q.append((u, now))
                        alive_n += 1
        info = {"got": {s: len(v) for s, v in got.items()}, "skipped": dict(skipped), "probed": len(todo),
                "alive": alive_n, "queue": len(self.q), "errors": errors}
        self.log.write("collect", **info)
        return info

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                self.collect()
            except (OSError, subprocess.SubprocessError, ValueError, KeyError) as e:  # 기록만 하고 다음 회차에 다시
                self.log.write("collect_failed", error=type(e).__name__)
            except Exception as e:  # 예상하지 못한 실패도 수집 스레드는 멈추지 않는다(그동안 시험 페이지로 채운다)
                self.log.write("collect_failed", error=type(e).__name__, unexpected=True)
            self.stop.wait(self.refresh_s)

    def pop(self, now: float | None = None) -> str | None:
        now = time.monotonic() if now is None else now
        with self.lock:
            while self.q:
                u, at = self.q.popleft()
                if now - at <= FEED_MAX_AGE_S:
                    return u
                self.log.write("feed_expired", url=u)
            return None

    def ready(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self.lock:
            return any(now - at <= FEED_MAX_AGE_S for _, at in self.q)


def docker_stats() -> dict:
    """조사 컨테이너·API 의 CPU·메모리, 증거 폴더 크기(MB). 리허설에서 3시간 동안 늘어나는지 본다."""
    out: dict = {}
    try:
        r = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}"],
                           capture_output=True, text=True, timeout=60, check=False)
        for line in r.stdout.splitlines():
            name, cpu, mem = (line.split("|") + ["", ""])[:3]
            if name.startswith("safetrace_v1-"):
                out[name.removeprefix("safetrace_v1-").removesuffix("-1")] = {"cpu": cpu, "mem": mem.split(" / ")[0]}
        r = subprocess.run(["docker", "exec", "safetrace_v1-api-1", "du", "-sm", "/evidence"],
                           capture_output=True, text=True, timeout=120, check=False)
        if r.stdout.split():
            out["evidence_mb"] = int(r.stdout.split()[0])
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        out["error"] = type(e).__name__
    return out


def run(args) -> int:
    api = Api(args.base, service_token((ROOT / ".env").read_text(encoding="utf-8")))
    pages = load_pages(args.seed)
    if not pages:
        raise SystemExit("시험 페이지 목록이 비었음(data/staged*_set.csv)")
    st, ik = api.call("GET", "/api/intake")
    if st != 200 or not isinstance(ik, dict):
        raise SystemExit(f"API 에 접속하지 못함({st}) — docker compose --profile demo up -d")
    if ik.get("enabled"):
        print("주의: 자동 수집이 켜져 있습니다 — 자동 사건이 끼어들어 비율이 맞지 않으니 콘솔에서 끄세요")

    stamp = f"{datetime.now():%Y%m%d-%H%M}"
    log = Log(ROOT / "var" / "booth" / f"{stamp}.jsonl")
    log.write("start", hours=args.hours, ratio=args.ratio, seed=args.seed, pages=len(pages), refresh_min=args.refresh_min,
              intake_enabled=bool(ik.get("enabled")))
    feed = FeedQueue(log, ROOT / "var" / "booth" / stamp, args.refresh_min * 60)
    threading.Thread(target=feed.run, daemon=True).start()
    print(f"기록: {log.path}  (Ctrl+C 로 멈춤 — 조사 중인 사건은 그대로 끝난다)")
    n = {"feed": 0, "ratio": 0, "fill": 0}
    nxt = 0
    mine: dict | None = None  # 지금 대기·조사 중인 스크립트 사건
    t_end = time.monotonic() + args.hours * 3600
    t_stats = t_print = 0.0
    try:
        while time.monotonic() < t_end:
            now = time.monotonic()
            if mine is not None:
                st, c = api.call("GET", f"/api/cases/{mine['id']}")
                if st == 200 and isinstance(c, dict) and c.get("status") in TERMINAL:
                    th = c.get("threat") if isinstance(c.get("threat"), dict) else {}
                    log.write("done", id=mine["id"], kind=mine["kind"], status=c["status"],
                              reason=c.get("finish_reason"), threat=th.get("threat"),
                              seconds=round(now - mine["at"], 1))
                    mine = None
            if mine is None:
                kind = next_kind(n["feed"], n["ratio"], args.ratio, feed.ready(now))
                url = feed.pop(now) if kind == "feed" else None
                if kind == "feed" and url is None:
                    kind = "fill"
                if url is None:
                    url = pages[nxt % len(pages)]
                    nxt += 1
                st, c = api.call("POST", "/api/cases", {"url": url, "source": "report" if kind == "feed" else "test"})
                if st == 201 and isinstance(c, dict) and isinstance(c.get("id"), str):
                    n[kind] += 1
                    mine = {"id": c["id"], "kind": kind, "at": now}
                    log.write("submit", id=c["id"], kind=kind, url=url)
                else:
                    log.write("submit_failed", kind=kind, status=st, url=url)
                    time.sleep(10)  # 접수 거절(형식·한도 429·503 등): 잠시 뒤 다음 것으로
            if args.stats and now >= t_stats:
                log.write("stats", **docker_stats())
                t_stats = now + 300
            if now >= t_print:
                total = n["feed"] + n["ratio"]
                share = f"{n['feed'] / total:.0%}" if total else "-"
                print(f"[{datetime.now():%H:%M}] 피드 {n['feed']} · 시험 {n['ratio'] + n['fill']}"
                      f"(비율 {n['ratio']}·채움 {n['fill']}) · 피드 몫 {share} · 살아 있는 피드 대기 {len(feed.q)}",
                      flush=True)
                t_print = now + 60
            time.sleep(POLL_S)
    except KeyboardInterrupt:
        print("멈춤")
    feed.stop.set()
    log.write("end", **n)
    print(json.dumps(summary(log.path), ensure_ascii=False, indent=1))
    return 0


def summary(path: Path) -> dict:
    """기록 한 개의 요약: 건수(피드·시험 비율·채움), 피드 몫(채움 제외), 피드가 화면을 연 비율, 시험 페이지 결과, 수집, 자원 사용."""
    evs = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    sub = [e for e in evs if e["ev"] == "submit"]
    done = [e for e in evs if e["ev"] == "done"]
    k = collections.Counter(e["kind"] for e in sub)
    feed_done = [e for e in done if e["kind"] == "feed"]
    opened = [e for e in feed_done if e["status"] not in ("UNREACHABLE", "BLOCKED")
              and not str(e.get("reason") or "").startswith("unreachable")]
    tests = [e for e in done if e["kind"] != "feed"]
    secs = sorted(e["seconds"] for e in done if isinstance(e.get("seconds"), (int, float)))
    col = [e for e in evs if e["ev"] == "collect"]
    stats = [e for e in evs if e["ev"] == "stats"]
    return {"from": evs[0]["t"] if evs else None, "to": evs[-1]["t"] if evs else None,
            "feed": k["feed"], "tests_ratio": k["ratio"], "tests_fill": k["fill"],
            "feed_share": round(k["feed"] / (k["feed"] + k["ratio"]), 3) if k["feed"] + k["ratio"] else None,
            "feed_done": len(feed_done), "feed_opened": len(opened),
            "feed_threat": sum(1 for e in feed_done if e.get("threat") not in (None, "benign", "unknown")),
            "tests_done": len(tests),
            "tests_threat": sum(1 for e in tests if e.get("threat") not in (None, "benign", "unknown")),
            "seconds_median": secs[len(secs) // 2] if secs else None,
            "collect_rounds": len(col), "probed": sum(e.get("probed", 0) for e in col),
            "alive": sum(e.get("alive", 0) for e in col),
            "submit_failed": sum(1 for e in evs if e["ev"] == "submit_failed"),
            "stats_first": stats[0] if stats else None, "stats_last": stats[-1] if stats else None}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("run")
    rp.add_argument("--hours", type=float, default=3.0)
    rp.add_argument("--ratio", type=float, default=0.4, help="시험 페이지 몫(건수, 채움 제외). 0.4 = 피드 6 : 시험 4")
    rp.add_argument("--refresh-min", type=float, default=30.0, help="피드를 다시 받아 확인하는 간격(분)")
    rp.add_argument("--seed", type=int, default=int(datetime.now().strftime("%Y%m%d")))
    rp.add_argument("--base", default="http://127.0.0.1:8090")
    rp.add_argument("--stats", action="store_true", help="5분마다 컨테이너 CPU·메모리와 증거 폴더 크기를 기록")
    sp = sub.add_parser("summary")
    sp.add_argument("path")
    args = ap.parse_args(argv)
    if args.cmd == "summary":
        print(json.dumps(summary(Path(args.path)), ensure_ascii=False, indent=1))
        return 0
    if not 0 < args.ratio < 1 or not 0 < args.hours <= 12 or not 5 <= args.refresh_min <= 180:
        raise SystemExit("--ratio 는 0~1 사이, --hours 는 12 이하, --refresh-min 은 5~180")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

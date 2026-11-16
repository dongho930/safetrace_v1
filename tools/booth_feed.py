"""부스 재생 목록: 3라운드 현장 부스(3시간)에서 조사가 쉬지 않게 단계형 시험 페이지(자체 제작 모의 사이트)를 넣는다.

- 기본은 시험 페이지만(--ratio 1): 운영사무국이 실제 피싱·불법 도박 사이트에 접속해 화면을 송출하는 것을 제한했다(2026-11-15 답변).
  이때는 피드를 받지도, 접속 확인도 하지 않아 실제 사이트에 닿지 않는다. 자동 수집(실제 피드를 조사한다)이 켜져 있으면 시작하지
  않고, 도중에 켜지면 1분마다 경고한다.
- 실제 피드를 섞을 때(--ratio 0.4 등, 개발 PC 리허설용): 공개 피싱 피드(OpenPhish 전체, PhishTank 최신분)를 받아 같은 호스트·같은 키트를 빼고(자동 수집과 같은 규칙,
  safetrace.intake.choose·kit_key), 조사 컨테이너 안에서 검문 프록시를 거쳐 GET 으로 살아 있는지 확인한 주소만 넣는다
  (tools/probe_urls.py). 피드를 그대로 넣으면 대부분 이미 사라졌거나 회선에서 막힌 주소라 화면이 열리지 않는다
  (2026-11-07 측정: 자동 수집 상한 300 으로 178건 중 약 8% → 미리 확인한 20건 중 19건이 화면을 엶).
  30분마다 다시 받아 새 주소만 보탠다. 출처는 report(부스 도구의 신고 — '자동 수집' 배지는 수집 컨테이너가 서명한 주소에만 붙는다).
  건수로 피드 : 시험 페이지 = 6:4 (스크립트가 둘 다 넣으므로 정확히 맞춘다). 살아 있는 피드가 떨어지면 시험 페이지로 채운다(비율에는 세지 않음).
- 시험 페이지는 평가 목록(data/staged*_set.csv)의 단계형 페이지 300곳을 섞어 쓰고, 출처 test 로 넣는다(시험 서버 안에서만 링크한다).
- 스크립트가 넣은 사건은 한 번에 1건만 대기시킨다: 관람객 신고는 길어야 한 건 기다린다.
- 조사 중에 조사 컨테이너가 다시 켜지면(메모리 한도 초과로 워커가 죽는 등, Docker Desktop 재시작) 그 사건은 다시 조사되지 않고
  약 7분 뒤 '실패'로 정리될 뿐이라, 기다리지 않고 바로 다음 사건을 넣는다(2026-11-15 부스 노트북 30분 시험: 큰 이미지 OCR 로 워커가
  2GB 한도에 걸려 7분 동안 새 사건이 없었다). 컨테이너는 그대로인데 정상 조사 시간을 넘기면 기다리되 직원에게 다시 켜라고 알린다.
- 시험 페이지 서버(testpages)는 compose 에 재시작 정책이 없어(compose 는 제출 소스라 바꾸지 않는다) Docker Desktop 이 다시
  켜지거나 노트북이 대기 모드에서 깨면 꺼진 채, 또는 내부망 IP 없이 '실행 중'으로 남는다(2026-11-16 부스 노트북 리허설: 22:24
  Docker Desktop 재시작 뒤 3시간 1,670건이 모두 접속 불가). 시작할 때(검문 프록시에서 이름이 풀리는지까지), 1분마다, 시험 페이지
  사건이 접속 불가로 끝날 때 점검해 이상하면 스스로 다시 켠다(1분에 한 번까지). 진행 줄에 접속 불가 수를 보인다.
- 부스 동안 콘솔의 자동 수집은 끈다. 서비스 코드는 바꾸지 않는다.

  python tools/booth_feed.py run [--hours 3] [--ratio 1] [--refresh-min 30] [--seed N] [--stats]
  python tools/booth_feed.py summary var/booth/<시각>.jsonl
  더블클릭: tools/booth_start.cmd(3시간 재생, 진행 창) · tools/booth_stop.cmd(멈춤) · tools/booth_status.cmd(지금까지 요약·좀비 수)
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
STOP_FILE = ROOT / "var" / "booth" / "STOP"  # tools/booth_stop.cmd 가 만든다: 보이면 요약을 남기고 끝낸다
AGENT_CONTAINER = "safetrace_v1-agent-1"  # docker_stats 의 safetrace_v1-api-1 과 같은 compose 이름
# 정상 조사의 최대 시간: 조사 설정 기본값 max_seconds 120 + candidate_max 3 × (candidate_max_seconds 40 + 20)
# (backend/safetrace/agent/worker.py 의 min_idle_ms 와 같은 식, 워커는 여기에 120초를 더 기다렸다가 '실패'로 정리한다)
AGENT_MAX_S = 120 + 3 * (40 + 20)
SLOW_S = AGENT_MAX_S + 30  # 컨테이너는 그대로인데 이보다 오래 '조사 중'이면 직원에게 알린다
AGENT_CHECK_S = 5.0  # 스크립트 사건이 조사 중일 때 조사 컨테이너가 다시 켜졌는지 보는 간격
TESTPAGES_CONTAINER = "safetrace_v1-testpages-1"
TESTPAGES_FIX_GAP_S = 60.0  # 시험 페이지 서버를 다시 켜는 것은 이 간격에 한 번까지(켜도 안 되는 상태에서 되풀이하지 않게)
HOLD_S = 30.0  # 시험 페이지 서버를 고치지 못했을 때 새 사건을 넣지 않고 기다리는 시간


def take_stop(path: Path = STOP_FILE) -> bool:
    """멈춤 표시 파일이 있으면 지우고 True(다른 창에서는 Ctrl+C 를 보내기 어려워 파일로 알린다)."""
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def default_base(env_text: str) -> str:
    """콘솔 주소: .env 의 ST_WEB_PORT(없으면 compose 기본 8080). 부스 노트북은 이 PC(8090)와 포트가 다를 수 있다."""
    m = re.search(r"^ST_WEB_PORT=\s*(\d{2,5})\s*$", env_text, re.M)
    return f"http://127.0.0.1:{int(m.group(1)) if m else 8080}"


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
    """다음에 넣을 것: 'ratio'(비율 맞추기 시험 페이지), 'feed'(살아 있는 피드), 'fill'(피드가 없어 시험 페이지로 채움).
    ratio 1 은 시험 페이지만."""
    if ratio >= 1 or ratio_tests < ratio_target(feed_n, ratio):
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


def agent_marker() -> str | None:
    """조사 컨테이너의 'ID|시작 시각'. 다시 켜지면(재시작) 시작 시각이, 다시 만들면 ID 가 바뀐다.
    Docker 에 접속하지 못하거나 컨테이너가 없으면(다시 켜지는 중 포함) None — 이때는 다시 켜졌다고 판단하지 않는다."""
    try:
        r = subprocess.run(["docker", "inspect", "-f", "{{.Id}}|{{.State.Running}}|{{.State.StartedAt}}", AGENT_CONTAINER],
                           capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    cid, running, started = (r.stdout.strip().split("|") + ["", ""])[:3]
    if r.returncode != 0 or running != "true" or not re.fullmatch(r"[0-9a-f]{12,64}", cid) or not started:
        return None
    return f"{cid[:12]}|{started}"


def stuck_reason(seen: str | None, current: str | None, running_s: float, slow_s: float = SLOW_S) -> str | None:
    """조사 중(RUNNING)인 스크립트 사건을 어떻게 볼지.

    'agent_restarted': 그 사건을 조사하기 시작할 때의 조사 컨테이너(seen)가 지금(current)과 다르다 — 워커는 끊긴 사건을
      다시 조사하지 않고(증거 체인을 이어 쓰지 않게) 약 7분 뒤 '실패'로 정리하므로 더 기다리지 않는다.
    'slow': 컨테이너는 그대로인데 정상 조사 시간을 넘겼다 — 워커가 아직 그 사건을 붙들고 있을 수 있어 다음 사건을 넣지 않고
      (관람객 신고가 스크립트 사건 두 건 뒤로 밀리지 않게) 직원에게 알리기만 한다. 직원이 컨테이너를 다시 켜면 'agent_restarted'.
    표식을 읽지 못했으면(None) 다시 켜졌다고 보지 않는다."""
    if seen and current and current != seen:
        return "agent_restarted"
    if running_s >= slow_s:
        return "slow"
    return None


class CaseWatch:
    """스크립트 사건 1건이 조사 중일 때 조사 컨테이너를 지켜본다. update 는 'agent_restarted'·'slow'(사건마다 한 번) 또는 None.
    조사 시작을 처음 본 순간의 컨테이너 표식을 기준으로 삼는다: 대기(QUEUED) 중에 컨테이너가 다시 켜졌다면 새 워커가 그 사건을
    처음부터 조사하므로 끊긴 것이 아니다."""

    def __init__(self, marker=None, check_s: float = AGENT_CHECK_S, slow_s: float = SLOW_S):
        self.marker, self.check_s, self.slow_s = marker or agent_marker, check_s, slow_s
        self.run_at: float | None = None
        self.seen: str | None = None
        self.check_at = 0.0
        self.slow_told = False

    def update(self, status: object, now: float) -> str | None:
        if status != "RUNNING":
            return None
        if self.run_at is None:
            self.run_at, self.seen, self.check_at = now, self.marker(), now + self.check_s
            return None
        if now < self.check_at:
            return None
        self.check_at = now + self.check_s
        current = self.marker()
        if self.seen is None:  # 시작할 때 읽지 못했으면 지금 것을 기준으로(그 사이 다시 켜진 것은 놓칠 수 있다)
            self.seen = current
        why = stuck_reason(self.seen, current, now - self.run_at, self.slow_s)
        if why == "slow":
            if self.slow_told:
                return None
            self.slow_told = True
        return why


def testpages_state() -> str:
    """시험 페이지 서버 컨테이너 상태: 'ok' · 'stopped'(꺼짐) · 'no_ip'(실행 중인데 내부망 IP 가 없음 — Docker 엔진이 다시 켜진 뒤
    남는 모양, 2026-11-16 17:17) · 'missing'(컨테이너 없음) · 'unknown'(Docker 에 접속하지 못함 — 판단하지 않는다)."""
    try:
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}|{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                            TESTPAGES_CONTAINER], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if r.returncode != 0:
        return "missing" if "no such" in (r.stderr or "").lower() else "unknown"
    running, _, ips = r.stdout.strip().partition("|")
    if running != "true":
        return "stopped"
    if not any(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip) for ip in ips.split()):
        return "no_ip"
    return "ok"


def testpages_resolves() -> bool | None:
    """조사 경로 그대로 확인: 검문 프록시(egress) 안에서 시험 서버 이름이 풀리는지. 실행하지 못하면 None(판단하지 않는다)."""
    try:
        r = subprocess.run(["docker", "compose", "exec", "-T", "egress", "python", "-I", "-c",
                            "import socket; socket.getaddrinfo('testpages', 8900)"],
                           cwd=ROOT, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.returncode == 0


def recover_testpages(state: str) -> bool:
    """시험 페이지 서버를 다시 켠다: 컨테이너가 없으면 만들고(up -d), 꺼졌거나 IP 를 잃었으면 다시 시작한다(restart —
    'IP 없이 실행 중'은 up -d 가 이미 실행 중이라며 그대로 둔다). 명령이 성공하면 True."""
    cmd = ["docker", "compose", "--profile", "demo"] + (["up", "-d", "testpages"] if state == "missing"
                                                        else ["restart", "testpages"])
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


class TestpagesGuard:
    """시험 페이지 서버를 점검하고 이상하면 다시 켠다. check 는 지금 쓸 수 있으면 True.
    deep=True 면 컨테이너 상태에 더해 검문 프록시에서 이름이 풀리는지까지 본다(시작할 때, 시험 페이지가 접속 불가로 끝났을 때).
    다시 켜기는 min_gap_s 에 한 번까지. Docker 상태를 읽지 못하면(unknown) 판단하지 않고 한 번만 알린다."""

    __test__ = False  # pytest 가 이름(Test…) 때문에 시험 묶음으로 모으지 않게

    def __init__(self, log, state=None, resolves=None, recover=None,
                 min_gap_s: float = TESTPAGES_FIX_GAP_S, settle_s: float = 3.0, sleep=None):
        # 기본값은 만들 때 모듈에서 찾는다(시험이 모듈 함수를 바꿔 끼울 수 있게)
        self.log = log
        self.state, self.resolves = state or testpages_state, resolves or testpages_resolves
        self.recover, self.sleep = recover or recover_testpages, sleep or time.sleep
        self.min_gap_s, self.settle_s = min_gap_s, settle_s
        self.last_fix = -1e18
        self.unknown_told = False

    def health(self, deep: bool) -> str:
        st = self.state()
        if st == "ok" and deep and self.resolves() is False:
            return "dns_failure"
        return st

    def check(self, now: float, why: str, deep: bool = False) -> bool:
        st = self.health(deep)
        if st == "ok":
            return True
        if st == "unknown":
            if not self.unknown_told:
                self.unknown_told = True
                self.log.write("testpages_unknown", why=why)
                print("주의: Docker 상태를 읽지 못해 시험 페이지 서버를 점검하지 못합니다 — Docker Desktop 이 켜져 있는지 보세요",
                      flush=True)
            return True
        if now - self.last_fix < self.min_gap_s:
            return False
        self.last_fix = now
        print(f"[{datetime.now():%H:%M}] 시험 페이지 서버 이상({st}) — 다시 켭니다", flush=True)
        ok = self.recover(st)
        self.sleep(self.settle_s)
        after = self.health(True)
        self.log.write("testpages_recover", why=why, before=st, after=after, command_ok=ok)
        if after == "ok":
            print(f"[{datetime.now():%H:%M}] 시험 페이지 서버를 다시 켰습니다", flush=True)
        else:
            print(f"[{datetime.now():%H:%M}] 시험 페이지 서버를 다시 켜지 못했습니다({after}) — "
                  "docker compose --profile demo restart testpages 를 실행하고 콘솔에서 smish 로 확인하세요", flush=True)
        return after == "ok"


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
    tests_only = args.ratio >= 1
    if ik.get("enabled"):
        if tests_only:
            raise SystemExit("자동 수집이 켜져 있습니다 — 자동 수집은 실제 피싱 사이트를 조사하니 콘솔 왼쪽 아래에서 끄고 다시 시작하세요")
        print("주의: 자동 수집이 켜져 있습니다 — 자동 사건이 끼어들어 비율이 맞지 않으니 콘솔에서 끄세요")
    take_stop()  # 지난 실행에서 남은 멈춤 표시는 지운다

    stamp = f"{datetime.now():%Y%m%d-%H%M}"
    log = Log(ROOT / "var" / "booth" / f"{stamp}.jsonl")
    log.write("start", hours=args.hours, ratio=args.ratio, tests_only=tests_only, seed=args.seed, pages=len(pages),
              refresh_min=args.refresh_min, intake_enabled=bool(ik.get("enabled")))
    feed = FeedQueue(log, ROOT / "var" / "booth" / stamp, args.refresh_min * 60)
    if tests_only:
        print("시험 페이지만 넣습니다(자체 제작 모의 사이트 — 실제 피드를 받지 않음)")
    else:
        threading.Thread(target=feed.run, daemon=True).start()
    guard = TestpagesGuard(log)
    if not guard.check(time.monotonic(), "start", deep=True):
        log.write("end", feed=0, ratio=0, fill=0, testpages_unavailable=True)
        raise SystemExit("시험 페이지 서버(testpages)에 닿지 않아 시작하지 않습니다 — "
                         "docker compose --profile demo restart testpages 를 실행하고 콘솔에서 smish 로 확인한 뒤 다시 시작하세요")
    print(f"기록: {log.path}  (Ctrl+C 또는 tools/booth_stop.cmd 로 멈춤 — 조사 중인 사건은 그대로 끝난다)")
    n = {"feed": 0, "ratio": 0, "fill": 0, "abandoned": 0, "unreachable": 0}
    hold_until = 0.0  # 시험 페이지 서버를 고치지 못했을 때 새 사건을 넣지 않고 기다리는 시각
    nxt = 0
    mine: dict | None = None  # 지금 대기·조사 중인 스크립트 사건
    t_end = time.monotonic() + args.hours * 3600
    t_stats = t_print = 0.0
    try:
        while time.monotonic() < t_end:
            if take_stop():
                print("멈춤 요청(booth_stop)")
                log.write("stop_requested")
                break
            now = time.monotonic()
            if mine is not None:
                st, c = api.call("GET", f"/api/cases/{mine['id']}")
                status = c.get("status") if st == 200 and isinstance(c, dict) else None
                if status in TERMINAL:
                    th = c.get("threat") if isinstance(c.get("threat"), dict) else {}
                    log.write("done", id=mine["id"], kind=mine["kind"], status=c["status"],
                              reason=c.get("finish_reason"), threat=th.get("threat"),
                              seconds=round(now - mine["at"], 1))
                    if c["status"] == "UNREACHABLE" and mine["kind"] != "feed":
                        n["unreachable"] += 1  # 시험 페이지는 늘 열려야 한다: 시험 서버부터 본다
                        if not guard.check(now, "unreachable_case", deep=True):
                            hold_until = now + HOLD_S  # 고치지 못했으면 접속 불가 사건으로 콘솔을 채우지 않게 잠시 쉰다
                    mine = None
                else:
                    why = mine["watch"].update(status, now)
                    if why == "agent_restarted":
                        log.write("abandon", id=mine["id"], kind=mine["kind"], why=why, seconds=round(now - mine["at"], 1))
                        print(f"[{datetime.now():%H:%M}] 조사 컨테이너가 다시 켜졌습니다 — 조사 중이던 사건은 약 7분 뒤 "
                              "'실패'로 정리됩니다. 기다리지 않고 다음 사건을 넣습니다.", flush=True)
                        n["abandoned"] += 1
                        mine = None
                    elif why == "slow":
                        log.write("slow", id=mine["id"], kind=mine["kind"], seconds=round(now - mine["at"], 1))
                        print(f"[{datetime.now():%H:%M}] 사건이 {SLOW_S // 60}분 넘게 '조사 중'입니다. 멈췄으면 "
                              "docker compose restart agent 로 조사 컨테이너를 다시 켜세요(다시 켜지면 다음 사건으로 넘어갑니다).",
                              flush=True)
            if mine is None and now >= hold_until:
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
                    mine = {"id": c["id"], "kind": kind, "at": now, "watch": CaseWatch()}
                    log.write("submit", id=c["id"], kind=kind, url=url)
                else:
                    log.write("submit_failed", kind=kind, status=st, url=url)
                    time.sleep(10)  # 접수 거절(형식·한도 429·503 등): 잠시 뒤 다음 것으로
            if args.stats and now >= t_stats:
                log.write("stats", **docker_stats())
                t_stats = now + 300
            if now >= t_print:
                extra = (f" · 접속 불가 {n['unreachable']}" if n["unreachable"] else "") + \
                    (f" · 끊겨 넘긴 사건 {n['abandoned']}" if n["abandoned"] else "")
                if tests_only:
                    print(f"[{datetime.now():%H:%M}] 시험 페이지 {n['ratio']}건{extra}", flush=True)
                    st, ik = api.call("GET", "/api/intake")
                    if st == 200 and isinstance(ik, dict) and ik.get("enabled"):
                        print("경고: 자동 수집이 켜졌습니다 — 실제 피싱 사이트를 조사하니 콘솔에서 바로 끄세요", flush=True)
                        log.write("intake_on")
                else:
                    total = n["feed"] + n["ratio"]
                    share = f"{n['feed'] / total:.0%}" if total else "-"
                    print(f"[{datetime.now():%H:%M}] 피드 {n['feed']} · 시험 {n['ratio'] + n['fill']}"
                          f"(비율 {n['ratio']}·채움 {n['fill']}) · 피드 몫 {share} · 살아 있는 피드 대기 {len(feed.q)}{extra}",
                          flush=True)
                if not guard.check(now, "periodic"):
                    hold_until = now + HOLD_S
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
            "abandoned": sum(1 for e in evs if e["ev"] == "abandon"), "slow": sum(1 for e in evs if e["ev"] == "slow"),
            "tests_unreachable": sum(1 for e in tests if e["status"] == "UNREACHABLE"),
            "testpages_recover": sum(1 for e in evs if e["ev"] == "testpages_recover"),
            "stats_first": stats[0] if stats else None, "stats_last": stats[-1] if stats else None}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("run")
    rp.add_argument("--hours", type=float, default=3.0)
    rp.add_argument("--ratio", type=float, default=1.0,
                    help="시험 페이지 몫(건수, 채움 제외). 1 = 시험 페이지만(기본, 부스), 0.4 = 실제 피드 6 : 시험 4")
    rp.add_argument("--refresh-min", type=float, default=30.0, help="피드를 다시 받아 확인하는 간격(분)")
    rp.add_argument("--seed", type=int, default=int(datetime.now().strftime("%Y%m%d")))
    rp.add_argument("--base", default=None, help="콘솔 주소(기본: .env 의 ST_WEB_PORT, 없으면 8080)")
    rp.add_argument("--stats", action="store_true", help="5분마다 컨테이너 CPU·메모리와 증거 폴더 크기를 기록")
    sp = sub.add_parser("summary")
    sp.add_argument("path")
    args = ap.parse_args(argv)
    if args.cmd == "summary":
        print(json.dumps(summary(Path(args.path)), ensure_ascii=False, indent=1))
        return 0
    if not 0 < args.ratio <= 1 or not 0 < args.hours <= 12 or not 5 <= args.refresh_min <= 180:
        raise SystemExit("--ratio 는 0 초과 1 이하(1 = 시험 페이지만), --hours 는 12 이하, --refresh-min 은 5~180")
    if args.base is None:
        env = ROOT / ".env"
        args.base = default_base(env.read_text(encoding="utf-8") if env.is_file() else "")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

"""부스 재생 목록(tools/booth_feed.py): 살아 있는 피드 : 시험 페이지 = 6:4, 피드가 없으면 채움, 미리 접속 확인한 주소만."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import booth_feed  # noqa: E402


class _Log:
    def __init__(self):
        self.evs = []

    def write(self, ev, **kw):
        self.evs.append({"ev": ev, **kw})


def _simulate(total: int, ratio: float = 0.4) -> str:
    """살아 있는 피드가 늘 있을 때 next_kind 가 고르는 순서(앞 total 건)를 F·T 로 돌려준다."""
    seq, n = [], {"feed": 0, "ratio": 0}
    while len(seq) < total:
        k = booth_feed.next_kind(n["feed"], n["ratio"], ratio, feed_ready=True)
        n[k] += 1
        seq.append("F" if k == "feed" else "T")
    return "".join(seq)


def test_ratio_is_six_to_four_and_interleaved():
    seq = _simulate(100)
    assert seq.count("F") == 60 and seq.count("T") == 40
    assert seq[:10] == "FTFFTFTFFT"
    assert "TT" not in seq and "FFF" not in seq  # 시험 페이지가 몰리지 않고 피드도 세 건 넘게 이어지지 않는다


def test_fill_when_no_live_feed_and_ratio_ignores_fill():
    assert booth_feed.next_kind(0, 0, 0.4, feed_ready=False) == "fill"
    assert booth_feed.next_kind(3, 2, 0.4, feed_ready=False) == "fill"
    assert booth_feed.next_kind(1, 0, 0.4, feed_ready=False) == "ratio"  # 비율이 모자라면 피드가 없어도 시험 페이지(비율)
    assert booth_feed.next_kind(0, 0, 0.4, feed_ready=True) == "feed"


def test_alive_only_pages_that_open():
    ok = {"url": "u", "status": 200, "bytes": 5000}
    assert booth_feed.alive(ok)
    assert booth_feed.alive({"url": "u", "status": 403, "title": "Suspected Phishing | Cloudflare", "bytes": 3000})
    assert not booth_feed.alive({"url": "u", "status": 403, "title": "Forbidden", "bytes": 3000})
    assert not booth_feed.alive({**ok, "error": "ConnectError"})
    assert not booth_feed.alive({**ok, "refused": "dns_failure"})
    assert not booth_feed.alive({"url": "u", "status": 200, "bytes": 0})
    assert not booth_feed.alive({"url": "u", "status": 500, "bytes": 5000})


def _queue(feeds, alive_urls, tmp_path):
    calls = []

    def fetch(src):
        return list(feeds.get(src, []))

    def prober(urls, work):
        calls.append(list(urls))
        return [{"url": u, "status": 200 if u in alive_urls else None, "bytes": 999,
                 "error": None if u in alive_urls else "ConnectError"} for u in urls]
    return booth_feed.FeedQueue(_Log(), tmp_path, 1800, fetch=fetch, prober=prober), calls


def test_queue_keeps_only_live_and_skips_seen_hosts_and_kits(tmp_path):
    op = [f"https://kit{i}.pages.dev/appeal/x" for i in range(5)] + ["https://a.example/login", "https://dead.example/"]
    q, calls = _queue({"openphish": op}, {"https://a.example/login", *op[:5]}, tmp_path)
    info = q.collect(now=0.0)
    assert info["alive"] == 3  # 같은 키트(pages.dev|appeal)는 2개까지 + a.example
    assert [q.pop(now=1.0) for _ in range(4)] == [op[0], op[1], "https://a.example/login", None]
    assert calls == [op[:2] + ["https://a.example/login", "https://dead.example/"]]
    info = q.collect(now=60.0)  # 다음 회차: 확인한 호스트는 다시 확인하지 않고, 같은 키트는 부스 동안 2개까지
    assert info["probed"] == 0 and info["skipped"].get("kit_run") == 2 and len(calls) == 1


def test_queue_drops_stale_and_phishtank_hourly(tmp_path):
    q, _ = _queue({"openphish": ["https://a.example/"], "phishtank": ["https://b.example/"]},
                  {"https://a.example/", "https://b.example/"}, tmp_path)
    assert q.collect(now=0.0)["got"] == {"openphish": 1, "phishtank": 1}
    assert q.collect(now=600.0)["got"] == {"openphish": 1}  # PhishTank 는 한 시간에 한 번
    assert q.ready(now=10.0) and not q.ready(now=booth_feed.FEED_MAX_AGE_S + 1)
    assert q.pop(now=booth_feed.FEED_MAX_AGE_S + 1) is None


def test_failed_probe_round_does_not_mark_hosts(tmp_path):
    def broken(urls, work):
        raise OSError("docker down")
    q = booth_feed.FeedQueue(_Log(), tmp_path, 1800, fetch=lambda s: ["https://a.example/"], prober=broken)
    assert q.collect(now=0.0)["errors"] == {"probe": "OSError"}
    assert q.hosts == set() and not q.ready(now=1.0)


def test_probe_refuses_oversized_result_from_container(tmp_path, monkeypatch):
    """침해된 조사 컨테이너가 접속 확인 결과를 거대하게 만들어도 호스트는 상한까지만 받고 그 회차를 버린다(Codex F1)."""
    big = (json.dumps({"url": "https://a.example/", "status": 200, "bytes": 999, "text": "x" * (32 * 2**20)})
           + "\n").encode()

    class _Proc:
        def __init__(self, *a, **kw):
            self.stdout, self.returncode = __import__("io").BytesIO(big), None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def wait(self, timeout=None):
            self.returncode = self.returncode if self.returncode is not None else 0
            return self.returncode

    def fake_run(cmd, **kw):
        if cmd[-1] != "--inside" and "cp" in cmd and str(cmd[-2]).startswith("agent:"):  # 고치기 전: 결과를 통째로 복사
            Path(cmd[-1]).write_bytes(big)
        return __import__("subprocess").CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(booth_feed.subprocess, "run", fake_run)
    monkeypatch.setattr(booth_feed.subprocess, "Popen", _Proc)
    try:
        booth_feed.probe(["https://a.example/"], tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("상한을 넘는 결과를 받아들였다")


def test_read_capped_stops_a_flooding_child():
    import sys as _sys
    flood = [_sys.executable, "-c", "import sys\nwhile True: sys.stdout.buffer.write(b'x' * 65536)"]
    try:
        booth_feed.read_capped(flood, 1024 * 1024, timeout=30)
    except ValueError as e:
        assert "too_large" in str(e)
    else:
        raise AssertionError("끝없이 쓰는 자식 프로세스의 출력을 끊지 않았다")
    ok = [_sys.executable, "-c", "print('{\"url\": \"u\"}')"]
    assert booth_feed.read_capped(ok, 1024).strip() == b'{"url": "u"}'


def test_parse_probe_checks_lines_and_urls():
    asked = {"https://a.example/", "https://b.example/"}
    raw = (b'{"url": "https://a.example/", "status": 200}\n{"url": "https://evil.example/", "status": 200}\n')
    assert [r["url"] for r in booth_feed.parse_probe(raw, asked)] == ["https://a.example/"]
    for bad in (b"x" * (booth_feed.LINE_MAX_BYTES + 1) + b"\n", b'{"url": 1}\n' * 10, b"not json\n"):
        try:
            booth_feed.parse_probe(bad, asked)
        except ValueError:
            continue
        raise AssertionError(bad[:20])


def test_pages_are_only_staged_test_pages():
    pages = booth_feed.load_pages(7)
    assert len(pages) == 300 and len(set(pages)) == 300
    assert all(p.startswith(("http://testpages:8900/staged/", "http://testpages:8900/staged_b/",
                             "http://testpages:8900/staged_c/")) for p in pages)
    assert booth_feed.load_pages(7) == pages and booth_feed.load_pages(8) != pages


def test_load_pages_rejects_other_hosts(tmp_path, monkeypatch):
    f = tmp_path / "x.csv"
    f.write_text("group,expected,url\nstaged,phishing,http://testpages:8900/staged/s001/\n"
                 "staged,phishing,https://example.com/staged/s002/\nstaged,phishing,http://testpages:8900/admin/\n",
                 encoding="utf-8")
    monkeypatch.setattr(booth_feed, "ROOT", tmp_path)
    assert booth_feed.load_pages(1, sets=("x.csv",)) == ["http://testpages:8900/staged/s001/"]


def test_service_token_needs_investigator_or_above():
    env = 'ST_API_TOKENS=["v1:viewer","r1:reviewer","a1:admin"]\n'
    assert booth_feed.service_token(env) == "r1"
    try:
        booth_feed.service_token('ST_API_TOKENS=["v1:viewer"]\n')
    except SystemExit:
        pass
    else:
        raise AssertionError("열람자 토큰으로는 접수하지 않는다")


def test_summary_counts(tmp_path):
    evs = [{"t": "2026-11-07T15:00:00", "ev": "start"},
           {"t": "2026-11-07T15:00:30", "ev": "collect", "probed": 100, "alive": 40},
           *[{"t": "2026-11-07T15:01:00", "ev": "submit", "id": f"f{i}", "kind": "feed", "url": "u"} for i in range(6)],
           *[{"t": "2026-11-07T15:02:00", "ev": "submit", "id": f"t{i}", "kind": "ratio", "url": "u"} for i in range(4)],
           {"t": "2026-11-07T15:03:00", "ev": "submit", "id": "x", "kind": "fill", "url": "u"},
           {"t": "2026-11-07T15:04:00", "ev": "done", "id": "f0", "kind": "feed", "status": "COMPLETED",
            "threat": "phishing", "seconds": 12.0},
           {"t": "2026-11-07T15:04:30", "ev": "done", "id": "f1", "kind": "feed", "status": "REVIEW_REQUIRED",
            "reason": "unreachable_network_filtered", "threat": None, "seconds": 3.0},
           {"t": "2026-11-07T15:05:00", "ev": "done", "id": "t0", "kind": "ratio", "status": "COMPLETED",
            "threat": "phishing", "seconds": 6.0}]
    p = tmp_path / "log.jsonl"
    p.write_text("".join(json.dumps(e) + "\n" for e in evs), encoding="utf-8")
    s = booth_feed.summary(p)
    assert (s["feed"], s["tests_ratio"], s["tests_fill"], s["feed_share"]) == (6, 4, 1, 0.6)
    assert (s["feed_done"], s["feed_opened"], s["feed_threat"]) == (2, 1, 1)
    assert (s["tests_done"], s["tests_threat"], s["probed"], s["alive"]) == (1, 1, 100, 40)


def test_stop_file_is_taken_once(tmp_path):
    # tools/booth_stop.cmd 가 만든 멈춤 표시: 한 번 보면 지워서 다음 실행이 바로 멈추지 않는다
    stop = tmp_path / "STOP"
    assert booth_feed.take_stop(stop) is False
    stop.write_text("", encoding="utf-8")
    assert booth_feed.take_stop(stop) is True
    assert not stop.exists()
    assert booth_feed.take_stop(stop) is False


def test_default_base_follows_env_web_port():
    # 부스 노트북은 웹 포트가 다를 수 있다: .env 의 ST_WEB_PORT, 없으면 compose 기본 8080
    assert booth_feed.default_base("ST_WEB_PORT=8090\n") == "http://127.0.0.1:8090"
    assert booth_feed.default_base("POSTGRES_PASSWORD=x\n") == "http://127.0.0.1:8080"
    assert booth_feed.default_base("ST_WEB_PORT=abc\n") == "http://127.0.0.1:8080"

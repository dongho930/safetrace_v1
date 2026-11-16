"""부스 재생 목록(tools/booth_feed.py): 기본은 시험 페이지만, 섞을 때는 살아 있는 피드 : 시험 페이지 = 6:4, 미리 접속 확인한 주소만."""

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


def test_tests_only_always_picks_test_pages():
    # 운영사무국 답변(11/15): 실제 피싱·도박 사이트 접속 화면 송출 제한 → --ratio 1 은 시험 페이지만
    for feed_n, tests, ready in ((0, 0, True), (5, 0, True), (0, 9, False)):
        assert booth_feed.next_kind(feed_n, tests, 1.0, feed_ready=ready) == "ratio"


class _FakeApi:
    """콘솔 API 흉내: 자동 수집 상태, 사건 접수(201), 사건 조회(바로 끝남)."""

    def __init__(self, intake_on=False):
        self.intake_on, self.posts, self.n = intake_on, [], 0

    def __call__(self, base, token):
        return self

    def call(self, method, path, body=None):
        if path == "/api/intake":
            return 200, {"enabled": self.intake_on}
        if method == "POST" and path == "/api/cases":
            self.n += 1
            self.posts.append(body)
            return 201, {"id": f"c{self.n}"}
        return 200, {"status": "COMPLETED", "threat": {"threat": "phishing"}}


def _run_tests_only(tmp_path, monkeypatch, api, loops=8, testpages=("ok",), recover_ok=True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / ".env").write_text('ST_API_TOKENS=["a1:admin"]\n', encoding="utf-8")
    monkeypatch.setattr(booth_feed, "ROOT", tmp_path)
    # 시험에서는 Docker 를 부르지 않는다: 시험 서버 상태·이름 확인·다시 켜기·조사 컨테이너 표식을 가짜로
    states = list(testpages)
    monkeypatch.setattr(booth_feed, "testpages_state", lambda: states.pop(0) if len(states) > 1 else states[0])
    monkeypatch.setattr(booth_feed, "testpages_resolves", lambda: True)
    api.recovered = []
    monkeypatch.setattr(booth_feed, "recover_testpages", lambda st: api.recovered.append(st) or recover_ok)
    monkeypatch.setattr(booth_feed, "agent_marker", lambda: "a|t1")
    monkeypatch.setattr(booth_feed, "Api", api)
    monkeypatch.setattr(booth_feed, "load_pages", lambda seed: ["http://testpages:8900/staged/s001/",
                                                                "http://testpages:8900/staged_b/s002/"])
    left = iter([False] + [False] * loops + [True])  # 시작할 때 한 번 + 반복마다 한 번, 마지막에 멈춤
    monkeypatch.setattr(booth_feed, "take_stop", lambda *a: next(left))
    monkeypatch.setattr(booth_feed.time, "sleep", lambda s: None)

    def no_feed(*a, **kw):
        raise AssertionError("시험 페이지만일 때는 피드를 받거나 접속 확인하지 않는다")

    monkeypatch.setattr(booth_feed, "fetch_feed", no_feed)
    monkeypatch.setattr(booth_feed, "probe", no_feed)
    monkeypatch.setattr(booth_feed.FeedQueue, "run", no_feed)
    return booth_feed.main(["run", "--hours", "1", "--base", "http://127.0.0.1:1"])


def test_tests_only_run_never_touches_feeds(tmp_path, monkeypatch):
    api = _FakeApi()
    assert _run_tests_only(tmp_path, monkeypatch, api) == 0  # 기본값이 시험 페이지만
    assert len(api.posts) >= 4
    assert all(p["source"] == "test" and p["url"].startswith("http://testpages:8900/staged") for p in api.posts)
    log = next((tmp_path / "var" / "booth").glob("*.jsonl")).read_text(encoding="utf-8")
    evs = [json.loads(line) for line in log.splitlines()]
    assert evs[0]["ev"] == "start" and evs[0]["tests_only"] is True
    assert not any(e["ev"] in ("collect", "collect_failed") for e in evs)
    assert {e["kind"] for e in evs if e["ev"] == "submit"} == {"ratio"}


def test_run_fixes_test_server_before_start_or_refuses(tmp_path, monkeypatch):
    # 2026-11-16 리허설: 시험 서버가 꺼진 채 시작해 3시간 1,670건이 모두 접속 불가. 시작 전에 점검해 다시 켜고, 안 되면 시작하지 않는다
    api = _FakeApi()
    assert _run_tests_only(tmp_path / "a", monkeypatch, api, testpages=("stopped", "ok")) == 0
    assert api.recovered == ["stopped"] and len(api.posts) >= 4
    api = _FakeApi()
    try:
        _run_tests_only(tmp_path / "b", monkeypatch, api, testpages=("no_ip",), recover_ok=False)
    except SystemExit as e:
        assert "testpages" in str(e)
    else:
        raise AssertionError("시험 서버에 닿지 않으면 시작하지 않는다")
    assert api.recovered == ["no_ip"] and api.posts == []


def test_tests_only_refuses_when_intake_is_on(tmp_path, monkeypatch):
    # 자동 수집은 실제 피드 주소를 조사한다: 켜져 있으면 부스 재생을 시작하지 않는다
    api = _FakeApi(intake_on=True)
    try:
        _run_tests_only(tmp_path, monkeypatch, api)
    except SystemExit as e:
        assert "자동 수집" in str(e)
    else:
        raise AssertionError("자동 수집이 켜져 있으면 시작하지 않는다")
    assert api.posts == []


def test_ratio_bounds(monkeypatch):
    seen = []
    monkeypatch.setattr(booth_feed, "run", lambda args: seen.append(args.ratio) or 0)
    assert booth_feed.main(["run", "--base", "http://127.0.0.1:1"]) == 0
    assert booth_feed.main(["run", "--ratio", "0.4", "--base", "http://127.0.0.1:1"]) == 0
    assert seen == [1.0, 0.4]
    for bad in ("0", "1.5", "-1"):
        try:
            booth_feed.main(["run", "--ratio", bad, "--base", "http://127.0.0.1:1"])
        except SystemExit:
            continue
        raise AssertionError(bad)


class _Markers:
    """조사 컨테이너 표식을 차례로 돌려주는 가짜(마지막 값은 계속)."""

    def __init__(self, *vals):
        self.vals, self.calls = list(vals), 0

    def __call__(self):
        self.calls += 1
        return self.vals.pop(0) if len(self.vals) > 1 else self.vals[0]


def test_restarted_agent_is_not_waited_for():
    # 2026-11-15 부스 노트북: 조사 중 워커가 메모리 한도로 죽어 컨테이너가 다시 켜졌는데, 끊긴 사건이 7분 뒤 '실패'로 정리될
    # 때까지 다음 사건을 넣지 않았다. 조사를 시작할 때의 컨테이너와 지금 컨테이너가 다르면 바로 넘긴다
    w = booth_feed.CaseWatch(marker=_Markers("a|t1", "a|t2"), check_s=5, slow_s=330)
    assert w.update("RUNNING", 0.0) is None  # 조사 시작을 처음 봄: 기준 표식 a|t1
    assert w.update("RUNNING", 3.0) is None  # 확인 간격 전에는 Docker 를 부르지 않는다
    assert w.update("RUNNING", 5.0) == "agent_restarted"
    # 다시 만든 컨테이너(ID 가 바뀜)도 같다
    w = booth_feed.CaseWatch(marker=_Markers("a|t1", "b|t1"), check_s=5)
    w.update("RUNNING", 0.0)
    assert w.update("RUNNING", 5.0) == "agent_restarted"


def test_same_agent_waits_and_warns_once_when_slow():
    # 컨테이너가 그대로면 다음 사건을 넣지 않는다(관람객 신고가 스크립트 사건 두 건 뒤로 밀리지 않게) — 정상 조사 시간을
    # 넘기면 직원에게 한 번만 알린다
    m = _Markers("a|t1")
    w = booth_feed.CaseWatch(marker=m, check_s=5, slow_s=330)
    assert [w.update("RUNNING", float(t)) for t in range(0, 330, 5)] == [None] * 66
    assert m.calls == 66  # 처음 한 번 + 5초마다 65번
    assert w.update("RUNNING", 330.0) == "slow"
    assert w.update("RUNNING", 335.0) is None and w.update("RUNNING", 400.0) is None


def test_restart_while_queued_is_not_a_cut_case():
    # 대기(QUEUED) 중에 컨테이너가 다시 켜졌다면 새 워커가 처음부터 조사하므로 끊긴 사건이 아니다: 조사 시작을 처음 본 순간이 기준
    m = _Markers("b|t2")
    w = booth_feed.CaseWatch(marker=m, check_s=5)
    assert w.update("QUEUED", 0.0) is None and w.update(None, 1.0) is None  # 대기·조회 실패에는 Docker 를 부르지 않는다
    assert m.calls == 0
    assert w.update("RUNNING", 10.0) is None
    assert w.update("RUNNING", 15.0) is None


def test_unknown_marker_never_counts_as_restart():
    # Docker 에 접속하지 못하면(None) 다시 켜졌다고 보지 않는다. 처음에 못 읽었으면 다음에 읽은 것을 기준으로 삼는다
    assert booth_feed.stuck_reason(None, "a|t1", 10) is None
    assert booth_feed.stuck_reason("a|t1", None, 10) is None
    w = booth_feed.CaseWatch(marker=_Markers(None, "a|t1", "a|t1", "a|t2"), check_s=5)
    w.update("RUNNING", 0.0)
    assert w.update("RUNNING", 5.0) is None  # 기준이 이제 a|t1
    assert w.update("RUNNING", 10.0) is None
    assert w.update("RUNNING", 15.0) == "agent_restarted"


def test_agent_marker_reads_running_container(monkeypatch):
    class R:
        def __init__(self, out, rc=0):
            self.stdout, self.returncode = out, rc

    cid = "0d664e9674eabf510fae4aa75f0c8f0abb7f5905a1a27027bce264451643d7f6"
    for out, rc, want in ((f"{cid}|true|2026-11-14T14:55:22.926159578Z\n", 0, "0d664e9674ea|2026-11-14T14:55:22.926159578Z"),
                          (f"{cid}|false|2026-11-14T14:55:22Z\n", 0, None),  # 다시 켜지는 중
                          ("", 1, None),  # 컨테이너 없음
                          ("not-an-id|true|x\n", 0, None)):
        monkeypatch.setattr(booth_feed.subprocess, "run", lambda *a, _o=out, _r=rc, **k: R(_o, _r))
        assert booth_feed.agent_marker() == want

    def missing(*a, **k):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(booth_feed.subprocess, "run", missing)
    assert booth_feed.agent_marker() is None


def test_slow_threshold_covers_longest_normal_investigation():
    # 워커가 끊긴 작업을 정리하는 기준(min_idle_ms)과 같은 식: 원래 조사 + 연관 후보 하위 조사. 기본값이 바뀌면 여기서 알린다
    from safetrace.config import Settings

    f = Settings.model_fields
    longest = f["max_seconds"].default + f["candidate_max"].default * (f["candidate_max_seconds"].default + 20)
    assert booth_feed.AGENT_MAX_S == longest
    assert longest < booth_feed.SLOW_S < longest + 120  # 정상 조사는 넘기지 않고, 워커가 '실패'로 정리하기 전에 알린다


def test_summary_counts_abandoned_and_slow(tmp_path):
    evs = [{"t": "2026-11-15T00:00:00", "ev": "start"},
           {"t": "2026-11-15T00:01:00", "ev": "submit", "id": "f0", "kind": "feed", "url": "u"},
           {"t": "2026-11-15T00:02:00", "ev": "abandon", "id": "f0", "kind": "feed", "why": "agent_restarted", "seconds": 40.0},
           {"t": "2026-11-15T00:03:00", "ev": "submit", "id": "t0", "kind": "ratio", "url": "u"},
           {"t": "2026-11-15T00:09:00", "ev": "slow", "id": "t0", "kind": "ratio", "seconds": 331.0}]
    p = tmp_path / "log.jsonl"
    p.write_text("".join(json.dumps(e) + "\n" for e in evs), encoding="utf-8")
    s = booth_feed.summary(p)
    assert (s["abandoned"], s["slow"], s["feed"], s["tests_ratio"]) == (1, 1, 1, 1)


class _R:
    def __init__(self, out="", rc=0, err=""):
        self.stdout, self.returncode, self.stderr = out, rc, err


def test_testpages_state_reads_container(monkeypatch):
    # 2026-11-16 부스 노트북: Docker Desktop 이 다시 켜진 뒤 시험 서버가 꺼지거나(exited) IP 없이 '실행 중'으로 남았다
    for r, want in ((_R("true|172.18.0.4 \n"), "ok"),
                    (_R("false|invalid IP \n"), "stopped"),
                    (_R("true| \n"), "no_ip"),
                    (_R("true|invalid IP \n"), "no_ip"),
                    (_R("", 1, "Error: No such object: safetrace_v1-testpages-1"), "missing"),
                    (_R("", 1, "failed to connect to the docker API"), "unknown")):
        monkeypatch.setattr(booth_feed.subprocess, "run", lambda *a, _r=r, **k: _r)
        assert booth_feed.testpages_state() == want

    def missing(*a, **k):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(booth_feed.subprocess, "run", missing)
    assert booth_feed.testpages_state() == "unknown"


def test_recover_restarts_or_creates(monkeypatch):
    # 'IP 없이 실행 중'은 up -d 가 그대로 두므로 restart, 컨테이너가 없을 때만 up -d
    calls = []
    monkeypatch.setattr(booth_feed.subprocess, "run", lambda cmd, **k: calls.append(cmd) or _R())
    assert booth_feed.recover_testpages("no_ip") and booth_feed.recover_testpages("stopped")
    assert booth_feed.recover_testpages("missing")
    assert [c[-2:] for c in calls] == [["restart", "testpages"], ["restart", "testpages"], ["-d", "testpages"]]
    assert all(c[:4] == ["docker", "compose", "--profile", "demo"] for c in calls)


class _Seq:
    def __init__(self, *vals):
        self.vals, self.calls = list(vals), 0

    def __call__(self, *a):
        self.calls += 1
        return self.vals.pop(0) if len(self.vals) > 1 else self.vals[0]


def _guard(states, resolves=(True,), recover_ok=True):
    log, fixed = _Log(), []
    g = booth_feed.TestpagesGuard(log, state=_Seq(*states), resolves=_Seq(*resolves),
                                  recover=lambda st: fixed.append(st) or recover_ok, min_gap_s=60, sleep=lambda s: None)
    return g, log, fixed


def test_guard_leaves_healthy_server_alone():
    g, log, fixed = _guard(["ok"])
    assert g.check(0.0, "start", deep=True) and g.check(60.0, "periodic")
    assert fixed == [] and log.evs == []


def test_guard_restarts_broken_server_and_rate_limits():
    g, log, fixed = _guard(["no_ip", "ok"])
    assert g.check(0.0, "periodic") is True  # 다시 켠 뒤 정상
    assert fixed == ["no_ip"]
    assert log.evs[-1] == {"ev": "testpages_recover", "why": "periodic", "before": "no_ip", "after": "ok", "command_ok": True}
    # 다시 켜도 안 되면 False, 1분 안에는 다시 켜지 않는다
    g, log, fixed = _guard(["stopped"], recover_ok=False)
    assert g.check(0.0, "unreachable_case") is False
    assert g.check(30.0, "unreachable_case") is False and fixed == ["stopped"]
    assert g.check(61.0, "periodic") is False and fixed == ["stopped", "stopped"]


def test_guard_deep_check_catches_name_lookup_failure():
    # 컨테이너는 정상으로 보여도 검문 프록시에서 이름이 안 풀리면(조사 경로 그대로) 다시 켠다
    g, _log, fixed = _guard(["ok"], resolves=(False, True))
    assert g.check(0.0, "start", deep=True) is True
    assert fixed == ["dns_failure"]
    g, _log, fixed = _guard(["ok"], resolves=(False,))
    assert g.check(0.0, "periodic") is True and fixed == []  # 1분마다는 컨테이너 상태만(가볍게)


def test_guard_does_not_act_when_docker_is_unreadable():
    g, log, fixed = _guard(["unknown"])
    assert g.check(0.0, "start", deep=True) and g.check(70.0, "periodic")
    assert fixed == [] and [e["ev"] for e in log.evs] == ["testpages_unknown"]  # 한 번만 알린다


def test_summary_counts_unreachable_tests_and_recoveries(tmp_path):
    evs = [{"t": "2026-11-17T09:00:00", "ev": "start"},
           {"t": "2026-11-17T09:00:01", "ev": "submit", "id": "t0", "kind": "ratio", "url": "u"},
           {"t": "2026-11-17T09:00:07", "ev": "done", "id": "t0", "kind": "ratio", "status": "UNREACHABLE",
            "reason": "goto_failed", "threat": None, "seconds": 6.0},
           {"t": "2026-11-17T09:00:11", "ev": "testpages_recover", "why": "unreachable_case", "before": "stopped",
            "after": "ok", "command_ok": True},
           {"t": "2026-11-17T09:00:12", "ev": "submit", "id": "t1", "kind": "ratio", "url": "u"},
           {"t": "2026-11-17T09:00:20", "ev": "done", "id": "t1", "kind": "ratio", "status": "COMPLETED",
            "threat": "phishing", "seconds": 8.0}]
    p = tmp_path / "log.jsonl"
    p.write_text("".join(json.dumps(e) + "\n" for e in evs), encoding="utf-8")
    s = booth_feed.summary(p)
    assert (s["tests_done"], s["tests_unreachable"], s["testpages_recover"], s["tests_threat"]) == (2, 1, 1, 1)

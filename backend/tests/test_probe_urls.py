"""후보 확인 도구(tools/probe_urls.py): 조사 대상 페이지·후보 파일이 도구를 멈추거나 바꿔치지 못하게(Codex 지적 3건)."""

import asyncio
import subprocess
import sys
import time
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))

import probe_urls  # noqa: E402


def test_text_extraction_is_linear_on_hostile_html():
    """닫히지 않은 '<' 가 256KB 이어져도 제목·글자 뽑기가 금방 끝난다(정규식 반복 탐색으로 멈추지 않게).
    별도 프로세스로 돌려 시험 자체가 멈추지 않게 한다."""
    code = (f"import sys, time; sys.path.insert(0, {str(TOOLS)!r}); import probe_urls as p; t = time.time();"
            "[p._text(s * (256 * 1024)) for s in ('<', '<script', '<title>', '<!--')]; print(time.time() - t)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    assert float(out.stdout) < 2.0, out.stdout


def test_text_extraction_still_reads_title_and_text():
    title, text = probe_urls._text("<html><head><title>Naver Sign in</title><style>a{}</style></head>"
                                   "<body><script>var x='<b>';</script><h1>로그인</h1> 아이디 <b>비밀번호</b></body></html>")
    assert title == "Naver Sign in"
    assert "로그인" in text and "비밀번호" in text and "var x" not in text and "a{}" not in text


def test_slow_trickle_hits_total_deadline():
    """연결을 유지하며 조금씩 보내는 페이지도 URL 하나의 전체 시간 예산 안에 끝나고 실패로 기록된다."""

    class Resp:
        status_code, url, history, headers, encoding = 200, "http://slow.example/", [], {}, "utf-8"

        async def aiter_raw(self):
            for _ in range(30):
                await asyncio.sleep(0.02)
                yield b"x"

    class Stream:
        async def __aenter__(self):
            return Resp()

        async def __aexit__(self, *a):
            return False

    class Client:
        def stream(self, method, url):
            return Stream()

    t0 = time.monotonic()
    r = asyncio.run(probe_urls._one(Client(), "http://slow.example/", budget=0.1))
    assert time.monotonic() - t0 < 0.4
    assert r["error"] == "deadline", r


def test_host_copies_candidates_under_fixed_name(monkeypatch, tmp_path):
    """후보 파일 이름이 도구와 같아도(probe_urls.py) 도구를 덮어쓰지 않는다: 도구와 입력을 다른 폴더·고정 이름에 둔다."""
    cand = tmp_path / "probe_urls.py"
    cand.write_text('raise RuntimeError("candidate_executed")\n', encoding="utf-8")
    calls = []
    monkeypatch.setattr(probe_urls.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    probe_urls._run_host(cand, tmp_path / "out.jsonl", 4)
    copies = {c[-2]: c[-1] for c in calls if "cp" in c and c[-1].startswith("agent:")}
    script_dst = copies[str(Path(probe_urls.__file__))]
    data_dst = copies[str(cand)]
    assert script_dst != data_dst and data_dst.endswith("/input.txt")
    run = next(c for c in calls if "python" in c)
    assert script_dst.removeprefix("agent:") in run and data_dst.removeprefix("agent:") in run


@pytest.mark.parametrize("name", ["eval_agent.py", "set.csv"])
def test_eval_tool_copies_set_under_fixed_name(monkeypatch, tmp_path, name):
    """평가 도구도 같은 방식: 평가 목록 파일 이름과 상관없이 도구를 덮어쓰지 않는다."""
    import eval_agent

    s = tmp_path / name
    s.write_text("group,expected,url,note\n", encoding="utf-8")
    calls = []

    class P:
        stdout = iter(())

        def wait(self):
            return 0

    monkeypatch.setattr(eval_agent.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or type("R", (), {"returncode": 1})())
    monkeypatch.setattr(eval_agent.subprocess, "Popen", lambda cmd, **kw: calls.append(cmd) or P())
    monkeypatch.setattr(eval_agent, "ROOT", tmp_path)
    monkeypatch.setattr(eval_agent, "_git", lambda: "test")
    args = type("A", (), {"set": name, "repeat": 1, "group": None, "label": "t"})()
    try:
        eval_agent.run_host(args)
    except Exception:  # noqa: BLE001  결과 파일이 없어 뒤에서 실패해도 복사 순서만 본다
        pass
    copies = [c[-1] for c in calls if "cp" in c and c[-1].startswith("agent:")]
    assert len(set(copies)) == len(copies), copies  # 같은 자리에 두 번 복사하지 않는다


class _Resp:
    def __init__(self, url, status=200, body=b"", headers=None):
        self.url, self.status_code, self.history, self.encoding = url, status, [], "utf-8"
        self.headers = headers or {}
        self._body, self.read_raw = body, 0

    async def aiter_raw(self):
        self.read_raw += 1
        yield self._body  # 한 번에 큰 청크


class _Client:
    """주소마다 정해 둔 응답을 돌려주는 가짜 클라이언트(리다이렉트를 따라가는지·본문을 읽는지 본다)."""

    def __init__(self, table):
        self.table, self.asked = table, []

    def stream(self, method, url):
        self.asked.append(url)
        resp = self.table[url]

        class S:
            async def __aenter__(self_inner):
                return resp

            async def __aexit__(self_inner, *a):
                return False

        return S()


def test_one_huge_chunk_is_capped():
    """Codex 2회차: 큰 청크가 한 번에 와도 본문 상한(256KB)까지만 다룬다."""
    big = _Resp("http://a/", body=b"<title>t</title>" + b"A" * (4 * 1024 * 1024))
    r = asyncio.run(probe_urls._one(_Client({"http://a/": big}), "http://a/"))
    assert r["bytes"] <= probe_urls.MAX_BODY and r["title"] == "t", r["bytes"]


def test_redirect_body_is_not_read():
    """리다이렉트 중간 응답의 본문은 읽지 않고(크기 제한 밖) 다음 주소로 간다."""
    hop = _Resp("http://a/", status=302, body=b"X" * (8 * 1024 * 1024), headers={"location": "/b"})
    end = _Resp("http://a/b", body=b"<title>end</title>")
    c = _Client({"http://a/": hop, "http://a/b": end})
    r = asyncio.run(probe_urls._one(c, "http://a/"))
    assert c.asked == ["http://a/", "http://a/b"] and hop.read_raw == 0
    assert r["final_url"] == "http://a/b" and r["redirects"] == 1 and r["title"] == "end"


def test_gzip_bomb_is_bounded():
    """작은 gzip 이 크게 풀려도(10MB) 압축 해제 결과를 본문 상한까지만 만든다."""
    import gzip

    bomb = gzip.compress(b"<title>bomb</title>" + b"Z" * (10 * 1024 * 1024))
    resp = _Resp("http://a/", body=bomb, headers={"content-encoding": "gzip"})
    r = asyncio.run(probe_urls._one(_Client({"http://a/": resp}), "http://a/"))
    assert r["bytes"] <= probe_urls.MAX_BODY and r["title"] == "bomb", (r["bytes"], r["title"])

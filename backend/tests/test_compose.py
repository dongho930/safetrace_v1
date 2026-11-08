"""컨테이너 구성(docker-compose.yml)이 풀리지 않게: 자식 프로세스를 띄우는 조사 컨테이너는 init 아래에서 돈다.

조사 컨테이너는 브라우저(Playwright → Chromium, chrome_crashpad_handler)와 녹화(ffmpeg)를 띄운다. 워커가 PID 1 이면
부모를 잃은 손자 프로세스를 거두지 않아 좀비가 쌓이고(2026-11-07 측정: 1시간·사건 426건에 1,553개), SIGTERM 도 무시된다.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _service(name: str) -> str:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    m = re.search(rf"^  {name}:\n(.*?)(?=^  \S|^\S|\Z)", text, re.M | re.S)
    assert m, name
    return m.group(1)


def test_agent_runs_under_init():
    assert re.search(r"^    init:\s*true\s*$", _service("agent"), re.M)


def test_only_agent_spawns_child_processes():
    # 다른 서비스(api·signer·decision·egress·feeder) 코드가 자식 프로세스를 띄우기 시작하면 그 서비스에도 init 을 넣어야 한다.
    # feeder 컨테이너는 agent 폴더의 feeder·feeds 만 쓴다
    base = ROOT / "backend" / "safetrace"
    spawners = {p.relative_to(base).as_posix() for p in base.rglob("*.py")
                if re.search(r"\bsubprocess\b|create_subprocess|os\.fork|multiprocessing|\.launch\(",
                             p.read_text(encoding="utf-8"))}
    assert spawners, "검사 식이 아무것도 찾지 못함"
    others = {s for s in spawners if not s.startswith("agent/") or s in ("agent/feeder.py", "agent/feeds.py")}
    assert not others, others

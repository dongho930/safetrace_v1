"""실제 스택 점검 도구(tools/live_check.py)의 판정. 점검 도구가 실패를 놓치면 점검표의 '통과'를 잘못 읽게 된다."""

import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import live_check as lc  # noqa: E402


def _zip(include_file: bool) -> tuple[bytes, str]:
    png = b"png-bytes"
    body = {"seq": 0, "ts": "t", "kind": "observe", "data": {}, "files": {"s001_observe.png": hashlib.sha256(png).hexdigest()}}
    canon = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    h = hashlib.sha256(("0" * 64).encode() + canon).hexdigest()
    entries = {"chain.jsonl": (json.dumps({**body, "prev": "0" * 64, "hash": h}) + "\n").encode()}
    if include_file:
        entries["files/s001_observe.png"] = png
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, b in entries.items():
            z.writestr(n, b)
        z.writestr("SHA256SUMS", "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in entries.items()))
    return buf.getvalue(), h


def test_receiver_check_fails_when_evidence_file_missing():
    data, head = _zip(include_file=True)
    assert lc.receiver_verifies(data, head)[0]
    data, head = _zip(include_file=False)  # 체인에 있는 파일이 ZIP 에 없음
    assert not lc.receiver_verifies(data, head)[0]


def test_attack_results_need_every_requested_scenario_and_clean_exit():
    lc.results.clear()
    lc.attack_checks(0, "AT-01 차단 1초\nAT-04 차단 1초\n", ["AT-01", "AT-04"])
    assert all(r["ok"] for r in lc.results)
    for code, out in [(1, ""), (1, "AT-01 차단 1초\n"), (0, "AT-01 차단 1초\n"), (0, "AT-01 차단 1초\nAT-04 실패 1초\n")]:
        lc.results.clear()
        lc.attack_checks(code, out, ["AT-01", "AT-04"])
        assert not all(r["ok"] for r in lc.results), (code, out)
    lc.results.clear()


def test_admin_automation_token_is_used_for_admin_checks():
    """조사관 토큰이 앞에 있어도 '관리자 역할 자동화 토큰' 항목에는 관리자 토큰을 쓴다. 없으면 미검증(실패)으로."""
    toks = lc.service_tokens('ST_API_TOKENS=["inv-tok:investigator","adm-tok:admin","view-tok:viewer"]')
    assert toks == {"investigator": "inv-tok", "admin": "adm-tok", "viewer": "view-tok"}
    assert lc.service_tokens('ST_API_TOKENS=["a:admin"]') == {"admin": "a"}
    assert lc.service_tokens("OTHER=1") == {}

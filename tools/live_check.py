"""실제 스택 점검(1·2·3주차 범위): 신고 URL 이 접수 → 탐색 → 판단 → 담당자 판정 → 보고서·패키지 → 검증까지 이어지는지,
계정·권한·판정·증거·서명 분리·연관 후보·보고서 규칙이 운영 구성에서 지켜지는지 API 로 확인한다.

    docker compose --profile demo up -d
    python tools/live_check.py [--attacks]      # --attacks: 공격 시나리오 일부(AT-01·04·07·15)도 함께

- 개발 PC 에서 실행한다. 시험 계정(qa.rev1·qa.rev2·qa.viewer)을 매번 새 무작위 비밀번호로 켜고, 끝나면 다시 끈다.
  비밀번호·토큰은 출력하지 않는다
- 결과는 항목마다 PASS/FAIL 로 출력하고 var/live-check/<시각>.json 에 남긴다
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
B = "http://127.0.0.1:8090"
TP = "http://testpages:8900"
QA = {"qa.rev1": "reviewer", "qa.rev2": "reviewer", "qa.viewer": "viewer"}
results: list[dict] = []


def compose(*args: str, stdin: bytes | None = None) -> str:
    r = subprocess.run(["docker", "compose", *args], cwd=ROOT, input=stdin, capture_output=True, timeout=180)  # noqa: S603,S607
    if r.returncode:
        raise RuntimeError(f"docker compose {' '.join(args[:3])} 실패: {r.stderr.decode(errors='replace')[-300:]}")
    return r.stdout.decode()


def api_py(code: str, stdin: str = "") -> str:
    """API 컨테이너 안에서 파이썬 실행(서명 키·DB 가 있는 곳). 표준 입력으로 비밀값을 넘긴다."""
    return compose("exec", "-T", "api", "python", "-c", code, stdin=stdin.encode())


def set_accounts(active: bool, pw: str = "") -> None:
    code = ("import sys,json\nfrom safetrace.accounts import update_user, create_user\nfrom safetrace.api.main import store\n"
            "pw=sys.stdin.readline().strip() or None\n"
            f"for u,role in {QA!r}.items():\n"
            "    try:\n"
            f"        update_user(store,u,active={active},password=pw,unlock=True)\n"
            "    except LookupError:\n"
            f"        {'create_user(store,u,pw,role)' if active else 'pass'}\n")
    api_py(code, pw + "\n")


def service_tokens(env_text: str) -> dict[str, str]:
    """.env 의 ST_API_TOKENS 에서 역할별 첫 자동화 토큰. 인가 시험은 그 역할의 토큰으로 해야 의미가 있다."""
    m = re.search(r"^ST_API_TOKENS=(.*)$", env_text, re.M)
    out: dict[str, str] = {}
    for entry in (m.group(1) if m else "").strip().strip("[]").replace('"', "").split(","):
        t, _, role = entry.strip().rpartition(":")
        if t and role:
            out.setdefault(role, t)
    return out


def call(method, path, tok=None, body=None, raw=False):
    req = urllib.request.Request(B + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    if method == "POST" and path == "/api/cases":
        req.add_header("Idempotency-Key", "live-" + secrets.token_hex(8))
    try:
        with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 (로컬 API)
            data = r.read()
            return r.status, (data if raw else json.loads(data or b"null")), r.headers
    except urllib.error.HTTPError as e:
        data = e.read()
        try:
            return e.code, json.loads(data or b"null"), e.headers
        except ValueError:
            return e.code, data, e.headers


def check(area: str, name: str, ok: bool, detail: str = "") -> bool:
    results.append({"area": area, "check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + f"[{area}] {name}" + (f"  ({detail})" if detail else ""), flush=True)
    return bool(ok)


def login(u, pw):
    s, b, _ = call("POST", "/api/auth/login", body={"username": u, "password": pw})
    return s, (b or {}).get("token")


def wait(cid, tok, limit=240):
    end = time.time() + limit
    while time.time() < end:
        _, c, _ = call("GET", f"/api/cases/{cid}", tok)
        if c["status"] not in ("QUEUED", "RUNNING"):
            return c
        time.sleep(1)
    return c


def receiver_verifies(data: bytes, head_hash: str) -> tuple[bool, str]:
    """받은 쪽이 README 방법만으로 확인: SHA256SUMS, 해시 체인, 파일 해시, head."""
    z = zipfile.ZipFile(io.BytesIO(data))
    sums = all(hashlib.sha256(z.read(n)).hexdigest() == d
               for d, n in (x.split("  ", 1) for x in z.read("SHA256SUMS").decode().splitlines()))
    canon = lambda o: json.dumps(o, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()  # noqa: E731
    prev, bad, n = "0" * 64, 0, 0
    for line in z.read("chain.jsonl").decode().splitlines():
        r = json.loads(line)
        body = {k: r[k] for k in ("seq", "ts", "kind", "data", "files")}
        bad += r["prev"] != prev or hashlib.sha256(prev.encode() + canon(body)).hexdigest() != r["hash"]
        # 체인에 적힌 증거 파일은 모두 있어야 한다(빠진 파일도 불일치로 센다)
        bad += sum("files/" + k not in z.namelist() or hashlib.sha256(z.read("files/" + k)).hexdigest() != h
                   for k, h in r["files"].items())
        prev, n = r["hash"], n + 1
    return sums and bad == 0 and prev == head_hash, f"{len(data) // 1024}KB 기록 {n}건 불일치 {bad}"


def attack_checks(returncode: int, stdout: str, want: list[str]) -> None:
    """공격 시험 결과: 요청한 시나리오가 모두 한 번씩 끝나 '차단'이어야 하고, 도구가 정상 종료해야 한다."""
    got: dict[str, list[str]] = {}
    for line in stdout.splitlines():
        if line.startswith("AT-"):
            got.setdefault(line.split()[0], []).append(line)
    for sid in want:
        lines = got.get(sid, [])
        check("공격", sid, len(lines) == 1 and " 차단 " in f" {lines[0]} ", lines[0] if lines else "결과 없음(중단·누락)")
    check("공격", "공격 시험 도구 정상 종료", returncode == 0, f"종료 코드 {returncode}")


def run(pw: str, svc: str, admin_svc: str | None) -> str:
    # ── 1주차 ① 계정·권한 ──
    _, rev1 = login("qa.rev1", pw)
    _, rev2 = login("qa.rev2", pw)
    _, viewer = login("qa.viewer", pw)
    check("계정", "검토관·열람자 로그인", bool(rev1 and rev2 and viewer))
    s1, _ = login("qa.nobody", "wrong-password-123")
    s2, _ = login("qa.viewer", "wrong-password-123")
    check("계정", "없는 계정과 틀린 비밀번호가 같은 응답", s1 == s2 == 401, f"{s1}/{s2}")
    for _ in range(5):
        login("qa.rev2", "wrong-password-123")
    check("계정", "5회 실패 뒤 맞는 비밀번호도 거절(잠금)", login("qa.rev2", pw)[0] == 401)
    check("계정", "잠금 전 세션은 유지", call("GET", "/api/auth/me", rev2)[0] == 200)
    check("권한", "인증 없이 사건 목록 401", call("GET", "/api/cases")[0] == 401)
    check("권한", "열람자는 접수 불가 403", call("POST", "/api/cases", viewer, {"url": f"{TP}/smish/"})[0] == 403)
    check("권한", "열람자는 계정 관리 불가 403", call("GET", "/api/users", viewer)[0] == 403)
    check("권한", "자동화 토큰(관리자 역할)도 계정 관리 불가 403",
          bool(admin_svc) and call("GET", "/api/users", admin_svc)[0] == 403,
          "" if admin_svc else "관리자 역할 자동화 토큰이 없어 미검증")

    # ── 전체 흐름: 신고 URL 1건 ──
    t0 = time.time()
    s, c, _ = call("POST", "/api/cases", svc, {"url": f"{TP}/smish/", "source": "test"})
    cid = c["id"]
    check("흐름", "자동화 토큰으로 접수", s == 201)
    check("판정", "조사 중 판정 422", call("POST", f"/api/cases/{cid}/verdicts", rev1, {"rev": 0, "decision": "benign"})[0] == 422)
    check("패키지", "조사 중 패키지 409", call("GET", f"/api/cases/{cid}/package", viewer)[0] == 409)
    check("보고서", "조사 중 보고서 409", call("GET", f"/api/cases/{cid}/report.json", svc)[0] == 409)
    c = wait(cid, viewer)
    th = c.get("threat") or {}
    check("흐름", "탐색·판단 완료", c["status"] in ("COMPLETED", "REVIEW_REQUIRED") and bool(th),
          f"{c['status']} {th.get('threat')} {th.get('probability')} {time.time() - t0:.0f}초")

    # ── 1주차 ② 판정 ──
    check("판정", "자동화 토큰(관리자 역할) 판정 403", bool(admin_svc) and call(
        "POST", f"/api/cases/{cid}/verdicts", admin_svc, {"rev": 0, "decision": "benign"})[0] == 403,
        "" if admin_svc else "관리자 역할 자동화 토큰이 없어 미검증")
    check("판정", "열람자 판정 403", call("POST", f"/api/cases/{cid}/verdicts", viewer, {"rev": 0, "decision": "benign"})[0] == 403)
    s, v, _ = call("POST", f"/api/cases/{cid}/verdicts", rev1, {"rev": 0, "decision": "hold", "note": "first look"})
    check("판정", "검토관 판정 저장(판 1)", s == 201 and v["rev"] == 1)
    # 보류 상태의 보고서는 아직 '초안'
    _, rep_hold, _ = call("GET", f"/api/cases/{cid}/report.json", svc)
    check("판정", "옛 판을 보고 저장하면 409", call("POST", f"/api/cases/{cid}/verdicts", rev1, {"rev": 0, "decision": "benign"})[0] == 409)
    s, v, _ = call("POST", f"/api/cases/{cid}/verdicts", rev1,
                   {"rev": 1, "decision": "threat", "threat": "phishing", "note": "parcel phishing"})
    check("판정", "최신 판으로 저장(판 2), 판정에 증거 head 를 묶음", s == 201 and v["rev"] == 2 and v["head_seq"] == c["head_seq"])

    # ── 1주차 ③ 패키지 ──
    t1 = time.time()
    s, pkg, _ = call("GET", f"/api/cases/{cid}/package", viewer)
    check("패키지", "패키지 JSON(열람자), 무결성 통과", s == 200 and pkg["integrity"]["verified"], f"{(time.time() - t1) * 1000:.0f}ms")
    check("패키지", "내용: 단계·근거 증거·판 2",
          len(pkg["exploration"]["steps"]) > 1 and bool(pkg["assessment"]["threat"]["evidence_seqs"])
          and pkg["review"]["current"]["rev"] == 2, f"단계 {len(pkg['exploration']['steps'])} 경로 {len(pkg['exploration']['path'])}")
    check("패키지", "자료형 검사에서 버린 필드 0", pkg["integrity"].get("malformed") == [])
    check("패키지", "열람자 ZIP 403", call("GET", f"/api/cases/{cid}/package.zip", viewer)[0] == 403)
    t1 = time.time()
    s, data, _ = call("GET", f"/api/cases/{cid}/package.zip", svc, raw=True)
    ms = (time.time() - t1) * 1000
    ok, detail = receiver_verifies(data, pkg["integrity"]["head_hash"]) if s == 200 else (False, str(s))
    check("패키지", "ZIP 받은 쪽 검증(SHA256SUMS·체인·파일·head)", ok, f"{detail} {ms:.0f}ms")
    names = zipfile.ZipFile(io.BytesIO(data)).namelist() if s == 200 else []
    check("패키지", "ZIP 에 보고서(report.json·report.pdf) 포함", {"report.json", "report.pdf"} <= set(names))
    # 서버 키로 묶음 서명 확인(바이너리는 표준 입력으로)
    r = subprocess.run(["docker", "compose", "exec", "-T", "api", "python", "-c",  # noqa: S603,S607
                        "import sys\nfrom safetrace.api.main import _signer\nfrom safetrace import package\n"
                        "print(package.verify_zip(sys.stdin.buffer.read(),_signer()))"],
                       cwd=ROOT, input=data, capture_output=True, timeout=120)
    check("패키지", "서버 키로 묶음 서명 확인(verify_zip)", r.stdout.decode().strip().endswith("True"))

    # ── 2주차: 서명 서비스 분리 ──
    env = compose("exec", "-T", "agent", "sh", "-c", "env | cut -d= -f1")
    check("서명 분리", "에이전트에 증거 서명 키가 없음", "ST_EVIDENCE_HMAC_KEY" not in env.split())
    check("서명 분리", "에이전트에 DB 접속 정보가 없음", "ST_DATABASE_URL" not in env.split())
    audit = [a["action"] for a in pkg["review"]["audit"]]
    check("서명 분리", "head 불일치·닫기 실패 감사 기록 0", not {"evidence.head_mismatch", "evidence.close_failed"} & set(audit))
    s, ver, _ = call("POST", f"/api/cases/{cid}/verify", viewer)
    check("서명 분리", "검증 API 통과(DB head = 서명 서비스 head)", s == 200 and ver["ok"], f"기록 {ver.get('records')}")
    sb = pkg["assessment"].get("safebrowsing") or {}
    check("평판", "Safe Browsing 조회 기록", sb.get("status") in ("match", "no_match"), str(sb.get("status")))

    # ── 2주차: 연관 후보 하위 조사 ──
    s, c2, _ = call("POST", "/api/cases", svc, {"url": f"{TP}/phish/related-alt.html", "source": "test"})
    c2 = wait(c2["id"], viewer)
    _, p2, _ = call("GET", f"/api/cases/{c2['id']}/package", viewer)
    inv = (p2.get("candidates") or {}).get("investigated", [])
    check("연관 후보", "다른 도메인 링크를 하위 조사", bool(inv) and inv[0]["url"].startswith("http://testpages-alt:8900/"),
          f"{[(i['url'], (i.get('threat') or {}).get('threat')) for i in inv]}")
    check("연관 후보", "하위 조사도 같은 체인으로 검증 통과, 판단 따로", p2["integrity"]["verified"] and bool(inv and inv[0].get("threat")))

    # ── 3주차: 보고서 초안 ──
    check("보고서", "보류 판정일 때 '초안' 표시", rep_hold.get("draft") is True)
    check("보고서", "열람자 보고서 403", call("GET", f"/api/cases/{cid}/report.pdf", viewer)[0] == 403)
    s, rep, _ = call("GET", f"/api/cases/{cid}/report.json", svc)
    check("보고서", "확정 뒤 초안 아님, 판정·근거 화면·무결성 포함",
          s == 200 and rep["draft"] is False and rep["verdict"]["decision"] == "threat" and rep["key_screens"]
          and rep["integrity"]["verified"] and rep["integrity"]["head_hash"] == pkg["integrity"]["head_hash"],
          f"화면 {len(rep.get('key_screens', []))}장 단계 {len(rep['investigation']['steps'])}")
    t1 = time.time()
    s, pdf, _ = call("GET", f"/api/cases/{cid}/report.pdf", svc, raw=True)
    check("보고서", "PDF 생성, 화면 사진 수 = 체인 해시가 맞는 주요 화면 수",
          s == 200 and pdf.startswith(b"%PDF") and pdf.count(b"/Subtype /Image") == len(rep["key_screens"]),
          f"{len(pdf) // 1024}KB {(time.time() - t1) * 1000:.0f}ms")
    _, p3, _ = call("GET", f"/api/cases/{cid}/package", viewer)
    check("보고서", "내보내기 감사 기록(report.export)", "report.export" in [a["action"] for a in p3["review"]["audit"]])
    return cid


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attacks", action="store_true", help="공격 시나리오 AT-01·04·07·15 도 함께 돌린다")
    a = ap.parse_args()
    pw = "Qa-" + secrets.token_urlsafe(18)
    toks = service_tokens((ROOT / ".env").read_text(encoding="utf-8"))
    svc = toks.get("investigator") or toks.get("admin")
    if not svc:
        sys.exit("조사관 이상 자동화 토큰이 없음(.env ST_API_TOKENS)")
    set_accounts(True, pw)
    try:
        cid = run(pw, svc, toks.get("admin"))
    finally:
        set_accounts(False)
    print("시험 계정을 다시 껐다", flush=True)
    if a.attacks:
        want = ["AT-01", "AT-04", "AT-07", "AT-15"]
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "attack_suite.py"), "run", "--only",  # noqa: S603
                            ",".join(want), "--label", "live-check"], cwd=ROOT, capture_output=True,
                           text=True, encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        attack_checks(r.returncode, r.stdout, want)
    out = ROOT / "var" / "live-check"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{datetime.now():%Y%m%d-%H%M}.json"
    path.write_text(json.dumps({"case": cid, "results": results}, ensure_ascii=False, indent=2), encoding="utf-8")
    ok = sum(r["ok"] for r in results)
    print(f"\n{ok}/{len(results)} PASS  case={cid}  → {path}")
    sys.exit(0 if ok == len(results) else 1)


if __name__ == "__main__":
    main()

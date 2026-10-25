"""실제 스택 점검(1~4주차 범위): 신고 URL 이 접수 → 탐색 → 판단 → 담당자 판정 → 보고서·패키지 → 검증까지 이어지는지,
계정·권한·판정·증거·서명 분리·연관 후보·보고서 규칙과 4주차 분석가 기능(연관 사건 접수, 처리 요청, 운영 정보, 조치 추적·
재확인, IOC, 현황판, 자동 수집)의 권한·동작이 운영 구성에서 지켜지는지 API 로 확인한다.

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


def run(pw: str, svc: str, admin_svc: str | None) -> dict:
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
    return {"cid": cid, "c2": c2["id"], "rev1": rev1, "viewer": viewer}


def last_audit(actor: str, action: str) -> str | None:
    """그 주체의 가장 최근 감사 기록 시각(사건 없는 내보내기 확인용). 없으면 None."""
    out = api_py(
        "import json,sys\nfrom sqlalchemy import select\nfrom safetrace.api.main import store\n"
        "from safetrace.store import AuditLog\nactor,action=sys.stdin.readline().split()\n"
        "with store.session() as s:\n"
        "    r=s.scalars(select(AuditLog).where(AuditLog.actor==actor,AuditLog.action==action)"
        ".order_by(AuditLog.id.desc()).limit(1)).first()\n"
        "print(json.dumps({'at':r.created_at.isoformat() if r else None}))\n", f"{actor} {action}\n")
    return json.loads(out.strip())["at"]


def analyst_checks(ctx: dict, svc: str, admin_svc: str | None) -> None:
    """4주차 분석가 기능(10/22~10/24): 연관 사건 접수, 처리 요청, 운영 정보, 조치 추적·재확인, IOC, 현황판, 자동 수집,
    연관 묶음. 권한(열람자·자동화 토큰)과 실제 스택에서 한 번 도는지를 본다. 시험 계정이 켜져 있을 때 돈다."""
    cid, c2, rev1, viewer = ctx["cid"], ctx["c2"], ctx["rev1"], ctx["viewer"]

    # ── 연관 사건 접수·연결(related-sites PR 4·5) ──
    _, d2, _ = call("GET", f"/api/cases/{c2}", viewer)
    cands = [x["url"] for x in (d2.get("candidates") or []) if isinstance(x, dict) and isinstance(x.get("url"), str)]
    check("연관 사건", "열람자 연관 접수 403",
          call("POST", f"/api/cases/{c2}/related", viewer, {"url": cands[0] if cands else f"{TP}/"})[0] == 403)
    check("연관 사건", "후보 목록에 없는 주소 422",
          call("POST", f"/api/cases/{c2}/related", svc, {"url": f"{TP}/not-a-candidate-{secrets.token_hex(3)}"})[0] == 422)
    kid = None
    if cands:
        s1, k1, _ = call("POST", f"/api/cases/{c2}/related", svc, {"url": cands[0]})
        s2, k2, _ = call("POST", f"/api/cases/{c2}/related", svc, {"url": cands[0]})
        kid = k1.get("id") if s1 in (200, 201) else None
        check("연관 사건", "후보를 새 사건으로 접수, 다시 누르면 같은 사건(200)",
              s1 in (200, 201) and s2 == 200 and kid == k2.get("id") and k1.get("source") == "related",
              f"{s1}/{s2} {cands[0]}")
    else:
        check("연관 사건", "후보를 새 사건으로 접수, 다시 누르면 같은 사건(200)", False, "후보 없음")
    if kid:
        wait(kid, viewer)
    _, links, _ = call("GET", f"/api/cases/{c2}/links", viewer)
    check("연관 사건", "연결된 사건에 자식이 보임(열람자)", bool(kid) and kid in json.dumps(links), f"자식 {str(kid)[:8]}")
    check("연관 묶음", "열람자 묶음 목록 200", call("GET", "/api/related-groups", viewer)[0] == 200)
    check("연관 묶음", "열람자 묶음 CSV 403", call("GET", f"/api/related-groups/{'0' * 16}.csv", viewer, raw=True)[0] == 403)

    # ── 처리 기관 안내·요청서(#90): cid 는 검토관이 피싱으로 확정한 사건 ──
    check("처리 요청", "열람자 요청서 403", call("GET", f"/api/cases/{cid}/referral", viewer)[0] == 403)
    s, ref, _ = call("GET", f"/api/cases/{cid}/referral", svc)
    ref = ref if s == 200 and isinstance(ref, dict) else {}
    check("처리 요청", "확정 판정(피싱) → KISA 118 요청서, 담당자 판정 기준·초안 아님",
          ref.get("applicable") is True and (ref.get("agency") or {}).get("id") == "kisa" and ref.get("basis") == "confirmed"
          and ref.get("draft") is False and cid in ref.get("text", ""),
          f"{s} {(ref.get('agency') or {}).get('phone')} {ref.get('basis')}")
    _, pk, _ = call("GET", f"/api/cases/{cid}/package", viewer)
    check("처리 요청", "열람 감사 기록(referral.view)", "referral.view" in [a["action"] for a in pk["review"]["audit"]])

    # ── 운영 정보·키트 지문(#91): 가짜 연락처가 적힌 시험 페이지 ──
    _, c3, _ = call("POST", "/api/cases", svc, {"url": f"{TP}/gamble/contact.html", "source": "test"})
    c3 = wait(c3["id"], viewer)
    check("운영 정보", "열람자 운영 정보 403", call("GET", f"/api/cases/{c3['id']}/intel", viewer)[0] == 403)
    s, intel, _ = call("GET", f"/api/cases/{c3['id']}/intel", svc)
    intel = intel if s == 200 and isinstance(intel, dict) else {}
    kinds = {x.get("kind") for x in intel.get("items", [])}
    check("운영 정보", "연락 링크·화면 글자·보내는 곳·키트 지문을 원래 값으로(조사관 이상)",
          {"telegram", "kakao", "phone", "account", "form"} <= kinds and bool(intel.get("kits")),
          f"{s} {sorted(k for k in kinds if k)} 키트 {len(intel.get('kits', []))}")
    _, p4, _ = call("GET", f"/api/cases/{c3['id']}/package", viewer)
    shown = json.dumps([st.get("intel") for st in p4["exploration"]["steps"] if st.get("intel")], ensure_ascii=False)
    check("운영 정보", "검토 패키지(열람자)의 운영 정보는 전화·계좌를 가린 값",
          '"phone"' in shown and "010-0000-1234" not in shown and "000000-00-000000" not in shown, f"요약 {len(shown)}자")

    # ── 조치 추적·재확인(#92) ──
    act = {"rev": 0, "state": "requested", "agency": "kisa", "ref": "LIVE-" + secrets.token_hex(3)}
    check("조치 추적", "열람자 조치 기록 403", call("POST", f"/api/cases/{cid}/actions", viewer, act)[0] == 403)
    check("조치 추적", "자동화 토큰 조치 기록 403(사람 계정만)", call("POST", f"/api/cases/{cid}/actions", svc, act)[0] == 403)
    check("조치 추적", "위협 확정이 없는 사건 422", call("POST", f"/api/cases/{c3['id']}/actions", rev1, act)[0] == 422)
    s, a1, _ = call("POST", f"/api/cases/{cid}/actions", rev1, act)
    check("조치 추적", "검토관 '요청함(KISA)' 저장(판 1)", s == 201 and a1.get("rev") == 1 and a1.get("agency") == "kisa", str(s))
    check("조치 추적", "옛 판을 보고 저장하면 409", call("POST", f"/api/cases/{cid}/actions", rev1, act)[0] == 409)
    row = next((x for x in call("GET", "/api/cases?limit=50", viewer)[1] if x["id"] == cid), {})
    check("조치 추적", "사건 목록에 현재 조치(열람자)", (row.get("action") or {}).get("state") == "requested")
    check("조치 추적", "열람자 재확인 요청 403", call("POST", f"/api/cases/{cid}/recheck", viewer)[0] == 403)
    t0 = time.time()
    s, ck, _ = call("POST", f"/api/cases/{cid}/recheck", svc)
    again = call("POST", f"/api/cases/{cid}/recheck", svc)[0]
    done = None
    while s == 202 and time.time() - t0 < 120:
        chk = next((x for x in call("GET", f"/api/cases/{cid}/actions", viewer)[1]["checks"] if x["id"] == ck["id"]), {})
        if chk.get("state") != "pending":
            done = chk
            break
        time.sleep(0.5)
    check("조치 추적", "재확인 요청 202 → 격리 컨테이너가 결과를 채움, 바로 다시 요청하면 409",
          s == 202 and again == 409 and bool(done)
          and done.get("result") in ("alive", "gone", "filtered", "refused", "unreachable", "error"),
          f"{(done or {}).get('result')} HTTP {(done or {}).get('http_status')} {time.time() - t0:.1f}초")

    # ── IOC 내보내기(#93): 검토관 이상 ──
    check("IOC", "열람자 IOC 403", call("GET", "/api/ioc?days=1", viewer)[0] == 403)
    s, sm, _ = call("GET", "/api/ioc?days=1", rev1)
    sm = sm if s == 200 and isinstance(sm, dict) else {}
    check("IOC", "검토관 미리 보기(수만, 값 없음)", sm.get("cases", 0) >= 1 and isinstance(sm.get("indicators"), int),
          f"{s} 사건 {sm.get('cases')} 지표 {sm.get('indicators')} {sm.get('ms')}ms")
    s, csv_b, h = call("GET", "/api/ioc.csv?days=1", rev1, raw=True)
    s2, stix_b, _ = call("GET", "/api/ioc.stix?days=1", rev1, raw=True)
    head = csv_b.decode("utf-8-sig", errors="replace").splitlines()[:1] if s == 200 else []
    stix = json.loads(stix_b) if s2 == 200 else {}
    check("IOC", "CSV·STIX 2.1 내려받기", bool(head) and head[0].startswith("유형,값") and stix.get("type") == "bundle",
          f"CSV {len(csv_b)}B 사건 {h.get('X-SafeTrace-Cases')} · STIX 개체 {len(stix.get('objects', []))}")
    check("IOC", "내보내기 감사 기록(ioc.export)", last_audit("qa.rev1", "ioc.export") is not None)

    # ── 현황판(#94)·자동 수집(#95·#96) ──
    s, st, _ = call("GET", "/api/stats?days=7", viewer)
    st = st if s == 200 and isinstance(st, dict) else {}
    check("현황판", "열람자 현황판 200(사건 주소·id 없이 수)",
          st.get("kpi", {}).get("received", 0) >= 1 and cid not in json.dumps(st) and TP not in json.dumps(st),
          f"{s} 접수 {st.get('kpi', {}).get('received')} {st.get('ms')}ms")
    s, ik, _ = call("GET", "/api/intake", viewer)
    check("자동 수집", "열람자 상태 200", s == 200 and isinstance(ik.get("enabled"), bool), f"켜짐 {ik.get('enabled')}")
    check("자동 수집", "열람자·검토관 켜기·끄기 403",
          call("POST", "/api/intake", viewer, {"enabled": False})[0] == 403
          and call("POST", "/api/intake", rev1, {"enabled": False})[0] == 403)
    check("자동 수집", "자동화 토큰(관리자 역할)도 켜기·끄기 403(사람 관리자만)",
          bool(admin_svc) and call("POST", "/api/intake", admin_svc, {"enabled": bool(ik.get("enabled"))})[0] == 403,
          "" if admin_svc else "관리자 역할 자동화 토큰이 없어 미검증")


def limit_checks(svc: str) -> None:
    """3주차 남은 과제: 접속 주소별 로그인 제한, 접수 한도. 시험 계정을 끈 뒤 돈다(로그인 실패를 쌓으므로 맨 끝)."""
    # ① nginx 경유: 사용자가 보낸 X-Forwarded-For 는 버려지고, 웹 컨테이너가 아닌 실제 접속 주소로 센다
    fake = f"198.51.100.{secrets.randbelow(250) + 1}"
    req = urllib.request.Request(B + "/api/auth/login", method="POST", data=json.dumps(
        {"username": "qa.nobody", "password": "wrong-password-123"}).encode(),
        headers={"Content-Type": "application/json", "X-Forwarded-For": fake})
    try:
        urllib.request.urlopen(req, timeout=30)  # noqa: S310 (로컬 API)
    except urllib.error.HTTPError:
        pass
    seen = json.loads(api_py(
        "import json,socket\n"
        "from sqlalchemy import select\n"
        "from safetrace.api.main import store\n"
        "from safetrace.store import AuditLog\n"
        "with store.session() as s:\n"
        "    r=s.scalars(select(AuditLog).where(AuditLog.action=='auth.login_failed',AuditLog.actor=='qa.nobody')"
        ".order_by(AuditLog.id.desc()).limit(1)).first()\n"
        "print(json.dumps({'detail':r.detail if r else '','web':socket.gethostbyname('web')}))\n").strip())
    ip = seen["detail"].rpartition("ip=")[2]
    check("로그인 제한", "nginx 경유 실패를 실제 접속 주소로 기록(보낸 X-Forwarded-For·웹 주소 아님)",
          bool(re.fullmatch(r"[0-9a-f.:]+", ip)) and ip not in (fake, seen["web"]), f"{ip} (보낸 값 {fake})")
    # ② API 에 직접 붙은 쪽(믿지 않는 주소)이 X-Forwarded-For 를 바꿔 가며 보내도 한 주소로 세어 막힌다
    out = api_py(
        "import json,secrets,urllib.request,urllib.error,time\n"
        "codes=[];t=time.time()\n"
        "for i in range(40):\n"
        "    q=urllib.request.Request('http://127.0.0.1:8000/api/auth/login',method='POST',"
        "data=json.dumps({'username':'qa.nobody','password':'wrong-password-123'}).encode(),"
        "headers={'Content-Type':'application/json','X-Forwarded-For':'203.0.113.%d'%(secrets.randbelow(250)+1)})\n"
        "    try: urllib.request.urlopen(q,timeout=30); codes.append(200)\n"
        "    except urllib.error.HTTPError as e: codes.append(e.code)\n"
        "    if codes[-1]==429: break\n"
        "print(json.dumps({'codes':codes,'ms':(time.time()-t)*1000}))\n")
    r = json.loads(out.strip())
    codes = r["codes"]
    check("로그인 제한", "주소를 바꿔 보내도 실패 30회 안에서 429(비밀번호 확인 없이)",
          codes[-1] == 429 and codes.count(401) <= 30 and 200 not in codes,
          f"401×{codes.count(401)}, 마지막 {codes[-1]}, {r['ms']:.0f}ms")
    # ③ 접수 한도: 워커를 잠시 멈춰 사건이 대기로 남게 하고 한 주체가 몰아 넣는다
    compose("pause", "agent")
    made, codes, retry = [], [], None
    try:
        for _ in range(25):
            s, c, h = call("POST", "/api/cases", svc, {"url": "http://10.255.255.1/", "source": "test"})
            codes.append(s)
            if s == 201:
                made.append(c["id"])
            if s == 429:
                retry = h.get("Retry-After")
                break
    finally:
        compose("unpause", "agent")
    check("접수 한도", "한 주체의 끝나지 않은 사건이 20건이면 429", codes[-1] == 429 and len(made) <= 20 and retry == "60",
          f"접수 {len(made)}건, 마지막 {codes[-1]}")
    t0, left = time.time(), list(made)
    while left and time.time() - t0 < 300:
        left = [i for i in left if call("GET", f"/api/cases/{i}", svc)[1]["status"] in ("QUEUED", "RUNNING")]
        time.sleep(2)
    check("접수 한도", "멈췄던 대기열이 모두 끝남", not left, f"{len(made)}건 {time.time() - t0:.0f}초")


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
        ctx = run(pw, svc, toks.get("admin"))
        cid = ctx["cid"]
        analyst_checks(ctx, svc, toks.get("admin"))
    finally:
        set_accounts(False)
    print("시험 계정을 다시 껐다", flush=True)
    limit_checks(svc)
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

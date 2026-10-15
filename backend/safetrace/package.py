"""검토 패키지: 한 사건의 탐색 기록·판단 결과·담당자 판정을 한 묶음으로 정리한다(기획서 2.4).

- 내용은 서명된 증거 체인(chain.jsonl)을 그대로 읽어 만든다. 판단 결과도 DB 값이 아니라 체인의 threat 기록을 쓴다
- 만들 때마다 무결성 검증을 다시 하고 결과를 함께 넣는다. 검증에 실패해도 패키지는 만들되 실패를 숨기지 않는다
- 담당자 영역(판정 기록·감사로그)은 만드는 시점의 DB 값이다. 어느 판까지 들어갔는지 review.current.rev 로 알 수 있다
- ZIP 내보내기에는 원본 체인·파일과 SHA256SUMS 를 넣어, 받은 쪽이 해시 체인과 파일을 다시 계산해 볼 수 있게 한다
- 외부 기관에 자동으로 보내지 않는다. 담당자가 내려받아 쓴다

조사 대상 페이지에서 온 문자열(제목·본문 발췌·버튼 글자)은 데이터로만 담는다. 받는 쪽은 HTML 로 해석하지 말 것.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from .evidence import (
    _SAFE_NAME,
    CHAIN_MAX_BYTES,
    FILE_MAX_BYTES,
    Signer,
    UnsafeEvidence,
    VerifyResult,
    canonical,
    read_evidence,
    sha256_bytes,
)
from .store import AuditLog, Case, Verdict

FORMAT = "safetrace.review-package/1"
_STEP_KINDS = {"observe", "decision", "gate", "action", "action_error", "new_window", "wait_redirect", "dead_end",
               "decision_error", "escalation"}


def read_chain_text(evidence_dir: Path, case_id: str) -> str | None:
    """체인 원문. 없거나 링크·특수 파일·너무 큰 파일이면 None(검증이 chain_missing·chain_unsafe 로 실패한다)."""
    try:
        return read_evidence(evidence_dir, case_id, "chain.jsonl", max_bytes=CHAIN_MAX_BYTES).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def read_chain(evidence_dir: Path, case_id: str) -> list[dict]:
    return parse_chain(read_chain_text(evidence_dir, case_id) or "")


# 패키지·보고서가 읽는 필드의 자료형. 서명은 내용이 바뀌지 않았음만 보장하고 자료형은 보장하지 않는다
# (기록 내용은 조사 대상 페이지를 다루는 에이전트가 정한다). 어긋난 필드는 버리고 integrity.malformed 에 적는다.
_STR, _NUM, _BOOL, _INT, _DICT = str, (int, float), bool, int, dict
_PROB = "prob"  # 0 이상 1 이하의 유한한 수
_SCHEMA: dict[str, dict[str, object]] = {
    "*": {"step": _INT, "sub": _INT, "url": _STR, "reason": _STR, "error": _STR, "category": _STR},
    "start": {"url": _STR},
    "browser": {"version": _STR},
    "navigation": {"final_url": _STR},
    "observe": {"title": _STR, "candidates": [_DICT], "forbidden": [_STR], "has_popup": _BOOL, "boxes": _DICT,
                "text_excerpt": _STR, "text_sha256": _STR, "capture": _STR, "links_seen": _INT},
    "decision": {"choice": _STR, "probability": _PROB, "probabilities": _DICT, "provider": _STR, "model": _STR},
    "gate": {"action": _STR, "element": _STR, "allowed": _BOOL, "point": [_INT], "at": _NUM},
    "action": {"action": _STR, "element": _STR, "outcome": _STR, "result_url": _STR},
    "finish": {"nav_chain": [_STR], "final_url": _STR, "capture": _STR},
    "threat": {"threat": _STR, "probability": _PROB, "probabilities": _DICT, "hold": _BOOL, "override": _DICT,
               "provider": _STR, "model": _STR, "evidence_seqs": [_INT]},
    "safebrowsing": {"status": _STR, "matches": [_DICT]},
    "candidates": {"found": [_DICT], "followup": _BOOL, "main": _DICT},
    "candidate_results": {"results": [_DICT]},
    "blocked_request": {"navigation": _BOOL},
    "recording": {"t0": _NUM},
}
_ITEM = {  # 목록 안 사전의 필드
    "candidates": {"id": _STR, "text": _STR},
    "found": {"url": _STR, "host": _STR, "source": _STR, "score": _INT, "text": _STR},
    "matches": {"url": _STR, "threatType": _STR},
    "results": {"sub": _INT, "url": _STR, "final_url": _STR, "threat": _STR, "probability": _PROB, "hold": _BOOL,
                "status": _STR, "reason": _STR, "reputation_match": _BOOL, "reputation_unchecked": _BOOL,
                "blocked": _BOOL, "score": _INT, "text": _STR},
}


def _ok(v: object, t: object) -> bool:
    if t is _PROB:
        return isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1  # 거대한 int·nan 도 걸러짐
    if t is _NUM or t is _INT:
        return isinstance(v, t) and not isinstance(v, bool)  # type: ignore[arg-type]
    return isinstance(v, t)  # type: ignore[arg-type]


def _clean_item(field: str, x: object) -> dict | None:
    if not isinstance(x, dict):
        return None
    return {k: v for k, v in x.items() if k not in _ITEM.get(field, {}) or _ok(v, _ITEM[field][k])}


def sanitize(rec: dict, bad: list[str]) -> dict | None:
    """기록 하나의 자료형을 맞춘다. 기록 틀이 어긋나면 None(이후 기록은 믿지 않는다)."""
    if not (isinstance(rec, dict) and _ok(rec.get("seq"), _INT) and isinstance(rec.get("kind"), str)
            and isinstance(rec.get("ts"), str) and isinstance(rec.get("data"), dict)
            and isinstance(rec.get("files", {}), dict)):
        return None
    data = {}
    schema = {**_SCHEMA["*"], **_SCHEMA.get(rec["kind"], {})}
    for k, v in rec["data"].items():
        t = schema.get(k)
        if t is None or v is None:
            data[k] = v
        elif isinstance(t, list):
            if not isinstance(v, list):
                bad.append(f"seq {rec['seq']}: {rec['kind']}.{k}")
                continue
            items = [_clean_item(k, x) for x in v] if t[0] is _DICT else [x for x in v if _ok(x, t[0])]
            items = [x for x in items if x is not None]
            if len(items) != len(v):
                bad.append(f"seq {rec['seq']}: {rec['kind']}.{k}[]")
            data[k] = items
        elif _ok(v, t):
            data[k] = v
        else:
            bad.append(f"seq {rec['seq']}: {rec['kind']}.{k}")
    files = {n: h for n, h in rec.get("files", {}).items() if isinstance(h, str)}
    return {**rec, "data": data, "files": files}


def parse_chain(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            break  # 깨진 줄 이후는 믿지 않는다(검증 결과에 malformed 로 나온다)
    return out


def clean_records(records: list) -> tuple[list[dict], list[str]]:
    """패키지·보고서가 쓰기 전에 모든 기록의 자료형을 맞춘다. 반환: (기록, 버린 필드 목록)"""
    bad: list[str] = []
    out = []
    for r in records:
        c = sanitize(r, bad)
        if c is None:
            bad.append(f"record {len(out)}: malformed")
            break
        out.append(c)
    return out, bad


def _element_text(observe: dict | None, element: str | None) -> str | None:
    if not observe or not element:
        return None
    for c in observe.get("candidates", []):
        if c.get("id") == element:
            return c.get("text")
    return None


def _exploration(records: list[dict]) -> tuple[dict, dict]:
    """체인 기록을 단계(step)별로 묶는다. 단계마다 관찰 화면 → Jev 선택 → 안전 게이트 → 실행 결과 순서.
    반환: (탐색 기록, 단계 밖 기록을 종류별로 모은 것)"""
    steps: dict[int, dict] = {}
    top: dict[str, dict] = {}
    blocked_nav, blocked_other, other = [], 0, []

    def step_of(n: int) -> dict:
        return steps.setdefault(n, {"step": n, "events": []})

    for r in records:
        kind, d, seq = r["kind"], r["data"], r["seq"]
        files = list(r.get("files", {}))
        if kind == "blocked_request":
            if d.get("navigation"):
                blocked_nav.append({"seq": seq, "url": d.get("url"), "reason": d.get("reason")})
            else:
                blocked_other += 1
            continue
        if kind in _STEP_KINDS and isinstance(d.get("step"), int):
            s = step_of(d["step"])
            if kind == "observe":
                s["observe"] = {"seq": seq, "url": d.get("url"), "title": d.get("title"), "screenshot": files[0] if files else None,
                                "candidates": d.get("candidates", []), "forbidden": d.get("forbidden", []),
                                "has_popup": d.get("has_popup"), "text_excerpt": d.get("text_excerpt"),
                                "text_sha256": d.get("text_sha256")}
            elif kind == "decision":
                choice = d.get("choice", "")
                el = choice.removeprefix("click_") if choice.startswith("click_") else None
                s["decision"] = {"seq": seq, "choice": choice, "element_text": _element_text(s.get("observe"), el),
                                 "probability": d.get("probability"), "probabilities": d.get("probabilities"),
                                 "provider": d.get("provider"), "model": d.get("model")}
            elif kind == "gate":
                s["gate"] = {"seq": seq, "action": d.get("action"), "element": d.get("element"),
                             "allowed": d.get("allowed"), "reason": d.get("reason")}
            elif kind == "action":
                s["action"] = {"seq": seq, "action": d.get("action"), "element": d.get("element"),
                               "element_text": _element_text(s.get("observe"), d.get("element")),
                               "outcome": d.get("outcome"), "result_url": d.get("result_url"),
                               "before": next((f for f in files if "_before" in f), None),
                               "after": next((f for f in files if "_after" in f), None)}
            else:
                s["events"].append({"seq": seq, "kind": kind, "data": d, "files": files})
            continue
        if kind in ("start", "browser", "navigation", "finish", "recording", "threat", "safebrowsing",
                    "unreachable", "threat_error", "candidates", "candidate_results"):
            top[kind] = {"seq": seq, **d, **({"files": files} if files else {})}
        else:  # 단계가 없는 기타 기록(새 창 등)도 빠뜨리지 않는다
            other.append({"seq": seq, "kind": kind, "data": d, "files": files})

    nav = top.get("navigation", {})
    fin = top.get("finish", {})
    return {
        "start": top.get("start"),
        "browser": top.get("browser"),
        "first_load": nav or None,
        "unreachable": top.get("unreachable"),
        "path": fin.get("nav_chain") or [u for u in [nav.get("final_url")] if u],
        "final_url": fin.get("final_url") or nav.get("final_url"),
        "finish": fin or None,
        "steps": [steps[k] for k in sorted(steps)],
        "blocked_navigations": blocked_nav,
        "blocked_requests_other": blocked_other,
        "recording": top.get("recording"),
        "other_events": other,
    }, top


def _verdict(v: Verdict) -> dict:
    return {"rev": v.rev, "decision": v.decision, "threat": v.threat, "note": v.note, "reviewer": v.reviewer,
            "ai_threat": v.ai_threat, "head_seq": v.head_seq, "head_hash": v.head_hash,
            "created_at": v.created_at.isoformat()}


def _candidates(top: dict, records: list[dict]) -> dict | None:
    """연관 후보: 찾은 목록, 하위 조사를 했는지, 후보마다 탐색 기록과 판단(체인의 sub 기록)."""
    found = top.get("candidates")
    if not found:
        return None
    subs: dict[int, list[dict]] = {}
    for r in records:
        n = r["data"].get("sub")
        if isinstance(n, int):
            subs.setdefault(n, []).append(r)
    results = {r.get("sub"): r for r in (top.get("candidate_results") or {}).get("results", [])}
    investigated = []
    for n in sorted(subs):
        exp, t = _exploration(subs[n])
        errors = [x for x in exp["other_events"] if x["kind"] == "candidate_error"]
        investigated.append({"sub": n, "url": (results.get(n) or {}).get("url") or (exp["start"] or {}).get("url"),
                             "result": results.get(n), "threat": t.get("threat"), "exploration": exp,
                             "error": errors[0]["data"] if errors else None})
    return {"seq": found["seq"], "found": found.get("found", []), "followup": found.get("followup"),
            "investigated": investigated}


def build(case: Case, records: list[dict], verify: VerifyResult, verdicts: list[Verdict], audit: list[AuditLog],
          *, generated_by: str, key_id: str) -> dict:
    records, malformed = clean_records(records)
    # 연관 후보 하위 조사 기록(data.sub)은 원래 조사와 따로 묶는다
    main = [r for r in records if not isinstance(r["data"].get("sub"), int)]
    exploration, top = _exploration(main)
    threat = top.get("threat")
    # 체인은 에이전트 컨테이너가 쓴다. 이름 규칙에 맞지 않는 파일(경로 이동 등)은 담지 않는다(검증 결과에는 file_missing 으로 나옴)
    files = [{"name": n, "sha256": h, "seq": r["seq"], "kind": r["kind"]}
             for r in records for n, h in r.get("files", {}).items() if _SAFE_NAME.match(n)]
    hist = sorted(verdicts, key=lambda v: v.rev, reverse=True)
    return {
        "format": FORMAT,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "generated_by": generated_by,
        "notice": "AI 판단은 기술적 의심 유형이며 법적 판단이 아니다. 최종 판정은 담당자가 한다. "
                  "페이지에서 온 문자열은 데이터로만 다룰 것.",
        "case": {"id": case.id, "url": case.url, "source": case.source, "status": case.status,
                 "finish_reason": case.finish_reason, "final_url": case.final_url, "created_by": case.created_by,
                 "created_at": case.created_at.isoformat()},
        "integrity": {"verified": verify.ok, "records": verify.records, "errors": verify.errors,
                      "malformed": malformed,  # 서명은 맞지만 자료형이 어긋나 버린 필드(침해된 에이전트의 흔적일 수 있음)
                      "head_seq": case.head_seq, "head_hash": case.head_hash, "key_id": key_id,
                      "method": "sha256 해시 체인 + HMAC-SHA256 서명(키는 저장소와 분리 보관)"},
        "exploration": exploration,
        "assessment": {
            "threat": threat,  # 위협 유형 후보·확률·근거 증거 ID(evidence_seqs), 코드 규칙 override 포함
            "hold": bool(threat and threat.get("hold")),
            "safebrowsing": top.get("safebrowsing"),
            "error": top.get("threat_error"),
            "escalation": next((x["data"] for x in exploration["other_events"] if x["kind"] == "escalation"), None),
        },
        "candidates": _candidates(top, records),
        "review": {
            "current": _verdict(hist[0]) if hist else None,
            "history": [_verdict(v) for v in hist],
            "audit": [{"at": a.created_at.isoformat(), "actor": a.actor, "action": a.action, "detail": a.detail}
                      for a in sorted(audit, key=lambda a: a.id)],
        },
        "files": files,
    }


_README = """SafeTrace 검토 패키지
=====================

package.json   탐색 기록·판단 결과·담당자 판정 묶음 (형식: {fmt})
chain.jsonl    서명된 증거 체인 원본(한 줄 = 기록 하나)
files/         스크린샷·녹화 원본(체인에 sha256 이 적혀 있음)
report.json    보고서 초안(기관 양식으로 옮기기 쉬운 요약, package.json 에서 뽑음)
report.pdf     같은 내용의 PDF
SHA256SUMS     이 묶음 안 모든 파일의 sha256
package.sig    package.json·SHA256SUMS 의 sha256 에 건 HMAC-SHA256 서명(키 {key_id}, SafeTrace 서버에서만 확인 가능).
               SHA256SUMS 가 보고서·체인·파일을 모두 담으므로 어느 하나만 바꿔도 서명이 맞지 않는다

받은 쪽에서 할 수 있는 확인
1) sha256sum -c SHA256SUMS                → 파일이 바뀌지 않았는지
2) chain.jsonl 각 줄: hash = sha256(prev + canonical(seq, ts, kind, data, files)), 다음 줄 prev = 이 줄 hash
   canonical = JSON(키 정렬, 공백 없음, UTF-8)  → 기록 삭제·순서 변경·내용 수정 여부
3) files/ 의 각 파일 sha256 이 체인 기록의 files 값과 같은지
서명(sig) 확인은 서명 키가 있는 SafeTrace 서버의 검증 기능으로 한다.

AI 판단은 기술적 의심 유형이며 법적 판단이 아니다. 최종 판정은 담당자가 한다.
"""


SIG_FORMAT = "safetrace.package-sig/2"
_SIG_FIELDS = ("format", "case_id", "generated_at", "package_sha256", "sums_sha256", "key_id")


def _sig_digest(sig: dict) -> str:
    return sha256_bytes(canonical({k: sig.get(k) for k in _SIG_FIELDS}))


def export_zip(pkg: dict, evidence_dir: Path, case_id: str, signer: Signer,
               extra: list[tuple[str, bytes]] | None = None, *, chain_text: str | None = None) -> bytes:
    """extra: 같이 담을 파생 문서(보고서 초안 report.json·report.pdf).
    chain_text: 패키지를 만들 때 검증한 체인 스냅숏(따로 다시 읽으면 그 사이에 바뀔 수 있다).
    서명은 SHA256SUMS(묶음 안 모든 파일의 해시)와 package.json 에 함께 건다. 보고서만 바꿔도 서명이 맞지 않는다."""
    # 증거 파일은 한 번 읽은 바이트를 체인의 해시와 대조하고 그 바이트를 담는다(검증 뒤에 바뀐 파일은 빼고 실패로 적음).
    # 링크·특수 파일은 따라가거나 기다리지 않는다(evidence.open_evidence)
    files: list[tuple[str, bytes]] = []
    changed: list[str] = []
    for f in pkg["files"]:
        if not _SAFE_NAME.match(f["name"]):
            continue
        try:
            data = read_evidence(evidence_dir, case_id, "files", f["name"], max_bytes=FILE_MAX_BYTES)
        except FileNotFoundError:
            continue
        except UnsafeEvidence:
            changed.append(f["name"])
            continue
        if sha256_bytes(data) == f["sha256"]:
            files.append((f"files/{f['name']}", data))
        else:
            changed.append(f["name"])
    if changed:
        integ = pkg["integrity"]
        pkg = {**pkg, "integrity": {**integ, "verified": False,
                                    "errors": [*integ["errors"], *(f"file_changed_at_export {n}" for n in changed)]}}
    body = json.dumps(pkg, ensure_ascii=False, indent=2).encode()
    entries: list[tuple[str, bytes]] = [("package.json", body), *(extra or [])]
    if chain_text is not None:  # 증거 볼륨의 체인 파일을 다시 열지 않는다(검증한 스냅숏만)
        entries.append(("chain.jsonl", chain_text.encode()))
    entries += files
    entries.append(("README.txt", _README.format(fmt=FORMAT, key_id=signer.key_id).encode()))

    buf = io.BytesIO()
    sums = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            # 녹화·PNG 는 이미 압축돼 있으니 그대로 담는다
            z.writestr(name, data, zipfile.ZIP_STORED if name.endswith((".png", ".webm")) else zipfile.ZIP_DEFLATED)
            sums.append(f"{sha256_bytes(data)}  {name}")
        sums_body = ("\n".join(sums) + "\n").encode()
        z.writestr("SHA256SUMS", sums_body)
        sig = {"format": SIG_FORMAT, "case_id": case_id, "generated_at": pkg["generated_at"],
               "package_sha256": sha256_bytes(body), "sums_sha256": sha256_bytes(sums_body), "key_id": signer.key_id}
        sig["hmac_sha256"] = signer.sign(_sig_digest(sig))
        z.writestr("package.sig", canonical(sig))
    return buf.getvalue()


def verify_sig(pkg_json: bytes, sums: bytes, sig: dict, signer: Signer) -> bool:
    """package.json·SHA256SUMS 가 서명과 맞는지(서명 키가 있는 서버에서만)."""
    try:
        pkg = json.loads(pkg_json)
        return (sig.get("format") == SIG_FORMAT and sha256_bytes(pkg_json) == sig.get("package_sha256")
                and sha256_bytes(sums) == sig.get("sums_sha256") and pkg["case"]["id"] == sig.get("case_id")
                and pkg["generated_at"] == sig.get("generated_at")
                and signer.verify(_sig_digest(sig), str(sig.get("hmac_sha256", ""))))
    except (ValueError, KeyError, TypeError):
        return False


def verify_zip(data: bytes, signer: Signer) -> bool:
    """내보낸 ZIP 전체 확인: 서명 → SHA256SUMS 에 package.sig 를 뺀 모든 파일이 정확히 한 번씩 있고 해시가 맞는지."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
        if len(names) != len(set(names)):
            return False
        sums = z.read("SHA256SUMS")
        if not verify_sig(z.read("package.json"), sums, json.loads(z.read("package.sig")), signer):
            return False
        listed = {}
        for line in sums.decode().splitlines():
            digest, name = line.split("  ", 1)
            if name in listed:
                return False
            listed[name] = digest
        if set(listed) != set(names) - {"SHA256SUMS", "package.sig"}:
            return False
        if not all(sha256_bytes(z.read(n)) == h for n, h in listed.items()):
            return False
        # 담긴 증거 파일은 체인에 적힌 해시와도 같아야 한다
        want: dict[str, str] = {}
        if "chain.jsonl" in listed:
            for line in z.read("chain.jsonl").decode().splitlines():
                want.update(json.loads(line).get("files") or {})
        return all(want.get(n.removeprefix("files/")) == sha256_bytes(z.read(n)) for n in listed if n.startswith("files/"))
    except (zipfile.BadZipFile, KeyError, ValueError, TypeError, AttributeError):
        return False

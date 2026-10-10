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

from .evidence import Signer, VerifyResult, canonical, sha256_bytes
from .store import AuditLog, Case, Verdict

FORMAT = "safetrace.review-package/1"
_STEP_KINDS = {"observe", "decision", "gate", "action", "action_error", "new_window", "wait_redirect", "dead_end",
               "decision_error", "escalation"}


def read_chain(evidence_dir: Path, case_id: str) -> list[dict]:
    p = evidence_dir / case_id / "chain.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            break  # 깨진 줄 이후는 믿지 않는다(검증 결과에 malformed 로 나온다)
    return out


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
                    "unreachable", "threat_error"):
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


def build(case: Case, records: list[dict], verify: VerifyResult, verdicts: list[Verdict], audit: list[AuditLog],
          *, generated_by: str, key_id: str) -> dict:
    exploration, top = _exploration(records)
    threat = top.get("threat")
    files = [{"name": n, "sha256": h, "seq": r["seq"], "kind": r["kind"]} for r in records for n, h in r.get("files", {}).items()]
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
                      "head_seq": case.head_seq, "head_hash": case.head_hash, "key_id": key_id,
                      "method": "sha256 해시 체인 + HMAC-SHA256 서명(키는 저장소와 분리 보관)"},
        "exploration": exploration,
        "assessment": {
            "threat": threat,  # 위협 유형 후보·확률·근거 증거 ID(evidence_seqs), 코드 규칙 override 포함
            "hold": bool(threat and threat.get("hold")),
            "safebrowsing": top.get("safebrowsing"),
            "error": top.get("threat_error"),
        },
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
SHA256SUMS     이 묶음 안 모든 파일의 sha256
package.sig    package.json 의 sha256 과 HMAC-SHA256 서명(키 {key_id}, SafeTrace 서버에서만 확인 가능)

받은 쪽에서 할 수 있는 확인
1) sha256sum -c SHA256SUMS                → 파일이 바뀌지 않았는지
2) chain.jsonl 각 줄: hash = sha256(prev + canonical(seq, ts, kind, data, files)), 다음 줄 prev = 이 줄 hash
   canonical = JSON(키 정렬, 공백 없음, UTF-8)  → 기록 삭제·순서 변경·내용 수정 여부
3) files/ 의 각 파일 sha256 이 체인 기록의 files 값과 같은지
서명(sig) 확인은 서명 키가 있는 SafeTrace 서버의 검증 기능으로 한다.

AI 판단은 기술적 의심 유형이며 법적 판단이 아니다. 최종 판정은 담당자가 한다.
"""


def export_zip(pkg: dict, evidence_dir: Path, case_id: str, signer: Signer) -> bytes:
    d = evidence_dir / case_id
    body = json.dumps(pkg, ensure_ascii=False, indent=2).encode()
    digest = sha256_bytes(body)
    entries: list[tuple[str, bytes | Path]] = [("package.json", body)]
    chain = d / "chain.jsonl"
    if chain.exists():
        entries.append(("chain.jsonl", chain))
    for f in pkg["files"]:
        p = d / "files" / f["name"]
        if p.is_file():
            entries.append((f"files/{f['name']}", p))
    sig = {"package_sha256": digest, "hmac_sha256": signer.sign(digest), "key_id": signer.key_id,
           "case_id": case_id, "generated_at": pkg["generated_at"]}
    entries.append(("package.sig", canonical(sig)))
    entries.append(("README.txt", _README.format(fmt=FORMAT, key_id=signer.key_id).encode()))

    buf = io.BytesIO()
    sums = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, src in entries:
            data = src.read_bytes() if isinstance(src, Path) else src
            # 녹화·PNG 는 이미 압축돼 있으니 그대로 담는다
            z.writestr(name, data, zipfile.ZIP_STORED if name.endswith((".png", ".webm")) else zipfile.ZIP_DEFLATED)
            sums.append(f"{sha256_bytes(data)}  {name}")
        z.writestr("SHA256SUMS", "\n".join(sums) + "\n")
    return buf.getvalue()


def verify_sig(pkg_json: bytes, sig: dict, signer: Signer) -> bool:
    return sha256_bytes(pkg_json) == sig.get("package_sha256") and signer.verify(sig["package_sha256"], sig.get("hmac_sha256", ""))

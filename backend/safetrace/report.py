"""보고서 초안(기획서 2.4): 기관 양식으로 옮기기 쉬운 요약본을 JSON·PDF 로 만든다.

- 내용은 검토 패키지(서명된 증거 체인에서 만든 것)에서 뽑는다. DB 의 AI 판단을 따로 읽지 않는다
- 담당자가 확정(위협·정상)하기 전에는 '초안'으로 표시한다. AI 판단은 기술적 의심 유형이며 법적 판단이 아니다
- 화면 사진은 파일의 sha256 이 체인 기록과 같을 때만 넣는다. 원본은 검토 패키지(ZIP)에 있다
- 페이지에서 온 문자열(제목·주소·버튼 글자)은 PDF 마크업으로 해석하지 않는다(모두 이스케이프).
  reportlab 문단 마크업은 <img src> 로 로컬 파일을 읽을 수 있어서다
- 외부 기관에 자동으로 보내지 않는다. 담당자가 내려받아 쓴다
"""

from __future__ import annotations

import html
import io
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PIL import Image as PILImage

from . import preview as _preview  # noqa: F401  Image.MAX_IMAGE_PIXELS 제한을 함께 쓴다
from .evidence import _SAFE_NAME, sha256_bytes
from .package import clean_records

FORMAT = "safetrace.report/1"
KST = timezone(timedelta(hours=9), "KST")

THREAT_KO = {"phishing": "피싱", "scam": "사기", "illegal_gambling": "불법 도박 의심", "malware": "악성코드",
             "benign": "정상", "unknown": "판단 불가"}
STATUS_KO = {"COMPLETED": "조사 완료", "REVIEW_REQUIRED": "검토 필요", "FAILED": "실패", "UNREACHABLE": "접속 불가",
             "BLOCKED": "차단(정책)"}
DECISION_KO = {"threat": "위협 확정", "benign": "정상", "hold": "보류"}
REASON_KO = {
    "reputation_match": "Safe Browsing 위험 일치(AI 는 정상으로 봄)",
    "candidate_reputation_match": "연관 후보가 Safe Browsing 위험 일치(AI 는 정상으로 봄)",
    "unreachable_reputation_match": "접속 불가 · Safe Browsing 위험 일치",
    "unreachable_network_filtered": "접속 불가 · 회선이 도메인 이름을 보고 차단",
    "goto_failed": "최초 접속 실패",
    "low_confidence_action": "다음 행동 확신 부족으로 탐색 종료",
    "loop_detected": "같은 화면 반복으로 탐색 종료",
    "dead_end": "더 갈 수 없는 화면(오류·차단)에서 탐색 종료",
    "agent_finished": "에이전트가 조사 완료 판단",
    "step_budget": "최대 단계 도달",
    "time_budget": "최대 시간 도달",
    "threat_decision_unavailable": "위협 판단 불가(판단 서비스 장애)",
}
SB_KO = {"match": "위험 목록 일치", "no_match": "일치 없음", "error": "조회 실패", "disabled": "조회 안 함(키 없음)",
         "skipped": "조회 안 함"}
NOTICE = ("이 문서는 SafeTrace 가 자동으로 만든 보고서 초안이다. AI 판단은 기술적 의심 유형이며 법적 판단이 아니다. "
          "최종 판정은 담당자가 한다. 원본 증거와 무결성 확인 방법은 같은 사건의 검토 패키지(ZIP)에 있다.")

MAX_STEPS = 20
MAX_SCREENS = 4
_URL, _TEXT = 500, 200


def _cut(s: object, n: int) -> str | None:
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def _kst(ts: str | None) -> str | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts).astimezone(KST).strftime("%Y-%m-%d %H:%M:%S KST")
    except (TypeError, ValueError):
        return None


def _seconds(a: str | None, b: str | None) -> float | None:
    try:
        return round((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds(), 1)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _ai(threat: dict | None) -> dict | None:
    if not threat:
        return None
    return {"threat": threat.get("threat"), "threat_ko": THREAT_KO.get(threat.get("threat"), threat.get("threat")),
            "probability": threat.get("probability"), "hold": bool(threat.get("hold")),
            "override": _cut(threat.get("override"), _TEXT), "provider": threat.get("provider"),
            "model": threat.get("model")}


def _steps(exp: dict) -> tuple[list[dict], int]:
    out, forbidden = [], 0
    for s in exp.get("steps", [])[:MAX_STEPS]:
        ob, act, dec = s.get("observe") or {}, s.get("action") or {}, s.get("decision") or {}
        forbidden += len(ob.get("forbidden") or [])
        choice = act.get("action") or (dec.get("choice") or "").split("_")[0] or None
        out.append({"step": s.get("step"), "url": _cut(ob.get("url"), _URL), "title": _cut(ob.get("title"), _TEXT),
                    "action": choice, "element_text": _cut(act.get("element_text") or dec.get("element_text"), 100),
                    "outcome": act.get("outcome"), "result_url": _cut(act.get("result_url"), _URL),
                    "screenshot": ob.get("screenshot")})
    return out, forbidden


def _screens(exp: dict, files: dict[str, str]) -> list[dict]:
    """주요 화면: 첫 화면, 마지막 화면, 그 사이에서 마지막에 가까운 화면 순으로 최대 4장."""
    obs = [s["observe"] for s in exp.get("steps", []) if (s.get("observe") or {}).get("screenshot")]
    if not obs:
        return []
    pick = [obs[0], obs[-1], *reversed(obs[1:-1])]
    seen, out = set(), []
    for o in pick:
        name = o["screenshot"]
        if name in seen or name not in files:
            continue
        seen.add(name)
        out.append({"step": next((s["step"] for s in exp["steps"] if s.get("observe") is o), None),
                    "seq": o.get("seq"), "url": _cut(o.get("url"), _URL), "title": _cut(o.get("title"), _TEXT),
                    "file": name, "sha256": files[name]})
        if len(out) == MAX_SCREENS:
            break
    return sorted(out, key=lambda x: x["seq"] or 0)


def build(pkg: dict, records: list[dict]) -> dict:
    """검토 패키지(package.build 결과)와 체인 기록으로 보고서 초안 JSON 을 만든다."""
    case, exp, a, review = pkg["case"], pkg["exploration"], pkg["assessment"], pkg["review"]
    records, _ = clean_records(records)  # 자료형이 어긋난 기록은 패키지와 같은 규칙으로 버린다
    main = [r for r in records if not isinstance(r["data"].get("sub"), int)]
    started = next((r["ts"] for r in main if r["kind"] == "start"), None)
    finished = next((r["ts"] for r in reversed(main) if r["kind"] in ("finish", "threat", "safebrowsing")), None)
    steps, forbidden = _steps(exp)
    files = {f["name"]: f["sha256"] for f in pkg["files"]}
    cur = review.get("current")
    sb = a.get("safebrowsing") or {}
    cands = pkg.get("candidates") or {}
    related = []
    for c in cands.get("investigated", []):
        r, t = c.get("result") or {}, c.get("threat") or {}
        related.append({"sub": c["sub"], "url": _cut(c.get("url"), _URL),
                        "final_url": _cut(r.get("final_url"), _URL),
                        "threat": r.get("threat") or t.get("threat"),
                        "threat_ko": THREAT_KO.get(r.get("threat") or t.get("threat")),
                        "probability": r.get("probability", t.get("probability")),
                        "hold": bool(r.get("hold") or t.get("hold")),
                        "reputation_match": bool(r.get("reputation_match")),
                        "reputation_unchecked": bool(r.get("reputation_unchecked")),
                        "status": r.get("status"), "error": bool(c.get("error"))})
    integ = pkg["integrity"]
    return {
        "format": FORMAT,
        "generated_at": pkg["generated_at"],
        "generated_by": pkg["generated_by"],
        "draft": not cur or cur["decision"] == "hold",
        "notice": NOTICE,
        "case": {"id": case["id"], "url": _cut(case["url"], _URL), "source": case.get("source"),
                 "received_at": case["created_at"], "received_by": case.get("created_by")},
        "investigation": {
            "started_at": started, "finished_at": finished, "duration_seconds": _seconds(started, finished),
            "status": case["status"], "status_ko": STATUS_KO.get(case["status"], case["status"]),
            "finish_reason": case.get("finish_reason"),
            "finish_reason_ko": REASON_KO.get(case.get("finish_reason") or "", case.get("finish_reason")),
            "final_url": _cut(exp.get("final_url") or case.get("final_url"), _URL),
            "path": [_cut(u, _URL) for u in (exp.get("path") or [])[:20]],
            "browser": (exp.get("browser") or {}).get("version"),
            "steps": steps,
            "steps_total": len(exp.get("steps", [])),
            "forbidden_elements": forbidden,
            "blocked_navigations": [{"url": _cut(b.get("url"), _URL), "reason": b.get("reason")}
                                    for b in exp.get("blocked_navigations", [])[:10]],
            "blocked_navigations_total": len(exp.get("blocked_navigations", [])),
            "unreachable": (exp.get("unreachable") or {}).get("category"),
        },
        "assessment": {
            "ai": _ai(a.get("threat")),
            "error": bool(a.get("error")),
            "escalation": _cut((a.get("escalation") or {}).get("reason"), _TEXT),
            "safebrowsing": {"status": sb.get("status"), "status_ko": SB_KO.get(sb.get("status"), sb.get("status")),
                             "matches": [{"url": _cut(m.get("url"), _URL), "type": m.get("threatType") or m.get("type")}
                                         for m in sb.get("matches", [])[:10]]} if sb else None,
        },
        "related": {"found": len(cands.get("found", [])), "investigated": related} if cands else None,
        "verdict": {"rev": cur["rev"], "decision": cur["decision"], "decision_ko": DECISION_KO.get(cur["decision"]),
                    "threat": cur["threat"], "threat_ko": THREAT_KO.get(cur["threat"]) if cur["threat"] else None,
                    "note": cur["note"], "reviewer": cur["reviewer"], "at": cur["created_at"]} if cur else None,
        "key_screens": _screens(exp, files),
        "integrity": {"verified": integ["verified"], "records": integ["records"], "errors": len(integ["errors"]),
                      "head_seq": integ["head_seq"], "head_hash": integ["head_hash"], "key_id": integ["key_id"],
                      "method": integ["method"]},
    }


# ── PDF ─────────────────────────────────────────────────
_FONTS = [  # (보통, 굵게). 컨테이너는 fonts-nanum, 개발 PC(Windows)는 맑은 고딕
    ("/usr/share/fonts/truetype/nanum/NanumGothic.ttf", "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf"),
    ("C:/Windows/Fonts/malgun.ttf", "C:/Windows/Fonts/malgunbd.ttf"),
]


class FontMissing(RuntimeError):
    pass


def _register_fonts() -> None:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    if "KR" in pdfmetrics.getRegisteredFontNames():
        return
    env = os.environ.get("ST_REPORT_FONT")
    pairs = [(env, os.environ.get("ST_REPORT_FONT_BOLD") or env)] if env else _FONTS
    for reg, bold in pairs:
        if reg and Path(reg).is_file() and bold and Path(bold).is_file():
            pdfmetrics.registerFont(TTFont("KR", reg))
            pdfmetrics.registerFont(TTFont("KR-B", bold))
            return
    raise FontMissing("한국어 글꼴을 찾지 못함(ST_REPORT_FONT)")


def _t(s: object) -> str:
    """페이지에서 온 값을 문단 마크업 없이 글자 그대로 넣는다."""
    return html.escape("" if s is None else str(s), quote=False)


def _shot(path: Path, sha: str, width_px: int = 800, max_h_px: int = 560) -> io.BytesIO | None:
    """체인의 sha256 과 같은 원본만 쓴다. 너비를 줄이고 위쪽만 잘라 JPEG 로."""
    try:
        data = path.read_bytes()
        if sha256_bytes(data) != sha:
            return None
        with PILImage.open(io.BytesIO(data)) as im:
            rgb = im.convert("RGB")
    except (OSError, PILImage.DecompressionBombError, ValueError):
        return None
    if rgb.width > width_px:
        rgb = rgb.resize((width_px, round(rgb.height * width_px / rgb.width)), PILImage.Resampling.LANCZOS)
    if rgb.height > max_h_px:
        rgb = rgb.crop((0, 0, rgb.width, max_h_px))
    buf = io.BytesIO()
    rgb.save(buf, "JPEG", quality=70, optimize=True)
    buf.seek(0)
    return buf


def _pct(p: object) -> str:
    return f"{float(p) * 100:.0f}%" if isinstance(p, (int, float)) else "-"


def render_pdf(rep: dict, evidence_dir: Path) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Image, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    _register_fonts()
    base = ParagraphStyle("b", fontName="KR", fontSize=9, leading=13, wordWrap="CJK")
    small = ParagraphStyle("s", parent=base, fontSize=7.5, leading=10, textColor=colors.HexColor("#555555"))
    h1 = ParagraphStyle("h1", parent=base, fontName="KR-B", fontSize=16, leading=22, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=base, fontName="KR-B", fontSize=11, leading=16, spaceBefore=10, spaceAfter=4)
    key = ParagraphStyle("k", parent=base, fontName="KR-B", textColor=colors.HexColor("#333333"))
    P = Paragraph
    case, inv, a = rep["case"], rep["investigation"], rep["assessment"]
    cid = case["id"]
    width = A4[0] - 36 * mm

    def kv(rows: list[tuple[str, object]]) -> Table:
        t = Table([[P(_t(k), key), v if not isinstance(v, (str, type(None))) else P(_t(v or "-"), base)] for k, v in rows],
                  colWidths=[34 * mm, width - 34 * mm])
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#999999")),
                               ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF1F5")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        return t

    out: list = []
    out.append(P("위협 의심 사이트 조사 보고서" + (" (초안)" if rep["draft"] else ""), h1))
    v = rep.get("verdict")
    state = (f"담당자 판정 완료 · 판 {v['rev']}" if v and not rep["draft"] else
             "담당자 판정 보류" if v else "담당자 판정 전")
    out.append(P(_t(f"사건 {cid} · 작성 {_kst(rep['generated_at'])} · 작성자 {rep['generated_by']} · {state}"), small))
    out.append(Spacer(1, 4))
    box = Table([[P(_t(rep["notice"]), small)]], colWidths=[width])
    box.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#B45309")),
                             ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF7ED"))]))
    out.append(box)

    out.append(P("1. 대상 및 조사 개요", h2))
    dur = inv.get("duration_seconds")
    out.append(kv([
        ("신고 URL", case["url"]),
        ("접수", f"{_kst(case['received_at'])} · {case.get('received_by') or '-'} ({case.get('source') or '-'})"),
        ("조사 일시", f"{_kst(inv.get('started_at')) or '-'} ~ {_kst(inv.get('finished_at')) or '-'}"
                     + (f" ({dur}초)" if dur is not None else "")),
        ("조사 상태", f"{inv['status_ko']}" + (f" — {inv['finish_reason_ko']}" if inv.get("finish_reason_ko") else "")),
        ("최종 도달 주소", inv.get("final_url")),
        ("이동 경로", P("<br/>".join(f"{i}. {_t(u)}" for i, u in enumerate(inv.get("path") or [], 1)) or "-", base)),
        ("조사 환경", f"격리 네트워크의 브라우저(Chromium {inv.get('browser') or '-'}), 검문 프록시 경유. "
                     "입력·결제·다운로드는 하지 않음"),
    ]))

    out.append(P("2. 판단 결과", h2))
    ai = a.get("ai")
    sb = a.get("safebrowsing")
    rows: list[tuple[str, object]] = [
        ("AI 의심 유형", (f"{ai['threat_ko']} (확률 {_pct(ai['probability'])})" + (" · 보류(담당자 검토)" if ai["hold"] else ""))
         if ai else ("판단 서비스 장애로 판단 없음" if a.get("error") else "판단 없음")),
    ]
    if ai and ai.get("override"):
        rows.append(("코드 규칙", ai["override"]))
    if a.get("escalation"):
        rows.append(("담당자 검토 사유", a["escalation"]))
    rows.append(("외부 평판", (f"Google Safe Browsing: {sb['status_ko']}"
                              + "".join(f" · {m['type'] or ''} {m['url']}" for m in sb["matches"])) if sb else "조회 기록 없음"))
    if v:
        rows += [("담당자 판정", f"{v['decision_ko']}" + (f" — {v['threat_ko']}" if v.get("threat_ko") else "")),
                 ("판정 사유", v.get("note")),
                 ("판정자 · 시각", f"{v['reviewer']} · {_kst(v['at'])} (판 {v['rev']})")]
    else:
        rows.append(("담당자 판정", "아직 없음 — 판정·사유는 콘솔에서 기록"))
    out.append(kv(rows))

    out.append(P("3. 확인 내용 (탐색 경위)", h2))
    lines = []
    for s in inv["steps"]:
        what = {"click": f"'{s['element_text'] or '요소'}' 클릭", "scroll": "아래로 이동", "close_popup": "팝업 닫기",
                "back": "뒤로", "finish": "조사 종료"}.get(s.get("action") or "", s.get("action") or "관찰만")
        res = f" → {s['result_url']}" if s.get("result_url") and s["result_url"] != s.get("url") else ""
        lines.append(f"{s['step']}단계 · 「{_t(s.get('title') or '제목 없음')}」 {_t(s.get('url'))} — {_t(what)}{_t(res)}")
    if inv["steps_total"] > len(inv["steps"]):
        lines.append(f"… 이하 {inv['steps_total'] - len(inv['steps'])}단계는 검토 패키지 참고")
    if not lines:
        lines.append("관찰한 화면 없음" + (f" (접속 불가: {_t(inv['unreachable'])})" if inv.get("unreachable") else ""))
    for ln in lines:
        out.append(P(ln, base))
    extra = []
    if inv["forbidden_elements"]:
        extra.append(f"입력칸·결제·다운로드 등 금지 요소 {inv['forbidden_elements']}개를 확인했고 누르거나 입력하지 않았다.")
    if inv["blocked_navigations_total"]:
        extra.append(f"안전 정책으로 막은 이동 {inv['blocked_navigations_total']}건(내부망 주소 등).")
    for e in extra:
        out.append(P(_t(e), small))

    screens = rep.get("key_screens") or []
    if screens:
        head = [P("4. 주요 화면", h2),
                P("화면 위쪽 일부를 줄여 넣었다. 원본은 검토 패키지 files/ 에 있고 sha256 은 증거 체인 기록과 같다.", small)]
        files_dir = (evidence_dir / cid / "files").resolve()
        col = (width - 6 * mm) / 2
        cells = []
        for sc in screens:
            p = (files_dir / sc["file"]).resolve()
            img = _shot(p, sc["sha256"]) if _SAFE_NAME.match(sc["file"]) and p.parent == files_dir else None
            cell = [P(_t(f"{sc['step']}단계 · {sc.get('title') or '제목 없음'}"), key), P(_t(sc.get("url")), small)]
            if img is None:
                cell.append(P("원본 해시가 체인 기록과 달라 넣지 않음", small))
            else:
                with PILImage.open(img) as im:
                    w, h = im.size
                img.seek(0)
                cell.append(Image(img, width=col - 4, height=(col - 4) * h / w))
            cell.append(P(_t(f"files/{sc['file']} · sha256 {sc['sha256'][:16]}…"), small))
            cells.append(cell)
        if len(cells) % 2:
            cells.append([])
        grid = Table([cells[i:i + 2] for i in range(0, len(cells), 2)], colWidths=[col + 3 * mm] * 2)
        grid.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        out.append(KeepTogether([*head, grid]))  # 제목만 앞 쪽 끝에 남지 않게

    rel = rep.get("related")
    if rel and rel["investigated"]:
        out.append(P(f"{5 if screens else 4}. 연관 사이트 (자동 하위 조사)", h2))
        out.append(P(_t(f"페이지에서 찾은 연관 후보 {rel['found']}개 중 {len(rel['investigated'])}개를 같은 안전 조건으로 조사했다."), small))
        data = [[P("주소", key), P("AI 의견", key), P("외부 평판", key)]]
        for r in rel["investigated"]:
            op = ("조사 실패" if r["error"] else
                  f"{r['threat_ko'] or '-'} ({_pct(r['probability'])})" + (" · 보류" if r["hold"] else ""))
            rep_ = "위험 일치" if r["reputation_match"] else "미확인" if r["reputation_unchecked"] else "일치 없음"
            data.append([P(_t(r["url"]) + (f"<br/>→ {_t(r['final_url'])}" if r.get("final_url") and r["final_url"] != r["url"] else ""), base),
                         P(_t(op), base), P(_t(rep_), base)])
        t = Table(data, colWidths=[width - 60 * mm, 32 * mm, 28 * mm], repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#999999")),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF1F5")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        out.append(t)

    n = 4 + bool(screens) + bool(rel and rel["investigated"])
    out.append(P(f"{n}. 증거 무결성", h2))
    i = rep["integrity"]
    out.append(kv([
        ("검증 결과", f"{'통과' if i['verified'] else '실패'} · 기록 {i['records']}건" + (f" · 오류 {i['errors']}건" if i["errors"] else "")),
        ("체인 끝(head)", f"{i['head_seq']}번 · {i['head_hash']}"),
        ("방식", f"{i['method']} · 키 {i['key_id']}"),
        ("원본 확인", "검토 패키지(ZIP)의 chain.jsonl·files·SHA256SUMS 로 다시 계산할 수 있다"),
    ]))

    def footer(cv, doc):
        cv.saveState()
        cv.setFont("KR", 7)
        cv.setFillColor(colors.HexColor("#666666"))
        cv.drawString(18 * mm, 10 * mm, f"SafeTrace 보고서{' 초안' if rep['draft'] else ''} · 사건 {cid[:8]} · "
                                        "AI 판단은 법적 판단이 아님")
        cv.drawRightString(A4[0] - 18 * mm, 10 * mm, f"{doc.page}쪽")
        cv.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=18 * mm, title=f"SafeTrace 보고서 {cid[:8]}", author="SafeTrace",
                            creator="SafeTrace", subject="위협 의심 사이트 조사 보고서")
    doc.build(out, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


"""위협 판단의 출처(AI 모델·코드 규칙): 코드 규칙이 정한 유형(확률 1.0)을 'AI' 로 부르거나 'AI 확률 100%' 로 적지 않는다.
콘솔(decisionDisplay.ts)·보고서 PDF·처리 요청서·연결된 사건 줄이 같은 기준을 쓴다(2026-10-28)."""

import re
import secrets
from pathlib import Path

from safetrace import package, referral, report
from safetrace.decision.schema import FALLBACK_PROVIDERS, MODEL_PROVIDERS, RULE_PROVIDERS, threat_source
from safetrace.evidence import EvidenceWriter, Signer, verify_case
from safetrace.store import Case, now

ROOT = Path(__file__).resolve().parents[2]


def test_threat_source():
    assert threat_source({"threat": "phishing", "provider": "jev_typesafe"}) == "model"
    assert threat_source({"threat": "phishing", "provider": "jev_openrouter"}) == "model"
    assert threat_source({"threat": "phishing", "provider": "jev_typesafe", "override": {"reason": "x"}}) == "rule"
    assert threat_source({"threat": "phishing", "provider": "link_takedown"}) == "rule"
    # Jev 가 둘 다 실패했을 때의 대체 판단기(낱말 점수)는 모델 확률도 코드 규칙도 아니다
    assert threat_source({"threat": "benign", "provider": "rules", "model": "rules-1"}) == "fallback"
    assert threat_source({"threat": "benign", "model": "rules-1"}) == "fallback"
    # 대체 판단 결과에 코드 규칙이 덧씌워지면 규칙이다(override 의 원래 판단 출처가 rules)
    assert threat_source({"threat": "phishing", "provider": "link_takedown", "model": "rules-1",
                          "override": {"reason": "link_takedown"}}) == "rule"
    # 출처를 모르면 AI 로 보지 않는다
    assert threat_source({"threat": "phishing"}) is None
    assert threat_source({"threat": "phishing", "provider": ["jev_typesafe"]}) is None
    assert threat_source({"provider": "jev_typesafe"}) is None
    assert threat_source(None) is None and threat_source("phishing") is None


def test_provider_lists_match_engine_and_console():
    """판단 엔진이 내는 provider 이름이 모두 분류돼 있고, 콘솔의 목록과 같다(한쪽만 바뀌면 같은 사건이 다르게 보인다)."""
    engine = (ROOT / "backend/safetrace/decision/engine.py").read_text(encoding="utf-8")
    named = set(re.findall(r'provider="([a-z_]+)"', engine)) | set(re.findall(r'reason = "([a-z_]+)"', engine))
    assert named - {"exhausted"} <= RULE_PROVIDERS  # exhausted 는 행동 판단(위협 판단 아님)
    assert {"brand_typo_domain", "brand_login_shared_hosting", "brand_clone_title"} <= named
    console = (ROOT / "frontend/src/decisionDisplay.ts").read_text(encoding="utf-8")
    block = console.split("const RULE_LABEL = dict({", 1)[1].split("});", 1)[0]
    assert set(re.findall(r"^\s*([a-z_]+):", block, re.M)) == RULE_PROVIDERS
    models = re.search(r"const modelProvider = .*?\[([^\]]*)\]", console).group(1)
    assert set(re.findall(r'"([a-z_]+)"', models)) == MODEL_PROVIDERS
    fallback = re.search(r"const FALLBACK_PROVIDERS = \[([^\]]*)\]", console).group(1)
    assert set(re.findall(r'"([a-z_]+)"', fallback)) == FALLBACK_PROVIDERS


def _chain(tmp_path, main_threat, subs=()):
    signer = Signer(secrets.token_bytes(32), "k1")
    cid = f"dddddddd-0000-0000-0000-{secrets.token_hex(6)}"
    w = EvidenceWriter(tmp_path / "ev", cid, signer)
    w.append("start", {"url": "https://reported.example/"})
    w.append("threat", {"probabilities": {main_threat["threat"]: main_threat["probability"]}, "evidence_seqs": [],
                        "model": "jev-1.13.0", **main_threat})
    if subs:
        w.append("candidates", {"found": [{"url": u, "host": u.split("/")[2], "source": "link"} for u, _ in subs],
                                "followup": True, "investigated": len(subs)})
        for n, (u, t) in enumerate(subs, 1):
            w.append("start", {"url": u, "sub": n})
            w.append("threat", {"probabilities": {t["threat"]: t["probability"]}, "evidence_seqs": [],
                                "model": "jev-1.13.0", "sub": n, **t})
        w.append("candidate_results", {"results": [{"sub": n, "url": u, "threat": t["threat"],
                                                    "probability": t["probability"], "hold": t["hold"]}
                                                   for n, (u, t) in enumerate(subs, 1)]})
    case = Case(id=cid, url="https://reported.example/", source="test", status="REVIEW_REQUIRED", created_by="t",
                created_at=now())
    records = package.read_chain(tmp_path / "ev", cid)
    pkg = package.build(case, records, verify_case(tmp_path / "ev", cid, signer, None), [], [],
                        generated_by="t", key_id="k1")
    return report.build(pkg, records), tmp_path / "ev"


RULE = {"threat": "phishing", "probability": 1.0, "hold": True, "provider": "link_takedown",
        "override": {"reason": "link_takedown",
                     "original": {"threat": "unknown", "probability": 0.5, "provider": "jev_typesafe"}}}
MODEL = {"threat": "phishing", "probability": 0.62, "hold": False, "provider": "jev_typesafe"}


def test_report_does_not_write_rule_type_as_ai_probability(tmp_path):
    """예전 PDF: '판단 결과 · AI 의심 유형 피싱 (확률 100%) · 보류(담당자 검토)'. 콘솔은 PR #111 부터 규칙 판단을 숫자 없이 보인다."""
    rep, ev = _chain(tmp_path, RULE, subs=[("https://kit.example/", {**RULE, "provider": "brand_name_domain",
                                                                      "override": {"reason": "brand_name_domain"}}),
                                            ("https://other.example/", MODEL)])
    ai = rep["assessment"]["ai"]
    assert ai["source"] == "rule"
    line = report.assessment_line(ai)
    assert line == "피싱 · 코드 규칙 판단 · 담당자 검토" and "100%" not in line and "AI" not in line
    assert ai["override"].endswith("모델은 원래 판단 불가")  # 모델의 원래 의견은 '코드 규칙' 줄에 남는다(판단 불가는 숫자 없이)
    rows = rep["related"]["investigated"]
    assert [r["source"] for r in rows] == ["rule", "model"]
    assert [report.related_opinion(r) for r in rows] == ["피싱 · 코드 규칙 판단 · 담당자 검토", "피싱 (AI 확률 62%)"]
    assert report.render_pdf(rep, ev).startswith(b"%PDF")


def test_report_model_and_unknown_lines(tmp_path):
    rep, _ = _chain(tmp_path, {**MODEL, "probability": 0.87})
    assert report.assessment_line(rep["assessment"]["ai"]) == "피싱 (AI 확률 87%)"
    rep, _ = _chain(tmp_path, {"threat": "unknown", "probability": 0.4, "hold": True, "provider": "jev_typesafe"})
    assert report.assessment_line(rep["assessment"]["ai"]) == "판단 불가 · 담당자 검토"  # 판단 불가의 확률은 안 적는다
    rep, _ = _chain(tmp_path, {**MODEL, "provider": "someone_else"})
    assert report.assessment_line(rep["assessment"]["ai"]) == "피싱"  # 출처를 모르면 AI 확률로 적지 않는다
    assert report.assessment_line(None) == "판단 없음" and report.assessment_line(None, True).startswith("판단 서비스 장애")


def test_related_row_source_needs_matching_sub_record(tmp_path):
    """하위 조사 결과와 그 판단 기록이 어긋나면(다른 확률) 출처를 붙이지 않는다(콘솔 candidatePresentation 과 같은 기준)."""
    rep, _ = _chain(tmp_path, MODEL, subs=[("https://other.example/", MODEL)])
    row = rep["related"]["investigated"][0]
    assert row["source"] == "model"
    assert report.related_opinion({**row, "probability": 0.9, "source": None}) == "피싱"


def test_referral_does_not_write_fallback_rule_score_as_ai(tmp_path):
    """Jev 장애 때 대체 판단기(rules)는 override 없이 낱말 점수(예: 0.75)를 남긴다. 요청서에 'AI 판단 75%' 로 적지 않는다."""
    rep, _ = _chain(tmp_path, {"threat": "phishing", "probability": 0.75, "hold": False, "provider": "rules",
                               "model": "rules-1"})
    r = referral.build(rep)
    assert r["applicable"] and "대체 판단(Jev 장애) · 담당자 판정 전" in r["text"] and "75%" not in r["text"]
    rep, _ = _chain(tmp_path, {**MODEL, "probability": 0.87})
    assert "AI 판단 87%" in referral.build(rep)["text"]


def test_report_hold_is_not_written_as_reviewer_hold(tmp_path):
    """'보류'는 담당자 판정에만 쓴다(콘솔 holdLabel 과 같은 기준): AI 가 넘긴 판단은 '확신 낮음', 규칙·판단 불가는 '담당자 검토'."""
    rep, _ = _chain(tmp_path, {**MODEL, "probability": 0.51, "hold": True},
                    subs=[("https://other.example/", {**MODEL, "probability": 0.55, "hold": True})])
    assert report.assessment_line(rep["assessment"]["ai"]) == "피싱 (AI 확률 51%) · 확신 낮음(담당자 검토)"
    assert report.related_opinion(rep["related"]["investigated"][0]) == "피싱 (AI 확률 55%) · 확신 낮음"
    rep, _ = _chain(tmp_path, {**MODEL, "threat": "benign", "probability": 0.48, "hold": True})
    assert report.assessment_line(rep["assessment"]["ai"]) == "정상 (AI 확률 48%) · 확신 낮음(담당자 검토)"
    assert report.hold_ko({"hold": True, "source": None, "threat": "phishing"}) == "담당자 검토"
    assert report.hold_ko({"hold": False, "source": "model"}) is None


def test_report_fallback_decision_is_not_ai_or_code_rule(tmp_path):
    """Jev 장애 때의 대체 판단기는 'AI 확률'도 '코드 규칙'도 아니다(콘솔 '대체 판단'과 같은 기준)."""
    rep, ev = _chain(tmp_path, {"threat": "benign", "probability": 0.75, "hold": False, "provider": "rules", "model": "rules-1"})
    ai = rep["assessment"]["ai"]
    assert ai["source"] == "fallback"
    assert report.assessment_line(ai) == "정상 · 대체 판단(Jev 장애)"
    assert report.basis_ko("fallback") == "대체 판단(Jev 장애)" and report.basis_ko("rule") == "코드 규칙 판단"
    assert report.basis_ko("model") == "AI 판단" and report.basis_ko(None) == "조사 판단"
    assert report.render_pdf(rep, ev).startswith(b"%PDF")
    # 대체 판단 위에 코드 규칙이 덧씌워지면, 원래 판단은 모델 확률로 적지 않는다
    o = {"reason": "link_takedown", "original": {"threat": "benign", "probability": 0.75, "provider": "rules"}}
    assert report._override_ko(o) == "단축·호스팅 서비스의 링크 정지 안내 → 담당자 검토 · 규칙 적용 전 대체 판단 정상"
    o["original"]["provider"] = "legacy_unknown"
    assert report._override_ko(o) == "단축·호스팅 서비스의 링크 정지 안내 → 담당자 검토"


def test_report_reputation_line_shows_type_and_candidate(tmp_path):
    """예전 PDF 는 일치 항목의 유형 칸을 threatType 으로 읽어(증거는 threat_type) 늘 비었고, 연관 후보 주소의 일치도
    신고 주소의 일치처럼 보였다."""
    signer = Signer(secrets.token_bytes(32), "k1")
    cid = f"dddddddd-0000-0000-0001-{secrets.token_hex(6)}"
    w = EvidenceWriter(tmp_path / "ev", cid, signer)
    w.append("start", {"url": "https://reported.example/"})
    w.append("threat", {"threat": "benign", "probability": 0.5, "probabilities": {"benign": 0.5}, "hold": True,
                        "provider": "jev_typesafe", "model": "jev", "evidence_seqs": []})
    w.append("safebrowsing", {"status": "match", "matches": [
        {"url": "https://reported.example/", "threat_type": "SOCIAL_ENGINEERING"},
        {"url": "https://cand.example/", "threat_type": "MALWARE"}]})
    w.append("candidates", {"found": [{"url": "https://cand.example/", "host": "cand.example", "source": "link"}],
                            "followup": False, "investigated": 0})
    case = Case(id=cid, url="https://reported.example/", source="test", status="REVIEW_REQUIRED", created_by="t",
                created_at=now())
    records = package.read_chain(tmp_path / "ev", cid)
    pkg = package.build(case, records, verify_case(tmp_path / "ev", cid, signer, None), [], [], generated_by="t", key_id="k1")
    sb = report.build(pkg, records)["assessment"]["safebrowsing"]
    assert [(m["type"], m["candidate"]) for m in sb["matches"]] == [("SOCIAL_ENGINEERING", False), ("MALWARE", True)]
    assert report.reputation_line(sb) == ("Google Safe Browsing: 위험 목록 일치 · SOCIAL_ENGINEERING https://reported.example/"
                                          " · MALWARE https://cand.example/ (연관 후보)")
    assert report.reputation_line(None) == "조회 기록 없음"


def test_threat_type_names_match_console_report_and_ioc():
    """유형 이름이 콘솔('악성 앱'·'불법 도박')과 보고서('악성코드'·'불법 도박 의심')에서 달랐다(2026-10-28). 한 표로 맞춘다.
    '의심'은 이름에 넣지 않는다 — 콘솔은 확신이 낮으면 ' 의심'을 붙이고, PDF 칸 이름이 '의심 유형'이며, 확정 판정 줄은
    '위협 확정 — 불법 도박 의심'처럼 엇갈렸다."""
    from safetrace import ioc
    from safetrace.decision.schema import THREAT_LABELS_KO

    console = (ROOT / "frontend/src/labels.ts").read_text(encoding="utf-8")
    block = console.split("export const THREAT_LABEL", 1)[1].split("});", 1)[0]
    labels = dict(re.findall(r'^\s*([a-z_]+):\s*"([^"]+)"', block, re.M))
    server = {t.value: name for t, name in THREAT_LABELS_KO.items()}
    assert labels == server == report.THREAT_KO
    assert all(server[k] == v for k, v in ioc.THREAT_KO.items())
    assert not any("의심" in v for v in server.values())
    assert server["malware"] == "악성코드" and server["illegal_gambling"] == "불법 도박"

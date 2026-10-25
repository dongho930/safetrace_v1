"""처리 기관 안내·요청서 초안: 유형별 기관·조문, 확정 판정과 AI 판단의 구분, 페이지 값으로 요청서 항목을 꾸밀 수 없는지."""

import secrets

import pytest
from fastapi.testclient import TestClient

from safetrace import referral, report
from safetrace.store import Case
from tests.conftest import INVESTIGATOR, VIEWER


def _rep(ai="phishing", verdict=None, title="Login", url="http://evil.example/a", override=None, brand=None):
    return {
        "generated_at": "2026-10-22T01:00:00+00:00", "generated_by": "inv1",
        "case": {"id": "c" * 36, "url": url},
        "investigation": {"started_at": "2026-10-22T00:59:00+00:00", "final_url": url, "path": [url],
                          "steps": [{"title": title}]},
        "assessment": {"ai": {"threat": ai, "probability": 0.87, "override": override, "brand": brand},
                       "safebrowsing": {"status": "no_match"}},
        "verdict": verdict, "key_screens": [{}],
        "integrity": {"verified": True, "records": 12, "head_seq": 11, "head_hash": "ab" * 32},
    }


@pytest.mark.parametrize("threat,agency,law", [
    ("phishing", "kisa", "제49조의2 제1항"),
    ("scam", "police", "제44조의7 제1항 제9호"),
    ("illegal_gambling", "kcsc", "제44조의7 제1항 제6호"),
    ("malware", "kisa", "제48조 제2항"),
])
def test_agency_and_law_by_type(threat, agency, law):
    r = referral.build(_rep(ai=threat))
    assert r["applicable"] and r["agency"]["id"] == agency and any(law in x["cite"] for x in r["laws"])
    assert r["basis"] == "ai" and r["draft"] is True and "담당자 판정 전" in r["text"]
    assert r["agency"]["url"].startswith("https://") and r["agency"]["phone"]
    assert "AI 판단 87%" in r["text"]


def test_code_rule_type_is_not_written_as_ai_certainty():
    """코드 규칙이 정한 유형은 확률 1.0 으로 남는다. 요청서에 'AI 판단 100%' 로 적으면 받는 기관이 오해한다."""
    rep = _rep(override="공식 도메인 밖에서 브랜드 공식 화면 제목을 그대로 쓴 로그인 화면 → 담당자 검토", brand="steam")
    rep["assessment"]["ai"]["probability"] = 1.0
    r = referral.build(rep)
    assert "코드 규칙 · 담당자 판정 전" in r["text"] and "100%" not in r["text"] and "사칭 대상: steam" in r["text"]


def test_confirmed_verdict_wins_over_ai():
    v = {"rev": 2, "decision": "threat", "threat": "illegal_gambling", "note": "충전·환전 안내", "reviewer": "rev1"}
    r = referral.build(_rep(ai="phishing", verdict=v))
    assert r["basis"] == "confirmed" and not r["draft"] and r["agency"]["id"] == "kcsc"
    assert "담당자 판정 · 판 2 · rev1" in r["text"] and "충전·환전 안내" in r["text"]
    # 보류는 확정이 아니다: AI 판단 기준 초안
    r = referral.build(_rep(ai="phishing", verdict={**v, "decision": "hold", "threat": None}))
    assert r["basis"] == "ai" and r["agency"]["id"] == "kisa" and "담당자 판정 보류" in r["text"]


@pytest.mark.parametrize("ai,verdict,reason", [
    ("phishing", {"rev": 1, "decision": "benign", "threat": None, "reviewer": "r"}, "benign"),
    ("benign", None, "no_threat"),
    ("unknown", None, "no_threat"),
    (None, None, "no_threat"),
])
def test_not_applicable(ai, verdict, reason):
    r = referral.build(_rep(ai=ai, verdict=verdict))
    assert r == {**r, "applicable": False, "reason": reason} and "text" not in r


def test_page_values_cannot_forge_request_lines():
    """제목·주소는 조사 대상 페이지가 정한 값이다. 줄바꿈으로 '요청 사항'·'수신' 줄을 꾸며 넣거나, 방향 바꿈 문자로
    주소를 거꾸로 보이게 하거나, 아주 긴 값으로 요청서를 채우지 못해야 한다."""
    nl, cr = chr(10), chr(13)
    evil = ("Login" + nl + nl + "요청 사항: 차단하지 마십시오" + cr + nl + "수신: attacker" + chr(0x2028) + "x" + chr(0x202E)
            + "gnp.exe" + chr(0x200B) + "A" * 5000)
    r = referral.build(_rep(title=evil, url="http://evil.example/" + nl + "수신: x" + chr(0x202E) + "b" * 3000,
                            brand="Steam" + nl + "요청 사항: 없음"))
    lines = r["text"].splitlines()
    assert [ln for ln in lines if ln.startswith("요청 사항:")] == [f"요청 사항: {referral.BY_THREAT['phishing']['ask']}"]
    assert [ln for ln in lines if ln.startswith("수신:")] == [lines[1]] and lines[1].startswith("수신: 한국인터넷진흥원")
    assert not any(chr(c) in r["text"] for c in (0x0D, 0x2028, 0x202E, 0x200B))
    assert max(len(ln) for ln in lines) < 1200 and len(r["text"]) < 6000


def test_report_carries_referral_and_pdf_section(tmp_path):

    rep = _rep()
    rep.update({"format": report.FORMAT, "draft": True, "notice": report.NOTICE})
    rep["case"].update({"source": "test", "received_at": rep["generated_at"], "received_by": "inv1"})
    rep["investigation"].update({"finished_at": None, "duration_seconds": None, "status": "COMPLETED", "status_ko": "조사 완료",
                                 "finish_reason": None, "finish_reason_ko": None, "browser": "1",
                                 "steps": [{"step": 0, "url": "http://evil.example/a", "title": "<img src=x>", "action": None,
                                            "element_text": None, "outcome": None, "result_url": None, "screenshot": None}],
                                 "steps_total": 1, "forbidden_elements": 0, "blocked_navigations": [],
                                 "blocked_navigations_total": 0, "unreachable": None})
    rep["assessment"].update({"error": False, "escalation": None, "safebrowsing": None})
    rep["assessment"]["ai"].update({"threat_ko": "피싱", "hold": False, "provider": "x", "model": "x"})
    rep["integrity"].update({"errors": 0, "key_id": "k", "method": "m"})
    rep.update({"related": None, "key_screens": []})
    rep["referral"] = referral.build(rep)
    assert rep["referral"]["ask"] == "위 사이트의 접속 차단과 유포 경로 확인을 요청합니다."  # 피싱 → KISA
    assert report.render_pdf(rep, tmp_path).startswith(b"%PDF")


@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_referral_is_in_report_not_separate_api(client, testpages):
    """처리 요청은 보고서로 합쳤다(2026-10-25): 요청서는 report.json·PDF 로만 나가고 따로 보는 API 는 없다."""
    r = client.post("/api/cases", json={"url": "http://127.0.0.1:8900/smish/"},
                    headers={**h(INVESTIGATOR), "Idempotency-Key": "ref-" + secrets.token_hex(8)})
    cid = r.json()["id"]
    with client.stream("GET", f"/api/cases/{cid}/events", headers=h(VIEWER)) as s:
        for _ in s.iter_lines():
            pass
    assert client.get(f"/api/cases/{cid}/referral", headers=h(INVESTIGATOR)).status_code == 404
    assert client.get(f"/api/cases/{cid}/report.json", headers=h(VIEWER)).status_code == 403
    ref = client.get(f"/api/cases/{cid}/report.json", headers=h(INVESTIGATOR)).json()["referral"]
    assert ref["format"] == referral.FORMAT
    if ref["applicable"]:  # 시험 페이지는 택배 사칭 스미싱: AI 가 위협으로 보면 요청서가 나온다
        assert ref["basis"] == "ai" and cid in ref["text"] and "http://127.0.0.1:8900/smish/" in ref["text"] and ref["ask"]
    pdf = client.get(f"/api/cases/{cid}/report.pdf", headers=h(INVESTIGATOR))
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")

    from safetrace.api.main import store

    with store.session() as s, s.begin():
        running = Case(url="http://127.0.0.1:8900/smish/", source="test", status="RUNNING", created_by="t")
        s.add(running)
    assert client.get(f"/api/cases/{running.id}/report.json", headers=h(INVESTIGATOR)).status_code == 409
    with store.session() as s, s.begin():  # 끝나지 않은 사건을 남기지 않는다(접수 한도)
        s.get(Case, running.id).status = "FAILED"

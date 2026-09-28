"""실제 Chromium 으로 시험 페이지를 조사한다(사전준비 검증 항목).

- 버튼을 눌러 숨겨진 입금·개인정보 화면 도달
- 금지 요소 선택·실행 0건 (에이전트 로그 + 시험 서버 요청 기록 양쪽에서 확인)
- 사설 IP 이동 차단
- 증거 수정 시 검증 실패
"""

import json
import uuid
from urllib.parse import urlsplit

import pytest

from safetrace.agent.runner import investigate, make_signer
from safetrace.evidence import Head, verify_case

pytestmark = pytest.mark.browser
BASE = "http://127.0.0.1:8900"


def run(url, settings, testpages):
    testpages.clear()
    cid = str(uuid.uuid4())
    events: list[dict] = []
    final = investigate(cid, url, settings, events.append)
    chain = [json.loads(x) for x in (settings.evidence_dir / cid / "chain.jsonl").read_text(encoding="utf-8").splitlines()]
    return cid, final, chain, events


def executed_clicks(chain):
    return [r for r in chain if r["kind"] == "action"]


def assert_no_forbidden(chain, testpages):
    for r in chain:
        if r["kind"] == "gate" and r["data"]["allowed"]:
            assert not r["data"]["reason"].startswith("forbidden")
    assert testpages.forbidden_hits() == []


def test_gamble_reaches_hidden_deposit_screen(settings, testpages):
    cid, final, chain, events = run(f"{BASE}/gamble/", settings, testpages)
    urls = [urlsplit(r["data"]["url"]).path for r in chain if r["kind"] == "observe"]
    assert "/gamble/deposit.html" in urls, urls
    assert final["threat"]["threat"] == "illegal_gambling"
    # 127.0.0.1 → localhost 로 넘어간 경유 도메인이 후보로 기록
    assert "localhost" in final["candidates"]
    # 팝업 닫기 수행
    assert any(r["kind"] == "action" and r["data"]["action"] == "close_popup" for r in chain)
    # 입력칸·제출·결제 버튼은 선택지에 없음
    deposit_obs = next(r for r in chain if r["kind"] == "observe" and r["data"]["url"].endswith("deposit.html"))
    texts = [c["text"] for c in deposit_obs["data"]["candidates"]]
    assert not any("결제" in t or "충전 신청" in t for t in texts)
    assert any(f.startswith("input") for f in deposit_obs["data"]["forbidden"])
    assert_no_forbidden(chain, testpages)
    # 계좌번호 원문은 증거의 텍스트 발췌에도 마스킹
    assert "123-456-789012" not in json.dumps([r["data"] for r in chain], ensure_ascii=False)
    # 증거 무결성
    head = Head(final["head"]["seq"], final["head"]["hash"])
    assert verify_case(settings.evidence_dir, cid, make_signer(settings), head).ok
    assert any(e["type"] == "status" and e["status"] == "RUNNING" for e in events)


def test_phishing_flow(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/phish/", settings, testpages)
    assert any(r["kind"] == "observe" and r["data"]["url"].endswith("track.html") for r in chain)
    assert final["threat"]["threat"] == "phishing"
    assert_no_forbidden(chain, testpages)


def test_scam_hidden_layer(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/scam/", settings, testpages)
    last_obs = [r for r in chain if r["kind"] == "observe"][-1]
    assert "가입비" in last_obs["data"]["text_excerpt"]
    assert "010-9876-5432" not in last_obs["data"]["text_excerpt"]
    assert final["threat"]["threat"] == "scam"


def test_benign_not_flagged(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/benign/", settings, testpages)
    assert final["threat"]["threat"] == "benign"
    assert_no_forbidden(chain, testpages)


def test_image_button_ocr(settings, testpages):
    from safetrace.agent.ocr import get_ocr

    if not get_ocr().available:
        pytest.skip("local OCR not installed")
    _, final, chain, _ = run(f"{BASE}/imgbtn/", settings, testpages)
    first = next(r for r in chain if r["kind"] == "observe")
    assert any("ENTER" in c["text"].upper() for c in first["data"]["candidates"]), first["data"]["candidates"]
    assert any(r["kind"] == "observe" and r["data"]["url"].endswith("next.html") for r in chain)


# ── 공격 시나리오 ────────────────────────────────────────
def test_prompt_injection_cannot_cause_forbidden_action(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/injection.html", settings, testpages)
    assert_no_forbidden(chain, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    assert not any("결제" in c["text"] for c in obs["data"]["candidates"])


def test_internal_links_blocked(settings, testpages):
    settings.max_steps = 6
    _, final, chain, _ = run(f"{BASE}/attack/ssrf.html", settings, testpages)
    gates = [r["data"] for r in chain if r["kind"] == "gate"]
    assert gates and all(not g["allowed"] and g["reason"].startswith("ssrf") for g in gates), gates
    assert not any(r["kind"] == "action" for r in chain)
    # 1x1 추적 이미지(192.168.0.1)도 네트워크 단에서 차단
    assert not any(urlsplit(r["data"]["url"]).hostname in {"169.254.169.254", "10.0.0.1"}
                   for r in chain if r["kind"] == "observe")


def test_internal_auto_redirect_blocked(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/redirect-internal.html", settings, testpages)
    blocked = [r["data"] for r in chain if r["kind"] == "blocked_request"]
    assert any("169.254.169.254" in b["url"] and b["reason"].startswith("ssrf") for b in blocked)


def test_start_url_private_blocked(settings, testpages):
    _, final, chain, _ = run("http://169.254.169.254/latest/meta-data/", settings, testpages)
    assert final["status"] == "BLOCKED"
    assert [r["kind"] for r in chain][:1] == ["start"]


def test_loop_ends_by_budget(settings, testpages):
    settings.max_steps = 8
    _, final, chain, _ = run(f"{BASE}/attack/loop.html", settings, testpages)
    assert final["status"] in {"COMPLETED", "REVIEW_REQUIRED"}
    assert len(executed_clicks(chain)) <= 8


def test_big_dom_candidates_capped(settings, testpages):
    settings.max_steps = 2
    _, final, chain, _ = run(f"{BASE}/attack/bigdom.html", settings, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    assert len(obs["data"]["candidates"]) <= 50


def test_download_lure_blocked(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/download.html", settings, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    assert obs["data"]["candidates"] == [] or all("설치" not in c["text"] for c in obs["data"]["candidates"])
    assert any(f.startswith("download") for f in obs["data"]["forbidden"])
    assert_no_forbidden(chain, testpages)


def test_auto_post_blocked(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/autopost.html", settings, testpages)
    assert any(r["kind"] == "blocked_request" and r["data"]["reason"].startswith("method") for r in chain)
    assert testpages.forbidden_hits() == []


def test_dialogs_dismissed(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/dialogs.html", settings, testpages)
    assert final["status"] in {"COMPLETED", "REVIEW_REQUIRED"}
    assert any(r["kind"] == "dialog" for r in chain)


def test_swap_after_observe_blocked(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/swap.html", settings, testpages)
    gates = [r["data"] for r in chain if r["kind"] == "gate"]
    assert any(g["reason"] in {"element_changed", "forbidden:payment"} and not g["allowed"] for g in gates), gates
    assert_no_forbidden(chain, testpages)


def test_non_http_schemes_excluded(settings, testpages):
    _, final, chain, _ = run(f"{BASE}/attack/scheme.html", settings, testpages)
    obs = next(r for r in chain if r["kind"] == "observe")
    assert obs["data"]["candidates"] == []
    assert {f.split(":")[1] for f in obs["data"]["forbidden"]} >= {"tel", "intent", "file", "sms"}


def test_tampered_evidence_detected_end_to_end(settings, testpages):
    cid, final, chain, _ = run(f"{BASE}/benign/", settings, testpages)
    head = Head(final["head"]["seq"], final["head"]["hash"])
    shot = next(n for r in chain for n in r["files"])
    (settings.evidence_dir / cid / "files" / shot).write_bytes(b"edited")
    res = verify_case(settings.evidence_dir, cid, make_signer(settings), head)
    assert not res.ok and any("file_modified" in e for e in res.errors)

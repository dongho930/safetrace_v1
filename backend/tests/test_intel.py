"""운영 정보·키트 지문 추출: 운영자가 쓰는 모양만 뽑고, 진짜 회사 대표번호·화면 아무 데의 번호·영문 낱말은 뽑지 않는다."""

import pytest

from safetrace.agent import intel


@pytest.mark.parametrize("href,kind,value", [
    ("https://t.me/CasinoKing_77", "telegram", "casinoking_77"),
    ("https://telegram.me/support_bet?start=1", "telegram", "support_bet"),
    ("https://t.me/+AbCdEfGhIjKl", "telegram", "+AbCdEfGhIjKl"),
    ("https://t.me/joinchat/AAAAAEm1234567", "telegram", "joinchat/AAAAAEm1234567"),
    ("tg://resolve?domain=VipAgent01", "telegram", "vipagent01"),
    ("https://open.kakao.com/o/sAbC123", "kakao", "o/sAbC123"),
    ("https://pf.kakao.com/_xYzAb", "kakao", "_xYzAb"),
    ("https://line.me/ti/p/~agent88", "line", "~agent88"),
    ("https://wa.me/821012345678", "whatsapp", "821012345678"),
    ("https://api.whatsapp.com/send?phone=6281234567890&text=hi", "whatsapp", "6281234567890"),
    ("https://discord.gg/abcDEF12", "discord", "abcDEF12"),
    ("tel:010-1234-5678", "phone", "01012345678"),
    ("tel:+82-10-1234-5678", "phone", "01012345678"),
    ("sms:07012345678?body=x", "phone", "07012345678"),
])
def test_contact_links(href, kind, value):
    assert intel.from_link(href) == {"kind": kind, "value": value, "src": "link"}


@pytest.mark.parametrize("href", [
    "https://t.me/share/url?url=x",          # 공유 버튼(운영자 아님)
    "https://t.me/s",                         # 예약 경로
    "tel:1588-1234",                          # 대표번호(피싱 키트가 진짜 회사 번호를 베낀다)
    "tel:02-123-4567",                        # 유선
    "https://example.com/t.me/abcde",         # 다른 사이트 경로 속 글자
    "https://t.me.evil.example/abcde",        # 비슷한 호스트
    "javascript:alert(1)",
])
def test_not_contact_links(href):
    assert intel.from_link(href) is None


def test_text_cues_only():
    snips = ["실시간 상담 텔레그램 @VIP_Agent77 24시간", "카톡 ID: bet365kr 문의", "고객센터 문의 010-9876-5432",
             "입금 계좌 국민은행 123456-01-234567 예금주 홍길동", "신한 110-123-456789",
             "고객센터 1588-1234", "주문번호 010-1111-2222 는 무시되지 않는다?",
             "텔레그램 telegram 공식 채널", "전화 02-123-4567", "부산 051-123-4567 지점", "우리은행 1002-123-456789",
             "우리 1002-123-456789"]
    got = {(x["kind"], x["value"]) for x in intel.from_text(snips)}
    assert ("telegram", "vip_agent77") in got and ("kakao", "id:bet365kr") in got
    assert ("phone", "01098765432") in got
    assert ("account", "국민:12345601234567") in got and ("account", "신한:110123456789") in got
    assert not any(k == "phone" and v in ("15881234", "021234567") for k, v in got)
    assert ("phone", "01011112222") not in got  # 문의·연락 같은 말이 앞에 없는 번호
    assert ("telegram", "telegram") not in got
    accounts = {v for k, v in got if k == "account"}
    assert accounts == {"국민:12345601234567", "신한:110123456789", "우리:1002123456789"}  # 지명 뒤 유선 번호·'우리' 단독은 아님


def test_forms_only_other_hosts():
    forms = [{"action": "https://collect.evil.example/p.php", "method": "post"},
             {"action": "https://site.example/login", "method": "post"},
             {"action": "javascript:void(0)"}, {"action": 5}, "x"]
    assert intel.from_forms(forms, "https://site.example/") == [
        {"kind": "form", "value": "https://collect.evil.example/p.php", "src": "form"}]


def test_extract_dedup_and_cap():
    links = [f"https://t.me/agent_{i:03d}" for i in range(40)] + ["https://t.me/agent_000"]
    out = intel.extract(links, ["텔레그램 @agent_000"], [], "https://x.example/")
    assert len(out) == intel.MAX_ITEMS and len({(x["kind"], x["value"]) for x in out}) == len(out)
    assert intel.extract("x", 5, None, "") == []  # 모양이 틀린 값(페이지가 정한 값)


def test_kit_fingerprint():
    dom = ",".join(f"div{i % 7}" for i in range(200))
    a = intel.kit_fingerprint({"dom": dom, "n": 200, "res": ["/assets/index-4f8aB2c9.js", "/assets/index-Xy12ab34.css",
                                                             "/favicon.ico", "/js/jquery.min.js"]})
    b = intel.kit_fingerprint({"dom": dom, "n": 200, "res": ["/assets/index-Xy12ab34.css", "/assets/index-4f8aB2c9.js"]})
    assert a["dom"] == b["dom"] and a["res"] == b["res"] and a["r"] == 2  # 해시 붙은 빌드 산출물만, 순서 무관
    assert intel.kit_fingerprint({"dom": "body0,div1", "n": 2, "res": []}) is None  # 오류·주차 화면처럼 요소가 적음
    c = intel.kit_fingerprint({"dom": dom, "n": 200, "res": ["/wp-includes/js/jquery/jquery.min.js"]})
    assert "res" not in c  # 흔한 CMS 파일은 산출물 지문을 만들지 않는다
    for bad in (None, {"dom": 1, "n": 100}, {"dom": "x", "n": "100"}, {"dom": "x", "n": True}):
        assert intel.kit_fingerprint(bad) is None


def test_mask():
    assert intel.mask("phone", "01012345678") == "010-****-5678"
    assert intel.mask("account", "국민:12345601234567") == "국민 ****4567"
    assert intel.mask("telegram", "vip_agent77") == "vip_agent77"


# ── 사건 잇기(related.intel_rows) ─────────────────────────
def _intel_rec(items, url="https://kit.example.net/a", kit=None, sub=None):
    d = {"step": 0, "obs": 1, "url": url, "items": items, **({"kit": kit} if kit else {}), **({"sub": sub} if sub else {})}
    return {"seq": 2, "kind": "intel", "data": d}


def test_intel_rows_keys_and_conditions():
    from safetrace import related

    kit = {"dom": "a" * 32, "res": "b" * 32, "n": 120}
    items = [{"kind": "telegram", "value": "vip_agent", "src": "link"}, {"kind": "phone", "value": "01012345678", "src": "text"},
             {"kind": "account", "value": "국민:12345601234567", "src": "text"},
             {"kind": "form", "value": "https://collect.example.net/p.php", "src": "form"},
             {"kind": "form", "value": "https://script.google.com/macros/s/x/exec?u=1", "src": "form"},
             {"kind": "form", "value": "http://10.0.0.5/p.php", "src": "form"},  # 내부 주소는 잇지 않음
             {"kind": "nope", "value": "x"}, "x"]
    rows = related.intel_rows([_intel_rec(items, kit=kit), _intel_rec(items[:1], sub=1)], "phishing")
    by = {r["site"]: r for r in rows}
    assert "telegram:vip_agent" in by and by["telegram:vip_agent"]["role"] == "contact"
    phone = next(r for r in rows if r["site"].startswith("phone:"))
    assert "01012345678" not in phone["site"] and phone["host"] == "010-****-5678"  # 열쇠는 해시, 보이는 값은 가림
    assert any(r["site"].startswith("account:") and r["host"] == "국민 ****4567" for r in rows)
    # 보내는 곳은 주소 전체(쿼리 빼고)가 같을 때만: 공용 서비스(script.google.com)로 남남끼리 묶이지 않게
    assert {"form:collect.example.net/p.php", "form:script.google.com/macros/s/x/exec"} <= set(by)
    assert not any("10.0.0.5" in r["site"] for r in rows)
    assert {"kit:dom:" + "a" * 32, "kit:res:" + "b" * 32} <= set(by) and by["kit:dom:" + "a" * 32]["host"] == "kit.example.net"
    assert len(rows) == 7
    # 정상으로 본 사건은 잇지 않고, 판단 불가면 키트 지문은 쓰지 않는다(오류·주차 화면 틀)
    assert related.intel_rows([_intel_rec(items, kit=kit)], "benign") == []
    assert not any(r["role"] == "kit" for r in related.intel_rows([_intel_rec(items, kit=kit)], "unknown"))
    # 공식·단축 서비스·내부 주소 화면의 지문은 운영자를 가리키지 않는다
    for url in ("https://www.facebook.com/", "https://bit.ly/x", "http://127.0.0.1:8900/a"):
        assert not any(r["role"] == "kit" for r in related.intel_rows([_intel_rec([], url=url, kit=kit)], "phishing"))
    assert related.intel_rows([_intel_rec([], kit={"dom": "x" * 32})], "phishing") == []  # 해시 모양이 아님
    from safetrace.store import INTEL_ROLES
    assert INTEL_ROLES == related.INTEL_ROLES


# ── 실제 브라우저 조사 → 서명 체인 → API ─────────────────────────
import json  # noqa: E402
import secrets  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from tests.conftest import INVESTIGATOR, VIEWER  # noqa: E402


@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


def _investigate(client, url):
    cid = client.post("/api/cases", json={"url": url},
                      headers={**_h(INVESTIGATOR), "Idempotency-Key": "intel-" + secrets.token_hex(8)}).json()["id"]
    with client.stream("GET", f"/api/cases/{cid}/events", headers=_h(VIEWER)) as s:
        lines = [ln for ln in s.iter_lines() if ln.startswith("data: ")]
    return cid, [json.loads(ln[6:]) for ln in lines]


@pytest.fixture(scope="module")
def two_cases(client, testpages):
    return [_investigate(client, "http://127.0.0.1:8900/gamble/contact.html") for _ in range(2)]


def test_observation_records_operator_info(client, two_cases):
    (cid, viewer_events), (cid2, _) = two_cases
    intel_events = [e for e in viewer_events if e.get("kind") == "intel"]
    assert intel_events, "운영 정보 기록이 없다"
    got = {(x["kind"], x["value"]) for e in intel_events for x in e["data"]["items"]}
    # 열람자 이벤트: 공개 채널 아이디는 그대로, 전화·계좌는 끝 4자리만
    assert {("telegram", "st_test_agent"), ("telegram", "st_test_vip"), ("kakao", "o/sTestOnly1"), ("kakao", "id:sttest77"),
            ("form", "https://collect.example.net/p.php"), ("phone", "010-****-5678"), ("phone", "010-****-1234"),
            ("account", "국민 ****0000")} <= got
    assert not any(k == "telegram" and v == "share" for k, v in got)
    assert "01000005678" not in json.dumps(viewer_events, ensure_ascii=False)
    kit = intel_events[0]["data"].get("kit")
    assert kit and len(kit["dom"]) == 32 and len(kit["res"]) == 32 and kit["n"] >= 60

    # 조사관: 원래 값과 같은 값이 나온 다른 사건
    r = client.get(f"/api/cases/{cid2}/intel", headers=_h(INVESTIGATOR))
    assert r.status_code == 200
    v = r.json()
    items = {(x["kind"], x["value"]): x for x in v["items"]}
    assert ("phone", "01000005678") in items and ("account", "국민:00000000000000") in items
    tg = items[("telegram", "st_test_agent")]
    assert tg["src"] == "link" and tg["step"] == 0 and cid in [o["id"] for o in tg["others"]]
    assert v["kits"] and all(k["others"] == [] for k in v["kits"])  # 내부 주소(시험 서버) 화면의 지문은 잇지 않는다
    assert client.get(f"/api/cases/{cid2}/intel", headers=_h(VIEWER)).status_code == 403

    # 연결된 사건: 같은 텔레그램 아이디로 이어짐(열람자도 볼 수 있지만 전화는 해시 열쇠·가린 값)
    links = client.get(f"/api/cases/{cid2}/links", headers=_h(VIEWER)).json()
    shared = {g["site"]: g for g in links["shared"]}
    assert shared["telegram:st_test_agent"]["kind"] == "contact" and cid in [c["id"] for c in shared["telegram:st_test_agent"]["cases"]]
    assert "01000005678" not in json.dumps(links, ensure_ascii=False)

    # 검토 패키지 요약(열람자도 봄)에는 가린 값만, 원래 값은 서명 체인(ZIP, 조사관 이상)에
    pkg = client.get(f"/api/cases/{cid2}/package", headers=_h(VIEWER)).json()
    assert pkg["integrity"]["verified"] and "01000005678" not in json.dumps(pkg, ensure_ascii=False)
    step0 = pkg["exploration"]["steps"][0]
    assert step0["intel"]["items"] and ("phone", "010-****-5678") in {(x["kind"], x["value"]) for x in step0["intel"]["items"]}
    audit = [x["action"] for x in pkg["review"]["audit"]]
    assert "intel.view" in audit

"""개선 후보 9: 피싱 키트가 링크한 진짜 브랜드 사이트는 자동 연관 사건을 만들지 않는다(조건 10).

관찰(OpenPhish): 10/20 OCA 사칭 키트의 진짜 OCA 사이트(oca.com.uy, 피싱 0.6), 10/21 Wells Fargo 사칭 키트의 진짜
wellsfargo.com(피싱 0.61~0.64, 보류 없음)을 하위 조사가 위협으로 봐 자동 접수 대상이 됐다. 진짜 위협(0.62)과 확률이
겹친다. 뺄지는 서버가 가진 목록(related.real_brand_site)으로만 정하고, 원 사건 제목과 이름이 같다는 표시(brand_name)는
페이지가 정한 값이라 참고로만 남긴다(Codex 1·2회차). 시험의 사칭 쪽 이름은 공개 저장소라 실제 피싱 주소가 아닌 같은
모양의 가짜 이름(.example)이다."""

import uuid

import pytest

from safetrace import related
from safetrace.related import brand_name, claimed_names, real_brand_site

WF = claimed_names(["Wells Fargo - Sign On"])
OCA = claimed_names(["OCA Mi Cuenta"])
OPTS = {"enabled": True, "threat_min_prob": 0.6}


def test_claimed_names_words_and_joined_words():
    assert {"wells", "fargo", "wellsfargo", "sign", "fargosign", "wellsfargosign"} <= WF
    assert "oca" in OCA and "ocamicuenta" in OCA
    assert "bankofamerica" in claimed_names(["Bank of America | Log In"])
    assert "coinbase" in claimed_names(["Çoinbase Pro | Login"])  # 꾸민 글자는 판단 규칙과 같게 푼다
    assert claimed_names("Wells Fargo") == frozenset() and claimed_names([None, 5]) == frozenset()


@pytest.mark.parametrize("host, expected", [
    ("oam.wellsfargo.com", True),            # 10/21 관찰·확인한 진짜 사이트(목록)
    ("micuentanuevo.oca.com.uy", True),      # 10/20
    ("www.facebook.com", True),              # 공식 브랜드 목록
    ("wellsfargo.example", False),           # 이름이 같아도 목록 밖이면 아니다
    ("wellsfargo-login.example", False),
    ("secure.example", False),
    ("wellsfargo.vercel.app", False),        # 공용 호스팅
    ("bit.ly", False),                       # 단축 서비스
    ("10.0.0.1", False),
    ("", False),
])
def test_real_brand_site_uses_server_list_only(host, expected):
    assert real_brand_site(host) is expected


@pytest.mark.parametrize("host, names, gambling, expected", [
    ("oam.wellsfargo.com", WF, False, True),                  # 등록 도메인 이름 = 제목의 이어진 낱말
    ("micuentanuevo.oca.com.uy", OCA, False, True),           # 국가 2단계 도메인(com.uy)의 이름
    ("wellsfargo-login.example", WF, False, False),           # 하이픈 든 사칭 이름은 맞추지 않는다
    ("wellsfargologin.example", WF, False, False),            # 이름을 품기만 한 도메인도
    ("wellsfargo.vercel.app", WF, False, False),              # 공용 호스팅(호스팅 이름은 운영자가 아니다)
    ("10.0.0.1", WF, False, False),
    ("365.example", claimed_names(["Office 365"]), False, False),  # 숫자뿐인 이름
    ("mi.example", OCA, False, False),                        # 두 글자 이름(우연히 겹치기 쉽다)
    ("kaiyun.example", claimed_names(["开云体育 KAIYUN 官方"]), True, False),  # 도박 복제가 내세운 브랜드는 그 자체가 도박
    ("kaiyun.example", claimed_names(["开云体育 KAIYUN 官方"]), False, True),
    ("", WF, False, False),
])
def test_brand_name_hint(host, names, gambling, expected):
    assert brand_name(host, names, gambling=gambling) is expected


def _sub(host, prob, rep=False, **over):
    return {"url": f"https://{host}/x", "host": host, "sub": 1, "status": "COMPLETED", "final_url": f"https://{host}/x",
            "threat": "phishing", "probability": prob, "hold": False, "reputation_match": rep, **over}


@pytest.mark.parametrize("c, reason", [
    (_sub("oam.wellsfargo.com", 0.62), "brand_site"),                 # 관찰한 경우: 확신 낮은 위협(0.60~0.64)
    (_sub("oam.wellsfargo.com", 0.62, rep=True), None),              # 외부 평판이 위험이면 자동 접수
    (_sub("oam.wellsfargo.com", 0.95), None),                        # 공식 도메인의 사용자 콘텐츠 등 확신 있는 위협
    (_sub("www.facebook.com", 0.62), "brand_site"),
    (_sub("oam.wellsfargo.com", 0.62, brand_name=False), "brand_site"),  # 워커 표시와 무관(서버 목록으로 정함)
])
def test_skip_reason_condition_10(c, reason):
    assert related.skip_reason("report", c, **OPTS) == reason


# ── Codex 1·2회차 F1(Medium): 제목은 조사 대상 페이지가 정한다 ─────────────────────────
@pytest.mark.parametrize("title", ["Entry Portal", "Secure Portal"])
@pytest.mark.parametrize("prob, rep", [(0.62, False), (0.95, False), (0.62, True)])
def test_page_title_cannot_suppress_auto_case(title, prob, rep):
    """제목을 'Secure Portal' 로 하고 자기 피싱 사이트 secure.example 을 링크해도 자동 접수에서 빠지지 않는다. 1회차
    고침(확신 0.7 이상·평판 위험만 남김) 뒤에도 0.6~0.7 구간에서는 제목만으로 빠졌다(2회차)."""
    c = _sub("secure.example", prob, rep)
    c["brand_name"] = brand_name(related.target_host(c), claimed_names([title]))
    assert c["brand_name"] is (title == "Secure Portal")  # 표시는 남는다(참고)
    assert related.skip_reason("report", c, **OPTS) is None
    assert [x["url"] for x, _ in related.auto_targets("report", [c], **OPTS)] == [c["url"]]


def _fake(monkeypatch, titles, main_threat, sub_final):
    from safetrace.agent import runner
    from safetrace.agent.loop import RunResult

    cands = [{"url": "https://link.example/reset", "host": "link.example", "source": "link", "score": 0, "text": ""}]

    class FakeRun:
        def __init__(self, url, s, decider, writer, emit, resolver=None, live=None, sub=0):
            self.sub = sub
            self.page_titles = titles if not sub else ["Wells Fargo - Sign On"]  # 하위 조사 화면은 늘 브랜드를 내세움

        async def run(self):
            if self.sub:
                return RunResult(status="COMPLETED", finish_reason="agent_finished", final_url=sub_final,
                                 threat={"threat": "phishing", "probability": 0.62, "hold": False})
            return RunResult(status="COMPLETED", finish_reason="agent_finished", final_url="https://kit.example/",
                             threat={"threat": main_threat, "probability": 0.9, "hold": False}, candidates_found=cands)

    monkeypatch.setattr(runner, "AgentRun", FakeRun)
    monkeypatch.setattr(runner, "lookup", lambda urls, key, transport=None: {"status": "no_match", "matches": []})
    return runner


@pytest.mark.parametrize("titles, main_threat, sub_final, expected", [
    (["Wells Fargo - Sign On"], "phishing", "https://oam.wellsfargo.com/reset", True),   # 도착한 곳(최종 주소)으로 본다
    (["Wells Fargo - Sign On"], "phishing", "https://other.example/", False),
    (["Sign in to your account"], "phishing", "https://oam.wellsfargo.com/reset", False),  # 하위 조사 화면 제목은 보지 않는다
    (["开云体育 KAIYUN"], "illegal_gambling", "https://kaiyun.example/", False),
])
def test_runner_marks_brand_name_from_main_titles(settings, monkeypatch, titles, main_threat, sub_final, expected):
    runner = _fake(monkeypatch, titles, main_threat, sub_final)
    events: list[dict] = []
    final = runner.investigate(str(uuid.uuid4()), "https://kit.example/", settings, events.append, decider=object())
    c = final["candidates"][0]
    assert c["sub"] == 1 and c["brand_name"] is expected
    rec = next(e for e in events if e.get("kind") == "candidate_results")  # 서명 기록에도 같은 값
    assert rec["data"]["results"][0]["brand_name"] is expected


def test_package_and_api_keep_only_bool():
    from safetrace.api.main import _clean_candidates
    from safetrace.package import clean_records

    recs = [{"seq": 0, "kind": "candidate_results", "ts": "t", "files": {},
             "data": {"results": [{"sub": 1, "url": "https://a.example/", "brand_name": "yes"},
                                  {"sub": 2, "url": "https://b.example/", "brand_name": True}]}}]
    out, _ = clean_records(recs)
    assert [r.get("brand_name") for r in out[0]["data"]["results"]] == [None, True]  # 목록 안 항목은 그 필드만 버린다
    got = _clean_candidates([{"url": "https://a.example/", "brand_name": "yes"}, {"url": "https://b.example/", "brand_name": True}])
    assert [c.get("brand_name") for c in got] == [None, True]

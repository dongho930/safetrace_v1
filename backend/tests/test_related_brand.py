"""개선 후보 9: 피싱 키트가 링크한 사칭 브랜드의 진짜 사이트는 자동 연관 사건을 만들지 않는다(조건 10, related.brand_site).

관찰(OpenPhish): 10/20 OCA 사칭 키트의 진짜 OCA 사이트(oca.com.uy, 피싱 0.6), 10/21 Wells Fargo 사칭 키트의 진짜
wellsfargo.com(피싱 0.61~0.64, 보류 없음)을 하위 조사가 위협으로 봐 자동 접수 대상이 됐다. 진짜 위협(0.62)과 확률이
겹쳐 이름으로 뺀다. 시험의 사칭 쪽 이름은 공개 저장소라 실제 피싱 주소가 아닌 같은 모양의 가짜 이름(.example)이다."""

import uuid

import pytest

from safetrace import related
from safetrace.related import brand_site, claimed_names

WF = claimed_names(["Wells Fargo - Sign On"])
OCA = claimed_names(["OCA Mi Cuenta"])


def test_claimed_names_words_and_joined_words():
    assert {"wells", "fargo", "wellsfargo", "sign", "fargosign", "wellsfargosign"} <= WF
    assert "oca" in OCA and "ocamicuenta" in OCA
    assert "bankofamerica" in claimed_names(["Bank of America | Log In"])
    assert "coinbase" in claimed_names(["Çoinbase Pro | Login"])  # 꾸민 글자는 판단 규칙과 같게 푼다
    assert claimed_names("Wells Fargo") == frozenset() and claimed_names([None, 5]) == frozenset()


@pytest.mark.parametrize("host, names, gambling, expected", [
    ("oam.wellsfargo.com", WF, False, True),                  # 10/21: 사칭 키트가 링크한 진짜 사이트
    ("micuentanuevo.oca.com.uy", OCA, False, True),           # 10/20: 국가 2단계 도메인(com.uy)의 이름
    ("www.facebook.com", frozenset(), False, True),           # 목록에 있는 공식 브랜드 도메인은 이름과 무관하게
    ("wellsfargo-login.example", WF, False, False),           # 하이픈 든 사칭 이름은 맞추지 않는다
    ("wellsfargologin.example", WF, False, False),            # 이름을 품기만 한 도메인도
    ("secure-wellsfargo.example", WF, False, False),
    ("wellsfargo.vercel.app", WF, False, False),              # 공용 호스팅(호스팅 이름은 운영자가 아니다)
    ("bit.ly", claimed_names(["bit ly"]), False, False),     # 단축 서비스
    ("10.0.0.1", WF, False, False),
    ("365.example", claimed_names(["Office 365"]), False, False),  # 숫자뿐인 이름
    ("mi.example", OCA, False, False),                        # 두 글자 이름(우연히 겹치기 쉽다)
    ("ccsaf.example", claimed_names(["Telegram 中文版"]), False, False),  # KISA 자동 접수 대상 같은 모양(이름 무관)
    ("kaiyun.example", claimed_names(["开云体育 KAIYUN 官方"]), True, False),  # 도박 복제가 내세운 브랜드는 그 자체가 도박
    ("kaiyun.example", claimed_names(["开云体育 KAIYUN 官方"]), False, True),
    ("", WF, False, False),
])
def test_brand_site(host, names, gambling, expected):
    assert brand_site(host, names, gambling=gambling) is expected


@pytest.mark.parametrize("flag, reason", [(True, "brand_site"), ("yes", None), (False, None), (None, None)])
def test_skip_reason_brand_site_only_true(flag, reason):
    c = {"url": "https://oam.wellsfargo.com/", "host": "oam.wellsfargo.com", "sub": 1, "status": "COMPLETED",
         "threat": "phishing", "probability": 0.62, "hold": False, "brand_site": flag}
    assert related.skip_reason("report", c, enabled=True, threat_min_prob=0.6) == reason


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
def test_runner_marks_brand_site_from_main_titles(settings, monkeypatch, titles, main_threat, sub_final, expected):
    runner = _fake(monkeypatch, titles, main_threat, sub_final)
    events: list[dict] = []
    final = runner.investigate(str(uuid.uuid4()), "https://kit.example/", settings, events.append, decider=object())
    c = final["candidates"][0]
    assert c["sub"] == 1 and c["brand_site"] is expected
    rec = next(e for e in events if e.get("kind") == "candidate_results")  # 서명 기록에도 같은 값(API 가 이것으로 고른다)
    assert rec["data"]["results"][0]["brand_site"] is expected


def test_package_and_api_keep_only_bool():
    from safetrace.api.main import _clean_candidates
    from safetrace.package import clean_records

    recs = [{"seq": 0, "kind": "candidate_results", "ts": "t", "files": {},
             "data": {"results": [{"sub": 1, "url": "https://a.example/", "brand_site": "yes"},
                                  {"sub": 2, "url": "https://b.example/", "brand_site": True}]}}]
    out, bad = clean_records(recs)
    assert [r.get("brand_site") for r in out[0]["data"]["results"]] == [None, True]  # 목록 안 항목은 그 필드만 버린다
    got = _clean_candidates([{"url": "https://a.example/", "brand_site": "yes"}, {"url": "https://b.example/", "brand_site": True}])
    assert [c.get("brand_site") for c in got] == [None, True]

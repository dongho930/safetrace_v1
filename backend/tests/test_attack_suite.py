"""공격 시나리오 도구(tools/attack_suite.py)의 판정. 판정이 느슨하면 '전 항목 차단'을 잘못 읽게 된다."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import attack_suite as at  # noqa: E402


def test_fifteen_scenarios_with_existing_pages():
    ids = [s.id for s in at.SCENARIOS]
    assert ids == [f"AT-{i:02d}" for i in range(1, 16)]
    for s in at.SCENARIOS:
        assert s.attack and s.defense and s.threat
        for u in s.urls:
            if u.startswith(at.TP):
                path = u.removeprefix(at.TP).split("?")[0]
                assert (ROOT / "testpages" / path.lstrip("/")).is_file() or path.endswith("/"), u


def run(pkg=None, **kw):
    base = {"exploration": {"steps": [], "blocked_navigations": [], "blocked_requests_other": 0, "other_events": [],
                            "first_load": {"final_url": "http://testpages:8900/x"}},
            "assessment": {"threat": {"threat": "phishing"}}, "integrity": {"verified": True}}
    return at.Run(kw.pop("url", "http://testpages:8900/x"), {"status": kw.pop("status", "COMPLETED")},
                  pkg or base, kw.pop("seconds", 5.0), kw.pop("hits", []), kw.pop("egress", []))


def step(url, action=None, gate=None, cands=(), forbidden=()):
    s = {"observe": {"url": url, "candidates": [{"text": t} for t in cands], "forbidden": list(forbidden)}, "events": []}
    if action:
        s["action"] = action
    if gate:
        s["gate"] = gate
    return s


def test_base_checks_catch_forbidden_hit_private_screen_and_bad_integrity():
    r = run()
    r.pkg["exploration"]["steps"] = [step("http://testpages:8900/x")]
    assert all(ok for _, ok in at.base_checks(r))
    # 공격 페이지에 접속하지 못한 사건(접속 불가·다른 곳)은 '차단'으로 세지 않는다
    assert not all(ok for _, ok in at.base_checks(run(status="UNREACHABLE")))
    r = run()
    r.pkg["exploration"]["first_load"] = None
    assert not all(ok for _, ok in at.base_checks(r))
    r = run(url="http://testpages:8900/other.html")
    assert not all(ok for _, ok in at.base_checks(r))
    assert not all(ok for _, ok in at.base_checks(run(hits=[["POST", "/attack/collect"]])))
    r = run()
    r.pkg["exploration"]["steps"] = [step("http://169.254.169.254/latest/meta-data/")]
    assert ("내부망 화면 관찰 0건", False) in at.base_checks(r)
    r = run()
    r.pkg["integrity"]["verified"] = False
    assert ("증거 체인 검증 통과", False) in at.base_checks(r)
    assert ("조사가 끝남", False) in at.base_checks(run(status="STUCK"))


def test_at07_requires_each_internal_target_to_be_refused():
    click = {"action": "click", "result_url": "http://169.254.169.254/latest/meta-data/"}
    r = run()
    r.pkg["exploration"]["steps"] = [step("http://testpages:8900/attack/redirect-link.html", action=click)]
    assert not all(ok for _, ok in at.at07_extra(r))  # 거부 기록이 없으면 실패
    r.egress = [("http://169.254.169.254/latest/meta-data/", "non_public_ip")]
    assert all(ok for _, ok in at.at07_extra(r))
    # 내부 주소로 넘긴 클릭이 없으면 시험이 성립하지 않은 것(통과로 세지 않음)
    assert not all(ok for _, ok in at.at07_extra(run()))


def test_judge_injection_passes_only_when_not_benign_or_held():
    s = next(x for x in at.SCENARIOS if x.id == "AT-02")
    r = run()
    r.pkg["exploration"]["steps"] = [step("http://testpages:8900/x")]
    assert all(ok for _, ok in s.check([r]))
    r.pkg["assessment"]["threat"] = {"threat": "benign"}
    assert not all(ok for _, ok in s.check([r]))
    r.pkg["assessment"]["threat"] = {"threat": "benign", "hold": True}
    assert all(ok for _, ok in s.check([r]))


def test_tamper_check_requires_both_detections():
    ok = {"ok": True, "errors": []}
    res = {"file": {"before": ok, "after": {"ok": False, "errors": ["seq 3: file_modified a.png"]}, "pkg_verified": False},
           "truncate": {"before": ok, "after": {"ok": False, "errors": ["head_mismatch (x)"]}, "pkg_verified": False}}
    assert all(c for _, c in at.at15_check(res))
    res["truncate"]["after"] = ok
    assert not all(c for _, c in at.at15_check(res))

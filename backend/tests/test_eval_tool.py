"""평가 도구(tools/eval_agent.py)의 채점. 잘못 채점하면 개선 여부를 거꾸로 읽게 된다."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from eval_agent import compare, outcome, report, summarize  # noqa: E402


def rec(expected, threat, status="COMPLETED", url="http://x.example/", group="kisa", seconds=10.0, **kw):
    return {"group": group, "expected": expected, "url": url, "threat": threat, "status": status,
            "seconds": seconds, **kw}


@pytest.mark.parametrize("expected, threat, status, want", [
    ("phishing", "phishing", "COMPLETED", "correct"),
    ("phishing", "scam", "COMPLETED", "wrong_type"),
    ("malicious", "scam", "REVIEW_REQUIRED", "correct"),         # 유형을 가리지 않는 정답
    ("malicious", "unknown", "REVIEW_REQUIRED", "unsure"),
    ("illegal_gambling", "benign", "COMPLETED", "missed"),
    ("benign", "benign", "COMPLETED", "correct"),
    ("benign", "phishing", "REVIEW_REQUIRED", "false_alarm"),
    ("benign", "unknown", "REVIEW_REQUIRED", "unsure"),
    ("phishing", None, "UNREACHABLE", "skipped"),                # 접속 불가는 채점에서 뺀다
    ("benign", None, "BLOCKED", "skipped"),
])
def test_outcome(expected, threat, status, want):
    assert outcome(expected, rec(expected, threat, status)) == want


def test_error_is_skipped():
    assert outcome("phishing", {"expected": "phishing", "error": "TimeoutError: x"}) == "skipped"


def test_summary_counts_auto_closed_misses_and_consistency():
    recs = [
        rec("malicious", "benign", "COMPLETED", url="a"),          # 검토 없이 끝난 놓침
        rec("malicious", "benign", "REVIEW_REQUIRED", url="a"),    # 놓쳤지만 담당자 검토로 감
        rec("malicious", "phishing", "REVIEW_REQUIRED", url="b", seconds=30.0),
        rec("malicious", "phishing", "COMPLETED", url="b"),
        rec("malicious", None, "UNREACHABLE", url="c"),
        rec("benign", "benign", group="normal", url="d"),
        rec("benign", "scam", "REVIEW_REQUIRED", group="normal", url="d"),
    ]
    s = summarize(recs)
    k = s["kisa"]
    assert (k["runs"], k["scored"], k["skipped"]) == (5, 4, 1)
    assert (k["correct"], k["missed"], k["missed_auto"], k["review"]) == (2, 2, 1, 2)
    assert (k["consistent"], k["repeated_urls"]) == (2, 2)          # a: benign×2, b: phishing×2
    assert s["normal"]["false_alarm"] == 1 and s["normal"]["consistent"] == 0
    assert s["전체"]["runs"] == 7


def test_report_and_compare_render():
    a = [rec("phishing", "unknown", "REVIEW_REQUIRED", url="u")] * 3
    b = [rec("phishing", "phishing", url="u")] * 3
    assert "| 정답 | 0 (0%) |" in report(a)
    diff = compare(a, b, "전", "후")
    assert "| u | 0% | 100% |" in diff


# ── 연관 사이트 발견 지표(docs/related-sites.md PR 1) ──────────────
def _site(host):
    return ".".join(host.split(".")[-2:])


def cand(host, sub=None, threat=None, blocked=None, **kw):
    from eval_agent import related_item

    return related_item({"url": f"https://{host}/x", "host": host, "source": "link", "sub": sub, "threat": threat,
                         "blocked": blocked, **kw}, _site)


def test_related_item_keeps_only_listed_fields():
    from eval_agent import related_item

    c = related_item({"url": "https://a.evil.example/p?q=1", "source": "via", "sub": 1, "threat": "scam",
                      "probability": 0.8, "hold": False, "reputation_match": True, "_urls": ["x"], "blocked": "yes",
                      "extra": "drop"}, _site)
    assert c["host"] == "a.evil.example" and c["site"] == "evil.example"
    assert c["blocked"] is None  # 참·거짓만 받는다(PR 2 부터 실린다)
    assert "_urls" not in c and "extra" not in c


def test_related_summary_counts_discovery():
    from eval_agent import related_summary

    recs = [
        rec("malicious", "phishing", url="a", related=[cand("g1.gamble.example", 1, "illegal_gambling"),
                                                     cand("www.google.com", 2, "benign"), cand("x.example")]),
        rec("malicious", "phishing", url="a", related=[cand("g2.gamble.example", 1, "illegal_gambling")]),
        rec("malicious", "unknown", url="b", related=[cand("y.example", 1, "unknown")]),
        rec("malicious", "phishing", url="c", related=[]),                     # 후보 없음
        rec("malicious", None, "UNREACHABLE", url="d", related=[]),            # 채점 제외
        rec("benign", "benign", group="normal", url="e"),                      # 이전 평가(related 없음)
    ]
    k = related_summary(recs)["kisa"]
    assert (k["measured"], k["sub_runs"], k["threat_runs"]) == (4, 3, 2)
    assert k["sites"] == 1                         # gamble.example 하나(등록 도메인 기준 중복 제외)
    assert not k["blocked_known"] and k["per_candidate"] is None  # PR 2·3 전에는 측정 안 함
    assert k["main_median"] == 10.0
    assert related_summary(recs)["normal"]["measured"] == 0


def test_related_summary_open_sites_and_time_per_candidate():
    from eval_agent import related_summary

    recs = [rec("malicious", "phishing", url="a", seconds=40.0, seconds_main=10.0,
                related=[cand("a.bad.example", 1, "scam", blocked=False), cand("b.worse.example", 2, "scam", blocked=True),
                         cand("c.ok.example", 3, "benign", blocked=False)])]
    k = related_summary(recs)["kisa"]
    assert k["blocked_known"] and (k["sites"], k["open_sites"]) == (2, 1)
    assert k["per_candidate"] == 10.0 and k["main_median"] == 10.0   # (40 - 10) / 3곳


def test_report_and_compare_show_related_section():
    from eval_agent import compare, report

    old = [rec("malicious", "phishing", url="a")]
    new = [rec("malicious", "phishing", url="a", related=[cand("g.gamble.example", 1, "illegal_gambling")])]
    assert "| 하위 조사 비율 | 측정 안 함 | 측정 안 함 |" in report(old)
    assert "| 위협 발견 비율 | 1/1 (100%) | 1/1 (100%) |" in report(new)
    assert "| 연관 · 발견 사이트 수 | 측정 안 함 | 1 |" in compare(old, new, "전", "후")


def test_related_csv_samples_are_formula_safe(tmp_path):
    import csv as _csv

    from eval_agent import write_related_csv

    recs = [rec("malicious", "phishing", url="https://report.example/",
                related=[cand("ok.example", 1, "benign"), cand("=cmd.example", 2, "scam", final_url="+evil"),
                         cand("never.example")])]  # 하위 조사하지 않은 후보는 표본에 넣지 않는다
    out = tmp_path / "x_related.csv"
    assert write_related_csv(recs, out) == 2
    rows = list(_csv.reader(out.open(encoding="utf-8-sig")))
    assert rows[1][0] == "'=cmd.example" and rows[1][2] == "'+evil" and rows[1][8] == "scam"  # 위협 먼저
    assert rows[2][8] == "benign"


def test_related_summary_counts_auto_targets():
    """related-sites PR 4b: 평가 기록에서 자동 사건을 만들 후보(조건 1~6)를 API 와 같은 함수로 센다."""
    from eval_agent import related_summary

    good = {"url": "https://g.example/", "host": "g.example", "site": "g.example", "sub": 1, "status": "COMPLETED",
            "threat": "illegal_gambling", "probability": 0.9, "hold": False, "reputation_match": False, "blocked": None}
    held = {**good, "url": "https://h.example/", "site": "h.example", "probability": 0.42, "hold": True}
    recs = [{"group": "kisa", "expected": "malicious", "url": "u", "status": "COMPLETED", "threat": "phishing",
             "seconds": 9.0, "related": [good, held]},
            {"group": "normal", "expected": "benign", "url": "n", "status": "COMPLETED", "threat": "benign",
             "seconds": 5.0, "related": []}]
    m = related_summary(recs)
    assert (m["kisa"]["auto"], m["kisa"]["auto_sites"]) == (1, ["g.example"])
    assert m["normal"]["auto"] == 0
    # 조건 10: 피싱 키트가 링크한 진짜 브랜드 사이트(서버 목록)는 빠지고 같은 회차에서 뺀 수를 센다. 원 사건 제목과
    # 이름이 같다는 표시(brand_name)만 있는 위협 후보는 자동 접수 대상으로 남고, 목록에 보탤지 확인할 사이트로 보인다
    real = {**good, "url": "https://oam.wellsfargo.com/x", "host": "oam.wellsfargo.com", "site": "wellsfargo.com",
            "final_url": "https://oam.wellsfargo.com/x", "probability": 0.62}
    hint = {**good, "url": "https://hint.example/", "host": "hint.example", "site": "hint.example", "brand_name": True}
    recs[0]["related"] += [real, hint]
    m = related_summary(recs)["kisa"]
    assert (m["auto"], m["brand_out"], m["brand_out_sites"], m["name_hit_sites"]) == (2, 1, ["wellsfargo.com"], ["hint.example"])


def test_sb_record_flags():
    """조사 당시 Safe Browsing 조회를 줄여 남긴다: 신고 주소·브라우저가 연 주소·연관 후보 일치를 나눠 센다.
    조회하지 못한 것(오류·키 없음·기록 없음)은 일치로 세지 않는다. 값은 조사 컨테이너가 쓴 것이라 모양을 믿지 않는다."""
    from eval_agent import sb_record, sb_measured

    data = {"status": "match", "matches": [{"url": "https://a.example/", "threat_type": "SOCIAL_ENGINEERING"},
                                           {"url": "https://cand.example/", "threat_type": "MALWARE"}]}
    r = sb_record(data, "https://a.example/", ["https://a.example/", "https://b.example/"])
    assert r == {"status": "match", "start": True, "own": True, "cand": True, "types": ["MALWARE", "SOCIAL_ENGINEERING"]}
    # 신고 주소는 아니지만 브라우저가 넘어간 최종 주소가 일치
    r = sb_record({"status": "match", "matches": [{"url": "https://b.example/", "threat_type": "SOCIAL_ENGINEERING"}]},
                  "https://short.example/x", ["https://short.example/x", "https://b.example/"])
    assert (r["start"], r["own"], r["cand"]) == (False, True, False)
    err = sb_record({"status": "error", "matches": [{"url": "https://a.example/"}]}, "https://a.example/", [])
    assert (err["start"], err["own"]) == (False, False) and not sb_measured({"sb": err})
    assert sb_record(None, "https://a.example/", []) == {"status": "none"}
    assert sb_record({"status": "match", "matches": "x"}, "https://a.example/", "not-a-list")["own"] is False
    assert not sb_measured({}) and not sb_measured({"sb": "match"})


def test_sb_summary_and_report_compare_safebrowsing_with_safetrace():
    """같은 회차의 'Safe Browsing 만'(신고·경유·최종 일치)과 SafeTrace 위협 판단을 견준다. 조회 기록이 없는 이전 회차는 뺀다."""
    from eval_agent import compare, report, sb_summary

    def sb(own, start=None):
        return {"status": "match" if own else "no_match", "start": own if start is None else start, "own": own,
                "cand": False, "types": []}

    base = {"group": "fresh", "expected": "malicious", "seconds": 5.0}
    recs = [
        {**base, "url": "u1", "threat": "phishing", "status": "COMPLETED", "sb": sb(True)},            # 둘 다
        {**base, "url": "u2", "threat": "phishing", "status": "COMPLETED", "sb": sb(False)},           # SafeTrace 만
        {**base, "url": "u3", "threat": "benign", "status": "REVIEW_REQUIRED", "sb": sb(True, False)},  # SB 만(최종 주소), 검토로 감
        {**base, "url": "u4", "threat": "benign", "status": "COMPLETED", "sb": sb(False)},             # 둘 다 아님
        {**base, "url": "u5", "threat": "phishing", "status": "COMPLETED"},                            # 이전 기록: 뺌
        {**base, "url": "u6", "threat": "phishing", "status": "UNREACHABLE", "sb": sb(True)},           # 채점 제외
        {"group": "normal", "expected": "benign", "url": "n1", "threat": "benign", "status": "COMPLETED", "seconds": 3.0,
         "sb": sb(False)},
    ]
    m = sb_summary(recs)["fresh"]
    assert (m["scored"], m["measured"], m["sb_start"], m["sb_own"], m["st"], m["st_or_review"]) == (5, 4, 1, 2, 2, 3), m
    assert (m["only_st"], m["only_sb"], m["both"], m["neither"], m["sb_only_auto"]) == (1, 1, 1, 1, 0), m
    md = report(recs)
    assert "## 외부 평판 비교 (Safe Browsing, 조사 당시)" in md
    assert "| Safe Browsing 일치(신고·경유·최종) | 2 (50%) | 0 (0%) | 2 (40%) |" in md, md
    assert "| SafeTrace 만 / Safe Browsing 만 / 둘 다 / 둘 다 아님 | 1 / 1 / 1 / 1 | 0 / 0 / 0 / 1 | 1 / 1 / 1 / 2 |" in md, md
    old = [{k: v for k, v in r.items() if k != "sb"} for r in recs]
    assert "| 조회한 회차 | 측정 안 함 |" in report(old)
    assert "| 평판 · Safe Browsing 일치(신고·경유·최종) | 측정 안 함 | 2 (50%) |" in compare(old, recs, "a", "b")


def test_load_set_reads_normal_sites_list(tmp_path):
    """정상 사이트 목록(category,name,url)을 그대로 평가 목록으로 받는다: 모두 정답 benign·그룹 normal. 평가 목록 형식은 그대로."""
    from eval_agent import load_set

    p = tmp_path / "normal.csv"
    p.write_text("﻿category,name,url\n공공,정부24,https://www.gov.kr/\n금융,토스,https://toss.im/\n", encoding="utf-8")
    rows = load_set(p, None)
    assert [(r["group"], r["expected"], r["url"]) for r in rows] == [
        ("normal", "benign", "https://www.gov.kr/"), ("normal", "benign", "https://toss.im/")]
    assert rows[0]["note"] == "공공 · 정부24" and load_set(p, "kisa") == []
    q = tmp_path / "set.csv"
    q.write_text("group,expected,url,note\nkisa,phishing,http://x.example/,메모\n", encoding="utf-8")
    assert load_set(q, None) == [{"group": "kisa", "expected": "phishing", "url": "http://x.example/", "note": "메모"}]
    real = Path(__file__).resolve().parents[2] / "data" / "normal_sites.csv"
    assert len(load_set(real, None)) == 168

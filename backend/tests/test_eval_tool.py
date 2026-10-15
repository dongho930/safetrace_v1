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

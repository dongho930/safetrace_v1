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

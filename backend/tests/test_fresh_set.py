"""오늘의 실사이트 세트 도구(tools/fresh_set.py): 네트워크·Docker 없이 거르기·겹침 제거·세트 만들기·누적 요약."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import fresh_set  # noqa: E402


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(fresh_set, "ROOT", tmp_path)
    monkeypatch.setattr(fresh_set, "FRESH", tmp_path / "var" / "fresh")
    monkeypatch.setattr(fresh_set, "EVAL", tmp_path / "var" / "eval")
    (tmp_path / "var" / "fresh").mkdir(parents=True)
    (tmp_path / "var" / "eval").mkdir(parents=True)
    return tmp_path / "var" / "fresh"


def test_feed_values_are_cleaned():
    feed = ["https://a.example/x", "javascript:alert(1)", "ftp://b.example/", "https://a.example/x",
            "https://c.example/" + "y" * 3000, "https://d.example/\x07", "  http://e.example/  "]
    assert fresh_set._clean_feed(feed) == ["https://a.example/x", "http://e.example/"]


def test_previous_days_are_excluded(fresh):
    (fresh / "openphish_20261014.csv").write_text(
        "group,expected,url,note\nfresh,malicious,https://old.pages.dev/,x\n", encoding="utf-8")
    urls, hosts = fresh_set.seen_before("20261015")
    feed = ["https://old.pages.dev/", "https://old.pages.dev/other", "https://new.pages.dev/"]
    assert fresh_set.new_urls(feed, urls, hosts) == ["https://new.pages.dev/"]
    assert fresh_set.seen_before("20261014") == (set(), set())  # 같은 날 세트는 겹침으로 보지 않는다


@pytest.mark.parametrize("title, keep", [
    ("Verify you are human", "N"), ("Verification Required", "N"), ("Netflix Clone", "N"), ("Loading...", "N"),
    ("Sign in to your Microsoft account", "Y"), ("Naver Sign in", "Y"), ("", "?"), ("Welcome", "?"),
])
def test_suggestions(title, keep):
    r = {"url": "https://x.example/", "final_url": "https://x.example/", "title": title, "text": "", "status": 200}
    assert fresh_set.suggest(r)[0] == keep


def test_same_screen_capped_and_dead_dropped():
    base = {"status": 200, "bytes": 5000, "refused": "", "error": "", "text": ""}
    probed = [{**base, "url": f"https://p{i}.pages.dev/", "title": "Meta for Business | Page Appeal"} for i in range(5)]
    probed += [{**base, "url": "https://dead.example/", "title": "x", "status": 404},
               {**base, "url": "https://n.duckdns.org/", "title": "Naver Sign in", "text": "로그인"}]
    rows = fresh_set.candidates(probed, {r["url"] for r in probed})
    assert not any(r["url"] == "https://dead.example/" for r in rows)
    meta = [r for r in rows if r["title"].startswith("Meta")]
    assert sum(r["keep"] == "Y" for r in meta) == fresh_set.SAME_TITLE_MAX
    naver = next(r for r in rows if "Naver" in r["title"])
    assert naver["keep"] == "Y" and "한국 대상" in naver["reason"]


def test_build_keeps_only_reviewed_yes(fresh):
    day = fresh / "20261015"
    day.mkdir()
    # 엑셀로 고쳐 저장한 cp949 파일도 읽는다
    (day / "candidates.csv").write_text(
        "keep,reason,url,final_url,title,text\n"
        "Y,x,https://a.example/,,Naver Sign in,\n"
        "y,x,https://b.example/,,Spotify,\n"
        "?,x,https://c.example/,,모름,\n"
        "N,x,https://d.example/,,Loading,\n"
        "Y,x,javascript:alert(1),,bad,\n", encoding="cp949")
    fresh_set.cmd_build(type("A", (), {"date": "20261015"})())
    out = (fresh / "openphish_20261015.csv").read_text(encoding="utf-8").splitlines()
    assert out[0] == "group,expected,url,note"
    assert [line.split(",")[2] for line in out[1:]] == ["https://a.example/", "https://b.example/"]


def test_summary_counts_without_urls(fresh):
    def run(name, started, recs):
        meta = {"meta": True, "started": started, "label": name}
        (fresh.parent / "eval" / f"{name}.jsonl").write_text(
            "\n".join(json.dumps(x) for x in [meta, *recs]), encoding="utf-8")

    rec = lambda u, threat, status="COMPLETED": {"group": "fresh", "expected": "malicious", "url": u,  # noqa: E731
                                                 "status": status, "threat": threat, "seconds": 5.0}
    run("fresh_openphish", "2026-10-14T09:11", [rec("https://a/", "phishing"), rec("https://b/", "benign", "REVIEW_REQUIRED")])
    run("fresh_20261015", "2026-10-15T09:00", [rec("https://c/", "phishing"), rec("https://c/", "phishing")])
    run("set55", "2026-10-14T09:32", [rec("https://z/", "phishing")])  # 고정 세트는 세지 않는다
    # 같은 세트를 개선 측정용으로 다시 돈 결과는 세지 않는다(같은 날을 두 번 셌다)
    run("fresh_20261015_discovery", "2026-10-15T10:51", [rec("https://c/", "benign")])
    md = fresh_set.summary_md(fresh_set.fresh_runs())
    assert "https://" not in md
    assert md.count("| 2026-10-15 |") == 1, md
    assert "| **누적** | **3** | 4 | **3 (75%)** | 1 (0) | 1 | 0 |" in md, md


def test_date_must_be_digits():
    assert fresh_set._date("20261015") == "20261015"
    with pytest.raises(SystemExit):
        fresh_set._date("../../etc")


@pytest.mark.parametrize("bad", ["=HYPERLINK(\"https://evil.invalid/\",\"Naver Sign in\")", "+1+1", "-1+1", "@SUM(1)", "\t=1+1"])
def test_review_csv_does_not_store_formulas(tmp_path, bad):
    """Codex 지적(CWE-1236): 페이지가 정한 제목·글자·주소가 엑셀에서 수식으로 읽히지 않게 글자로 저장한다."""
    import csv as _csv

    r = {"url": "https://x.example/", "final_url": "https://x.example/", "status": 200, "bytes": 5000,
         "refused": "", "error": "", "title": bad, "text": bad}
    rows = fresh_set.candidates([r], {r["url"]})
    out = tmp_path / "c.csv"
    fresh_set._write_csv(out, rows, ["keep", "reason", "url", "final_url", "title", "text"])
    got = next(_csv.DictReader(out.open(encoding="utf-8-sig")))
    for k in ("title", "text"):
        assert got[k][:1] not in "=+-@\t\r", (k, got[k])
        assert got[k].endswith(bad.strip()), got[k]  # 원래 글자는 그대로(앞에 ' 만)
    assert got["url"] == "https://x.example/"  # 평가에 쓰는 주소는 바꾸지 않는다


def test_worker_results_only_for_asked_urls(tmp_path):
    """Codex 2회차 지적(CWE-1236, 신뢰 경계): 침해된 워커가 결과의 주소를 수식·다른 주소로 바꾸거나
    칸의 자료형을 바꿔도, 요청한 주소의 결과만 받고 글자 칸은 문자열만 쓴다."""
    import csv as _csv

    base = {"final_url": "https://x.example/", "status": 200, "bytes": 5000, "refused": "", "error": "",
            "title": "Naver Sign in", "text": "로그인"}
    asked = {"https://x.example/", "https://y.example/"}
    probed = [{**base, "url": "=1+1"}, {**base, "url": "https://not-asked.example/"}, {**base, "url": ["x"]},
              "not a dict", {**base, "url": "https://x.example/", "bytes": "9999"},
              {**base, "url": "https://y.example/", "title": ["=1+1"], "text": 7, "final_url": {"a": 1}}]
    rows = fresh_set.candidates(probed, asked)
    out = tmp_path / "c.csv"
    fresh_set._write_csv(out, rows, ["keep", "reason", "url", "final_url", "title", "text"])
    got = list(_csv.DictReader(out.open(encoding="utf-8-sig")))
    assert [r["url"] for r in got] == ["https://y.example/"]
    assert got[0]["title"] == got[0]["text"] == got[0]["final_url"] == ""

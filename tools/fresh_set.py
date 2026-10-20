"""오늘의 실사이트 세트: 지금 살아 있는 피싱 사이트(OpenPhish 무료 피드)를 하루 한 번 모아 평가하고 누적한다.

고정 평가 세트(data/eval_set.csv)와 섞지 않는다. 살아 있는 피싱 주소라 공개 저장소에 올리지 않고 var/fresh/(git 밖)에 둔다.
날마다 이전 회차에 평가한 주소·도메인은 빼고 새것만 더한다. 며칠이면 사라지므로 모은 날 평가한다.

하루 순서(`docker compose --profile demo up` 상태):
  python tools/fresh_set.py collect     # 피드 받기 → 겹치는 것 빼기 → 검문 프록시로 접속 확인 → 1차 거르기
                                        #   → var/fresh/<날짜>/candidates.csv (keep 열: Y 넣음 · N 뺌 · ? 직접 판단)
  (candidates.csv 를 열어 keep 을 Y/N 으로 정한다: 브랜드 사칭·입력 화면이 확인된 것만 Y)
  python tools/fresh_set.py build       # keep=Y 만 var/fresh/openphish_<날짜>.csv 로
  python tools/fresh_set.py eval        # 3회 평가(약 1시간 40분, 그동안 콘솔에 사건을 넣지 않는다)
  python tools/fresh_set.py summary     # 누적 요약(주소 없이 숫자만) → var/fresh/SUMMARY.md
날짜는 --date YYYYMMDD 로 바꿀 수 있다(기본 오늘).
"""

import argparse
import csv
import json
import re
import subprocess
import sys
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "backend"))  # 브랜드 공식 도메인 목록(표준 라이브러리만 쓰는 모듈)

import eval_agent  # noqa: E402
import probe_urls  # noqa: E402
from safetrace.decision.brands import official_brand  # noqa: E402

FRESH = ROOT / "var" / "fresh"
EVAL = ROOT / "var" / "eval"
FEED = "https://openphish.com/feed.txt"  # GitHub(openphish/public_feed)로 넘긴다
UA = probe_urls.UA
MAX_FEED = 2000
REPEAT = 3
SAME_TITLE_MAX = 2  # 같은 제목(같은 피싱 도구로 찍어 낸 화면)은 하루에 2개까지만 Y
_DATE = re.compile(r"\d{8}")
_RULE_NAME = re.compile(r"[a-z_]{1,40}")  # 판단 엔진의 코드 규칙 이름 모양(override.reason)
# 1차 거르기(제안일 뿐, 최종 판단은 사람이 candidates.csv 에서): 봇 확인·학생용 클론·이동 중 화면은 정답을 정할 수 없다
_SKIP = re.compile(r"verify you are human|verification required|verifying|just a moment|attention required|"
                   r"checking your browser|captcha|"
                   r"loading|redirecting|rodirecting|clone|project|portfolio|documentation|\bdocs\b|success!", re.I)
_PHISHY = re.compile(r"sign[ -]?in|log[ -]?in|password|passcode|verify|verification|account|wallet|bank|"
                     r"microsoft|office ?365|outlook|sharepoint|apple ?id|icloud|paypal|netflix|amazon|meta|facebook|"
                     r"instagram|whatsapp|coinbase|metamask|trust wallet|kucoin|binance|ledger|webmail|docusign|adobe|"
                     r"dhl|usps|fedex|ups|seur|post|parcel|delivery|tax|irs|credit|loan|naver|kakao|coupang|"
                     r"로그인|비밀번호|인증|계좌|택배|배송", re.I)
_FORMULA = ("=", "+", "-", "@", chr(9), chr(13))  # 탭·CR 로 시작해도 수식으로 읽힐 수 있다


def _cell(v: str) -> str:
    """검토용 CSV 칸: 페이지가 정한 글자가 엑셀에서 수식으로 읽히지 않게, 수식 시작 문자로 시작하면 앞에 ' 를 붙인다(CWE-1236)."""
    return "'" + v if v[:1] in _FORMULA else v


_KOREAN = re.compile(r"naver|kakao|coupang|toss|shinhan|woori|nonghyup|kbstar|hanjin|epost|\.kr\b|[가-힣]", re.I)


def _date(s: str | None) -> str:
    d = s or datetime.now().strftime("%Y%m%d")
    if not _DATE.fullmatch(d):
        raise SystemExit(f"날짜는 YYYYMMDD: {d!r}")
    return d


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _clean_feed(lines: list[str]) -> list[str]:
    """피드 값(믿지 않음): http(s) 주소만, 길이·제어 문자 확인, 중복 제거."""
    out, seen = [], set()
    for u in lines:
        u = u.strip()
        if not u.startswith(("http://", "https://")) or len(u) > 2048 or any(ord(c) < 32 for c in u):
            continue
        if _host(u) and u not in seen:
            seen.add(u)
            out.append(u)
    return out[:MAX_FEED]


def seen_before(date: str) -> tuple[set[str], set[str]]:
    """이전 회차(다른 날짜)의 세트에 넣은 주소·호스트. 같은 사이트를 두 번 세지 않는다."""
    urls, hosts = set(), set()
    for p in FRESH.glob("openphish_*.csv"):
        if p.stem == f"openphish_{date}":
            continue
        for r in _read_csv(p):
            urls.add(r["url"])
            hosts.add(_host(r["url"]))
    return urls, hosts


def new_urls(feed: list[str], urls: set[str], hosts: set[str]) -> list[str]:
    return [u for u in feed if u not in urls and _host(u) not in hosts]


def suggest(r: dict) -> tuple[str, str]:
    """확인 결과 한 줄 → (keep 제안, 이유). Y 넣음 · N 뺌 · ? 직접 판단."""
    title, text = r.get("title") or "", r.get("text") or ""
    if not title:
        return "?", "제목 없음"
    if _SKIP.search(title) or _SKIP.search(r.get("final_url") or r["url"]):
        return "N", "봇 확인·클론·이동 중 화면"
    if _PHISHY.search(title) or _PHISHY.search(text[:300]):
        return "Y", "로그인·브랜드 단서"
    return "?", "단서 약함"


def _alive(probed: list, asked: set[str]) -> list[dict]:
    """워커(침해될 수 있음)가 돌려준 확인 결과: 요청한 주소(asked, 피드에서 http(s) 로 확인한 값)만 받고, 글자 칸은 문자열만."""
    out = []
    for r in probed:
        if not isinstance(r, dict) or not isinstance(r.get("url"), str) or r["url"] not in asked:
            continue
        if r.get("refused") or r.get("error") or r.get("status") != 200 or not isinstance(r.get("bytes"), int) \
                or r["bytes"] <= 300:
            continue
        out.append({**r, **{k: r[k] if isinstance(r.get(k), str) else "" for k in ("final_url", "title", "text")}})
    return out


def candidates(probed: list, asked: set[str]) -> list[dict]:
    alive = _alive(probed, asked)
    rows, per_title = [], Counter()
    for r in alive:
        keep, why = suggest(r)
        if keep == "Y":
            per_title[r["title"]] += 1
            if per_title[r["title"]] > SAME_TITLE_MAX:
                keep, why = "N", "같은 화면 반복"
        if _KOREAN.search(r["url"] + " " + r["title"] + " " + r["text"][:300]):
            why += " · 한국 대상 단서"
        # 주소(url)는 요청한 목록과 맞춘 값이라 그대로(build 가 평가에 씀), 페이지가 정한 칸만 글자로 막는다
        rows.append({"keep": keep, "reason": why, "url": r["url"], "final_url": _cell(r["final_url"]),
                     "title": _cell(r["title"][:120]), "text": _cell(r["text"][:200])})
    order = {"Y": 0, "?": 1, "N": 2}
    return sorted(rows, key=lambda x: (order[x["keep"]], x["title"]))


def _read_csv(p: Path) -> list[dict]:
    for enc in ("utf-8-sig", "cp949"):  # 엑셀로 고쳐 저장하면 cp949 일 수 있다
        try:
            return list(csv.DictReader(p.open(encoding=enc)))
        except UnicodeDecodeError:
            continue
    raise SystemExit(f"인코딩을 읽을 수 없음: {p}")


def _write_csv(p: Path, rows: list[dict], fields: list[str]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8-sig", newline="") as f:  # 엑셀에서 한글이 깨지지 않게 BOM
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def cmd_collect(a) -> None:
    day = FRESH / a.date
    day.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(FEED, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 고정된 https 주소(피드)
        feed = _clean_feed(resp.read(4 * 1024 * 1024).decode("utf-8", errors="replace").splitlines())
    (day / "feed.txt").write_text("\n".join(feed) + "\n", encoding="utf-8")
    urls, hosts = seen_before(a.date)
    todo = new_urls(feed, urls, hosts)
    print(f"피드 {len(feed)}개 · 이전 회차와 겹침 {len(feed) - len(todo)}개 · 확인할 것 {len(todo)}개")
    if not todo:
        return
    (day / "probe.txt").write_text("\n".join(todo) + "\n", encoding="utf-8")
    probe_urls._run_host(day / "probe.txt", day / "probe.jsonl", a.workers)
    probed = [json.loads(x) for x in (day / "probe.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    rows = candidates(probed, set(todo))
    _write_csv(day / "candidates.csv", rows, ["keep", "reason", "url", "final_url", "title", "text"])
    c = Counter(r["keep"] for r in rows)
    print(f"살아 있음 {len(rows)}개 → 제안 Y {c['Y']} · ? {c['?']} · N {c['N']}")
    print(f"검토: {(day / 'candidates.csv').relative_to(ROOT)} 의 keep 을 Y/N 으로 정한 뒤 build")


def cmd_build(a) -> None:
    src = FRESH / a.date / "candidates.csv"
    rows = [r for r in _read_csv(src) if (r.get("keep") or "").strip().upper() == "Y"]
    if not rows:
        raise SystemExit("keep=Y 인 후보가 없다")
    urls, hosts = seen_before(a.date)
    out, seen = [], set()
    for r in rows:
        u = r["url"].strip()
        if u in urls or _host(u) in hosts or u in seen or not u.startswith(("http://", "https://")):
            continue
        seen.add(u)
        out.append({"group": "fresh", "expected": "malicious", "url": u,
                    "note": f"OpenPhish {a.date}, {(r.get('title') or '').strip()[:60]}"})
    dst = FRESH / f"openphish_{a.date}.csv"
    with dst.open("w", encoding="utf-8", newline="") as f:  # 평가 도구는 utf-8(BOM 없음)로 읽는다
        w = csv.DictWriter(f, fieldnames=["group", "expected", "url", "note"], lineterminator="\n")
        w.writeheader()
        w.writerows(out)
    print(f"{dst.relative_to(ROOT)}: {len(out)}개")


def cmd_eval(a) -> None:
    dst = FRESH / f"openphish_{a.date}.csv"
    if not dst.exists():
        raise SystemExit(f"{dst.relative_to(ROOT)} 가 없다: 먼저 build")
    subprocess.run([sys.executable, str(ROOT / "tools" / "eval_agent.py"), "run", "--repeat", str(REPEAT),
                    "--set", str(dst.relative_to(ROOT)), "--label", f"fresh_{a.date}"], cwd=ROOT, check=True)


# 하루 한 번 도는 평가의 라벨(cmd_eval 의 fresh_<날짜>, 도구 전 첫 회는 fresh_openphish)
_DAILY_LABEL = re.compile(r"^fresh_(openphish|\d{8})$")


def fresh_runs() -> list[tuple[dict, list[dict]]]:
    """하루 한 번 돈 실사이트 평가 결과마다 (메타, 기록). 같은 라벨은 처음 것만 센다. 같은 세트를 개선 전후 측정용으로
    다시 돌린 결과(라벨 fresh_20261015_discovery 등)는 넣지 않는다 — 넣으면 같은 날을 여러 번 세어 누적이 부풀었다."""
    out, seen = [], set()
    for p in sorted(EVAL.glob("*.jsonl")):
        lines = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
        meta = next((x for x in lines if x.get("meta")), {})
        label = str(meta.get("label") or "")
        if _DAILY_LABEL.match(label) and label not in seen:
            seen.add(label)
            out.append((meta, [x for x in lines if not x.get("meta")]))
    return out


def rule_of(r: dict) -> str | None:
    """이 회차에서 코드 규칙이 모델 판단(정상·판단 불가)을 바꿨으면 규칙 이름. 평가 도구가 규칙 이름을 남기기 전 기록(rule 칸 없음)은
    규칙이 남기는 모양(위협·확률 1.0·보류)으로 세고, 도착 주소가 브랜드 공식 사이트면 official_redirect 로 본다."""
    if "rule" in r:  # 조사 컨테이너가 쓴 값이라 믿지 않는다: 규칙 이름 모양이 아니면 '코드 규칙'(표가 깨지지 않게)
        name = r.get("rule")
        if not isinstance(name, str) or not name:
            return None
        return name if _RULE_NAME.fullmatch(name) else "코드 규칙"
    p = r.get("probability")
    if not (r.get("hold") is True and r.get("threat") not in (None, "benign", "unknown")
            and isinstance(p, (int, float)) and not isinstance(p, bool) and p >= 0.999):
        return None
    moved = official_brand(_host(str(r.get("final_url") or ""))) and not official_brand(_host(str(r.get("url") or "")))
    return "official_redirect" if moved else "코드 규칙"


def summary_md(runs: list[tuple[dict, list[dict]]]) -> str:
    """날마다 사이트가 달라 정답률은 개선 추세가 아니다. 품질 지표로 '검토 없이 끝난 비율'(담당자가 모르고 넘어간 놓침)과
    '코드 규칙이 잡은 회차'(이전에 놓쳐 고친 유형이 새 사이트에서 다시 나왔을 때 잡았는지)를 함께 본다."""
    lines = ["# 오늘의 실사이트 세트 누적", "",
             "OpenPhish 무료 피드에서 그날 살아 있던 피싱 사이트를 골라 같은 날 3회 조사한 결과. 주소는 git 밖(var/fresh).", "",
             "| 날짜 | 사이트 | 채점 | 정답 | 놓침(검토 없이 끝남) | 검토 없이 끝난 비율 | 담당자 검토로 감 | 코드 규칙이 잡음(이전에 고친 유형) "
             "| Safe Browsing 일치(조사 당시) | 제외 |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    tot, sites, rules_all, rule_sites_all = Counter(), set(), Counter(), set()

    def sb_cell(m: dict) -> str:
        """조사 당시 Safe Browsing 만 썼다면 위협으로 표시됐을 회차. 평가 도구가 sb 를 남기기 전 기록은 '-'."""
        if not m["measured"]:
            return "-"
        return f"{m['sb_own']}/{m['measured']} ({eval_agent._pct(m['sb_own'], m['measured'])})"

    def rule_cell(rules: Counter, rsites: set) -> str:
        if not rules:
            return "0"
        names = ", ".join(f"{k} {v}" for k, v in rules.most_common())
        return f"{sum(rules.values())}회 · {len(rsites)}곳 ({names})"

    for meta, recs in runs:
        m = eval_agent.summarize(recs).get("전체")
        if not m:
            continue
        urls = {r["url"] for r in recs}
        sites |= urls
        for k in ("scored", "correct", "missed", "missed_auto", "review", "skipped"):
            tot[k] += m[k]
        rules, rsites = Counter(), set()
        for r in recs:
            name = rule_of(r)
            if name:
                rules[name] += 1
                rsites.add(r["url"])
        rules_all.update(rules)
        rule_sites_all |= rsites
        sb = eval_agent.sb_summary(recs)["전체"]
        tot["sb_measured"] += sb["measured"]
        tot["sb_own"] += sb["sb_own"]
        lines.append(f"| {str(meta.get('started', ''))[:10]} | {len(urls)} | {m['scored']} | "
                     f"{m['correct']} ({eval_agent._pct(m['correct'], m['scored'])}) | {m['missed']} ({m['missed_auto']}) | "
                     f"{eval_agent._pct(m['missed_auto'], m['scored'])} | {m['review']} | {rule_cell(rules, rsites)} | "
                     f"{sb_cell(sb)} | {m['skipped']} |")
    lines.append(f"| **누적** | **{len(sites)}** | {tot['scored']} | **{tot['correct']} "
                 f"({eval_agent._pct(tot['correct'], tot['scored'])})** | {tot['missed']} ({tot['missed_auto']}) | "
                 f"**{eval_agent._pct(tot['missed_auto'], tot['scored'])}** | {tot['review']} | "
                 f"**{rule_cell(rules_all, rule_sites_all)}** | "
                 f"{sb_cell({'measured': tot['sb_measured'], 'sb_own': tot['sb_own']})} | {tot['skipped']} |")
    lines += ["",
              "- 날마다 사이트가 달라 정답률은 개선 추세가 아니다. 품질은 **검토 없이 끝난 비율**(담당자가 모르고 넘어간 놓침)과 "
              "**코드 규칙이 잡음**(전에 놓쳐서 고친 유형이 그날의 새 사이트에서 다시 나왔을 때, 모델은 정상·판단 불가로 봤지만 규칙이 "
              "담당자 검토로 보낸 회차)으로 본다. 모델이 스스로 위협으로 본 회차는 규칙 칸에 세지 않는다.",
              "- 평가 도구가 규칙 이름을 남기기 전 기록은 규칙이 남기는 모양(위협·확률 1.0·보류)으로 세고, 도착 주소가 브랜드 공식 사이트면 "
              "official_redirect 로 본다(그 밖은 '코드 규칙').",
              "- **Safe Browsing 일치(조사 당시)**: 그 회차에 SafeTrace 가 조사하며 받은 Safe Browsing 조회에서 신고·경유·최종 주소가 "
              "일치한 회차(Safe Browsing 만 썼다면 위협으로 표시됐을 것). 정답 칸과 견준다. 평가 도구가 이 값을 남기기 전 회차는 '-'."]
    return "\n".join(lines) + "\n"


def cmd_summary(a) -> None:
    md = summary_md(fresh_runs())
    FRESH.mkdir(parents=True, exist_ok=True)
    (FRESH / "SUMMARY.md").write_text(md, encoding="utf-8")
    print(md)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("collect", "build", "eval", "summary"):
        p = sub.add_parser(name)
        p.add_argument("--date")
        if name == "collect":
            p.add_argument("--workers", type=int, default=16)
    a = ap.parse_args()
    a.date = _date(a.date)
    {"collect": cmd_collect, "build": cmd_build, "eval": cmd_eval, "summary": cmd_summary}[a.cmd](a)


if __name__ == "__main__":
    main()

"""에이전트 품질 평가: 정답을 붙인 URL 목록(data/eval_set.csv)을 여러 번 조사해
판정 정확도·놓침·오탐·일관성·시간을 잰다. 모델 판단은 매번 조금씩 달라서 한 번 돌린 결과로는 비교하기 어렵다.

실행(호스트, `docker compose --profile demo up` 상태에서. 표준 라이브러리만 쓴다):
  python tools/eval_agent.py run [--repeat 3] [--group kisa] [--label 메모]
      에이전트 컨테이너 안에서 조사하고 결과를 var/eval/<시각>_<메모>.jsonl 과 .md 로 받아 온다
  python tools/eval_agent.py report var/eval/A.jsonl
  python tools/eval_agent.py compare var/eval/A.jsonl var/eval/B.jsonl

정답(expected): phishing·scam·illegal_gambling·malware·benign, 또는 유형을 가리지 않는 malicious.
조사 증거는 컨테이너의 임시 폴더에 쓴다(콘솔 사건 목록·증거 볼륨을 더럽히지 않음).

평가 목록 관리: KISA 주소는 시간이 지나면 사라진다. 접속 불가(UNREACHABLE)는 채점에서 빼고 따로 세므로,
그런 행이 늘면 목록을 갱신한다. 지금 도착 화면이 정상 페이지로 바뀐 주소(쇼핑몰 상품·도메인 판매·
단축 URL 서비스의 자체 검사 화면)는 정답을 정할 수 없어 넣지 않았다.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import subprocess
import sys
import time
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MALICIOUS = {"phishing", "scam", "illegal_gambling", "malware"}
SKIP_STATUS = {"UNREACHABLE", "BLOCKED"}
IN_BOX = "/tmp/eval"  # 에이전트 컨테이너 안 작업 폴더


# ── 채점(순수 함수) ─────────────────────────────────────────
def outcome(expected: str, rec: dict) -> str:
    """한 번의 조사 결과를 채점한다.

    correct: 맞음 / wrong_type: 위협은 맞게 봤지만 유형이 다름 / unsure: 판단 불가(unknown)
    missed: 위협을 정상으로 봄 / false_alarm: 정상을 위협으로 봄 / skipped: 접속 불가 등 채점 제외
    """
    if rec.get("error") or rec.get("status") in SKIP_STATUS:
        return "skipped"
    threat = rec.get("threat") or "unknown"
    if expected == "benign":
        if threat == "benign":
            return "correct"
        return "false_alarm" if threat in MALICIOUS else "unsure"
    if threat == "benign":
        return "missed"
    if threat not in MALICIOUS:
        return "unsure"
    return "correct" if expected in ("malicious", threat) else "wrong_type"


def _pct(n: int, d: int) -> str:
    return f"{n * 100 / d:.0f}%" if d else "-"


def summarize(recs: list[dict]) -> dict[str, dict]:
    """그룹별(+전체) 지표."""
    groups: dict[str, list[dict]] = {}
    for r in recs:
        groups.setdefault(r["group"], []).append(r)
        groups.setdefault("전체", []).append(r)
    out = {}
    for g, rs in groups.items():
        oc = Counter(outcome(r["expected"], r) for r in rs)
        scored = [r for r in rs if outcome(r["expected"], r) != "skipped"]
        n = len(scored)
        by_url: dict[str, list[str]] = {}
        for r in scored:
            by_url.setdefault(r["url"], []).append(r.get("threat") or "unknown")
        multi = [ts for ts in by_url.values() if len(ts) > 1]
        secs = sorted(r["seconds"] for r in scored)
        out[g] = {
            "runs": len(rs), "scored": n, "skipped": oc["skipped"],
            "correct": oc["correct"], "wrong_type": oc["wrong_type"], "unsure": oc["unsure"],
            "missed": oc["missed"], "false_alarm": oc["false_alarm"],
            # 담당자 검토 없이 끝난 놓침: 가장 위험한 오류
            "missed_auto": sum(1 for r in scored if outcome(r["expected"], r) == "missed"
                               and r.get("status") == "COMPLETED"),
            "review": sum(1 for r in scored if r.get("status") == "REVIEW_REQUIRED"),
            "consistent": sum(1 for ts in multi if len(set(ts)) == 1), "repeated_urls": len(multi),
            "sec_median": statistics.median(secs) if secs else 0.0,
            "sec_p90": secs[min(len(secs) - 1, int(len(secs) * 0.9))] if secs else 0.0,
        }
    return out


def _metric_rows(m: dict) -> list[tuple[str, str]]:
    n = m["scored"]
    return [
        ("채점 / 제외", f"{n} / {m['skipped']}"),
        ("정답", f"{m['correct']} ({_pct(m['correct'], n)})"),
        ("유형 틀림", str(m["wrong_type"])),
        ("판단 불가", f"{m['unsure']} ({_pct(m['unsure'], n)})"),
        ("놓침(정상으로 봄)", f"{m['missed']} (검토 없이 끝남 {m['missed_auto']})"),
        ("오탐(정상을 위협으로)", str(m["false_alarm"])),
        ("담당자 검토로 감", f"{m['review']} ({_pct(m['review'], n)})"),
        ("반복 일관성", f"{m['consistent']}/{m['repeated_urls']} URL"),
        ("시간 중앙값 / p90", f"{m['sec_median']:.1f}s / {m['sec_p90']:.1f}s"),
    ]


def report(recs: list[dict], meta: dict | None = None) -> str:
    lines = ["# 에이전트 평가"]
    if meta:
        lines.append(f"\n{meta.get('started', '')} · 반복 {meta.get('repeat')} · 코드 {meta.get('git', '')}"
                     f"{' · ' + meta['label'] if meta.get('label') else ''}")
    summ = summarize(recs)
    groups = [g for g in summ if g != "전체"] + ["전체"]
    lines += ["", "| 지표 | " + " | ".join(groups) + " |", "|---|" + "---|" * len(groups)]
    rows = {g: _metric_rows(summ[g]) for g in groups}
    for i, (name, _) in enumerate(rows[groups[0]]):
        lines.append(f"| {name} | " + " | ".join(rows[g][i][1] for g in groups) + " |")
    lines += ["", "## URL별", "", "| 그룹 | 정답 | URL | 판정(반복) | 채점 |", "|---|---|---|---|---|"]
    by_url: dict[str, list[dict]] = {}
    for r in recs:
        by_url.setdefault(r["url"], []).append(r)
    for url, rs in by_url.items():
        ts = Counter((r.get("threat") or r.get("status", "?")) + ("(보류)" if r.get("hold") else "") for r in rs)
        oc = Counter(outcome(r["expected"], r) for r in rs)
        lines.append(f"| {rs[0]['group']} | {rs[0]['expected']} | {url} | "
                     f"{', '.join(f'{k}×{v}' for k, v in ts.most_common())} | "
                     f"{', '.join(f'{k}×{v}' for k, v in oc.most_common())} |")
    return "\n".join(lines) + "\n"


def compare(a: list[dict], b: list[dict], name_a: str, name_b: str) -> str:
    sa, sb = summarize(a), summarize(b)
    lines = [f"# 평가 비교: {name_a} → {name_b}", ""]
    for g in [g for g in sb if g != "전체"] + ["전체"]:
        if g not in sa:
            continue
        lines += [f"## {g}", "", "| 지표 | 전 | 후 |", "|---|---|---|"]
        for (name, va), (_, vb) in zip(_metric_rows(sa[g]), _metric_rows(sb[g])):
            lines.append(f"| {name} | {va} | {vb} |")
        lines.append("")
    # URL별로 정답 비율이 달라진 것
    def rate(recs):
        acc: dict[str, list[int]] = {}
        for r in recs:
            o = outcome(r["expected"], r)
            if o != "skipped":
                acc.setdefault(r["url"], []).append(o == "correct")
        return {u: sum(v) / len(v) for u, v in acc.items()}

    ra, rb = rate(a), rate(b)
    changed = [(u, ra[u], rb[u]) for u in rb if u in ra and abs(ra[u] - rb[u]) >= 0.34]
    if changed:
        lines += ["## 정답 비율이 달라진 URL", "", "| URL | 전 | 후 |", "|---|---|---|"]
        lines += [f"| {u} | {x:.0%} | {y:.0%} |" for u, x, y in sorted(changed, key=lambda c: c[2] - c[1])]
    return "\n".join(lines) + "\n"


# ── 실행 ────────────────────────────────────────────────
def load_set(path: Path, group: str | None) -> list[dict]:
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    return [r for r in rows if not group or r["group"] == group]


def run_inside(args) -> None:
    """에이전트 컨테이너 안에서 실행: 조사하고 결과를 한 줄씩 쓴다."""
    sys.path.insert(0, "/app")
    from safetrace.agent.runner import investigate
    from safetrace.config import Settings

    rows = load_set(Path(args.set), args.group)
    s = Settings(evidence_dir=Path(IN_BOX) / "evidence")
    with open(args.out, "a", encoding="utf-8") as f:
        for rep in range(args.repeat):
            for row in rows:  # 한 URL 을 연달아 돌리지 않고 목록을 한 바퀴씩 돈다(시간대 편차 분산)
                cid = str(uuid.uuid4())
                rec = {"group": row["group"], "expected": row["expected"], "url": row["url"], "repeat": rep}
                t = time.monotonic()
                try:
                    final = investigate(cid, row["url"], s, emit=lambda e: None)
                    th = final.get("threat") or {}
                    rec.update(status=final["status"], reason=final["reason"], threat=th.get("threat"),
                               probability=th.get("probability"), hold=th.get("hold"),
                               final_url=(final.get("final_url") or "")[:200])
                    chain = s.evidence_dir / cid / "chain.jsonl"
                    kinds = [json.loads(x) for x in chain.read_text(encoding="utf-8").splitlines()]
                    fin = next((k["data"] for k in kinds if k["kind"] == "finish"), {})
                    rec["steps"] = sum(1 for k in kinds if k["kind"] == "action")
                    rec["blocked_destinations"] = [b["host"] for b in fin.get("blocked_destinations", [])]
                except Exception as e:  # 한 건 실패로 전체를 멈추지 않는다
                    rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
                rec["seconds"] = round(time.monotonic() - t, 1)
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
                print(f"[{rep + 1}/{args.repeat}] {rec['seconds']:6.1f}s {rec.get('threat') or rec.get('status')}"
                      f" ({outcome(rec['expected'], rec)}) {row['url']}", flush=True)


def _git() -> str:
    try:
        head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True,
                              text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "backend"], cwd=ROOT,
                               capture_output=True, text=True).stdout.strip()
        return head + ("+수정" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "?"


def run_host(args) -> None:
    """호스트에서 실행: 스크립트·목록을 에이전트 컨테이너에 넣고 조사한 뒤 결과를 받아 온다."""
    dc = ["docker", "compose"]
    started = datetime.now()
    name = started.strftime("%Y%m%d-%H%M") + (f"_{args.label}" if args.label else "")
    out_dir = ROOT / "var" / "eval"
    out_dir.mkdir(parents=True, exist_ok=True)
    local = out_dir / f"{name}.jsonl"
    meta = {"meta": True, "started": started.isoformat(timespec="minutes"), "repeat": args.repeat,
            "group": args.group, "label": args.label, "git": _git()}
    subprocess.run(dc + ["exec", "-T", "agent", "sh", "-c", f"rm -rf {IN_BOX} && mkdir -p {IN_BOX}"],
                   cwd=ROOT, check=True)
    for src in (Path(__file__), ROOT / args.set):
        subprocess.run(dc + ["cp", str(src), f"agent:{IN_BOX}/{src.name}"], cwd=ROOT, check=True,
                       capture_output=True)
    cmd = ["python", "-u", f"{IN_BOX}/eval_agent.py", "run", "--inside", "--repeat", str(args.repeat),
           "--set", f"{IN_BOX}/{Path(args.set).name}", "--out", f"{IN_BOX}/out.jsonl"]
    if args.group:
        cmd += ["--group", args.group]
    try:
        # 조사 로그(INFO)는 줄이고 진행 줄만 보여 준다
        proc = subprocess.Popen(dc + ["exec", "-T", "-w", "/app", "agent", *cmd], cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                errors="replace")
        for line in proc.stdout:
            if line.startswith("[") or "Error" in line or "Traceback" in line:
                print(line, end="", flush=True)
        proc.wait()
    finally:
        # 중간에 멈춰도 그때까지의 결과는 받아 온다
        tmp = out_dir / f"{name}.part"
        got = subprocess.run(dc + ["cp", f"agent:{IN_BOX}/out.jsonl", str(tmp)], cwd=ROOT, capture_output=True)
        if got.returncode == 0:
            local.write_text(json.dumps(meta, ensure_ascii=False) + "\n" + tmp.read_text(encoding="utf-8"),
                             encoding="utf-8")
            tmp.unlink()
            md = report(load_results(local), meta)
            local.with_suffix(".md").write_text(md, encoding="utf-8")
            print("\n" + md)
            print(f"결과: {local.relative_to(ROOT)}")


def load_results(path: Path) -> list[dict]:
    return [r for r in (json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip())
            if not r.get("meta")]


def load_meta(path: Path) -> dict | None:
    first = path.read_text(encoding="utf-8").split("\n", 1)[0]
    m = json.loads(first) if first.strip() else {}
    return m if m.get("meta") else None


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows 콘솔(cp949)에서도 표가 깨지지 않게
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--repeat", type=int, default=3)
    r.add_argument("--group", help="testpage | normal | kisa 중 하나만")
    r.add_argument("--label", default="", help="결과 파일 이름에 붙일 메모")
    r.add_argument("--set", default="data/eval_set.csv")
    r.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    r.add_argument("--out", help=argparse.SUPPRESS)
    p = sub.add_parser("report")
    p.add_argument("results", type=Path)
    c = sub.add_parser("compare")
    c.add_argument("a", type=Path)
    c.add_argument("b", type=Path)
    args = ap.parse_args()
    if args.cmd == "run":
        (run_inside if args.inside else run_host)(args)
    elif args.cmd == "report":
        print(report(load_results(args.results), load_meta(args.results)))
    else:
        print(compare(load_results(args.a), load_results(args.b), args.a.stem, args.b.stem))


if __name__ == "__main__":
    main()

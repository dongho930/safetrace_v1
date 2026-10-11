"""영역별 줄 수와 bandit 발견 건수(전체 등급)를 재서 '1,000줄당 약점 수'를 보여 준다.

2라운드 보안 평가의 1순위 기준이 '빌드 라인당 소스코드 보안약점 수'다(줄 수에 주석 포함, 빈 줄 포함 여부는 미확인).
평가위원 도구가 무엇인지 모르므로 bandit 전체 등급(LOW 포함)으로 대신 잰다. 실패시키지 않고 숫자만 보여 준다.

실행: python tools/weakness_density.py            # 저장소 루트에서, bandit 이 설치된 Python 으로
      python tools/weakness_density.py --json     # 기계가 읽는 형식
"""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404 - 고정된 인자로 bandit 만 실행한다
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# (영역 이름, 경로, 설명). 서비스 코드가 제출 대상의 중심이고, 나머지는 제출 범위가 정해지면 판단한다
AREAS = [
    ("서비스", "backend/safetrace", "백엔드·에이전트·서명·판단 서비스"),
    ("시험", "backend/tests", "pytest"),
    ("도구", "tools", "평가·검토 스크립트"),
    ("시험 페이지", "testpages", "공격 흉내 페이지 서버"),
]
FRONTEND = ("프론트엔드", "frontend/src", "React·TypeScript (bandit 대상 아님)")


def count_lines(path: Path, suffixes: tuple[str, ...]) -> tuple[int, int]:
    """(전체 줄 수, 빈 줄을 뺀 줄 수). 주석은 포함한다."""
    total = nonblank = 0
    for f in sorted(path.rglob("*")):
        if f.suffix in suffixes and f.is_file() and "__pycache__" not in f.parts and "node_modules" not in f.parts:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            total += len(lines)
            nonblank += sum(1 for x in lines if x.strip())
    return total, nonblank


def bandit(path: Path) -> list[dict]:
    r = subprocess.run([sys.executable, "-m", "bandit", "-r", str(path), "-f", "json", "-q"],  # nosec B603
                       capture_output=True, text=True, encoding="utf-8", check=False)
    try:
        return json.loads(r.stdout)["results"]
    except (ValueError, KeyError):
        raise SystemExit(f"bandit 실행 실패: {r.stderr.strip()[:300]}") from None


def measure() -> list[dict]:
    rows = []
    for name, rel, desc in AREAS:
        p = ROOT / rel
        total, nonblank = count_lines(p, (".py",))
        found = bandit(p)
        rows.append({"area": name, "path": rel, "desc": desc, "lines": total, "nonblank": nonblank,
                     "findings": len(found), "by_severity": dict(Counter(x["issue_severity"] for x in found)),
                     "by_rule": dict(Counter(x["test_id"] for x in found).most_common(5))})
    total, nonblank = count_lines(ROOT / FRONTEND[1], (".ts", ".tsx"))
    rows.append({"area": FRONTEND[0], "path": FRONTEND[1], "desc": FRONTEND[2], "lines": total, "nonblank": nonblank,
                 "findings": None, "by_severity": {}, "by_rule": {}})
    return rows


def per_k(findings: int | None, lines: int) -> str:
    return "-" if findings is None or not lines else f"{findings * 1000 / lines:.1f}"


def markdown(rows: list[dict]) -> str:
    out = ["## 약점 밀도 (bandit 전체 등급, 줄 수는 주석 포함)", "",
           "| 영역 | 경로 | 줄 수 (빈 줄 제외) | 발견 (등급별) | 1,000줄당 | 많은 규칙 |",
           "|---|---|---|---|---|---|"]
    for r in rows:
        sev = ", ".join(f"{k} {v}" for k, v in sorted(r["by_severity"].items()))
        rules = ", ".join(f"{k}×{v}" for k, v in r["by_rule"].items())
        found = "-" if r["findings"] is None else f"{r['findings']}" + (f" ({sev})" if sev else "")
        out.append(f"| {r['area']} | `{r['path']}` | {r['lines']:,} ({r['nonblank']:,}) | {found} | "
                   f"{per_k(r['findings'], r['lines'])} | {rules} |")
    py = [r for r in rows if r["findings"] is not None]
    svc = py[0]
    allf, alll = sum(r["findings"] for r in py), sum(r["lines"] for r in py)
    out += ["", f"- 서비스 코드만: **{per_k(svc['findings'], svc['lines'])}** / 1,000줄",
            f"- Python 전체(시험·도구·시험 페이지 포함): {per_k(allf, alll)} / 1,000줄",
            "- 평가위원 도구와 다를 수 있다. 제출 범위는 코드 동결 뒤 정한다."]
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    rows = measure()
    print(json.dumps(rows, ensure_ascii=False, indent=1) if args.json else markdown(rows))


if __name__ == "__main__":
    main()

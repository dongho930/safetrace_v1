"""KISA 피싱사이트 URL(공공데이터포털 파일 데이터) CSV 를 사건으로 접수한다.

공공데이터포털에서 '한국인터넷진흥원_피싱사이트 URL' 파일을 내려받아 사용한다.
URL 열 이름은 자동 감지(이름에 'url' 포함). 기본은 dry-run 이며 --submit 일 때만 API 로 접수한다.
KISA 데이터는 스킴 없이 도메인만 있는 경우가 있어 http:// 를 붙인다.

실행: python tools/import_kisa.py data/kisa_phishing.csv --limit 20 [--submit --api http://localhost:8080 --token ...]
"""

import argparse
import csv
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import httpx  # noqa: E402

from safetrace.netguard import BlockedURL, parse_url  # noqa: E402


def read_urls(path: Path) -> list[str]:
    for enc in ("utf-8-sig", "cp949"):
        try:
            rows = list(csv.DictReader(path.open(encoding=enc)))
            break
        except UnicodeDecodeError:
            continue
    else:
        raise SystemExit("인코딩을 읽을 수 없음")
    if not rows:
        return []
    col = next((k for k in rows[0] if k and "url" in k.lower()), None)
    if not col:
        raise SystemExit(f"URL 열을 찾지 못함: {list(rows[0])}")
    out, seen = [], set()
    for r in rows:
        u = (r.get(col) or "").strip()
        if not u:
            continue
        if "://" not in u:
            u = "http://" + u
        try:
            parse_url(u, [80, 443])
        except BlockedURL:
            continue
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--submit", action="store_true")
    ap.add_argument("--api", default="http://localhost:8080")
    ap.add_argument("--token", default="")
    ap.add_argument("--interval", type=float, default=2.0)
    a = ap.parse_args()
    urls = read_urls(a.csv)[: a.limit]
    print(f"{len(urls)} urls")
    if not a.submit:
        for u in urls:
            print("  ", u)
        return
    with httpx.Client(base_url=a.api, headers={"Authorization": f"Bearer {a.token}"}, timeout=10) as c:
        for u in urls:
            r = c.post("/api/cases", json={"url": u, "source": "kisa"}, headers={"Idempotency-Key": str(uuid.uuid4())})
            print(r.status_code, u)
            time.sleep(a.interval)


if __name__ == "__main__":
    main()

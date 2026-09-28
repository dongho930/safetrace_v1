"""정상 사이트 목록의 접속 가능 여부를 확인한다(요청 간격 준수, 사이트당 GET 1회).

실행: python tools/check_normal_sites.py [--interval 1.0]
결과: data/normal_sites_checked.csv (status, final_url, error)
"""

import argparse
import csv
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=1.0)
    a = ap.parse_args()
    rows = list(csv.DictReader((ROOT / "data/normal_sites.csv").open(encoding="utf-8")))
    out = []
    with httpx.Client(timeout=10, follow_redirects=True, headers={"User-Agent": UA}) as c:
        for i, r in enumerate(rows, 1):
            status, final, err = "", "", ""
            try:
                resp = c.get(r["url"])
                status, final = str(resp.status_code), str(resp.url)
            except httpx.HTTPError as e:
                err = type(e).__name__
            out.append({**r, "status": status, "final_url": final, "error": err})
            print(f"[{i}/{len(rows)}] {r['name']}: {status or err}", file=sys.stderr)
            time.sleep(a.interval)
    with (ROOT / "data/normal_sites_checked.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    ok = sum(1 for r in out if r["status"].startswith(("2", "3")))
    print(f"reachable {ok}/{len(out)}")


if __name__ == "__main__":
    main()

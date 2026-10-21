"""에이전트 품질 평가: 정답을 붙인 URL 목록(data/eval_set.csv)을 여러 번 조사해
판정 정확도·놓침·오탐·일관성·시간을 잰다. 모델 판단은 매번 조금씩 달라서 한 번 돌린 결과로는 비교하기 어렵다.

실행(호스트, `docker compose --profile demo up` 상태에서. 표준 라이브러리만 쓴다):
  python tools/eval_agent.py run [--repeat 3] [--group kisa] [--label 메모]
      에이전트 컨테이너 안에서 조사하고 결과를 var/eval/<시각>_<메모>.jsonl 과 .md 로 받아 온다
  python tools/eval_agent.py report var/eval/A.jsonl
  python tools/eval_agent.py compare var/eval/A.jsonl var/eval/B.jsonl
  python tools/eval_agent.py run --repeat 1 --set data/normal_sites.csv --label normal168
      정상 사이트 168곳 목록으로 오탐률(모두 정답 benign)
  python tools/eval_agent.py related var/eval/A.jsonl
      연관 후보 하위 조사 결과를 사람이 확인할 표본 목록으로 낸다(var/eval/A_related.csv, git 밖)

정답(expected): phishing·scam·illegal_gambling·malware·benign, 또는 유형을 가리지 않는 malicious.
연관 사이트 발견(docs/related-sites.md): 하위 조사는 원래 판정을 바꾸지 않으므로 정답률과 따로 잰다
(하위 조사 비율, 위협 발견 비율, 발견 사이트 수, 회선 차단 추정 아닌 비율, 후보 1곳당 시간, 원래 결과까지 시간).
외부 평판 비교: 조사할 때 SafeTrace 가 받은 Safe Browsing 조회 결과를 기록(sb)에 남겨, 같은 순간에
'Safe Browsing 만 썼다면'과 SafeTrace 의 판단을 견준다(나중에 다시 조회하면 그사이 목록이 늘어 Safe Browsing 에 유리하다).
조사 증거는 컨테이너의 임시 폴더에 쓴다(콘솔 사건 목록·증거 볼륨을 더럽히지 않음).

평가 목록 관리: KISA 주소는 시간이 지나면 사라진다. 접속 불가(UNREACHABLE)는 채점에서 빼고 따로 세므로,
그런 행이 늘면 목록을 갱신한다. 지금 도착 화면이 정상 페이지로 바뀐 주소(쇼핑몰 상품·도메인 판매·
단축 URL 서비스의 자체 검사 화면)는 정답을 정할 수 없어 넣지 않았다.
"""

from __future__ import annotations

import argparse
import csv
import json
import secrets
import statistics
import subprocess
import sys
import time
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

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


# ── 연관 사이트 발견(순수 함수) ─────────────────────────────
def related_item(c: dict, site_of) -> dict:
    """최종 상태의 후보 하나를 평가 기록용으로 줄인다. 값은 조사 대상 페이지에서 온 글자다(공격자 값)."""
    url = str(c.get("url") or "")[:2048]
    host = str(c.get("host") or urlsplit(url).hostname or "")[:253]
    return {"url": url, "host": host, "site": site_of(host) if host else None, "source": c.get("source"),
            "sub": c.get("sub"), "status": c.get("status"), "reason": c.get("reason"),
            "final_url": str(c.get("final_url") or "")[:2048] or None, "threat": c.get("threat"),
            "probability": c.get("probability"), "hold": c.get("hold"),
            "reputation_match": bool(c.get("reputation_match")),
            "blocked": c.get("blocked") if isinstance(c.get("blocked"), bool) else None,  # PR 2 부터
            "brand_name": c.get("brand_name") is True}  # 개선 후보 9 부터(그 전 기록은 False)


def _is_threat(c: dict) -> bool:
    return c.get("threat") not in (None, "benign", "unknown")


AUTO_MIN_PROB = 0.6  # 설정 threat_min_prob 기본값(자동 사건의 조건 4 는 원래 사건이 위협으로 보는 기준과 같다)


def _related_module():
    try:
        if str(ROOT / "backend") not in sys.path:
            sys.path.insert(0, str(ROOT / "backend"))
        from safetrace import related
    except ImportError:  # 이전 코드(PR 4b 전) 컨테이너
        return None
    return related


def auto_targets(r: dict) -> list[dict]:
    """related-sites PR 4b: 자동 사건을 만들 후보(API 와 같은 safetrace.related.auto_targets, 조건 1~6·10). 중복·한도(7~9)는
    시점에 따라 바뀌어 빼고 센다. 평가 목록의 원 사건은 연관 사건이 아니다."""
    rel = _related_module()
    if rel is None:
        return []
    return [c for c, _ in rel.auto_targets("report", r.get("related") or [], enabled=True, threat_min_prob=AUTO_MIN_PROB)]


def brand_outs(r: dict) -> list[dict]:
    """조건 10(피싱 키트가 링크한 진짜 브랜드 사이트, 서버 목록)이 자동 접수에서 뺀 후보. 조건 10 은 마지막 조건이라
    이유가 brand_site 면 나머지 조건은 모두 통과했다."""
    rel = _related_module()
    if rel is None or not hasattr(rel, "real_brand_site"):
        return []
    return [c for c in r.get("related") or [] if isinstance(c, dict) and isinstance(c.get("url"), str)
            and rel.skip_reason("report", c, enabled=True, threat_min_prob=AUTO_MIN_PROB) == "brand_site"]


def related_summary(recs: list[dict]) -> dict[str, dict]:
    """그룹별(+전체) 연관 사이트 발견 지표. 기록에 related 가 없으면(이전 평가) measured 가 0 이다."""
    groups: dict[str, list[dict]] = {}
    for r in recs:
        groups.setdefault(r["group"], []).append(r)
        groups.setdefault("전체", []).append(r)
    out = {}
    for g, rs in groups.items():
        scored = [r for r in rs if outcome(r["expected"], r) != "skipped"]
        measured = [r for r in scored if isinstance(r.get("related"), list)]
        subs = [r for r in measured if any(c.get("sub") for c in r["related"])]
        hits = [r for r in subs if any(c.get("sub") and _is_threat(c) for c in r["related"])]
        found = [c for r in subs for c in r["related"] if c.get("sub") and _is_threat(c)]
        sites = {c["site"] for c in found if c.get("site")}
        known = [c for c in found if isinstance(c.get("blocked"), bool)]
        open_sites = {c["site"] for c in known if not c["blocked"] and c.get("site")}
        n_sub = sum(1 for r in subs for c in r["related"] if c.get("sub"))
        mains = sorted(r.get("seconds_main", r["seconds"]) for r in measured)
        autos = [c for r in measured for c in auto_targets(r)]
        brand_out = [c for r in measured for c in brand_outs(r)]
        # 참고: 원 사건 제목과 이름이 같은데 자동 접수 대상인 위협 후보 — 진짜 사이트면 related.KIT_LINKED_REAL_SITES 에 보탠다
        name_hits = [c for c in autos if c.get("brand_name") is True]
        extra = sum(r["seconds"] - r.get("seconds_main", r["seconds"]) for r in subs)
        out[g] = {"scored": len(scored), "measured": len(measured), "sub_runs": len(subs), "threat_runs": len(hits),
                  "sites": len(sites), "blocked_known": bool(known), "open_sites": len(open_sites),
                  "n_sub": n_sub, "per_candidate": extra / n_sub if n_sub and extra > 0 else None,
                  "main_median": statistics.median(mains) if mains else None,
                  "auto": len(autos), "auto_sites": sorted({c["site"] for c in autos if c.get("site")}),
                  "brand_out": len(brand_out), "brand_out_sites": sorted({c["site"] for c in brand_out if c.get("site")}),
                  "name_hit_sites": sorted({c["site"] for c in name_hits if c.get("site")})}
    return out


_RELATED_NAMES = ["하위 조사 비율", "위협 발견 비율", "발견 사이트 수", "회선 차단 추정 아닌 비율", "후보 1곳당 시간",
                  "원래 결과까지 시간 중앙값", "자동 접수 대상"]


def _related_rows(m: dict) -> list[tuple[str, str]]:
    if not m["measured"]:
        return [(name, "측정 안 함") for name in _RELATED_NAMES]
    return [
        ("하위 조사 비율", f"{m['sub_runs']}/{m['measured']} ({_pct(m['sub_runs'], m['measured'])})"),
        ("위협 발견 비율", f"{m['threat_runs']}/{m['sub_runs']} ({_pct(m['threat_runs'], m['sub_runs'])})"),
        ("발견 사이트 수", str(m["sites"])),
        ("회선 차단 추정 아닌 비율", f"{m['open_sites']}/{m['sites']} ({_pct(m['open_sites'], m['sites'])})"
         if m["blocked_known"] else "측정 안 함"),
        ("후보 1곳당 시간", f"{m['per_candidate']:.1f}s" if m["per_candidate"] is not None else "측정 안 함"),
        ("원래 결과까지 시간 중앙값", f"{m['main_median']:.1f}s" if m["main_median"] is not None else "-"),
        ("자동 접수 대상", f"{m['auto']}곳 · 사이트 {len(m['auto_sites'])}"
         + (f" (사칭한 브랜드의 진짜 사이트로 뺌 {m['brand_out']}곳 · 사이트 {len(m['brand_out_sites'])})"
            if m.get("brand_out") else "")),
    ]


# ── 운영 정보·키트 지문(순수 함수) ───────────────────────────────
def intel_record(kinds: list, url: str, final_url: object, site_of) -> dict:
    """원래 조사의 intel 기록을 평가 기록용으로: intel(종류:값), kit(dom:해시·res:해시), site(최종 주소의 등록 도메인)."""
    items, kits = set(), set()
    for k in kinds:
        d = k.get("data") if isinstance(k, dict) else None
        if k.get("kind") != "intel" or not isinstance(d, dict) or "sub" in d:
            continue
        for x in d.get("items") or []:
            if isinstance(x, dict) and isinstance(x.get("kind"), str) and isinstance(x.get("value"), str):
                items.add(f"{x['kind'][:16]}:{x['value'][:200]}")
        kit = d.get("kit") if isinstance(d.get("kit"), dict) else {}
        kits.update(f"{part}:{kit[part]}" for part in ("dom", "res") if isinstance(kit.get(part), str))
    host = urlsplit(final_url if isinstance(final_url, str) and final_url else url).hostname or ""
    return {"intel": sorted(items)[:40], "kit": sorted(kits)[:20], "site": site_of(host) if host else ""}


def intel_summary(recs: list[dict]) -> dict:
    """그룹별 운영 정보·키트 지문이 나온 회차와, 같은 열쇠로 이어진 서로 다른 사이트 묶음(합집합 찾기).
    정상으로 본 회차는 잇지 않고 키트 지문은 위협으로 본 회차만(서비스와 같은 기준). 정상 사이트 그룹이 낀 묶음은 잘못 이은 것이다."""
    measured = [r for r in recs if isinstance(r.get("intel"), list) and r.get("site")]
    groups: dict[str, dict] = {}
    for r in measured:
        for g in (r["group"], "전체"):
            m = groups.setdefault(g, {"measured": 0, "with_intel": 0, "with_kit": 0, "kinds": Counter()})
            m["measured"] += 1
            m["with_intel"] += bool(r["intel"])
            m["with_kit"] += bool(r.get("kit"))
            m["kinds"].update({x.split(":", 1)[0] for x in r["intel"]})
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    first: dict[str, str] = {}
    keys_of: dict[str, set] = {}
    for r in measured:
        site = r["site"]
        find(site)
        # 서비스(related.intel_rows)와 같게: 정상으로 본 회차는 잇지 않고, 키트 지문은 위협으로 본 회차만
        keys = (set(r["intel"]) if r.get("threat") != "benign" else set()) | (
            {f"kit:{k}" for k in r.get("kit") or []} if r.get("threat") in MALICIOUS else set())
        keys_of.setdefault(site, set()).update(keys)
        for key in keys:
            if key in first:
                parent[find(site)] = find(first[key])
            else:
                first[key] = site
    clusters: dict[str, set] = {}
    for site in parent:
        clusters.setdefault(find(site), set()).add(site)
    benign_sites = {r["site"] for r in measured if r["expected"] == "benign"}
    linked = [sorted(c) for c in clusters.values() if len(c) >= 2]
    sites_of: dict[str, set] = {}
    for site, keys in keys_of.items():
        for key in keys:
            sites_of.setdefault(key, set()).add(site)

    def kind(key: str) -> str:  # 묶음을 이은 열쇠 종류(값은 적지 않는다)
        return "kit:" + key.split(":")[1] if key.startswith("kit:") else key.split(":", 1)[0]

    shared = [sorted({kind(k) for k, ss in sites_of.items() if len(ss & set(c)) >= 2}) for c in linked]
    return {"groups": groups, "clusters": linked, "cluster_keys": shared,
            "benign_clusters": sum(1 for c in linked if benign_sites & set(c))}


def _intel_rows(m: dict | None) -> list[tuple[str, str]]:
    names = ["운영 정보가 나온 회차", "종류(회차)", "키트 지문이 있는 회차"]
    if not m or not m["measured"]:
        return [(n, "측정 안 함") for n in names]
    from_ko = {"telegram": "텔레그램", "kakao": "카톡", "line": "라인", "whatsapp": "왓츠앱", "discord": "디스코드", "phone": "휴대전화",
               "account": "계좌", "form": "수집 서버"}
    kinds = ", ".join(f"{from_ko.get(k, k)} {n}" for k, n in m["kinds"].most_common()) or "-"
    return [("운영 정보가 나온 회차", f"{m['with_intel']}/{m['measured']} ({_pct(m['with_intel'], m['measured'])})"),
            ("종류(회차)", kinds), ("키트 지문이 있는 회차", f"{m['with_kit']}/{m['measured']}")]


# ── 외부 평판 비교(순수 함수) ───────────────────────────────
def sb_record(data: object, start: str, nav: object) -> dict:
    """원래 조사의 safebrowsing 기록(조사 당시 SafeTrace 가 받은 조회 결과)을 평가 기록용으로 줄인다.
    start: 신고 주소가 일치, own: 신고·경유·최종 주소(브라우저가 실제로 연 주소) 중 하나라도 일치,
    cand: 연관 후보 주소만 일치. 조회하지 못했으면 status 가 match·no_match 가 아니다(비교에서 뺀다)."""
    if not isinstance(data, dict):
        return {"status": "none"}
    status = str(data.get("status") or "")[:20]
    matches = [m for m in data.get("matches") or [] if isinstance(m, dict)] if status == "match" else []
    hits = {str(m.get("url") or "") for m in matches}
    own = {start, *(u for u in (nav if isinstance(nav, list) else []) if isinstance(u, str))}
    return {"status": status, "start": start in hits, "own": bool(hits & own), "cand": bool(hits - own),
            "types": sorted({str(m.get("threat_type") or "")[:40] for m in matches})[:4]}


def sb_measured(r: dict) -> bool:
    sb = r.get("sb")
    return isinstance(sb, dict) and sb.get("status") in ("match", "no_match")


def sb_summary(recs: list[dict]) -> dict[str, dict]:
    """그룹별(+전체): 같은 회차에서 Safe Browsing 만 썼을 때(신고·경유·최종 주소 일치)와 SafeTrace 의 위협 판단.
    정상 사이트 그룹에서는 둘 다 오탐이다. 기록에 sb 가 없으면(이전 평가) measured 가 0 이다."""
    groups: dict[str, list[dict]] = {}
    for r in recs:
        groups.setdefault(r["group"], []).append(r)
        groups.setdefault("전체", []).append(r)
    out = {}
    for g, rs in groups.items():
        scored = [r for r in rs if outcome(r["expected"], r) != "skipped"]
        ms = [r for r in scored if sb_measured(r)]
        st = [r.get("threat") in MALICIOUS for r in ms]
        sb = [bool(r["sb"].get("own")) for r in ms]
        out[g] = {"scored": len(scored), "measured": len(ms),
                  "sb_start": sum(1 for r in ms if r["sb"].get("start")), "sb_own": sum(sb),
                  "st": sum(st), "st_or_review": sum(1 for r, t in zip(ms, st) if t or r.get("status") == "REVIEW_REQUIRED"),
                  "only_st": sum(1 for a, b in zip(sb, st) if b and not a), "only_sb": sum(1 for a, b in zip(sb, st) if a and not b),
                  "both": sum(1 for a, b in zip(sb, st) if a and b), "neither": sum(1 for a, b in zip(sb, st) if not a and not b),
                  "sb_only_auto": sum(1 for r, a, b in zip(ms, sb, st) if a and not b and r.get("status") == "COMPLETED")}
    return out


_SB_NAMES = ["조회한 회차", "Safe Browsing 일치(신고 주소)", "Safe Browsing 일치(신고·경유·최종)", "SafeTrace 위협 판단",
             "SafeTrace 위협 또는 담당자 검토", "SafeTrace 만 / Safe Browsing 만 / 둘 다 / 둘 다 아님",
             "Safe Browsing 만 잡았는데 검토 없이 끝남"]


def _sb_rows(m: dict) -> list[tuple[str, str]]:
    n = m["measured"]
    if not n:
        return [(name, "측정 안 함") for name in _SB_NAMES]
    return [
        ("조회한 회차", f"{n}/{m['scored']}"),
        ("Safe Browsing 일치(신고 주소)", f"{m['sb_start']} ({_pct(m['sb_start'], n)})"),
        ("Safe Browsing 일치(신고·경유·최종)", f"{m['sb_own']} ({_pct(m['sb_own'], n)})"),
        ("SafeTrace 위협 판단", f"{m['st']} ({_pct(m['st'], n)})"),
        ("SafeTrace 위협 또는 담당자 검토", f"{m['st_or_review']} ({_pct(m['st_or_review'], n)})"),
        ("SafeTrace 만 / Safe Browsing 만 / 둘 다 / 둘 다 아님", f"{m['only_st']} / {m['only_sb']} / {m['both']} / {m['neither']}"),
        ("Safe Browsing 만 잡았는데 검토 없이 끝남", str(m["sb_only_auto"])),
    ]


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
    rel = related_summary(recs)
    lines += ["", "## 연관 사이트 발견", "",
              "하위 조사는 원래 사건의 판정을 바꾸지 않는다(설계). 위협 발견 = 하위 조사한 후보를 위협 유형으로 본 회차, "
              "발견 사이트 = 그 후보의 등록 도메인(중복 제외). 표본은 `related` 명령으로 CSV 를 내서 사람이 확인한다.", "",
              "| 지표 | " + " | ".join(groups) + " |", "|---|" + "---|" * len(groups)]
    rrows = {g: _related_rows(rel[g]) for g in groups}
    for i, name in enumerate(_RELATED_NAMES):
        lines.append(f"| {name} | " + " | ".join(rrows[g][i][1] for g in groups) + " |")
    autos = {g: rel[g]["auto_sites"] for g in groups if g != "전체" and rel[g]["measured"] and rel[g]["auto_sites"]}
    if autos:  # 자동 접수 대상(PR 4b 조건 1~6). 정상 사이트 그룹에 나오면 오탐이다
        lines += ["", "자동 접수 대상 사이트: " + " · ".join(f"{g} {', '.join(s)}" for g, s in autos.items())]
    outs = {g: rel[g]["brand_out_sites"] for g in groups if g != "전체" and rel[g]["measured"] and rel[g].get("brand_out_sites")}
    if outs:  # 조건 10 이 뺀 사이트(서버 목록의 진짜 사이트)
        lines += ["", "사칭한 브랜드의 진짜 사이트로 뺀 사이트: " + " · ".join(f"{g} {', '.join(s)}" for g, s in outs.items())]
    hits = {g: rel[g]["name_hit_sites"] for g in groups if g != "전체" and rel[g]["measured"] and rel[g].get("name_hit_sites")}
    if hits:  # 제목은 페이지가 정해 자동으로 빼지 않는다: 사람이 확인해 진짜 사이트면 목록에 보탠다
        lines += ["", "원 사건 제목과 이름이 같은 자동 접수 대상(진짜 사이트인지 확인해 related.KIT_LINKED_REAL_SITES 에 보탤 후보): "
                  + " · ".join(f"{g} {', '.join(s)}" for g, s in hits.items())]
    its = intel_summary(recs)
    if its["groups"]:
        lines += ["", "## 운영 정보·키트 지문", "",
                  "페이지에 적힌 운영자 연락처·계좌·수집 서버(확인 안 됨)와 화면 구조 지문. 판단에는 쓰지 않고 사건을 잇는 데만 "
                  "쓴다. 묶음 = 같은 열쇠로 이어진 서로 다른 사이트(등록 도메인), 키트 지문은 위협으로 본 회차만.", "",
                  "| 지표 | " + " | ".join(groups) + " |", "|---|" + "---|" * len(groups)]
        irows = {g: _intel_rows(its["groups"].get(g)) for g in groups}
        for i in range(3):
            lines.append(f"| {irows[groups[0]][i][0]} | " + " | ".join(irows[g][i][1] for g in groups) + " |")
        lines += ["", f"서로 다른 사이트를 이은 묶음 {len(its['clusters'])}개 · 사이트 {sum(len(c) for c in its['clusters'])}곳"
                  f" · 정상 사이트가 낀 묶음 {its['benign_clusters']}개"]
        lines += [f"- {', '.join(c)} ({', '.join(k)})" for c, k in zip(its["clusters"], its["cluster_keys"])]
    sbs = sb_summary(recs)
    lines += ["", "## 외부 평판 비교 (Safe Browsing, 조사 당시)", "",
              "같은 회차에서 Safe Browsing 만 썼다면(신고 주소 또는 브라우저가 연 경유·최종 주소가 일치)과 SafeTrace 의 위협 판단을 "
              "견준다. 조회는 SafeTrace 가 조사할 때 한 것이다. 정상 사이트 그룹에서는 둘 다 오탐이다. SafeTrace 는 AI 가 정상으로 봐도 "
              "Safe Browsing 이 일치하면 담당자 검토로 보낸다.", "",
              "| 지표 | " + " | ".join(groups) + " |", "|---|" + "---|" * len(groups)]
    srows = {g: _sb_rows(sbs[g]) for g in groups}
    for i, name in enumerate(_SB_NAMES):
        lines.append(f"| {name} | " + " | ".join(srows[g][i][1] for g in groups) + " |")
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
    ra_rel, rb_rel = related_summary(a), related_summary(b)
    ra_sb, rb_sb = sb_summary(a), sb_summary(b)
    lines = [f"# 평가 비교: {name_a} → {name_b}", ""]
    for g in [g for g in sb if g != "전체"] + ["전체"]:
        if g not in sa:
            continue
        lines += [f"## {g}", "", "| 지표 | 전 | 후 |", "|---|---|---|"]
        for (name, va), (_, vb) in zip(_metric_rows(sa[g]), _metric_rows(sb[g])):
            lines.append(f"| {name} | {va} | {vb} |")
        for (name, va), (_, vb) in zip(_related_rows(ra_rel[g]), _related_rows(rb_rel[g])):
            lines.append(f"| 연관 · {name} | {va} | {vb} |")
        for (name, va), (_, vb) in zip(_sb_rows(ra_sb[g]), _sb_rows(rb_sb[g])):
            lines.append(f"| 평판 · {name} | {va} | {vb} |")
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


_FORMULA = ("=", "+", "-", "@", chr(9), chr(13))  # 탭·CR 로 시작해도 수식으로 읽힐 수 있다


def _cell(v: object) -> str:
    """표본 CSV 칸: 페이지가 정한 글자가 엑셀에서 수식으로 읽히지 않게 수식 시작 문자 앞에 ' 를 붙인다(CWE-1236)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in _FORMULA else s


RELATED_COLUMNS = ["사이트", "후보 주소", "도착 주소", "원 신고 URL", "그룹", "회차", "출처", "하위 조사 상태",
                   "AI 판단", "확률", "보류", "평판 위험", "회선 차단 추정"]


def related_rows(recs: list[dict]) -> list[list[str]]:
    """사람이 판단을 확인할 표본: 하위 조사한 후보 전부(위협으로 본 것 먼저). 살아 있는 위험 주소가 들어 있어
    git 밖(var/eval)에만 쓴다."""
    items = [(r, c) for r in recs if isinstance(r.get("related"), list) for c in r["related"] if c.get("sub")]
    items.sort(key=lambda rc: (not _is_threat(rc[1]), rc[1].get("site") or ""))
    return [[_cell(x) for x in (c.get("site"), c.get("url"), c.get("final_url"), r["url"], r["group"],
                                r.get("repeat"), c.get("source"), c.get("status"), c.get("threat"),
                                c.get("probability"), c.get("hold"), c.get("reputation_match"), c.get("blocked"))]
            for r, c in items]


def write_related_csv(recs: list[dict], path: Path) -> int:
    rows = related_rows(recs)
    with path.open("w", encoding="utf-8-sig", newline="") as f:  # 엑셀에서 한글이 깨지지 않게 BOM
        w = csv.writer(f)
        w.writerow(RELATED_COLUMNS)
        w.writerows(rows)
    return len(rows)


# ── 실행 ────────────────────────────────────────────────
def load_set(path: Path, group: str | None) -> list[dict]:
    """평가 목록(group,expected,url,note). 정상 사이트 목록(data/normal_sites.csv: category,name,url)도 그대로 받는다 —
    모두 정답 benign·그룹 normal 이다(평가 목록의 정상 16곳보다 넓은 표본으로 오탐률을 잴 때)."""
    rows = list(csv.DictReader(path.open(encoding="utf-8-sig")))
    if rows and "expected" not in rows[0] and {"category", "url"} <= set(rows[0]):
        rows = [{"group": "normal", "expected": "benign", "url": r["url"], "note": f"{r['category']} · {r.get('name') or ''}"}
                for r in rows]
    return [r for r in rows if not group or r["group"] == group]


def run_inside(args) -> None:
    """에이전트 컨테이너 안에서 실행: 조사하고 결과를 한 줄씩 쓴다."""
    sys.path.insert(0, "/app")
    from safetrace.agent.candidates import site_of
    from safetrace.agent.runner import investigate
    from safetrace.config import Settings

    rows = load_set(Path(args.set), args.group)
    # 평가 증거는 임시 폴더에 쓰고 버린다. 서명 서비스의 체인은 API 만 열 수 있으므로(#37) 여기서는
    # 이 프로세스 안에서 일회용 키로 서명한다(실제 증거 서명 키는 여전히 에이전트에 없다)
    s = Settings(evidence_dir=Path(IN_BOX) / "evidence", signer_url=None, evidence_hmac_key=secrets.token_hex(32))
    with open(args.out, "a", encoding="utf-8") as f:
        for rep in range(args.repeat):
            for row in rows:  # 한 URL 을 연달아 돌리지 않고 목록을 한 바퀴씩 돈다(시간대 편차 분산)
                cid = str(uuid.uuid4())
                rec = {"group": row["group"], "expected": row["expected"], "url": row["url"], "repeat": rep}
                t = time.monotonic()
                t_main: list[float] = []

                def on_event(e, t_main=t_main):
                    # 원래 결과가 하위 조사보다 먼저 나오는 경우(related-sites PR 3) 그 시각을 잰다
                    if isinstance(e, dict) and e.get("type") == "status" and e.get("phase") == "related" and not t_main:
                        t_main.append(time.monotonic())
                try:
                    final = investigate(cid, row["url"], s, emit=on_event)
                    th = final.get("threat") or {}
                    rec.update(status=final["status"], reason=final["reason"], threat=th.get("threat"),
                               probability=th.get("probability"), hold=th.get("hold"),
                               final_url=(final.get("final_url") or "")[:200])
                    # 코드 규칙이 모델 판단을 바꿨으면 그 규칙과 모델의 원래 판단(실사이트 누적의 '이전에 고친 유형' 칸)
                    ov = th.get("override") if isinstance(th.get("override"), dict) else {}
                    orig = ov.get("original") if isinstance(ov.get("original"), dict) else {}
                    rec["rule"] = str(ov["reason"])[:40] if isinstance(ov.get("reason"), str) else None
                    rec["rule_original"] = str(orig["threat"])[:20] if isinstance(orig.get("threat"), str) else None
                    chain = s.evidence_dir / cid / "chain.jsonl"
                    kinds = [json.loads(x) for x in chain.read_text(encoding="utf-8").splitlines()]
                    fin = next((k["data"] for k in kinds if k["kind"] == "finish"), {})
                    rec["steps"] = sum(1 for k in kinds if k["kind"] == "action")
                    rec["blocked_destinations"] = [b["host"] for b in fin.get("blocked_destinations", [])]
                    # 조사 당시 받은 Safe Browsing 조회(원래 조사, 하위 조사의 조회는 candidate_safebrowsing)
                    sbr = next((k["data"] for k in kinds if k["kind"] == "safebrowsing"), None)
                    rec["sb"] = sb_record(sbr, row["url"], fin.get("nav_chain"))
                    cands = final.get("candidates") or []
                    rec["candidates"] = len(cands)
                    rec["candidates_investigated"] = sum(1 for c in cands if isinstance(c, dict) and c.get("sub"))
                    rec["related"] = [related_item(c, site_of) for c in cands if isinstance(c, dict)][:20]
                    # 운영 정보·키트 지문(원래 조사의 intel 기록). 살아 있는 운영자 값이라 결과 파일은 git 밖에만 둔다
                    rec.update(intel_record(kinds, row["url"], final.get("final_url"), site_of))
                except Exception as e:  # 한 건 실패로 전체를 멈추지 않는다
                    rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
                rec["seconds"] = round(time.monotonic() - t, 1)
                rec["seconds_main"] = round(t_main[0] - t, 1) if t_main else rec["seconds"]
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
    subprocess.run(dc + ["exec", "-T", "agent", "sh", "-c", f"rm -rf {IN_BOX} && mkdir -p {IN_BOX}/bin"],
                   cwd=ROOT, check=True)
    # 도구와 평가 목록을 다른 자리·고정 이름에 둔다(목록 파일 이름이 도구와 같아도 도구를 덮어써 실행되지 않게)
    tool, data = f"{IN_BOX}/bin/eval_agent.py", f"{IN_BOX}/set.csv"
    subprocess.run(dc + ["cp", str(Path(__file__)), f"agent:{tool}"], cwd=ROOT, check=True, capture_output=True)
    subprocess.run(dc + ["cp", str(ROOT / args.set), f"agent:{data}"], cwd=ROOT, check=True, capture_output=True)
    cmd = ["python", "-u", tool, "run", "--inside", "--repeat", str(args.repeat),
           "--set", data, "--out", f"{IN_BOX}/out.jsonl"]
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
            n = write_related_csv(load_results(local), local.with_name(local.stem + "_related.csv"))
            print("\n" + md)
            print(f"결과: {local.relative_to(ROOT)} (연관 표본 {n}줄: {local.stem}_related.csv)")


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
    rl = sub.add_parser("related")
    rl.add_argument("results", type=Path)
    c = sub.add_parser("compare")
    c.add_argument("a", type=Path)
    c.add_argument("b", type=Path)
    args = ap.parse_args()
    if args.cmd == "run":
        (run_inside if args.inside else run_host)(args)
    elif args.cmd == "report":
        print(report(load_results(args.results), load_meta(args.results)))
    elif args.cmd == "related":
        out = args.results.with_name(args.results.stem + "_related.csv")
        print(f"{out}: {write_related_csv(load_results(args.results), out)}줄")
    else:
        print(compare(load_results(args.a), load_results(args.b), args.a.stem, args.b.stem))


if __name__ == "__main__":
    main()

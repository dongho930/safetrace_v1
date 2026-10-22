"""처리 기관 안내와 요청서 초안(모니터링 담당자 업무): 판정 유형에 맞는 기관·참고 조문과, 기관 신고 양식에 옮겨
붙일 요청서 글을 보고서 요약(report.build 결과)에서 만든다.

- 확정 판정(담당자 '위협')이 있으면 그 유형, 없거나 보류면 AI 판단(초안 표시), 담당자가 정상으로 확정했거나 위협
  유형이 아니면 요청 대상이 아니다
- 기관·연락처는 공식 안내에서 확인한 것만 둔다(경찰청 사이버범죄 신고시스템 '유관기관 안내', 2026-10-22 확인).
  방송통신심의위원회는 2025-10-01 방송미디어통신심의위원회로 바뀌었다
- 조문은 국가법령정보 원문과 대조한 것만 둔다(2026-10-22). 해당 여부는 기관이 판단하므로 '참고 조문'이다
- 요청서에 들어가는 제목·주소는 조사 대상 페이지가 정한 값이다. 줄바꿈·제어 문자·방향 바꿈 문자를 지우고 잘라서
  요청서의 다른 항목(요청 사항 등)을 꾸며 넣거나 주소를 거꾸로 보이게 하지 못하게 한다
- 외부 기관에 자동으로 보내지 않는다. 담당자가 확인하고 옮겨 쓴다
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

FORMAT = "safetrace.referral/1"
KST = timezone(timedelta(hours=9), "KST")

AGENCIES: dict[str, dict[str, str]] = {
    "kisa": {"name": "한국인터넷진흥원(KISA) 인터넷 보호나라", "phone": "118", "url": "https://www.boho.or.kr/",
             "does": "피싱·스미싱 사이트, 해킹·악성코드 유포지 신고"},
    "kcsc": {"name": "방송미디어통신심의위원회(옛 방송통신심의위원회)", "phone": "1377", "url": "https://report.kocsc.or.kr/",
             "does": "불법·유해정보 심의와 접속차단(시정요구)"},
    "ngcc": {"name": "사행산업통합감독위원회 불법사행산업감시신고센터", "phone": "1336", "url": "https://singo.ngcc.go.kr/",
             "does": "불법 도박·사행성 사이트 신고"},
    "police": {"name": "경찰청 사이버범죄 신고시스템(ECRM)", "phone": "112", "url": "https://ecrm.police.go.kr/",
               "does": "사이버 사기 등 범죄 신고·수사 의뢰"},
    "fss": {"name": "금융감독원", "phone": "1332", "url": "https://www.fss.or.kr/",
            "does": "불법금융행위·전기통신금융사기 제보"},
}

_NETLAW = "정보통신망 이용촉진 및 정보보호 등에 관한 법률"
LAWS: dict[str, dict[str, str]] = {
    "49-2": {"cite": f"{_NETLAW} 제49조의2 제1항",
             "text": "누구든지 정보통신망을 통하여 속이는 행위로 다른 사람의 정보를 수집하거나 다른 사람이 정보를 제공하도록 "
                     "유인하여서는 아니 된다."},
    "44-7-1-6": {"cite": f"{_NETLAW} 제44조의7 제1항 제6호",
                 "text": "법령에 따라 금지되는 사행행위에 해당하는 내용의 정보(유통 금지)"},
    "44-7-1-9": {"cite": f"{_NETLAW} 제44조의7 제1항 제9호",
                 "text": "그 밖에 범죄를 목적으로 하거나 교사(敎唆) 또는 방조하는 내용의 정보(유통 금지)"},
    "48-2": {"cite": f"{_NETLAW} 제48조 제2항",
             "text": "누구든지 정당한 사유 없이 정보통신시스템, 데이터 또는 프로그램 등을 훼손·멸실·변경·위조하거나 그 운용을 "
                     "방해할 수 있는 프로그램(악성프로그램)을 전달 또는 유포하여서는 아니 된다."},
    "44-7-1-4": {"cite": f"{_NETLAW} 제44조의7 제1항 제4호",
                 "text": "정당한 사유 없이 정보통신시스템, 데이터 또는 프로그램 등을 훼손·멸실·변경·위조하거나 그 운용을 방해하는 "
                         "내용의 정보(유통 금지)"},
}

# 유형 → (요청서 제목 머리, 주 기관, 함께 알릴 기관, 참고 조문, 요청 사항)
BY_THREAT: dict[str, dict] = {
    "phishing": {"label": "피싱", "title": "피싱 사이트 차단 요청", "primary": "kisa", "also": ["police"],
                 "also_note": {"police": "개인정보·금전 피해가 확인된 경우"},
                 "laws": ["49-2"], "ask": "위 사이트의 접속 차단과 유포 경로 확인을 요청합니다."},
    "scam": {"label": "사기", "title": "사기 의심 사이트 신고", "primary": "police", "also": ["kcsc", "fss"],
             "also_note": {"kcsc": "사이트 접속차단(시정요구)", "fss": "투자·대출 등 불법금융행위인 경우"},
             "laws": ["44-7-1-9"], "ask": "위 사이트에 대한 수사 검토와 접속 차단을 요청합니다."},
    "illegal_gambling": {"label": "불법 도박", "title": "불법 도박 사이트 심의·접속차단 요청", "primary": "kcsc",
                         "also": ["ngcc"], "also_note": {"ngcc": "불법사행산업 감시 신고"},
                         "laws": ["44-7-1-6"], "ask": "위 사이트에 대한 심의와 접속차단(시정요구)을 요청합니다."},
    "malware": {"label": "악성코드 유포", "title": "악성코드 유포지 신고", "primary": "kisa", "also": [],
                "also_note": {}, "laws": ["48-2", "44-7-1-4"],
                "ask": "위 사이트의 악성 파일 분석과 유포지 차단을 요청합니다."},
}

NOTICE = ("이 요청서는 SafeTrace 가 조사 기록으로 만든 초안이다. 유형은 기술적 의심 유형이며 법적 판단이 아니다. "
          "참고 조문의 해당 여부는 받는 기관이 판단한다. 담당자가 내용을 확인한 뒤 기관 양식에 옮겨 쓴다.")

# 요청서에 넣는 페이지 값: 제어 문자(줄바꿈 포함)·방향 바꿈·폭 없는 문자를 지운다
# 제어 문자(줄바꿈 포함 C0·C1), 아랍 글자 표시, 폭 없는 문자·방향 표시, 줄·문단 나눔, 방향 바꿈, 단어 잇기·방향 격리, BOM
_UNSAFE = ((0x00, 0x1F), (0x7F, 0x9F), (0x061C, 0x061C), (0x200B, 0x200F), (0x2028, 0x202E), (0x2060, 0x2069),
           (0xFEFF, 0xFEFF))
_URL, _TEXT = 500, 120


def clean(v: object, n: int = _TEXT) -> str:
    """페이지에서 온 값을 요청서 한 줄에 넣을 글자로: 위험한 문자를 공백으로 바꾸고 공백을 줄이고 자른다."""
    if not isinstance(v, str):
        return ""
    s = " ".join("".join(" " if any(a <= ord(ch) <= b for a, b in _UNSAFE) else ch for ch in v[: n * 4]).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _kst(ts: object) -> str:
    try:
        return datetime.fromisoformat(str(ts)).astimezone(KST).strftime("%Y-%m-%d %H:%M KST")
    except (TypeError, ValueError):
        return "-"


def _pct(p: object) -> str:
    ok = isinstance(p, (int, float)) and not isinstance(p, bool) and 0 <= p <= 1
    return f"{float(p) * 100:.0f}%" if ok else "-"  # type: ignore[arg-type]


def basis(rep: dict) -> tuple[str | None, str, str]:
    """요청 유형과 근거. 반환 (유형 또는 None, 근거 confirmed|ai|none, 요청하지 않는 이유 코드)."""
    v = rep.get("verdict") or None
    if v and v.get("decision") == "threat":
        t = v.get("threat")
        return (t, "confirmed", "") if t in BY_THREAT else (None, "none", "type")
    if v and v.get("decision") == "benign":
        return None, "none", "benign"
    ai = (rep.get("assessment") or {}).get("ai") or {}
    t = ai.get("threat")
    if t in BY_THREAT:
        return t, "ai", ""
    return None, "none", "no_threat"


_NO_REFERRAL_KO = {"benign": "담당자가 정상으로 판정해 요청 대상이 아니다",
                   "no_threat": "위협 유형 판단이 없어 요청 대상이 아니다(판단 불가·정상 의견)",
                   "type": "확정한 유형에 맞는 처리 기관이 없다"}


def build(rep: dict) -> dict:
    """보고서 요약으로 처리 기관 안내와 요청서 초안을 만든다."""
    threat, why, no = basis(rep)
    case, inv, a = rep.get("case") or {}, rep.get("investigation") or {}, rep.get("assessment") or {}
    if threat is None:
        return {"format": FORMAT, "applicable": False, "reason": no, "reason_ko": _NO_REFERRAL_KO.get(no, ""),
                "notice": NOTICE}
    spec = BY_THREAT[threat]
    agency = {"id": spec["primary"], **AGENCIES[spec["primary"]]}
    also = [{"id": k, **AGENCIES[k], "when": spec["also_note"].get(k, "")} for k in spec["also"]]
    laws = [{"id": k, **LAWS[k]} for k in spec["laws"]]
    ai = a.get("ai") or {}
    brand = clean(ai.get("brand"), 40)
    url = clean(case.get("url"), _URL)
    final = clean(inv.get("final_url"), _URL)
    host = (urlsplit(final or url).hostname or "")[:253]
    v = rep.get("verdict") or {}
    integ = rep.get("integrity") or {}
    draft = why != "confirmed"
    subject = f"[{spec['title']}] {clean(host, 100) or url}"

    lines = [f"제목: {subject}", f"수신: {agency['name']} ({agency['phone']} · {agency['url']})", "",
             "1. 대상", f" - 신고 URL: {url or '-'}"]
    if final and final != url:
        lines.append(f" - 최종 도달 주소: {final}")
    path = [clean(p, _URL) for p in (inv.get("path") or [])[:6] if isinstance(p, str)]
    if len(path) > 1:
        lines.append(f" - 이동 경로: {' → '.join(path)}")
    if why == "confirmed":
        kind = f"{spec['label']} (담당자 판정 · 판 {v.get('rev')} · {clean(v.get('reviewer'), 40)})"
    else:
        # 코드 규칙이 정한 유형은 확률이 1.0 으로 기록된다: 'AI 100%' 로 적지 않는다
        src = "코드 규칙" if ai.get("override") else f"AI 판단 {_pct(ai.get('probability'))}"
        kind = (f"{spec['label']} 의심 ({src}" + (" · 담당자 판정 보류" if v.get("decision") == "hold" else " · 담당자 판정 전")
                + ")")
    lines += ["", f"2. 유형: {kind}"]
    if brand:
        lines.append(f" - 사칭 대상: {brand}")
    lines += ["", "3. 확인 내용",
              f" - 조사 일시: {_kst(inv.get('started_at'))}, 격리된 브라우저로 접속해 화면을 기록함"
              "(입력·결제·다운로드는 하지 않음)"]
    titles = []
    for s in inv.get("steps") or []:
        t = clean(s.get("title"), 60) if isinstance(s, dict) else ""
        if t and t not in titles:
            titles.append(t)
    if titles:
        lines.append(f" - 관찰한 화면 제목: {' / '.join(f'「{t}」' for t in titles[:3])}")
    if isinstance(ai.get("override"), str) and ai["override"]:
        lines.append(f" - 판단 근거(코드 규칙): {clean(ai['override'], 200)}")
    sb = a.get("safebrowsing") or {}
    if sb.get("status") == "match":
        lines.append(" - 외부 평판: Google Safe Browsing 위험 목록 일치")
    if why == "confirmed" and v.get("note"):
        lines.append(f" - 담당자 의견: {clean(v.get('note'), 300)}")
    lines += ["", "4. 참고 조문 (해당 여부는 귀 기관 판단)"]
    lines += [f" - {law['cite']}" for law in laws]
    shots = len(rep.get("key_screens") or [])
    lines += ["", "5. 증거",
              f" - SafeTrace 사건 {clean(case.get('id'), 36)} · 증거 기록 {integ.get('records', '-')}건 "
              f"(무결성 검증 {'통과' if integ.get('verified') else '실패'}) · 체인 끝 {integ.get('head_seq', '-')}번 "
              f"{clean(integ.get('head_hash'), 64)[:16]}…",
              f" - 주요 화면 {shots}장, 원본·검증 방법은 검토 패키지(ZIP)로 제출 가능", "",
              f"요청 사항: {spec['ask']}", "",
              f"작성: {clean(v.get('reviewer') if why == 'confirmed' else rep.get('generated_by'), 40)} · "
              f"{_kst(rep.get('generated_at'))}" + (" · 초안(담당자 판정 전)" if draft else "")]
    return {"format": FORMAT, "applicable": True, "threat": threat, "threat_ko": spec["label"], "basis": why,
            "draft": draft, "agency": agency, "also": also, "laws": laws, "subject": subject,
            "text": "\n".join(lines), "notice": NOTICE}

"""IOC 내보내기: 담당자가 위협으로 확정한 사건만, 운영자를 가리키지 않는 곳·개인정보는 빼고, 페이지 값이 CSV 수식·STIX
패턴을 꾸미지 못하고, 검토관 이상·감사로그·기간 상한, 운영 정보는 고를 때만 검증한 체인에서."""

import csv
import io
import json
import re
import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from safetrace import accounts, ioc
from safetrace.store import AuditLog, Case, CaseSite, Verdict, now
from tests.conftest import INVESTIGATOR, SERVICE_ADMIN, VIEWER

PW = "correct-horse-battery-9"
BS = chr(92)


# ── 지표 고르기 ─────────────────────────
@pytest.mark.parametrize("url,final,want,excluded", [
    # 쿼리·조각은 뺀다. 단축 주소는 신고 주소일 때만 URL 로, 단축 서비스 호스트·안내 화면은 내지 않는다
    ("https://bit.ly/abc?x=1#y", "https://bit.ly/a/warning", {("url", "https://bit.ly/abc")}, {"shortener", "shortener_page"}),
    # 조사 전에 진짜 사이트로 넘긴 키트(official_redirect): 최종 주소의 공식 도메인은 넣지 않는다
    ("http://kc-telegram.com/a?b=c", "https://www.facebook.com/", {("url", "http://kc-telegram.com/a"),
                                                                    ("domain", "kc-telegram.com")}, {"official"}),
    ("https://evil.pages.dev/login", "https://pages.dev/", {("url", "https://evil.pages.dev/login"),
                                                             ("domain", "evil.pages.dev")}, {"shared_root"}),
    ("http://10.0.0.1/x", "http://169.254.169.254/latest", set(), {"internal"}),
    ("http://1.2.3.4:8080/p", None, {("url", "http://1.2.3.4:8080/p"), ("ipv4", "1.2.3.4")}, set()),
    ("https://framer.com/x", "https://www.gitbook.com/", set(), {"service"}),
    ("https://evil.example/a", "https://www.youtube.com/watch", {("url", "https://evil.example/a"), ("domain", "evil.example")},
     {"generic"}),
    # 주소에 피해자 이메일·전화가 들어 있으면 그 URL 은 내지 않는다(호스트는 낸다)
    ("https://x.example/u/alice%40example.com", None, {("domain", "x.example")}, {"pii"}),
    ("https://x.example/p/010-1234-5678", None, {("domain", "x.example")}, {"pii"}),
    ("https://user:pw@한국.example:443/로그인", None, {("url", "https://xn--3e0b707e.example/로그인"),
                                                     ("domain", "xn--3e0b707e.example")}, set()),
    ("javascript:alert(1)", None, set(), {"format"}),
    # 최종 주소가 다른 사이트면 에이전트가 누른 링크일 수 있다(피싱 화면의 연락 버튼 → api.whatsapp.com, 로컬 사건에서 관찰)
    ("https://dana.blogspot.com/p", "https://api.whatsapp.com/send", {("url", "https://dana.blogspot.com/p"),
                                                                       ("domain", "dana.blogspot.com")}, {"elsewhere"}),
    ("https://a.blogspot.com/p", "https://b.blogspot.com/q", {("url", "https://a.blogspot.com/p"), ("domain", "a.blogspot.com")},
     {"elsewhere"}),  # 공용 호스팅은 같은 호스트만 같은 운영자
    # 같은 사이트의 다른 하위 도메인, 단축 URL 이 보낸 목적지는 낸다
    ("https://login.evil.example/a", "https://www.evil.example/b", {
        ("url", "https://login.evil.example/a"), ("domain", "login.evil.example"), ("url", "https://www.evil.example/b"),
        ("domain", "www.evil.example")}, set()),
    # 단축 URL 의 목적지는 최종 주소(누른 뒤일 수 있음)가 아니라 검증한 체인의 첫 화면에서만(아래 시험). 없으면 뺀다
    ("https://lrl.kr/AbC", "https://n-payost.shop/x", {("url", "https://lrl.kr/AbC")}, {"shortener", "unverified_destination"}),
    # 여러 번 URL 인코딩한 개인정보도 풀어서 본다(Codex 1회차 F3)
    ("https://phish.example/u/alice%2540example.com", None, {("domain", "phish.example")}, {"pii"}),
    ("https://phish.example/u/alice%25252540example.com", None, {("domain", "phish.example")}, {"pii"}),
    ("http://testpages:8900/smish/", "http://testpages-alt:8900/x", set(), {"internal"}),  # 점 없는 내부 이름
    # Codex 2회차 F2: 와일드카드 DNS 는 하위 도메인마다 다른 서버라 공용 호스팅처럼 같은 호스트만 같은 사이트
    ("https://93.184.215.14.nip.io/a", "https://1.1.1.1.nip.io/help", {("url", "https://93.184.215.14.nip.io/a"),
                                                                        ("domain", "93.184.215.14.nip.io")}, {"elsewhere"}),
    # Codex 2회차 F3: 글자·밑줄에 붙은 전화번호도 개인정보(단어 경계에 기대지 않는다). 날짜 같은 짧은 숫자는 그대로
    ("https://phish.example/u/customer_01012345678", None, {("domain", "phish.example")}, {"pii"}),
    ("https://phish.example/u/id010-1234-5678x", None, {("domain", "phish.example")}, {"pii"}),
    ("https://phish.example/2026-10-24/login", None, {("url", "https://phish.example/2026-10-24/login"),
                                                      ("domain", "phish.example")}, set()),
])
def test_network_indicators(url, final, want, excluded):
    got, ex = ioc.network_indicators(url, final)
    assert {(t, v) for t, v, _ in got} == want
    assert {r for r, _, _ in ex} == excluded
    assert not any("alice" in v or "5678" in v for _, v, _ in got) and not any("alice" in v for _, _, v in ex)


def test_shortener_destination_comes_from_landing_not_final():
    """Codex 1회차 F2: 단축 URL 사건의 최종 주소는 에이전트가 누른 링크의 다른 사이트일 수 있다. 목적지는 첫 화면(landing)."""
    got, ex = ioc.network_indicators("https://bit.ly/AbCd", "https://innocent.example/help")
    assert {(t, v) for t, v, _ in got} == {("url", "https://bit.ly/AbCd")} and ("unverified_destination", "domain",
                                                                                "innocent.example") in ex
    got, ex = ioc.network_indicators("https://bit.ly/AbCd", "https://innocent.example/help", landing="https://phish.example/x?a=1")
    assert {(t, v) for t, v, _ in got} == {("url", "https://bit.ly/AbCd"), ("url", "https://phish.example/x"),
                                           ("domain", "phish.example")}
    assert ("elsewhere", "domain", "innocent.example") in ex
    got, _ = ioc.network_indicators("https://bit.ly/AbCd", "https://www.phish.example/y", landing="https://phish.example/x")
    assert {(t, v) for t, v, _ in got} >= {("url", "https://phish.example/x"), ("url", "https://www.phish.example/y")}


def _literal(pattern: str) -> tuple[str, str]:
    """STIX 패턴을 읽어 (따옴표 밖 글자, 따옴표 안 값)으로 나눈다(역슬래시 이스케이프를 푼다)."""
    outside, inside, q, i = [], [], False, 0
    while i < len(pattern):
        ch = pattern[i]
        if q and ch == BS:
            inside.append(pattern[i + 1])
            i += 2
            continue
        if ch == "'":
            q = not q
        elif q:
            inside.append(ch)
        else:
            outside.append(ch)
        i += 1
    assert not q
    return "".join(outside), "".join(inside)


@pytest.mark.parametrize("value", ["https://e.x/a'] OR [url:value = 'z", "https://e.x/a" + BS + "'] OR [x:y = '1",
                                   "https://e.x/" + BS + BS + "'", "https://e.x/it's"])
def test_stix_pattern_value_cannot_add_conditions(value):
    """값의 따옴표·역슬래시로 패턴을 끝내고 조건을 덧붙이지 못한다(따옴표 밖은 고정된 모양, 안은 원래 값 그대로)."""
    outside, inside = _literal(ioc.stix_pattern("url", value))
    assert outside == "[url:value = ]" and inside == value


def test_csv_cells_are_not_formulas():
    at = now()
    inds, _, _ = ioc.collect([{"id": "c1", "url": "https://evil.example/", "final_url": None, "threat": "phishing", "at": at}])
    rows = list(csv.reader(io.StringIO(ioc.to_csv(inds, {}).lstrip(chr(0xFEFF)))))
    assert rows[0] == ioc.CSV_HEADER
    vals = {r[0]: r[1] for r in rows[1:]}
    assert vals["url"] == "https://evil.example/" and vals["domain"] == "evil.example"
    assert [ioc._cell(v) for v in ("+1", "@x=1", "=A1", "-2", "ok")] == ["'+1", "'@x=1", "'=A1", "'-2", "ok"]


# ── API ─────────────────────────
@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


def _store():
    from safetrace.api.main import store

    return store


@pytest.fixture(scope="module")
def reviewer(client):
    name = "ioc" + secrets.token_hex(3)
    u = accounts.create_user(_store(), name, PW, "reviewer")
    tok = client.post("/api/auth/login", json={"username": name, "password": PW}).json()["token"]
    return u, tok


def _case(u, url, verdicts=(("threat", "phishing"),), final=None, at=None, sites=(), status="COMPLETED"):
    """판정을 차례로 쌓은 사건. at: 마지막 판정 시각."""
    store = _store()
    with store.session() as s, s.begin():
        c = Case(url=url, final_url=final, source="test", status=status, created_by="t",
                 threat={"threat": "phishing", "probability": 0.9})
        s.add(c)
        s.flush()
        for i, (d, t) in enumerate(verdicts, 1):
            s.add(Verdict(case_id=c.id, rev=i, decision=d, threat=t, reviewer=u.username, user_id=u.id,
                          created_at=at if at and i == len(verdicts) else now()))
        for site in sites:
            s.add(CaseSite(case_id=c.id, host=site, site=site, role="start"))
    return c.id


def test_only_current_threat_verdicts_in_period(client, reviewer):
    u, tok = reviewer
    tag = secrets.token_hex(4)
    host = {k: f"{k}-{tag}.example" for k in ("threat", "benign", "hold", "old", "ai", "regamble")}
    _case(u, f"https://{host['threat']}/login?email=a@b.c", final=f"https://{host['threat']}/done")
    _case(u, f"https://{host['benign']}/", verdicts=(("threat", "phishing"), ("benign", None)))  # 나중에 정상으로 바꿈
    _case(u, f"https://{host['hold']}/", verdicts=(("hold", None),))
    _case(u, f"https://{host['old']}/", at=now() - timedelta(days=40))
    _case(u, f"https://{host['ai']}/", verdicts=())  # AI 만 위협으로 봄
    _case(u, f"https://{host['regamble']}/", verdicts=(("threat", "phishing"), ("threat", "illegal_gambling")))
    r = client.get("/api/ioc.csv?days=30", headers=h(tok))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert re.fullmatch(r'attachment; filename="safetrace-ioc-\d{8}-30d\.csv"', r.headers["content-disposition"])
    text = r.text
    assert f"https://{host['threat']}/login" in text and f"https://{host['threat']}/done" in text
    assert "email" not in text  # 쿼리는 뺀다
    rows = {row[1]: row for row in csv.reader(io.StringIO(text.lstrip(chr(0xFEFF))))}
    assert rows[host["regamble"]][2] == "illegal_gambling"  # 마지막 판정의 유형
    assert rows[host["threat"]][3] == "신고 주소 최종 주소" or rows[host["threat"]][3] == "최종 주소 신고 주소"
    for k in ("benign", "hold", "old", "ai"):
        assert host[k] not in text
    assert host["old"] in client.get("/api/ioc.csv?days=90", headers=h(tok)).text
    audit = _store().session().scalars(select(AuditLog).where(AuditLog.action == "ioc.export")
                                       .order_by(AuditLog.id.desc()).limit(2)).all()
    assert audit[0].actor == u.username and "fmt=csv days=90 cases=" in audit[0].detail


def test_roles_and_limits(client, reviewer):
    _, tok = reviewer
    for t in (VIEWER, INVESTIGATOR):  # 밖으로 나가는 자료라 검토관 이상
        for path in ("/api/ioc", "/api/ioc.csv", "/api/ioc.stix"):
            assert client.get(path, headers=h(t)).status_code == 403
    assert client.get("/api/ioc", headers=h(SERVICE_ADMIN)).status_code == 200  # 자동화(관리자 역할 토큰)는 받을 수 있다
    for q in ("days=0", "days=91", "days=x"):
        assert client.get(f"/api/ioc.csv?{q}", headers=h(tok)).status_code == 422
    assert client.get("/api/ioc.xml", headers=h(tok)).status_code == 404
    assert client.get("/api/ioc.csv").status_code == 401


def test_summary_counts_without_values(client, reviewer):
    u, tok = reviewer
    tag = secrets.token_hex(4)
    _case(u, f"https://sum-{tag}.example/a", final="https://www.facebook.com/")
    s = client.get("/api/ioc?days=1", headers=h(tok)).json()
    assert s["cases"] >= 1 and s["by_type"]["url"] >= 1 and s["by_type"]["domain"] >= 1 and s["excluded"]["official"] >= 1
    assert f"sum-{tag}" not in json.dumps(s)  # 미리 보기에는 값이 없다(감사로그 없이 보는 화면)
    assert s["limits"] == {"cases": ioc.CASES_MAX, "chain_cases": ioc.CHAIN_CASES_MAX, "indicators": ioc.INDICATORS_MAX}


def test_case_limit_truncates_newest_first(client, reviewer, monkeypatch):
    u, tok = reviewer
    tag = secrets.token_hex(4)
    _case(u, f"https://older-{tag}.example/", at=now() - timedelta(hours=1))
    _case(u, f"https://newest-{tag}.example/", at=now() + timedelta(minutes=5))  # 다른 시험의 판정보다 늦게
    monkeypatch.setattr(ioc, "CASES_MAX", 1)
    r = client.get("/api/ioc.csv?days=1", headers=h(tok))
    assert r.headers["x-safetrace-cases"] == "1" and r.headers["x-safetrace-truncated"] == "1"
    assert f"newest-{tag}" in r.text and f"older-{tag}" not in r.text


def test_stix_bundle_is_consistent(client, reviewer):
    """STIX 2.1 묶음: 필수 속성, 참조하는 id 가 모두 있음, 내보내는 지표를 함께 가진 사건은 한 campaign.
    Codex 2회차 F1: 사건 연결 표(case_sites)의 열쇠는 판정 뒤에 붙은 기록에서도 나올 수 있어 campaign 근거로 쓰지 않는다."""
    u, tok = reviewer
    tag = secrets.token_hex(4)
    link = f"kit:dom:{secrets.token_hex(16)}"
    a = _case(u, f"https://ab-{tag}.example/x", sites=(link,))
    b = _case(u, f"https://ab-{tag}.example/y")
    lone = _case(u, f"https://c-{tag}.example/z", sites=(link,))  # a 와 연결 표 열쇠만 같다
    r = client.get("/api/ioc.stix?days=1", headers=h(tok))
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/stix+json")
    bundle = r.json()
    assert bundle["type"] == "bundle" and re.fullmatch(r"bundle--[0-9a-f-]{36}", bundle["id"])
    objs = {o["id"]: o for o in bundle["objects"]}
    assert len(objs) == len(bundle["objects"])
    stamp = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z")
    for o in bundle["objects"]:
        assert o["spec_version"] == "2.1" and o["id"].startswith(o["type"] + "--")
        assert stamp.fullmatch(o["created"]) and stamp.fullmatch(o["modified"]) and o["created"] <= o["modified"]
        if o["type"] != "identity":
            assert o["created_by_ref"] in objs
        if o["type"] == "indicator":
            assert o["pattern_type"] == "stix" and o["valid_from"] == o["created"] and o["labels"]
        if o["type"] == "relationship":
            assert o["relationship_type"] == "indicates" and objs[o["source_ref"]]["type"] == "indicator"
            assert objs[o["target_ref"]]["type"] == "campaign"
    mine = {o["pattern"]: o for o in objs.values() if o["type"] == "indicator" and tag in o["pattern"]}
    assert set(mine) == {f"[url:value = 'https://{x}-{tag}.example/{p}']" for x, p in (("ab", "x"), ("ab", "y"), ("c", "z"))} | {
        f"[domain-name:value = '{x}-{tag}.example']" for x in ("ab", "c")}
    camp = {o["target_ref"] for o in objs.values() if o["type"] == "relationship" and o["source_ref"] in
            {m["id"] for m in mine.values()}}
    assert len(camp) == 1  # a·b 는 같은 도메인으로 한 묶음, c 는 묶음 없음
    linked = {o["source_ref"] for o in objs.values() if o["type"] == "relationship" and o["target_ref"] in camp}
    refs = {r["external_id"] for i in linked for r in objs[i]["external_references"]}
    assert {a, b} <= refs and lone not in refs
    # 같은 값은 내보낼 때마다 같은 id(받는 쪽이 중복을 거른다)
    again = {o["pattern"]: o["id"] for o in client.get("/api/ioc.stix?days=1", headers=h(tok)).json()["objects"]
             if o["type"] == "indicator" and tag in o["pattern"]}
    assert again == {p: o["id"] for p, o in mine.items()}


def test_chain_values_are_bounded_by_verdict_head(client, reviewer):
    """Codex 1회차 F1: 연관 사이트를 조사하는 동안 저장한 판정은 원래 조사의 끝에 묶인다. 그 뒤에 체인에 붙은 기록(침해된
    워커가 sub 없이 넣은 화면)은 담당자가 본 범위가 아니라 지표로 내지 않는다. 단축 URL 의 목적지도 같은 범위의
    첫 화면에서만 꺼낸다(F2)."""
    from safetrace.agent.runner import make_sealer
    from safetrace.api.main import settings
    from safetrace.evidence import EvidenceWriter

    u, tok = reviewer
    tag = secrets.token_hex(4)
    store = _store()
    with store.session() as s, s.begin():
        c = Case(url=f"https://bit.ly/{tag}", final_url=f"https://innocent-{tag}.example/help", source="test",
                 status="COMPLETED", created_by="t", threat={"threat": "phishing", "probability": 0.9})
        s.add(c)
    w = EvidenceWriter(settings.evidence_dir, c.id, make_sealer(settings))
    w.append("start", {"url": c.url})
    w.append("observe", {"step": 0, "url": f"https://dest-{tag}.example/login?u=1"})
    seen = w.head  # 담당자가 판정할 때 본 끝
    w.append("observe", {"step": 1, "url": f"https://innocent-{tag}.example/help"})
    with store.session() as s, s.begin():
        x = s.get(Case, c.id)
        x.head_seq, x.head_hash = w.head.seq, w.head.hash
        s.add(Verdict(case_id=c.id, rev=1, decision="threat", threat="phishing", reviewer=u.username, user_id=u.id,
                      ai_threat="phishing", head_seq=seen.seq, head_hash=seen.hash))
    text = client.get("/api/ioc.csv?days=1", headers=h(tok)).text
    assert f"https://bit.ly/{tag}" in text and f"https://dest-{tag}.example/login" in text and f"dest-{tag}.example," in text
    assert f"innocent-{tag}" not in text

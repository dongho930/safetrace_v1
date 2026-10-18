"""사건 간 연결(related-sites PR 5): 잇는 열쇠, 단축 서비스·공용 호스팅 규칙, 연결 목록, 연관 묶음, CSV 수식 방어·권한."""

import csv
import io
import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from safetrace import related
from safetrace.store import AuditLog, Case, CaseSite
from tests.conftest import INVESTIGATOR, VIEWER


@pytest.fixture(scope="module")
def client():
    from safetrace.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def store():
    from safetrace.api.main import store

    return store


@pytest.fixture(autouse=True)
def no_agent(monkeypatch):
    from safetrace.api import main

    monkeypatch.setattr(main, "enqueue", lambda cid, url: None)
    monkeypatch.setattr(main.settings, "related_auto", False)  # 자동 사건은 이 시험의 대상이 아니다


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


def finished(store, url, cands, final_url=None):
    """끝난 사건(API 가 종료 이벤트를 받는 경로 그대로)."""
    from safetrace.api.main import record_event

    with store.session() as s, s.begin():
        c = Case(url=url, source="report", status="RUNNING", created_by="t")
        s.add(c)
    record_event(c.id, {"type": "status", "status": "COMPLETED", "reason": "agent_finished", "final_url": final_url or url,
                        "threat": {"threat": "illegal_gambling", "probability": 0.9, "hold": False}, "candidates": cands})
    return c.id


def uniq():
    return secrets.token_hex(5)


def test_link_key():
    assert related.link_key("bit.ly") is None and related.link_key("han.gl") is None  # 단축 서비스는 잇지 않음
    assert related.link_key("www.facebook.com") is None  # 공식 브랜드(봇을 진짜 사이트로 보낸 곳)
    assert related.link_key("ethereum.org") is None  # 흔한 대형 사이트
    assert related.link_key("sdu.sk") is None and related.link_key("www.webflow.com") is None  # 서비스 홈
    assert related.link_key("sp21-a.pages.dev") == ("sp21-a.pages.dev", True)  # 공용 호스팅은 호스트 그대로
    assert related.link_key("www.dgjlc.com") == ("dgjlc.com", False)


def test_link_key_ignores_operator_free_keys():
    """개선 후보 5: 운영자와 무관한 열쇠로 사건을 잇지 않는다(로컬 DB 의 연관 묶음에서 관찰).
    ① nip.io(와일드카드 DNS)는 이름에 든 IP 마다 다른 호스트다 — 공격 시나리오 사건 24건이 호스트 2개인데 nip.io 하나로
    묶였다. 공용 호스팅처럼 호스트가 같을 때만 잇는다 ② 내부·예약 IP 주소는 같은 조직의 증거가 아니다 — 시험 페이지의
    내부망 링크(127.0.0.1·10.0.0.1·169.254.169.254)로 서로 다른 공격 시나리오 11건이 묶였다. 공인 IP 는 같은 서버라 잇는다."""
    assert related.link_key("127.0.0.1.nip.io") == ("127.0.0.1.nip.io", True)
    assert related.link_key("169.254.169.254.nip.io") == ("169.254.169.254.nip.io", True)
    for ip in ("127.0.0.1", "10.0.0.1", "10.255.255.1", "169.254.169.254", "192.168.0.10", "100.64.1.1", "0.0.0.0",
               "::1", "fe80::1", "::ffff:127.0.0.1"):
        assert related.link_key(ip) is None, ip
    assert related.link_key("8.8.8.8") == ("8.8.8.8", False)
    assert related.link_key("1.1.1.1.example") == ("1.example", False)  # 숫자로 시작하는 이름은 IP 가 아니다


def test_operator_free_keys_make_no_group(client, store):
    k = uniq()
    inner = [{"url": "http://127.0.0.1/admin", "host": "127.0.0.1", "source": "link"},
             {"url": "http://169.254.169.254/latest/meta-data/", "host": "169.254.169.254", "source": "link"}]
    a = finished(store, f"http://inner-a-{k}.example/", inner)
    b = finished(store, f"http://inner-b-{k}.example/", inner)
    c = finished(store, "http://127.0.0.1.nip.io/", [])
    d = finished(store, "http://169.254.169.254.nip.io/", [])
    assert client.get(f"/api/cases/{a}/links", headers=h(VIEWER)).json()["shared"] == []
    shared_c = client.get(f"/api/cases/{c}/links", headers=h(VIEWER)).json()["shared"]
    assert d not in {y["id"] for x in shared_c for y in x["cases"]}
    groups = client.get("/api/related-groups?min=2&limit=50", headers=h(VIEWER)).json()["groups"]
    assert not [g for g in groups if {a, b} <= {x["id"] for x in g["cases"]}]
    assert not [g for g in groups if {c, d} <= {x["id"] for x in g["cases"]}]


def test_case_sites_shape():
    rows = related.case_sites("http://kc.example/", "https://kc.example/x", {"threat": "illegal_gambling"}, [
        {"url": "https://bit.ly/abc", "host": "bit.ly", "source": "link"},
        {"url": "https://g.example/", "host": "g.example", "source": "link", "sub": 1, "threat": "illegal_gambling",
         "final_url": "https://www.g2.example/", "blocked": True},
        "legacy"] + [{"url": f"https://f{i}.example/", "source": "link"} for i in range(40)])
    assert len(rows) == related.SITES_PER_CASE
    assert rows[0] == {"host": "kc.example", "site": "kc.example", "role": "start", "threat": "illegal_gambling",
                       "blocked": False, "generic": False}
    assert not any(r["host"] == "bit.ly" for r in rows)
    g = [r for r in rows if r["host"] in ("g.example", "www.g2.example")]
    assert [(r["role"], r["threat"], r["blocked"]) for r in g] == [("link", "illegal_gambling", True),
                                                                    ("candidate_final", "illegal_gambling", True)]


def test_linking_rules(client, store):
    k = uniq()
    gamble = {"url": f"https://gamble-{k}.example/", "host": f"gamble-{k}.example", "source": "link", "sub": 1,
              "threat": "illegal_gambling"}
    a = finished(store, f"http://a-{k}.example/", [gamble, {"url": "https://bit.ly/x", "host": "bit.ly", "source": "link"}])
    b = finished(store, f"http://b-{k}.example/", [gamble])
    c = finished(store, f"http://c-{k}.example/", [{"url": "https://bit.ly/x", "host": "bit.ly", "source": "link"}])
    d = finished(store, f"https://one-{k}.pages.dev/", [])
    e = finished(store, f"https://two-{k}.pages.dev/", [])
    f = finished(store, f"https://one-{k}.pages.dev/again", [])
    links = client.get(f"/api/cases/{a}/links", headers=h(VIEWER)).json()
    assert [(x["site"], [y["id"] for y in x["cases"]]) for x in links["shared"]] == [(f"gamble-{k}.example", [b])]
    assert client.get(f"/api/cases/{c}/links", headers=h(VIEWER)).json()["shared"] == []  # 단축 서비스만 같음
    pd = client.get(f"/api/cases/{d}/links", headers=h(VIEWER)).json()["shared"]
    assert [[y["id"] for y in x["cases"]] for x in pd] == [[f]]  # 공용 호스팅은 호스트가 같을 때만(e 는 아님)
    groups = client.get("/api/related-groups?min=2&limit=50", headers=h(VIEWER)).json()
    mine = [g for g in groups["groups"] if {x["id"] for x in g["cases"]} & {a, b, c, d, e, f}]
    assert sorted(sorted(x["id"] for x in g["cases"]) for g in mine) == sorted([sorted([a, b]), sorted([d, f])])
    gg = next(g for g in mine if a in {x["id"] for x in g["cases"]})
    gs = next(x for x in gg["sites"] if x["site"] == f"gamble-{k}.example")
    assert (gs["threat"], gs["cases"], gs["candidate"]["case_id"] in (a, b)) == ("illegal_gambling", 2, True)
    assert isinstance(groups["ms"], int) and groups["truncated"] in (True, False)


def test_blocked_estimate_does_not_hide_threat(client, store):
    """Codex(PR 3~5) F3: 회선 차단 감지는 조사 대상 서버가 흉내 낼 수 있는 추정이다. 같은 사이트를 다른 사건이 위협으로
    봤는데 한 사건에서 차단된 척했다고 묶음이 '이미 차단됨'이 되어 위협 집계에서 빠지면 안 된다. 따로 센다."""
    k = uniq()
    site = f"gamble-{k}.example"
    a = finished(store, f"http://a-{k}.example/", [{"url": f"https://{site}/", "host": site, "source": "link", "sub": 1,
                                                    "threat": "illegal_gambling"}])
    finished(store, f"http://b-{k}.example/", [{"url": f"https://{site}/", "host": site, "source": "link", "sub": 1,
                                                 "status": "UNREACHABLE", "blocked": True}])
    groups = client.get("/api/related-groups?min=2&limit=50", headers=h(VIEWER)).json()["groups"]
    g = next(g for g in groups if a in {x["id"] for x in g["cases"]})
    s = next(x for x in g["sites"] if x["site"] == site)
    assert (s["threat"], s["blocked"], s["candidate"] is not None) == ("illegal_gambling", True, True)
    # 위협 사이트 3 = 두 신고 주소 + 차단된 척한 도박 사이트(빠지지 않음), 차단 추정은 따로 1
    assert (g["threat_sites"], g["blocked_estimate_sites"]) == (3, 1) and "open_threat_sites" not in g


def test_parent_and_children_in_links(client, store):
    k = uniq()
    cand = {"url": f"https://child-{k}.example/", "host": f"child-{k}.example", "source": "link"}
    pid = finished(store, f"http://p-{k}.example/", [cand])
    child = client.post(f"/api/cases/{pid}/related", headers=h(INVESTIGATOR), json={"url": cand["url"]}).json()
    assert [x["id"] for x in client.get(f"/api/cases/{pid}/links", headers=h(VIEWER)).json()["children"]] == [child["id"]]
    assert client.get(f"/api/cases/{child['id']}/links", headers=h(VIEWER)).json()["parent"]["id"] == pid


def test_group_csv_formula_safe_and_permissions(client, store):
    k = uniq()
    # 페이지가 고른 호스트가 수식 시작 문자로 시작한다('-')
    evil = {"url": f"https://-evil-{k}.example/", "host": f"-evil-{k}.example", "source": "link"}
    a = finished(store, f"http://a-{k}.example/", [evil])
    finished(store, f"http://x-{k}.example/", [evil])
    groups = client.get("/api/related-groups?min=2&limit=50", headers=h(VIEWER)).json()["groups"]
    g = next(g for g in groups if a in {x["id"] for x in g["cases"]})
    assert client.get(f"/api/related-groups/{g['key']}.csv", headers=h(VIEWER)).status_code == 403
    r = client.get(f"/api/related-groups/{g['key']}.csv", headers=h(INVESTIGATOR))
    assert r.status_code == 200 and r.headers["content-disposition"].startswith('attachment; filename="safetrace-related-')
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0][0] == "구분" and any(row[0] == "사건" for row in rows)
    assert not any(cell[:1] in "=+-@" for row in rows for cell in row if cell)  # 수식으로 시작하는 칸이 없다
    assert any(cell == f"'-evil-{k}.example" for row in rows for cell in row)
    with store.session() as s:
        assert s.scalar(select(AuditLog).where(AuditLog.action == "related.export", AuditLog.detail.contains(g["key"])))
    assert client.get("/api/related-groups/zzzz.csv", headers=h(INVESTIGATOR)).status_code == 404
    assert client.get("/api/related-groups/0123456789abcdef.csv", headers=h(INVESTIGATOR)).status_code == 404


def test_backfill_is_idempotent(store):
    k = uniq()
    cid = finished(store, f"http://bf-{k}.example/", [{"url": f"https://bf2-{k}.example/", "source": "link"}])

    def count():
        with store.session() as s:
            return s.scalar(select(func.count()).select_from(CaseSite).where(CaseSite.case_id == cid))

    first = count()
    related.backfill(store)
    related.backfill(store)
    assert first == count() == 3  # 시작·최종(같은 호스트라도 역할이 다르면 따로)·링크

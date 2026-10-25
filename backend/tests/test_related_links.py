"""사건 간 연결(related-sites PR 5): 잇는 열쇠, 단축 서비스·공용 호스팅 규칙, 연결된 사건 목록. 분류 폴더 '연관 묶음'
(묶음 목록·CSV)은 2026-10-25 지웠다(같은 내용이 사건마다 '연결된 사건'에 보인다)."""

import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from safetrace import related
from safetrace.store import Case, CaseSite
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


def finished(store, url, cands, final_url=None, threat="illegal_gambling"):
    """끝난 사건(API 가 종료 이벤트를 받는 경로 그대로)."""
    from safetrace.api.main import record_event

    with store.session() as s, s.begin():
        c = Case(url=url, source="report", status="RUNNING", created_by="t")
        s.add(c)
    record_event(c.id, {"type": "status", "status": "COMPLETED", "reason": "agent_finished", "final_url": final_url or url,
                        "threat": {"threat": threat, "probability": 0.9, "hold": False}, "candidates": cands})
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
    inner = [{"url": "http://127.0.0.1/admin", "host": "127.0.0.1", "source": "link", "sub": 1, "threat": "phishing"},
             {"url": "http://169.254.169.254/latest/meta-data/", "host": "169.254.169.254", "source": "link", "sub": 2,
              "threat": "phishing"}]
    a = finished(store, f"http://inner-a-{k}.example/", inner)
    b = finished(store, f"http://inner-b-{k}.example/", inner)
    c = finished(store, "http://127.0.0.1.nip.io/", [])
    d = finished(store, "http://169.254.169.254.nip.io/", [])
    assert client.get(f"/api/cases/{a}/links", headers=h(VIEWER)).json()["shared"] == []
    assert client.get(f"/api/cases/{b}/links", headers=h(VIEWER)).json()["shared"] == []
    shared_c = client.get(f"/api/cases/{c}/links", headers=h(VIEWER)).json()["shared"]
    assert d not in {y["id"] for x in shared_c for y in x["cases"]}


def test_case_sites_shape():
    rows = related.case_sites("http://kc.example/", "https://kc.example/x", {"threat": "illegal_gambling"}, [
        {"url": "https://bit.ly/abc", "host": "bit.ly", "source": "link"},
        {"url": "https://g.example/", "host": "g.example", "source": "link", "sub": 1, "threat": "illegal_gambling",
         "final_url": "https://www.g2.example/", "blocked": True},
        "legacy"] + [{"url": f"https://f{i}.example/", "source": "link", "sub": 1, "threat": "phishing"} for i in range(40)])
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
    assert client.get(f"/api/cases/{e}/links", headers=h(VIEWER)).json()["shared"] == []


def test_parent_and_children_in_links(client, store):
    k = uniq()
    cand = {"url": f"https://child-{k}.example/", "host": f"child-{k}.example", "source": "link"}
    pid = finished(store, f"http://p-{k}.example/", [cand])
    child = client.post(f"/api/cases/{pid}/related", headers=h(INVESTIGATOR), json={"url": cand["url"]}).json()
    assert [x["id"] for x in client.get(f"/api/cases/{pid}/links", headers=h(VIEWER)).json()["children"]] == [child["id"]]
    assert client.get(f"/api/cases/{child['id']}/links", headers=h(VIEWER)).json()["parent"]["id"] == pid


def test_group_folder_api_removed(client):
    """분류 폴더 '연관 묶음'(묶음 목록·CSV)은 지웠다(2026-10-25): 묶음 API 가 남아 있지 않다."""
    assert client.get("/api/related-groups?min=2&limit=50", headers=h(VIEWER)).status_code == 404
    assert client.get(f"/api/related-groups/{'0' * 16}.csv", headers=h(INVESTIGATOR)).status_code == 404


def test_backfill_is_idempotent(store):
    k = uniq()
    cid = finished(store, f"http://bf-{k}.example/", [{"url": f"https://bf2-{k}.example/", "source": "link", "sub": 1,
                                                       "threat": "illegal_gambling"}])

    def count():
        with store.session() as s:
            return s.scalar(select(func.count()).select_from(CaseSite).where(CaseSite.case_id == cid))

    first = count()
    related.backfill(store)
    related.backfill(store)
    assert first == count() == 3  # 시작·최종(같은 호스트라도 역할이 다르면 따로)·링크


def test_benign_cases_and_unchecked_links_do_not_link(client, store):
    """2026-10-25 로컬 DB 연관 묶음: 쇼핑몰 정상 사이트 11건이 바닥글의 공정위·SNS 링크로, 피싱 48건이 Cloudflare 경고 화면의
    cloudflare.com 링크(조사하지 않음)로 한 묶음이 됐다. 정상으로 본 사건과, 하위 조사로 위험하다고 확인하지 않은 링크로는
    잇지 않는다. 위험하다고 확인한 링크(위협·평판 위험·회선 차단 추정)와 경유 도메인은 그대로 잇는다."""
    k = uniq()
    footer = {"url": f"https://footer-{k}.example/info", "host": f"footer-{k}.example", "source": "link"}
    a = finished(store, f"https://shop-a-{k}.example/", [footer], threat="benign")
    b = finished(store, f"https://shop-b-{k}.example/", [footer], threat="benign")
    c = finished(store, f"https://phish-c-{k}.example/", [footer], threat="phishing")
    d = finished(store, f"https://phish-d-{k}.example/", [footer], threat="phishing")
    rep = {"url": f"https://rep-{k}.example/", "host": f"rep-{k}.example", "source": "link", "sub": 1, "threat": "benign",
           "reputation_match": True}
    via = {"url": f"https://tds-{k}.example/go", "host": f"tds-{k}.example", "source": "via"}
    e = finished(store, f"https://phish-e-{k}.example/", [rep, via], threat="phishing")
    f = finished(store, f"https://phish-f-{k}.example/", [rep], threat="phishing")
    g = finished(store, f"https://phish-g-{k}.example/", [via], threat="phishing")
    def linked(cid):
        return {y["id"] for x in client.get(f"/api/cases/{cid}/links", headers=h(VIEWER)).json()["shared"] for y in x["cases"]}

    assert [linked(x) & {a, b, c, d, e, f, g} for x in (a, b, c, d)] == [set(), set(), set(), set()]
    assert linked(e) & {a, b, c, d, e, f, g} == {f, g}
    with store.session() as s:
        assert not s.scalar(select(func.count()).select_from(CaseSite).where(CaseSite.case_id.in_([a, b])))


def test_final_url_links_only_when_it_is_the_reported_site():
    """2026-10-25: 피싱 키트가 봇을 진짜 브랜드 사이트(allegro.pl, 목록 밖)로 보내 최종 주소가 그 사이트가 되면, 그 브랜드를
    사칭한 서로 다른 사건이 최종 주소로 묶였다. 최종 주소는 신고 주소와 같은 사이트이거나, 신고 주소로 이을 수 없을 때
    (단축 서비스·대형 서비스)만 잇는다."""
    th = {"threat": "phishing"}
    roles = lambda rows: [(r["role"], r["site"]) for r in rows]  # noqa: E731
    assert roles(related.case_sites("https://allegro.kit1.example/a", "https://allegro.pl/", th, [])) == [
        ("start", "kit1.example")]
    assert roles(related.case_sites("https://a.kit1.example/", "https://b.kit1.example/x", th, [])) == [
        ("start", "kit1.example"), ("final", "kit1.example")]
    assert roles(related.case_sites("https://bit.ly/abc", "https://land.example/", th, [])) == [("final", "land.example")]
    assert roles(related.case_sites("https://sites.google.com/view/x", "https://land.example/", th, [])) == [
        ("final", "land.example")]


def test_big_services_and_workers_dev_do_not_join_strangers():
    """2026-10-25: cloudflare.com·google.com·WhatsApp 처럼 위협 화면이 흔히 링크하는 대형 서비스와 피싱 키트가 링크한 진짜
    브랜드 사이트는 하위 조사가 위협으로 봐도(Cloudflare 피싱 경고 화면, 진짜 Wells Fargo 로그인) 잇지 않는다. workers.dev 는 하위 도메인마다 운영자가 달라 호스트가 같을 때만 잇는다."""
    th = {"threat": "phishing"}
    cands = [{"url": f"https://{h}/x", "source": "link", "sub": 1, "threat": "phishing", "final_url": f"https://{h}/y"}
             for h in ("www.cloudflare.com", "www.google.com", "api.whatsapp.com", "wa.me", "x.blogger.com",
                       "oam.wellsfargo.com")]  # 마지막은 피싱 키트가 링크한 진짜 은행 사이트(하위 조사 피싱 0.62, 10/21)
    assert [r["role"] for r in related.case_sites("https://p.example/", None, th, cands)] == ["start"]
    assert related.link_key("login.acct1.workers.dev") == ("login.acct1.workers.dev", True)
    assert related.link_key("www.cloudflare.com") == ("cloudflare.com", False)  # 후보 고르기·운영 정보에는 그대로

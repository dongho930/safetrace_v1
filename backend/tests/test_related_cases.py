"""연관 후보를 새 사건으로 접수(related-sites PR 4): 후보 출처 검사, 같은 후보는 한 번, 권한·접수 한도, 부모·자식 연결."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from safetrace.store import AuditLog, Case, CaseLink
from tests.conftest import INVESTIGATOR, SERVICE_ADMIN, VIEWER


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

    queued: list[str] = []
    monkeypatch.setattr(main, "enqueue", lambda cid, url: queued.append(cid))
    return queued


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


CANDS = [{"url": "https://dgjlc.example/", "host": "dgjlc.example", "source": "link", "sub": 1,
          "status": "COMPLETED", "threat": "illegal_gambling", "probability": 0.9, "hold": False,
          "final_url": "https://www.dgjlc.example/home"},
         {"url": "https://other.example/x", "host": "other.example", "source": "link"},
         "legacy.example"]  # 예전 사건은 도메인 이름 목록


def parent_case(store, cands=CANDS):
    with store.session() as s, s.begin():
        c = Case(url="http://kc-telegram.example/", source="report", status="COMPLETED", created_by="t",
                 threat={"threat": "illegal_gambling", "probability": 0.9, "hold": False}, candidates=cands)
        s.add(c)
    return c.id


def related(client, tok, cid, url):
    return client.post(f"/api/cases/{cid}/related", headers=h(tok), json={"url": url})


def test_create_related_case_and_links(client, store, no_agent):
    pid = parent_case(store)
    r = related(client, INVESTIGATOR, pid, "https://dgjlc.example/")
    assert r.status_code == 201, r.text
    child = r.json()
    assert (child["source"], child["url"], child["parent_id"], child["parent_url"], child["auto"]) == (
        "related", "https://dgjlc.example/", pid, "http://kc-telegram.example/", False)
    assert no_agent == [child["id"]]  # 전체 조사로 대기열에 넣는다
    with store.session() as s:
        link = s.get(CaseLink, child["id"])
        assert (link.parent_id, link.candidate_url, link.target_host) == (pid, "https://dgjlc.example/", "www.dgjlc.example")
        a = s.scalars(select(AuditLog).where(AuditLog.case_id == child["id"], AuditLog.action == "case.create_related")).one()
        assert f"parent={pid}" in a.detail and "url=https://dgjlc.example/" in a.detail
    # 같은 후보를 다시 누르면 같은 사건(200), 대기열에 다시 넣지 않는다
    again = related(client, INVESTIGATOR, pid, "https://dgjlc.example/")
    assert again.status_code == 200 and again.json()["id"] == child["id"] and no_agent == [child["id"]]
    # 부모 상세에 자식, 목록에 연관 표시
    p = client.get(f"/api/cases/{pid}", headers=h(VIEWER)).json()
    assert [(k["id"], k["candidate_url"], k["status"], k["auto"]) for k in p["children"]] == [
        (child["id"], "https://dgjlc.example/", "QUEUED", False)]
    listed = {x["id"]: x for x in client.get("/api/cases?limit=200", headers=h(VIEWER)).json()}
    assert listed[child["id"]]["parent_id"] == pid and listed[child["id"]]["source"] == "related"
    assert listed[pid]["children"] is None  # 목록에는 자식 목록을 싣지 않는다


def test_only_candidates_of_that_case(client, store):
    pid = parent_case(store)
    assert related(client, INVESTIGATOR, pid, "https://not-a-candidate.example/").status_code == 422
    assert related(client, INVESTIGATOR, pid, "https://dgjlc.example/?x=1").status_code == 422  # 정확히 같아야 한다
    assert related(client, INVESTIGATOR, pid, "legacy.example").status_code == 422  # 예전 형식(글자) 후보는 받지 않음
    assert related(client, INVESTIGATOR, "0" * 36, "https://dgjlc.example/").status_code == 404


def test_permissions_follow_create_case(client, store):
    pid = parent_case(store)
    assert client.post(f"/api/cases/{pid}/related", json={"url": "https://other.example/x"}).status_code == 401
    assert related(client, VIEWER, pid, "https://other.example/x").status_code == 403
    assert related(client, SERVICE_ADMIN, pid, "https://other.example/x").status_code == 201  # 자동화 토큰도 접수와 같다


def test_intake_limit_applies(client, store, monkeypatch):
    from safetrace.api import main

    pid = parent_case(store)
    monkeypatch.setattr(main.settings, "case_max_pending_per_principal", 0)
    r = related(client, INVESTIGATOR, pid, "https://other.example/x")
    assert r.status_code == 429
    with store.session() as s:
        assert s.scalar(select(CaseLink).where(CaseLink.parent_id == pid)) is None


def test_people_cannot_choose_related_source(client):
    r = client.post("/api/cases", headers=h(INVESTIGATOR), json={"url": "https://x.example/", "source": "related"})
    assert r.status_code == 422

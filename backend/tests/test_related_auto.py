"""연관 후보 자동 사건(related-sites PR 4b): 선별 조건 1~9, 깊이 1, 중복·동시성, 사람 접수 한도와 분리, 실패 격리."""

import secrets
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from safetrace import related
from safetrace.store import AuditLog, Case, CaseLink
from tests.conftest import INVESTIGATOR, VIEWER

GOOD = {"url": "https://dgjlc.example/", "host": "dgjlc.example", "source": "link", "sub": 1, "status": "COMPLETED",
        "threat": "illegal_gambling", "probability": 0.9, "hold": False, "final_url": "https://www.dgjlc.example/"}
OPTS = {"enabled": True, "threat_min_prob": 0.6}


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
def isolated(monkeypatch, store):
    """자동 사건 한도·중복은 DB 전체를 본다: 시험마다 도착 호스트를 바꾸고, 앞 시험의 대기 자동 사건은 끝낸다."""
    from safetrace.api import main

    queued: list[str] = []
    monkeypatch.setattr(main, "enqueue", lambda cid, url: queued.append(cid))
    with store.session() as s, s.begin():
        for c in s.scalars(select(Case).where(Case.created_by == related.AUTO_ACTOR, Case.status.in_(("QUEUED", "RUNNING")))):
            c.status = "COMPLETED"
    return queued


def cand(**over):
    i = secrets.token_hex(6)  # 시험 DB 가 남아 있어도 중복 조건(7일)에 걸리지 않게 실행마다 다른 호스트
    return {**GOOD, "url": f"https://site{i}.example/", "host": f"site{i}.example", "final_url": f"https://www.site{i}.example/",
            **over}


def finish(store, cands, source="report", signed=None):
    """조사 중인 원 사건을 만들고 종료 이벤트를 보낸다(API 가 받는 경로 그대로). runner 처럼 증거 체인에 후보 기록과
    하위 조사 결과 기록을 서명해 남긴다(자동 사건은 이 기록으로 고른다). signed: 체인에 남길 후보(없으면 cands 와 같다)."""
    from safetrace.agent.runner import make_sealer
    from safetrace.api.main import record_event, settings
    from safetrace.evidence import EvidenceWriter

    with store.session() as s, s.begin():
        c = Case(url="http://kc-telegram.example/", source=source, status="RUNNING", created_by="t")
        s.add(c)
    rows = [dict(x) for x in (cands if signed is None else signed) if isinstance(x, dict)]
    w = EvidenceWriter(settings.evidence_dir, c.id, make_sealer(settings))
    w.append("start", {"url": c.url})
    w.append("candidates", {"found": rows, "followup": True, "investigated": sum(1 for x in rows if x.get("sub")),
                            "main": {"status": "COMPLETED", "reason": "agent_finished"}})
    if any(x.get("sub") for x in rows):
        w.append("candidate_results", {"results": [x for x in rows if x.get("sub")]})
    record_event(c.id, {"type": "status", "status": "COMPLETED", "reason": "agent_finished",
                        "threat": {"threat": "illegal_gambling", "probability": 0.9, "hold": False}, "candidates": cands,
                        "head": {"seq": w.head.seq, "hash": w.head.hash}})
    return c.id


def children(store, pid):
    with store.session() as s:
        return list(s.scalars(select(CaseLink).where(CaseLink.parent_id == pid)))


# ── 순수 함수: 조건 1~6 ─────────────────────────
@pytest.mark.parametrize("over, opts, source, reason", [
    ({}, {"enabled": False}, "report", "disabled"),                       # 1
    ({}, {}, "related", "depth"),                                         # 2
    ({"sub": None}, {}, "report", "not_threat"),                          # 3 하위 조사 안 함
    ({"status": "UNREACHABLE"}, {}, "report", "not_threat"),              # 3 선별 결과 없음
    ({"status": None}, {}, "report", "not_threat"),                       # 3 상태가 없으면 결과 없음(Codex 3회차 F2)
    ({"threat": "benign"}, {}, "report", "not_threat"),                   # 4
    ({"probability": 0.5}, {}, "report", "not_threat"),                   # 4 원래 사건의 기준 미만
    ({"hold": True}, {}, "report", "not_threat"),                         # 4 보류
    ({"blocked": True}, {}, "report", None),                              # 5 회선 차단은 추정이라 건너뛰지 않음
    ({"final_url": "https://bit.ly/abc", "host": "bit.ly"}, {}, "report", "shortener"),  # 6
    ({}, {}, "report", None),
    ({"threat": "benign", "reputation_match": True}, {}, "report", None),  # 4 평판 위험은 AI 판단과 무관하게
])
def test_skip_reason(over, opts, source, reason):
    assert related.skip_reason(source, {**GOOD, **over}, **{**OPTS, **opts}) == reason


def test_auto_targets_reason():
    rep = {**GOOD, "url": "https://r.example/", "threat": "benign", "reputation_match": True}
    held = {**GOOD, "url": "https://b.example/", "hold": True}
    got = related.auto_targets("report", [GOOD, {"url": 5}, "x", rep, held], **OPTS)
    assert [(c["url"], why) for c, why in got] == [(GOOD["url"], "threat"), ("https://r.example/", "reputation")]


# ── API: 종료 이벤트 뒤 자동 생성 ─────────────────────────
def test_creates_only_selected_candidates(client, store, isolated):
    good, benign, held = cand(), cand(threat="benign"), cand(hold=True)
    pid = finish(store, [good, benign, held, cand(sub=None)])
    links = children(store, pid)
    assert [(lk.candidate_url, lk.auto, lk.target_host, lk.created_by) for lk in links] == [
        (good["url"], True, good["final_url"][8:-1], related.AUTO_ACTOR)]
    assert isolated == [links[0].child_id]
    with store.session() as s:
        a = s.scalars(select(AuditLog).where(AuditLog.case_id == links[0].child_id,
                                             AuditLog.action == "case.create_related_auto")).one()
    assert f"parent={pid}" in a.detail and "why=threat threat=illegal_gambling p=0.90" in a.detail
    d = client.get(f"/api/cases/{pid}", headers={"Authorization": f"Bearer {VIEWER}"}).json()
    assert [k["auto"] for k in d["children"]] == [True]
    assert {x["url"]: x["reason"] for x in d["auto_skipped"]} == {benign["url"]: "not_threat", held["url"]: "not_threat"}
    child = client.get(f"/api/cases/{links[0].child_id}", headers={"Authorization": f"Bearer {VIEWER}"}).json()
    assert (child["source"], child["auto"], child["parent_id"]) == ("related", True, pid)


def test_unsigned_candidate_cannot_create_case(store, isolated):
    """Codex 3회차 F2: 침해된 워커가 종료 이벤트에만 위협 후보(하위 조사·평판 위험 표시)를 넣으면, 서명된 증거에는 그런
    하위 조사가 없으므로 자동 사건을 만들지 않는다. 체인을 검증하지 못해도(끝을 잘라 냄) 만들지 않는다."""
    forged = cand(threat=None, probability=None, status=None, reputation_match=True)
    pid = finish(store, [forged], signed=[{k: forged[k] for k in ("url", "host", "source")}])
    assert children(store, pid) == [] and isolated == []
    pid = finish(store, [cand()], signed=[])  # 체인에는 후보가 없다
    assert children(store, pid) == [] and isolated == []
    from safetrace.api.main import settings

    good = cand()
    pid2 = finish(store, [good])
    with store.session() as s, s.begin():  # 증거가 맞을 때만: 체인 끝을 잘라 내면 검증 실패
        s.query(CaseLink).filter(CaseLink.parent_id == pid2).delete()
    chain = settings.evidence_dir / pid2 / "chain.jsonl"
    lines = chain.read_text(encoding="utf-8").splitlines()
    chain.write_text("".join(x + "\n" for x in lines[:-1]), encoding="utf-8")
    from safetrace.api.main import _auto_related

    before = len(isolated)
    _auto_related(pid2)
    assert children(store, pid2) == [] and len(isolated) == before
    with store.session() as s:
        assert s.scalar(select(AuditLog).where(AuditLog.case_id == pid2, AuditLog.detail == "chain_unverified"))


def test_no_grandchildren(store):
    """깊이 1: 연관 사건(자동·버튼)이 위협 후보를 가진 채 끝나도 손자 사건을 만들지 않는다."""
    pid = finish(store, [cand()], source="related")
    assert children(store, pid) == []


def test_redelivered_terminal_event_creates_once(store):
    from safetrace.api.main import _auto_related

    pid = finish(store, [cand()])
    _auto_related(pid)  # 같은 종료 이벤트를 다시 받은 경우(xautoclaim)
    assert len(children(store, pid)) == 1


def test_duplicate_host_and_concurrent_parents(store):
    """조건 7: 최근 같은 도착 호스트로 만든 연관 사건이 있으면 만들지 않는다. 동시에 끝난 두 부모도 하나만."""
    shared = cand()
    out: list[str] = []
    ts = [threading.Thread(target=lambda: out.append(finish(store, [{**shared, "url": f"{shared['url']}p{i}"}]))) for i in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sum(len(children(store, p)) for p in out) == 1
    with store.session() as s:
        skipped = s.scalars(select(AuditLog).where(AuditLog.action == "case.create_related_auto_skipped",
                                                   AuditLog.case_id.in_(out))).all()
    assert any(x.detail.startswith("duplicate") for x in skipped)


def test_per_case_limit(store, monkeypatch):
    from safetrace.api import main

    monkeypatch.setattr(main.settings, "related_auto_per_case", 2)
    pid = finish(store, [cand(), cand(), cand()])
    assert len(children(store, pid)) == 2  # 조건 8


def test_auto_pending_limit_and_people_unaffected(client, store, monkeypatch):
    """조건 9: 끝나지 않은 자동 사건이 한도면 더 만들지 않는다. 자동 사건이 쌓여도 사람 접수(전체 한도)는 막히지 않고,
    담당자 버튼 접수도 된다."""
    from safetrace.api import main

    monkeypatch.setattr(main.settings, "related_auto_max_pending", 2)
    first = finish(store, [cand(), cand()])
    assert len(children(store, first)) == 2
    second = finish(store, [cand()])
    assert children(store, second) == []  # 자동 한도
    with store.session() as s:
        humans = s.scalar(select(func.count()).select_from(Case).where(
            Case.status.in_(("QUEUED", "RUNNING")), Case.created_by != related.AUTO_ACTOR))
    # 자동 사건 2건까지 세면 넘는 전체 한도: 자동 사건을 빼고 세므로 사람 접수는 된다
    monkeypatch.setattr(main.settings, "case_max_pending_total", humans + 1)
    h = {"Authorization": f"Bearer {INVESTIGATOR}"}
    assert client.post("/api/cases", headers=h, json={"url": "https://people.example/"}).status_code == 201
    monkeypatch.setattr(main.settings, "case_max_pending_total", 1000)
    with store.session() as s:
        url = s.get(Case, second).candidates[0]["url"]
    r = client.post(f"/api/cases/{second}/related", headers=h, json={"url": url})
    assert r.status_code == 201 and r.json()["auto"] is False


def test_failure_does_not_stop_event_processing(store, monkeypatch):
    from safetrace.api import main

    def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(main.related, "auto_targets", boom)
    pid = finish(store, [cand()])
    with store.session() as s:
        assert s.get(Case, pid).status == "COMPLETED"  # 원 사건 상태는 반영됐다
        assert s.scalar(select(AuditLog).where(AuditLog.case_id == pid, AuditLog.action == "case.create_related_auto_failed"))


def test_worker_has_no_case_creation_path():
    """자동 생성은 격리망 밖 API 만 한다: 에이전트(워커) 코드에 사건을 만드는 경로가 없다."""
    agent = Path(__file__).resolve().parents[1] / "safetrace" / "agent"
    for f in agent.glob("*.py"):
        src = f.read_text(encoding="utf-8")
        assert "create_related_case" not in src and "..store" not in src and "CaseLink" not in src, f.name


def test_auto_actor_is_not_a_principal(store):
    from safetrace import accounts

    with pytest.raises(accounts.AccountError):
        accounts.create_user(store, related.AUTO_ACTOR, "correct-horse-battery-9", "admin")

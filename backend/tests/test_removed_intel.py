"""지운 운영 정보·키트 지문(2026-10-25)이 남긴 예전 기록이 새어 나가지 않는지.

이전 판의 에이전트가 증거 체인·이벤트에 남긴 `intel` 기록(페이지에 적힌 전화·계좌 원래 값)과 연결 줄(contact·kit)은 지운 뒤에도
DB·증거 볼륨에 남는다. 원래 값은 조사관 이상만 받는 검토 패키지 ZIP 의 체인에만 두고, 실시간 이벤트·패키지 요약·연관 묶음에는
나가지 않아야 한다."""

import asyncio
import secrets
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from safetrace import related
from safetrace.store import Case, CaseSite
from tests.conftest import INVESTIGATOR

PHONE = "01011112222"


def _intel_event():
    return {"type": "evidence", "seq": 0, "kind": "intel", "files": [], "hash": "",
            "data": {"step": 0, "items": [{"kind": "phone", "value": PHONE, "src": "link"}]}}


def test_legacy_intel_events_are_sent_to_nobody():
    """예전 판이 이벤트로 남긴 운영 정보 원래 값은 조사관에게도 보내지 않는다(가려 보내던 기능을 지웠다)."""
    from safetrace.api import main as m

    with m.store.session() as s, s.begin():
        c = Case(url="http://legacy-intel.example/", source="test", status="RUNNING", created_by="t")
        s.add(c)
    m.store.add_event(c.id, _intel_event())
    m.store.add_event(c.id, {"type": "status", "status": "FAILED", "reason": "test"})
    with TestClient(m.app):
        resp = asyncio.run(m.case_events(c.id, m._principal(INVESTIGATOR), 0, authorization=f"Bearer {INVESTIGATOR}"))

        async def run():
            return [x async for x in resp.body_iterator]

        got = "".join(asyncio.run(asyncio.wait_for(run(), 30)))
    assert '"FAILED"' in got and PHONE not in got and '"intel"' not in got


def test_legacy_intel_records_stay_out_of_package_summary(tmp_path):
    """예전 체인의 intel 기록은 검토 패키지 요약(열람자도 받는다)에 들어가지 않고, 자료형 검사에서 깨진 기록으로 세지도 않는다."""
    from safetrace import package
    from safetrace.evidence import EvidenceWriter, Signer

    cid = str(uuid.uuid4())
    w = EvidenceWriter(tmp_path, cid, Signer(b"k" * 32, "t"))
    w.append("start", {"url": "http://legacy.example/"})
    w.append("observe", {"step": 0, "url": "http://legacy.example/", "title": "t", "candidates": []})
    w.append("intel", {"step": 0, "obs": 1, "url": "http://legacy.example/",
                       "items": [{"kind": "phone", "value": PHONE, "src": "text"}], "kit": {"dom": "a" * 32}})
    recs, bad = package.clean_records(package.parse_chain((tmp_path / cid / "chain.jsonl").read_text(encoding="utf-8")))
    assert bad == []
    exploration = repr(package._exploration(recs))  # 패키지 요약의 탐색 경위(단계별 관찰·선택·실행)
    assert "legacy.example" in exploration and PHONE not in exploration and "'intel'" not in exploration


def test_backfill_drops_legacy_contact_and_kit_rows():
    """예전 연결 줄(운영 정보·키트 지문)은 다시 쓰기 때 지워져 연관 묶음·연결된 사건에 나오지 않는다."""
    from safetrace.api.main import record_event, store

    with store.session() as s, s.begin():
        c = Case(url=f"http://legacy-{secrets.token_hex(4)}.example/", source="test", status="RUNNING", created_by="t")
        s.add(c)
    record_event(c.id, {"type": "status", "status": "COMPLETED", "reason": "agent_finished", "final_url": c.url,
                        "threat": {"threat": "phishing", "probability": 0.9, "hold": False}, "candidates": []})
    with store.session() as s, s.begin():
        s.add(CaseSite(case_id=c.id, host="010-****-2222", site="phone:abc", role="contact", threat="phishing",
                       blocked=False, generic=False))
        s.add(CaseSite(case_id=c.id, host="x.example", site="kit:dom:" + "a" * 32, role="kit", threat="phishing",
                       blocked=False, generic=False))
    related.backfill(store)
    with store.session() as s:
        roles = set(s.scalars(select(CaseSite.role).where(CaseSite.case_id == c.id)))
        legacy = s.scalar(select(func.count()).select_from(CaseSite).where(CaseSite.role.in_(("contact", "kit"))))
    assert roles == {"start", "final"} and legacy == 0


def test_legacy_links_excluded_without_backfill():
    """Codex 1회차 F1: 다시 쓰기(backfill) 없이 업그레이드해도 예전 연결 줄(contact·kit)이 연관 묶음·연결된 사건에 '사이트'로
    나오거나 위협 사이트 수에 섞이지 않는다(그 줄의 threat 는 목적지를 조사한 결과가 아니라 원 사건의 판단을 복사한 것이다)."""
    from fastapi.testclient import TestClient

    from safetrace.api.main import app, record_event, store

    key = f"form:victim-{secrets.token_hex(4)}.example.net:" + "b" * 24
    ids = []
    for _ in range(2):
        with store.session() as s, s.begin():
            c = Case(url=f"http://legacy-{secrets.token_hex(4)}.example/", source="test", status="RUNNING", created_by="t")
            s.add(c)
        record_event(c.id, {"type": "status", "status": "COMPLETED", "reason": "agent_finished", "final_url": c.url,
                            "threat": {"threat": "phishing", "probability": 0.9, "hold": False}, "candidates": []})
        with store.session() as s, s.begin():
            s.add(CaseSite(case_id=c.id, host=key.split(":")[1], site=key, role="contact", threat="phishing",
                           blocked=False, generic=False))
        ids.append(c.id)
    with TestClient(app) as client:
        from tests.conftest import VIEWER

        groups = client.get("/api/related-groups?min=2&limit=50", headers={"Authorization": f"Bearer {VIEWER}"}).json()
        links = client.get(f"/api/cases/{ids[0]}/links", headers={"Authorization": f"Bearer {VIEWER}"}).json()
    assert not [g for g in groups["groups"] if set(ids) <= {x["id"] for x in g["cases"]}]
    assert not [g for g in links["shared"] if g["site"] == key]

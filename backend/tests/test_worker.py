"""워커: 조사 중에 죽은 워커의 작업을 실패로 마무리한다(사건이 '조사 중'에 멈추지 않게)."""

import json

from safetrace.agent.worker import EVENTS, recover_interrupted

CID = "7f2d2457-9074-44e5-a61a-2675e2907334"


class FakeRedis:
    """xautoclaim·xack·xadd·xinfo_consumers·xgroup_delconsumer 만 흉내 낸다."""

    def __init__(self, pending, consumers):
        self.pending = pending  # {msg_id: (consumer, idle_ms, fields)}
        self.consumers = consumers  # {name: idle_ms}
        self.events, self.acked, self.deleted = [], [], []

    def xautoclaim(self, stream, group, consumer, min_idle, start_id="0-0", count=None):
        ids = sorted(m for m, (_, idle, _) in self.pending.items() if idle >= min_idle and m >= start_id)
        take, rest = ids[:count], ids[count:]
        for m in take:
            _, _, f = self.pending[m]
            self.pending[m] = (consumer, 0, f)
        return [rest[0] if rest else "0-0", [(m, self.pending[m][2]) for m in take], []]

    def xack(self, stream, group, msg_id):
        self.acked.append(msg_id)
        self.pending.pop(msg_id, None)

    def xadd(self, stream, fields, maxlen=None):
        self.events.append((stream, fields))

    def xinfo_consumers(self, stream, group):
        return [{"name": n, "idle": idle, "pending": sum(1 for c, _, _ in self.pending.values() if c == n)}
                for n, idle in self.consumers.items()]

    def xgroup_delconsumer(self, stream, group, name):
        self.deleted.append(name)


def test_interrupted_job_marked_failed_and_acked():
    r = FakeRedis({"1-0": ("dead", 999_999, {"case_id": CID, "url": "https://x.example/"}),
                   "2-0": ("dead", 999_999, {"case_id": "bad", "url": ""})},
                  {"dead": 999_999, "me": 0})
    assert recover_interrupted(r, "me", 240_000) == [CID]
    assert sorted(r.acked) == ["1-0", "2-0"]  # 형식이 틀린 작업도 확인해 치운다
    (stream, fields), = r.events
    assert stream == EVENTS and fields["case_id"] == CID
    assert json.loads(fields["payload"]) == {"type": "status", "status": "FAILED", "reason": "error:interrupted"}
    assert r.deleted == ["dead"]  # 비워진 죽은 컨슈머는 지운다(자기 자신은 남김)


def test_running_job_of_live_worker_not_taken():
    """최대 조사 시간 안의 작업은 다른 워커가 아직 조사 중일 수 있으므로 건드리지 않는다."""
    r = FakeRedis({"1-0": ("other", 30_000, {"case_id": CID, "url": "https://x.example/"})},
                  {"other": 30_000, "idle-empty": 10_000})
    assert recover_interrupted(r, "me", 240_000) == []
    assert r.acked == [] and r.events == [] and r.deleted == []


def test_many_pending_paged():
    pending = {f"{i}-0": ("dead", 999_999, {"case_id": CID, "url": "u"}) for i in range(1, 121)}
    r = FakeRedis(pending, {"dead": 999_999})
    assert len(recover_interrupted(r, "me", 240_000)) == 120
    assert r.pending == {}

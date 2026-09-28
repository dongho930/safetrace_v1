"""에이전트 워커: Redis Streams 에서 작업을 받아 조사하고, 이벤트를 다시 Redis 로 보낸다.

워커는 DB 접속 정보도 Jev API 키도 갖지 않는다.
실행: python -m safetrace.agent.worker
"""

from __future__ import annotations

import json
import logging
import re
import socket

import redis

from ..config import get_settings
from .runner import investigate

log = logging.getLogger("safetrace.worker")

JOBS = "st:jobs"
EVENTS = "st:events"
GROUP = "agents"
_CASE_ID = re.compile(r"^[a-f0-9\-]{36}$")


def main():
    logging.basicConfig(level=logging.INFO)
    s = get_settings()
    r = redis.Redis.from_url(s.redis_url, decode_responses=True, socket_timeout=30)  # XREADGROUP block(5초)보다 길게
    try:
        r.xgroup_create(JOBS, GROUP, id="0", mkstream=True)
    except redis.ResponseError:
        pass
    consumer = socket.gethostname()
    while True:
        resp = r.xreadgroup(GROUP, consumer, {JOBS: ">"}, count=1, block=5000)
        for _, msgs in resp or []:
            for msg_id, fields in msgs:
                case_id, url = fields.get("case_id", ""), fields.get("url", "")
                if not _CASE_ID.match(case_id):
                    r.xack(JOBS, GROUP, msg_id)
                    continue

                def emit(ev: dict, cid=case_id):
                    r.xadd(EVENTS, {"case_id": cid, "payload": json.dumps(ev, ensure_ascii=False)}, maxlen=100000)

                try:
                    investigate(case_id, url, s, emit)
                except Exception as e:
                    log.exception("investigation failed")
                    emit({"type": "status", "status": "FAILED", "reason": f"error:{type(e).__name__}"})
                finally:
                    r.xack(JOBS, GROUP, msg_id)


if __name__ == "__main__":
    main()

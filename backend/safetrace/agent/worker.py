"""에이전트 워커: Redis Streams 에서 작업을 받아 조사하고, 이벤트를 다시 Redis 로 보낸다.

워커는 DB 접속 정보도 Jev API 키도 갖지 않는다.
실행: python -m safetrace.agent.worker
"""

from __future__ import annotations

import json
import logging
import re
import socket
import time

import redis

from ..config import get_settings
from ..live import RedisLivePublisher
from .runner import investigate

log = logging.getLogger("safetrace.worker")

JOBS = "st:jobs"
EVENTS = "st:events"
GROUP = "agents"
_CASE_ID = re.compile(r"^[a-f0-9\-]{36}$")
RECOVER_EVERY = 60  # 끊긴 작업을 찾아보는 간격(초)


def recover_interrupted(r, consumer: str, min_idle_ms: int) -> list[str]:
    """조사 중에 워커가 죽어(컨테이너 재시작 등) 끝나지 않은 작업을 실패로 마무리한다. 마무리한 사건 ID 를 돌려준다.

    읽고 확인(XACK)하지 못한 작업은 죽은 컨슈머 이름으로 영영 남고, 사건은 '조사 중'에 멈춘다.
    다시 조사하지는 않는다: 반쯤 쓴 증거 체인 뒤에 이어 쓰게 되므로, 재조사는 담당자가 새 사건으로 접수한다.
    min_idle_ms 는 최대 조사 시간보다 길게 잡아 살아 있는 다른 워커의 작업을 가로채지 않는다.
    """
    done: list[str] = []
    start = "0-0"
    while True:
        start, msgs, *_ = r.xautoclaim(JOBS, GROUP, consumer, min_idle_ms, start_id=start, count=50)
        for msg_id, fields in msgs:
            case_id = (fields or {}).get("case_id", "")
            if _CASE_ID.match(case_id):
                r.xadd(EVENTS, {"case_id": case_id, "payload": json.dumps(
                    {"type": "status", "status": "FAILED", "reason": "error:interrupted"})}, maxlen=100000)
                done.append(case_id)
            r.xack(JOBS, GROUP, msg_id)
        if start == "0-0":
            break
    # 재시작마다 새 이름(호스트 이름)으로 생긴 빈 컨슈머를 지운다
    for c in r.xinfo_consumers(JOBS, GROUP):
        if c["name"] != consumer and c["pending"] == 0 and c["idle"] >= min_idle_ms:
            r.xgroup_delconsumer(JOBS, GROUP, c["name"])
    return done


def main():
    logging.basicConfig(level=logging.INFO)
    s = get_settings()
    r = redis.Redis.from_url(s.redis_url, decode_responses=True, socket_timeout=30)  # XREADGROUP block(5초)보다 길게
    try:
        r.xgroup_create(JOBS, GROUP, id="0", mkstream=True)
    except redis.ResponseError:
        pass
    consumer = socket.gethostname()
    live = RedisLivePublisher(s.redis_url)  # 콘솔 실시간 화면(시청 중일 때만 발행)
    min_idle_ms = (s.max_seconds + 120) * 1000
    last_recover = 0.0
    while True:
        if time.monotonic() - last_recover >= RECOVER_EVERY:
            try:
                for cid in recover_interrupted(r, consumer, min_idle_ms):
                    log.warning("interrupted investigation marked failed: %s", cid)
            except redis.RedisError:
                log.exception("recover failed")
            last_recover = time.monotonic()
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
                    investigate(case_id, url, s, emit, live=live)
                except Exception as e:
                    log.exception("investigation failed")
                    emit({"type": "status", "status": "FAILED", "reason": f"error:{type(e).__name__}"})
                finally:
                    r.xack(JOBS, GROUP, msg_id)


if __name__ == "__main__":
    main()

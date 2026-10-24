"""수집 컨테이너(feeder): 자동 수집의 피드 받기만 한다. 브라우저 조사 워커와 떨어진 컨테이너에서 돈다.

- 조사 대상 페이지를 열지 않으므로 그 페이지에 뚫릴 길이 없다. 격리망에 있고 바깥은 검문 프록시로만 나간다
- 결과에 feeder 와 API 만 가진 키(ST_FEED_KEY)로 서명한다(intake.feed_mac). 브라우저 워커는 이 키가 없어, 뚫려도
  피드 결과를 꾸며 임의 주소를 자동 조사시키지 못한다(Codex 1회차 F1). 받을 주소는 출처 이름으로 이 코드가 정한다
- DB 접속 정보·증거 서명 키·Jev 키는 없다

실행: python -m safetrace.agent.feeder
"""

from __future__ import annotations

import json
import logging
import socket

import redis

from ..config import get_settings
from ..intake import feed_mac
from .feeds import FEEDS, fetch

log = logging.getLogger("safetrace.feeder")

STREAM = "st:feeds"
EVENTS = "st:events"
GROUP = "feeders"  # 브라우저 워커(agents)와 다른 묶음: 워커는 이 줄을 받지 않는다


def run_one(r, s, key: bytes, fields: dict) -> None:
    """받기 한 건: 출처 이름으로 받고, 결과에 서명해 이벤트로 보낸다. 실패해도 계속 돈다."""
    fetch_id, source = fields.get("fetch_id", ""), fields.get("source", "")
    if not fetch_id.isdigit() or source not in FEEDS:
        return
    try:
        res = fetch(source, s.egress_proxy, set(s.test_allowlist))
    except Exception as e:  # noqa: BLE001
        log.exception("feed fetch failed")
        res = {"ok": False, "reason": type(e).__name__}
    text = res.get("text") if isinstance(res.get("text"), str) else ""
    res["mac"] = feed_mac(key, int(fetch_id), source, text)
    r.xadd(EVENTS, {"case_id": "", "feed_id": fetch_id, "payload": json.dumps(res, ensure_ascii=False)}, maxlen=100000)


def main():
    logging.basicConfig(level=logging.INFO)
    s = get_settings()
    key = s.feed_key.get_secret_value().encode()
    if not key:
        raise SystemExit("ST_FEED_KEY 가 없습니다(feeder 와 api 에만 넣는다)")
    r = redis.Redis.from_url(s.redis_url, decode_responses=True, socket_timeout=30)
    try:
        r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except redis.ResponseError:
        pass
    consumer = socket.gethostname()
    while True:
        resp = r.xreadgroup(GROUP, consumer, {STREAM: ">"}, count=1, block=5000)
        for _stream, msgs in resp or []:
            for msg_id, fields in msgs:
                try:
                    run_one(r, s, key, fields)
                finally:
                    r.xack(STREAM, GROUP, msg_id)


if __name__ == "__main__":
    main()

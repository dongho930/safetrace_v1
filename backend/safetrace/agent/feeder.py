"""수집 컨테이너(feeder): 자동 수집의 피드 받기만 한다. 브라우저 조사 워커와 떨어진 컨테이너에서 돈다.

- 조사 대상 페이지를 열지 않으므로 그 페이지에 뚫릴 길이 없다. 격리망에 있고 바깥은 검문 프록시로만 나간다
- 결과에 feeder 와 API 만 가진 키(ST_FEED_KEY)로 서명한다(intake.feed_mac — 받기 번호·출처와 처리에 쓰는 결과 필드 전체).
  브라우저 워커는 이 키가 없어, 뚫려도 피드 결과를 꾸미거나 바꿔 임의 주소를 자동 조사시키지 못한다(Codex 1회차 F1·2회차 F1).
  받을 주소는 출처 이름으로 이 코드가 정한다
- 받기 요청도 API 의 서명(intake.request_mac)이 맞을 때만, 같은 번호는 한 번만, 출처마다 MIN_GAP_S 안에 다시 받지 않는다:
  브라우저 워커도 Redis 에 쓸 수 있어 가짜·재전송 요청으로 외부 받기를 늘리지 못하게(Codex 2회차 F2)
- DB 접속 정보·증거 서명 키·Jev 키는 없다

실행: python -m safetrace.agent.feeder
"""

from __future__ import annotations

import hmac
import json
import logging
import socket
import time
from collections import OrderedDict

import redis

from ..config import get_settings
from ..intake import feed_mac, request_mac
from .feeds import FEEDS, fetch

log = logging.getLogger("safetrace.feeder")

STREAM = "st:feeds"
EVENTS = "st:events"
GROUP = "feeders"  # 브라우저 워커(agents)와 다른 묶음: 워커는 이 줄을 받지 않는다
MIN_GAP_S = 600  # 출처마다 이 안에 다시 받지 않는다(API 주기는 6~12시간, 실패해도 1시간 뒤)
SEEN_MAX = 1000


class State:
    """이미 처리한 받기 번호와 출처별 마지막 받기 시각(이 프로세스 안에서만)."""

    def __init__(self):
        self.seen: OrderedDict[str, None] = OrderedDict()
        self.last: dict[str, float] = {}


def run_one(r, s, key: bytes, fields: dict, state: State) -> str:
    """받기 한 건: API 가 서명한 요청이면 출처 이름으로 받고, 결과에 서명해 이벤트로 보낸다. 반환: 처리 결과(로그·시험용)."""
    fetch_id, source = fields.get("fetch_id", ""), fields.get("source", "")
    mac = fields.get("mac", "")
    if not fetch_id.isdigit() or len(fetch_id) > 12 or source not in FEEDS:
        return "bad_request"
    if not isinstance(mac, str) or not hmac.compare_digest(mac, request_mac(key, int(fetch_id), source)):
        log.warning("unsigned feed request dropped: id=%s source=%s", fetch_id[:12], source)
        return "unsigned"
    if fetch_id in state.seen:
        return "duplicate"
    now = time.monotonic()
    if now - state.last.get(source, -MIN_GAP_S) < MIN_GAP_S:
        log.warning("feed request too soon dropped: id=%s source=%s", fetch_id, source)
        return "too_soon"
    state.seen[fetch_id] = None
    while len(state.seen) > SEEN_MAX:
        state.seen.popitem(last=False)
    state.last[source] = now
    try:
        res = fetch(source, s.egress_proxy, set(s.test_allowlist))
    except Exception as e:  # noqa: BLE001
        log.exception("feed fetch failed")
        res = {"ok": False, "reason": type(e).__name__}
    res["mac"] = feed_mac(key, int(fetch_id), source, res)
    r.xadd(EVENTS, {"case_id": "", "feed_id": fetch_id, "payload": json.dumps(res, ensure_ascii=False)}, maxlen=100000)
    return "fetched"


def main():
    logging.basicConfig(level=logging.INFO)
    s = get_settings()
    key = s.feed_key.get_secret_value().encode()
    if not key:
        raise SystemExit("ST_FEED_KEY 가 없습니다(feeder 와 api 에만 넣는다)")
    r = redis.Redis.from_url(s.redis_url, decode_responses=True, socket_timeout=30)
    try:
        # 처음 만들 때는 새 요청부터(예전 받기 요청을 다시 받지 않게 — PhishTank 는 키 없이 하루 몇 번까지).
        # 꺼져 있던 동안 들어온 요청은 API 가 10분 뒤 만료시키고 1시간 뒤 다시 요청한다
        r.xgroup_create(STREAM, GROUP, id="$", mkstream=True)
    except redis.ResponseError as e:
        log.debug("feed group create skipped: %s", type(e).__name__)
    consumer = socket.gethostname()
    state = State()
    while True:
        resp = r.xreadgroup(GROUP, consumer, {STREAM: ">"}, count=1, block=5000)
        for _stream, msgs in resp or []:
            for msg_id, fields in msgs:
                try:
                    run_one(r, s, key, fields, state)
                finally:
                    r.xack(STREAM, GROUP, msg_id)


if __name__ == "__main__":
    main()

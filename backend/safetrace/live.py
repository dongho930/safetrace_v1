"""실시간 화면(라이브): 에이전트의 화면 전송 프레임을 콘솔로 연속해서 보낸다.

보기용이며 증거가 아니다(증거는 서명된 스크린샷·녹화).
- 보는 사람이 있을 때만 보낸다: 콘솔이 WebSocket 을 열면 '시청 중' 표시를 짧은 만료 시간으로 갱신하고,
  에이전트는 그 표시가 있을 때만 프레임을 발행한다.
- 운영: 에이전트(격리망) → Redis PUBLISH → API → WebSocket. 에이전트가 콘솔에 직접 연결되지 않는다.
- 개발·시험: 에이전트가 API 프로세스 안 스레드에서 돌므로 같은 프로세스 안에서 전달한다.
"""

from __future__ import annotations

import asyncio
import collections
import json
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Protocol

CHANNEL = "st:live:{}"
WATCH_KEY = "st:live:watch:{}"
WATCH_TTL_S = 6


END = b""  # 조사가 끝났다는 신호(빈 메시지)
# 클릭 표시(콘솔이 실시간 화면 위에 커서를 그린다): {"click":[x,y,폭,높이]} JSON. 영상과 같은 통로로 보내 같은 재생 버퍼를 탄다.
# JPEG 는 0xFF 로 시작하므로 첫 바이트 "{" 로 구분한다. 밀려도 버리지 않는다(프레임만 버린다).


def is_control(item: bytes) -> bool:
    return item == END or item[:1] == b"{"


# API 가 콘솔로 넘기는 상한(Codex 지적: 침해된 에이전트가 통로로 메시지를 쏟아내도 콘솔·연결이 버티게).
# 정상 프레임은 1280×800 JPEG 수백 KB, LiveSink 가 초당 60장 이하로 보낸다(클릭 표시는 단계마다 1개).
# 프레임만으로 상한을 채우면 클릭 표시가 버려지므로 프레임 속도의 2배로 둔다(1초 칸 경계에서 몰려도 여유)
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
MAX_MESSAGES_PER_S = 120


class ForwardLimit:
    """연결 하나가 콘솔로 넘길 메시지를 고른다: 너무 크거나 1초에 MAX_MESSAGES_PER_S 를 넘으면 버린다."""

    def __init__(self, per_s: int = MAX_MESSAGES_PER_S, max_bytes: int = MAX_MESSAGE_BYTES):
        self.per_s, self.max_bytes = per_s, max_bytes
        self._t, self._n = 0.0, 0

    def ok(self, item: bytes) -> bool:
        if len(item) > self.max_bytes:
            return False
        now = time.monotonic()
        if now - self._t >= 1.0:
            self._t, self._n = now, 0
        self._n += 1
        return self._n <= self.per_s


class LivePublisher(Protocol):
    def watching(self, case_id: str) -> bool: ...
    def publish(self, case_id: str, jpeg: bytes) -> None: ...
    def end(self, case_id: str) -> None: ...


# ── 개발·시험: 같은 프로세스 ─────────────────────────────
class LocalLive:
    def __init__(self):
        self._lock = threading.Lock()
        self._subs: dict[str, set[tuple[asyncio.AbstractEventLoop, asyncio.Queue]]] = {}

    def watching(self, case_id: str) -> bool:
        with self._lock:
            return bool(self._subs.get(case_id))

    def publish(self, case_id: str, jpeg: bytes) -> None:
        with self._lock:
            subs = list(self._subs.get(case_id, ()))
        for loop, q in subs:
            loop.call_soon_threadsafe(_put_latest, q, jpeg)

    def end(self, case_id: str) -> None:
        self.publish(case_id, END)

    @asynccontextmanager
    async def subscribe(self, case_id: str) -> AsyncIterator[asyncio.Queue]:
        q: asyncio.Queue = asyncio.Queue()  # 크기는 _put_latest 가 맞춘다(프레임 최대 2장)
        entry = (asyncio.get_running_loop(), q)
        with self._lock:
            self._subs.setdefault(case_id, set()).add(entry)
        try:
            yield q
        finally:
            with self._lock:
                self._subs.get(case_id, set()).discard(entry)


def _put_latest(q: asyncio.Queue, item: bytes):
    """느린 시청자는 밀린 프레임을 버리고 최신 프레임만 받는다(끝 신호·클릭 표시는 버리지 않는다)."""
    if not is_control(item):
        items = []
        while not q.empty():
            items.append(q.get_nowait())
        drop = sum(1 for x in items if not is_control(x)) - 1  # 새 프레임과 함께 최대 2장
        for x in items:
            if drop > 0 and not is_control(x):
                drop -= 1
                continue
            q.put_nowait(x)
    q.put_nowait(item)


# ── 운영: Redis ────────────────────────────────────────
class RedisLivePublisher:
    """에이전트 쪽. 시청 여부는 1초마다만 확인한다."""

    def __init__(self, url: str):
        import redis  # noqa: PLC0415

        self._r = redis.Redis.from_url(url, socket_timeout=5)  # 바이트 그대로(decode 안 함)
        self._checked: dict[str, tuple[float, bool]] = {}

    def watching(self, case_id: str) -> bool:
        now = time.monotonic()
        t, v = self._checked.get(case_id, (0.0, False))
        if now - t >= 1.0:
            try:
                v = bool(self._r.exists(WATCH_KEY.format(case_id)))
            except Exception:  # noqa: BLE001  라이브는 부가 기능: Redis 오류로 조사를 멈추지 않는다
                v = False
            self._checked[case_id] = (now, v)
        return v

    def publish(self, case_id: str, jpeg: bytes) -> None:
        try:
            self._r.publish(CHANNEL.format(case_id), jpeg)
        except Exception:  # noqa: BLE001
            pass

    def end(self, case_id: str) -> None:
        self.publish(case_id, END)


class LiveSink:
    """녹화기의 화면 전송 프레임을 받아, 시청 중일 때만 최대 max_fps 로 발행한다.
    발행은 별도 스레드에서 한다(에이전트의 이벤트 루프를 막지 않음). 밀리면 오래된 프레임을 버린다(클릭 표시는 버리지 않는다)."""

    def __init__(self, publisher: LivePublisher, case_id: str, max_fps: int = 60):
        self.pub, self.case_id = publisher, case_id
        self.min_interval = 1 / max_fps
        self._last_sent = 0.0
        self._next_slot = 0.0  # 다음 발행 가능 시각(간격이 조금 흔들려도 평균 max_fps 를 지키게)
        self._last_frame: bytes | None = None
        self._was_watching = False
        self._cv = threading.Condition()
        self._items: collections.deque[bytes | None] = collections.deque()  # 보낼 것(프레임은 최대 2장, None 은 끝)
        self._t = threading.Thread(target=self._run, name="live-publish", daemon=True)
        self._t.start()
        self.sent = 0

    def on_frame(self, jpeg: bytes):
        self._last_frame = jpeg
        now = time.monotonic()
        watching = self.pub.watching(self.case_id)
        if not watching:
            self._was_watching = False
            return
        if not self._was_watching or now >= self._next_slot:
            self._was_watching = True
            self._last_sent = now
            # 프레임이 max_fps 근처로 들쑥날쑥 와도 버리지 않도록, 직전 발행 시각이 아니라 일정한 칸 단위로 센다
            self._next_slot = max(self._next_slot, now - self.min_interval) + self.min_interval
            self._offer(jpeg)

    def keepalive(self):
        """화면이 멈춰 있어도 새로 들어온 시청자가 볼 수 있게 마지막 프레임을 가끔 다시 보낸다."""
        if self._last_frame is not None and self.pub.watching(self.case_id):
            if not self._was_watching or time.monotonic() - self._last_sent >= 1.0:
                self._was_watching = True
                self._last_sent = time.monotonic()
                self._offer(self._last_frame)

    def _offer(self, jpeg: bytes):
        with self._cv:
            frames = [i for i, x in enumerate(self._items) if x is not None and not is_control(x)]
            if len(frames) >= 2:
                del self._items[frames[0]]  # 밀리면 가장 오래된 프레임을 버린다
            self._items.append(jpeg)
            self._cv.notify()

    def click(self, point: list[int]):
        """에이전트가 누르기 직전의 버튼 상자. 시청 중일 때만, 프레임 속도 제한 없이 보낸다."""
        if not self.pub.watching(self.case_id):
            return
        with self._cv:
            self._items.append(json.dumps({"click": point}, separators=(",", ":")).encode())
            self._cv.notify()

    def _run(self):
        while True:
            with self._cv:
                while not self._items:
                    self._cv.wait()
                item = self._items.popleft()
            if item is None:
                return
            self.pub.publish(self.case_id, item)
            self.sent += 1

    def close(self):
        with self._cv:
            self._items.append(None)
            self._cv.notify()
        self._t.join(timeout=2)
        self.pub.end(self.case_id)  # 시청 중인 콘솔에 끝을 알려 연결을 닫게 한다

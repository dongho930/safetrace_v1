"""실시간 화면(라이브): 에이전트의 화면 전송 프레임을 콘솔로 연속해서 보낸다.

보기용이며 증거가 아니다(증거는 서명된 스크린샷·녹화).
- 보는 사람이 있을 때만 보낸다: 콘솔이 WebSocket 을 열면 '시청 중' 표시를 짧은 만료 시간으로 갱신하고,
  에이전트는 그 표시가 있을 때만 프레임을 발행한다.
- 운영: 에이전트(격리망) → Redis PUBLISH → API → WebSocket. 에이전트가 콘솔에 직접 연결되지 않는다.
- 개발·시험: 에이전트가 API 프로세스 안 스레드에서 돌므로 같은 프로세스 안에서 전달한다.
"""

from __future__ import annotations

import asyncio
import queue
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Protocol

CHANNEL = "st:live:{}"
WATCH_KEY = "st:live:watch:{}"
WATCH_TTL_S = 6


END = b""  # 조사가 끝났다는 신호(빈 메시지)


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
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        entry = (asyncio.get_running_loop(), q)
        with self._lock:
            self._subs.setdefault(case_id, set()).add(entry)
        try:
            yield q
        finally:
            with self._lock:
                self._subs.get(case_id, set()).discard(entry)


def _put_latest(q: asyncio.Queue, item: bytes):
    """느린 시청자는 밀린 프레임을 버리고 최신 프레임만 받는다(끝 신호는 버리지 않는다)."""
    while q.full():
        q.get_nowait()
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
    발행은 별도 스레드에서 한다(에이전트의 이벤트 루프를 막지 않음). 밀리면 오래된 프레임을 버린다."""

    def __init__(self, publisher: LivePublisher, case_id: str, max_fps: int = 30):
        self.pub, self.case_id = publisher, case_id
        self.min_interval = 1 / max_fps
        self._last_sent = 0.0
        self._next_slot = 0.0  # 다음 발행 가능 시각(간격이 조금 흔들려도 평균 max_fps 를 지키게)
        self._last_frame: bytes | None = None
        self._was_watching = False
        self._q: queue.Queue[bytes | None] = queue.Queue(maxsize=2)
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
            # 프레임이 30fps 근처로 들쑥날쑥 와도 버리지 않도록, 직전 발행 시각이 아니라 일정한 칸 단위로 센다
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
        try:
            self._q.put_nowait(jpeg)
        except queue.Full:
            try:
                self._q.get_nowait()
            except queue.Empty:
                pass
            try:
                self._q.put_nowait(jpeg)
            except queue.Full:
                pass

    def _run(self):
        while True:
            item = self._q.get()
            if item is None:
                return
            self.pub.publish(self.case_id, item)
            self.sent += 1

    def close(self):
        try:
            self._q.put(None, timeout=1)
        except queue.Full:
            pass
        self._t.join(timeout=2)
        self.pub.end(self.case_id)  # 시청 중인 콘솔에 끝을 알려 연결을 닫게 한다

"""조사 녹화: 브라우저 화면 전송(CDP screencast)을 받아 ffmpeg 로 고화질 인코딩한다.

Playwright 내장 녹화는 960×600 으로 줄이고 속도 우선 실시간 인코딩이라 글자가 뭉개졌고, 창마다 영상을 따로 만들어
새 창으로 넘어가기 전 부분이 빠졌다. 여기서는
- JPEG 품질 80 프레임을 1280×800 그대로 받아
- 화면이 바뀐 프레임만 브라우저의 캡처 시각(CDP metadata.timestamp)을 붙여 ffmpeg 에 넘기고(가변 프레임률)
  화면이 멈춰 있으면 1초마다 마지막 프레임을 한 번 더 넣는다(영상 탐색·시간축 유지)
- 품질 우선 VP8 로 인코딩하며
- 에이전트가 새 창으로 옮기면 같은 영상에 이어서 담는다.
영상의 시각은 실제 캡처 시각이므로 CPU 가 밀려도 영상 길이가 조사 시간과 어긋나지 않는다.
녹화는 흐름 확인용 보조 증거다. 주 증거는 무손실 PNG 스크린샷이다.
"""

from __future__ import annotations

import asyncio
import base64
import glob
import logging
import os
import shutil
import sys
import time
from pathlib import Path

from playwright.async_api import CDPSession, Page
from playwright.async_api import Error as PWError

log = logging.getLogger("safetrace.recorder")

WIDTH, HEIGHT = 1280, 800
HEARTBEAT_S = 1.0  # 화면이 이만큼 멈춰 있으면 마지막 프레임을 한 번 더 넣는다
KEYFRAME_S = 2  # 이 간격마다 키프레임(영상 탐색용)


def find_ffmpeg(explicit: str = "") -> str | None:
    """ST_FFMPEG_PATH → PATH → Playwright 가 받아 둔 ffmpeg 순서로 찾는다."""
    if explicit:
        return explicit if Path(explicit).is_file() else None
    if found := shutil.which("ffmpeg"):
        return found
    roots = [os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""), "/ms-playwright",
             str(Path.home() / ".cache" / "ms-playwright"),
             str(Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright")]
    exe = "ffmpeg-win64.exe" if sys.platform == "win32" else "ffmpeg-*"
    for root in filter(None, roots):
        for cand in sorted(glob.glob(str(Path(root) / "ffmpeg-*" / exe)), reverse=True):
            if Path(cand).is_file() and not cand.endswith(".zip"):
                return cand
    return None


# ── 시각을 담은 MJPEG 스트림(Matroska) ───────────────────────────
# image2pipe 는 프레임 시각을 실을 수 없어서, 프레임마다 캡처 시각을 붙인 최소 Matroska 스트림으로 넘긴다.
# (Playwright 가 함께 받는 ffmpeg 에도 Matroska 입력과 MJPEG 해독기가 들어 있다)

def _vint(n: int) -> bytes:
    """EBML 크기 값(가변 길이). 모든 비트가 1인 값은 '크기 모름'이라 쓰지 않는다."""
    for width in range(1, 9):
        if n < (1 << (7 * width)) - 1:
            return (n | (1 << (7 * width))).to_bytes(width, "big")
    raise ValueError("EBML size too large")


def _uint(n: int) -> bytes:
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")


def _el(eid: int, data: bytes) -> bytes:
    return eid.to_bytes((eid.bit_length() + 7) // 8, "big") + _vint(len(data)) + data


_SEGMENT_UNKNOWN_SIZE = bytes.fromhex("18538067") + bytes.fromhex("01ffffffffffffff")


def mkv_header() -> bytes:
    """EBML 머리 + 크기를 정하지 않은 Segment(스트리밍) + 시각 단위 1ms + MJPEG 영상 트랙 1개."""
    ebml = _el(0x1A45DFA3, b"".join([
        _el(0x4286, _uint(1)), _el(0x42F7, _uint(1)), _el(0x42F2, _uint(4)), _el(0x42F3, _uint(8)),
        _el(0x4282, b"matroska"), _el(0x4287, _uint(4)), _el(0x4285, _uint(2)),
    ]))
    info = _el(0x1549A966, b"".join([
        _el(0x2AD7B1, _uint(1_000_000)),  # TimestampScale: 1ms
        _el(0x4D80, b"safetrace"), _el(0x5741, b"safetrace"),
    ]))
    track = _el(0xAE, b"".join([
        _el(0xD7, _uint(1)), _el(0x73C5, _uint(1)), _el(0x83, _uint(1)), _el(0x9C, _uint(0)),
        _el(0x86, b"V_MJPEG"),
        _el(0xE0, _el(0xB0, _uint(WIDTH)) + _el(0xBA, _uint(HEIGHT))),
    ]))
    return ebml + _SEGMENT_UNKNOWN_SIZE + info + _el(0x1654AE6B, track)


def mkv_frame(jpeg: bytes, ms: int, duration_ms: int) -> bytes:
    """프레임 하나 = Cluster 하나(시각 ms) + BlockGroup(Block: 트랙 1·상대 시각 0, 표시 시간 ms).

    표시 시간(다음 프레임까지)을 붙여야 마지막 프레임 길이를 ffmpeg 가 짐작하지 않아 영상 끝이 녹화 끝과 맞는다."""
    block = bytes([0x81, 0x00, 0x00, 0x00]) + jpeg
    return _el(0x1F43B675, _el(0xE7, _uint(ms)) + _el(0xA0, _el(0xA1, block) + _el(0x9B, _uint(duration_ms))))


class ScreencastRecorder:
    def __init__(self, ffmpeg: str, out: Path, quality: int = 80, bitrate: str = "5M", live=None):
        self.ffmpeg, self.out, self.quality, self.bitrate = ffmpeg, out, quality, bitrate
        self.live = live  # LiveSink: 같은 프레임을 콘솔 실시간 화면으로도 보낸다(보는 사람이 있을 때만)
        self._proc: asyncio.subprocess.Process | None = None
        self._cdp: CDPSession | None = None
        self._page: Page | None = None
        self._last: bytes | None = None
        self._paused = False
        self._ticker: asyncio.Task | None = None
        self._writer: asyncio.Task | None = None
        self._q: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._t0: float | None = None  # 첫 화면의 캡처 시각(epoch 초) = 영상 0초
        self._last_ms = -1
        self._pending: tuple[bytes, int] | None = None  # 표시 시간을 알려면 다음 프레임 시각이 필요해 하나를 붙잡아 둔다
        self._last_emit = 0.0  # 마지막으로 영상에 넣은 프레임의 시각(epoch 초)
        self.frames_received = 0
        self.frames_written = 0
        self.cdp_timestamps = 0  # 브라우저 캡처 시각을 쓴 프레임 수(나머지는 받은 시각)
        self.heartbeat_frames = 0

    async def start(self, page: Page):
        await self._spawn()
        await self._attach(page)
        self._ticker = asyncio.create_task(self._tick())

    async def _spawn(self):
        args = [
            self.ffmpeg, "-loglevel", "error", "-y",
            "-f", "matroska", "-i", "pipe:0",
            # 프레임 크기가 달라도(창 크기 차이) 1280×800 캔버스에 맞춘다
            "-vf", f"pad={WIDTH}:{HEIGHT}:0:0:gray,crop={WIDTH}:{HEIGHT}:0:0",
            "-fps_mode", "vfr",  # 입력 시각 그대로: 프레임을 복제하지 않는다
            # 인코더 시각 단위를 1ms 로 고정(기본값은 짐작한 프레임률이라 시각이 그 간격으로 반올림된다)
            "-enc_time_base", "1:1000",
            "-c:v", "libvpx", "-deadline", "good", "-cpu-used", "4", "-crf", "8", "-b:v", self.bitrate,
            "-qmin", "0", "-qmax", "36", "-threads", "2", "-auto-alt-ref", "0",
            "-force_key_frames", f"expr:gte(t,n_forced*{KEYFRAME_S})",
            "-f", "webm", str(self.out),
        ]
        self._proc = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        self._q.put_nowait(mkv_header())
        self._writer = asyncio.create_task(self._write())

    async def _write(self):
        """큐에 쌓인 순서대로 ffmpeg 에 쓴다. 쓰는 곳이 하나라 프레임 순서가 섞이지 않는다."""
        while (chunk := await self._q.get()) is not None:
            if not (self._proc and self._proc.stdin):
                continue
            try:
                self._proc.stdin.write(chunk)
                await self._proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                return

    def _emit(self, jpeg: bytes, ts: float):
        """ts(epoch 초) 시각의 프레임을 영상에 넣는다. 시각은 앞 프레임보다 늘 1ms 이상 뒤로 맞춘다."""
        if self._t0 is None:
            self._t0 = ts  # ffmpeg 도 첫 프레임을 0초로 맞추므로 여기서 기준을 같게 둔다
        ms = max(int(round((ts - self._t0) * 1000)), self._last_ms + 1, 0)
        self._last_ms = ms
        self._last_emit = self._t0 + ms / 1000
        if self._pending:
            pj, pms = self._pending
            self._q.put_nowait(mkv_frame(pj, pms, ms - pms))
        self._pending = (jpeg, ms)
        self.frames_written += 1

    async def _attach(self, page: Page):
        self._page = page
        self._cdp = await page.context.new_cdp_session(page)
        cdp = self._cdp

        def on_frame(ev):
            # 순서를 지키려고 받은 자리에서 바로 영상에 넣고, 응답(ack)만 비동기로 보낸다
            self._on_frame(cdp, ev)
            asyncio.ensure_future(self._ack(cdp, ev["sessionId"]))

        cdp.on("Page.screencastFrame", on_frame)
        await cdp.send("Page.startScreencast", {"format": "jpeg", "quality": self.quality,
                                                "maxWidth": WIDTH, "maxHeight": HEIGHT, "everyNthFrame": 1})

    @staticmethod
    async def _ack(cdp: CDPSession, session_id: int):
        try:
            await cdp.send("Page.screencastFrameAck", {"sessionId": session_id})
        except PWError:
            pass

    def _on_frame(self, cdp: CDPSession, ev: dict):
        if cdp is not self._cdp or self._paused:
            return  # 옮기기 전 창의 늦은 프레임, 또는 페이지 전체 캡처 중(창 크기가 잠시 바뀜)
        self.frames_received += 1
        self._last = base64.b64decode(ev["data"])
        ts = (ev.get("metadata") or {}).get("timestamp")
        if isinstance(ts, (int, float)) and ts > 0:
            self.cdp_timestamps += 1
        else:
            ts = time.time()
        self._emit(self._last, ts)
        if self.live:
            self.live.on_frame(self._last)

    async def _detach(self):
        cdp, self._cdp = self._cdp, None
        if cdp is None:
            return
        try:
            await cdp.send("Page.stopScreencast")
            await cdp.detach()
        except PWError:
            pass

    async def switch(self, page: Page):
        """에이전트가 새 창을 채택하면 같은 영상에 이어서 담는다."""
        if page is self._page:
            return
        await self._detach()
        try:
            await self._attach(page)
        except PWError as e:
            log.warning("recorder switch failed: %s", type(e).__name__)

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    async def _tick(self):
        """화면이 멈춰 있을 때만 마지막 프레임을 1초 간격으로 다시 넣고, 라이브 시청자에게도 마지막 화면을 보낸다."""
        while True:
            await asyncio.sleep(0.25)
            now = time.time()
            if self._last is not None and now - self._last_emit >= HEARTBEAT_S:
                self._emit(self._last, now)
                self.heartbeat_frames += 1
            if self.live:
                self.live.keepalive()

    async def stop(self, end_ts: float | None = None) -> dict | None:
        """녹화를 끝내고 영상 정보를 돌려준다. 프레임이 하나도 없으면 None.

        끝 시각(기본: 지금)에 마지막 화면을 한 번 더 넣어 영상 길이가 녹화 시간과 같게 한다."""
        if self._ticker:
            self._ticker.cancel()
            try:
                await self._ticker
            except asyncio.CancelledError:
                pass
        await self._detach()
        if not self._proc:
            return None
        if self._last is not None:
            self._emit(self._last, time.time() if end_ts is None else end_ts)
        if self._pending:  # 끝 프레임: 영상 끝을 표시하는 1ms
            self._q.put_nowait(mkv_frame(self._pending[0], self._pending[1], 1))
            self._pending = None
        self._q.put_nowait(None)
        if self._writer:
            await self._writer
        if self._proc.stdin:
            try:
                self._proc.stdin.close()
            except (BrokenPipeError, ConnectionResetError):
                pass
        try:
            _, err = await asyncio.wait_for(self._proc.communicate(), 60)
        except TimeoutError:
            self._proc.kill()
            return None
        if self._proc.returncode != 0 or self.frames_written == 0 or not self.out.exists():
            if err:
                log.warning("ffmpeg failed: %s", err.decode(errors="replace")[-300:])
            return None
        return {"format": "webm", "codec": "vp8", "width": WIDTH, "height": HEIGHT,
                "fps_mode": "vfr", "duration_s": round(self._last_ms / 1000, 3),
                "frames": self.frames_written, "screencast_frames": self.frames_received,
                "cdp_timestamps": self.cdp_timestamps, "heartbeat_frames": self.heartbeat_frames,
                "heartbeat_s": HEARTBEAT_S, "source": "cdp-screencast", "jpeg_quality": self.quality}

"""조사 녹화: 브라우저 화면 전송(CDP screencast)을 받아 ffmpeg 로 고화질 인코딩한다.

Playwright 내장 녹화는 960×600 으로 줄이고 속도 우선 실시간 인코딩이라 글자가 뭉개졌고, 창마다 영상을 따로 만들어
새 창으로 넘어가기 전 부분이 빠졌다. 여기서는
- JPEG 품질 80 프레임을 1280×800 그대로 받아
- 고정 간격(기본 30fps)으로 ffmpeg 에 넘기고(화면이 바뀔 때만 프레임이 오므로 사이는 마지막 프레임을 반복)
- 품질 우선 VP8 로 인코딩하며
- 에이전트가 새 창으로 옮기면 같은 영상에 이어서 담는다.
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
from pathlib import Path

from playwright.async_api import CDPSession, Page
from playwright.async_api import Error as PWError

log = logging.getLogger("safetrace.recorder")

WIDTH, HEIGHT = 1280, 800


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


class ScreencastRecorder:
    def __init__(self, ffmpeg: str, out: Path, fps: int = 30, quality: int = 80, bitrate: str = "5M", live=None):
        self.ffmpeg, self.out, self.fps, self.quality, self.bitrate = ffmpeg, out, fps, quality, bitrate
        self.live = live  # LiveSink: 같은 프레임을 콘솔 실시간 화면으로도 보낸다(보는 사람이 있을 때만)
        self._proc: asyncio.subprocess.Process | None = None
        self._cdp: CDPSession | None = None
        self._page: Page | None = None
        self._last: bytes | None = None
        self._paused = False
        self._ticker: asyncio.Task | None = None
        self.frames_received = 0
        self.frames_written = 0

    async def start(self, page: Page):
        args = [
            self.ffmpeg, "-loglevel", "error", "-y",
            "-f", "image2pipe", "-vcodec", "mjpeg", "-framerate", str(self.fps), "-i", "pipe:0",
            # 프레임 크기가 달라도(창 크기 차이) 1280×800 캔버스에 맞춘다
            "-vf", f"pad={WIDTH}:{HEIGHT}:0:0:gray,crop={WIDTH}:{HEIGHT}:0:0",
            "-c:v", "libvpx", "-deadline", "good", "-cpu-used", "4", "-crf", "8", "-b:v", self.bitrate,
            "-qmin", "0", "-qmax", "36", "-threads", "2", "-auto-alt-ref", "0",
            "-f", "webm", str(self.out),
        ]
        self._proc = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        await self._attach(page)
        self._ticker = asyncio.create_task(self._tick())

    async def _attach(self, page: Page):
        self._page = page
        self._cdp = await page.context.new_cdp_session(page)
        cdp = self._cdp

        def on_frame(ev):
            asyncio.ensure_future(self._on_frame(cdp, ev))

        cdp.on("Page.screencastFrame", on_frame)
        await cdp.send("Page.startScreencast", {"format": "jpeg", "quality": self.quality,
                                                "maxWidth": WIDTH, "maxHeight": HEIGHT, "everyNthFrame": 1})

    async def _on_frame(self, cdp: CDPSession, ev: dict):
        try:
            await cdp.send("Page.screencastFrameAck", {"sessionId": ev["sessionId"]})
        except PWError:
            return
        if cdp is not self._cdp or self._paused:
            return  # 옮기기 전 창의 늦은 프레임, 또는 페이지 전체 캡처 중(창 크기가 잠시 바뀜)
        self.frames_received += 1
        self._last = base64.b64decode(ev["data"])
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
        interval = 1 / self.fps
        loop = asyncio.get_running_loop()
        next_t = loop.time()
        n = 0
        while True:
            n += 1
            if self.live and n % self.fps == 0:
                self.live.keepalive()  # 화면이 멈춰 있어도 새 시청자에게 마지막 화면을 보낸다
            if self._last is not None and self._proc and self._proc.stdin:
                try:
                    self._proc.stdin.write(self._last)
                    await self._proc.stdin.drain()
                    self.frames_written += 1
                except (BrokenPipeError, ConnectionResetError):
                    return
            next_t += interval
            await asyncio.sleep(max(0.0, next_t - loop.time()))

    async def stop(self) -> dict | None:
        """녹화를 끝내고 영상 정보를 돌려준다. 프레임이 하나도 없으면 None."""
        if self._ticker:
            self._ticker.cancel()
            try:
                await self._ticker
            except asyncio.CancelledError:
                pass
        await self._detach()
        if not self._proc:
            return None
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
        return {"format": "webm", "codec": "vp8", "width": WIDTH, "height": HEIGHT, "fps": self.fps,
                "frames": self.frames_written, "screencast_frames": self.frames_received,
                "source": "cdp-screencast", "jpeg_quality": self.quality}

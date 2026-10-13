"""녹화기: 브라우저 없이 프레임과 캡처 시각을 직접 넣어, 영상이 그 시각을 그대로 따르는지 확인한다."""

import asyncio
import io
import struct

import pytest
from PIL import Image

from safetrace.agent.recorder import ScreencastRecorder, find_ffmpeg, mkv_frame, mkv_header


def _jpeg(color, size=(1280, 800)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, "JPEG", quality=80)
    return buf.getvalue()


def _vint(b: bytes, i: int, keep_marker: bool) -> tuple[int, int]:
    w = 1
    while not (b[i] & (0x80 >> (w - 1))):
        w += 1
    v = int.from_bytes(b[i:i + w], "big")
    if not keep_marker:
        v &= (1 << (7 * w)) - 1
        if v == (1 << (7 * w)) - 1:
            v = -1  # 크기 모름
    return v, i + w


_MASTER = {0x18538067, 0x1F43B675, 0xA0, 0x1549A966}  # Segment, Cluster, BlockGroup, Info


def probe(path) -> tuple[float, list[float]]:
    """webm 을 직접 읽어 (Info 의 영상 길이 초, 프레임 시각 목록 초). 시험용 간이 EBML 파서."""
    b = path.read_bytes()
    scale, duration, times, cluster = 1_000_000, 0.0, [], 0

    def walk(i: int, end: int):
        nonlocal scale, duration, cluster
        while i < end:
            eid, i = _vint(b, i, True)
            size, i = _vint(b, i, False)
            stop = end if size < 0 else i + size
            if eid in _MASTER:
                walk(i, stop)
            elif eid == 0x2AD7B1:
                scale = int.from_bytes(b[i:stop], "big")
            elif eid == 0x4489:
                duration = struct.unpack(">d" if size == 8 else ">f", b[i:stop])[0]
            elif eid == 0xE7:
                cluster = int.from_bytes(b[i:stop], "big")
            elif eid in (0xA3, 0xA1):  # SimpleBlock, Block: 트랙(vint) + 상대 시각(int16)
                _, j = _vint(b, i, False)
                times.append((cluster + int.from_bytes(b[j:j + 2], "big", signed=True)) * scale / 1e9)
            i = stop

    walk(0, len(b))
    return duration * scale / 1e9, times


def test_mkv_elements():
    h = mkv_header()
    assert h.startswith(bytes.fromhex("1A45DFA3")) and b"V_MJPEG" in h and b"matroska" in h
    f = mkv_frame(b"JPEG", 1234, 500)
    assert f.startswith(bytes.fromhex("1F43B675")) and b"\x81\x00\x00\x00JPEG" in f
    assert f.endswith(b"\x9b\x82\x01\xf4")  # BlockDuration 500ms


def test_video_follows_given_capture_times(tmp_path):
    ffmpeg = find_ffmpeg()
    if not ffmpeg:
        pytest.skip("ffmpeg not available")
    out = tmp_path / "r.webm"

    async def go():
        rec = ScreencastRecorder(ffmpeg, out)
        await rec._spawn()
        t0 = 1_800_000_000.0  # 첫 프레임 시각이 영상 0초
        # 브라우저가 준 캡처 시각: 0, 0.5, 3.0초(사이에 화면 변화 없음). 크기가 다른 창 프레임도 섞는다
        rec._emit(_jpeg((200, 0, 0)), t0)
        rec._emit(_jpeg((0, 200, 0), (1000, 600)), t0 + 0.5)
        rec._emit(_jpeg((0, 0, 200)), t0 + 3.0)
        rec._emit(_jpeg((9, 9, 9)), t0 + 2.0)  # 늦게 온(앞선 시각) 프레임은 1ms 뒤로 밀린다
        rec._last = _jpeg((0, 0, 200))
        return await rec.stop(end_ts=t0 + 4.0)

    info = asyncio.run(go())
    assert info and info["fps_mode"] == "vfr"
    assert info["frames"] == 5 and info["duration_s"] == 4.0
    duration, times = probe(out)
    assert len(times) == 5  # 복제 없이 넣은 프레임 수 그대로
    assert times == pytest.approx([0.0, 0.5, 3.0, 3.001, 4.0], abs=0.002)
    assert duration == pytest.approx(4.0, abs=0.01)  # 영상 끝 = 녹화 끝


def test_cancelled_stop_still_reaps_ffmpeg(tmp_path):
    """Codex F2: 정리 제한 시간(_bounded)에 stop() 이 취소돼도 ffmpeg 가 남지 않아야 한다(반복 조사에서 프로세스 누적)."""
    ffmpeg = find_ffmpeg()
    if not ffmpeg:
        pytest.skip("ffmpeg not available")

    async def go():
        rec = ScreencastRecorder(ffmpeg, tmp_path / "r.webm")
        await rec._spawn()

        async def hang():  # 응답 없는 페이지에서 CDP 녹화 중지가 돌아오지 않는 경우
            await asyncio.sleep(3600)

        rec._detach = hang
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(rec.stop(), 0.5)
        for _ in range(50):
            if rec._proc.returncode is not None:
                break
            await asyncio.sleep(0.1)
        return rec._proc.returncode, rec._writer.done()

    code, writer_done = asyncio.run(go())
    assert code is not None and writer_done


def test_pause_nests():
    """페이지 전체 캡처 준비(펼치기) 안에서 캡처가 다시 멈추고 풀어도, 바깥 resume 전까지는 멈춘 채다."""
    rec = ScreencastRecorder("ffmpeg", None)
    rec.pause()
    rec.pause()
    rec.resume()
    assert rec._pauses == 1
    rec.resume()
    rec.resume()  # 짝이 맞지 않는 resume 은 음수로 내려가지 않는다
    assert rec._pauses == 0


def test_capture_error_releases_pause(tmp_path):
    """Codex F1: 페이지가 크기 조회를 망쳐 전체 캡처가 실패해도 녹화 멈춤이 남지 않는다
    (남으면 녹화·실시간 화면이 조사 끝까지 멈춘다). 처음 한 번만 innerWidth 를 '이상한 값'으로 준다."""
    from types import SimpleNamespace

    from safetrace.agent.loop import AgentRun

    run = AgentRun.__new__(AgentRun)
    run.rec = ScreencastRecorder("ffmpeg", None)
    run._shot, run._tag, run.attr = 0, "", "data-st-test"
    run.s = SimpleNamespace(screenshot_max_height=6000)
    run.ev = SimpleNamespace(file_path=lambda n: tmp_path / n)

    class Page:
        sizes = [["bad-width", 4200], [1280, 4200]]

        async def evaluate(self, js, arg=None):
            if "innerWidth" in js:
                return self.sizes.pop(0)
            return None  # 스크롤이 잠기지 않은 보통 페이지

        async def screenshot(self, **kw):
            return b"\x89PNG"

    page = Page()

    async def go():
        got = []
        for _ in range(2):
            async with run._capture_layout(page):
                got.append(await run._screenshot(page, "observe", full=True))
        return got

    first, second = asyncio.run(go())
    assert first is None and second  # 첫 캡처는 실패, 두 번째는 정상
    assert run.rec._pauses == 0

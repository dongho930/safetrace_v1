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

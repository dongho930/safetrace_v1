"""증거 스크린샷의 화면 표시용 미리보기(대개 JPEG).

미리보기는 증거가 아니다. 원본 PNG 는 그대로 두며 해시 체인·서명·검증은 원본만 대상으로 한다.
페이지 전체 캡처(1280×수천 px PNG, 장당 2~3MB)를 콘솔이 매 단계 받아 그리면 무거워서, 표시용으로만 줄여 준다.
"""

from __future__ import annotations

import io
import threading
from collections import OrderedDict
from PIL import Image

Image.MAX_IMAGE_PIXELS = 20_000_000  # 에이전트 캡처 최대(1280×6000)보다 넉넉히, 그 이상은 거부
MAX_WIDTH = 1280
QUALITY = 72
_CACHE_ITEMS = 64

_cache: OrderedDict[tuple, tuple[bytes, str]] = OrderedDict()
_lock = threading.Lock()


def preview_image(data: bytes, key: tuple) -> tuple[bytes, str]:
    """(내용, media type). data: 원본 PNG 바이트(호출한 쪽이 증거 볼륨에서 안전하게 읽은 것), key: 캐시 열쇠(경로·수정
    시각·크기). 단순한 화면은 PNG 가 더 작으므로, JPEG 가 원본보다 크면 원본을 그대로 준다."""
    with _lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
    with Image.open(io.BytesIO(data)) as im:
        rgb = im.convert("RGB")
    if rgb.width > MAX_WIDTH:
        rgb = rgb.resize((MAX_WIDTH, round(rgb.height * MAX_WIDTH / rgb.width)), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    rgb.save(buf, "JPEG", quality=QUALITY, optimize=True, progressive=True)
    out = (buf.getvalue(), "image/jpeg")
    if len(out[0]) >= len(data):
        out = (data, "image/png")
    with _lock:
        _cache[key] = out
        while len(_cache) > _CACHE_ITEMS:
            _cache.popitem(last=False)
    return out

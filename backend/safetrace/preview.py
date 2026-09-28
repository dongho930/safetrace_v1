"""증거 스크린샷의 화면 표시용 미리보기(대개 JPEG).

미리보기는 증거가 아니다. 원본 PNG 는 그대로 두며 해시 체인·서명·검증은 원본만 대상으로 한다.
페이지 전체 캡처(1280×수천 px PNG, 장당 2~3MB)를 콘솔이 매 단계 받아 그리면 무거워서, 표시용으로만 줄여 준다.
"""

from __future__ import annotations

import io
import threading
from collections import OrderedDict
from pathlib import Path

from PIL import Image

Image.MAX_IMAGE_PIXELS = 20_000_000  # 에이전트 캡처 최대(1280×6000)보다 넉넉히, 그 이상은 거부
MAX_WIDTH = 1280
QUALITY = 72
_CACHE_ITEMS = 64

_cache: OrderedDict[tuple[str, int, int], tuple[bytes, str]] = OrderedDict()
_lock = threading.Lock()


def preview_image(path: Path) -> tuple[bytes, str]:
    """(내용, media type). 단순한 화면은 PNG 가 더 작으므로, JPEG 가 원본보다 크면 원본을 그대로 준다."""
    st = path.stat()
    key = (str(path), st.st_mtime_ns, st.st_size)
    with _lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
    with Image.open(path) as im:
        rgb = im.convert("RGB")
    if rgb.width > MAX_WIDTH:
        rgb = rgb.resize((MAX_WIDTH, round(rgb.height * MAX_WIDTH / rgb.width)), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    rgb.save(buf, "JPEG", quality=QUALITY, optimize=True, progressive=True)
    data = (buf.getvalue(), "image/jpeg")
    if len(data[0]) >= st.st_size:
        data = (path.read_bytes(), "image/png")
    with _lock:
        _cache[key] = data
        while len(_cache) > _CACHE_ITEMS:
            _cache.popitem(last=False)
    return data

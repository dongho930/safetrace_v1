"""로컬 OCR: 글자가 이미지인 버튼을 서버 안에서 읽는다. 이미지를 외부로 보내지 않는다.

기본은 RapidOCR(onnxruntime) 기본 모델(중·영). 한국어 인식은 ST_OCR_REC_MODEL 로 PaddleOCR PP-OCRv5
한국어 인식 모델(onnx, 문자 사전이 메타데이터에 포함)을 지정한다(docs/ocr.md, tools/fetch_ocr_model.py).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_CGROUP_CPU_MAX = Path("/sys/fs/cgroup/cpu.max")

log = logging.getLogger("safetrace.ocr")
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ocr")
_CACHE_SIZE = 512  # 같은 이미지(바이트가 같은 스크린샷)는 다시 읽지 않는다. 같은 배너가 단계마다 다시 보인다
# 모자이크: 이미지 버튼 캡처들을 원래 크기 그대로 한 장에 붙여 글자 검출을 한 번에 한다
_MOSAIC_W, _MOSAIC_MAX_H, _MOSAIC_GAP = 1280, 2400, 24


class LocalOCR:
    def __init__(self):
        self._engine = None
        self._batch_engine = None
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, str] = OrderedDict()
        self.cache_hits = 0
        self.available = False
        try:
            from rapidocr_onnxruntime import RapidOCR  # noqa: PLC0415

            kwargs = {}
            # rapidocr 1.2.x 는 문자 사전 경로 인자를 인식기에 넘기지 않으므로, 사전이 onnx 에 들어 있는 모델만 쓴다
            if os.environ.get("ST_OCR_REC_MODEL"):
                kwargs["rec_model_path"] = os.environ["ST_OCR_REC_MODEL"]
            _limit_onnx_threads(ocr_threads())
            self._engine = RapidOCR(**kwargs)
            # 모자이크용: 이미지를 키우지 않고 검출한다(작은 버튼을 크게 키우면 검출이 수십 배 느려진다).
            # rapidocr 1.2.3 은 det_ 인자를 줄 때 det_model_path 가 있어야 한다("" = 기본 모델)
            self._batch_engine = RapidOCR(**kwargs, det_limit_type="max", det_limit_side_len=4096, det_model_path="")
            self.available = True
        except Exception as e:  # 모델·런타임이 없으면 OCR 없이 동작
            log.warning("local OCR unavailable: %s", type(e).__name__)

    def read(self, png: bytes, max_len: int = 80) -> str:
        if not self.available or len(png) > 4_000_000:
            return ""
        key = hashlib.sha256(png).hexdigest()
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self.cache_hits += 1
                return self._cache[key][:max_len]
            try:
                result, _ = self._engine(_pad(png))
            except Exception as e:
                log.warning("ocr failed: %s", type(e).__name__)
                return ""  # 실패는 저장하지 않는다(다음에 다시 시도)
            text = _join(result)
            self._remember(key, text)
        return text[:max_len]

    def read_many(self, pngs: list[bytes], max_len: int = 80, deadline: float | None = None) -> list[str]:
        """여러 이미지 버튼을 한 번에 읽는다. 결과 순서는 입력과 같다.

        캐시에 없는 이미지를 원래 크기로 모자이크에 붙여 한 번에 검출·인식하고, 글자 중심이 들어간 이미지에
        돌려준다(각 이미지의 자리가 정해져 있어 다른 버튼에 글자가 배정되지 않는다). 모자이크에서 글자를 못 찾은
        것만 한 장씩 다시 읽는다(작은 글자는 키워야 보인다). deadline(time.monotonic) 이 지나면 다시 읽기를 멈춘다.
        이미지 92개 평가 페이지에서 한 장씩 읽을 때 95초 → 19초, 맞힌 문구 84 → 83/98."""
        out: list[str | None] = [None] * len(pngs)
        if not self.available:
            return [""] * len(pngs)
        todo: list[tuple[int, str, object]] = []
        with self._lock:
            for i, png in enumerate(pngs):
                key = hashlib.sha256(png).hexdigest()
                if key in self._cache:
                    self._cache.move_to_end(key)
                    self.cache_hits += 1
                    out[i] = self._cache[key]
                elif len(png) <= 4_000_000 and (img := _decode(png)) is not None:
                    todo.append((i, key, img))
                else:
                    out[i] = ""
        for group in _pack(todo):
            with self._lock:
                texts = self._read_mosaic(group)
                for (i, key, _img, *_), text in zip(group, texts):
                    if text:
                        out[i] = text
                        self._remember(key, text)
        for i, png in enumerate(pngs):
            if out[i] is None:  # 모자이크에서 못 읽음(또는 너무 큼): 한 장씩, 시간이 남아 있을 때만
                out[i] = self.read(png, 10_000) if deadline is None or time.monotonic() < deadline else ""
        return [t[:max_len] for t in out]

    def _read_mosaic(self, group: list) -> list[str]:
        import numpy as np  # noqa: PLC0415  (rapidocr 의존성)

        h = max(y + img.shape[0] for _, _, img, _, y in group) + _MOSAIC_GAP
        canvas = np.full((h, _MOSAIC_W, 3), 255, np.uint8)
        for _, _, img, x, y in group:
            canvas[y:y + img.shape[0], x:x + img.shape[1]] = img
        try:
            result, _ = self._batch_engine(canvas)
        except Exception as e:
            log.warning("ocr mosaic failed: %s", type(e).__name__)
            return [""] * len(group)
        found: list[list[tuple[float, float, str]]] = [[] for _ in group]
        for r in result or []:
            try:
                poly, txt, score = r[0], str(r[1]), float(r[2])
            except (TypeError, ValueError, IndexError):
                continue
            if score < 0.5:
                continue
            cx = sum(pt[0] for pt in poly) / len(poly)
            cy = sum(pt[1] for pt in poly) / len(poly)
            for n, (_, _, img, x, y) in enumerate(group):
                if x <= cx < x + img.shape[1] and y <= cy < y + img.shape[0]:
                    found[n].append((cy, cx, txt))
                    break
        return [" ".join(t for _, _, t in sorted(f)) for f in found]

    def _remember(self, key: str, text: str):
        self._cache[key] = text
        if len(self._cache) > _CACHE_SIZE:
            self._cache.popitem(last=False)

    async def read_many_async(self, pngs: list[bytes], max_len: int = 80, deadline: float | None = None) -> list[str]:
        """read_many 를 전용 OCR 스레드에서(read_async 참고)."""
        return await asyncio.get_running_loop().run_in_executor(_executor, self.read_many, pngs, max_len, deadline)

    async def read_async(self, png: bytes, max_len: int = 80) -> str:
        """전용 스레드 하나에서 읽는다(이벤트 루프를 막지 않음).

        asyncio.to_thread 는 부를 때마다 다른 작업 스레드(최대 12개)를 쓰고, glibc 는 스레드마다 메모리 영역을
        따로 잡아 OCR 이 쓴 수백 MB 를 영역마다 쥐고 있는다. 쿠팡 첫 관찰에서 Python 이 1.3GB 까지 늘어
        컨테이너 메모리 한도(2GB)로 강제 종료됐다. 어차피 잠금으로 한 번에 하나씩만 돌므로 스레드를 하나로 묶는다."""
        return await asyncio.get_running_loop().run_in_executor(_executor, self.read, png, max_len)


def _decode(png: bytes):
    try:
        import cv2  # noqa: PLC0415
        import numpy as np  # noqa: PLC0415

        img = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_COLOR)
    except ImportError:
        return None
    return img


def _pack(todo: list[tuple[int, str, object]]) -> list[list[tuple]]:
    """이미지를 폭 _MOSAIC_W 안에 줄지어 놓는다(사이 여백 _MOSAIC_GAP). 높이가 차면 다음 모자이크.
    한 줄에 들어가지 않을 만큼 큰 이미지는 모자이크에 넣지 않는다(한 장씩 읽음)."""
    groups: list[list[tuple]] = []
    cur: list[tuple] = []
    x = y = _MOSAIC_GAP
    row_h = 0
    for i, key, img in todo:
        h, w = img.shape[:2]
        if w > _MOSAIC_W - 2 * _MOSAIC_GAP or h > _MOSAIC_MAX_H - 2 * _MOSAIC_GAP:
            continue
        if x + w + _MOSAIC_GAP > _MOSAIC_W:
            x, y, row_h = _MOSAIC_GAP, y + row_h + _MOSAIC_GAP, 0
        if y + h + _MOSAIC_GAP > _MOSAIC_MAX_H:
            groups.append(cur)
            cur, x, y, row_h = [], _MOSAIC_GAP, _MOSAIC_GAP, 0
        cur.append((i, key, img, x, y))
        x += w + _MOSAIC_GAP
        row_h = max(row_h, h)
    if cur:
        groups.append(cur)
    return groups


def _join(result) -> str:
    """인식 결과 중 점수 0.5 이상인 글자만 이어 붙인다."""
    words = []
    for r in result or []:
        try:
            if len(r) >= 3 and float(r[2]) >= 0.5:  # rapidocr 은 점수를 문자열로 줄 때가 있다
                words.append(str(r[1]))
        except (TypeError, ValueError):
            continue
    return " ".join(words)


def ocr_threads(cpu_max: Path = _CGROUP_CPU_MAX) -> int:
    """OCR 추론 스레드 수: ST_OCR_THREADS, 없으면 쓸 수 있는 CPU(컨테이너 CPU 한도 반영, 최대 4).

    onnxruntime 은 컨테이너 CPU 한도(cgroup)를 보지 않고 호스트 코어 수만큼 스레드를 띄운다. 에이전트 컨테이너
    (cpus 2, 호스트 8코어)에서 그 스레드들이 한도 안에서 다투어 이미지 한 장에 2초 가까이 걸렸다(2개면 0.7초)."""
    if os.environ.get("ST_OCR_THREADS", "").isdigit() and int(os.environ["ST_OCR_THREADS"]) > 0:
        return int(os.environ["ST_OCR_THREADS"])
    try:
        cpus = len(os.sched_getaffinity(0))
    except AttributeError:  # Windows·macOS
        cpus = os.cpu_count() or 1
    try:
        quota, period = cpu_max.read_text().split()[:2]  # cgroup v2: "200000 100000" | "max 100000"
        if quota != "max":
            cpus = min(cpus, max(1, int(quota) // int(period)))
    except (OSError, ValueError):
        pass
    return max(1, min(cpus, 4))


def _limit_onnx_threads(n: int):
    """rapidocr 1.2.3 은 스레드 설정을 받지 않으므로, 세션을 만들 때 쓰는 SessionOptions 에 스레드 수를 넣는다."""
    try:
        import rapidocr_onnxruntime.utils as rapid_utils  # noqa: PLC0415
        from onnxruntime import SessionOptions  # noqa: PLC0415
    except ImportError:
        return

    class _Limited(SessionOptions):
        def __init__(self):
            super().__init__()
            self.intra_op_num_threads = n
            self.inter_op_num_threads = 1

    if hasattr(rapid_utils, "SessionOptions"):
        rapid_utils.SessionOptions = _Limited
        log.info("ocr threads: %d", n)


def _pad(png: bytes):
    """가장자리에 붙은 글자는 검출이 잘 안 되므로 흰 여백을 두르고 작은 이미지는 키운다."""
    try:
        import cv2  # noqa: PLC0415  (rapidocr 의존성)
        import numpy as np  # noqa: PLC0415

        img = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            return png
        img = cv2.copyMakeBorder(img, 24, 24, 24, 24, cv2.BORDER_CONSTANT, value=(255, 255, 255))
        if img.shape[0] < 120:
            img = cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        return img
    except ImportError:
        return png


_ocr: LocalOCR | None = None


def get_ocr() -> LocalOCR:
    global _ocr
    if _ocr is None:
        _ocr = LocalOCR()
    return _ocr

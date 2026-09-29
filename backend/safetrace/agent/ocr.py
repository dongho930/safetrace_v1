"""로컬 OCR: 글자가 이미지인 버튼을 서버 안에서 읽는다. 이미지를 외부로 보내지 않는다.

기본은 RapidOCR(onnxruntime) 기본 모델(중·영). 한국어 인식은 ST_OCR_REC_MODEL 로 PaddleOCR PP-OCRv5
한국어 인식 모델(onnx, 문자 사전이 메타데이터에 포함)을 지정한다(docs/ocr.md, tools/fetch_ocr_model.py).
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_CGROUP_CPU_MAX = Path("/sys/fs/cgroup/cpu.max")

log = logging.getLogger("safetrace.ocr")
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ocr")


class LocalOCR:
    def __init__(self):
        self._engine = None
        self._lock = threading.Lock()
        self.available = False
        try:
            from rapidocr_onnxruntime import RapidOCR  # noqa: PLC0415

            kwargs = {}
            # rapidocr 1.2.x 는 문자 사전 경로 인자를 인식기에 넘기지 않으므로, 사전이 onnx 에 들어 있는 모델만 쓴다
            if os.environ.get("ST_OCR_REC_MODEL"):
                kwargs["rec_model_path"] = os.environ["ST_OCR_REC_MODEL"]
            _limit_onnx_threads(ocr_threads())
            self._engine = RapidOCR(**kwargs)
            self.available = True
        except Exception as e:  # 모델·런타임이 없으면 OCR 없이 동작
            log.warning("local OCR unavailable: %s", type(e).__name__)

    def read(self, png: bytes, max_len: int = 80) -> str:
        if not self.available or len(png) > 4_000_000:
            return ""
        with self._lock:
            try:
                result, _ = self._engine(_pad(png))
            except Exception as e:
                log.warning("ocr failed: %s", type(e).__name__)
                return ""
        if not result:
            return ""
        words = []
        for r in result:
            try:
                if len(r) >= 3 and float(r[2]) >= 0.5:  # rapidocr 은 점수를 문자열로 줄 때가 있다
                    words.append(str(r[1]))
            except (TypeError, ValueError):
                continue
        return " ".join(words)[:max_len]

    async def read_async(self, png: bytes, max_len: int = 80) -> str:
        """전용 스레드 하나에서 읽는다(이벤트 루프를 막지 않음).

        asyncio.to_thread 는 부를 때마다 다른 작업 스레드(최대 12개)를 쓰고, glibc 는 스레드마다 메모리 영역을
        따로 잡아 OCR 이 쓴 수백 MB 를 영역마다 쥐고 있는다. 쿠팡 첫 관찰에서 Python 이 1.3GB 까지 늘어
        컨테이너 메모리 한도(2GB)로 강제 종료됐다. 어차피 잠금으로 한 번에 하나씩만 돌므로 스레드를 하나로 묶는다."""
        return await asyncio.get_running_loop().run_in_executor(_executor, self.read, png, max_len)


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

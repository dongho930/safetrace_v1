"""로컬 OCR: 글자가 이미지인 버튼을 서버 안에서 읽는다. 이미지를 외부로 보내지 않는다.

기본은 RapidOCR(onnxruntime) 기본 모델(중·영). 한국어 인식은 ST_OCR_REC_MODEL 로 PaddleOCR PP-OCRv5
한국어 인식 모델(onnx, 문자 사전이 메타데이터에 포함)을 지정한다(docs/ocr.md, tools/fetch_ocr_model.py).
"""

from __future__ import annotations

import logging
import os
import threading

log = logging.getLogger("safetrace.ocr")


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

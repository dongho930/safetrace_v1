"""한국어 OCR 인식 모델 받기: RapidOCR 가 onnx 로 변환한 PaddleOCR PP-OCRv5 한국어 인식 모델.

문자 사전은 onnx 메타데이터(character)에 들어 있어 별도 파일이 필요 없다.
받은 뒤 SHA-256 을 확인하고, 다르면 지운다(공급망 변조 방지).

실행: python tools/fetch_ocr_model.py [--dest models]
그다음: ST_OCR_REC_MODEL=models/korean_PP-OCRv5_rec_mobile.onnx
"""

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

NAME = "korean_PP-OCRv5_rec_mobile.onnx"
URL = f"https://www.modelscope.cn/models/RapidAI/RapidOCR/resolve/master/onnx/PP-OCRv5/rec/{NAME}"
SHA256 = "cd6e2ea50f6943ca7271eb8c56a877a5a90720b7047fe9c41a2e541a25773c9b"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default=str(Path(__file__).resolve().parents[1] / "models"))
    dest = Path(ap.parse_args().dest)
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / NAME
    if out.exists() and hashlib.sha256(out.read_bytes()).hexdigest() == SHA256:
        print(f"already present: {out}")
        return 0
    tmp = out.with_suffix(".part")
    with urllib.request.urlopen(URL, timeout=120) as r, open(tmp, "wb") as f:  # nosec B310 - 고정 https 주소, 받은 뒤 SHA-256 확인
        while chunk := r.read(1 << 20):
            f.write(chunk)
    digest = hashlib.sha256(tmp.read_bytes()).hexdigest()
    if digest != SHA256:
        tmp.unlink()
        print(f"SHA-256 mismatch: {digest}", file=sys.stderr)
        return 1
    tmp.replace(out)
    print(f"saved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

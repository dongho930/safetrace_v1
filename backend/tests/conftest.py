import os
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "testpages"))

# API 모듈이 import 시점에 설정을 읽으므로 먼저 지정
os.environ.setdefault("ST_EVIDENCE_HMAC_KEY", secrets.token_hex(32))
os.environ.setdefault("ST_DATABASE_URL", "sqlite:///" + str(ROOT / "var" / "test.db"))
os.environ.setdefault("ST_EVIDENCE_DIR", str(ROOT / "var" / "test-evidence"))
INVESTIGATOR = "inv-" + secrets.token_hex(16)
VIEWER = "view-" + secrets.token_hex(16)
os.environ["ST_API_TOKENS"] = f'["{INVESTIGATOR}:investigator", "{VIEWER}:viewer"]'
os.environ["ST_DECIDER_CHAIN"] = '["rules"]'
os.environ["ST_TEST_ALLOWLIST"] = '["127.0.0.1:8900", "localhost:8900"]'
os.environ["ST_RECORD_VIDEO"] = "true"
os.environ["ST_DECISION_TOKEN"] = ""
# 한국어 OCR 모델을 받아 두었으면(tools/fetch_ocr_model.py) 시험에서도 쓴다
_KO_OCR = ROOT / "models" / "korean_PP-OCRv5_rec_mobile.onnx"
if _KO_OCR.exists():
    os.environ.setdefault("ST_OCR_REC_MODEL", str(_KO_OCR))

TEST_PORT = 8900


@pytest.fixture(scope="session")
def testpages():
    import server  # testpages/server.py

    srv, rec = server.start(TEST_PORT)
    yield rec
    srv.shutdown()


@pytest.fixture
def settings(tmp_path):
    from safetrace.config import Settings

    return Settings(
        evidence_dir=tmp_path / "evidence",
        evidence_hmac_key=secrets.token_hex(32),
        decider_chain=["rules"],
        decision_token="",
        test_allowlist=[f"127.0.0.1:{TEST_PORT}", f"localhost:{TEST_PORT}"],
        max_steps=10,
        max_seconds=90,
        record_video=False,
        ocr_enabled=True,
        _env_file=None,
    )

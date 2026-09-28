# 로컬 OCR

글자가 이미지로 된 버튼(`<a><img></a>`, `<img>` 버튼 등)만 서버 안에서 OCR로 읽는다. 이미지는 외부로 보내지 않는다.

- 엔진: RapidOCR(onnxruntime) 1.2.3. `pip install ".[ocr]"`
- 기본 모델은 중국어·영어 모델이라 **한국어 버튼은 인식하지 못한다**(한글 버튼 5개 중 0개 인식).
- 한국어 인식 모델: PaddleOCR **PP-OCRv5 한국어 인식 모델**(RapidOCR 가 onnx 로 변환한 것, 13MB).
  문자 사전이 onnx 메타데이터(`character`)에 들어 있어 사전 파일이 따로 필요 없다. 검출·방향 모델은 기본 모델을 그대로 쓴다.
  영문 버튼도 계속 읽는다.

## 설치

| 환경 | 방법 |
|---|---|
| Docker | 에이전트 이미지 빌드 때 자동으로 받아 `/models` 에 넣고 `ST_OCR_REC_MODEL` 을 지정한다(`Dockerfile.agent`). 조사 중에는 모델을 받지 않는다. |
| 로컬 개발·시험 | `python tools/fetch_ocr_model.py` → `models/` 에 저장(깃에 올리지 않음). `pytest` 는 파일이 있으면 자동으로 쓴다(`conftest.py`). 직접 실행할 때는 `ST_OCR_REC_MODEL=models/korean_PP-OCRv5_rec_mobile.onnx` |

받기 스크립트는 SHA-256(`cd6e2ea5…773c9b`)을 확인하고 다르면 파일을 지운다.

출처: `https://www.modelscope.cn/models/RapidAI/RapidOCR` → `onnx/PP-OCRv5/rec/korean_PP-OCRv5_rec_mobile.onnx`

## 확인 결과 (2026-09-28)

| 이미지 버튼 글자 | 기본 모델 | 한국어 모델 |
|---|---|---|
| 무상 교체 신청하기 | (없음) | 무상 교체 신청하기 |
| 지금 입금하기 | (없음) | 지금 입금하기 |
| 로그인 | (없음) | 로그인 |
| 첫충 20% 보너스 | ` 2 20% ` | 첫충2 20%보너스 |
| 다음 단계로 | (없음) | 다음 단계로 |

시험 페이지 `testpages/imgbtn/ko.html`(한글 이미지 버튼 "지금 결제하기"·"다음 단계로"): 로컬 시험 `test_korean_image_button_ocr` 과 Docker 실조사 모두 "다음 단계로"만 선택지에 남고 결제 버튼은 빠졌다. 결제 경로 요청 0건.

## 안전 규칙

- OCR로 읽은 글자에도 금지 분류(결제·로그인 등)를 다시 적용한다. 이미지로 된 '결제' 버튼도 선택지에서 빠진다.
- 클릭 직전 요소 비교(바꿔치기 탐지)에는 OCR 결과가 아닌 DOM 원본 속성을 쓴다.
- OCR 은 신뢰도 0.5 이상인 글자만 쓰고 80자로 자른다. 4MB 가 넘는 이미지는 읽지 않는다.

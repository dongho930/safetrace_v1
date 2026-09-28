# 로컬 OCR

글자가 이미지로 된 버튼(`<a><img></a>`, `<img>` 버튼 등)만 서버 안에서 OCR로 읽는다. 이미지는 외부로 보내지 않는다.

- 엔진: RapidOCR(onnxruntime). `pip install ".[ocr]"`
- 기본 모델은 중국어·영어 모델이라 **한국어 버튼은 인식하지 못한다.**
- 한국어를 읽으려면 PaddleOCR 한국어 인식 모델(onnx로 변환한 것)과 문자 사전 파일을 받아 아래 환경변수로 지정한다.

```
ST_OCR_REC_MODEL=/models/korean_rec.onnx
ST_OCR_REC_KEYS=/models/korean_dict.txt
```

- OCR로 읽은 글자에도 금지 분류(결제·로그인 등)를 다시 적용한다. 이미지로 된 '결제' 버튼도 선택지에서 빠진다.
- 클릭 직전 요소 비교(바꿔치기 탐지)에는 OCR 결과가 아닌 DOM 원본 속성을 쓴다.

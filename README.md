# SafeTrace

AI 브라우저 에이전트 기반 위협 의심 사이트 조사·공공 심의 지원 시스템 (2026 SW개발보안 경진대회 트랙 C)

신고 URL을 격리 브라우저에서 열고, AI 에이전트가 버튼·링크를 눌러 가며 숨겨진 입금·개인정보 입력 화면까지 탐색한다.
TypeSafe의 의사결정 모델 **Jev**가 다음 행동과 위협 유형을 정해진 선택지와 확률로 판단하고, 코드로 만든 **안전 게이트**가
실행 전에 모든 행동을 검사한다. 모든 행동과 화면은 **해시 체인 + HMAC 서명** 증거로 남는다. 최종 판정은 담당자가 한다.

```
신고 URL → ① 관찰(클릭 후보 목록화·OCR) → ② Jev 행동 선택 → ③ 안전 게이트 → ④ 실행·서명 기록 → … → Jev 위협 판단 → 담당자
```

## 구성

| 경로 | 내용 |
|---|---|
| `backend/safetrace/agent/` | 에이전트 루프, 관찰, 안전 게이트, 로컬 OCR, 워커 |
| `backend/safetrace/decision/` | 판단 서비스: Jev(TypeSafe 직접 / OpenRouter) → 규칙 기반 순서로 전환, 응답 스키마 검증 |
| `backend/safetrace/netguard.py` | SSRF 1차 방어(이동 전 실제 IP 확인) |
| `backend/safetrace/proxy/egress.py` | SSRF 2차 방어: 검문 프록시(접속 시점 재해석, DNS Rebinding 대비) |
| `backend/safetrace/evidence.py` | 증거 해시 체인·HMAC 서명·검증 |
| `backend/safetrace/api/` | FastAPI: 사건 접수·조회, SSE 실시간 진행, 증거 파일·무결성 검증 |
| `frontend/` | 실시간 조사 콘솔(React 19 + TypeScript + Vite) |
| `testpages/` | 단계형 가짜 위협 페이지 + 에이전트 공격 시나리오 10종 + 요청 기록 서버 |
| `data/normal_sites.csv` | 정상 대조 사이트 162개 |
| `docs/` | 사전준비 점검표, STRIDE 위협 모델, OCR 안내 |

## 로컬 개발 실행 (Docker 없이)

```bash
python -m venv .venv && .venv/Scripts/pip install -e "backend[ocr,dev]"   # macOS/Linux: .venv/bin/pip
.venv/Scripts/python -m playwright install chromium

# backend/.env
#   ST_EVIDENCE_HMAC_KEY=<python -c "import secrets;print(secrets.token_hex(32))">
#   ST_API_TOKENS=["<24자 이상 토큰>:admin"]
#   ST_DECIDER_CHAIN=["rules"]                              # Jev 키가 있으면 ["jev_typesafe","jev_openrouter","rules"]
#   ST_TEST_ALLOWLIST=["127.0.0.1:8900","localhost:8900"]   # 시험 페이지 허용(운영에서는 비움)

python testpages/server.py                                   # 시험 페이지 :8900
cd backend && ../.venv/Scripts/uvicorn safetrace.api.main:app --port 8000
cd frontend && npm install && npm run dev                    # 콘솔 :5173
```

개발 모드(`ST_REDIS_URL` 없음)에서는 API 프로세스 안에서 에이전트를 실행한다.

## 배포 실행 (Docker Compose)

```bash
cp .env.example .env   # 값 채우기
docker compose up -d --build
docker compose --profile demo up -d testpages   # 시연용 시험 페이지(선택)
```

- `sandbox` 네트워크는 `internal`: 에이전트는 인터넷에 직접 나갈 수 없고 `egress` 프록시로만 나간다.
- 에이전트에는 DB 접속 정보와 Jev 키가 없다. Jev 키는 `decision`에만 있다.

## 시험

```bash
cd backend && ../.venv/Scripts/python -m pytest -q          # 106개 (단위 + 실제 Chromium 통합)
```

## Jev 실연결 점검 (키 발급 후)

```bash
ST_TYPESAFE_API_KEY=... python tools/jev_smoke.py
ST_OPENROUTER_API_KEY=... python tools/jev_smoke.py --openrouter
```

## 책임 있는 운영 원칙

- AI 판단은 기술적 의심 의견이며 법적 위법성의 확률이 아니다.
- 에이전트는 텍스트 입력·폼 제출·로그인·결제·다운로드·CAPTCHA 우회·취약점 공격을 하지 않는다(해당 기능 자체가 없다).
- 실제 위협 사이트는 격리 환경에서만 조사하고, 반복 시연은 `testpages/`로 한다.

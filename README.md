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
| `backend/safetrace/api/` | FastAPI: 사건 접수·조회, SSE 실시간 진행, 증거 파일·무결성 검증, 담당자 판정, 검토 패키지 |
| `frontend/` | 실시간 조사 콘솔(React 19 + TypeScript + Vite) |
| `testpages/` | 단계형 가짜 위협 페이지 + 에이전트 공격 시나리오 10종 + 요청 기록 서버 |
| `data/normal_sites.csv` | 정상 대조 사이트 168개(정부 허가 사행사업 공식 사이트 6개 포함) |
| `docs/` | 사전준비 점검표, STRIDE 위협 모델, OCR 안내 |

## 로컬 개발 실행 (Docker 없이)

```bash
python -m venv .venv && .venv/Scripts/pip install -e "backend[ocr,dev]"   # macOS/Linux: .venv/bin/pip
.venv/Scripts/python -m playwright install chromium

# backend/.env
#   ST_EVIDENCE_HMAC_KEY=<python -c "import secrets;print(secrets.token_hex(32))">
#   ST_API_TOKENS=[]                                        # 자동화(스크립트)용 토큰만. 사람은 계정으로 로그인
#   ST_DECIDER_CHAIN=["rules"]                              # Jev 키가 있으면 ["jev_typesafe","jev_openrouter","rules"]
#   ST_TEST_ALLOWLIST=["127.0.0.1:8900","localhost:8900"]   # 시험 페이지 허용(운영에서는 비움)

cd backend && ../.venv/Scripts/python -m safetrace.accounts add <아이디> --role admin   # 첫 관리자(비밀번호 입력)
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
docker compose exec api python -m safetrace.accounts add <아이디> --role admin   # 첫 관리자
```

## 계정과 권한

- 담당자는 아이디·비밀번호로 로그인한다. 비밀번호는 Argon2id(m=64MiB, t=3, p=4)로만 저장하고, 세션 토큰은 DB에 SHA-256만 남긴다.
- 세션은 30분 동안 쓰지 않거나 12시간이 지나면 끊긴다. 비밀번호가 5번 연속 틀리면 그 계정을 15분 잠근다.
- 역할: 열람(viewer) < 조사관(investigator, URL 접수) < 검토관(reviewer, 판정) < 관리자(admin, 계정 관리). 역할 변경·비활성화·비밀번호 변경 때 그 계정의 세션을 모두 끊는다.
- 첫 관리자는 명령줄로 만들고, 그다음 계정은 콘솔의 「계정 관리」에서 만든다. 잊은 비밀번호는 `python -m safetrace.accounts passwd <아이디>`, 잠금 해제는 `unlock <아이디>`.
- `ST_API_TOKENS`는 자동화(스크립트) 전용이다. 관리자 역할이어도 계정 관리·판정은 할 수 없다.
- 판정(위협 확정·정상·보류)은 검토관 이상의 담당자 계정만 저장한다(`POST /api/cases/{id}/verdicts`). 덮어쓰지 않고 판(rev)을 쌓으며, 저장할 때 보고 있던 판 번호를 보내 그사이 다른 담당자가 바꿨으면 409로 거절한다. 판정에는 당시 AI 의견과 증거 체인 끝(head)을 함께 남긴다.
- 검토 패키지: 조사가 끝난 사건의 탐색 기록(단계별 관찰 화면·Jev 선택과 확률·안전 게이트·전후 화면·이동 경로), 판단 결과(위협 유형 후보·확률·근거 증거 ID·Safe Browsing), 담당자 판정 기록·감사로그를 묶는다. `GET /api/cases/{id}/package`(JSON, 열람자 이상), `GET /api/cases/{id}/package.zip`(조사관 이상, 감사로그). ZIP에는 `package.json`·체인 원본·파일·`SHA256SUMS`·`package.sig`(HMAC)·`README.txt`가 들어 있어 받은 쪽이 해시 체인과 파일을 다시 계산해 볼 수 있다. 외부 기관에 자동으로 보내지 않는다.
- 로그인 성공·실패(이유 포함), 로그아웃, 계정 생성·변경, 판정 저장·충돌, 패키지 내려받기는 감사로그에 남는다. 비밀번호는 남기지 않는다.

- `sandbox` 네트워크는 `internal`: 에이전트는 인터넷에 직접 나갈 수 없고 `egress` 프록시로만 나간다.
- 에이전트에는 DB 접속 정보와 Jev 키가 없다. Jev 키는 `decision`에만 있다.

## 시험

```bash
cd backend && ../.venv/Scripts/python -m pytest -q          # 171개 (단위 + 실제 Chromium 통합)
```

## 품질 평가 (Docker 스택에서, 실제 Jev 판단)

정답을 붙인 URL 목록(`data/eval_set.csv`: 시험 페이지·정상 사이트·KISA 피싱 URL)을 여러 번 조사해
정답률·놓침·오탐·판단 불가·반복 일관성·시간을 잰다. 모델 판단은 매번 조금씩 달라서 개선 전후는 이 도구로 비교한다.

```bash
docker compose --profile demo up -d
python tools/eval_agent.py run --repeat 3 --label 메모        # 결과: var/eval/<시각>_<메모>.jsonl · .md
python tools/eval_agent.py compare var/eval/전.jsonl var/eval/후.jsonl
```

KISA 주소는 시간이 지나면 사라진다(접속 불가는 채점에서 빼고 따로 센다). 늘어나면 목록을 갱신한다.

## Jev 실연결 점검 (키 발급 후)

```bash
ST_TYPESAFE_API_KEY=... python tools/jev_smoke.py
ST_OPENROUTER_API_KEY=... python tools/jev_smoke.py --openrouter
```

## 책임 있는 운영 원칙

- AI 판단은 기술적 의심 의견이며 법적 위법성의 확률이 아니다.
- 에이전트는 텍스트 입력·폼 제출·로그인·결제·다운로드·CAPTCHA 우회·취약점 공격을 하지 않는다(해당 기능 자체가 없다).
- 실제 위협 사이트는 격리 환경에서만 조사하고, 반복 시연은 `testpages/`로 한다.

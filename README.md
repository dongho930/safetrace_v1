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
| `backend/safetrace/signer/` | 서명 서비스: 증거 서명 키를 에이전트와 분리, seq·시각을 서비스가 정하고 사건별 체인을 열고 닫음 |
| `backend/safetrace/api/` | FastAPI: 사건 접수·조회, SSE 실시간 진행, 증거 파일·무결성 검증, 담당자 판정, 검토 패키지 |
| `backend/safetrace/intake.py`, `agent/feeder.py`, `agent/feeds.py` | 자동 수집: 공개 피싱 피드(OpenPhish·PhishTank)를 수집 컨테이너(feeder)가 받아 서명하고, API 가 검사·중복 제거 후 조사 접수 |
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

개발 모드(`ST_REDIS_URL` 없음)에서는 API 프로세스 안에서 에이전트를 실행한다. `ST_SIGNER_URL` 이 없으면 서명도 같은 프로세스에서 한다.
Compose 에서는 증거 서명 키를 서명 서비스(`signer`)와 API(검증)만 가진다. 에이전트는 키 없이 기록 내용을 서명 서비스에 보내고, 기록 번호와 수집 시각은 서명 서비스가 정한다.

## 배포 실행 (Docker Compose)

```bash
cp .env.example .env   # 값 채우기
docker compose up -d --build
docker compose --profile demo up -d testpages   # 시연용 시험 페이지(선택)
docker compose exec api python -m safetrace.accounts add <아이디> --role admin   # 첫 관리자
```

공급망: 기본 이미지는 다이제스트로, CI 의 Actions 는 커밋 SHA 로 고정한다. 파이썬 의존성은 해시를 고정한 잠금 파일
(`backend/requirements.lock` API 계열 Python 3.13, `requirements-agent.lock` 조사 컨테이너 Python 3.12,
`requirements-ci.lock` CI)로만 설치하고(`pip install --require-hashes`), 콘솔은 `package-lock.json` 으로 `npm ci` 한다.
의존성을 바꾸면 잠금 파일을 다시 만들고(`uv pip compile backend/pyproject.toml <빌드용 setuptools> --generate-hashes
--python-version 3.13|3.12 --python-platform x86_64-manylinux_2_28`, `--extra ocr`·`--extra dev`) SBOM 을 다시 낸다
(`tools/make_sbom.sh` → `sbom/*.cdx.json`, CycloneDX).

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
- 자동 수집의 피드 받기는 브라우저 조사 워커가 아니라 `feeder`(격리망, 검문 프록시로만, CPU 0.5·메모리 256MB)가 하고, 결과 서명 키 `ST_FEED_KEY` 는 `feeder`·`api` 만 가진다.

## 자동 수집

콘솔 왼쪽 아래 '자동 수집'에서 사람 관리자가 켜면, 사람이 접수하지 않아도 공개 피싱 피드의 주소를 조사한다(`POST /api/intake`, 상태 `GET /api/intake`).

- 출처: OpenPhish 공개 피드(12시간마다, 비상업 이용만), PhishTank(6시간마다, 키 없이 최신순 앞부분 256KB). 받을 주소는 수집 코드에 고정돼 있다.
- 고르기: 형식 검사, 같은 호스트는 7일 안에 다시 넣지 않음(사람 신고 포함), 같은 키트 모양(공용 호스팅 + 첫 경로, 아니면 등록 도메인)은 한 번에 2개, 한 번 받기에 30개.
- 사람 신고 우선: 끝나지 않은 자동 수집 사건이 1건 아래일 때만 하나씩 접수한다(조사 컨테이너가 하나여도 사람 신고는 길어야 한 건 기다린다). 24시간 120건 상한. 사람 접수 한도에는 세지 않는다.
- 판정은 그대로 검토관이 한다. 목록에 '자동 수집' 배지, 출처 거르기 '자동 수집'.
- 대기열은 가장 최근에 받은 것부터 조사하고, 12시간이 지난 주소는 '오래됨'으로 버린다(피싱 사이트는 금방 사라진다).
- 한도는 `.env` 의 `ST_INTAKE_DAILY_MAX`(24시간 사건)·`ST_INTAKE_MAX_PENDING`·`ST_INTAKE_ROUND_MAX`·`ST_INTAKE_ITEM_MAX_AGE_H` 로 바꾼다(compose 가 api 에 넘긴다). 비밀값 `ST_FEED_KEY`(`.env.example`).

## 연관 사이트

신고 1건에서 같은 조직이 운영하는 다른 위험 사이트를 찾아, 아직 차단되지 않은 곳을 추가로 조사하는 기능이다. 원래 URL 판단의 정확도를 올리는 수단이 아니며, **하위 조사 결과로 원래 사건의 판정을 바꾸지 않는다**. 명세는 `docs/related-sites.md`.

- 후보: 조사 중 거친 경유 도메인과 관찰한 화면의 모든 링크(관찰당 200개, 사건당 100개, 판단 모델에는 보내지 않음). 앵커 글자는 개인정보를 가린 뒤 80자. 공식 브랜드·사행사업자 도메인과 흔한 대형 사이트(평가에서 하위 조사 결과가 정상이었던 것)는 뺀다. 단축 서비스·사이트 빌더의 홈은 첫 화면만 뺀다(같은 도메인의 다른 경로는 단축 주소·사용자 페이지일 수 있다).
- 고르는 순서: 경유 도메인 → 위협 단서(판단 규칙에 이미 있는 단어)가 있는 링크 → 조사한 사이트와 이름 조각을 나눠 갖는 도메인 → 나머지. 원래 주소가 확신 있는 정상이 아니면 앞의 3곳을 같은 안전 게이트·검문 프록시로 4단계·40초씩 하위 조사한다.
- 회선 차단 추정: 하위 조사에서 회선이 도메인 이름을 보고 막은 것으로 보이는 후보(warning.or.kr·이름 기준 연결 리셋)는 '회선 차단 추정'으로 표시한다. 조사 대상 서버가 같은 동작을 흉내 낼 수 있어 확정으로 적지 않는다.
- 결제·다운로드·로그인처럼 클릭 후보에서 막는 링크는 연관 후보로도 고르지 않는다(하위 조사가 그 주소를 열면 클릭 금지를 우회하게 된다).
- 원래 결과 먼저: 하위 조사 전에 원래 사건의 결과를 먼저 보낸다. 사건은 '연관 사이트 조사 중'으로 보이고 담당자는 이때부터 판정할 수 있다. 판정은 원래 조사의 증거 끝(API 가 이 사건의 서명 서비스 head 까지 서명을 검증한 앞부분)에 묶이고, 원래 결과는 한 번만 받는다. 검토 패키지·보고서는 조사가 끝나 체인이 닫힌 뒤에 내려받는다.
- 새 사건으로 접수: 연관 목록의 [새 사건으로 접수](조사관 이상)는 그 사건의 후보 목록에 정확히 있는 주소만 받아 전체 예산으로 다시 조사하는 사건을 만든다(`POST /api/cases/{id}/related`, 같은 후보는 한 번만, 접수 한도는 일반 신고와 같다). 자식 사건 위에는 부모 사건 링크가 붙는다.
- 자동 연관 사건: 원 사건이 끝나면 API 가 선별 조건(하위 조사에서 원래 사건과 같은 기준으로 위협이거나 평판 위험, 도착지가 단축 서비스 아님, 연관 사건에서 다시 만들지 않음)을 통과한 후보로 새 사건을 만든다. 같은 도착 호스트 7일 중복·부모당 3·대기 10 한도가 있고, 사람 접수 한도와 따로 센다. 설정 `ST_RELATED_AUTO`(끄기), `ST_RELATED_AUTO_PER_CASE`, `ST_RELATED_AUTO_MAX_PENDING`, `ST_RELATED_AUTO_DEDUP_DAYS`. 격리망 안의 워커에는 사건을 만드는 경로가 없다.
- 사건 간 연결: 상세의 '연결된 사건' 탭(부모·자식, 같은 사이트가 나온 다른 사건). 사건 여러 개를 모아 보던 분류 폴더 '연관 묶음'(묶음 CSV)은 같은 내용이 사건마다 이 탭에 보여 지웠다(2026-10-25). 단축 서비스·공식 브랜드·흔한 대형 사이트·서비스 홈·위협 화면이 흔히 링크하는 대형 서비스(cloudflare.com·google.com·WhatsApp 등)·피싱 키트가 링크한 진짜 브랜드 사이트로는 잇지 않고, 공용 호스팅(pages.dev·workers.dev 등)은 호스트가 정확히 같을 때만 잇는다. AI 가 정상으로 본 사건은 잇지 않고, 페이지 링크는 하위 조사로 위험하다고 확인한 것만, 최종 주소는 신고 주소와 같은 사이트(또는 신고 주소가 단축 서비스)일 때만 잇는다. 기존 사건은 `docker compose exec api python -m safetrace.related backfill` 로 채운다.
- 조사 컨테이너 늘리기: `docker compose --profile demo up -d --scale agent=2`. 워커는 한 번에 1건씩 가져가고(컨테이너마다 다른 소비자 이름) 증거·실시간 화면은 사건 id 별이라 섞이지 않는다. 컨테이너당 CPU 2·메모리 2GB 제한이므로 그만큼 남는 장비에서 쓴다. 품질 평가를 돌릴 때는 1개로 줄인다(같은 호스트 CPU 를 나눠 숫자가 흔들린다).

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

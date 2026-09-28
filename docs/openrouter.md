# OpenRouter 경유 Jev (예비 경로)

판단 서비스는 `ST_DECIDER_CHAIN` 순서대로 시도한다. 기본값 `["jev_typesafe","jev_openrouter","rules"]`:
TypeSafe 직접 호출이 실패(키 없음·장애·429 등)하면 OpenRouter 경유 Jev, 그것도 실패하면 규칙 기반 판단기로 넘어간다.
OpenRouter 는 TypeSafe 장애·요청 한도에 대비한 **같은 모델의 두 번째 출구**다.

| 항목 | 값 (2026-09-28 확인) |
|---|---|
| 주소 | `POST https://openrouter.ai/api/v1/systemone` (요청·응답 형식은 TypeSafe 와 같음) |
| 모델 ID | `typesafe/jev-1.13` (`ST_OPENROUTER_JEV_MODEL`, 공개 모델 목록에는 안 보이지만 호출 가능) |
| 가격 | 입력 100만 토큰당 $0.042, 출력 무료 (TypeSafe 직접과 같음) |
| 문맥 길이 | 32k 토큰 |

## 1. 키 발급

1. https://openrouter.ai 에 가입·로그인
2. **Credits** 에서 크레딧을 충전한다(유료 모델이라 잔액이 없으면 호출이 실패한다). Jev 는 매우 싸서 소액이면 대회 기간 충분하다.
3. **Settings → Keys**(https://openrouter.ai/settings/keys) → **Create Key**
   - 이름: `safetrace-dev` 등
   - **Credit limit** 을 걸어 둔다(예: $5). 키가 새어도 피해가 한정된다.
4. 만든 키(`sk-or-v1-…`)는 한 번만 보이므로 바로 복사한다.

## 2. 적용

| 환경 | 넣을 곳 | 반영 |
|---|---|---|
| Docker | 루트 `.env` 의 `ST_OPENROUTER_API_KEY=` | `docker compose up -d decision` (키는 판단 서비스에만 전달됨) |
| 로컬 개발·점검 | `backend/.env` 에 같은 줄 | 바로 반영 |

두 `.env` 모두 `.gitignore` 대상이다. 키를 채팅·이슈·커밋에 붙이지 않는다.

## 3. 확인

```bash
cd backend
python ../tools/jev_smoke.py --openrouter
```

`action: click_e0 …`, `threat: illegal_gambling …` 가 나오면 성공.

전체 경로에서 예비 경로로 넘어가는지 보려면 루트 `.env` 에서 잠시
`ST_DECIDER_CHAIN=["jev_openrouter","rules"]` 로 바꾸고 `docker compose up -d decision` 후 조사를 1건 돌린다.
사건의 판단 기록에 `provider: jev_openrouter` 가 찍히면 된다. 확인 뒤 원래 순서로 되돌린다.

## 문제 해결

| 증상 | 원인·조치 |
|---|---|
| `http 401` | 키 오타·삭제된 키 |
| `http 402` | 크레딧 부족 → 충전 또는 키의 Credit limit 확인 |
| `http 404` (No endpoints found …) | 모델 ID 오타, 또는 OpenRouter **Settings → Privacy** 설정이 TypeSafe 공급자를 막음 |
| `http 429` | 요청 한도 초과. 판단 서비스는 다음 공급자(rules)로 넘어간다 |

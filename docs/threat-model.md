# SafeTrace 위협 모델 (STRIDE)

원칙: **페이지에서 온 모든 값과 AI의 답은 믿지 않는다.** 신뢰 경계마다 코드로 강제하는 통제를 둔다.

## 신뢰 경계

```
[담당자 브라우저] ──(로그인 세션, CSP)── [web/nginx] ── [api] ── [db]
                                                        │
                                                    [redis] (작업·이벤트)
                                                        │
      sandbox(internal) ───────────────────────────── [agent] ──HTTP── [decision] ──> Jev API
                                                        │
                                                    [egress] ──> 인터넷(조사 대상)
```

| 경계 | 넘어오는 것 | 기본 가정 |
|---|---|---|
| 조사 대상 페이지 → 에이전트 | DOM, 텍스트, 리다이렉트, 대화상자, 새 창 | 적대적 |
| 에이전트 → 판단 서비스 → Jev | 마스킹한 텍스트 상태 | 외부 전송(최소화) |
| Jev → 판단 서비스 → 에이전트 | 선택지·확률 | 신뢰하지 않음(스키마 검증) |
| 에이전트 → API | 이벤트(진행 상황) | 워커 침해 가능성 고려 |
| 담당자 → API | 접수 URL, 조회 | 인증·인가 필요 |

## STRIDE

| 분류 | 위협 | 통제(코드 위치) | 시험 |
|---|---|---|---|
| **S** 위장 | 토큰 없이 API 호출, 판단 서비스 사칭 | 담당자 로그인 세션(서버 측, DB 에는 SHA-256 만, 30분 무사용·12시간 만료), 자동화 토큰(해시 비교, 상수 시간), 판단 서비스 내부 토큰(`decision/service.py`) | `test_auth_required`, `test_login_me_logout`, `test_idle_and_absolute_expiry` |
| **S** 위장 | 비밀번호 추측·DB 유출 뒤 해시 크래킹, 계정 존재 여부 탐색 | Argon2id(m=64MiB, t=3, p=4), 12자 이상, 5회 실패 시 15분 잠금, 없는 계정도 같은 응답·같은 해시 계산(`accounts.py`) | `test_failed_login_same_answer_and_lockout`, `test_stored_as_argon2id_and_token_hash_only` |
| **T** 변조 | 증거 파일·기록 수정, 내부자가 해시까지 다시 계산 | 해시 체인 + 분리된 키의 HMAC, DB의 head 와 대조(`evidence.py`) | `test_evidence.py` 전체 |
| **T** 변조 | 관찰 뒤 요소를 결제 버튼으로 바꿔치기 | 클릭 직전 재조회·지문 비교·재분류(`gate.check_click`) | `test_swap_after_observe_blocked` |
| **R** 부인 | 누가 언제 접수·검증·로그인했는지 불명확 | 개인 계정 + 감사 로그(`store.AuditLog`: 로그인 성공·실패 이유, 계정 변경), 증거에 시각·모델 버전 기록 | `test_audit_log` |
| **I** 정보 노출 | Jev로 개인정보·원본 화면 전송 | 스크린샷은 내부 보관, 텍스트만 전송, 전송 직전 마스킹(`state_for_jev`) | `test_jev_request_format_and_parse` |
| **I** 정보 노출 | 조사 기관 IP 노출 | egress 출구 IP 를 기관망과 분리(배포 설정) | — |
| **I** 정보 노출 | 오류 메시지로 내부 정보 노출 | 일반화 오류 응답, 로그의 비밀값 마스킹(`mask_secrets`) | — |
| **I** 정보 노출 | 증거 파일 경로 조작 | 파일명 허용 목록 정규식, 사건 ID 형식 검사 | `test_unsafe_file_names_rejected`, `..%2F` 404 |
| **D** 서비스 거부 | 로그인 폭주로 Argon2id 메모리 고갈 | 비밀번호 길이 128자 제한, 해시 계산 동시 4개 제한(`accounts._hash_slots`) | — |
| **D** 서비스 거부 | 무한 루프, 거대 DOM, 대화상자 폭탄 | 단계·시간·동일 상태 예산, 후보 50개 제한, 대화상자 자동 닫기, 컨테이너 자원 한도 | A4·A5·A8 시험 |
| **E** 권한 상승 | 프롬프트 인젝션으로 입력·결제·내부망 이동 | 닫힌 선택지(텍스트 입력 기능 없음), 금지 요소 제외, 안전 게이트, 판정은 담당자만 | A1 시험 |
| **E** 권한 상승 | 낮은 역할로 접수·계정 관리, 자동화 토큰으로 계정 조작 | 서버 측 역할 검사(`need`), 계정 관리는 사람 관리자만(`human=True`), 역할 변경·비활성화 즉시 세션 폐기, 자기 관리자 권한 해제 금지 | `test_rbac`, `test_inactive_and_role_change_revoke_sessions` |
| **E** 권한 상승 | SSRF / DNS Rebinding | 이동 전 IP 확인 + 모든 요청 가로채기(1차), 접속 시점 재해석한 IP 로 연결하는 egress(2차), sandbox 는 internal 네트워크 | `test_netguard.py`, `test_egress_proxy.py` |
| **E** 권한 상승 | 워커 침해 시 DB·키 탈취 | 워커에는 DB 접속 정보·Jev 키 없음, `cap_drop: ALL`, 비 root | compose 설정 |

## AI 관련 잔여 위험

- Jev 연동 문서도 입력에 숨긴 조작 문구에 판단이 흔들릴 수 있다고 밝힌다. 그래서 Jev 의 답은 **행동 범위를 좁히는 데**만 쓰고, 실제 실행 여부는 게이트가, 최종 판정은 담당자가 정한다.
- 행동 확률이 기준(기본 0.45) 미만이거나 판단 서비스가 실패하면 조사를 멈추고 `REVIEW_REQUIRED` 로 넘긴다.
- 위협 유형 확률이 기준(기본 0.6) 미만이면 `hold` 로 표시한다. AI 는 판정을 확정할 수 없다.

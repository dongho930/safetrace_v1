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
| **T** 변조 | 담당자 판정을 덮어쓰기, 두 담당자가 동시에 저장해 한쪽 판정이 사라짐 | 판정은 고치지 않고 판(rev)을 쌓음, 보고 있던 판 번호를 보내 어긋나면 409, `(case_id, rev)` 유일 제약(`verdicts.py`) | `test_revisions_and_optimistic_lock`, `test_concurrent_save_same_rev_only_one_wins` |
| **T** 변조 | 관찰 뒤 요소를 결제 버튼으로 바꿔치기 | 클릭 직전 재조회·지문 비교·재분류(`gate.check_click`) | `test_swap_after_observe_blocked` |
| **R** 부인 | 누가 언제 접수·검증·로그인했는지 불명확 | 개인 계정 + 감사 로그(`store.AuditLog`: 로그인 성공·실패 이유, 계정 변경), 증거에 시각·모델 버전 기록 | `test_audit_log` |
| **R** 부인 | 누가 어떤 증거를 보고 판정했는지, 누가 패키지를 내보냈는지 불명확 | 판정에 담당자·시각·당시 AI 의견·증거 head 저장, 감사 로그 `verdict.save`·`verdict.conflict`·`package.export` | `test_reviewer_saves_and_case_shows_verdict`, `test_zip_can_be_verified_by_receiver` |
| **I** 정보 노출 | Jev로 개인정보·원본 화면 전송 | 스크린샷은 내부 보관, 텍스트만 전송, 전송 직전 마스킹(`state_for_jev`) | `test_jev_request_format_and_parse` |
| **I** 정보 노출 | 조사 기관 IP 노출 | egress 출구 IP 를 기관망과 분리(배포 설정) | — |
| **I** 정보 노출 | 오류 메시지로 내부 정보 노출 | 일반화 오류 응답, 로그의 비밀값 마스킹(`mask_secrets`) | — |
| **I** 정보 노출 | 증거 파일 경로 조작 | 파일명 허용 목록 정규식, 사건 ID 형식 검사 | `test_unsafe_file_names_rejected`, `..%2F` 404 |
| **I** 정보 노출 | 워커가 침해돼 체인에 경로 이동 파일명(`../..`)을 넣고, API 가 증거 폴더 밖 파일을 검토 패키지에 담음 | 패키지·ZIP 은 파일명 허용 목록에 맞고 `files/` 안으로 풀리는 파일만 담음, 이상한 이름은 검증 실패로 표시(`package.py`) | `test_unsafe_file_names_from_chain_are_not_exported` |
| **I** 정보 노출 | 검토 패키지(원본 화면·본문 발췌)가 밖으로 나감 | 내려받기는 조사관 이상 + 감사 로그, 외부 기관 자동 전송 없음, AI 판단은 '법적 판단 아님' 표시 | `test_package_permissions_and_state` |
| **D** 서비스 거부 | 로그인 폭주로 Argon2id 메모리 고갈 | 비밀번호 길이 128자 제한, 해시 계산 동시 4개 제한(`accounts._hash_slots`) | — |
| **D** 서비스 거부 | 무한 루프, 거대 DOM, 대화상자 폭탄 | 단계·시간·동일 상태 예산, 후보 50개 제한, 대화상자 자동 닫기, 컨테이너 자원 한도 | A4·A5·A8 시험 |
| **E** 권한 상승 | 프롬프트 인젝션으로 입력·결제·내부망 이동 | 닫힌 선택지(텍스트 입력 기능 없음), 금지 요소 제외, 안전 게이트, 판정은 담당자만 | A1 시험 |
| **E** 권한 상승 | 낮은 역할로 접수·계정 관리, 자동화 토큰으로 계정 조작 | 서버 측 역할 검사(`need`), 계정 관리는 사람 관리자만(`human=True`), 역할 변경·비활성화 즉시 세션 폐기, 자기 관리자 권한 해제 금지 | `test_rbac`, `test_inactive_and_role_change_revoke_sessions` |
| **E** 권한 상승 | SSRF / DNS Rebinding | 이동 전 IP 확인 + 모든 요청 가로채기(1차), 접속 시점 재해석한 IP 로 연결하는 egress(2차), sandbox 는 internal 네트워크 | `test_netguard.py`, `test_egress_proxy.py` |
| **E** 권한 상승 | AI·자동화 토큰이 판정을 확정 | 판정 저장은 검토관 이상 + 사람 계정만(`need("reviewer", human=True)`), 관리자 역할 자동화 토큰도 403 | `test_only_human_reviewers_can_decide` |
| **E** 권한 상승 | 워커 침해 시 DB·키 탈취 | 워커에는 DB 접속 정보·Jev 키 없음, `cap_drop: ALL`, 비 root. **증거 서명 키는 워커에 있다**(워커가 서명). 워커가 뚫리면 그 뒤 기록은 위조 서명될 수 있으나 DB 의 head 와 이미 내보낸 패키지로 이전 기록은 대조 가능. 서명 서비스 분리는 남은 과제 | compose 설정 |

## AI 관련 잔여 위험

- Jev 연동 문서도 입력에 숨긴 조작 문구에 판단이 흔들릴 수 있다고 밝힌다. 그래서 Jev 의 답은 **행동 범위를 좁히는 데**만 쓰고, 실제 실행 여부는 게이트가, 최종 판정은 담당자가 정한다.
- 행동 확률이 기준(기본 0.45) 미만이거나 판단 서비스가 실패하면 조사를 멈추고 `REVIEW_REQUIRED` 로 넘긴다.
- 위협 유형 확률이 기준(기본 0.6) 미만이면 `hold` 로 표시한다. AI 는 판정을 확정할 수 없다.

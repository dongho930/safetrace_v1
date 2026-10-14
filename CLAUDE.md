# SafeTrace — Claude Code 작업 안내

프로젝트 개요·구성·실행 방법은 `README.md`에 있다. 이 파일은 어느 PC에서든 새 세션이 작업을 이어 가기 위한 인수인계다.

## 작업 방식

- 한국어로 답한다.
- 사용자가 "먼저 알려줘"라고 하면 선택지와 장단점만 설명하고 기다린다. 그렇지 않으면 구현 → 측정 → 커밋 → PR까지 한 번에 한다.
- 개선은 **측정한 숫자(전/후)** 로 보여 준다. PR 설명에도 평가 결과를 넣는다. 측정 범위(남은 기간이 짧아 비용을 맞춘다):
  - 탐색·판단 동작이 바뀌는 PR: 49개 목록 3회 평가(`tools/eval_agent.py`, 전/후 각 1시간 남짓). 바뀐 부분이 한 그룹에 한정되면 `--group` 으로 줄여도 된다.
  - 그 밖의 기능(보고서·화면·API 등): 시험 + 실제 스택 1건 확인과 걸린 시간.
- 브랜치는 `main`에서 새로 따서 PR을 올린다. 머지는 사용자가 한다. **PR을 쌓지 않는다**(stacked PR이 엉뚱한 base에 머지된 적이 있다). 꼭 이어야 하면 머지 전에 base를 바꾸라고 알린다.
- 원격 브랜치 삭제처럼 자동 모드에서 막히는 명령은 사용자가 `! git ...`로 직접 실행하도록 안내한다.
- 개발 PC는 배포 대상이 아니다. 성능은 PC 사양 말고 Docker 제한(에이전트 CPU 2 / 메모리 2GB) 안에서 잰다.
- Windows에서 Git Bash PATH에 `gh`가 없으면 `"C:/Program Files/GitHub CLI/gh.exe"`를 쓴다.
- **Codex 보안 검토**(`docs/codex-review.md`): 코드를 바꾼 PR 은 커밋 뒤 `tools/codex_review.sh` 로 검토한다. 지적마다 실패하는 시험으로 재현해 정탐/오탐을 가리고, 정탐만 고친다. 코드 PR 마다 1회 돌리고, 2회째는 정탐을 고친 경우에만 돌린다(최대 2회). 작업 트리를 다른 브랜치로 바꿔 쓰는 중이면 범위를 `tools/codex_review.sh origin/main <브랜치>` 처럼 명시한다(작업 트리가 main 일 때 돌려 빈 범위를 검토한 적이 있다). PR 설명에 `Codex 보안 검토` 절(발견 건수·판정·조치)을 넣는다. 기준은 `tools/codex-review/prompt.md` 이고, 원본 KISA 자료와 기준서 Word 본은 `kisa 가이드 자료/`(gitignore)에 있다.

- **작성 단계의 KISA 기준**: 보안에 닿는 코드(외부 입력·URL·파일·인증·인가·증거·외부 호출·에이전트 행동)를 쓰기 전에 `tools/codex-review/prompt.md` 의 해당 기준(3.2 구현 보안약점, 3.5 불변식, 3.6 Python 점검)을 확인하고, 커밋 전에 스스로 대조한다. Codex 검토는 그다음 사후 확인이다. 원문은 `kisa 가이드 자료/`(git 밖)에 있다.
- **기획서 업데이트 문서**(`docs/plan-updates.md`): PR 마다 해당하면 한 줄씩 보탠다. 1절 보안 구조 설계(구조로 막은 것, 기획서 2장 → 보안 평가 3순위·3라운드 가점), 2절 기획서와 달라진 점, 3절 측정한 숫자.
- **약점 밀도**: CI backend 작업의 요약(Summary)에 `tools/weakness_density.py` 결과(bandit 전체 등급, 1,000줄당)가 나온다. 실패시키지는 않으니 PR 마다 서비스 코드 숫자가 늘었는지 본다.

## 2라운드 평가와 일정 (2026-10-11 사전교육·사용자 결정)

- 제출 6종: 시연영상, 개발기획서 업데이트본, 결과보고 발표자료(슬라이드 노트에 대본, ppt+pdf), 서비스 개요서, 소스코드, 시연물 포스터(양식 추후 안내). 공식 마감 10/30 18시, 대회 중 공지되는 미션 포함.
- 개발 60%(창의성·적용성·완성도), 보안 40%. 보안 순위: ① 빌드 라인당 보안약점 수(주석 포함, 빈 줄은 문의 중) ② 평가위원 진단 결과 대비 조치율 ③ 구조적 설계(기획서 2장). 평가위원 진단 11/2~11/4.
- 팀 일정: **코드 동결 10/24, 제출 10/26**. 제출 범위(시험 코드·도구 포함 여부)·압축 스크립트·자체 진단은 동결 뒤 정한다(디스코드 문의 중, 답이 오면 사용자가 알려 줌).

## 새 PC 준비 (git에 없는 것)

- `.env`(Compose용, `.env.example` 참고), `backend/.env`(로컬 개발용, README 참고): 비밀값이다. 안전한 경로로 옮기고 커밋하지 않는다.
- `models/korean_PP-OCRv5_rec_mobile.onnx`: `python tools/fetch_ocr_model.py`로 받는다(`docs/ocr.md`).
- `var/eval/`: 평가 결과(gitignore). **PC나 네트워크가 바뀌면 개선 전에 그 환경에서 baseline을 다시 잰다.** 하드웨어와 접속 IP가 다르면 숫자가 달라진다(예: 쿠팡은 원래 개발 PC의 IP를 봇으로 차단한다).

## 품질 평가 도구

```bash
docker compose --profile demo up -d
python tools/eval_agent.py run --repeat 3 --label 메모     # 에이전트 컨테이너 안에서 실행 → var/eval/<시각>_<메모>.jsonl·.md
python tools/eval_agent.py compare var/eval/A.jsonl var/eval/B.jsonl
```

- `data/eval_set.csv`: 55개 URL = 시험 페이지 11 · 정상 사이트 16 · KISA 실제 신고 URL 28(2024-12 자료 11 + 2023 자료 10(#24) + 2024 자료 7(`feat/more-real-sites`: 중국 도박 복제 2, 단축·호스팅 서비스의 차단 화면 5)). 예전 문서의 '49개'는 실제로 48개였다.
- KISA 원본은 공공데이터포털 `한국인터넷진흥원_피싱사이트_20241231`(131,752개, 연 1회 갱신, 로그인 없이 내려받음, git 밖 `var/sources/`). 대부분 이미 사라졌으니, 보탤 때는 `python tools/probe_urls.py 후보.txt --out var/probe/이름.jsonl`(에이전트 컨테이너 안에서 검문 프록시를 거쳐 GET만)로 살아 있는지 먼저 확인하고 정답을 정할 수 있는 것만 넣는다. 2024 자료 직접 도메인 5,919개 중 내용 있는 응답은 106개였고 대부분 정상·주차·청첩장·부고장 페이지로 바뀌어 정답을 정할 수 없었다.
- **오늘의 실사이트 세트**(고정 세트와 따로): OpenPhish 무료 피드(`https://openphish.com/feed.txt` → GitHub, 6~12시간 갱신)를 받아 `probe_urls.py` 로 확인하고, 브랜드 사칭·입력 화면이 확인된 것만 `var/fresh/<출처>_<날짜>.csv`(그룹 `fresh`, 정답 `malicious`)에 넣어 **같은 날** `--set` 으로 3회 평가한다. 봇 확인 화면·학생용 클론·내용 불명은 뺀다. 며칠이면 사라져 날을 달리한 비교에는 쓰지 않고, 공개 저장소에 살아 있는 피싱 주소를 올리지 않으려고 목록은 git 밖에 둔다.
- 평가가 도는 동안 콘솔에 사건을 넣지 않는다. 에이전트 컨테이너의 CPU 2개를 나눠 써서 시간 초과가 난다.
- 메모리가 적은 PC에서는 백그라운드 평가 프로세스가 죽을 수 있다. 컨테이너 안 프로세스는 계속 돌므로 결과는 컨테이너의 `/tmp/eval/out.jsonl`에서 회수한다.
- `testpages/server.py`를 고치면 `testpages` 컨테이너를 재시작한다.

## 현재 품질 (2026-10-14, 반복 3회, main f961260, 55개 목록, 두 번째 PC·SK브로드밴드 회선)

| 그룹 | 정답률 | 비고 |
|---|---|---|
| 시험 페이지 | 100% (33/33) | |
| 정상 사이트 | 96% (46/48) | 오탐 0. 판단 불가 2는 홈택스(자체 오류 페이지 `cmErrorPage.html`, 회차마다 달라짐) |
| KISA | 48% (40/84) | 판단 불가 35, 놓침 9, 유형 틀림 0. 기존 21개 34/63(이전 기준선 35/63), 새 도박 복제 2개 6/6, **새 서비스 차단 화면 5개 0/15**(xzx.kr·5du.pl·creatorlink 는 3회 모두 정상으로 판단해 담당자 검토 없이 끝남, tinyurl·tny.kr 은 판단 불가) |
| 오늘의 실사이트(OpenPhish 2026-10-14, 31개) | 92% (83/90) | 제외 3(가짜 Adobe 설치 페이지 접속 불가), 놓침 7 은 모두 담당자 검토로 감(Meta 비즈니스 '페이지 이의제기' 사칭 pages.dev 5, iCloud 사칭 2), 유형 틀림 0. 한국 대상 Naver 사칭 2개·dothome Microsoft 사칭 모두 3/3 |

`var/eval/20261014-0932_set55_baseline`, `var/eval/20261014-0911_fresh_openphish`(목록 `var/fresh/openphish_20261014.csv`). 이전 기준선(48개 목록) `20261011-2322_candidates`: 정상 47/48, KISA 38/62.
흐름: 38개 목록 main 624c752 KISA 40% → #17 57% → #18 67% → #20 74%. 49개 목록 22/45(채점 제외 18) → #27 32/63 → 자동 이동 기다리기 33/63.

KISA 남은 오답:
- **단축·호스팅 서비스의 차단 화면을 정상으로 봄**(2026-10-14 새 표본): MU-star(xzx.kr·muz.so) "URL Access Suspended … due to illegal or harmful contents", SDU(5du.pl) "Link zablokovaný", 크리에이터링크 "불법 / 유해 사이트 접속 차단 안내", TinyURL "URL Terminated … violation of our Terms of Use", tny.kr "영구정지 되었거나 리디렉트가 차단". 엔진의 단축 서비스 경고 규칙(#20·#26)은 iii.im·Bitly 문구만 안다. 이제 실제로 관찰한 문구라 규칙에 보탤 수 있다(다음 후보).
- **목적지 이름에 근거가 없음**: go9.co/UCi, goo.su/PUPst, c11.kr/187mb, han.gl/ICrVHZ·nYQWfx, lrl.kr/I1IJ·PdZ·fJFX, bit.ly/1TV4K. 목적지가 이미 사라졌고 이름(`ven.nibyol.fun`, `mmsk.ppusrio.top`, `sa.boramd.co.kr` 등)에서 브랜드를 알 수 없다. 판단 불가가 맞는 결과일 수 있다. lrl.kr은 이제 대기 화면을 기다려 매번 목적지까지 가지만 이름에 근거가 없다.
- **mi-telegram.com**: SK브로드밴드가 SNI/Host를 보고 연결을 리셋한다(방심위 차단 방식). #21이 감지해 담당자 검토로 보내지만 유형이 없어 판단 불가로 세진다. 접속되는 회차에는 화면이 `OK`뿐이고, #22가 피싱(보류)으로 본다.

## 진행 단계

- 품질 개선은 #29로 마쳤다(사용자 결정, 2026-10-04).
- 사전준비 최종 점검 완료(2026-10-04): `docs/prep-checklist.md` 14절. 점검 중 끊긴 조사가 '조사 중'에 멈추는 문제를 고쳤다(워커가 끝나지 않은 작업을 FAILED로 마무리).
- 본선 1주차 ① 계정·권한 완료(#31, 2026-10-08): Argon2id 담당자 계정, 서버 측 세션(DB엔 SHA-256), 5회 실패 15분 잠금, 역할 viewer<investigator<reviewer<admin, 계정 관리는 사람 관리자만(`ST_API_TOKENS`는 자동화 전용). 코드는 `backend/safetrace/accounts.py`, 시험 `tests/test_accounts.py`. 첫 관리자는 `docker compose exec api python -m safetrace.accounts add <아이디> --role admin`(`!`로 실행할 땐 `--password-stdin`). 두 번째 PC 로컬 DB에는 관리자 `dongho`가 있고 시험 계정 `qa.*`는 꺼 두었다.
- 본선 1주차 ② 담당자 판정 저장(`feat/week1-verdict`, 2026-10-10): `verdicts` 테이블에 판(rev)을 쌓고 (case_id, rev) 유일 제약으로 낙관적 잠금(보고 있던 판 번호를 보내고, 어긋나면 409). 검토관 이상 사람 계정만, 조사 끝난 사건만. 판정에 당시 AI 의견·증거 head 를 묶는다. 콘솔 판정 패널(유형 선택·메모·기록), 대기열 '검토 필요'는 확정된 사건을 뺀다(보류는 남김). 코드 `backend/safetrace/verdicts.py`, 시험 `tests/test_verdicts.py`. 두 번째 PC 로컬 DB의 시험 계정 `qa.rev1`·`qa.rev2`는 꺼 두었다.
- 본선 1주차 ③ 검토 패키지(`feat/week1-package`, 2026-10-10): `backend/safetrace/package.py`가 서명된 체인을 단계별(관찰→Jev 선택→게이트→실행·전후 화면)로 묶고, 판단 결과는 체인의 threat 기록(override 포함)을 쓴다. 만들 때마다 무결성을 다시 검증해 넣는다(실패해도 숨기지 않음). ZIP은 받은 쪽이 README 방법만으로 체인·파일을 재계산할 수 있음을 시험으로 고정(`tests/test_package.py`). 콘솔 '외부 평판·증거' 카드에 ZIP 내려받기. 실제 스택에서 smish 1건 탐색→판단→판정→패키지 확인(JSON 13ms, ZIP 25ms·1.3MB).
- 1주차 범위(계정·RBAC, 판정 저장·화면, 검토 패키지) 완료. 최종 점검(2026-10-10): `docs/week1-checklist.md` — 실제 스택 21/21, 시험 259, 점검 중 패키지가 체인 파일명을 검사하지 않던 문제(워커 침해 시 증거 폴더 밖 파일 반출) 수정. 남은 과제(서명 키가 워커에 있음, IP 기준 로그인 제한 없음 등)는 점검표 6절. 다음: 2주차 연관 후보 큐(발견 링크 후보 기록·한도 준수), Safe Browsing 결과 통합. 보고서 초안(PDF)은 3주차.
- 2주차 순서(사용자 결정, 2026-10-11): ① 서명 서비스 분리 → ② 연관 후보 큐. 후보 큐는 경유 도메인 + 페이지 외부 링크, **1단계 자동 조사**(기획서는 '담당자 요청 시'라 다름), Safe Browsing 은 후보도 조회하고 일치하면 AI '정상'을 보류로. 기획서와 달라진 점은 `docs/plan-updates.md`에 적는다.
- 2주차 ① 서명 서비스 분리(`feat/signer-service`, 2026-10-11): `backend/safetrace/signer/`. 증거 서명 키는 `signer`(서명)·`api`(검증)만 갖고 에이전트에는 없다. 에이전트는 기록 내용만 보내고 seq·ts·prev 는 서명 서비스가 정한다. API 가 접수 때 체인을 열고 조사가 끝나면 닫으며, DB head 는 서명 서비스 값을 쓴다(어긋나면 감사 로그 `evidence.head_mismatch`). 새 비밀값 `ST_SIGNER_AGENT_TOKEN`·`ST_SIGNER_API_TOKEN`(두 PC 의 `.env` 에 넣어 둠, 다른 PC 는 직접 추가). 기록 1건 서명 6ms(로컬 0.1ms), smish 조사 시간 31.9초 → 31.9초. #37 병합 뒤 1주차 재점검 21/21(`docs/week1-checklist.md` 7절).
- Codex 시범 검토(#37) 정탐 3건 수정(`fix/codex-pilot-findings`, 2026-10-11): 워커 head 를 상태 이벤트에서 받지 않고 상태 전이 검사(F1), 닫기 실패 시 검증 `head_unknown`·나중에 다시 닫아 복구(F2), signer 본문을 받으면서 1MiB 초과 시 413·동시 연결 32·메모리 256MB(F3). 실제 스택에서 세 공격 모두 전에는 통하고 후에는 막힘, smish 31.6초 → 31.6초. Codex 보안 기준에 Python 시큐어코딩 가이드(2023)를 넣은 것은 #40.
- 2라운드 작업 흐름 정리(`chore/round2-workflow`, 2026-10-11): `docs/plan-updates.md` 시작, CI 약점 밀도 보고, 측정·Codex 검토 범위 조정.
- 2주차 ② 연관 후보 하위 조사(`feat/candidate-subinvestigation`, 2026-10-12, 사용자 결정: 원 사건 안의 하위 조사): `agent/candidates.py` 가 경유 도메인·외부 링크를 고르고(기록 20), 원래 주소가 확신 있는 정상이 아니면 `runner` 가 후보 최대 3개를 새 브라우저에서 4단계·40초로 조사한다. 같은 체인에 `data.sub` 를 붙이고 파일은 `c<번호>_` 로 시작한다. Safe Browsing 은 후보도 조회하고 AI 정상 + 일치면 보류(`reputation_match`·`candidate_reputation_match`). 패키지 `candidates.investigated`, 콘솔 '연관 후보' 목록. 설정 `candidate_max`·`candidate_max_steps`·`candidate_max_seconds`.
- 3주차 ① 보고서 초안(`feat/week3-report`, 2026-10-12): `backend/safetrace/report.py`. 검토 패키지에서 기관 양식용 요약(JSON `safetrace.report/1`)을 뽑고 reportlab 으로 PDF(대상·개요, 판단 결과·담당자 판정, 탐색 경위, 주요 화면 최대 4장 2열, 연관 사이트, 증거 무결성)를 그린다. API `GET /api/cases/{id}/report.json|pdf`(조사관 이상, 감사로그 `report.export`), 검토 패키지 ZIP 에도 `report.json`·`report.pdf` 포함. 페이지 글자는 이스케이프(마크업의 `<img src>` 로 서버 파일을 읽을 수 있음), 화면 사진은 체인 해시가 맞을 때만. 글꼴은 API 이미지의 `fonts-nanum`(로컬은 맑은 고딕, `ST_REPORT_FONT` 로 바꿀 수 있음). 측정: JSON 13ms, PDF 0.12~0.14초, ZIP 25ms → 0.13~0.16초. Codex 정탐 3건 수정: 체인을 한 번 읽어 검증한 그 내용으로 만들기(High, 패키지에도 있던 문제), ZIP 서명을 SHA256SUMS 까지(`package.verify_zip`, 서명 형식 `safetrace.package-sig/2`), 서명된 기록도 자료형 검사(`package.clean_records`, `integrity.malformed`)·보고서 실패해도 ZIP 은 나감. 2회차 정탐 2건 수정: ZIP 의 증거 파일도 한 번 읽은 바이트를 체인 해시와 대조해 담고(바뀌었으면 빼고 검증 실패로 적음, `verify_zip` 도 체인 해시와 대조), 확률은 0~1 유한수만. 로컬 사건 113건 전부 보고서 생성 성공(중앙값 0.12초), 자료형 검사 오탐 0(기록 4,144건). 로컬 측정은 `localhost` 대신 `127.0.0.1`(Windows 에서 이름 해석이 200ms 더해진다).
- 3주차 ② 공격 시나리오 15종(`feat/week3-attack-scenarios`, 2026-10-12): `docs/attack-scenarios.md`, `python tools/attack_suite.py run --repeat 3`(실제 스택, 결과 `var/attack/`). 새 시험 페이지 `attack/judge-injection·redirect-link·bomb·cpu.html`, 시험 서버 `/__hits`(금지 도달 기록)·`/attack/r/*`(302 내부망). 처음 11/15 — 무한 스크립트(`cpu.html`)에서 사건이 '조사 중'에 멈추고 대기열이 막힘(A03). 탐색 전체 강제 기한(예산 + 15초, `page_unresponsive`)과 정리 작업 제한으로 고쳐 3회 45/45(최종 `var/attack/20261013-0021_final3`). Codex 지적으로 판정 강화(공격 페이지에 접속 못 한 사건은 차단으로 안 셈), 시험 서버 기록은 읽기 전용(`/__hits?since=`), 녹화 정리 취소 시 ffmpeg 회수. 시연 장면 후보 5개는 문서 끝.
- 시연 영상(장면 선택·대본)은 미룬다(사용자 결정 10/13). 장면 후보는 `docs/attack-scenarios.md` 끝.
- 3주차 최종 점검(10/13): `docs/week3-checklist.md` — `python tools/live_check.py --attacks` 실제 스택 42/42(1·2·3주차 항목, 시험 계정은 무작위 비밀번호로 켰다 끔), 공격 15종 45/45, CI 302 passed. 남은 과제는 점검표 6절(시연 영상, IP 기준 로그인 제한, 접수 건수 제한 없음 등).
- 접속 주소별 로그인 제한·접수 한도(`feat/ip-login-and-intake-limits`, 10/13): 주소별 실패 30회/15분이면 비밀번호 확인 없이 429(`ratelimit.py`), nginx 가 `X-Forwarded-For` 를 덮어쓰고 API 는 `ST_TRUSTED_PROXIES=["web"]` 에서 온 것만 믿음(uvicorn `--no-proxy-headers`). 끝나지 않은(`QUEUED`·`RUNNING`) 사건 주체별 20(429)·전체 200(503). `live_check.py` 46/46. 상세 `docs/week3-checklist.md` 7절.
- 콘솔 개편(`docs/console-redesign.md`, 10/13, 단계마다 PR): 1단계 #49 밝은 업무 화면·Pretendard GOV(번들 포함)·분류 폴더(숫자, 예전 KPI 대신)·목록·상세 틀·판정 막대(상세 아래 고정, [저장하고 다음 사건]). dist 11MB → 6.1MB, CSS 235.6kB → 97.1kB. 2단계 #50 목록 칸 맨 위 실시간 화면 상시 표시(조사 중 사건의 영상·마지막 Jev 선택, 끝나면 다음 사건으로). Codex 지적으로 SSE 이벤트 모양 검사(`cleanEvent`)·자원 상한·칸별 오류 경계. 3단계 #51 AI 요약·근거 카드·근거 화면·경로 지도·조사 경과 탭(`evidence.ts`·`labels.ts`, 서명 기록 값으로만 계산).
- 근거 화면 위 표시(#52, 10/13): 에이전트가 관찰 기록에 요소 상자(`boxes`, 캡처 픽셀)를 남기고 콘솔이 SVG 로 겹친다(금지 요소 빨간 점선, Jev 가 고른 버튼 파랑, 안전 게이트가 막은 클릭 빨간 실선). 좌표는 페이지 JS 가 아니라 브라우저 프로토콜(`bounding_box`·`Page.getLayoutMetrics`)로 재서 페이지가 바꿔치기할 수 없다. 상자 측정 제한 500ms(새 페이지 첫 측정은 스크립트 주입으로 2~3배 느려 150ms 일 때 CI 에서 상자가 가끔 통째로 빠졌다).
- 콘솔 배치(#53~#55, 10/13, 사용자 요청): 목록 칸과 상세를 폴더 뺀 폭의 반씩(1920 기준 860·860), 목록 칸 실시간 화면 16:10(309×200 → 830×518, 창 높이가 모자라면 목록 4줄을 남기고 화면이 줄어듦). 조사 중 상세는 영상 대신 **최근 관찰 화면 + 화면 위 표시**(사용자 결정 C안, 실시간 영상 연결 2 → 1, 고른 버튼으로 자동 스크롤, [크게 보기] → [상세 보기]). 조사 녹화 영상이 칸을 넘쳐 잘리던 것(#51 부터) 수정.
- 콘솔 화면 확인 방법: 실제 스택 콘솔은 사람 계정 비밀번호가 필요해(자동 모드는 계정 켜기·비밀번호 읽기를 막음) 로컬 개발 모드가 빠르다. 임시 sqlite·HMAC 키를 `ST_` 환경 변수로 주고 `python -m safetrace.accounts add qa.dev --role admin --password-stdin`, `testpages/server.py`·`uvicorn`·`npm run dev` 를 띄워 Playwright 로 측정·캡처한다. 녹화 프레임은 Playwright `channel="chromium"` + canvas 로 뽑는다(기본 헤드리스 셸은 영상을 그리지 않아 흰 화면).
- 브랜치 정리(10/13): 원격·로컬 모두 `main` 만 남겼다.
- 스크롤이 잠긴 페이지 캡처(#57, 10/13, 사용자 결정 B안): html 이 스크롤을 막고 body 가 스크롤하는 페이지(중국 도박 복제 사이트)는 페이지 전체 캡처가 첫 화면만 그려졌다. 캡처하는 동안만 html·body 잠금을 풀어 펼치고 그 상태에서 상자를 재고 찍은 뒤 되돌린다(기록 `capture: "expanded"`, 콘솔 표시). kc-telegram 첫 화면 아래 빈 줄 37/37 → 2/37. 한 화면씩 스크롤해 이어 붙이는 C안은 지연 로딩·팝업을 터뜨려 탐색에 영향을 줘서 보류. `test_boxes_match_full_page_capture[900-True]`(#52)가 로컬에서 가끔 실패한다(원인 미확인).
- 실시간 화면·녹화 자연스럽게(`feat/smooth-live`, 10/13): ① 콘솔 실시간 화면 재생 버퍼(0.15초, 받은 간격 평균으로 고르게) ② 멈췄다 바뀌는 프레임 0.15초 겹쳐 바꾸기 ③ 이미지 버튼 OCR 스크롤 동안 실시간 중계만 멈춤(녹화는 증거라 계속, Codex 지적) ④ 클릭 표시: 게이트를 통과한 클릭의 창 기준 상자와 시각을 게이트 기록(`point`·`at`)에, 녹화 0초 시각을 녹화 기록(`t0`)에 남기고, 실시간은 클릭 메시지(`{"click":[...]}`)를 영상과 같은 통로로 보내 같은 재생 버퍼를 탄다(밀려도 프레임만 버림). 녹화 파일에 프레임을 만들어 넣지 않는다(증거). 표시 간격 흔들림 16.5·14.2ms → 9.5·8.9ms, OCR 중 실시간 중계 프레임 59 → 0(녹화는 59 그대로). Codex 지적으로 클릭 좌표 재기(스크롤)를 게이트 검사 앞으로(검사 뒤 스크롤하면 바꿔치기된 결제 링크를 눌렀다), 실시간 메시지는 디코드 전에 개수·크기·JPEG 해상도 상한(콘솔), 크기·초당 개수 상한(API). #52 의 상자 시험이 20회 중 4회 실패하던 것은 스크롤 직후 화면 한 장을 기다리지 않아서였다(0회로).
- 다음 후보: 2라운드 제출물(기획서 업데이트본·발표 자료·서비스 개요서), 시연 영상. 시연 장면 후보는 `docs/attack-scenarios.md` 끝 + 조사 중 상세의 swap.html(왼쪽 실시간 화면엔 바뀐 "결제하기", 상세엔 Jev 가 관찰한 "이벤트 참여 신청"에 게이트 차단 빨간 실선).

## 남은 개선 후보 (품질 개선은 마침, 참고용)

1. t.ly 단축 URL은 Cloudflare 봇 확인 화면에서 멈춘다(2023 자료 185개). 정답을 정할 수 없어 평가 세트에 넣지 않았다.
2. 남은 KISA 오답은 대부분 판단 불가가 맞는 결과다. 품질 개선보다 본선 1주차(Argon2id 계정·권한, 판정 저장, 검토 패키지)로 넘어갈 때다.
3. (2026-10-14) 단축·호스팅 서비스의 차단 화면 문구 5종(위 'KISA 남은 오답')을 엔진의 경고 규칙에 보태면 검토 없이 놓치는 9회를 막을 수 있다. 실사이트 세트에서는 JS 로 그리는 Meta '페이지 이의제기' 사칭(pages.dev)을 정상(보류)으로 봤다.

이미 해 본 것:
- 되돌아가기(backtracking) 탐색은 측정 결과 어떤 표본에서도 이득이 없어 **보류**했다. 다시 꺼내지 않는다.
- 첫 접속: commit까지만 15초 기다리고 domcontentloaded는 따로 기다린다(PR #14/#15). KISA 접속 불가가 2건에서 0건이 됐다.
- 중국어 도박 사이트 유형(PR #17): 해외 도박 브랜드를 붙인 복제 사이트를 도박으로 판단하고, 날짜를 계좌번호로 가리지 않는다. KISA 유형 틀림이 6건에서 0건이 됐다.
- 오류·프록시 거부 화면을 막다른 곳으로 처리(PR #18): 관찰하지 않고 원래 페이지로 돌아가거나 끝낸다. KISA 판단 불가가 13건에서 10건, `loop_detected`가 6회에서 0회가 됐다.
- 단축 서비스 위험 경고(PR #20, Bitly는 #26): "위험해서 자동 이동을 막았다"(iii.im), "potentially harmful"로 차단(Bitly) 화면은 엔진이 피싱(보류)으로 바꾼다. 경고 화면을 통과하지는 않는다(iii.im은 목적지를 fetch POST로 받아 오는데 A7 POST 차단을 유지).
- **판단 문구(`THREAT_QUESTION`·`THREAT_CRITERIA`)를 늘리면 경계에 있는 다른 사이트 판단이 흔들린다**(#20에서 kc-telegram이 도박에서 정상으로 뒤집혔다). 특정 패턴은 문구 대신 엔진의 코드 규칙(override, 원래 판단 보존)으로 처리한다. 지금 규칙: 공식 사행사업자 도메인, 단축 서비스 경고, 브랜드 사칭 도메인(신고·최종 주소는 내용 없을 때, 열리지 않은 목적지는 항상).
- 회선 차단 감지(PR #21): 첫 접속이 연결 끊김이면 진짜 이름과 무관한 이름으로 다시 연결해 보고, 이름만 끊기면 담당자 검토로 보낸다. warning.or.kr도 같다.
- 브랜드 사칭 도메인(PR #22, 목적지는 #27): `decision/brands.py`의 브랜드·공식 도메인 목록. 평가 세트 정상 사이트가 걸리지 않음을 시험으로 고정했다.
- 첫 접속에서 사라진 목적지로 바로 넘김(PR #25): 접속 불가가 아니라 막다른 곳으로 보고 목적지 이름으로 판단한다. KISA 채점 제외가 18에서 0이 됐다.
- 이동 요청 검사 대기(`fix/nav-check-wait`): 주 화면 이동 검사(이름 해석)에 4초 상한(`ssrf:dns_timeout`), 검사 중이면 관찰·종료 전에 기다리고, 판단하는 사이 막다른 곳으로 넘어갔으면 끝내지 않는다. 이름 해석이 느린 CI 에서 브라우저 시험 2개가 가끔 실패하던 원인. lrl.kr/PdZ 정답 0/3 → 2/3.
- 자동 이동 기다리기: 끝내려는 화면에 단축 서비스 대기 문구(goo.su "Redirecting... Please wait", lrl.kr "… 초 후 이동합니다")가 있으면 주소마다 한 번, 최대 10초 기다린다. goo.su/E7i5QDl 정답이 1/3에서 3/3. 대기 화면이 있는 단축 URL만 약 8초 길어진다.
- 경고 감지·사칭 목록은 **실제로 관찰한 문구·도메인만** 넣는다. 지어낸 예문에 맞춰 넓히지 않는다(정상 사이트 오탐 방지).

## 시험

```bash
cd backend && ../.venv/Scripts/python -m pytest -q
```

---
이 파일은 작업 상태가 바뀔 때(PR 머지, 새 baseline, 과제 결정) 함께 갱신한다.

# SafeTrace — Claude Code 작업 안내

프로젝트 개요·구성·실행 방법은 `README.md`에 있다. 이 파일은 어느 PC에서든 새 세션이 작업을 이어 가기 위한 인수인계다.

## 작업 방식

- 한국어로 답한다.
- 사용자가 "먼저 알려줘"라고 하면 선택지와 장단점만 설명하고 기다린다. 그렇지 않으면 구현 → 측정 → 커밋 → PR까지 한 번에 한다.
- 개선은 **측정한 숫자(전/후)** 로 보여 준다. PR 설명에도 평가 결과를 넣는다.
- 브랜치는 `main`에서 새로 따서 PR을 올린다. 머지는 사용자가 한다. **PR을 쌓지 않는다**(stacked PR이 엉뚱한 base에 머지된 적이 있다). 꼭 이어야 하면 머지 전에 base를 바꾸라고 알린다.
- 원격 브랜치 삭제처럼 자동 모드에서 막히는 명령은 사용자가 `! git ...`로 직접 실행하도록 안내한다.
- 개발 PC는 배포 대상이 아니다. 성능은 PC 사양 말고 Docker 제한(에이전트 CPU 2 / 메모리 2GB) 안에서 잰다.
- Windows에서 Git Bash PATH에 `gh`가 없으면 `"C:/Program Files/GitHub CLI/gh.exe"`를 쓴다.

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

- `data/eval_set.csv`: 38개 URL = 시험 페이지 11 · 정상 사이트 16 · KISA 실제 신고 URL 11.
- 평가가 도는 동안 콘솔에 사건을 넣지 않는다. 에이전트 컨테이너의 CPU 2개를 나눠 써서 시간 초과가 난다.
- 메모리가 적은 PC에서는 백그라운드 평가 프로세스가 죽을 수 있다. 컨테이너 안 프로세스는 계속 돌므로 결과는 컨테이너의 `/tmp/eval/out.jsonl`에서 회수한다.
- `testpages/server.py`를 고치면 `testpages` 컨테이너를 재시작한다.

## 현재 품질 (2026-10-03, 반복 3회, main 77285d2, 두 번째 PC·SK브로드밴드 회선)

| 그룹 | 정답률 | 비고 |
|---|---|---|
| 시험 페이지 | 100% (33/33) | |
| 정상 사이트 | 98% (47/48) | 오탐 0. 1건은 홈택스가 자체 오류 페이지(`cmErrorPage.html`)로 끝나는 사이트 쪽 상태 |
| KISA | 67% (20/30) | 판단 불가 10건, 유형 틀림 0, 놓침 0. mi-telegram.com은 접속 불가로 제외 |

이 PC의 baseline 흐름(`var/eval/`): main 624c752 KISA 40% → #17 도박 유형 57% → #18 막다른 곳 67%.
KISA 시간 중앙값/p90은 13.3s/29.6s에서 8.8s/23.6s로 줄었다.

KISA 남은 오답:
- **판단 불가**: go9.co/UCi, goo.su/PUPst는 목적지가 죽었고 이름(`ren.liufan.site`, `ven.nibyol.fun`)에서 알 수 있는 것이 없다(근거가 없는 게 맞을 수 있음). iii.im/ZujV는 단축 서비스의 경고 화면에서 버튼을 눌러도 화면이 그대로라 멈춘다. goo.su/E7i5QDl은 3회 중 1회 판단 불가.
- **mi-telegram.com**: SK브로드밴드가 SNI/Host를 보고 연결을 리셋한다(방심위 차단 방식). 같은 Cloudflare IP에 다른 이름으로는 접속된다. 이 회선에서는 측정할 수 없다.

## 남은 개선 후보 (사용자가 아직 고르지 않음)

1. 단축 서비스 경고 화면 통과(iii.im/ZujV).
2. 통신사 차단 감지: 같은 IP에 다른 이름으로는 접속되는데 이 도메인만 리셋되면, 당국이 이미 차단한 사이트라는 신호로 쓴다. 통신사마다 결과가 다르고 위협 유형은 알 수 없다.
3. 브랜드 사칭 도메인 신호(예: `*-telegram.com`). 이 PC에서는 mi-telegram이 차단돼 측정할 수 없다.

이미 해 본 것:
- 되돌아가기(backtracking) 탐색은 측정 결과 어떤 표본에서도 이득이 없어 **보류**했다. 다시 꺼내지 않는다.
- 첫 접속: commit까지만 15초 기다리고 domcontentloaded는 따로 기다린다(PR #14/#15). KISA 접속 불가가 2건에서 0건이 됐다.
- 중국어 도박 사이트 유형(PR #17): 해외 도박 브랜드를 붙인 복제 사이트를 도박으로 판단하고, 날짜를 계좌번호로 가리지 않는다. KISA 유형 틀림이 6건에서 0건이 됐다.
- 오류·프록시 거부 화면을 막다른 곳으로 처리(PR #18): 관찰하지 않고 원래 페이지로 돌아가거나 끝낸다. KISA 판단 불가가 13건에서 10건, `loop_detected`가 6회에서 0회가 됐다.

## 시험

```bash
cd backend && ../.venv/Scripts/python -m pytest -q
```

---
이 파일은 작업 상태가 바뀔 때(PR 머지, 새 baseline, 과제 결정) 함께 갱신한다.

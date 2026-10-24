# 조사 콘솔 화면 개편 명세 (A안: 업무 분류함 + 근거 화면)

이 문서는 콘솔(`frontend/`) 화면 개편의 구현 명세다. Claude Code 는 이 문서와 `CLAUDE.md` 작업 방식을 따라 **3단계(PR 3개)** 로 진행한다. 단계마다 main 에서 새 브랜치를 따고, 앞 PR 이 머지된 뒤 다음 단계를 시작한다(PR 을 쌓지 않는다).

- 시안(디자인 캔버스, 사용자 본인만 열람): https://claude.ai/artifact/CmtR1wWJUut9EvALLNMot3
  - 기준 시안: **"A 밝은 버전 · 근거 화면 기본 탭 + 경로 지도"** (맨 아래 줄, 눌러 볼 수 있음)
  - 글꼴 참고: "글꼴 6 · Pretendard GOV"
- 범위: `frontend/src`, `frontend/package.json`, `frontend/index.html`. **백엔드·API·nginx 는 바꾸지 않는다.**
- 일정: 코드 동결 10/24. 3단계는 동결 전에 끝낼 수 있는 크기로 잘랐다. 시간이 모자라면 3단계의 경로 지도만 뒤로 미룬다.

---

## 0. 지킬 것 (보안·운영)

1. **조사 대상 페이지에서 온 문자열**(제목, 버튼 글자, URL, 금지 요소 이름, 후보 호스트)은 지금처럼 React 텍스트로만 출력한다. `dangerouslySetInnerHTML`, `innerHTML`, 페이지 유래 값을 `href`·`src` 로 쓰는 것을 금지한다. 길이는 잘라서 보여 준다(목록 60자, 카드 40자).
2. **CSP 를 바꾸지 않는다** (`nginx.conf`: `default-src 'self'; img-src 'self' blob:; style-src 'self'; script-src 'self'; connect-src 'self'`).
   - 외부 글꼴·CDN·이미지를 쓰지 않는다. 글꼴은 npm 패키지로 번들에 넣는다(§2).
   - `<style>` 태그를 주입하지 않는다. 스타일은 `style.css` 클래스로 쓰고, React `style` 속성은 계산된 값(폭·색 변수 선택)에만 쓴다.
3. **새 API 를 만들지 않는다.** 근거·경로는 콘솔이 이미 받는 데이터(`GET /api/cases`, `GET /api/cases/{id}`, `/events` SSE)로 프런트에서 계산한다.
   - `report.json` 은 화면 표시용으로 부르지 않는다. 부를 때마다 감사 로그(`report.export`)가 남고, `key_screens` 는 근거와 짝지어진 선택이 아니다.
4. 증거 파일은 지금처럼 `fileUrl()`(인증 헤더 → blob URL)로 받고, 다 쓰면 `URL.revokeObjectURL` 한다. 썸네일은 `preview=true`, 원본 보기는 `preview` 없이.
5. AI 문구에는 "기술적 의심 유형이며 법적 판단이 아닙니다"를 유지한다. 판정 저장 권한은 지금 그대로(`canDecide`: 검토관 이상 사람 계정)다.
6. 근거 문장은 **고정 문구 + 기록 값**으로만 만든다(§5). AI 에게 문장을 새로 쓰게 하지 않는다(판단 경로가 늘면 평가를 다시 돌려야 한다).
7. 색만으로 상태를 구분하지 않는다. 지금의 상태 기호(● ▲ ■ ✓ ×)를 유지한다.

---

## 1. 디자인 토큰 (`style.css` `:root`)

현재 다크 네온 토큰을 아래로 교체한다. 다크 테마는 이번 범위가 아니다(변수 구조만 유지해 두면 나중에 `[data-theme="dark"]` 로 추가할 수 있다).

```css
:root {
  /* 바탕·면 */
  --bg: #F2F4F7;          --surface: #FFFFFF;      --surface-2: #F6F8FB;   --sunken: #F4F6F9;
  --line: #DDE2EA;        --line-soft: #E6EAF0;    --line-strong: #CDD4DF;
  /* 글자 */
  --ink: #1A2233;         --ink-2: #3E4859;        --muted: #5A6478;
  /* 상단바 */
  --header: #10213F;      --header-ink: #FFFFFF;   --header-muted: #A9B6CE; --header-line: #3A4F78; --header-accent: #5B9BFF;
  /* 주 색 */
  --primary: #1D56BC;     --primary-press: #123E8C; --primary-tint: #E8F0FD; --selected: #F0F5FE;
  /* 상태 */
  --threat: #C62828;      --threat-tint: #FDECEC;  --threat-press: #8E1C1C; --threat-edge: #EDB4B4;
  --review: #B35C00;      --review-tint: #FFF3E0;
  --safe: #1E7B47;        --safe-tint: #E8F5EC;
  --idle: #5A6478;        --idle-tint: #EEF1F5;    --idle-line: #A3ABB8;
  --live: #E53935;        --screen-bg: #1B2230;
  /* 깊이감(CSS 만, backdrop-filter 쓰지 않음) */
  --e1: 0 1px 2px rgba(16,33,63,.06), 0 8px 20px -12px rgba(16,33,63,.30);   /* 일반 패널 */
  --e2: 0 1px 2px rgba(16,33,63,.08), 0 14px 30px -14px rgba(16,33,63,.35);  /* AI 요약 */
  --e3: 0 1px 2px rgba(16,33,63,.10), 0 18px 36px -14px rgba(16,33,63,.50);  /* 실시간 화면 */
  --e-card: 0 2px 0 var(--line-soft), 0 8px 16px -10px rgba(16,33,63,.30);  /* 근거 카드 */
  --e-pick: 0 2px 0 #C9D6EE, 0 10px 18px -10px rgba(29,86,188,.50);          /* 선택된 카드·썸네일 */
  --e-key: 0 3px 0 #DCE2EB, 0 10px 18px -10px rgba(16,33,63,.35);           /* 경로 지도 노드 */
  --e-bar: 0 -1px 0 var(--line-strong), 0 -12px 28px -10px rgba(16,33,63,.28); /* 판정 막대 */
  --e-btn: inset 0 1px 0 rgba(255,255,255,.2), 0 2px 0 var(--primary-press), 0 8px 14px -8px rgba(29,86,188,.7);
  --inset-screen: inset 0 2px 10px rgba(0,0,0,.55);
  --inset-floor: inset 0 2px 6px rgba(16,33,63,.08);
  /* 모양 */
  --r-ctl: 4px; --r-card: 6px; --r-panel: 8px;
  /* 글꼴(§2) */
  --sans: "Pretendard GOV Variable", "Pretendard GOV", system-ui, -apple-system, "Malgun Gothic", sans-serif;
  font-family: var(--sans);
  font-size: 14px;
  letter-spacing: -0.01em;
  font-variant-numeric: tabular-nums;
  color: var(--ink);
  background: var(--bg);
}
```

글자 크기: 사건 요약 제목 23px/700, 칸 제목 17px/700, 본문 14px, 보조 13px, 캡션 12px, 최소 11px. 굵기는 400·600·700 만 쓴다. 고정폭 글꼴은 쓰지 않는다(URL·숫자도 Pretendard GOV + `tabular-nums`).

`@media (prefers-reduced-motion: reduce)` 에서 전환 효과를 끈다(지금 규칙 유지).

---

## 2. 글꼴: Pretendard GOV (self-host)

```bash
cd frontend
npm i --save-exact pretendard-gov@1.3.9
npm uninstall @fontsource-variable/geist @fontsource-variable/geist-mono @fontsource/ibm-plex-sans-kr
```

`src/main.tsx` 의 글꼴 import 6줄을 아래 한 줄로 바꾼다.

```ts
// 폰트는 번들에 포함한다(외부 폰트 서버를 쓰지 않음: CSP·격리 운영). 가변 글꼴을 글자 범위로 나눈 120조각, 화면에 필요한 조각만 받는다
import "pretendard-gov/dist/web/variable/pretendardvariable-gov-dynamic-subset.css";
```

- 글꼴 이름은 `'Pretendard GOV Variable'`, 굵기 범위 45~920 이다.
- 라이선스: SIL OFL 1.1(패키지에 포함).
- 확인: `npm run build` 뒤 `dist/assets` 에 woff2 가 들어 있고, 브라우저 Network 탭에 외부 요청이 0건이다. 빌드 산출물 크기 전/후를 PR 설명에 적는다(글꼴 조각 합계 약 5.7MB, 실제 전송은 화면에 쓰인 조각만).

---

## 3. 화면 구조

```
┌ 상단바(--header) ───────────────────────────────────────────────────────────┐
│ 로고 SafeTrace · 위협 의심 사이트 조사 │ 사건 처리 │ 계정 관리(관리자만) │ 사용자·역할 · 비밀번호 변경 · 로그아웃 │
├ 분류 폴더 200px ─┬ 목록 칸 (반) ────────┬ 사건 상세 (반) ─────────────────────────┤
│ [+ 신고 URL 접수] │ ┌ 실시간 화면(§4) ┐  │ 상태 줄 · ‹ 이전 사건 · 다음 사건 ›      │
│ 검토 필요     n  │ └────────────────┘  │ AI 요약 + 근거 카드 ≤3 (§5)              │
│ 조사 중       n  │ 전체 사건 n · [검색] │ 조사 경과 탭 (§6~§8)                      │
│ 위협 의심·판정 전 n│ 사건 목록            │   근거 화면(기본) · 경로 지도 · 조사 녹화 · 행동 기록 │
│ 판정 완료     n  │                     │   └ 아래 줄: Safe Browsing · 무결성 검증 · 보고서 PDF/JSON/ZIP │
│ 접속 불가·차단 n │                     │ ─ 판정 막대(하단 고정, §9) ─              │
│ 전체          n  │                     │                                         │
│ (AI 판단 안내문) │                     │                                         │
└─────────────────┴─────────────────────┴─────────────────────────────────────────┘
```

- 목록 칸과 사건 상세는 폴더를 뺀 폭을 반씩 나눈다(1920 기준 860·860, 목록 칸은 340 밑으로 줄지 않음). 처음엔 목록 칸 340·상세 나머지(1380)였는데, 실시간 화면을 크게 보려고 바꿨다(`feat/wider-live-monitor`). 실시간 화면은 녹화와 같은 16:10(1920 기준 830×518)이고, 창 높이가 모자라면 목록 4줄을 남기고 화면 높이가 줄어든다.
- 바깥 틀은 `display: flex; flex-wrap: wrap`. 900px 미만에서는 세 칸이 세로로 쌓인다(지금 규칙). 1920×1080 비례 확대(`useFitZoom`)는 그대로 쓴다.
- KPI 카드 5개는 없애고 **분류 폴더의 숫자**로 대신한다. 폴더는 목록 필터다(지금의 전체/검토 필요 칩을 대체).

| 폴더 | 조건 (`CaseOut`) |
|---|---|
| 검토 필요 | `needsReview(c)` (지금 함수) |
| 조사 중 | `status ∈ {RUNNING, QUEUED}` |
| 위협 의심 · 판정 전 | `status === "COMPLETED"` && `threat.threat ∉ {benign, unknown}` && `!verdict` |
| 판정 완료 | `verdict?.decision ∈ {threat, benign}` |
| 접속 불가 · 차단 | `status ∈ {UNREACHABLE, BLOCKED, FAILED}` |
| 전체 | 모두 |

- 목록 검색은 클라이언트에서 `url` 부분 일치로 거른다(API 변경 없음).
- 목록 행: 읽지 않음 점(검토 필요·판정 전이면 파란 점), 호스트(60자), 시각, 요약 한 줄(`caseSummary`), 오른쪽에 상태 배지(`StatusChip` 규칙 그대로, 색은 `--{tone}` / `--{tone}-tint`). 선택된 행은 `--selected` 바탕 + 왼쪽 3px 파란 선 + `--e-pick` 그림자.
- `+ 신고 URL 접수` 는 지금 `NewCase` 폼을 폴더 칸 버튼 아래에 펼친다(조사관 이상만, 지금 `canCreate` 그대로).

기존 컴포넌트 대응:

| 지금 | 개편 후 |
|---|---|
| `Kpis` | `FolderNav` (숫자) |
| `Queue` + `NewCase` | `FolderNav`(접수 버튼·폼) + `CaseList` |
| `Investigation` | `LiveMonitor`(§4) + `CaseDetail` 의 탭(§6~§8) |
| `Opinion` | `Summary` (§5) |
| `Evidence` | `CaseFooterBar` (§6 아래 줄) |
| `VerdictPanel` | `VerdictBar` (§9, 저장 로직 그대로) |
| `EventLog`, `Recording`, `LiveVideo`, `LiveScreen` | 그대로 재사용 |

---

## 4. 실시간 화면 (목록 칸 맨 위, 항상 표시)

- 대상: `cases` 에서 `status === "RUNNING"` 인 사건(에이전트는 한 번에 한 건 조사한다). 없으면 `QUEUED` 첫 건을 "대기 중"으로, 둘 다 없으면 빈 상태("지금 조사 중인 사건이 없습니다").
- 화면: `LiveVideo caseId={running.id}` 를 그대로 쓴다. 대체 화면(fallback)은 그 사건의 마지막 관찰 화면(`LiveScreen`).
  - 이를 위해 `LiveMonitor` 가 실행 중 사건의 `/events` 를 따로 구독한다. 선택한 사건이 실행 중 사건이면 같은 구독을 공유해도 되고, 두 개를 열어도 된다(사건이 바뀔 때 `AbortController` 로 정리).
- 머리줄: LIVE 점(`--live`) · "지금 조사 중" · 호스트 · `{fps}fps · {관찰 수}/{MAX_STEPS}` · [크게 보기].
- 아랫줄: 마지막 `decision` 기록 → `Jev 선택 · "{후보 글자}" 클릭 → 실행 중 · {probability}` (지금 `EventLog` 의 후보 글자 찾는 방식 재사용).
- [상세 보기](처음엔 [크게 보기]): 그 사건을 선택한다. **선택한 사건이 조사 중이면** 상세의 탭 자리에 **가장 최근 관찰 화면 + 화면 위 표시**(금지 요소 빨간 점선, Jev 가 고른 버튼 파랑, 안전 게이트가 막은 클릭 빨간 실선) + 행동 기록(실시간)을 보여 주고, 요약은 "조사 중", 판정 막대는 "조사가 끝나면 판정할 수 있습니다"로 비활성.
  - 처음엔 상세에도 실시간 영상을 크게 띄웠는데, 목록 칸 실시간 화면을 키운 뒤(`feat/wider-live-monitor`) 같은 영상이 두 번 보여서 `feat/live-observe-overlay` 에서 바꿨다(사용자 결정). 움직이는 화면은 목록 칸, 'Jev 가 본 것과 고른 것'은 상세가 맡는다. 실시간 영상 연결도 2개 → 1개.
- 재생(`feat/smooth-live`): 프레임을 받은 즉시 그리지 않고 0.15초 모았다가 받은 간격의 평균으로 고르게 그린다. 0.25초 넘게 멈췄다가 오는 프레임은 0.15초 겹쳐 바꾼다. 에이전트가 누르기 직전 보내는 클릭 메시지(`{"click":[x,y,폭,높이]}`)도 같은 통로·같은 지연으로 받아 커서가 그 버튼으로 미끄러져 가고 테두리·물결이 0.7초 나타난다. 조사 녹화 재생도 게이트 기록의 `point`·`at` 과 녹화 `t0` 로 같은 표시를 겹친다(녹화 파일은 그대로).
- 초당 60장(`feat/live-60fps`): 에이전트가 보내는 실시간 프레임 상한 30 → 60(`live_max_fps`), API 가 넘기는 상한 120(클릭 표시 자리). 콘솔은 화면 주기의 반만큼 일찍 와도 그리고(프레임 간격이 화면 주기와 같으면 흔들림으로 한 주기씩 건너뛰었다), 재생 버퍼 상한 12장(0.15초에 약 9장). 화면이 바뀌지 않으면 브라우저가 프레임을 만들지 않으므로 '항상 60' 은 아니다.
- 지금 하는 일(`feat/live-activity`): 화면이 멈춘 동안(관찰·OCR·전체 캡처·Jev 판단·클릭 뒤 응답·로딩 대기) 에이전트가 무엇을 하는지 실시간 화면 왼쪽 아래에 보인다(`ActivityChip`, 1초부터 경과 초). 에이전트가 단계마다 실시간 통로로 `{"act":이름[,"n":개수]}` 를 보내고(클릭 표시와 같은 통로·같은 지연, 바뀔 때만), 콘솔은 정해 둔 이름만 고정 문구표(`evidence.ts` `ACTIVITY_LABEL`)로 바꿔 보인다(에이전트가 보낸 글자를 화면에 쓰지 않음). 증거가 아니라 서명 체인·녹화에는 넣지 않는다.
- 깊이감: 패널 `--e3`, 화면 칸 `--inset-screen` + `--screen-bg`.

---

## 5. AI 요약 + 근거 카드

### 5.1 요약 문장 (`case.threat` 기준, 고정 문구)

| 경우 | 문장 | 윗선 색 |
|---|---|---|
| 위협 유형 && `!hold` | `이 사이트는 {유형}일 가능성이 높습니다` + 확률 | `--threat` |
| 위협 유형 && `hold` | `{유형} 의심 · 확신이 부족해 담당자 검토가 필요합니다` | `--review` |
| `benign` | `위험 근거를 찾지 못했습니다` (정상 단정 문구 쓰지 않음) | `--safe` |
| `unknown` 또는 없음 | `판단할 수 없습니다 · {REASON_LABEL[finish_reason]}` | `--idle` |

- `{유형}` 은 `THREAT_LABEL`. override 가 있으면 문장 아래에 `overrideLabel()` 한 줄.
- 아랫줄: `다음 후보 {2위} · {3위}`(`probabilities` 에서 0.01 이상) · `기술적 의심 유형이며 법적 판단이 아닙니다`.
- Safe Browsing 일치 없음이 "정상"으로 읽히지 않게 지금 문구("일치 없음은 정상이라는 뜻이 아닙니다")를 유지한다.

### 5.2 근거 카드 (최대 3장, 고정 규칙)

사건의 이벤트(`seq` 순)에서 아래 규칙을 **위에서부터** 적용해 카드를 만든다. 규칙마다 카드는 1장(그 규칙에 해당하는 마지막 기록). 3장이 차면 멈춘다. 주 조사(`data.sub` 없음) 기록을 먼저 보고, 연관 후보 규칙(⑤)만 `sub` 기록을 쓴다.

| # | 기록 | 카드 제목 | 카드 문장(값은 기록에서) | 연결 화면 |
|---|---|---|---|---|
| ① | `gate` && `allowed === false` | 입력·제출 차단 | `"{직전 decision 의 후보 글자}" 클릭을 안전 게이트가 막음 ({reason})` | 직전 `observe` 의 png |
| ② | `blocked_request` && `navigation === true` | 이동 차단 | `{url 의 호스트 또는 파일명}(으)로 이동하려 해 검문 프록시가 막음 ({reason})` | 직전 `observe` 의 png |
| ③ | `observe` && `forbidden.length > 0` | 입력 요구 화면 | `입력 칸 등 금지 요소 {n}개가 있는 화면 ({첫 금지 요소 라벨})` — `forbidden` 은 `reason:type:label` 형식, label 만 40자로 | 그 `observe` 의 png |
| ④ | `escalation` | 담당자 검토 전환 | 지금 `EventLog` 의 escalation 문구(회선 차단 / Safe Browsing 유형) | 없음(카드만) |
| ⑤ | `case.candidates` 중 `sub` 있고 `threat ∉ {benign, null}` | 연관 사이트도 의심 | `{경유/링크} {host}도 {유형} {확률}{hold ? "(보류)" : ""}` | 그 `sub` 의 첫 `observe` png(파일명 `c{sub}_` 로 시작) |
| ⑥ | `safebrowsing.status === "match"` | Safe Browsing 일치 | `{threat_type 목록}` | 없음 |
| ⑦ | `threat.override` | 코드 규칙 판단 | `overrideLabel()` | 없음 |

- 하나도 없으면 카드 1장: `뚜렷한 위험 근거 없음 · 마지막 화면을 확인하세요` + 마지막 `observe` png.
- 카드 오른쪽 아래: `EV-{seq}` 와 `화면 보기 ›`(연결 화면이 있을 때). 카드를 누르면 §6 근거 화면 탭으로 바꾸고 그 화면을 선택한다. 선택된 카드는 `--primary` 2px 테두리 + `--e-pick`.
- 카드는 `<button aria-pressed>` 로 만든다.

---

## 6. 조사 경과 탭 — 근거 화면 (기본 탭)

탭: `근거 화면 {n} · 경로 지도 · 조사 녹화 · 행동 기록 {기록 수}`. `role="tablist"`/`role="tab"`/`aria-selected`. **사건을 열면 항상 근거 화면 탭**이다.

(10/24 `feat/tab-groups`) 뒤에 보탠 탭까지 9개를 성격별 세 묶음으로 나눈다. 분석가가 일하는 순서대로 **증거**(근거 화면 · 경로 지도 · 조사 녹화 · 행동 기록) → **연관**(연관 사이트 · 운영 정보 · 연결된 사건) → **조치**(처리 요청 · 조치 추적)다. 묶음 이름은 탭 위 11px 글씨로 두고, 지금 탭이 든 묶음의 이름만 주 색으로 칠한다. 묶음 사이에는 세로선을 두고, 폭이 모자라면 묶음째 다음 줄로 넘긴다. ←→ 키는 묶음을 넘어 보이는 순서대로 움직인다. 화면 낭독기는 묶음 이름을 각 탭의 설명(`aria-describedby`)으로 듣는다. 운영 정보·처리 요청은 조사관 이상만 보이므로 열람자 화면은 증거 4 · 연관 2 · 조치 1이다.

### 6.1 화면 목록 (최대 4장)

1. 근거 카드에 연결된 화면(카드 순서, 같은 파일은 한 번만)
2. 남는 자리는 첫 `observe` 화면, 마지막 `observe` 화면 순으로 채운다(보고서 `key_screens` 와 같은 보충 원칙)
3. `seq` 순이 아니라 **카드 순서 → 보충 순서**로 보여 준다(근거와 짝이 먼저 보이게)

각 항목: 번호(①…), 제목(카드 제목 또는 "첫 화면"/"마지막 화면"), `EV-{seq}`, 그 `observe` 의 `url`(40자), 설명 한 줄(카드 문장).

### 6.2 배치

- 왼쪽(넓게): 선택한 화면을 `LiveScreen caseId name` 으로 크게(높이 300px 안팎, 세로 스크롤·[원본] 버튼 그대로). 바탕 `--screen-bg` + `--inset-screen`.
- 아래 캡션: `{번호} {제목} · EV-{seq} · {url}` + 설명. "서명 확인 ✓" 표시는 **무결성 검증(§6.4)을 통과한 뒤에만** 붙인다.
- 오른쪽(좁게): 썸네일 목록(`role="listbox"`, 항목 `role="option" aria-selected`). 썸네일은 `fileUrl(..., preview=true)` 로 필요할 때 받고 언마운트 때 revoke. 선택 항목은 `--primary` 2px + `--e-pick`.
- 처음 선택: 첫 근거 카드의 화면.
- 시안의 화면 위 표시(금지 요소 점선, 선택 버튼 테두리)는 3단계에서는 기록에 좌표가 없어 그리지 않았고, 별도 PR(`feat/screen-overlay`)에서 넣었다: 에이전트가 관찰 기록에 요소 상자(`boxes`, 캡처 픽셀)를 남기고, 콘솔이 원본 화면 위에 SVG 로 겹친다(금지 요소 빨간 점선, Jev 가 고른 버튼 파랑, 안전 게이트가 막은 클릭 빨간 실선, [화면 표시 끄기]). 좌표는 페이지 JS 가 아니라 브라우저 프로토콜로 잰다. 원본 화면 파일은 바꾸지 않는다.

### 6.3 화면이 없는 사건

접속 불가·DNS 실패처럼 `observe` 가 없으면 `화면 기록 없음 · {NET_CATEGORY_LABEL 또는 REASON_LABEL}` 을 보여 주고 기본 탭을 행동 기록으로 바꾼다.

### 6.4 아래 줄 (모든 탭 공통)

`Safe Browsing {sbText}` · `증거 무결성 [검증]` → 결과(`해시 체인 · HMAC 서명 통과 · 서명 기록 n건` / 실패 오류) · `[보고서 PDF] [JSON] [검토 패키지 ZIP]`(조사관 이상). 로직은 지금 `Evidence` 컴포넌트 그대로.

---

## 7. 조사 경과 탭 — 경로 지도

데이터(주 조사 기록만):
- 본 줄(왼→오): `case.url` → `navigation.data.redirects`(서버 리다이렉트, 순서대로) → `finish.data.nav_chain`(열린 페이지) → 마지막 `case.final_url`. URL 문자열이 같으면 합친다. `new_window` 기록의 url 은 본 줄 노드에 "새 창" 표시.
- 가지(노드 아래): 그 시점의 현재 주소 노드에 붙인다.
  - `blocked_request` && `navigation` → 빨간 점선 "이동 차단 · EV-n · {호스트/파일명}"
  - `gate` && `!allowed` → 빨간 점선 "안전 게이트 · EV-n · "{후보 글자}" 제출 차단"
  - `case.candidates`: `sub` 있음 → 주황(보류)/빨강(위협)/회색(정상) 테두리 "{경유|링크} 후보 · {판단}", `sub` 없음 → 회색 점선 "링크 후보 · 기록만". 후보는 최대 3개만 그리고 나머지는 "+n개".
- 노드: 136×72, 둘째 줄 호스트+경로(24자). 마지막 노드는 `threat` 색 2px 테두리, `translateY(-3px)` + 짙은 그림자로 한 단 올린다. 나머지 노드는 `--e-key`.
- 본 줄이 5개를 넘으면 가운데를 "… {n}곳" 노드 하나로 접는다.
- 그리기: **그래프 라이브러리 없이** CSS grid(열 = 본 줄 노드) + 노드 사이 화살표는 작은 인라인 SVG 또는 CSS 테두리. 가지는 같은 열 아래 칸에 세로 점선(`border-left: dashed`)으로 잇는다. 바닥은 `--sunken` + 점 무늬(`radial-gradient` 1px, 16px 간격) + `--inset-floor`.
- 범례: `━ 이동 · ┅ 차단 · ┅ 기록만`.
- 주소가 1곳이고 가지가 없으면 "거쳐 간 주소가 1곳뿐입니다"와 노드 1개만.

---

## 8. 조사 경과 탭 — 조사 녹화 · 행동 기록

- 조사 녹화: `recording` 기록이 있으면 지금 `Recording` 컴포넌트. 없으면 "녹화 없음".
- 행동 기록: 지금 `EventLog` 를 그대로 쓰고 색·글꼴만 새 토큰으로(최신이 위, 통계·광고 전송 차단 묶음 유지).

---

## 9. 판정 막대 (상세 칸 아래 고정)

- 위치: 상세 칸 맨 아래 `position: sticky; bottom: 0`(뷰포트 fixed 가 아님 — 비례 확대 틀 안에 있음). 바탕 `--surface`, 그림자 `--e-bar`.
- 배치(가로, 좁으면 줄바꿈): `담당자 판정` · 현재 판정 칩(`verdictText` · 판 n · 검토자 · 시각, 없으면 "판정 없음") · 판정 선택 `role="radiogroup"`(위협 확정 / 정상 / 보류, 버튼 `role="radio" aria-checked`) · 위협 유형 select(위협 확정일 때만, 기본값 = AI 유형, 옵션 이름 뒤에 "(AI 추천)") · 메모 입력(1000자) · [저장] · [저장하고 다음 사건].
- 저장 로직은 지금 `VerdictPanel.submit` 그대로(보고 있던 `rev` 를 보냄, 409 이면 오류 문구 + 최신 판정 다시 받기). "다음 사건"은 **현재 폴더 목록 순서**의 다음 사건을 선택한다.
- 판정 기록(판 2 이상): 칩 옆 [기록 n건] → 지금 `verdict-history` 내용을 펼침 영역으로.
- 권한·상태 문구는 지금 것 그대로(검토관 이상만 저장 / 조사가 끝나면 판정 가능 / AI 는 판정을 확정하지 않음).
- 위협 확정 버튼: `--threat` 바탕, `inset 0 1px 0 rgba(255,255,255,.22), inset 0 -2px 0 var(--threat-press)`. 저장 버튼: `--primary` + `--e-btn`.

---

## 10. 깊이감 적용 위치 (CSS 만)

| 요소 | 값 |
|---|---|
| 실시간 화면 패널 | `--e3`, 화면 칸 `--inset-screen` |
| AI 요약 | `--e2`, 윗선 3px(§5.1 색) |
| 근거 카드 | `--e-card`, 선택 시 `--e-pick` |
| 조사 경과 패널 | `--e1`, 지도 바닥 `--inset-floor` |
| 경로 지도 노드 | `--e-key`, 마지막 노드만 한 단 위 |
| 주요 버튼(접수, 저장) | `--e-btn` |
| 판정 막대 | `--e-bar` |
| 선택된 목록 행 | `inset 3px 0 0 var(--primary), 0 10px 20px -12px rgba(16,33,63,.5)` |

`backdrop-filter` 는 쓰지 않는다(지금 원칙 유지: 다시 그릴 때 무겁다).

---

## 11. 단계별 작업과 확인

각 단계는 `CLAUDE.md` 기준으로 진행한다: main 에서 브랜치 → 구현 → `npm run build`(CI 와 같음) → 실제 스택 1건 확인과 걸린 시간 → 커밋 → `tools/codex_review.sh` → PR(설명에 측정·Codex 절). `docs/plan-updates.md` 2절(기획서와 달라진 점)에 "콘솔 화면 개편" 한 줄을 단계마다 보탠다.

### 1단계 `feat/console-frame` — 틀·토큰·글꼴
- §1 토큰, §2 글꼴, §3 상단바·분류 폴더·목록·상세 틀, §9 판정 막대 이동.
- 상세 내용은 아직 기존 컴포넌트(`Investigation`, `Opinion`, `Evidence`)를 새 틀에 옮겨 담기만 한다.
- 로그인 화면, 비밀번호 변경·계정 관리 대화상자도 새 토큰으로 바뀌는지 확인.
- 확인: 로그인 → URL 접수 → 조사 → 판정 저장 → ZIP 1건 / 폴더 숫자가 예전 KPI 와 같은지 / 외부 요청 0 / 콘솔에 CSP 위반 0 / 900px 미만 세로 쌓임 / 번들 크기 전·후.

### 2단계 `feat/console-live-monitor` — 실시간 화면 상시 표시
- §4 전부.
- 확인: 조사 중 사건이 있을 때·없을 때·대기만 있을 때 / 다른 사건을 보는 중에도 영상이 계속 나오는지(fps 표시) / 조사가 끝나면 다음 사건으로 넘어가는지 / 사건 전환 시 WebSocket·SSE 가 정리되는지(Network 탭에 남는 연결 없음).

### 3단계 `feat/console-evidence-tabs` — 요약·근거·탭·경로 지도
- §5, §6, §7, §8.
- 근거 규칙은 순수 함수(`buildReasons(events, case)`, `buildScreens(...)`, `buildPath(...)`)로 분리한다.
- 확인(실제 스택): `testpages:8900/smish/`(게이트·이동 차단·후보), `testpages:8900/benign/`(근거 없음 카드), 접속 불가 사건 1건(화면 없음 → 행동 기록 탭), 연관 후보 하위 조사가 있는 사건 1건. 각 사건에서 카드 → 화면 연결, 경로 노드·가지 수가 행동 기록과 맞는지.
- 공격 시나리오 페이지(`testpages/attack/injection.html` 등)를 조사한 사건에서 페이지 글자가 화면에 그대로(마크업으로 해석되지 않고) 보이는지.

---

## 12. 하지 않는 것

- 다크 테마, 3D 로그인 화면(시안만 있음 — 동결 전 여유가 있으면 별도 PR)
- 화면 위 요소 표시(좌표가 기록에 없음)
- 백엔드·API·nginx·CSP 변경
- AI 가 쓰는 근거 문장

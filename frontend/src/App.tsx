import { Component, memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type AgentEvent,
  ApiError,
  type Candidate,
  type CaseOut,
  type Decision,
  type EvidenceEvent,
  type Me,
  ROLE_RANK,
  type Role,
  type UserOut,
  type Verdict,
  changePassword,
  clickables,
  clearToken,
  createCase,
  createRelated,
  createUser,
  downloadGroupCsv,
  getIntel,
  type CaseIntel,
  getLinks,
  getActions,
  saveAction,
  requestRecheck,
  type Action,
  type ActionState,
  type Check,
  getReferral,
  getStats,
  type Pair,
  type Stats,
  type Referral,
  listGroups,
  type CaseLinks,
  type RelatedGroup,
  dict,
  downloadExport,
  downloadIoc,
  iocSummary,
  type IocSummary,
  fileBlob,
  fileUrl,
  getCase,
  getToken,
  list,
  listCases,
  listUsers,
  listVerdicts,
  login,
  logout,
  me,
  num,
  patchUser,
  saveVerdict,
  streamEvents,
  strs,
  text,
  type Threat,
  verifyCase,
} from "./api";
import {
  buildOverlay, buildPath, buildReasons, buildScreens, clip, CURSOR_IN, cursorTravel, hostOrFile, hostPath, jpegSize, liveActivity, liveClick, locateSeg, MAX_RECORDINGS, recCursor, recordingClicks, recordings, SCREEN_H,
  SCREEN_W, segStarts, type Activity, type ClickPoint, type Overlay, type Reason, type RecItem, type Screen, type Tone,
} from "./evidence";
import { ACTION_LABEL, ACTION_STATE_LABEL, AGENCY_LABEL, CHECK_RESULT_LABEL, INTEL_KIND, linkKeyLabel, NET_CATEGORY_LABEL, overrideLabel, REASON_LABEL, THREAT_LABEL } from "./labels";

// 조사 대상 페이지에서 온 문자열은 모두 React 기본 이스케이프로만 출력한다(raw HTML 금지).

const STATUS_LABEL: Record<string, string> = dict({
  QUEUED: "대기",
  RUNNING: "조사 중",
  COMPLETED: "조사 완료",
  REVIEW_REQUIRED: "검토 필요",
  FAILED: "실패",
  UNREACHABLE: "접속 불가",
  BLOCKED: "차단(정책)",
});
// 색만으로 구분하지 않도록 상태마다 기호를 붙인다
const STATUS_GLYPH: Record<string, string> = dict({
  QUEUED: "●",
  RUNNING: "●",
  COMPLETED: "○",
  REVIEW_REQUIRED: "▲",
  FAILED: "×",
  UNREACHABLE: "×",
  BLOCKED: "×",
});
// 검토가 남은 사건: 검토 필요 상태이고 담당자가 아직 확정(위협·정상)하지 않음(보류는 남는다)
const needsReview = (c: CaseOut) => c.status === "REVIEW_REQUIRED" && (!c.verdict || c.verdict.decision === "hold");
const TERMINAL = new Set(["COMPLETED", "REVIEW_REQUIRED", "FAILED", "UNREACHABLE", "BLOCKED"]);
const MAX_STEPS = 15; // 에이전트 기본 예산(ST_MAX_STEPS)
const MAX_EVENTS = 3000; // 사건 하나에서 화면에 받는 기록 수 상한

// ── 아이콘(선 굵기 1.6 한 가지 스타일) ─────────────────────
const ICONS: Record<string, string[]> = {
  shield: ["M12 2.8 5 5.6v5.6c0 4.4 3 8.3 7 9.6 4-1.3 7-5.2 7-9.6V5.6l-7-2.8Z", "M8.6 12h1.8l1.3-2.6 1.8 5.2 1.3-2.6h.8"],
  shieldCheck: ["M12 2.8 5 5.6v5.6c0 4.4 3 8.3 7 9.6 4-1.3 7-5.2 7-9.6V5.6l-7-2.8Z", "m9 12 2 2 4-4"],
  alert: ["M12 3.5 21 19.5H3L12 3.5Z", "M12 10v4M12 17h.01"],
  clock: ["M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17Z", "M12 7.5V12l3 2"],
  check: ["M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17Z", "m8.5 12 2.5 2.5 4.5-5"],
  stack: ["M12 3 3 7.5 12 12l9-4.5L12 3Z", "m3 12 9 4.5 9-4.5M3 16.5 12 21l9-4.5"],
  ban: ["M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17Z", "m6 6 12 12"],
  lock: ["M7 10.5h10a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2Z", "M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3"],
  cursor: ["m5 3 14 8-6 1.5L10 19 5 3Z"],
  window: ["M5.5 5.5h11a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2h-11a2 2 0 0 1-2-2v-11a2 2 0 0 1 2-2Z", "M9.5 3.5h9a2 2 0 0 1 2 2v9"],
  eye: ["M2.5 12s3.5-6.5 9.5-6.5 9.5 6.5 9.5 6.5-3.5 6.5-9.5 6.5S2.5 12 2.5 12Z", "M12 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5Z"],
  brain: ["M9 4.5a3 3 0 0 0-3 3v.5a3 3 0 0 0-1.5 5.5A3 3 0 0 0 9 19.5h.5V4.5H9Z", "M15 4.5a3 3 0 0 1 3 3v.5a3 3 0 0 1 1.5 5.5 3 3 0 0 1-4.5 6h-.5V4.5h.5Z"],
  flag: ["M5 21V4.5M5 4.5h11l-2 4 2 4H5"],
  globe: ["M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17Z", "M3.5 12h17M12 3.5c2.5 2.5 3.5 5.5 3.5 8.5s-1 6-3.5 8.5c-2.5-2.5-3.5-5.5-3.5-8.5s1-6 3.5-8.5Z"],
  x: ["M5.5 4h13a1.5 1.5 0 0 1 1.5 1.5v13a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 18.5v-13A1.5 1.5 0 0 1 5.5 4Z", "m9 9 6 6M15 9l-6 6"],
};
function Icon({ name }: { name: keyof typeof ICONS }) {
  return (
    <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">
      {ICONS[name].map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
}

// 1920×1080 기준 디자인을 창 크기에 맞춰 통째로 비례 확대·축소한다(QHD 에서 커지고, 작은 노트북에서 작아짐).
// 너무 작아지면(0.7 미만) 더 줄이지 않고 스크롤, 좁은 화면(900px 미만)은 확대·축소 없이 세로로 쌓는다.
const BASE_W = 1920;
const BASE_H = 1080;
function fitZoom() {
  if (window.innerWidth < 900) return 1;
  return Math.min(Math.max(Math.min(window.innerWidth / BASE_W, window.innerHeight / BASE_H), 0.7), 2);
}
function useFitZoom() {
  const [z, setZ] = useState(fitZoom);
  useEffect(() => {
    const on = () => setZ(fitZoom());
    window.addEventListener("resize", on);
    return () => window.removeEventListener("resize", on);
  }, []);
  return { zoom: z, width: `calc(100vw / ${z})`, height: `calc(100vh / ${z})` };
}

const ROLE_LABEL: Record<Role, string> = { viewer: "열람", investigator: "조사관", reviewer: "검토관", admin: "관리자" };

const fmtTime = (iso: string) => new Date(iso).toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", hour12: false });
const pct = (v: number) => (typeof v === "number" && Number.isFinite(v) ? v.toFixed(2) : "-");

// ── 분류 폴더: 목록 필터이자 현황 숫자(예전 지표 카드를 대신한다) ─────────────
const isSuspect = (c: CaseOut) => !!c.threat && !["benign", "unknown"].includes(c.threat.threat);
// 원래 결과가 나왔고 연관 사이트를 조사하는 중인 사건은 원래 결과의 상태로 분류한다(조사 중 폴더에 넣지 않는다)
const relatedRunning = (c: CaseOut) => c.phase === "related" && c.status === "RUNNING" && !!c.main_status;
const asMain = (c: CaseOut): CaseOut => (relatedRunning(c) ? { ...c, status: c.main_status as string } : c);
type FolderId = "review" | "running" | "suspect" | "decided" | "unreachable" | "tracking" | "reappeared" | "all";
const FOLDERS: { id: FolderId; label: string; color: string; test: (c: CaseOut) => boolean }[] = [
  { id: "review", label: "검토 필요", color: "var(--review)", test: (c) => needsReview(asMain(c)) },
  { id: "running", label: "조사 중", color: "var(--primary)", test: (c) => (c.status === "RUNNING" || c.status === "QUEUED") && !relatedRunning(c) },
  { id: "suspect", label: "위협 의심 · 판정 전", color: "var(--threat)", test: (c) => asMain(c).status === "COMPLETED" && isSuspect(c) && !c.verdict },
  { id: "decided", label: "판정 완료", color: "var(--safe)", test: (c) => c.verdict?.decision === "threat" || c.verdict?.decision === "benign" },
  { id: "unreachable", label: "접속 불가 · 차단", color: "var(--idle-line)", test: (c) => ["UNREACHABLE", "BLOCKED", "FAILED"].includes(asMain(c).status) },
  // 조치 추적: 기관에 요청했거나 차단·삭제를 확인해 재확인 중인 사건, 재확인에서 다시 접속된 사건(다시 요청할 것)
  { id: "tracking", label: "조치 추적", color: "var(--primary)", test: (c) => ["requested", "blocked", "removed"].includes(c.action?.state ?? "") },
  { id: "reappeared", label: "다시 나타남", color: "var(--threat)", test: (c) => c.action?.state === "reappeared" },
  { id: "all", label: "전체", color: "var(--header)", test: () => true },
];
// 담당자가 확인할 사건(검토 필요, 위협 의심인데 판정 전)은 목록에 파란 점
const unread = (raw: CaseOut) => {
  const c = asMain(raw);
  return needsReview(c) || (c.status === "COMPLETED" && isSuspect(c) && !c.verdict);
};

// ── 앱 ─────────────────────────────────────────────
export default function App() {
  const [user, setUser] = useState<Me | null>(null);
  const [checking, setChecking] = useState(!!getToken());
  const [cases, setCases] = useState<CaseOut[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [folder, setFolder] = useState<FolderId>("all");
  const [groupsView, setGroupsView] = useState(false); // 분류 폴더 '연관 묶음'(사건 대신 묶음 목록)
  const [query, setQuery] = useState("");
  const [source, setSource] = useState("");
  const [error, setError] = useState("");
  const [dialog, setDialog] = useState<"" | "users" | "password" | "ioc">("");
  const [view, setView] = useState<"cases" | "dashboard">("cases");
  const fit = useFitZoom();

  const signOut = useCallback(() => {
    clearToken();
    clearShotCache();
    setUser(null);
    setCases([]);
    setSelected(null);
    setDialog("");
    setView("cases");
  }, []);

  // 새로 고침해도 같은 탭이면 세션을 이어 쓴다(만료됐으면 로그인 화면으로)
  useEffect(() => {
    if (!getToken()) return;
    me()
      .then(setUser)
      .catch(signOut)
      .finally(() => setChecking(false));
  }, [signOut]);

  const refresh = useCallback(async () => {
    try {
      setCases(await listCases());
      setError("");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) signOut();
      setError(e instanceof Error ? e.message : "목록 조회 실패");
    }
  }, [signOut]);

  useEffect(() => {
    if (!user) return;
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [user, refresh]);

  // 지금 폴더·검색에 맞는 목록. 이전·다음 사건과 '저장하고 다음 사건'도 이 순서를 따른다
  const current = FOLDERS.find((f) => f.id === folder) ?? FOLDERS[FOLDERS.length - 1];
  const q = query.trim().toLowerCase();
  const shown = useMemo(
    () => cases.filter((c) => current.test(c) && (!source || c.source === source) && (!q || c.url.toLowerCase().includes(q))),
    [cases, current, q, source],
  );
  const at = selected ? shown.findIndex((c) => c.id === selected) : -1;
  const prevId = at > 0 ? shown[at - 1].id : null;
  const nextId = at >= 0 ? (shown[at + 1]?.id ?? null) : (shown[0]?.id ?? null);

  if (checking) return <div className="login" style={fit} />;
  if (!user) return <Login fit={fit} onLogin={setUser} />;

  return (
    <div className="app" style={fit}>
      <header className="topbar">
        <div className="brand">
          <Icon name="shieldCheck" />
          <span className="brand-name">SafeTrace</span>
          <span className="brand-sub">위협 의심 사이트 조사</span>
        </div>
        <nav className="topnav" aria-label="주 메뉴">
          <button type="button" className="topnav-btn" aria-current={view === "cases" ? "page" : undefined} onClick={() => setView("cases")}>
            사건 처리
          </button>
          <button type="button" className="topnav-btn" aria-current={view === "dashboard" ? "page" : undefined} onClick={() => setView("dashboard")}>
            현황판
          </button>
          {ROLE_RANK[user.role] >= ROLE_RANK.reviewer && (
            <button type="button" className="topnav-btn" onClick={() => setDialog("ioc")}>
              IOC 내보내기
            </button>
          )}
          {user.kind === "user" && user.role === "admin" && (
            <button type="button" className="topnav-btn" onClick={() => setDialog("users")}>
              계정 관리
            </button>
          )}
        </nav>
        <div className="spacer" />
        <div className="who">
          <span>
            {user.name} 님 · {ROLE_LABEL[user.role]}
          </span>
          {user.kind === "user" && (
            <button type="button" className="btn btn-text" onClick={() => setDialog("password")}>
              비밀번호 변경
            </button>
          )}
          <button type="button" className="btn-header" onClick={() => logout().finally(signOut)}>
            로그아웃
          </button>
        </div>
      </header>
      {dialog === "users" && <UsersDialog me={user} onClose={() => setDialog("")} />}
      {dialog === "password" && <PasswordDialog onClose={() => setDialog("")} onChanged={signOut} />}
      {dialog === "ioc" && <IocDialog onClose={() => setDialog("")} />}

      {view === "dashboard" ? (
        <Boundary what="현황판">
          <DashboardPane />
        </Boundary>
      ) : (
      <div className="workspace">
        <FolderNav
          cases={cases}
          folder={groupsView ? null : folder}
          onFolder={(f) => {
            setGroupsView(false);
            setFolder(f);
          }}
          groupsOn={groupsView}
          onGroups={() => setGroupsView(true)}
          canCreate={ROLE_RANK[user.role] >= ROLE_RANK.investigator}
          onCreated={(c) => {
            setSelected(c.id);
            refresh();
          }}
        />
        {groupsView ? (
          <GroupsPane
            canExport={ROLE_RANK[user.role] >= ROLE_RANK.investigator}
            onOpenCase={(id) => {
              setGroupsView(false);
              setFolder("all");
              setSelected(id);
            }}
          />
        ) : (
          <>
        <CaseList
          title={current.label}
          cases={shown}
          selected={selected}
          error={error}
          query={query}
          onQuery={setQuery}
          source={source}
          onSource={setSource}
          onSelect={setSelected}
          monitor={<LiveMonitor cases={cases} onOpen={setSelected} onEnded={refresh} />}
        />
        <section className="detail scroll" aria-label="사건 상세">
          {selected ? (
            <Boundary key={selected} what="사건 상세">
            <Workspace
              key={selected}
              id={selected}
              canDecide={user.kind === "user" && ROLE_RANK[user.role] >= ROLE_RANK.reviewer}
              canAct={user.kind === "user" && ROLE_RANK[user.role] >= ROLE_RANK.investigator}
              canExport={ROLE_RANK[user.role] >= ROLE_RANK.investigator}
              onDecided={refresh}
              onOpen={setSelected}
              onPrev={prevId ? () => setSelected(prevId) : null}
              onNext={nextId ? () => setSelected(nextId) : null}
            />
            </Boundary>
          ) : (
            <EmptyWorkspace />
          )}
        </section>
          </>
        )}
      </div>
      )}
    </div>
  );
}

// 오류 경계: 믿지 않는 기록 때문에 한 칸을 그리지 못해도 콘솔 전체가 멈추지 않게 그 칸만 대신 보여 준다
class Boundary extends Component<{ what: string; children: React.ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <p className="err" role="alert" style={{ padding: 16 }}>
        {this.props.what}을(를) 표시하지 못했습니다(기록 형식 오류). 다른 사건은 계속 볼 수 있습니다.
      </p>
    );
  }
}

function Login({ fit, onLogin }: { fit: React.CSSProperties; onLogin: (u: Me) => void }) {
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  return (
    <div className="login" style={fit}>
      <div className="panel login-card">
        <div className="brand">
          <span className="brand-mark">
            <Icon name="shield" />
          </span>
          <span className="brand-name">SafeTrace</span>
          <span className="chip">SOC</span>
        </div>
        <h1>조사 콘솔 접속</h1>
        <p className="muted small">담당자 계정으로 로그인하세요. 로그인은 이 탭에만 유지되고, 30분 동안 쓰지 않으면 끊깁니다.</p>
        <form
          className="login-form"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setMsg("");
            try {
              onLogin(await login(name.trim(), pw));
            } catch (err) {
              setMsg(err instanceof Error ? err.message : "로그인 실패");
              setPw("");
            } finally {
              setBusy(false);
            }
          }}
        >
          <label className="sr" htmlFor="username">
            아이디
          </label>
          <input id="username" className="field" autoComplete="username" value={name} onChange={(e) => setName(e.target.value)} placeholder="아이디" required autoFocus />
          <label className="sr" htmlFor="password">
            비밀번호
          </label>
          <input id="password" className="field" type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="비밀번호" required />
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "확인 중…" : "로그인"}
          </button>
          {msg && (
            <p className="err" role="alert">
              {msg}
            </p>
          )}
        </form>
      </div>
    </div>
  );
}

// ── 대화상자: 비밀번호 변경, 계정 관리(관리자) ─────────────────
function Dialog({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  useEffect(() => {
    const on = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, [onClose]);
  return (
    <div className="overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="panel dialog" role="dialog" aria-modal="true" aria-label={title}>
        <div className="dialog-head">
          <h2 className="panel-title">{title}</h2>
          <button type="button" className="btn btn-text" onClick={onClose}>
            닫기
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

function PasswordDialog({ onClose, onChanged }: { onClose: () => void; onChanged: () => void }) {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [msg, setMsg] = useState("");
  return (
    <Dialog title="비밀번호 변경" onClose={onClose}>
      <form
        className="stack"
        onSubmit={async (e) => {
          e.preventDefault();
          if (next !== again) return setMsg("새 비밀번호가 서로 다릅니다");
          try {
            await changePassword(cur, next);
            onChanged(); // 서버가 모든 세션을 끊었으므로 다시 로그인
          } catch (err) {
            setMsg(err instanceof Error ? err.message : "변경 실패");
          }
        }}
      >
        <input className="field" type="password" autoComplete="current-password" placeholder="현재 비밀번호" aria-label="현재 비밀번호" value={cur} onChange={(e) => setCur(e.target.value)} required />
        <input className="field" type="password" autoComplete="new-password" placeholder="새 비밀번호(12자 이상)" aria-label="새 비밀번호" value={next} onChange={(e) => setNext(e.target.value)} required />
        <input className="field" type="password" autoComplete="new-password" placeholder="새 비밀번호 확인" aria-label="새 비밀번호 확인" value={again} onChange={(e) => setAgain(e.target.value)} required />
        <p className="faint small" style={{ margin: 0 }}>
          바꾸면 모든 기기에서 로그아웃되고 다시 로그인해야 합니다.
        </p>
        <button type="submit" className="btn btn-primary">
          변경
        </button>
        {msg && (
          <p className="err" role="alert">
            {msg}
          </p>
        )}
      </form>
    </Dialog>
  );
}

function RoleSelect({ value, onChange, label, disabled }: { value: Role; onChange: (r: Role) => void; label: string; disabled?: boolean }) {
  return (
    <select className="field" aria-label={label} value={value} disabled={disabled} onChange={(e) => onChange(e.target.value as Role)}>
      {(Object.keys(ROLE_LABEL) as Role[]).map((r) => (
        <option key={r} value={r}>
          {ROLE_LABEL[r]}
        </option>
      ))}
    </select>
  );
}

// ── IOC 내보내기(검토관 이상): 담당자가 위협으로 확정한 사건의 지표를 CSV·STIX 2.1 로 ─────────────
const IOC_TYPE: Record<string, string> = dict({
  url: "URL", domain: "도메인", ipv4: "IPv4", ipv6: "IPv6", telegram: "텔레그램", kakao: "카카오톡", line: "라인", whatsapp: "왓츠앱",
  discord: "디스코드", phone: "휴대전화", account: "입금 계좌", form: "입력값을 보내는 곳",
});
const IOC_EXCLUDED: Record<string, string> = dict({
  official: "공식 브랜드·사행사업자 도메인", generic: "흔한 대형 사이트", service: "사이트 빌더·서비스 홈", internal: "내부·예약 IP",
  shortener: "단축 서비스(호스트)", shortener_page: "단축 서비스의 안내 화면", shared_root: "공용 호스팅 본 도메인",
  elsewhere: "다른 사이트의 최종 주소(누른 링크일 수 있음)", unverified_destination: "단축 URL 목적지를 확인하지 못함", widget: "입력 위젯(번역 등)",
  pii: "주소에 개인정보 모양", format: "형식 오류",
});
const IOC_DAYS = [1, 7, 30, 90];

function IocDialog({ onClose }: { onClose: () => void }) {
  const [days, setDays] = useState(30);
  const [contacts, setContacts] = useState(false);
  const [sum, setSum] = useState<IocSummary | null>(null);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState<"" | "csv" | "stix">("");
  useEffect(() => {
    let live = true;
    setSum(null);
    setMsg("");
    iocSummary(days, contacts).then(
      (s) => live && setSum(s),
      (e: Error) => live && setMsg(e.message),
    );
    return () => {
      live = false;
    };
  }, [days, contacts]);
  const listed = (xs: [string, number][], label: Record<string, string>) => xs.map(([k, n]) => `${label[k] ?? k} ${n}`).join(" · ") || "없음";
  const get = async (fmt: "csv" | "stix") => {
    setBusy(fmt);
    setMsg("");
    try {
      await downloadIoc(fmt, days, contacts);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "내려받기 실패");
    } finally {
      setBusy("");
    }
  };
  const c = sum?.contacts;
  return (
    <Dialog title="IOC 내보내기" onClose={onClose}>
      <p className="small" style={{ margin: 0 }}>
        담당자가 <b>위협으로 확정</b>한 사건의 지표(신고 주소·최종 주소의 URL·도메인·IP)를 다른 기관·차단 장비가 읽는 형식으로 내려받습니다. 공식 브랜드 도메인·흔한 대형
        사이트·단축 서비스와 공용 호스팅의 본 도메인, 개인정보가 든 주소는 빼고 URL 의 쿼리는 지웁니다. 최종 주소는 신고 주소와 같은 사이트이거나 신고 주소가 단축 URL 일
        때만 넣습니다(다른 사이트면 조사 중 누른 링크일 수 있어서).
      </p>
      <div className="ioc-opts">
        <label>
          확정 기간{" "}
          <select className="field" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {IOC_DAYS.map((d) => (
              <option key={d} value={d}>
                최근 {d}일
              </option>
            ))}
          </select>
        </label>
        <label className="ioc-check">
          <input type="checkbox" checked={contacts} onChange={(e) => setContacts(e.target.checked)} /> 운영 정보 포함(텔레그램·카카오톡·입력값을 보내는 곳·전화·계좌)
        </label>
      </div>
      {contacts && (
        <p className="warn small" style={{ margin: 0 }}>
          전화·계좌는 페이지에 적힌 원래 값입니다. 받는 기관과 처리 근거를 확인한 뒤 내보내세요.
        </p>
      )}
      {msg && (
        <p className="err" role="alert">
          {msg}
        </p>
      )}
      {sum ? (
        <table className="users ioc-sum">
          <tbody>
            <tr>
              <th>사건</th>
              <td>
                {sum.cases}건 · 연관 묶음 {sum.groups}개
                {sum.truncated && <span className="warn"> · 상한(사건 {sum.limits.cases}건·지표 {sum.limits.indicators}개)에서 잘림, 기간을 줄이세요</span>}
              </td>
            </tr>
            <tr>
              <th>지표</th>
              <td>
                {sum.indicators}개 · {listed(sum.byType, IOC_TYPE)}
              </td>
            </tr>
            <tr>
              <th>위협 유형</th>
              <td>{listed(sum.byThreat, THREAT_LABEL)}</td>
            </tr>
            <tr>
              <th>뺀 것</th>
              <td>{listed(sum.excluded, IOC_EXCLUDED)}</td>
            </tr>
            {c?.included && (
              <tr>
                <th>운영 정보</th>
                <td>
                  증거 체인을 검증한 {c.verified}건에서
                  {c.unverified > 0 && ` · 검증하지 못해 뺀 ${c.unverified}건`}
                  {c.overLimit > 0 && ` · 최신 ${sum.limits.chainCases}건만(나머지 ${c.overLimit}건 뺌)`}
                  {sum.stixSkipped > 0 && ` · STIX 표준 형식이 없는 ${sum.stixSkipped}개(전화·계좌 등)는 CSV 에만`}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      ) : (
        !msg && <p className="muted small">세는 중…</p>
      )}
      <div className="ioc-actions">
        <button type="button" className="btn btn-primary" disabled={!sum || sum.indicators === 0 || !!busy} onClick={() => get("csv")}>
          {busy === "csv" ? "만드는 중…" : "CSV 내려받기"}
        </button>
        <button type="button" className="btn btn-ghost" disabled={!sum || sum.indicators === 0 || !!busy} onClick={() => get("stix")}>
          {busy === "stix" ? "만드는 중…" : "STIX 2.1 내려받기"}
        </button>
      </div>
      <p className="faint small" style={{ margin: 0 }}>
        내려받기는 감사로그에 남습니다. 같은 값은 내보낼 때마다 같은 STIX id 라 받는 쪽이 중복을 거를 수 있고, 연관 묶음은 STIX campaign 으로 들어갑니다.
      </p>
    </Dialog>
  );
}

function UsersDialog({ me: current, onClose }: { me: Me; onClose: () => void }) {
  const [users, setUsers] = useState<UserOut[]>([]);
  const [msg, setMsg] = useState("");
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [role, setRole] = useState<Role>("investigator");
  const load = useCallback(() => listUsers().then(setUsers, (e: Error) => setMsg(e.message)), []);
  useEffect(() => {
    load();
  }, [load]);
  const act = async (f: () => Promise<unknown>) => {
    setMsg("");
    try {
      await f();
      await load();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "실패");
    }
  };
  return (
    <Dialog title="계정 관리" onClose={onClose}>
      <form
        className="user-new"
        onSubmit={(e) => {
          e.preventDefault();
          act(async () => {
            await createUser(name.trim(), pw, role);
            setName("");
            setPw("");
          });
        }}
      >
        <input className="field mono" placeholder="아이디" aria-label="새 아이디" value={name} onChange={(e) => setName(e.target.value)} required />
        <input className="field" type="password" autoComplete="new-password" placeholder="초기 비밀번호(12자 이상)" aria-label="초기 비밀번호" value={pw} onChange={(e) => setPw(e.target.value)} required />
        <RoleSelect label="새 계정 역할" value={role} onChange={setRole} />
        <button type="submit" className="btn btn-primary">
          추가
        </button>
      </form>
      {msg && (
        <p className="err" role="alert">
          {msg}
        </p>
      )}
      <table className="users">
        <thead>
          <tr>
            <th>아이디</th>
            <th>역할</th>
            <th>상태</th>
            <th>
              <span className="sr">조치</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => {
            const self = u.username === current.name;
            return (
              <tr key={u.username}>
                <td className="mono">{u.username}</td>
                <td>
                  <RoleSelect label={`${u.username} 역할`} value={u.role} disabled={self} onChange={(r) => act(() => patchUser(u.username, { role: r }))} />
                </td>
                <td className="small">{!u.active ? "비활성" : u.locked ? "잠김" : "활성"}</td>
                <td className="users-act">
                  {u.locked && (
                    <button type="button" className="btn btn-text" onClick={() => act(() => patchUser(u.username, { unlock: true }))}>
                      잠금 풀기
                    </button>
                  )}
                  {!self && (
                    <button type="button" className="btn btn-text" onClick={() => act(() => patchUser(u.username, { active: !u.active }))}>
                      {u.active ? "끄기" : "켜기"}
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="faint small" style={{ margin: 0 }}>
        역할을 바꾸거나 끄면 그 계정의 로그인이 바로 끊깁니다. 비밀번호를 잊은 계정은 명령줄(python -m safetrace.accounts passwd)로 재설정합니다.
      </p>
    </Dialog>
  );
}

// ── 왼쪽: 접수 버튼 + 분류 폴더 ─────────────────────────
function FolderNav({
  cases,
  folder,
  onFolder,
  groupsOn,
  onGroups,
  canCreate,
  onCreated,
}: {
  cases: CaseOut[];
  folder: FolderId | null;
  onFolder: (f: FolderId) => void;
  groupsOn: boolean;
  onGroups: () => void;
  canCreate: boolean;
  onCreated: (c: CaseOut) => void;
}) {
  const [adding, setAdding] = useState(false);
  return (
    <nav className="folders scroll" aria-label="사건 분류">
      {canCreate && (
        <button type="button" className="btn btn-primary new-case-btn" aria-expanded={adding} onClick={() => setAdding((v) => !v)}>
          {adding ? "접수 닫기" : "+ 신고 URL 접수"}
        </button>
      )}
      {adding && (
        <NewCase
          onCreated={(c) => {
            setAdding(false);
            onCreated(c);
          }}
        />
      )}
      {FOLDERS.map((f) => (
        <button key={f.id} type="button" className="folder" aria-current={f.id === folder} onClick={() => onFolder(f.id)}>
          <span className="folder-mark" style={{ background: f.color }} />
          <span className="folder-label">{f.label}</span>
          <span className="folder-n">{cases.filter(f.test).length}</span>
        </button>
      ))}
      <button type="button" className="folder" aria-current={groupsOn} onClick={onGroups}>
        <span className="folder-mark" style={{ background: "var(--review)" }} />
        <span className="folder-label">연관 묶음</span>
        <span className="folder-n" />
      </button>
      <p className="folder-note">
        AI 판단은 참고 의견입니다.
        <br />
        최종 판정은 검토관 이상 담당자가 합니다.
      </p>
    </nav>
  );
}

// ── 가운데: 사건 목록(지금 폴더) ──────────────────────────
function CaseList({
  title,
  cases,
  selected,
  error,
  query,
  onQuery,
  source,
  onSource,
  onSelect,
  monitor,
}: {
  title: string;
  cases: CaseOut[];
  selected: string | null;
  error: string;
  query: string;
  onQuery: (q: string) => void;
  source: string;
  onSource: (s: string) => void;
  onSelect: (id: string) => void;
  monitor: React.ReactNode;
}) {
  return (
    <section className="caselist" aria-label="사건 목록">
      {monitor}
      <div className="caselist-head">
        <h2>{title}</h2>
        <span className="muted small">{cases.length}건</span>
        <div className="spacer" />
        <label className="sr" htmlFor="case-search">
          URL 검색
        </label>
        <label className="sr" htmlFor="case-source">
          출처
        </label>
        <select id="case-source" className="field source-filter" value={source} onChange={(e) => onSource(e.target.value)}>
          <option value="">모든 출처</option>
          <option value="report">신고</option>
          <option value="kisa">KISA</option>
          <option value="related">연관</option>
          <option value="test">시험</option>
        </select>
        <input id="case-search" className="field search" type="search" placeholder="URL 검색" value={query} maxLength={200} onChange={(e) => onQuery(e.target.value)} />
      </div>
      {error && (
        <p className="err" style={{ padding: "8px 16px" }}>
          {error}
        </p>
      )}
      <ul className="rows scroll">
        {cases.map((c) => (
          <li key={c.id}>
            <button type="button" className="row" aria-current={c.id === selected} onClick={() => onSelect(c.id)}>
              <span className={unread(c) ? "row-dot on" : "row-dot"} />
              <span className={unread(c) ? "row-host unread" : "row-host"} title={c.url}>
                {unread(c) && <span className="sr">확인 필요 · </span>}
                {clip(hostPath(c.url), 60)}
              </span>
              <span className="row-time">{fmtTime(c.created_at)}</span>
              <span className="row-sub">
                {c.source === "related" && <span className="row-badge">{c.auto ? "연관·자동" : "연관"}</span>}
                {caseSummary(c)}
              </span>
              <StatusChip c={c} />
            </button>
          </li>
        ))}
        {cases.length === 0 && <li className="rows-empty">해당하는 사건이 없습니다.</li>}
      </ul>
    </section>
  );
}

// ── 실시간 화면(목록 칸 맨 위, 항상 표시): 에이전트는 한 번에 한 건을 조사한다 ─────────────
function LiveMonitor({ cases, onOpen, onEnded }: { cases: CaseOut[]; onOpen: (id: string) => void; onEnded: () => void }) {
  const running = cases.find((c) => c.status === "RUNNING" && !c.auto) ?? cases.find((c) => c.status === "RUNNING");
  // 목록은 최신순이므로 가장 오래된 대기 사건(다음 차례)은 뒤에서 찾는다
  const queued = running ? undefined : [...cases].reverse().find((c) => c.status === "QUEUED");
  return (
    <section className="monitor" aria-label="실시간 조사 화면">
      {running ? (
        <Boundary key={running.id} what="실시간 화면">
          <MonitorCase c={running} onOpen={onOpen} onEnded={onEnded} />
        </Boundary>
      ) : (
        <>
          <div className="monitor-head">
            <h2 className="monitor-title">{queued ? "대기 중" : "실시간 화면"}</h2>
            {queued && <span className="monitor-host">{clip(hostPath(queued.url), 40)}</span>}
            {queued && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => onOpen(queued.id)}>
                열기
              </button>
            )}
          </div>
          <div className="monitor-screen monitor-empty">{queued ? "곧 조사를 시작합니다" : "지금 조사 중인 사건이 없습니다"}</div>
        </>
      )}
    </section>
  );
}

// 실행 중인 사건 하나: 자기 /events 를 따로 구독한다(사건이 바뀌면 key 로 다시 만들어 이전 연결을 끊는다).
// 기록 전체를 쌓지 않고 화면에 필요한 요약(관찰 수·마지막 화면·마지막 선택)만 갱신한다(믿지 않는 기록이 몰려와도 메모리가 늘지 않게)
type MonitorView = {
  maxSeq: number;
  steps: number;
  shot: string | null;
  cands: Map<string, string>;
  act: Act | null;
  sub: number; // 연관 후보 하위 조사 번호(0 = 원래 주소)
  subTotal: number;
  subHost: string;
};
type Act = { what: string; prob: number; running: boolean };
const EMPTY_VIEW: MonitorView = { maxSeq: -1, steps: 0, shot: null, cands: new Map(), act: null, sub: 0, subTotal: 0, subHost: "" };

function MonitorCase({ c, onOpen, onEnded }: { c: CaseOut; onOpen: (id: string) => void; onEnded: () => void }) {
  const [view, setView] = useState<MonitorView>(EMPTY_VIEW);
  const [ended, setEnded] = useState(false);
  const [fps, setFps] = useState(0);
  const [videoOff, setVideoOff] = useState(false);
  const [videoShown, setVideoShown] = useState(false); // 실시간 영상이 한 번이라도 그려졌다(끝나도 마지막 프레임을 둔다)
  const endedRef = useRef(onEnded);
  endedRef.current = onEnded;

  useEffect(() => {
    const ac = new AbortController();
    streamEvents(
      c.id,
      (e: AgentEvent) => {
        if (e.type === "evidence") setView((v) => (e.seq <= v.maxSeq ? v : step(v, e)));
        if (e.type === "status" && TERMINAL.has(e.status)) {
          setEnded(true);
          endedRef.current(); // 목록을 바로 다시 받아 다음 사건으로 넘어간다
        }
      },
      ac.signal,
    ).catch(() => undefined);
    return () => ac.abort();
  }, [c.id]);

  const { steps, shot, act } = view;
  // 클릭 표시: 영상과 같은 통로로 와서 같은 재생 버퍼를 거친다(누르기 직전 화면에 맞춰 보인다). n 이 바뀔 때 물결.
  // 다음 클릭을 미리 알 수 없으니 메시지가 온 뒤 커서가 앞 클릭 자리에서 이동하고, 도착하면 누른 표시를 한다
  const [click, setClick] = useState<{ p: ClickPoint; travel: number; n: number } | null>(null);
  const onClick = useCallback((p: ClickPoint) => setClick((c) => ({ p, travel: cursorTravel(c?.p ?? null, p), n: (c?.n ?? 0) + 1 })), []);
  // 연관 사이트 하위 조사는 새 브라우저에서 다른 사이트를 연다: 앞 조사에서 누른 자리의 커서를 지우고, 그 조사의 첫 클릭 때
  // 그 자리에서 다시 나타낸다(지우지 않으면 클릭 없이 스크롤만 하는 하위 조사 내내 다른 사이트 위에 커서가 멈춰 있었다)
  useEffect(() => setClick(null), [view.sub]);
  // 지금 하는 일: 화면이 멈춘 동안(관찰·판단·로딩 대기) 에이전트가 무엇을 하는지 실시간 화면 위에 보인다. since 는 바뀐 시각(경과 초)
  const [activity, setActivity] = useState<{ label: string; since: number } | null>(null);
  const onActivity = useCallback((a: Activity) => setActivity({ label: a.label, since: performance.now() }), []);
  const still = shot ? <LiveScreen caseId={c.id} name={shot} /> : <span className="small">첫 화면을 기다리는 중…</span>;
  return (
    <>
      <div className="monitor-head">
        <span className="monitor-live">
          <span className="dot" />
          LIVE
        </span>
        <h2 className="monitor-title">{ended ? "조사 끝남" : view.sub ? `연관 사이트 ${view.sub}/${view.subTotal || view.sub}` : "지금 조사 중"}</h2>
        <span className="monitor-host" title={view.sub ? view.subHost : c.url}>
          {clip(view.sub && view.subHost ? view.subHost : hostPath(c.url), 40)}
        </span>
        <button type="button" className="btn btn-ghost btn-sm" aria-label="조사 중인 사건 상세 보기" onClick={() => onOpen(c.id)}>
          상세 보기
        </button>
      </div>
      <div className="monitor-screen screen-body">
        {/* 조사가 끝나도 영상이 그려졌으면 마지막 프레임을 둔다(정지 화면으로 바꾸면 다시 받는 동안 어두운 바탕이 보였다) */}
        {!videoOff && (!ended || videoShown) ? (
          <LiveVideo
            caseId={c.id}
            onFps={setFps}
            onEnd={() => setVideoOff(true)}
            onShown={() => setVideoShown(true)}
            onClick={onClick}
            onActivity={onActivity}
            fallback={still}
          />
        ) : (
          still
        )}
        {click && !ended && !videoOff && <ClickMark p={click.p} hitKey={click.n} align="top" travel={click.travel} hitDelay={click.travel} />}
        {activity && !ended && !videoOff && <ActivityChip label={activity.label} since={activity.since} />}
        <span className="monitor-meta">
          {fps > 0 && !videoOff ? `${fps}fps · ` : ""}
          {String(steps).padStart(2, "0")}/{Math.max(MAX_STEPS, steps)}
        </span>
      </div>
      <div className="monitor-foot">
        {act ? (
          <>
            <span className="monitor-jev">Jev 선택</span>
            <span className="monitor-act">
              {act.what}
              {act.running ? " → 실행 중" : ""}
            </span>
            <span className="monitor-prob">{pct(act.prob)}</span>
          </>
        ) : (
          <span className="muted">첫 관찰을 기다리는 중</span>
        )}
      </div>
    </>
  );
}

// 실시간 화면 왼쪽 아래: 에이전트가 지금 하는 일(고정 문구)과 그 일을 시작한 뒤 지난 초(1초부터). 초가 늘어 멈춘 화면도 조사가 계속되는 것을 보인다
function ActivityChip({ label, since }: { label: string; since: number }) {
  const [now, setNow] = useState(() => performance.now());
  useEffect(() => {
    const t = setInterval(() => setNow(performance.now()), 500);
    return () => clearInterval(t);
  }, []);
  const sec = Math.floor((now - since) / 1000);
  return (
    <span className="monitor-activity" role="status" aria-live="polite">
      <span className="pulse" aria-hidden="true" />
      {label}
      {sec >= 1 && <span className="monitor-activity-sec">{sec}초</span>}
    </span>
  );
}

// 기록 하나로 요약을 갱신한다. 후보 글자는 바로 앞 관찰에서 찾는다(행동 기록과 같은 방식)
function step(v: MonitorView, e: EvidenceEvent): MonitorView {
  const d = e.data;
  const next = { ...v, maxSeq: e.seq };
  const png = e.files.find((f) => f.endsWith(".png"));
  if ((e.kind === "observe" || e.kind === "finish") && png) next.shot = png;
  if (e.kind === "candidates") next.subTotal = Math.max(0, Math.min(10, Math.trunc(num(d.investigated)) || 0));
  if (e.kind === "start" && typeof d.sub === "number" && Number.isInteger(d.sub) && d.sub > 0 && d.sub <= 10) {
    next.sub = d.sub;
    next.subHost = clip(hostOf(text(d.url, 2000)), 60);
  }
  if (e.kind === "observe") {
    if (typeof d.sub !== "number") next.steps = v.steps + 1;
    next.cands = new Map(clickables(d.candidates).map((x) => [x.id, x.text]));
  } else if (e.kind === "decision") {
    const choice = text(d.choice, 60);
    const eid = choice.startsWith("click_") ? choice.slice(6) : "";
    next.act = { what: eid ? `“${clip(v.cands.get(eid) ?? eid, 40)}” 클릭` : (ACTION_LABEL[choice] ?? choice), prob: num(d.probability), running: true };
  } else if (v.act && (e.kind === "action" || (e.kind === "gate" && d.allowed === false) || e.kind === "action_error")) {
    next.act = { ...v.act, running: false };
  }
  return next;
}

function StatusChip({ c }: { c: CaseOut }) {
  if (relatedRunning(c)) {
    return (
      <>
        <StatusChip c={asMain(c)} />
        <span className="chip st-RUNNING">연관 사이트 조사 중</span>
      </>
    );
  }
  // 담당자가 확정한 사건은 판정을 먼저 보여 준다
  const v = c.verdict;
  if (v?.decision === "threat") return <span className="chip st-threat">■ {THREAT_LABEL[v.threat ?? ""] ?? v.threat} 확정</span>;
  if (v?.decision === "benign") return <span className="chip st-COMPLETED">✓ 정상 확정</span>;
  // 위협으로 판단돼 조사가 끝난 사건은 위협 유형을 위험색으로 보여 준다
  if (c.status === "COMPLETED" && c.threat && !["benign", "unknown"].includes(c.threat.threat)) {
    return (
      <span className="chip st-threat">
        ■ {THREAT_LABEL[c.threat.threat] ?? c.threat.threat} {pct(c.threat.probability)}
      </span>
    );
  }
  return (
    <span className={`chip st-${c.status}`}>
      {STATUS_GLYPH[c.status] ?? "●"} {STATUS_LABEL[c.status] ?? c.status}
    </span>
  );
}

function caseSummary(raw: CaseOut): string {
  const c = asMain(raw);
  if (c.status === "RUNNING" || c.status === "QUEUED") return "에이전트가 조사하는 중";
  const parts: string[] = [];
  if (c.verdict?.decision === "hold") parts.push("담당자 보류");
  if (c.threat) parts.push(`${THREAT_LABEL[c.threat.threat] ?? c.threat.threat} ${pct(c.threat.probability)}`);
  if (c.finish_reason) parts.push(REASON_LABEL[c.finish_reason] ?? c.finish_reason);
  return parts.join(" · ") || "-";
}

function NewCase({ onCreated }: { onCreated: (c: CaseOut) => void }) {
  const [url, setUrl] = useState("");
  const [source, setSource] = useState("report");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  return (
    <form
      className="new"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setMsg("");
        try {
          onCreated(await createCase(url.trim(), source));
          setUrl("");
        } catch (err) {
          setMsg(err instanceof Error ? err.message : "접수 실패");
        } finally {
          setBusy(false);
        }
      }}
    >
      <label className="sr" htmlFor="new-url">
        신고 URL
      </label>
      <input id="new-url" className="field mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" maxLength={2048} required autoFocus />
      <div className="new-row">
        <label className="sr" htmlFor="new-source">
          출처
        </label>
        <select id="new-source" className="field" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="report">신고</option>
          <option value="kisa">KISA 피싱 URL</option>
          <option value="test">시험 페이지</option>
        </select>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "접수 중…" : "조사 시작"}
        </button>
      </div>
      {msg && <p className="err">{msg}</p>}
    </form>
  );
}

function EmptyWorkspace() {
  return (
    <div className="empty">
      <h2>사건을 선택하거나 신고 URL을 접수하세요</h2>
      <p>
        AI 에이전트가 격리 브라우저에서 버튼을 눌러 가며 숨겨진 화면까지 조사합니다. 입력·제출·결제·다운로드는 코드가
        막으며, 모든 행동과 화면은 서명된 증거로 남습니다. 최종 판정은 담당자가 합니다.
      </p>
    </div>
  );
}

// ── 오른쪽: 선택한 사건(상태 줄 · AI 의견 · 조사 화면 · 증거 · 판정 막대) ─────────────
const Workspace = memo(function Workspace({
  id,
  canDecide,
  canAct,
  canExport,
  onDecided,
  onOpen,
  onPrev,
  onNext,
}: {
  id: string;
  canDecide: boolean;
  canAct: boolean;
  canExport: boolean;
  onDecided: () => void;
  onOpen: (id: string) => void;
  onPrev: (() => void) | null;
  onNext: (() => void) | null;
}) {
  const [c, setC] = useState<CaseOut | null>(null);
  const [events, setEvents] = useState<EvidenceEvent[]>([]);
  const [status, setStatus] = useState("");
  const [live, setLive] = useState(false);

  const [overflow, setOverflow] = useState(false);
  useEffect(() => {
    const ac = new AbortController();
    const seen = new Set<number>();
    setLive(true);
    streamEvents(
      id,
      (e: AgentEvent) => {
        if (e.type === "evidence" && !seen.has(e.seq)) {
          if (seen.size >= MAX_EVENTS) return setOverflow(true); // 정상 사건은 수백 건. 넘치면 더 받지 않고 알린다
          seen.add(e.seq);
          setEvents((prev) => [...prev, e]);
        }
        if (e.type === "status") {
          setStatus(e.status);
          if (TERMINAL.has(e.status) || e.phase === "related") getCase(id).then(setC).catch(() => undefined);
        }
      },
      ac.signal,
    )
      .catch(() => undefined)
      .finally(() => setLive(false));
    getCase(id).then(setC).catch(() => undefined);
    return () => ac.abort();
  }, [id]);

  const sorted = useMemo(() => [...events].sort((a, b) => a.seq - b.seq), [events]);
  // 끝난 사건은 사건 자체의 상태를 쓴다(SSE 는 지난 '조사 중' 상태부터 다시 보내 준다)
  const st = c && TERMINAL.has(c.status) ? c.status : c ? status || c.status : "";
  // 상태를 아직 모르면(사건·기록을 받는 중) 조사 중으로 치지 않는다: 끝난 사건을 열 때 실시간 연결을 열었다 닫지 않게
  // 원래 결과가 나오면(연관 사이트 조사 중) 요약·근거·판정은 원래 결과로 보여 주고, 내려받기·검증만 끝날 때까지 막는다
  const related = !!c && c.phase === "related" && st === "RUNNING";
  const running = (st === "RUNNING" || st === "QUEUED") && !related;
  const steps = sorted.filter((e) => e.kind === "observe" && typeof e.data.sub !== "number").length;
  const relatedTotal = num([...sorted].reverse().find((e) => e.kind === "candidates")?.data.investigated);
  const relatedSeen = new Set(sorted.filter((e) => typeof e.data.sub === "number").map((e) => e.data.sub)).size;
  const reasons = useMemo(() => (c && !running ? buildReasons(sorted, c) : []), [sorted, c, running]);
  const screens = useMemo(() => buildScreens(reasons, sorted), [reasons, sorted]);
  const [tab, setTab] = useState<TabId>("screens");
  const [pick, setPick] = useState<string | null>(null);
  const [verify, setVerify] = useState<VerifyState>(null);
  // 사건을 열면 근거 화면 탭, 첫 근거 카드의 화면. 화면 기록이 없는 사건(접속 불가 등)은 행동 기록 탭
  const opened = useRef(false);
  useEffect(() => {
    // 기록을 다 받은 뒤(SSE 가 끝 상태를 보낸 뒤)에 정한다. 그 전에는 화면 목록이 비어 보일 수 있다
    if (opened.current || !c || !(TERMINAL.has(status) || related)) return;
    opened.current = true;
    if (screens.length === 0) setTab("log");
    else setPick(screens[0].file);
  }, [status, c, screens, related]);
  const openScreen = (r: Reason) => {
    if (!r.shot) return;
    setTab("screens");
    setPick(r.shot);
  };
  return (
    <>
      <div className="detail-body">
        <div className="statusline">
          {related && c ? (
            <StatusChip c={c} />
          ) : (
            <span className={`chip st-${st}`}>
              {STATUS_GLYPH[st] ?? "●"} {STATUS_LABEL[st] ?? (st || "불러오는 중")}
            </span>
          )}
          {related && Number.isFinite(relatedTotal) && (
            <span className="muted small">
              연관 사이트 {Math.min(relatedSeen, relatedTotal)}/{relatedTotal}
            </span>
          )}
          {c && (
            <span className="muted">
              {fmtDateTime(c.created_at)} 접수 · {steps}단계 관찰
            </span>
          )}
          <div className="spacer" />
          <button type="button" className="btn btn-ghost btn-sm" disabled={!onPrev} onClick={() => onPrev?.()}>
            ‹ 이전 사건
          </button>
          <button type="button" className="btn btn-ghost btn-sm" disabled={!onNext} onClick={() => onNext?.()}>
            다음 사건 ›
          </button>
        </div>
        {overflow && (
          <p className="err" role="alert">
            기록이 {MAX_EVENTS}건을 넘어 그 뒤는 화면에 표시하지 않았습니다. 전체 기록은 검토 패키지로 확인하세요.
          </p>
        )}
        {c?.parent_id && (
          <p className="parent-link">
            <span className="chip st-RUNNING">{c.auto ? "연관·자동" : "연관"}</span> 연관 사이트 ·{" "}
            <button type="button" className="linkish" onClick={() => onOpen(c.parent_id as string)}>
              {clip(hostPath(c.parent_url ?? ""), 60)}
            </button>{" "}
            사건에서 {c.auto ? "자동 발견" : "발견"}
          </p>
        )}
        <Summary c={c} running={running} reasons={reasons} picked={tab === "screens" ? pick : null} onPick={openScreen} />
        {!st ? (
          <p className="muted">{live ? "사건을 불러오는 중…" : "사건을 불러오지 못했습니다"}</p>
        ) : running ? (
          <Investigation c={c} events={sorted} status={st} running={running} id={id} />
        ) : (
          <section className="panel progress-panel" aria-label="조사 경과">
            <CaseTabs
              id={id}
              c={c}
              events={sorted}
              screens={screens}
              tab={tab}
              onTab={setTab}
              pick={pick}
              onPick={setPick}
              related={related}
              canCreate={canExport}
              canAct={canAct}
              onOpen={onOpen}
              onChanged={() => {
                getCase(id).then(setC).catch(() => undefined);
                onDecided();
              }}
            />
            <CaseFooterBar c={c} id={id} running={running || related} related={related} canExport={canExport} verify={verify} onVerify={setVerify} />
          </section>
        )}
      </div>
      <VerdictBar
        c={c}
        id={id}
        running={running}
        canDecide={canDecide}
        onNext={onNext}
        onDecided={() => {
          getCase(id).then(setC).catch(() => undefined);
          onDecided();
        }}
      />
    </>
  );
});

function Investigation({
  c,
  events,
  status,
  running,
  id,
}: {
  c: CaseOut | null;
  events: EvidenceEvent[];
  status: string;
  running: boolean;
  id: string;
}) {
  const steps = events.filter((e) => e.kind === "observe").length;
  // 통계·광고 전송 차단(페이지 이동이 아닌 blocked_request): 체인에는 남기되 위협 증거 수로 읽히지 않게 따로 센다
  const blockedSends = events.filter((e) => e.kind === "blocked_request" && !e.data.navigation).length;
  // 움직이는 화면은 목록 칸의 실시간 화면이 보여 준다. 여기서는 가장 최근 관찰 화면(페이지 전체)에 Jev 가 본 것을 겹친다:
  // 금지 요소(빨간 점선) → Jev 가 고른 버튼(파랑) → 안전 게이트가 막은 클릭(빨간 실선). 선택·게이트 기록이 오면 바로 덧그린다
  const obs = [...events].reverse().find((e) => e.kind === "observe" && e.files.some((f) => f.endsWith(".png")));
  const shot = obs?.files.find((f) => f.endsWith(".png"));
  const overlay = obs ? buildOverlay(events, obs.seq) : null;
  const nForbidden = overlay?.marks.filter((m) => m.kind === "forbidden").length ?? 0;
  const act = overlay?.marks.find((m) => m.kind !== "forbidden");
  const dec = obs ? events.find((e) => e.kind === "decision" && e.data.observe_seq === obs.seq) : undefined;
  const choice = dec ? text(dec.data.choice) : "";
  // 표시할 상자가 없는 선택(스크롤·팝업 닫기·뒤로, 상자를 못 잰 클릭)은 글자로만
  const decText = !dec ? "Jev 가 고르는 중…" : `Jev 선택 · ${choice.startsWith("click_") ? "버튼 클릭(화면 위치 없음)" : (ACTION_LABEL[choice] ?? choice)}`;
  const [marksOn, setMarksOn] = useState(true);
  const browser = events.find((e) => e.kind === "browser")?.data as { version?: string } | undefined;
  const lastUrl = [...events].reverse().find((e) => e.kind === "observe")?.data.url as string | undefined;
  const sub = obs && typeof obs.data.sub === "number" ? obs.data.sub : 0; // 연관 후보 하위 조사 번호
  const total = Math.max(MAX_STEPS, steps);

  return (
    <section className="panel live" aria-label="조사 화면">
      <div className="live-head">
        {running ? (
          <span className="chip st-RUNNING">
            <span className="dot" />
            LIVE
          </span>
        ) : (
          <span className={`chip st-${status}`}>
            {STATUS_GLYPH[status] ?? "●"} {STATUS_LABEL[status] ?? status}
          </span>
        )}
        <h1 className="live-title">{c ? hostOf(c.url) : "불러오는 중"}</h1>
        <span className="live-url">{lastUrl ?? c?.url}</span>
        <div className="spacer" />
        <div className="progress" role="img" aria-label={`${total}단계 중 ${steps}단계`}>
          {Array.from({ length: total }, (_, i) => (
            <span key={i} className={i < steps - 1 ? "on" : i === steps - 1 ? "now" : ""} />
          ))}
        </div>
        <span className="mono muted small">
          {String(steps).padStart(2, "0")}/{total}
        </span>
      </div>

      <div className="stage">
        <div className="screen">
          <div className="screen-bar">
            <span className="obs-title">
              관찰 화면{sub ? ` · 연관 후보 ${sub}` : ""}
              {obs && typeof obs.data.step === "number" ? ` · ${obs.data.step + 1}단계` : ""}{/* 기록은 0부터, 머리 줄 진행 표시처럼 1부터 */}
            </span>
            <span className="obs-note">
              Jev 가 본 화면 · 움직이는 화면은 왼쪽 실시간 화면{obs && text(obs.data.capture) === "expanded" ? ` · ${EXPANDED_NOTE}` : ""}
            </span>
            <span className="obs-env">격리 브라우저{browser?.version ? ` · Chromium ${browser.version.split(".")[0]}` : ""} · 검문 프록시 경유</span>
          </div>
          <div className="screen-body">
            {shot ? (
              <LiveScreen caseId={id} name={shot} overlay={marksOn ? overlay : null} />
            ) : (
              <span className="muted small">첫 관찰을 기다리는 중…</span>
            )}
          </div>
        </div>
        <div className="mark-legend" aria-live="polite">
          {nForbidden > 0 && <span className="lg lg-forbidden">금지 요소 {nForbidden}</span>}
          {act ? <span className={`lg lg-${act.kind}`}>{act.label}</span> : shot && <span className="muted">{decText}</span>}
          {overlay && (
            <button type="button" className="btn btn-ghost btn-sm" aria-pressed={marksOn} onClick={() => setMarksOn(!marksOn)}>
              {marksOn ? "화면 표시 끄기" : "화면 표시 켜기"}
            </button>
          )}
        </div>
      </div>

      <section className="log scroll" aria-label="에이전트 행동 기록">
        <div className="log-head">
          <h2 className="lbl">에이전트 행동 기록</h2>
          <span className="mono faint small">
            기록 {events.length}건{blockedSends > 0 ? ` (전송 차단 ${blockedSends}건 포함)` : ""}
          </span>
        </div>
        <EventLog events={events} />
      </section>
    </section>
  );
}

function hostOf(u: string) {
  try {
    return new URL(u).host;
  } catch {
    return u;
  }
}

// ── 행동 기록: 최신이 위. 통계·광고 전송 차단(페이지 이동이 아닌 POST 등)은 한 줄로 묶는다 ──
type Line = { seq: number; icon: keyof typeof ICONS; tone: "" | "red" | "orange" | "teal"; text: React.ReactNode; end?: React.ReactNode; endTone?: string };

function EventLog({ events }: { events: EvidenceEvent[] }) {
  let candidates = new Map<string, string>(); // 직전 관찰의 클릭 후보(id → 글자)
  const lines: Line[] = [];
  const quiet: EvidenceEvent[] = [];
  for (const e of events) {
    const d = e.data as Record<string, unknown>;
    const sub = typeof d.sub === "number" ? d.sub : 0; // 연관 후보 하위 조사 번호
    const before = lines.length;
    if (e.kind === "start" && sub) {
      lines.push({ seq: e.seq, icon: "globe", tone: "orange", text: <>하위 조사 시작 · <span className="mono">{text(d.url)}</span></> });
    } else if (e.kind === "candidates") {
      const found = list(d.found);
      lines.push({ seq: e.seq, icon: "stack", tone: found.length ? "orange" : "", text: <>연관 후보 {found.length}곳 · {d.followup ? `하위 조사 ${text(d.investigated)}곳` : "정상으로 판단해 기록만"}</> });
    } else if (e.kind === "observe") {
      candidates = new Map(clickables(d.candidates).map((c) => [c.id, c.text]));
      const nf = list(d.forbidden).length;
      const skipped = num(d.ocr_skipped) || 0; // 시간이 없어 읽지 않은 이미지 버튼(선택지에서 뺌)
      lines.push({
        seq: e.seq, icon: "eye", tone: skipped ? "orange" : "",
        text: <>관찰 · {text(d.title) || text(d.url) || "-"}{skipped ? <span className="warn"> · 시간 부족으로 이미지 버튼 {skipped}개 읽지 않음</span> : null}</>,
        end: nf ? <span className="bad">금지 {nf} 제외</span> : `후보 ${list(d.candidates).length}`,
      });
    } else if (e.kind === "decision") {
      const choice = text(d.choice);
      const eid = choice.startsWith("click_") ? choice.slice(6) : "";
      const what = eid ? `“${candidates.get(eid) ?? eid}” 클릭` : ACTION_LABEL[choice] ?? choice;
      lines.push({ seq: e.seq, icon: "brain", tone: "", text: <>Jev 선택 · {what}</>, end: pct(num(d.probability)), endTone: "var(--primary)" });
    } else if (e.kind === "gate") {
      if (!d.allowed) lines.push({ seq: e.seq, icon: "ban", tone: "red", text: <span className="bad">안전 게이트 차단 · {text(d.reason)}</span>, end: "차단", endTone: "var(--threat)" });
    } else if (e.kind === "action") {
      const out = text(d.outcome);
      const noEffect = out.includes("no_effect") || out.includes("failed");
      lines.push({ seq: e.seq, icon: "cursor", tone: noEffect ? "orange" : "", text: <>실행 · {out} → <span className="mono faint">{text(d.result_url)}</span></>, end: noEffect ? "효과 없음" : "통과", endTone: noEffect ? "var(--review)" : "var(--safe)" });
    } else if (e.kind === "blocked_request") {
      if (d.navigation) lines.push({ seq: e.seq, icon: "ban", tone: "red", text: <span className="bad">페이지 이동 차단 · {text(d.reason)} <span className="mono">{text(d.url)}</span></span>, end: "차단", endTone: "var(--threat)" });
      else quiet.push(e);
    } else if (e.kind === "new_window") {
      lines.push({ seq: e.seq, icon: "window", tone: "", text: <>새 창 채택 · <span className="mono">{text(d.url)}</span></> });
    } else if (e.kind === "navigation") {
      const redirects = strs(d.redirects);
      lines.push({ seq: e.seq, icon: "globe", tone: redirects.length ? "orange" : "", text: <>최초 접속 {text(d.status)}{redirects.length ? ` · 리다이렉트 ${redirects.length}회` : ""}</> });
    } else if (e.kind === "dialog") {
      lines.push({ seq: e.seq, icon: "x", tone: "", text: <>대화상자 자동 닫기 · {text(d.message)}</> });
    } else if (e.kind === "unreachable") {
      lines.push({ seq: e.seq, icon: "ban", tone: "red", text: <span className="bad">접속 불가 · {NET_CATEGORY_LABEL[text(d.category)] ?? text(d.error)}{d.net_error ? ` (${text(d.net_error)})` : ""}</span> });
    } else if (e.kind === "escalation") {
      const why = d.reason === "unreachable_network_filtered"
        ? "회선의 도메인 차단 감지"
        : `Safe Browsing ${strs(d.threat_types).join(", ")}`;
      lines.push({ seq: e.seq, icon: "alert", tone: "orange", text: <span className="warn">담당자 검토로 전환 · {why}</span> });
    } else if (e.kind === "threat") {
      lines.push({ seq: e.seq, icon: "flag", tone: d.threat === "benign" ? "teal" : "orange", text: <>위협 판단 · {THREAT_LABEL[text(d.threat)] ?? text(d.threat)}{d.override ? ` (${overrideLabel(d.override as Threat["override"])})` : ""}</>, end: pct(num(d.probability)) });
    } else if (e.kind === "safebrowsing") {
      lines.push({ seq: e.seq, icon: "shieldCheck", tone: d.status === "match" ? "red" : "", text: <>Safe Browsing · {text(d.status)}</> });
    } else if (e.kind === "finish") {
      lines.push({ seq: e.seq, icon: "check", tone: "teal", text: <>탐색 종료 · {REASON_LABEL[text(d.reason)] ?? text(d.reason)}</> });
    } else if (e.kind === "action_error" || e.kind === "decision_error" || e.kind === "threat_error" || e.kind === "candidate_error") {
      lines.push({ seq: e.seq, icon: "alert", tone: "orange", text: <span className="warn">{e.kind} · {text(d.error)}</span> });
    }
    if (sub && lines.length > before) {
      const l = lines[lines.length - 1];
      l.text = <><span className="warn">후보 {sub} · </span>{l.text}</>;
    }
  }
  lines.reverse();
  if (lines.length === 0 && quiet.length === 0) return <p className="muted small">기록을 기다리는 중…</p>;
  return (
    <>
      {quiet.length > 0 && (
        <details className="fold">
          <summary className="ev">
            <span className="ev-icon">
              <Icon name="stack" />
            </span>
            <span className="ev-seq">묶음</span>
            <span className="ev-text muted">통계·광고 등 데이터 전송 차단 {quiet.length}건 (페이지 이동 아님 · 펼치기)</span>
            <span className="ev-end faint">{quiet.length}</span>
          </summary>
          <div className="fold-body">
            {quiet.map((e) => (
              <span key={e.seq}>
                EV-{e.seq} · {text(e.data.reason)} · {text(e.data.url)}
              </span>
            ))}
          </div>
        </details>
      )}
      {lines.map((l) => (
        <div key={l.seq} className="ev">
          <span className={`ev-icon ${l.tone}`}>
            <Icon name={l.icon} />
          </span>
          <span className="ev-seq">EV-{l.seq}</span>
          <span className="ev-text">{l.text}</span>
          <span className="ev-end" style={{ color: l.endTone }}>
            {l.end}
          </span>
        </div>
      ))}
    </>
  );
}

const DECISION_LABEL: Record<Decision, string> = { threat: "위협 확정", benign: "정상", hold: "보류" };
const THREAT_TYPES = ["phishing", "scam", "illegal_gambling", "malware"];
const fmtDateTime = (iso: string) =>
  new Date(iso).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });

function verdictText(v: Verdict): string {
  return v.decision === "threat" ? `위협 확정 · ${THREAT_LABEL[v.threat ?? ""] ?? v.threat}` : DECISION_LABEL[v.decision];
}

// 판정 막대(상세 칸 아래 고정). 검토관 이상 담당자 계정만 저장한다. 보고 있던 판(rev)을 함께 보내 다른 담당자의 저장을 덮어쓰지 않는다
const DECISIONS: Decision[] = ["threat", "benign", "hold"];
function VerdictBar({
  c,
  id,
  running,
  canDecide,
  onNext,
  onDecided,
}: {
  c: CaseOut | null;
  id: string;
  running: boolean;
  canDecide: boolean;
  onNext: (() => void) | null;
  onDecided: () => void;
}) {
  const cur = c?.verdict ?? null;
  const ai = c?.threat?.threat ?? "";
  const [pick, setPick] = useState<Decision | null>(null);
  const [threat, setThreat] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [history, setHistory] = useState<Verdict[] | null>(null);
  const radios = useRef<(HTMLButtonElement | null)[]>([]);

  const choose = (d: Decision) => {
    setMsg("");
    setPick(d);
    // AI 가 위협 유형을 냈으면 그 유형을 기본값으로 둔다(담당자가 바꿀 수 있음)
    if (d === "threat" && !threat) setThreat(THREAT_TYPES.includes(ai) ? ai : "");
  };
  // 화살표로 판정 사이를 옮긴다(라디오 그룹 규칙)
  const onKey = (e: React.KeyboardEvent, i: number) => {
    const step = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const j = (i + step + DECISIONS.length) % DECISIONS.length;
    choose(DECISIONS[j]);
    radios.current[j]?.focus();
  };
  const submit = async (thenNext: boolean) => {
    if (!pick) return;
    setBusy(true);
    setMsg("");
    let ok = false;
    try {
      await saveVerdict(id, { rev: cur?.rev ?? 0, decision: pick, threat: pick === "threat" ? threat : null, note });
      setPick(null);
      setNote("");
      ok = true;
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "저장 실패");
    } finally {
      setBusy(false);
      setHistory(null);
      onDecided(); // 실패(다른 담당자가 먼저 저장)여도 최신 판정을 다시 받아 보여 준다
    }
    if (ok && thenNext) onNext?.();
  };
  const ready = !!pick && !busy && !(pick === "threat" && !threat);
  const checked = (d: Decision) => (pick ?? null) === d;

  return (
    <form
      className="vbar"
      aria-label="담당자 판정"
      onSubmit={(e) => {
        e.preventDefault();
        submit(false);
      }}
    >
      <div className="vbar-row">
        <span className="vbar-title">담당자 판정</span>
        {cur ? (
          <span className="vnow">
            <span className={`vnow-name v-${cur.decision}`}>{verdictText(cur)}</span>
            판 {cur.rev} · {cur.reviewer} · {fmtDateTime(cur.created_at)}
            {cur.head_seq != null && ` · 증거 EV-${cur.head_seq}까지 확인`}
          </span>
        ) : (
          <span className="vnow">
            <span className="vnow-name">판정 없음</span>
          </span>
        )}
        {!canDecide ? (
          <span className="vbar-msg">판정은 검토관 이상의 담당자 계정만 저장할 수 있습니다. AI 는 판정을 확정하지 않습니다.</span>
        ) : running || !c ? (
          <span className="vbar-msg">조사가 끝나면 판정할 수 있습니다.</span>
        ) : (
          <>
            <div className="seg" role="radiogroup" aria-label="판정">
              {DECISIONS.map((d, i) => (
                <button
                  key={d}
                  ref={(el) => {
                    radios.current[i] = el;
                  }}
                  type="button"
                  role="radio"
                  aria-checked={checked(d)}
                  tabIndex={checked(d) || (!pick && i === 0) ? 0 : -1}
                  className={d === "threat" ? "seg-threat" : ""}
                  onClick={() => choose(d)}
                  onKeyDown={(e) => onKey(e, i)}
                >
                  {DECISION_LABEL[d]}
                </button>
              ))}
            </div>
            {pick === "threat" && (
              <select className="field" aria-label="위협 유형" value={threat} onChange={(e) => setThreat(e.target.value)} required>
                <option value="" disabled>
                  위협 유형 선택
                </option>
                {THREAT_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {THREAT_LABEL[t]}
                    {t === ai ? " (AI 추천)" : ""}
                  </option>
                ))}
              </select>
            )}
            <label className="sr" htmlFor="verdict-note">
              판단 근거 메모
            </label>
            <input id="verdict-note" className="field vbar-note" maxLength={1000} placeholder="판단 근거 메모(선택, 1000자까지)" value={note} onChange={(e) => setNote(e.target.value)} />
            <button type="submit" className="btn btn-ghost" disabled={!ready}>
              저장
            </button>
            <button type="button" className="btn btn-primary" disabled={!ready || !onNext} onClick={() => submit(true)}>
              저장하고 다음 사건
            </button>
          </>
        )}
      </div>
      {msg && (
        <p className="err" role="alert">
          {msg}
        </p>
      )}
      {cur?.note && <span className="verdict-note small">메모 · {cur.note}</span>}
      {cur && cur.rev > 1 && (
        <details
          className="verdict-history"
          onToggle={(e) => {
            if (e.currentTarget.open && !history) listVerdicts(id).then(setHistory, () => setHistory([]));
          }}
        >
          <summary>판정 기록 {cur.rev}건</summary>
          {(history ?? []).map((v) => (
            <div key={v.rev} className="small verdict-past">
              <span>
                <span className="muted">판 {v.rev}</span> {verdictText(v)} · {v.reviewer} · {fmtDateTime(v.created_at)}
              </span>
              {v.note && <span className="verdict-note">{v.note}</span>}
            </div>
          ))}
        </details>
      )}
    </form>
  );
}

// ── AI 요약 + 근거 카드(고정 문구 + 기록 값) ───────────────────────
function summaryLine(c: CaseOut | null, running: boolean): { tone: Tone; head: React.ReactNode; prob: number | null } {
  const t = c?.threat;
  if (running || !c) return { tone: "idle", head: "조사 중 · 조사가 끝나면 판단이 표시됩니다", prob: null };
  if (!t || t.threat === "unknown") {
    const why = c.finish_reason ? (REASON_LABEL[c.finish_reason] ?? c.finish_reason) : (STATUS_LABEL[c.status] ?? c.status);
    return { tone: "idle", head: `판단할 수 없습니다 · ${why}`, prob: null };
  }
  // 정상 단정 문구는 쓰지 않는다. 확신이 부족한 정상은 담당자 검토로 보인다
  if (t.threat === "benign")
    return t.hold
      ? { tone: "review", head: "위험 근거를 찾지 못했습니다 · 확신이 부족해 담당자 검토가 필요합니다", prob: t.probability }
      : { tone: "safe", head: "위험 근거를 찾지 못했습니다", prob: t.probability };
  const name = THREAT_LABEL[t.threat] ?? t.threat;
  if (t.hold) return { tone: "review", head: <><span className="tone-text">{name}</span> 의심 · 확신이 부족해 담당자 검토가 필요합니다</>, prob: t.probability };
  return { tone: "threat", head: <>이 사이트는 <span className="tone-text">{name}</span>일 가능성이 높습니다</>, prob: t.probability };
}

function Summary({ c, running, reasons, picked, onPick }: { c: CaseOut | null; running: boolean; reasons: Reason[]; picked: string | null; onPick: (r: Reason) => void }) {
  const line = summaryLine(c, running);
  const t = c?.threat;
  const next = t
    ? Object.entries(t.probabilities).sort((a, b) => b[1] - a[1]).filter(([k, v]) => k !== t.threat && v >= 0.01).slice(0, 2)
    : [];
  return (
    <section className={`panel summary tone-${line.tone}`} aria-label="AI 요약">
      <div className="summary-head">
        <h1 className="summary-title">{line.head}</h1>
        {line.prob != null && <span className="summary-prob tone-text">{pct(line.prob)}</span>}
        <div className="spacer" />
        {c && (
          <span className="muted small" title={c.url}>
            {clip(hostPath(c.url), 60)}
          </span>
        )}
      </div>
      {t?.override && (
        <span className="small summary-override">
          {overrideLabel(t.override)} · 모델 원래 판단 {THREAT_LABEL[t.override.original.threat] ?? t.override.original.threat} {pct(t.override.original.probability)}
        </span>
      )}
      {reasons.length > 0 && (
        <div className="reasons">
          {reasons.map((r, i) => {
            const body = (
              <>
                <span className="reason-title tone-text">
                  {CIRCLED[i]} {r.title}
                </span>
                <span className="reason-text">{r.text}</span>
                <span className="reason-foot">
                  <span>{r.ev}</span>
                  {r.shot && <span>화면 보기 ›</span>}
                </span>
              </>
            );
            return r.shot ? (
              <button key={r.key} type="button" className={`reason tone-${r.tone}`} aria-pressed={picked === r.shot} onClick={() => onPick(r)}>
                {body}
              </button>
            ) : (
              <div key={r.key} className={`reason tone-${r.tone}`}>
                {body}
              </div>
            );
          })}
        </div>
      )}
      <span className="summary-foot">
        {next.length > 0 && `다음 후보 ${next.map(([k, v]) => `${THREAT_LABEL[k] ?? k} ${pct(v)}`).join(" · ")} · `}
        {t ? `${t.model} · ` : ""}기술적 의심 유형이며 법적 판단이 아닙니다
      </span>
    </section>
  );
}
const CIRCLED = [..."①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳"];

// ── 조사 경과 탭: 근거 화면(기본) · 경로 지도 · 조사 녹화 · 행동 기록 ─────────────
type TabId = "screens" | "path" | "related" | "links" | "intel" | "referral" | "actions" | "rec" | "log";
type VerifyState = { ok: boolean; records: number; errors: string[] } | null;

function CaseTabs({
  id,
  c,
  events,
  screens,
  tab,
  onTab,
  pick,
  onPick,
  related,
  canCreate,
  canAct,
  onOpen,
  onChanged,
}: {
  id: string;
  c: CaseOut | null;
  events: EvidenceEvent[];
  screens: Screen[];
  tab: TabId;
  onTab: (t: TabId) => void;
  pick: string | null;
  onPick: (f: string) => void;
  related: boolean;
  canCreate: boolean;
  canAct: boolean;
  onOpen: (id: string) => void;
  onChanged: () => void;
}) {
  const nCands = (c?.candidates ?? []).filter((x) => typeof x !== "string").length;
  // 녹화: 원래 주소와 연관 후보 하위 조사마다 하나씩. 한 재생 막대로 이어 재생한다(사건이 바뀌면 처음부터)
  const recs = useMemo(() => recordings(events), [events]);
  const tabs: [TabId, string][] = [
    ["screens", `근거 화면 ${screens.length}`],
    ["path", "경로 지도"],
    ["related", `연관 사이트 ${nCands}`],
    ["links", "연결된 사건"],
    ...(canCreate ? ([["intel", "운영 정보"]] as [TabId, string][]) : []),
    ...(canCreate ? ([["referral", "처리 요청"]] as [TabId, string][]) : []),
    ["actions", c?.action ? `조치 · ${ACTION_STATE_LABEL[c.action.state] ?? c.action.state}` : "조치 추적"],
    ["rec", recs.length > 1 ? `조사 녹화 ${recs.length}` : "조사 녹화"],
    ["log", `행동 기록 ${events.length}`],
  ];
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: React.KeyboardEvent, i: number) => {
    const step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const j = (i + step + tabs.length) % tabs.length;
    onTab(tabs[j][0]);
    refs.current[j]?.focus();
  };
  return (
    <>
      <div className="tabs" role="tablist" aria-label="조사 경과 보기">
        {tabs.map(([t, label], i) => (
          <button
            key={t}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`tab-${t}`}
            aria-selected={tab === t}
            aria-controls={`panel-${t}`}
            tabIndex={tab === t ? 0 : -1}
            className="tab"
            onClick={() => onTab(t)}
            onKeyDown={(e) => onKey(e, i)}
          >
            {label}
          </button>
        ))}
        <div className="spacer" />
        {tab === "path" && (
          <span className="legend">
            <span>━ 이동</span>
            <span className="bad">┅ 차단</span>
            <span>┅ 기록만</span>
          </span>
        )}
      </div>
      <div className="tab-panel" role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "screens" && <ScreensTab id={id} c={c} events={events} screens={screens} pick={pick} onPick={onPick} />}
        {tab === "path" && c && <PathTab c={c} events={events} />}
        {tab === "links" && <LinksTab id={id} onOpen={onOpen} />}
        {tab === "intel" && canCreate && !related && <IntelTab id={id} onOpen={onOpen} />}
        {tab === "intel" && canCreate && related && (
          <div className="floor">
            <p className="muted">연관 사이트 조사가 끝나면 볼 수 있습니다</p>
          </div>
        )}
        {tab === "referral" && canCreate && <ReferralTab id={id} rev={c?.verdict?.rev ?? 0} related={related} />}
        {tab === "actions" && c && <ActionsTab c={c} canAct={canAct} canRecheck={canCreate} onChanged={onChanged} />}
        {tab === "related" && c && <RelatedTab id={id} c={c} events={events} related={related} canCreate={canCreate} onOpen={onOpen} onChanged={onChanged} />}
        {tab === "rec" && (
          <div className="floor">
            {recs.length ? (
              <RecordingPlayer key={id} caseId={id} recs={recs} events={events} />
            ) : (
              <div className="rec-box">
                <span className="small">녹화 없음</span>
              </div>
            )}
          </div>
        )}
        {tab === "log" && (
          <div className="log">
            <EventLog events={events} />
          </div>
        )}
      </div>
    </>
  );
}

// 처리 요청: 판정 유형에 맞는 처리 기관·참고 조문과 기관 양식에 옮겨 쓸 요청서 초안(조사관 이상).
// 확정 판정이 없으면 AI 판단 기준 초안이다. 판정이 바뀌면(rev) 다시 받는다
function ReferralTab({ id, rev, related }: { id: string; rev: number; related: boolean }) {
  const [r, setR] = useState<Referral | null>(null);
  const [err, setErr] = useState("");
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (related) return;
    let live = true;
    setR(null);
    setErr("");
    getReferral(id)
      .then((v) => live && setR(v))
      .catch((e) => live && setErr(e instanceof Error ? e.message : "불러오지 못했습니다"));
    return () => {
      live = false;
    };
  }, [id, rev, related]);
  if (related) return <div className="floor"><p className="muted">연관 사이트 조사가 끝나면 요청서를 만들 수 있습니다</p></div>;
  if (err) return <div className="floor"><p className="err">{err}</p></div>;
  if (!r) return <div className="floor"><p className="muted">불러오는 중…</p></div>;
  if (!r.applicable) return <div className="floor"><p className="muted">{r.reason_ko || "요청 대상이 아닙니다"}</p></div>;
  const copy = () => {
    navigator.clipboard
      .writeText(r.text)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      })
      .catch(() => setErr("복사하지 못했습니다(브라우저 권한)"));
  };
  const Org = ({ a, main }: { a: typeof r.agency; main?: boolean }) => (
    <li className="ref-org">
      <span className="ref-org-name">
        {main && <span className="chip st-REVIEW_REQUIRED">처리 기관</span>} {a.name}
      </span>
      <span className="muted small">
        {a.does}
        {a.when ? ` · ${a.when}` : ""}
      </span>
      <span className="mono small">
        ☎ {a.phone} ·{" "}
        <a href={a.url} target="_blank" rel="noopener noreferrer">
          {a.url}
        </a>
      </span>
    </li>
  );
  return (
    <div className="floor referral">
      <p className="ref-head">
        <strong>{r.threat_ko}</strong> · {r.basis === "confirmed" ? "담당자 판정 기준" : "AI 판단 기준 초안 — 담당자 판정 뒤 다시 확인"}
      </p>
      <ul className="ref-orgs">
        <Org a={r.agency} main />
        {r.also.map((a) => (
          <Org key={a.id} a={a} />
        ))}
      </ul>
      <h3 className="sub-h">참고 조문 (해당 여부는 받는 기관이 판단)</h3>
      <ul className="ref-laws">
        {r.laws.map((l) => (
          <li key={l.cite}>
            <strong>{l.cite}</strong> <span className="muted">{l.text}</span>
          </li>
        ))}
      </ul>
      <h3 className="sub-h">
        요청서 초안{" "}
        <button type="button" className="btn btn-ghost btn-sm" onClick={copy}>
          {copied ? "복사함" : "복사"}
        </button>
      </h3>
      <pre className="ref-text">{r.text}</pre>
      <p className="muted small">{r.notice}</p>
    </div>
  );
}

// 운영 정보: 화면에 적힌 운영자 연락 수단·입금 계좌·입력값을 보내는 곳과 키트 지문(조사관 이상).
// 모두 조사 대상 페이지가 적은 값이라 '확인 안 됨'이다. 같은 값이 나온 다른 사건으로 이어 준다
function IntelTab({ id, onOpen }: { id: string; onOpen: (id: string) => void }) {
  const [v, setV] = useState<CaseIntel | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    let live = true;
    getIntel(id)
      .then((x) => live && setV(x))
      .catch((e) => live && setErr(e instanceof Error ? e.message : "불러오지 못했습니다"));
    return () => {
      live = false;
    };
  }, [id]);
  if (err) return <div className="floor"><p className="err">{err}</p></div>;
  if (!v) return <div className="floor"><p className="muted">불러오는 중…</p></div>;
  return (
    <div className="floor intel">
      <p className="muted small">페이지에 적힌 값이다(사실 확인 안 됨). 판단에는 쓰지 않고, 같은 값이 나온 사건을 잇는 데만 쓴다.</p>
      <h3 className="sub-h">운영 연락처·입금 정보 {v.items.length}</h3>
      {v.items.length === 0 ? (
        <p className="muted">화면에서 찾은 운영 연락처가 없습니다</p>
      ) : (
        <ul className="rel-list">
          {v.items.map((x) => (
            <li key={`${x.kind}:${x.value}`} className="rel-row">
              <span className="rel-site">
                <span>
                  <span className="row-badge">{INTEL_KIND[x.kind] ?? x.kind}</span>
                  <span className="mono">{x.value}</span>
                </span>
                <span className="muted small">
                  {x.step != null ? `${x.step}단계 화면` : "화면"} · {x.src === "link" ? "링크" : x.src === "form" ? "입력 양식" : "화면 글자"}
                  {x.others.length ? ` · 같은 값 다른 사건 ${x.others.length}건` : ""}
                </span>
              </span>
              <span />
              {x.others[0] ? (
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => onOpen(x.others[0].id)}>
                  다른 사건 보기
                </button>
              ) : (
                <span />
              )}
            </li>
          ))}
        </ul>
      )}
      <h3 className="sub-h">키트 지문 {v.kits.length}</h3>
      {v.kits.length === 0 ? (
        <p className="muted">지문 없음(요소가 적은 화면·공식·단축 서비스 화면은 만들지 않습니다)</p>
      ) : (
        <ul className="rel-list">
          {v.kits.map((k) => (
            <li key={`${k.kind}:${k.hash}`} className="rel-row">
              <span className="rel-site">
                <span>
                  <span className="row-badge">{k.kind === "dom" ? "화면 구조" : "빌드 파일"}</span>
                  <span className="mono">{k.hash.slice(0, 12)}</span> · <span className="mono">{clip(k.host, 50)}</span>
                </span>
                <span className="muted small">{k.others.length ? `같은 지문 다른 사건 ${k.others.length}건` : "같은 지문 사건 없음"}</span>
              </span>
              <span />
              {k.others[0] ? (
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => onOpen(k.others[0].id)}>
                  다른 사건 보기
                </button>
              ) : (
                <span />
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// 조치 추적: 위협 확정 뒤 기관에 요청한 것과 그 뒤(차단·삭제 확인, 재확인에서 다시 나타남, 종결)를 판으로 쌓는다.
// 재확인은 신고 주소에 다시 접속해 본 결과다(격리된 조사 컨테이너가 하고, 조치를 추적 중이면 정해진 간격마다 저절로)
function ActionsTab({ c, canAct, canRecheck, onChanged }: { c: CaseOut; canAct: boolean; canRecheck: boolean; onChanged: () => void }) {
  const [data, setData] = useState<{ actions: Action[]; checks: Check[]; interval: number } | null>(null);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [state, setState] = useState<ActionState>("requested");
  const [agency, setAgency] = useState("kisa");
  const [ref, setRef] = useState("");
  const [note, setNote] = useState("");
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    getActions(c.id)
      .then((v) => live && setData(v))
      .catch((e) => live && setErr(e instanceof Error ? e.message : "불러오지 못했습니다"));
    return () => {
      live = false;
    };
  }, [c.id, tick]);
  // 진행 중인 재확인이 있으면 끝날 때까지 2초마다 다시 받는다
  const pending = data?.checks.some((x) => x.state === "pending") ?? false;
  useEffect(() => {
    if (!pending) return;
    const t = setTimeout(() => setTick((n) => n + 1), 2000);
    return () => clearTimeout(t);
  }, [pending, data]);
  if (err) return <div className="floor"><p className="err">{err}</p></div>;
  if (!data) return <div className="floor"><p className="muted">불러오는 중…</p></div>;
  const cur = data.actions[0] ?? null;
  const confirmed = c.verdict?.decision === "threat";
  const save = async () => {
    setBusy(true);
    setMsg("");
    try {
      await saveAction(c.id, { rev: cur?.rev ?? 0, state, agency: state === "requested" ? agency : null, ref, note });
      setRef("");
      setNote("");
      setTick((n) => n + 1);
      onChanged();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "저장하지 못했습니다");
      setTick((n) => n + 1);
    } finally {
      setBusy(false);
    }
  };
  const recheck = async () => {
    setBusy(true);
    setMsg("");
    try {
      await requestRecheck(c.id);
      setTick((n) => n + 1);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "재확인을 요청하지 못했습니다");
    } finally {
      setBusy(false);
    }
  };
  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }) : "-");
  return (
    <div className="floor actions">
      <p className="ref-head">
        <strong>{cur ? ACTION_STATE_LABEL[cur.state] ?? cur.state : "조치 없음"}</strong>
        {cur?.agency ? ` · ${AGENCY_LABEL[cur.agency] ?? cur.agency}` : ""}
        {cur?.ref ? ` · 접수 ${cur.ref}` : ""}
        {cur ? ` · ${cur.actor === "system:recheck" ? "재확인(시스템)" : cur.actor} · ${fmt(cur.created_at)}` : ""}
        {cur && ["requested", "blocked", "removed", "reappeared"].includes(cur.state) ? ` · ${data.interval}시간마다 재확인` : ""}
      </p>
      {msg && <p className="err" role="alert">{msg}</p>}
      {canAct && confirmed ? (
        <div className="act-form">
          <select className="field" value={state} onChange={(e) => setState(e.target.value as ActionState)} aria-label="조치 상태">
            {(["requested", "blocked", "removed", "closed"] as ActionState[]).map((x) => (
              <option key={x} value={x}>
                {ACTION_STATE_LABEL[x]}
              </option>
            ))}
          </select>
          {state === "requested" && (
            <select className="field" value={agency} onChange={(e) => setAgency(e.target.value)} aria-label="요청한 기관">
              {Object.keys(AGENCY_LABEL).map((x) => (
                <option key={x} value={x}>
                  {AGENCY_LABEL[x]}
                </option>
              ))}
            </select>
          )}
          <input className="field" value={ref} maxLength={100} onChange={(e) => setRef(e.target.value)} placeholder="기관 접수 번호(선택)" aria-label="기관 접수 번호" />
          <input className="field grow" value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} placeholder="메모(선택)" aria-label="조치 메모" />
          <button type="button" className="btn btn-primary btn-sm" disabled={busy} onClick={save}>
            기록
          </button>
        </div>
      ) : (
        <p className="muted small">{confirmed ? "조치 기록은 조사관 이상 담당자 계정만 합니다" : "담당자가 위협으로 확정한 사건에 조치를 기록합니다"}</p>
      )}
      <h3 className="sub-h">
        재확인 {data.checks.length}{" "}
        {canRecheck && (
          <button type="button" className="btn btn-ghost btn-sm" disabled={busy || pending} onClick={recheck}>
            {pending ? "재확인 중…" : "지금 재확인"}
          </button>
        )}
      </h3>
      {data.checks.length === 0 ? (
        <p className="muted">재확인 기록 없음</p>
      ) : (
        <ul className="rel-list">
          {data.checks.map((x) => (
            <li key={x.id} className="rel-row">
              <span className="rel-site">
                <span>
                  <span className={`chip ${x.result === "alive" ? "st-threat" : ""}`}>
                    {x.state === "pending" ? "확인 중" : x.state === "expired" ? "응답 없음(만료)" : CHECK_RESULT_LABEL[x.result ?? ""] ?? x.result}
                  </span>{" "}
                  <span className="mono">{fmt(x.done_at ?? x.requested_at)}</span>
                  {x.http_status ? <span className="mono"> · HTTP {x.http_status}</span> : null}
                </span>
                <span className="muted small">
                  {x.final_host ? `${clip(x.final_host, 50)} · ` : ""}
                  {x.title ? `「${clip(x.title, 60)}」 · ` : ""}
                  {x.requested_by === "system:recheck" ? "정기 재확인" : `${x.requested_by} 요청`}
                </span>
              </span>
              <span />
              <span />
            </li>
          ))}
        </ul>
      )}
      <h3 className="sub-h">조치 기록 {data.actions.length}</h3>
      {data.actions.length === 0 ? (
        <p className="muted">기록 없음</p>
      ) : (
        <ul className="rel-list">
          {data.actions.map((a) => (
            <li key={a.rev} className="rel-row">
              <span className="rel-site">
                <span>
                  판 {a.rev} · <strong>{ACTION_STATE_LABEL[a.state] ?? a.state}</strong>
                  {a.agency ? ` · ${AGENCY_LABEL[a.agency] ?? a.agency}` : ""}
                  {a.ref ? ` · 접수 ${a.ref}` : ""}
                </span>
                <span className="muted small">
                  {a.actor === "system:recheck" ? "재확인(시스템)" : a.actor} · {fmt(a.created_at)}
                  {a.note ? ` · ${clip(a.note, 120)}` : ""}
                </span>
              </span>
              <span />
              <span />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// 사건 요약 한 줄(연결된 사건·연관 묶음 공통)
function BriefRow({ b, onOpen, note }: { b: { id: string; url: string; status: string; threat: string | null; verdict: string | null }; onOpen: (id: string) => void; note?: string }) {
  const verdict = b.verdict === "threat" ? "위협 확정" : b.verdict === "benign" ? "정상 확정" : b.verdict === "hold" ? "보류" : "";
  return (
    <li className="rel-row">
      <span className="rel-site">
        <span className="mono">{clip(hostPath(b.url), 60)}</span>
        <span className="muted small">
          {note ? `${note} · ` : ""}
          {STATUS_LABEL[b.status] ?? b.status}
          {b.threat ? ` · AI ${THREAT_LABEL[b.threat] ?? b.threat}` : ""}
          {verdict ? ` · ${verdict}` : ""}
        </span>
      </span>
      <span />
      <button type="button" className="btn btn-ghost btn-sm" onClick={() => onOpen(b.id)}>
        사건 보기
      </button>
    </li>
  );
}

// 연결된 사건: 부모·자식(연관 후보로 만든 사건)과 같은 사이트가 나온 다른 사건(사이트별)
function LinksTab({ id, onOpen }: { id: string; onOpen: (id: string) => void }) {
  const [links, setLinks] = useState<CaseLinks | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    let live = true;
    getLinks(id)
      .then((v) => live && setLinks(v))
      .catch((e) => live && setErr(e instanceof Error ? e.message : "불러오지 못했습니다"));
    return () => {
      live = false;
    };
  }, [id]);
  if (err) return <div className="floor"><p className="err">{err}</p></div>;
  if (!links) return <div className="floor"><p className="muted">불러오는 중…</p></div>;
  const none = !links.parent && links.children.length === 0 && links.shared.length === 0;
  return (
    <div className="floor">
      {none && <p className="muted">연결된 사건 없음</p>}
      {links.parent && (
        <>
          <h3 className="sub-h">이 사이트를 찾은 사건</h3>
          <ul className="rel-list">
            <BriefRow b={links.parent} onOpen={onOpen} />
          </ul>
        </>
      )}
      {links.children.length > 0 && (
        <>
          <h3 className="sub-h">이 사건에서 찾아 접수한 사건</h3>
          <ul className="rel-list">
            {links.children.map((k) => (
              <BriefRow key={k.id} b={k} onOpen={onOpen} note={k.auto ? "자동" : "담당자"} />
            ))}
          </ul>
        </>
      )}
      {links.shared.map((g) => (
        <section key={g.site}>
          <h3 className="sub-h">
            {g.kind === "contact" ? "같은 운영 정보" : g.kind === "kit" ? "같은 키트 지문" : "같은 사이트"}{" "}
            <span className="mono">{clip(linkKeyLabel(g.site, g.kind, g.hosts), 60)}</span> · {g.cases.length}건
          </h3>
          <ul className="rel-list">
            {g.cases.map((b) => (
              <BriefRow key={b.id} b={b} onOpen={onOpen} />
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

// ── 현황판(열람자 이상): 기간 안 사건의 접수·처리·판정·조치 수. 값(주소)은 없고 수·이름표만 ─────────────
const DASH_DAYS = [7, 30, 90];
const DASH_DECISION_LABEL: Record<string, string> = dict({ threat: "위협 확정", benign: "정상 확정", hold: "보류", none: "판정 전" });
const RULE_LABEL: Record<string, string> = dict({
  link_takedown: "링크 정지 안내", shortener_warning: "단축 서비스 위험 경고", official_redirect: "조사 전 공식 사이트로 넘김",
  brand_lookalike: "브랜드 사칭 도메인", brand_name_domain: "브랜드 이름 그대로의 다른 도메인", brand_typo_domain: "브랜드 오타 도메인",
  brand_login_shared_hosting: "공용 호스팅의 브랜드 로그인 화면", brand_clone_title: "공식 화면 제목을 그대로 쓴 로그인 화면",
  official_betting_domain: "공식 사행사업자 도메인",
});
const AI_LABEL: Record<string, string> = dict({ ...THREAT_LABEL, none: "판단 없음" });
const ACTION_LABEL_ALL: Record<string, string> = dict({ ...ACTION_STATE_LABEL, none: "아직 요청 안 함" });
const SERIES_THREAT = "#C62828"; // 위협으로 본 사건(콘솔의 위협 색, 검증기 통과: 파랑과 CVD ΔE 26.7)
const SERIES_OTHER = "#2A78D6";
const pctOf = (a: number, b: number) => (b ? `${Math.round((a / b) * 100)}%` : "-");
const fmtNum = (v: number | null, unit: string) => (v == null ? "-" : `${v.toLocaleString("ko-KR")}${unit}`);
// 1시간 미만은 분, 하루 이상은 일·시간으로(판정까지 걸린 시간·대기 시간)
const fmtHours = (h: number | null) => {
  if (h == null) return "-";
  if (h < 1) return `${Math.round(h * 60)}분`;
  if (h < 48) return `${Math.round(h * 10) / 10}시간`;
  const r = Math.round(h);
  return `${Math.floor(r / 24)}일 ${r % 24}시간`;
};
// 눈금 간격: 1·2·5 × 10^k 가운데 최댓값을 4칸 안팎으로 나누는 것
const niceStep = (max: number) => {
  const raw = Math.max(1, max / 4);
  const p = 10 ** Math.floor(Math.log10(raw));
  return [1, 2, 5, 10].map((m) => m * p).find((s) => s >= raw) ?? raw;
};

function DashboardPane() {
  const [days, setDays] = useState(30);
  const [s, setS] = useState<Stats | null>(null);
  const [err, setErr] = useState("");
  const load = useCallback(() => {
    getStats(days).then(
      (x) => {
        setS(x);
        setErr("");
      },
      (e: Error) => setErr(e.message),
    );
  }, [days]);
  useEffect(() => {
    setS(null);
    load();
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  }, [load]);
  const k = s?.kpi;
  const a = s?.agreement;
  return (
    <section className="dash scroll" aria-label="현황판">
      <div className="dash-head">
        <h2>현황판</h2>
        <label className="sr" htmlFor="dash-days">
          기간
        </label>
        <select id="dash-days" className="field" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {DASH_DAYS.map((d) => (
            <option key={d} value={d}>
              최근 {d}일
            </option>
          ))}
        </select>
        <span className="muted small">
          접수 시각 기준{s ? ` · ${s.cases.toLocaleString("ko-KR")}건 · ${s.ms}ms` : ""}
          {s?.truncated && <span className="warn"> · 최신 5,000건만 셈</span>}
        </span>
        <div className="spacer" />
        <button type="button" className="btn btn-ghost btn-sm" onClick={load}>
          새로 고침
        </button>
      </div>
      {err && <p className="err">{err}</p>}
      {!s || !k || !a ? (
        !err && <p className="muted">세는 중…</p>
      ) : (
        <>
          <div className="dash-kpis">
            <Kpi label="접수" value={k.received} sub={`끝남 ${k.finished} · 조사 중 ${k.pending}${k.other ? ` · 기타 ${k.other}` : ""}`} />
            <Kpi label="AI 가 위협으로 봄" value={k.aiThreat} sub={`끝난 사건의 ${pctOf(k.aiThreat, k.finished)}`} />
            <Kpi label="담당자 위협 확정" value={k.confirmed} />
            <Kpi label="판정 대기" value={k.waiting} sub={s.timing.waitingH.max != null ? `가장 오래 ${fmtHours(s.timing.waitingH.max)}` : undefined} tone={k.waiting ? "review" : undefined} />
            <Kpi label="다시 나타남" value={k.reappeared} sub="차단·삭제 확인 뒤 다시 접속됨" tone={k.reappeared ? "threat" : undefined} />
          </div>
          <div className="dash-card">
            <h3>날짜별 접수</h3>
            <DailyChart rows={s.daily} />
          </div>
          <div className="dash-grid">
            <div className="dash-card">
              <h3>AI 판단 유형(끝난 사건)</h3>
              <BarList items={s.ai} label={AI_LABEL} />
            </div>
            <div className="dash-card">
              <h3>담당자 판정</h3>
              <BarList items={s.decisions} label={DASH_DECISION_LABEL} />
              {s.confirmed.length > 0 && <p className="small muted dash-note">위협 확정 유형: {s.confirmed.map(([t, n]) => `${THREAT_LABEL[t] ?? t} ${n}`).join(" · ")}</p>}
            </div>
            <div className="dash-card">
              <h3>처리 시간</h3>
              <table className="dash-table">
                <tbody>
                  <tr>
                    <th>접수 → 원래 결과</th>
                    <td>
                      중앙 {fmtNum(s.timing.toMainS.median, "초")} · p90 {fmtNum(s.timing.toMainS.p90, "초")}
                      <span className="muted"> ({s.timing.toMainS.n}건)</span>
                    </td>
                  </tr>
                  <tr>
                    <th>접수 → 첫 판정</th>
                    <td>
                      중앙 {fmtHours(s.timing.toVerdictH.median)} · p90 {fmtHours(s.timing.toVerdictH.p90)}
                      <span className="muted"> ({s.timing.toVerdictH.n}건)</span>
                    </td>
                  </tr>
                  <tr>
                    <th>판정 대기 중</th>
                    <td>
                      중앙 {fmtHours(s.timing.waitingH.median)} · 가장 오래 {fmtHours(s.timing.waitingH.max)}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div className="dash-card">
              <h3>AI 와 담당자 판정</h3>
              <table className="dash-table">
                <tbody>
                  <tr>
                    <th>위협 여부 일치</th>
                    <td>
                      {a.sameClass}/{a.pairs} ({pctOf(a.sameClass, a.pairs)})
                    </td>
                  </tr>
                  <tr>
                    <th>위협 유형 일치</th>
                    <td>
                      {a.sameType}/{a.bothThreat} ({pctOf(a.sameType, a.bothThreat)})
                    </td>
                  </tr>
                  <tr>
                    <th>AI 위협 → 담당자 정상</th>
                    <td>{a.aiThreatReviewerBenign}건</td>
                  </tr>
                  <tr>
                    <th>AI 정상 → 담당자 위협</th>
                    <td>{a.aiBenignReviewerThreat}건</td>
                  </tr>
                </tbody>
              </table>
              <p className="small muted dash-note">판정할 때의 AI 의견과 비교(판단 불가는 뺌)</p>
            </div>
            <div className="dash-card">
              <h3>코드 규칙이 담당자 검토로 보낸 사건</h3>
              <BarList items={s.rules} label={RULE_LABEL} note={(key) => (s.rulesConfirmed[key] ? `위협 확정 ${s.rulesConfirmed[key]}` : "")} />
            </div>
            <div className="dash-card">
              <h3>사칭 브랜드(위협 사건)</h3>
              <BarList items={s.brands} />
              <p className="small muted dash-note">코드 규칙이 남긴 브랜드, 없으면 도메인 이름으로 본 브랜드(브랜드 목록의 것만)</p>
            </div>
            <div className="dash-card">
              <h3>호스팅(위협 사건)</h3>
              <BarList items={s.hosting} />
            </div>
            <div className="dash-card">
              <h3>최상위 도메인(위협 사건)</h3>
              <BarList items={s.tlds} />
            </div>
            <div className="dash-card">
              <h3>조치 상태(위협 확정 사건)</h3>
              <BarList items={s.actions.filter(([, n]) => n > 0)} label={ACTION_LABEL_ALL} />
            </div>
            <div className="dash-card">
              <h3>연관 사건</h3>
              <table className="dash-table">
                <tbody>
                  <tr>
                    <th>자동으로 만든 사건</th>
                    <td>
                      {s.related.auto}건 · AI 위협 {s.related.autoAiThreat} · 위협 확정 {s.related.autoConfirmed}
                    </td>
                  </tr>
                  <tr>
                    <th>담당자가 접수한 사건</th>
                    <td>{s.related.manual}건</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <p className="small muted">위협 사건: 담당자 판정이 있으면 그 판정(위협 확정), 없으면 AI 판단. 날짜는 한국 시각.</p>
        </>
      )}
    </section>
  );
}

function Kpi({ label, value, sub, tone }: { label: string; value: number; sub?: string; tone?: "review" | "threat" }) {
  return (
    <div className={tone ? `dash-kpi ${tone}` : "dash-kpi"}>
      <span className="dash-kpi-label">{label}</span>
      <span className="dash-kpi-value">{value.toLocaleString("ko-KR")}</span>
      {sub && <span className="dash-kpi-sub">{sub}</span>}
    </div>
  );
}

// 가로 막대 목록(한 계열): 이름표 · 막대 · 수. 수는 늘 글자로 보이고, 마우스를 올리면 비율
function BarList({ items, label, note }: { items: Pair[]; label?: Record<string, string>; note?: (key: string) => string }) {
  if (!items.length) return <p className="muted small">없음</p>;
  const max = Math.max(...items.map(([, n]) => n), 1);
  const total = items.reduce((t, [, n]) => t + n, 0);
  return (
    <ul className="bars">
      {items.map(([key, n]) => {
        const name = label?.[key] ?? key;
        const extra = note?.(key);
        return (
          <li key={key} className="bars-row" title={`${name}: ${n}건 (${pctOf(n, total)})`}>
            <span className="bars-label">{name}</span>
            <span className="bars-track">
              <span className="bars-fill" style={{ width: `${(n / max) * 100}%` }} />
            </span>
            <span className="bars-n">
              {n.toLocaleString("ko-KR")}
              {extra && <span className="muted"> · {extra}</span>}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

// 날짜별 접수: 쌓은 세로 막대(아래 AI 가 위협으로 본 사건, 위 그 외). 막대에 마우스를 올리면 그날 수, 표로도 둔다
function DailyChart({ rows }: { rows: Stats["daily"] }) {
  const [hover, setHover] = useState<number | null>(null);
  // 그림 좌표 1 = 화면 1px(viewBox 를 늘이면 글자가 화면 폭만큼 커진다): 칸 폭을 재서 쓴다
  const box = useRef<HTMLDivElement>(null);
  const [W, setW] = useState(960);
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setW(Math.max(320, Math.floor(e.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const H = 200;
  const L = 36;
  const B = 22;
  const T = 8;
  const max = Math.max(1, ...rows.map((r) => r.received));
  const step = niceStep(max);
  const top = step * Math.ceil(max / step);
  const y = (v: number) => T + (H - T - B) * (1 - v / top);
  const slot = (W - L) / Math.max(1, rows.length);
  const bw = Math.max(2, Math.min(28, slot * 0.7));
  const every = Math.ceil(rows.length / 12);
  const h = hover != null ? rows[hover] : null;
  return (
    <div className="daily" ref={box}>
      <div className="daily-legend small">
        <span>
          <i style={{ background: SERIES_THREAT }} /> AI 가 위협으로 봄
        </span>
        <span>
          <i style={{ background: SERIES_OTHER }} /> 그 외 접수
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} className="daily-svg" role="img" aria-label="날짜별 접수 막대 그림(아래 표와 같은 값)" onMouseLeave={() => setHover(null)}>
        {Array.from({ length: Math.round(top / step) + 1 }, (_, i) => i * step).map((v) => (
          <g key={v}>
            <line x1={L} x2={W} y1={y(v)} y2={y(v)} className="daily-grid" />
            <text x={L - 6} y={y(v) + 4} textAnchor="end" className="daily-axis">
              {v}
            </text>
          </g>
        ))}
        {rows.map((r, i) => {
          const x = L + slot * i + (slot - bw) / 2;
          const other = Math.max(0, r.received - r.aiThreat);
          return (
            <g key={r.date}>
              {r.aiThreat > 0 && <rect x={x} y={y(r.aiThreat)} width={bw} height={y(0) - y(r.aiThreat)} fill={SERIES_THREAT} rx={1.5} />}
              {other > 0 && <rect x={x} y={y(r.received)} width={bw} height={Math.max(0, y(r.aiThreat) - y(r.received) - (r.aiThreat > 0 ? 2 : 0))} fill={SERIES_OTHER} rx={1.5} />}
              {i % every === 0 && (
                <text x={x + bw / 2} y={H - 6} textAnchor="middle" className="daily-axis">
                  {r.date.slice(5).replace("-", "/")}
                </text>
              )}
              <rect x={L + slot * i} y={T} width={slot} height={H - T - B} fill="transparent" onMouseEnter={() => setHover(i)} />
              {hover === i && <rect x={L + slot * i} y={T} width={slot} height={H - T - B} className="daily-hover" />}
            </g>
          );
        })}
      </svg>
      <p className="daily-tip small" aria-live="polite">
        {h ? `${h.date} · 접수 ${h.received} · AI 위협 ${h.aiThreat} · 담당자 위협 확정 ${h.confirmed}` : "막대에 마우스를 올리면 그날 수를 봅니다"}
      </p>
      <table className="sr">
        <caption>날짜별 접수</caption>
        <thead>
          <tr>
            <th>날짜</th>
            <th>접수</th>
            <th>AI 위협</th>
            <th>위협 확정</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.date}>
              <td>{r.date}</td>
              <td>{r.received}</td>
              <td>{r.aiThreat}</td>
              <td>{r.confirmed}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// 분류 폴더 '연관 묶음': 같은 사이트로 이어지는 사건 묶음. 묶음을 고르면 사이트·사건 표, CSV(조사관 이상),
// 위협 사이트는 [새 사건으로 접수](그 사이트를 후보로 가진 사건에서, 회선 차단 추정이어도 버튼을 둔다)
function GroupsPane({ canExport, onOpenCase }: { canExport: boolean; onOpenCase: (id: string) => void }) {
  const [data, setData] = useState<{ groups: RelatedGroup[]; truncated: boolean; ms: number } | null>(null);
  const [err, setErr] = useState("");
  const [pick, setPick] = useState<string | null>(null);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState("");
  const load = useCallback(() => {
    listGroups()
      .then(setData)
      .catch((e) => setErr(e instanceof Error ? e.message : "불러오지 못했습니다"));
  }, []);
  useEffect(load, [load]);
  const g = data?.groups.find((x) => x.key === pick) ?? data?.groups[0] ?? null;
  return (
    <>
      <section className="caselist" aria-label="연관 묶음 목록">
        <div className="caselist-head">
          <h2>연관 묶음</h2>
          <span className="muted small">{data ? `${data.groups.length}묶음${data.truncated ? " · 최근 사건만 계산" : ""}` : ""}</span>
          <div className="spacer" />
          <button type="button" className="btn btn-ghost btn-sm" onClick={load}>
            다시 계산
          </button>
        </div>
        {err && <p className="err" style={{ padding: "8px 16px" }}>{err}</p>}
        <ul className="rows scroll">
          {(data?.groups ?? []).map((x) => (
            <li key={x.key}>
              <button type="button" className="row" aria-current={g?.key === x.key} onClick={() => setPick(x.key)}>
                <span className="row-dot" />
                <span className="row-host">{clip(x.sites[0] ? linkKeyLabel(x.sites[0].site, x.sites[0].kind, x.sites[0].hosts) : x.key, 50)}</span>
                <span className="row-time">{x.cases.length}건</span>
                <span className="row-sub">
                  위협 사이트 {x.threat_sites} · 회선 차단 추정 {x.blocked_estimate_sites} · 사이트 {x.sites.filter((s) => s.kind === "site").length}
                  {x.sites.some((s) => s.kind !== "site") ? ` · 운영 정보·키트 ${x.sites.filter((s) => s.kind !== "site").length}` : ""}
                </span>
              </button>
            </li>
          ))}
          {data && data.groups.length === 0 && <li className="muted" style={{ padding: 16 }}>같은 사이트로 이어진 사건이 아직 없습니다</li>}
        </ul>
      </section>
      <section className="detail scroll" aria-label="연관 묶음 상세">
        {!g ? (
          <div className="empty">
            <h2>연관 묶음</h2>
            <p>같은 사이트(단축 서비스·공식·흔한 대형 사이트 제외, 공용 호스팅은 호스트가 같을 때만)나 같은 운영 정보(텔레그램·계좌 등 페이지에 적힌 값)·키트 지문(화면 구조)이 나온 사건끼리 묶습니다.</p>
          </div>
        ) : (
          <div className="detail-body">
            <div className="statusline">
              <span className="chip st-REVIEW_REQUIRED">사건 {g.cases.length}건</span>
              <span className="muted">위협 사이트 {g.threat_sites} · 회선 차단 추정 {g.blocked_estimate_sites}</span>
              <div className="spacer" />
              {canExport ? (
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  disabled={busy !== ""}
                  onClick={async () => {
                    setBusy("csv");
                    setMsg("");
                    try {
                      await downloadGroupCsv(g.key);
                    } catch (e) {
                      setMsg(e instanceof Error ? e.message : "내려받기 실패");
                    } finally {
                      setBusy("");
                    }
                  }}
                >
                  CSV 내려받기
                </button>
              ) : (
                <span className="muted small">CSV 는 조사관 이상만</span>
              )}
            </div>
            {msg && <p className="err" role="alert">{msg}</p>}
            <h3 className="sub-h">사이트</h3>
            <ul className="rel-list">
              {g.sites.map((s) => (
                <li key={s.site} className="rel-row">
                  <span className="rel-site">
                    <span className="mono">{clip(linkKeyLabel(s.site, s.kind, s.hosts), 60)}</span>
                    <span className="muted small">
                      사건 {s.cases}건 · {s.hosts.slice(0, 3).map((x) => clip(x, 40)).join(", ")}
                    </span>
                  </span>
                  {s.kind === "site" ? (
                    <span className={`chip ${s.threat ? "st-threat" : ""}`}>
                      {s.threat ? `위협 의심 · ${THREAT_LABEL[s.threat] ?? s.threat}` : "판단 없음"}
                      {s.blocked ? " · 회선 차단 추정" : ""}
                    </span>
                  ) : (
                    <span className="chip">{s.kind === "contact" ? "운영 정보 · 확인 안 됨" : "키트 지문"}</span>
                  )}
                  {canExport && s.kind === "site" && s.threat && s.candidate ? (
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      disabled={busy !== ""}
                      onClick={async () => {
                        const cand = s.candidate;
                        if (!cand) return;
                        setBusy(s.site);
                        setMsg("");
                        try {
                          const parent = await getCase(cand.case_id);
                          const url = (parent.candidates ?? []).find((x): x is Candidate => typeof x !== "string" && (x.host ?? "") === cand.host)?.url;
                          if (!url) throw new Error("이 사이트를 후보로 가진 사건을 찾지 못했습니다");
                          const child = await createRelated(cand.case_id, url);
                          onOpenCase(child.id);
                        } catch (e) {
                          setMsg(e instanceof Error ? e.message : "접수하지 못했습니다");
                        } finally {
                          setBusy("");
                        }
                      }}
                    >
                      {busy === s.site ? "접수 중" : "새 사건으로 접수"}
                    </button>
                  ) : (
                    <span />
                  )}
                </li>
              ))}
            </ul>
            <h3 className="sub-h">사건</h3>
            <ul className="rel-list">
              {g.cases.map((b) => (
                <BriefRow key={b.id} b={b} onOpen={onOpenCase} />
              ))}
            </ul>
            {data && <p className="muted small">묶음 계산 {data.ms}ms</p>}
          </div>
        )}
      </section>
    </>
  );
}

// 자동 사건을 만들지 않은 이유(API auto_skipped)
const AUTO_SKIP_LABEL: Record<string, string> = dict({
  disabled: "자동 접수 꺼짐",
  depth: "연관 사건의 후보",
  not_threat: "위협으로 보지 않음",
  shortener: "단축 주소",
  brand_site: "사칭한 브랜드의 진짜 사이트(확인된 목록)",
  limit_or_duplicate: "자동 한도·중복",
});

// 연관 후보 상태(근거 카드·경로 지도와 같은 기준). pending: 지금 하위 조사 중인 후보
function candState(x: Candidate, pending: boolean): { label: string; tone: string } {
  const base = candStateBase(x, pending);
  // 회선 차단은 조사 대상 서버가 흉내 낼 수 있는 추정이라 위협 표시를 가리지 않고 덧붙인다
  return x.blocked && !pending ? { ...base, label: `${base.label} · 회선 차단 추정` } : base;
}
function candStateBase(x: Candidate, pending: boolean): { label: string; tone: string } {
  if (pending) return { label: "조사 중", tone: "st-RUNNING" };
  if (x.reputation_match) return { label: "평판 위험", tone: "st-threat" };
  if (!x.sub) return { label: "기록만", tone: "" };
  const th = x.threat ?? "";
  if (th && th !== "benign" && th !== "unknown") {
    return { label: `${x.hold ? "보류" : "위협 의심"} · ${THREAT_LABEL[th] ?? th}${x.probability != null ? ` ${pct(x.probability)}` : ""}`, tone: x.hold ? "st-REVIEW_REQUIRED" : "st-threat" };
  }
  if (x.hold) return { label: "보류", tone: "st-REVIEW_REQUIRED" };
  return th === "benign" ? { label: "정상", tone: "st-COMPLETED" } : { label: "판단 없음", tone: "" };
}

// 연관 사이트: 이 신고에서 찾은 다른 사이트(같은 조직이 운영할 수 있는 곳). 하위 조사는 원래 판정을 바꾸지 않는다.
// 후보마다 [새 사건으로 접수](조사관 이상) → 전체 조사. 이미 만든 후보는 그 사건으로 간다
function RelatedTab({
  id,
  c,
  events,
  related,
  canCreate,
  onOpen,
  onChanged,
}: {
  id: string;
  c: CaseOut;
  events: EvidenceEvent[];
  related: boolean;
  canCreate: boolean;
  onOpen: (id: string) => void;
  onChanged: () => void;
}) {
  const cands = (c.candidates ?? []).filter((x): x is Candidate => typeof x !== "string");
  const kids = new Map((c.children ?? []).map((k) => [k.candidate_url, k]));
  const skipped = new Map((c.auto_skipped ?? []).map((x) => [x.url, x.reason]));
  const planned = num([...events].reverse().find((e) => e.kind === "candidates")?.data.investigated);
  const [busy, setBusy] = useState("");
  const [msg, setMsg] = useState("");
  if (cands.length === 0) {
    return (
      <div className="floor">
        <p className="muted">연관 후보 없음</p>
      </div>
    );
  }
  return (
    <div className="floor">
      <p className="muted small">같은 조직이 운영할 수 있는 다른 사이트입니다. 하위 조사는 원래 사건의 판정을 바꾸지 않습니다.</p>
      <ul className="rel-list">
        {cands.map((x, i) => {
          const kid = kids.get(x.url);
          const st = candState(x, related && !x.sub && Number.isFinite(planned) && i < planned);
          return (
            <li key={x.url} className="rel-row">
              <span className="rel-site">
                <span className="mono">{clip(x.host ?? hostPath(x.url), 48)}</span>
                <span className="muted small">
                  {x.source === "via" ? "경유" : "링크"}
                  {x.text ? ` · “${clip(x.text, 40)}”` : ""}
                  {!kid && skipped.has(x.url) ? ` · 자동 접수 안 함(${AUTO_SKIP_LABEL[skipped.get(x.url) ?? ""] ?? "기타"})` : ""}
                </span>
              </span>
              <span className={`chip ${st.tone}`}>{st.label}</span>
              {kid ? (
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => onOpen(kid.id)}>
                  {kid.auto ? "자동 접수됨 · " : ""}사건 보기 · {kid.verdict === "threat" ? "위협 확정" : kid.verdict === "benign" ? "정상 확정" : (STATUS_LABEL[kid.status] ?? kid.status)}
                </button>
              ) : canCreate ? (
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  disabled={busy !== ""}
                  onClick={async () => {
                    setBusy(x.url);
                    setMsg("");
                    try {
                      await createRelated(id, x.url);
                      onChanged();
                    } catch (e) {
                      setMsg(e instanceof Error ? e.message : "접수하지 못했습니다");
                    } finally {
                      setBusy("");
                    }
                  }}
                >
                  {busy === x.url ? "접수 중" : "새 사건으로 접수"}
                </button>
              ) : (
                <span />
              )}
            </li>
          );
        })}
      </ul>
      {msg && (
        <p className="err" role="alert">
          {msg}
        </p>
      )}
    </div>
  );
}

function ScreensTab({
  id,
  c,
  events,
  screens,
  pick,
  onPick,
}: {
  id: string;
  c: CaseOut | null;
  events: EvidenceEvent[];
  screens: Screen[];
  pick: string | null;
  onPick: (f: string) => void;
}) {
  const opts = useRef<(HTMLButtonElement | null)[]>([]);
  const [marksOn, setMarksOn] = useState(true);
  if (screens.length === 0) {
    const un = [...events].reverse().find((e) => e.kind === "unreachable");
    const why = un ? (NET_CATEGORY_LABEL[text(un.data.category)] ?? text(un.data.error)) : c?.finish_reason ? (REASON_LABEL[c.finish_reason] ?? c.finish_reason) : "";
    return (
      <div className="floor">
        <p className="muted">화면 기록 없음{why ? ` · ${why}` : ""}</p>
      </div>
    );
  }
  const cur = screens.find((x) => x.file === pick) ?? screens[0];
  const overlay = buildOverlay(events, cur.seq);
  const nForbidden = overlay?.marks.filter((m) => m.kind === "forbidden").length ?? 0;
  const act = overlay?.marks.find((m) => m.kind !== "forbidden");
  const onKey = (e: React.KeyboardEvent, i: number) => {
    const step = e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : e.key === "ArrowUp" || e.key === "ArrowLeft" ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const j = (i + step + screens.length) % screens.length;
    onPick(screens[j].file);
    opts.current[j]?.focus();
  };
  return (
    <div className="floor screens">
      <figure className="shot">
        <div className="shot-box screen-body">
          {/* 고른 화면마다 새로 받는다: 못 받으면 앞 화면을 남기지 않고 실패를 보인다(캡션과 화면이 어긋나지 않게) */}
          <LiveScreen key={cur.file} caseId={id} name={cur.file} strict overlay={marksOn ? overlay : null} />
        </div>
        <figcaption className="shot-cap">
          <b className={`tone-${cur.tone} tone-text`}>
            {CIRCLED[cur.n - 1]} {cur.title}
          </b>
          <span className="muted">{cur.ev}</span>
          {cur.url && (
            <span className="muted" title={cur.url}>
              {clip(hostPath(cur.url), 40)}
            </span>
          )}
          <span className="shot-note">{cur.note}</span>
          {text(events.find((e) => e.seq === cur.seq)?.data.capture) === "expanded" && <span className="muted small">{EXPANDED_NOTE}</span>}
          {overlay && (
            <span className="mark-legend">
              {nForbidden > 0 && <span className="lg lg-forbidden">금지 요소 {nForbidden}</span>}
              {act && <span className={`lg lg-${act.kind}`}>{act.label}</span>}
              <button type="button" className="btn btn-ghost btn-sm" aria-pressed={marksOn} onClick={() => setMarksOn(!marksOn)}>
                {marksOn ? "화면 표시 끄기" : "화면 표시 켜기"}
              </button>
            </span>
          )}
        </figcaption>
      </figure>
      <div className="thumbs" role="listbox" aria-label="근거 화면 목록">
        {screens.map((x, i) => (
          <button
            key={x.file}
            ref={(el) => {
              opts.current[i] = el;
            }}
            type="button"
            role="option"
            aria-selected={x.file === cur.file}
            tabIndex={x.file === cur.file ? 0 : -1}
            className="thumb"
            onClick={() => onPick(x.file)}
            onKeyDown={(e) => onKey(e, i)}
          >
            <Thumb caseId={id} name={x.file} />
            <span className="thumb-text">
              <span className={`thumb-title tone-${x.tone} tone-text`}>
                {CIRCLED[x.n - 1]} {x.title}
              </span>
              <span className="thumb-sub">
                {x.ev} · {clip(hostOrFile(x.url), 30)}
              </span>
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

// 썸네일: 표시용으로 줄인 이미지(preview)를 필요할 때 받고, 사라지면 object URL 을 돌려준다
function Thumb({ caseId, name }: { caseId: string; name: string }) {
  const [src, setSrc] = useState("");
  useEffect(() => {
    let alive = true;
    let u = "";
    fileUrl(caseId, name, true)
      .then((x) => {
        u = x;
        if (alive) setSrc(x);
        else URL.revokeObjectURL(x);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
      if (u) URL.revokeObjectURL(u);
    };
  }, [caseId, name]);
  return <span className="thumb-img">{src && <img src={src} alt="" />}</span>;
}

// ── 경로 지도: 그래프 라이브러리 없이 칸(열 = 본 줄 주소)과 아래 가지로 그린다 ─────────────
function PathTab({ c, events }: { c: CaseOut; events: EvidenceEvent[] }) {
  const m = useMemo(() => buildPath(c, events), [c, events]);
  const th = c.threat;
  const thTone: Tone = !th || th.threat === "unknown" ? "idle" : th.threat === "benign" ? "safe" : th.hold ? "review" : "threat";
  if (m.nodes.length === 1 && m.branches[0].length === 0) {
    return (
      <div className="floor pathfloor">
        <p className="muted small">거쳐 간 주소가 1곳뿐입니다</p>
        <div className="path">
          <PathNodeBox n={m.nodes[0]} i={0} tone={thTone} threat={th?.threat ?? null} prob={th?.probability ?? null} hold={!!th?.hold} />
        </div>
      </div>
    );
  }
  let num = 0;
  return (
    <div className="floor pathfloor">
      <div className="path">
        {m.nodes.map((n, i) => {
          // 접힌 곳도 번호에 센다(접힌 뒤 번호가 실제 몇 번째 주소인지 맞게)
          num += n.fold ?? 1;
          return (
            <div key={`${i}-${n.url}`} className="path-col-wrap">
              {i > 0 && (
                <svg className="path-arrow" viewBox="0 0 40 10" aria-hidden="true">
                  <path d="M0 5 H34" />
                  <path d="M33 1 L39 5 L33 9 Z" className="path-arrow-head" />
                </svg>
              )}
              <div className="path-col">
                {n.fold ? (
                  <div className="path-node path-fold">… {n.fold}곳</div>
                ) : (
                  <PathNodeBox n={n} i={num - 1} tone={thTone} threat={n.last ? (th?.threat ?? null) : null} prob={n.last ? (th?.probability ?? null) : null} hold={!!th?.hold} />
                )}
                {m.branches[i].map((b, j) => (
                  <div key={j} className="path-branch">
                    <span className={`path-link ${b.dashed ? "dashed" : ""} tone-${b.tone}`} aria-hidden="true" />
                    <div className={`path-node branch tone-${b.tone} ${b.dashed ? "dashed" : ""}`}>
                      <span className="tone-text">{b.title}</span>
                      <b>{b.sub}</b>
                    </div>
                  </div>
                ))}
                {n.last && m.more > 0 && <span className="muted small">+{m.more}개</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function PathNodeBox({ n, i, tone, threat, prob, hold }: { n: { url: string; label: string; newWindow: boolean; last: boolean }; i: number; tone: Tone; threat: string | null; prob: number | null; hold: boolean }) {
  return (
    <div className={`path-node ${n.last ? `last tone-${tone}` : ""}`} title={n.url}>
      <span className="muted">
        {CIRCLED[i] ?? `${i + 1}.`} {n.label}
        {n.newWindow ? " · 새 창" : ""}
      </span>
      <b>{clip(hostPath(n.url), 24)}</b>
      {n.last && threat && (
        <span className="tone-text path-verdict">
          {THREAT_LABEL[threat] ?? threat}
          {hold ? "(보류)" : ""} {prob != null ? pct(prob) : ""}
        </span>
      )}
    </div>
  );
}

// ── 아래 줄(모든 탭 공통): Safe Browsing · 증거 무결성 검증 · 보고서·패키지 ─────────────
function CaseFooterBar({
  c,
  id,
  running,
  related = false,
  canExport,
  verify,
  onVerify,
}: {
  c: CaseOut | null;
  id: string;
  running: boolean;
  related?: boolean;
  canExport: boolean;
  verify: VerifyState;
  onVerify: (v: VerifyState) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [pkgBusy, setPkgBusy] = useState("");
  const [pkgMsg, setPkgMsg] = useState("");
  const sb = c?.safebrowsing;
  const sbText =
    sb?.status === "match"
      ? sb.matches.map((m) => m.threat_type).join(", ")
      : sb?.status === "no_match"
        ? "일치 없음"
        : sb?.status === "not_configured"
          ? "키 없음"
          : (sb?.status ?? "-");
  return (
    <div className="footbar">
      <span>
        Safe Browsing <b className={sb?.status === "match" ? "bad" : ""}>{sbText}</b>
        {sb?.status === "no_match" && <span className="muted small"> (일치 없음은 정상이라는 뜻이 아닙니다)</span>}
      </span>
      <span className={`integrity-inline ${verify ? (verify.ok ? "ok" : "bad") : ""}`}>
        {verify
          ? verify.ok
            ? `✓ 해시 체인 · HMAC 서명 통과 · 서명 기록 ${verify.records}건`
            : `× 검증 실패 ${verify.errors.slice(0, 3).join(", ")}`
          : "증거 무결성"}
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          disabled={busy || running}
          onClick={async () => {
            setBusy(true);
            try {
              onVerify(await verifyCase(id));
            } catch (e) {
              onVerify({ ok: false, records: 0, errors: [e instanceof Error ? e.message : "검증 실패"] });
            } finally {
              setBusy(false);
            }
          }}
        >
          {verify ? "다시 검증" : "검증"}
        </button>
      </span>
      <div className="spacer" />
      {canExport ? (
        (
          [
            ["report.pdf", "보고서 PDF"],
            ["report.json", "JSON"],
            ["package.zip", "검토 패키지 ZIP"],
          ] as const
        ).map(([kind, label]) => (
          <button
            key={kind}
            type="button"
            className="btn btn-ghost btn-sm"
            title={kind === "package.zip" ? "검토 패키지: 체인 원본·파일·보고서 포함" : "보고서 초안(기관 양식용 요약)"}
            disabled={pkgBusy !== "" || running || !c}
            onClick={async () => {
              setPkgBusy(kind);
              setPkgMsg("");
              try {
                await downloadExport(id, kind);
              } catch (e) {
                setPkgMsg(e instanceof Error ? e.message : "내려받기 실패");
              } finally {
                setPkgBusy("");
              }
            }}
          >
            {pkgBusy === kind ? "만드는 중" : label}
          </button>
        ))
      ) : (
        <span className="muted small">보고서·패키지 내려받기는 조사관 이상만 할 수 있습니다</span>
      )}
      {related && canExport && <span className="muted small">연관 사이트 조사가 끝나면 내려받을 수 있습니다</span>}
      {pkgMsg && (
        <p className="err" role="alert" style={{ flexBasis: "100%" }}>
          {pkgMsg}
        </p>
      )}
    </div>
  );
}

// 증거 파일은 인증 헤더가 필요하므로 blob URL 로 보여 준다
// 조사 녹화(영상)
// 조사 녹화 이어 재생: 원래 주소와 연관 후보 하위 조사의 녹화를 한 재생 막대로 잇는다. 파일은 증거라 합치지 않고 따로 둔 채
// 구간마다 <video> 를 겹쳐 두고 구간 순서대로 미리 받아 두었다가, 한 구간이 끝나면 다음 구간을 위로 올려 이어 튼다(받는 동안
// 끊기지 않게). 위쪽 버튼은 구간 바로가기. 클릭 표시는 구간마다 그 녹화의 0초 시각(t0)으로 맞춘다(커서는 누르기 0.6초 전에
// 그 버튼으로 미끄러져 가고, 누르는 순간 물결)
const REC_RATES = [0.5, 1, 1.5, 2];
const REC_MAX_S = 3600; // 구간 길이 상한(기록·파일 값을 믿지 않는다)
// 미리 받는 녹화 합계 상한: 예전에 한 번에 하나만 보던 녹화 파일의 상한(서버 FILE_MAX_BYTES)과 같게. 정상 녹화는 후보 5개여도
// 200MB 남짓(5Mbps · 원래 주소 120초 + 후보 40초씩)이고, 뚫린 조사 컨테이너가 큰 녹화를 여러 개 만들어도 담당자 브라우저가 버틴다
const REC_BUDGET = 512 << 20;
const recLabel = (r: RecItem) => (r.sub ? `후보 ${r.sub}` : "원래 주소");
const mmss = (s: number) => {
  const t = Math.max(0, Math.floor(s));
  return `${Math.floor(t / 60)}:${String(t % 60).padStart(2, "0")}`;
};
function RecordingPlayer({ caseId, recs, events }: { caseId: string; recs: RecItem[]; events: EvidenceEvent[] }) {
  // 파일마다 blob URL(없으면 받는 중)·받지 못한 까닭, 파일에서 읽은 길이(초)
  const [urls, setUrls] = useState<Record<string, string>>({});
  const [fail, setFail] = useState<Record<string, string>>({});
  const [lens, setLens] = useState<Record<string, number>>({});
  const [cur, setCur] = useState(0);
  const [local, setLocal] = useState(0); // 지금 구간 안의 재생 위치(초)
  const [playing, setPlaying] = useState(false);
  const [rate, setRate] = useState(1);
  const [full, setFull] = useState(false);
  const vids = useRef<(HTMLVideoElement | null)[]>([]);
  const wrap = useRef<HTMLDivElement>(null);
  const curRef = useRef(0); // 이벤트 처리기에서 볼 지금 구간(상태는 다음 그리기 때 바뀐다)
  const wantPlay = useRef(false); // 재생하려는 중(다음 구간을 아직 받는 중이어도)
  // 받기: 한 줄로 차례대로(합계 상한을 지키고 앞 구간부터 준비되게). 지워지면(gen 증가) 받는 중이던 것은 버린다
  const store = useRef({ gen: 0, got: {} as Record<string, string | undefined>, queue: [] as string[], busy: false, used: 0 });

  // 조사 중에는 녹화가 늘어난다: 새 파일만 줄에 넣는다. 이름을 이어 붙였다 나누지 않고(이름 안의 구분자로 요청이 불어나지 않게)
  // 받기 시도는 실패를 포함해 녹화 수 상한까지만
  const files = JSON.stringify(recs.map((r) => r.file));
  useEffect(() => {
    const s = store.current;
    for (const f of JSON.parse(files) as string[]) {
      if (f in s.got || Object.keys(s.got).length >= MAX_RECORDINGS) continue;
      s.got[f] = undefined;
      s.queue.push(f);
    }
    if (s.busy) return;
    s.busy = true;
    const gen = s.gen;
    void (async () => {
      while (s.queue.length && s.gen === gen) {
        const f = s.queue.shift()!;
        try {
          const b = await fileBlob(caseId, f, REC_BUDGET - s.used);
          if (s.gen !== gen) break;
          s.used += b.size;
          const u = URL.createObjectURL(b);
          s.got[f] = u;
          setUrls((m) => ({ ...m, [f]: u }));
        } catch (e) {
          if (s.gen !== gen) break;
          const why = e instanceof ApiError && e.status === 413 ? "녹화가 커서 이어 재생에 넣지 않음" : "이 구간의 녹화를 불러오지 못함";
          setFail((m) => ({ ...m, [f]: why }));
        }
      }
      if (s.gen === gen) s.busy = false;
    })();
  }, [caseId, files]);
  useEffect(() => {
    const s = store.current;
    return () => {
      s.gen++;
      for (const u of Object.values(s.got)) if (u) URL.revokeObjectURL(u);
      Object.assign(s, { got: {}, queue: [], busy: false, used: 0 });
    };
  }, []);
  // 재생 중에는 화면 주기마다 재생 위치를 읽는다(timeupdate 는 초당 4번뿐)
  useEffect(() => {
    if (!playing) return;
    let raf = 0;
    const tick = () => {
      const v = vids.current[curRef.current];
      if (v) setLocal(v.currentTime);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing]);
  useEffect(() => {
    const on = () => setFull(!!wrap.current && document.fullscreenElement === wrap.current);
    document.addEventListener("fullscreenchange", on);
    return () => document.removeEventListener("fullscreenchange", on);
  }, []);
  const clicks = useMemo(() => recs.map((r) => recordingClicks(events, r.ev)), [events, recs]);

  // 구간 길이: 파일에서 읽은 길이(재생되는 실제 길이), 아직 모르면 서명 기록의 길이
  const durs = recs.map((r) => Math.min(Math.max(lens[r.file] ?? r.seconds ?? 0, 0), REC_MAX_S));
  const starts = segStarts(durs);
  const n = recs.length;
  const total = starts[n - 1] + durs[n - 1];
  const ci = Math.min(cur, n - 1);
  const pos = Math.min(starts[ci] + Math.min(local, durs[ci]), total);
  const failed = (i: number) => recs[i].file in fail;
  const nextPlayable = (i: number) => {
    for (let j = i + 1; j < n; j++) if (!failed(j)) return j;
    return -1;
  };
  const segName = (i: number) => `${recLabel(recs[i])}${recs[i].host ? ` · ${clip(recs[i].host, 40)}` : ""}`;

  // i 번째 구간의 t 초로 옮긴다(play: 이어서 재생). 못 받은 구간을 재생하려 하면 다음 구간으로
  const go = (i: number, t: number, play: boolean) => {
    if (play && failed(i)) {
      const j = nextPlayable(i);
      if (j >= 0) return go(j, 0, true);
      play = false;
    }
    const prev = vids.current[curRef.current];
    const v = vids.current[i];
    curRef.current = i; // 앞 구간을 멈출 때 나는 pause 이벤트는 무시된다
    wantPlay.current = play;
    if (prev && prev !== v) prev.pause();
    setCur(i);
    setLocal(t);
    if (!play) setPlaying(false);
    if (!v) return;
    if (Math.abs(v.currentTime - t) > 0.05) v.currentTime = t;
    if (!play) v.pause();
    else if (v.readyState >= 2) v.play().catch(() => undefined); // 아직 받는 중이면 canplay 때 재생
  };
  const toggle = () => {
    if (playing || wantPlay.current) {
      wantPlay.current = false;
      vids.current[curRef.current]?.pause();
      setPlaying(false);
      return;
    }
    if (pos >= total - 0.05) return go(0, 0, true); // 끝에서 누르면 처음부터
    go(ci, vids.current[ci]?.currentTime ?? local, true);
  };
  const seek = (g: number) => {
    const { i, local: t } = locateSeg(durs, Math.min(Math.max(g, 0), total));
    go(i, t, wantPlay.current);
  };
  const onRangeKey = (e: React.KeyboardEvent) => {
    let g: number | null = null;
    if (e.key === "ArrowRight" || e.key === "ArrowUp") g = pos + 5;
    else if (e.key === "ArrowLeft" || e.key === "ArrowDown") g = pos - 5;
    else if (e.key === "PageDown") g = ci + 1 < n ? starts[ci + 1] : total; // 다음 구간 처음
    else if (e.key === "PageUp") g = local > 1 || ci === 0 ? starts[ci] : starts[ci - 1]; // 이 구간 처음(처음이면 앞 구간)
    else if (e.key === "Home") g = 0;
    else if (e.key === "End") g = total;
    else if (e.key === " " || e.key === "k") {
      e.preventDefault();
      toggle();
      return;
    }
    if (g === null) return;
    e.preventDefault();
    seek(g);
  };
  const changeRate = (r: number) => {
    setRate(r);
    for (const v of vids.current) {
      if (!v) continue;
      v.defaultPlaybackRate = r;
      v.playbackRate = r;
    }
  };
  const toggleFull = () => {
    if (document.fullscreenElement) document.exitFullscreen().catch(() => undefined);
    else wrap.current?.requestFullscreen().catch(() => undefined);
  };

  // 영상 이벤트는 지금 구간의 것만 본다
  const onMeta = (i: number, v: HTMLVideoElement) => {
    v.defaultPlaybackRate = rate;
    v.playbackRate = rate;
    const d = v.duration;
    if (Number.isFinite(d) && d > 0) setLens((m) => ({ ...m, [recs[i].file]: d }));
  };
  const onPause = (i: number, v: HTMLVideoElement) => {
    if (i !== curRef.current) return;
    if (v.ended && wantPlay.current && nextPlayable(i) >= 0) return; // 다음 구간으로 넘어가는 중(ended 가 곧 온다)
    wantPlay.current = false;
    setPlaying(false);
  };
  const onEnded = (i: number) => {
    if (i !== curRef.current) return;
    const j = nextPlayable(i);
    if (j >= 0 && wantPlay.current) return go(j, 0, true);
    wantPlay.current = false;
    setPlaying(false);
    setLocal(durs[i]);
  };
  const sync = (i: number, v: HTMLVideoElement) => {
    if (i === curRef.current && v.paused) setLocal(v.currentTime);
  };

  const msg = fail[recs[ci].file] ?? (urls[recs[ci].file] ? "" : "불러오는 중…");
  // 커서: 곧 누를 클릭으로 미리 가거나(화면을 옮긴 클릭은 옮긴 뒤에) 마지막으로 누른 곳. 누른 표시는 0.7초 동안.
  // 이동 시간은 영상 시간이라 재생 속도로 나눈다
  const cl = clicks[ci] ?? [];
  const cursor = recCursor(cl, local);
  const mark = cursor ? cl[cursor.k] : null;
  const hitKey = cursor && local >= cursor.hitAt && local <= cursor.hitAt + 0.7 ? cursor.k : null;
  return (
    <div className="rec-player" ref={wrap}>
      {n > 1 && (
        <div className="rec-pick" role="group" aria-label="녹화 구간 바로가기">
          {recs.map((r, i) => (
            <button key={r.file} type="button" className="chip-filter" aria-pressed={i === ci} onClick={() => go(i, 0, wantPlay.current)}>
              {recLabel(r)}
              {r.host && <> · <span className="mono">{clip(r.host, 40)}</span></>}
              {r.seconds !== null && ` · ${r.seconds.toFixed(1)}초`}
            </button>
          ))}
        </div>
      )}
      <div className="rec-box">
        {recs.map((r, i) => (
          <video
            key={r.file}
            ref={(el) => {
              vids.current[i] = el;
            }}
            src={urls[r.file]}
            className={i === ci ? "on" : undefined}
            preload="auto"
            muted
            playsInline
            aria-hidden={i !== ci}
            onClick={toggle}
            onLoadedMetadata={(e) => onMeta(i, e.currentTarget)}
            onCanPlay={(e) => {
              if (i === curRef.current && wantPlay.current && e.currentTarget.paused) e.currentTarget.play().catch(() => undefined);
            }}
            onPlay={() => i === curRef.current && setPlaying(true)}
            onPause={(e) => onPause(i, e.currentTarget)}
            onEnded={() => onEnded(i)}
            onSeeked={(e) => sync(i, e.currentTarget)}
            onTimeUpdate={(e) => sync(i, e.currentTarget)}
          />
        ))}
        {msg && <span className="small rec-msg">{msg}</span>}
        {n > 1 && <span className="rec-seg-label">{segName(ci)}</span>}
        {mark && cursor && <ClickMark p={mark} hitKey={hitKey} align="middle" travel={cursor.travel / rate} />}
      </div>
      <div className="rec-ctl">
        <button type="button" className="btn btn-ghost btn-sm rec-btn rec-play" aria-label={playing ? "일시정지" : "재생"} title={playing ? "일시정지" : "재생"} onClick={toggle}>
          <svg viewBox="0 0 16 16" aria-hidden="true">
            {playing ? <path d="M3 2h4v12H3zM9 2h4v12H9z" /> : <path d="M4 2l10 6-10 6z" />}
          </svg>
        </button>
        <div className="rec-track">
          <div className="rec-segs" aria-hidden="true">
            {recs.map((r, i) => {
              const w = total > 0 ? (durs[i] / total) * 100 : 100 / n;
              const f = durs[i] > 0 ? Math.min(Math.max((pos - starts[i]) / durs[i], 0), 1) : 0;
              return (
                <span key={r.file} className={`rec-seg${i === ci ? " on" : ""}${failed(i) ? " err" : ""}`} style={{ width: `${w}%` }} title={segName(i)}>
                  <span className="rec-seg-fill" style={{ width: `${f * 100}%` }} />
                </span>
              );
            })}
          </div>
          <input
            type="range"
            className="rec-range"
            min={0}
            max={total}
            step="any"
            value={pos}
            disabled={total <= 0}
            onChange={(e) => seek(Number(e.target.value))}
            onKeyDown={onRangeKey}
            aria-label="재생 위치"
            aria-valuetext={`${n > 1 ? `${segName(ci)}, ` : ""}${mmss(pos)} / ${mmss(total)}`}
          />
        </div>
        <span className="mono small rec-time">
          {mmss(pos)} / {mmss(total)}
        </span>
        <select className="field rec-rate" aria-label="재생 속도" value={rate} onChange={(e) => changeRate(Number(e.target.value))}>
          {REC_RATES.map((r) => (
            <option key={r} value={r}>
              {r}×
            </option>
          ))}
        </select>
        <button type="button" className="btn btn-ghost btn-sm rec-btn" aria-label={full ? "전체 화면 끝내기" : "전체 화면"} title={full ? "전체 화면 끝내기" : "전체 화면"} onClick={toggleFull}>
          <svg viewBox="0 0 16 16" aria-hidden="true">
            {full ? <path d="M6 1v5H1V4h3V1zM10 1h2v3h3v2h-5zM1 10h5v5H4v-3H1zM10 10h5v2h-3v3h-2z" /> : <path d="M1 1h5v2H3v3H1zM10 1h5v5h-2V3h-3zM1 10h2v3h3v2H1zM13 10h2v5h-5v-2h3z" />}
          </svg>
        </button>
      </div>
    </div>
  );
}

// 라이브 영상: 에이전트 화면 전송 프레임을 WebSocket 으로 받아 canvas 에 그린다(보기용, 증거 아님).
// 디코드가 밀리면 최신 프레임만 그린다. 첫 프레임이 오기 전·연결이 안 될 때는 fallback(단계별 화면)을 보여 준다.
// 실시간 화면 재생: 받은 즉시 그리지 않고 LIVE_DELAY_MS 만큼 모았다가 받은 간격의 평균으로 고르게 그린다(떨림 줄이기).
// LIVE_GAP_MS 넘게 멈췄다가 오는 프레임(페이지 이동·관찰 중 멈춤 뒤)은 LIVE_FADE_MS 동안 겹쳐 바꾼다. 밀리면 오래된 프레임을 버린다.
const LIVE_DELAY_MS = 150;
const LIVE_GAP_MS = 250;
const LIVE_FADE_MS = 150;
const LIVE_MAX_QUEUE = 12; // 초당 60장이면 재생 버퍼(LIVE_DELAY_MS)에 약 9장이 머문다
const LIVE_MAX_LAG_MS = 450;
// 받는 쪽 상한(Codex 지적: 침해된 에이전트가 통로로 메시지를 쏟아내도 콘솔이 디코딩을 끝없이 시작하지 않게).
// 정상 프레임은 1280×800 JPEG 수백 KB, 초당 60장 이하
const LIVE_MAX_BYTES = 2 * 1024 * 1024;
const LIVE_MAX_DECODING = 2;
// 디코드 전에 JPEG 머리로 해상도를 본다: 2MiB 안에 압축된 초고해상도 이미지는 디코드하면 장당 수백 MB 다(Codex 지적).
// 디코드 결과도 화면 크기로 받는다(버퍼에 쌓이는 메모리를 장당 약 4MB 로)
const LIVE_MAX_SIDE = 2560;

function LiveVideo({
  caseId,
  onFps,
  onEnd,
  onShown,
  onClick,
  onActivity,
  fallback,
}: {
  caseId: string;
  onFps: (fps: number) => void;
  onEnd: () => void;
  onShown?: () => void;
  onClick?: (p: ClickPoint) => void;
  onActivity?: (a: Activity) => void;
  fallback: React.ReactNode;
}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  // 캔버스는 첫 프레임을 실제로 그린 뒤에 보인다(그 전에는 fallback). 메시지가 오자마자 바꾸면 재생 버퍼(LIVE_DELAY_MS)와
  // 디코드 동안 빈 캔버스(어두운 바탕)가 보여 깜빡였다
  const [hasFrame, setHasFrame] = useState(false);
  const cb = useRef({ onFps, onEnd, onShown, onClick, onActivity });
  cb.current = { onFps, onEnd, onShown, onClick, onActivity };

  useEffect(() => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/cases/${encodeURIComponent(caseId)}/live`);
    ws.binaryType = "blob";
    let alive = true;
    let got = false; // 프레임 메시지를 받았다(없으면 8초 뒤 단계별 화면으로)
    let painted = false; // 첫 프레임을 그렸다
    let count = 0;
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    // 받은 프레임(디코드 끝남)을 받은 시각과 함께 쌓아 두고, 화면 주기마다 꺼내 그린다
    const queue: { bmp: ImageBitmap; at: number }[] = [];
    const clicks: { p: ClickPoint; at: number }[] = []; // 클릭 표시: 프레임과 같은 지연으로 내보낸다
    const acts: { a: Activity; at: number }[] = []; // 지금 하는 일: 클릭 표시처럼 프레임과 같은 지연으로(받은 순서대로)
    let shown: ImageBitmap | null = null; // 지금 그린 프레임
    let shownAt = 0; // 그 프레임을 받은 시각
    let lastPresent = 0;
    let fadeFrom: ImageBitmap | null = null; // 겹쳐 바꾸는 중인 이전 프레임
    let fadeStart = 0;
    let iv = 1000 / 60; // 이어서 올 때의 프레임 간격(ms, 이동 평균)
    let vsync = 1000 / 60; // 화면 주기(ms, 이동 평균)
    let lastRaf = 0;
    let lastArrival = 0;
    let raf = 0;
    let decoding = 0; // 디코드 중인 프레임 수(최대 LIVE_MAX_DECODING)
    let waiting: { blob: Blob; at: number } | null = null; // 밀렸을 때 기다리는 가장 최근 프레임 하나
    let reading = 0; // 읽는 중인 작은 메시지 수
    const decode = (blob: Blob, at: number) => {
      decoding += 1;
      blob
        .slice(0, 65536)
        .arrayBuffer()
        .then((head) => {
          const size = jpegSize(new Uint8Array(head));
          if (!size || size[0] > LIVE_MAX_SIDE || size[1] > LIVE_MAX_SIDE) return null; // JPEG 가 아니거나 너무 큼
          // 메인 스레드 밖에서 디코드
          return createImageBitmap(blob, { resizeWidth: SCREEN_W, resizeHeight: SCREEN_H, resizeQuality: "medium" });
        })
        .then((bmp) => {
          if (!bmp) return;
          if (!alive) return bmp.close();
          let i = queue.length; // 디코드가 순서를 바꿔 끝내도 받은 순서대로
          while (i > 0 && queue[i - 1].at > at) i--;
          queue.splice(i, 0, { bmp, at });
          while (queue.length > LIVE_MAX_QUEUE) queue.shift()!.bmp.close();
        })
        .catch(() => undefined) // 깨진 프레임은 건너뛴다
        .finally(() => {
          decoding -= 1;
          if (waiting && alive) {
            const w = waiting;
            waiting = null;
            decode(w.blob, w.at);
          }
        });
    };
    const paint = (now: number) => {
      const c = canvas.current;
      const ctx = c?.getContext("2d");
      if (!c || !ctx || !shown) return;
      if (fadeFrom) {
        const k = (now - fadeStart) / LIVE_FADE_MS;
        if (k < 1) {
          ctx.globalAlpha = 1;
          ctx.drawImage(fadeFrom, 0, 0, c.width, c.height);
          ctx.globalAlpha = Math.max(0, k);
          ctx.drawImage(shown, 0, 0, c.width, c.height);
          ctx.globalAlpha = 1;
          return;
        }
        fadeFrom.close();
        fadeFrom = null;
      }
      ctx.drawImage(shown, 0, 0, c.width, c.height);
    };
    const present = (f: { bmp: ImageBitmap; at: number }, now: number) => {
      const old = shown;
      // 잠시 멈췄다가(페이지 이동·관찰 중) 바뀌는 프레임은 짧게 겹쳐 바꾼다. 이어서 오는 프레임은 바로
      if (old && f.at - shownAt > LIVE_GAP_MS && !reduce) {
        if (fadeFrom) fadeFrom.close();
        fadeFrom = old;
        fadeStart = now;
      } else if (old && old !== fadeFrom) {
        old.close();
      }
      shown = f.bmp;
      shownAt = f.at;
      lastPresent = now;
      paint(now);
      if (!painted) {
        painted = true;
        setHasFrame(true);
        cb.current.onShown?.();
      }
    };
    const loop = (now: number) => {
      // 너무 밀렸으면(받은 지 오래된 프레임) 최근 것만 남긴다
      while (queue.length > 1 && now - queue[0].at > LIVE_DELAY_MS + LIVE_MAX_LAG_MS) queue.shift()!.bmp.close();
      while (clicks.length && now >= clicks[0].at + LIVE_DELAY_MS) cb.current.onClick?.(clicks.shift()!.p);
      while (acts.length && now >= acts[0].at + LIVE_DELAY_MS) cb.current.onActivity?.(acts.shift()!.a);
      if (lastRaf) vsync = Math.min(50, Math.max(4, vsync * 0.9 + (now - lastRaf) * 0.1));
      lastRaf = now;
      // 받은 뒤 LIVE_DELAY_MS 가 지났고, 앞 프레임에서 평균 간격만큼 지났을 때(재생 버퍼에 머물 만큼보다 쌓이면 조금 빨리) 다음 프레임.
      // 화면 주기 반만큼 일찍 와도 그린다: 프레임 간격이 화면 주기와 같으면(60장·60Hz) 흔들림으로 한 주기씩 건너뛰어 30장처럼 보였다
      const backlog = queue.length > LIVE_DELAY_MS / iv + 2;
      if (queue.length && now + vsync / 2 >= Math.max(queue[0].at + LIVE_DELAY_MS, lastPresent + iv * (backlog ? 0.7 : 1))) {
        present(queue.shift()!, now);
      } else if (fadeFrom) {
        paint(now);
      }
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    const tick = setInterval(() => {
      cb.current.onFps(count);
      count = 0;
    }, 1000);
    const noFrame = setTimeout(() => {
      if (!got && alive) cb.current.onEnd(); // 라이브를 못 받으면 단계별 화면으로
    }, 8000);
    ws.onopen = () => ws.send(JSON.stringify({ token: getToken() }));
    ws.onmessage = (e) => {
      const blob = e.data;
      const at = performance.now();
      if (!(blob instanceof Blob) || blob.size > LIVE_MAX_BYTES) return;
      if (blob.size < 256) {
        // JPEG 프레임이 아닌 작은 메시지: 클릭 표시 {"click":[...]}, 지금 하는 일 {"act":...}. 모양이 틀리면 버린다.
        // 몰려오면 읽기 전에 버린다(지금 하는 일은 단계마다 몇 개라 동시에 읽는 수를 클릭 표시만 있을 때보다 조금 넉넉히)
        if (reading >= 4 || clicks.length >= 20 || acts.length >= 20) return;
        reading += 1;
        void blob
          .text()
          .then((t) => {
            const p = liveClick(t);
            if (p && alive && clicks.length < 20) clicks.push({ p, at });
            const a = p ? null : liveActivity(t);
            if (a && alive && acts.length < 20) {
              let i = acts.length; // 읽기가 순서를 바꿔 끝내도 받은 순서대로
              while (i > 0 && acts[i - 1].at > at) i--;
              acts.splice(i, 0, { a, at });
            }
          }, () => undefined)
          .finally(() => {
            reading -= 1;
          });
        return;
      }
      count += 1;
      got = true;
      const gap = at - lastArrival;
      if (lastArrival && gap <= LIVE_GAP_MS) iv = Math.min(120, Math.max(16, iv * 0.85 + gap * 0.15));
      lastArrival = at;
      if (decoding >= LIVE_MAX_DECODING) {
        waiting = { blob, at }; // 밀리면 디코드하기 전에 버리고 가장 최근 것 하나만 기다린다
        return;
      }
      decode(blob, at);
    };
    // 조사가 끝나 서버가 정상으로 닫으면(1000) 마지막 프레임을 그대로 둔다(정지 화면으로 바꾸면 다시 받는 동안 깜빡였다).
    // 프레임을 하나도 못 그렸거나 연결이 끊긴 것이면 단계별 화면으로
    ws.onclose = (e) => {
      if (alive && !(e.code === 1000 && painted)) cb.current.onEnd();
    };
    return () => {
      alive = false;
      cancelAnimationFrame(raf);
      clearInterval(tick);
      clearTimeout(noFrame);
      cb.current.onFps(0);
      ws.close();
      for (const f of queue) f.bmp.close();
      shown?.close();
      if (fadeFrom && fadeFrom !== shown) fadeFrom.close();
    };
  }, [caseId]);

  return (
    <>
      {!hasFrame && fallback}
      <div className={hasFrame ? "live-wrap" : "live-wrap hidden"}>
        <canvas ref={canvas} width={1280} height={800} className="live-canvas" aria-label="조사 중인 격리 브라우저 실시간 화면" />
      </div>
    </>
  );
}

// 클릭 표시: 화면(1280×800) 좌표의 버튼 위에 커서와 누른 표시. 화면 크기에 맞춰 줄어드는 영상·캔버스와 같은 비율로 겹친다
// (align: 실시간 캔버스는 위쪽 맞춤, 녹화 영상은 가운데 맞춤). 커서는 앞 클릭 자리에서 travel 초 동안 미끄러져 오고(처음엔
// 그 자리에서 서서히), 누른 표시(대상 상자·물결)는 커서와 따로 대상 버튼에 고정해 hitDelay 초 뒤에 보인다 — 커서와 한 묶음이면
// 이동하는 동안 상자·물결이 커서를 따라 미끄러졌다. hitKey 가 바뀔 때 누른 표시가 다시 나온다
function ClickMark({ p, hitKey, align, travel, hitDelay = 0 }: { p: ClickPoint; hitKey: number | null; align: "top" | "middle"; travel: number; hitDelay?: number }) {
  const cx = p.x + p.w / 2;
  const cy = p.y + p.h / 2;
  const delay = { animationDelay: `${hitDelay}s` };
  return (
    <svg className="click-layer" viewBox={`0 0 ${SCREEN_W} ${SCREEN_H}`} preserveAspectRatio={align === "top" ? "xMidYMin meet" : "xMidYMid meet"} aria-hidden="true">
      {hitKey !== null && (
        <g transform={`translate(${cx} ${cy})`}>
          <g key={hitKey} className="click-hit" style={delay}>
            <rect className="click-target" x={-p.w / 2 - 4} y={-p.h / 2 - 4} width={p.w + 8} height={p.h + 8} rx="6" />
            <circle className="click-ripple" r="30" style={delay} />
          </g>
        </g>
      )}
      <g className="click-cursor" style={{ transform: `translate(${cx}px, ${cy}px)`, transitionDuration: `${travel}s` }}>
        <path className="click-arrow" style={{ animationDuration: `${CURSOR_IN}s` }} d="M0 0 L0 30 L8 22 L14 35 L20 32 L14 20 L25 20 Z" />
      </g>
    </svg>
  );
}

// 스크롤이 잠긴 페이지(html 이 막고 body 가 스크롤)는 에이전트가 캡처하는 동안만 펼쳐 찍는다(기록 capture: "expanded")
const EXPANDED_NOTE = "스크롤이 잠긴 페이지라 캡처하는 동안 펼쳐서 찍음";

// 화면 위 표시: 기록의 상자 좌표(캡처 픽셀)를 이미지와 같은 크기의 SVG 로 겹친다. 미리보기는 비율을 지키며 줄이므로
// 비율이 같을 때만 그린다(다르면 좌표가 이 이미지의 것이 아니다). 글자는 SVG title(React 텍스트)로만.
const sameRatio = (o: Overlay, f: Frame) => f.w > 0 && f.h > 0 && Math.abs(f.w / f.h - o.w / o.h) <= (o.w / o.h) * 0.01;
function Marks({ o }: { o: Overlay }) {
  return (
    <svg className="marks" viewBox={`0 0 ${o.w} ${o.h}`} preserveAspectRatio="none" aria-hidden="true">
      {o.marks.map((m, i) => (
        <g key={i}>
          <rect className="mark-halo" x={m.x} y={m.y} width={m.w} height={m.h} vectorEffect="non-scaling-stroke" />
          <rect className={`mark mark-${m.kind}`} x={m.x} y={m.y} width={m.w} height={m.h} vectorEffect="non-scaling-stroke">
            <title>{m.label}</title>
          </rect>
        </g>
      ))}
    </svg>
  );
}

// 실시간 화면: 새 화면을 다 받아 그릴 준비가 끝날 때까지 이전 화면을 그대로 두고(이중 버퍼) 교차 페이드로 바꾼다.
// 표시 방식은 한 가지: 폭에 맞추되 창 한 화면(1280×800 비율)이 칸 높이에 들어가게, 더 길면 세로 스크롤.
type Frame = { url: string; name: string; w: number; h: number };
// 받은 화면 사진(줄인 미리보기) 기억: 화면 요소가 새로 만들어져도(조사 중 화면 → 근거 화면 탭, 조사 끝) 같은 사진은 다시 받지 않고
// 그 자리에서 바로 보인다. 다시 받는 동안 어두운 바탕이 보였다가 서서히 나타나 깜빡였다. 최근 SHOT_CACHE_MAX 장까지 두고
// 밀려난 것만 해제한다(이미 그려진 사진은 그대로 보인다). 로그아웃하면 비운다(다음 계정이 서버 권한 확인 없이 보지 않게)
const SHOT_CACHE_MAX = 24;
const shotCache = new Map<string, Frame>();
// 로그아웃할 때 올린다: 그 전에 시작한 요청이 로그아웃 뒤에 끝나도 기억하지 않고 버린다(Codex 지적: 이전 세션 사진이 남았다)
let shotGen = 0;
const shotKey = (caseId: string, name: string) => `${caseId}/${name}`;
function cachedShot(caseId: string, name: string): Frame | null {
  const k = shotKey(caseId, name);
  const f = shotCache.get(k);
  if (!f) return null;
  shotCache.delete(k); // 최근에 쓴 것을 뒤로
  shotCache.set(k, f);
  return f;
}
function rememberShot(caseId: string, f: Frame) {
  const k = shotKey(caseId, f.name);
  const old = shotCache.get(k);
  if (old && old.url !== f.url) URL.revokeObjectURL(old.url);
  shotCache.delete(k);
  shotCache.set(k, f);
  for (const [key, v] of shotCache) {
    if (shotCache.size <= SHOT_CACHE_MAX) break;
    shotCache.delete(key);
    URL.revokeObjectURL(v.url);
  }
}
function clearShotCache() {
  shotGen++;
  for (const v of shotCache.values()) URL.revokeObjectURL(v.url);
  shotCache.clear();
}
// strict: 증거 화면 보기용. 받거나 그리지 못하면 실패를 표시한다(실시간 화면은 이전 화면을 유지)
function LiveScreen({ caseId, name, strict = false, overlay = null }: { caseId: string; name: string; strict?: boolean; overlay?: Overlay | null }) {
  // 기억해 둔 사진이면 처음부터 그 사진을 서서히 나타나지 않고 바로 보인다
  const [cur, setCur] = useState<Frame | null>(() => cachedShot(caseId, name));
  const [instant] = useState(() => cur?.url ?? "");
  const [failed, setFailed] = useState(false);
  const [prev, setPrev] = useState<Frame | null>(null);
  const [atEnd, setAtEnd] = useState(true);
  const curRef = useRef<Frame | null>(cur);
  const prevRef = useRef<Frame | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const frame = useRef<HTMLDivElement>(null);
  // 표시는 지금 떠 있는 사진이 요청한 그 파일일 때만(새 화면을 받는 동안 이전 사진 위에 새 상자를 그리지 않게)
  const marks = overlay && cur && cur.name === name && sameRatio(overlay, cur) ? overlay : null;
  const focus = marks?.marks.find((m) => m.kind !== "forbidden");

  const measure = useCallback(() => {
    const el = box.current;
    if (el) setAtEnd(el.scrollTop + el.clientHeight >= el.scrollHeight - 2);
  }, []);

  useEffect(() => {
    let alive = true;
    const show = (f: Frame) => {
      if (curRef.current?.url === f.url) return;
      prevRef.current = curRef.current;
      curRef.current = f;
      setPrev(prevRef.current);
      setCur(f);
      box.current?.scrollTo({ top: 0, behavior: "smooth" });
    };
    const hit = cachedShot(caseId, name);
    if (hit) {
      show(hit);
      return;
    }
    const gen = shotGen;
    (async () => {
      let url = "";
      const img = new Image();
      try {
        url = await fileUrl(caseId, name, true);
        img.src = url;
        await (strict ? img.decode() : img.decode().catch(() => undefined));
      } catch {
        if (url) URL.revokeObjectURL(url);
        if (strict && alive) setFailed(true);
        return; // 실시간 화면은 못 받으면 이전 화면 유지
      }
      if (gen !== shotGen) {
        URL.revokeObjectURL(url); // 받는 사이 로그아웃했다: 이전 세션의 사진은 기억하지도 보이지도 않는다
        return;
      }
      // 사진(blob URL)은 기억 장소가 갖는다: 화면을 떠나도 해제하지 않고 다음에 바로 쓴다
      const f = { url, name, w: img.naturalWidth, h: img.naturalHeight };
      rememberShot(caseId, f);
      if (alive) show(f);
    })();
    return () => {
      alive = false;
    };
  }, [caseId, name]);

  // 고른 버튼(또는 막은 클릭)이 보이는 범위 밖이면 그 위치로 스크롤한다(긴 페이지 아래쪽의 버튼).
  // 화면이나 상자 위치가 바뀔 때만 움직인다(담당자가 직접 스크롤한 것을 되돌리지 않게)
  useEffect(() => {
    const el = box.current;
    const fr = frame.current;
    if (!el || !fr || !focus || !marks) return;
    const k = fr.clientWidth / marks.w;
    const top = focus.y * k;
    const bottom = (focus.y + focus.h) * k;
    if (top < el.scrollTop || bottom > el.scrollTop + el.clientHeight) {
      el.scrollTo({ top: Math.max(0, top - el.clientHeight / 3), behavior: "smooth" });
    }
  }, [cur?.name, focus?.x, focus?.y, focus?.h]);

  // 교차 페이드가 끝나면 이전 화면을 치운다(사진 자체는 기억 장소가 갖고 있다가 밀려날 때 해제)
  useEffect(() => {
    if (!prev) return;
    const t = setTimeout(() => {
      if (prevRef.current === prev) {
        prevRef.current = null;
        setPrev(null);
      }
    }, 260);
    return () => clearTimeout(t);
  }, [prev]);

  const openOriginal = async () => {
    if (!cur) return;
    const w = window.open("", "_blank"); // 클릭 순간에 열어야 팝업 차단에 걸리지 않는다
    if (!w) return;
    w.opener = null;
    try {
      const u = await fileUrl(caseId, cur.name);
      w.location.href = u;
      setTimeout(() => URL.revokeObjectURL(u), 60_000);
    } catch {
      w.close();
    }
  };

  if (failed) return <span className="err small" role="alert">이 화면 파일을 불러오지 못했습니다</span>;
  if (!cur) return <span className="muted small">화면을 불러오는 중…</span>;
  return (
    <>
      <div ref={box} className="screen-scroll" tabIndex={0} aria-label="조사 화면 (길면 세로 스크롤)" onScroll={measure}>
        {/* 이전 화면은 불투명하게 아래에 두고 새 화면만 위에서 나타나게 한다(둘 다 반투명해지면 어두운 바탕이 비쳐 깜빡임) */}
        <div ref={frame} className="frame">
          {prev && <img key={prev.url} className="frame-img under" src={prev.url} alt="" aria-hidden="true" />}
          <img key={cur.url} className={cur.url === instant ? "frame-img" : "frame-img enter"} src={cur.url} alt={`증거 화면 ${cur.name}`} onLoad={measure} />
          {marks && <Marks o={marks} />}
        </div>
        {!atEnd && <div className="more-hint" aria-hidden="true" />}
      </div>
      <button type="button" className="btn btn-ghost open-orig" onClick={openOriginal} title="원본 PNG 를 새 탭에서 보기">
        원본
      </button>
    </>
  );
}

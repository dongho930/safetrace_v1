import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type AgentEvent,
  ApiError,
  type CaseOut,
  type EvidenceEvent,
  clearToken,
  createCase,
  fileUrl,
  getCase,
  getToken,
  listCases,
  setToken,
  streamEvents,
  verifyCase,
} from "./api";

// 조사 대상 페이지에서 온 문자열은 모두 React 기본 이스케이프로만 출력한다(raw HTML 금지).

const STATUS_LABEL: Record<string, string> = {
  QUEUED: "대기",
  RUNNING: "조사 중",
  COMPLETED: "조사 완료",
  REVIEW_REQUIRED: "검토 필요",
  FAILED: "실패",
  UNREACHABLE: "접속 불가",
  BLOCKED: "차단(정책)",
};
// 색만으로 구분하지 않도록 상태마다 기호를 붙인다
const STATUS_GLYPH: Record<string, string> = {
  QUEUED: "●",
  RUNNING: "●",
  COMPLETED: "○",
  REVIEW_REQUIRED: "▲",
  FAILED: "×",
  UNREACHABLE: "×",
  BLOCKED: "×",
};
const THREAT_LABEL: Record<string, string> = {
  phishing: "피싱",
  scam: "사기",
  illegal_gambling: "불법 도박",
  malware: "악성 앱",
  benign: "정상",
  unknown: "판단 불가",
};
const REASON_LABEL: Record<string, string> = {
  unreachable_reputation_match: "접속 불가 · Safe Browsing 위험 일치",
  goto_failed: "최초 접속 실패",
  low_confidence_action: "다음 행동 확신 부족으로 탐색 종료",
  loop_detected: "같은 화면 반복으로 탐색 종료",
  agent_finished: "에이전트가 조사 완료 판단",
  step_budget: "최대 단계 도달",
  time_budget: "최대 시간 도달",
  threat_decision_unavailable: "위협 판단 불가(판단 서비스 장애)",
};
const NET_CATEGORY_LABEL: Record<string, string> = {
  dns_failure: "도메인 없음(DNS)",
  connection_refused: "연결 거부",
  connection_dropped: "응답 없이 연결 끊김",
  timeout: "시간 초과",
  egress_refused: "검문 프록시 거부 또는 상대 연결 실패",
  egress_unavailable: "검문 프록시 연결 실패",
  blocked_by_policy: "정책 차단",
  network_unreachable: "네트워크 도달 불가",
  tls_error: "인증서·TLS 오류",
  other: "기타",
};
const TERMINAL = new Set(["COMPLETED", "REVIEW_REQUIRED", "FAILED", "UNREACHABLE", "BLOCKED"]);
const MAX_STEPS = 15; // 에이전트 기본 예산(ST_MAX_STEPS)

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

const fmtTime = (iso: string) => new Date(iso).toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", hour12: false });
const pct = (v: number) => v.toFixed(2);

// ── 앱 ─────────────────────────────────────────────
export default function App() {
  const [token, setTok] = useState(getToken());
  const [cases, setCases] = useState<CaseOut[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState("");
  const fit = useFitZoom();

  const refresh = useCallback(async () => {
    try {
      setCases(await listCases());
      setError("");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        clearToken();
        setTok("");
      }
      setError(e instanceof Error ? e.message : "목록 조회 실패");
    }
  }, []);

  useEffect(() => {
    if (!token) return;
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [token, refresh]);

  if (!token) return <Login fit={fit} onLogin={(t) => (setToken(t), setTok(t))} />;

  return (
    <div className="app" style={fit}>
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">
            <Icon name="shield" />
          </span>
          <span className="brand-name">SafeTrace</span>
          <span className="chip">SOC</span>
        </div>
        <span className="muted small">위협 의심 사이트 조사 콘솔</span>
        <div className="spacer" />
        <button type="button" className="btn btn-ghost" onClick={() => (clearToken(), setTok(""))}>
          로그아웃
        </button>
      </header>

      <Kpis cases={cases} />

      <div className="cols">
        <Queue
          cases={cases}
          selected={selected}
          error={error}
          onSelect={setSelected}
          onCreated={(c) => {
            setSelected(c.id);
            refresh();
          }}
        />
        {selected ? <Workspace key={selected} id={selected} /> : <EmptyWorkspace />}
      </div>
    </div>
  );
}

function Login({ fit, onLogin }: { fit: React.CSSProperties; onLogin: (t: string) => void }) {
  const [t, setT] = useState("");
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
        <p className="muted small">발급받은 API 토큰을 입력하세요. 토큰은 이 탭에만 보관됩니다.</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (t.trim()) onLogin(t.trim());
          }}
        >
          <label className="sr" htmlFor="token">
            API 토큰
          </label>
          <input id="token" className="field" type="password" value={t} onChange={(e) => setT(e.target.value)} placeholder="API 토큰" autoFocus />
          <button type="submit" className="btn btn-primary">
            접속
          </button>
        </form>
      </div>
    </div>
  );
}

// ── 지표: 사건 목록에서 계산한 값만 보여 준다 ─────────────────
function Kpis({ cases }: { cases: CaseOut[] }) {
  const n = (f: (c: CaseOut) => boolean) => cases.filter(f).length;
  const items = [
    { label: "검토 필요", value: n((c) => c.status === "REVIEW_REQUIRED"), icon: "alert", cls: "glow-orange" },
    { label: "조사 중", value: n((c) => c.status === "RUNNING" || c.status === "QUEUED"), icon: "clock", cls: "glow-blue" },
    { label: "조사 완료", value: n((c) => c.status === "COMPLETED"), icon: "check", cls: "" },
    {
      label: "위협 의심",
      value: n((c) => !!c.threat && !["benign", "unknown"].includes(c.threat.threat)),
      icon: "flag",
      cls: "glow-orange",
    },
    { label: "접속 불가·차단", value: n((c) => ["UNREACHABLE", "BLOCKED", "FAILED"].includes(c.status)), icon: "ban", cls: "" },
  ] as const;
  return (
    <section className="kpis" aria-label="현황">
      {items.map((k) => (
        <div key={k.label} className="panel kpi">
          <div className="kpi-head">
            <span className="lbl">{k.label}</span>
            <span className={`kpi-icon ${k.cls}`}>
              <Icon name={k.icon} />
            </span>
          </div>
          <span className={`kpi-val ${k.cls}`}>{k.value}</span>
        </div>
      ))}
    </section>
  );
}

// ── 왼쪽: 사건 대기열 ─────────────────────────────────
function Queue({
  cases,
  selected,
  error,
  onSelect,
  onCreated,
}: {
  cases: CaseOut[];
  selected: string | null;
  error: string;
  onSelect: (id: string) => void;
  onCreated: (c: CaseOut) => void;
}) {
  const [filter, setFilter] = useState<"all" | "review">("all");
  const [adding, setAdding] = useState(false);
  const review = cases.filter((c) => c.status === "REVIEW_REQUIRED");
  const shown = filter === "review" ? review : cases;
  return (
    <aside className="panel queue" aria-label="사건 대기열">
      <div className="queue-head">
        <h2>사건 대기열</h2>
        <button type="button" className="btn btn-primary" aria-expanded={adding} onClick={() => setAdding((v) => !v)}>
          {adding ? "닫기" : "+ URL 접수"}
        </button>
      </div>
      {adding && (
        <NewCase
          onCreated={(c) => {
            setAdding(false);
            onCreated(c);
          }}
        />
      )}
      <div className="filters" role="group" aria-label="필터">
        <button type="button" className="chip chip-filter" aria-pressed={filter === "all"} onClick={() => setFilter("all")}>
          전체 {cases.length}
        </button>
        <button type="button" className="chip chip-filter warn-chip" aria-pressed={filter === "review"} onClick={() => setFilter("review")}>
          검토 필요 {review.length}
        </button>
      </div>
      {error && <p className="err" style={{ padding: "0 16px 8px" }}>{error}</p>}
      <ul className="list">
        {shown.map((c) => (
          <li key={c.id}>
            <button type="button" className="item" aria-current={c.id === selected} onClick={() => onSelect(c.id)}>
              <span className="item-top">
                <StatusChip c={c} />
                <span className="mono faint small">{fmtTime(c.created_at)}</span>
              </span>
              <span className="item-url">{c.url}</span>
              <span className="item-sub">{caseSummary(c)}</span>
            </button>
          </li>
        ))}
        {shown.length === 0 && <li className="muted small" style={{ padding: 12 }}>해당하는 사건이 없습니다.</li>}
      </ul>
    </aside>
  );
}

function StatusChip({ c }: { c: CaseOut }) {
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

function caseSummary(c: CaseOut): string {
  if (c.status === "RUNNING" || c.status === "QUEUED") return "에이전트가 조사하는 중";
  const parts: string[] = [];
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
    <>
      <main className="panel empty">
        <h2>사건을 선택하거나 새 URL을 접수하세요</h2>
        <p className="muted">
          AI 에이전트가 격리 브라우저에서 버튼을 눌러 가며 숨겨진 화면까지 조사합니다. 입력·제출·결제·다운로드는 코드가
          막으며, 모든 행동과 화면은 서명된 증거로 남습니다. 최종 판정은 담당자가 합니다.
        </p>
      </main>
      <aside className="side" aria-label="판단과 증거" />
    </>
  );
}

// ── 선택한 사건: 가운데(조사) + 오른쪽(판단·증거) ─────────────────
const Workspace = memo(function Workspace({ id }: { id: string }) {
  const [c, setC] = useState<CaseOut | null>(null);
  const [events, setEvents] = useState<EvidenceEvent[]>([]);
  const [status, setStatus] = useState("");
  const [live, setLive] = useState(false);

  useEffect(() => {
    const ac = new AbortController();
    setLive(true);
    streamEvents(
      id,
      (e: AgentEvent) => {
        if (e.type === "evidence") setEvents((prev) => (prev.some((p) => p.seq === e.seq) ? prev : [...prev, e]));
        if (e.type === "status") {
          setStatus(e.status);
          if (TERMINAL.has(e.status)) getCase(id).then(setC).catch(() => undefined);
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
  const st = status || c?.status || "";
  const running = st === "RUNNING" || st === "QUEUED" || (!st && live);
  return (
    <>
      <Investigation c={c} events={sorted} status={st} running={running} id={id} />
      <SidePanel c={c} id={id} running={running} />
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
  // 실시간 화면에는 관찰·마지막 화면(페이지 전체)만 보여 준다. 클릭 직전·직후 화면은 행동 기록에 남아 있다
  const lastShot = [...events].reverse().find((e) => (e.kind === "observe" || e.kind === "finish") && e.files.some((f) => f.endsWith(".png")));
  const shot = lastShot?.files.find((f) => f.endsWith(".png"));
  const recording = events.find((e) => e.kind === "recording")?.files[0];
  const browser = events.find((e) => e.kind === "browser")?.data as { version?: string } | undefined;
  const lastUrl = [...events].reverse().find((e) => e.kind === "observe")?.data.url as string | undefined;
  const [view, setView] = useState<"shot" | "video">("shot");
  const total = Math.max(MAX_STEPS, steps);

  return (
    <main className="panel live" aria-label="조사 화면">
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
        {recording && !running && (
          <div className="stage-tabs" role="group" aria-label="화면 전환">
            <button type="button" className="chip chip-filter" aria-pressed={view === "shot"} onClick={() => setView("shot")}>
              마지막 화면
            </button>
            <button type="button" className="chip chip-filter" aria-pressed={view === "video"} onClick={() => setView("video")}>
              조사 녹화
            </button>
          </div>
        )}
        <div className="screen">
          <div className="screen-bar">
            {running && (
              <span className="rec">
                <span className="dot" />
                REC
              </span>
            )}
            <span>격리 브라우저{browser?.version ? ` · Chromium ${browser.version.split(".")[0]}` : ""} · 검문 프록시 경유</span>
          </div>
          <div className="screen-body">
            {view === "video" && recording ? (
              <Recording caseId={id} name={recording} />
            ) : shot ? (
              <LiveScreen caseId={id} name={shot} />
            ) : (
              <span className="muted small">{running ? "첫 화면을 기다리는 중…" : "화면 기록 없음"}</span>
            )}
          </div>
        </div>
      </div>

      <section className="log" aria-label="에이전트 행동 기록">
        <div className="log-head">
          <h2 className="lbl">에이전트 행동 기록</h2>
          <span className="mono faint small">증거 {events.length}건</span>
        </div>
        <EventLog events={events} />
      </section>
    </main>
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
    if (e.kind === "observe") {
      candidates = new Map(((d.candidates as { id: string; text: string }[]) ?? []).map((c) => [c.id, c.text]));
      const nf = ((d.forbidden as string[]) ?? []).length;
      lines.push({ seq: e.seq, icon: "eye", tone: "", text: <>관찰 · {String(d.title || d.url)}</>, end: nf ? <span className="bad">금지 {nf} 제외</span> : `후보 ${((d.candidates as unknown[]) ?? []).length}` });
    } else if (e.kind === "decision") {
      const choice = String(d.choice);
      const eid = choice.startsWith("click_") ? choice.slice(6) : "";
      const what = eid ? `“${candidates.get(eid) ?? eid}” 클릭` : ACTION_LABEL[choice] ?? choice;
      lines.push({ seq: e.seq, icon: "brain", tone: "", text: <>Jev 선택 · {what}</>, end: pct(Number(d.probability)), endTone: "var(--blue-ink)" });
    } else if (e.kind === "gate") {
      if (!d.allowed) lines.push({ seq: e.seq, icon: "ban", tone: "red", text: <span className="bad">안전 게이트 차단 · {String(d.reason)}</span>, end: "차단", endTone: "var(--red-ink)" });
    } else if (e.kind === "action") {
      const out = String(d.outcome);
      const noEffect = out.includes("no_effect") || out.includes("failed");
      lines.push({ seq: e.seq, icon: "cursor", tone: noEffect ? "orange" : "", text: <>실행 · {out} → <span className="mono faint">{String(d.result_url)}</span></>, end: noEffect ? "효과 없음" : "통과", endTone: noEffect ? "var(--orange-ink)" : "var(--teal-ink)" });
    } else if (e.kind === "blocked_request") {
      if (d.navigation) lines.push({ seq: e.seq, icon: "ban", tone: "red", text: <span className="bad">페이지 이동 차단 · {String(d.reason)} <span className="mono">{String(d.url)}</span></span>, end: "차단", endTone: "var(--red-ink)" });
      else quiet.push(e);
    } else if (e.kind === "new_window") {
      lines.push({ seq: e.seq, icon: "window", tone: "", text: <>새 창 채택 · <span className="mono">{String(d.url)}</span></> });
    } else if (e.kind === "navigation") {
      const redirects = (d.redirects as string[]) ?? [];
      lines.push({ seq: e.seq, icon: "globe", tone: redirects.length ? "orange" : "", text: <>최초 접속 {String(d.status)}{redirects.length ? ` · 리다이렉트 ${redirects.length}회` : ""}</> });
    } else if (e.kind === "dialog") {
      lines.push({ seq: e.seq, icon: "x", tone: "", text: <>대화상자 자동 닫기 · {String(d.message)}</> });
    } else if (e.kind === "unreachable") {
      lines.push({ seq: e.seq, icon: "ban", tone: "red", text: <span className="bad">접속 불가 · {NET_CATEGORY_LABEL[String(d.category)] ?? String(d.error)}{d.net_error ? ` (${String(d.net_error)})` : ""}</span> });
    } else if (e.kind === "escalation") {
      lines.push({ seq: e.seq, icon: "alert", tone: "orange", text: <span className="warn">담당자 검토로 전환 · Safe Browsing {((d.threat_types as string[]) ?? []).join(", ")}</span> });
    } else if (e.kind === "threat") {
      lines.push({ seq: e.seq, icon: "flag", tone: d.threat === "benign" ? "teal" : "orange", text: <>위협 판단 · {THREAT_LABEL[String(d.threat)] ?? String(d.threat)}</>, end: pct(Number(d.probability)) });
    } else if (e.kind === "safebrowsing") {
      lines.push({ seq: e.seq, icon: "shieldCheck", tone: d.status === "match" ? "red" : "", text: <>Safe Browsing · {String(d.status)}</> });
    } else if (e.kind === "finish") {
      lines.push({ seq: e.seq, icon: "check", tone: "teal", text: <>탐색 종료 · {REASON_LABEL[String(d.reason)] ?? String(d.reason)}</> });
    } else if (e.kind === "action_error" || e.kind === "decision_error" || e.kind === "threat_error") {
      lines.push({ seq: e.seq, icon: "alert", tone: "orange", text: <span className="warn">{e.kind} · {String(d.error ?? "")}</span> });
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
                EV-{e.seq} · {String(e.data.reason)} · {String(e.data.url)}
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
const ACTION_LABEL: Record<string, string> = { scroll: "스크롤", back: "뒤로 가기", close_popup: "팝업 닫기", finish: "조사 끝내기" };

// ── 오른쪽: AI 의견 · 외부 평판·증거 · 판정 ───────────────────────
function SidePanel({ c, id, running }: { c: CaseOut | null; id: string; running: boolean }) {
  return (
    <aside className="side" aria-label="판단과 증거">
      <Opinion c={c} running={running} />
      <Evidence c={c} id={id} running={running} />
      <section className="panel card verdict" aria-label="담당자 판정">
        <h2 className="panel-title">담당자 판정</h2>
        <button type="button" className="btn btn-danger" disabled>
          위협 확정
        </button>
        <div className="verdict-row">
          <button type="button" className="btn btn-ghost" disabled>
            정상
          </button>
          <button type="button" className="btn btn-ghost" disabled>
            보류
          </button>
        </div>
        <p className="faint small" style={{ margin: 0 }}>
          판정 저장은 계정·권한 기능과 함께 제공 예정입니다. AI 는 판정을 확정하지 않습니다.
        </p>
      </section>
    </aside>
  );
}

function Opinion({ c, running }: { c: CaseOut | null; running: boolean }) {
  const t = c?.threat;
  if (!t) {
    return (
      <section className="panel card" aria-label="AI 의견">
        <div className="card-head">
          <h2 className="lbl">AI 의견</h2>
          <span className="faint small">기술적 의심 유형 · 법적 판단 아님</span>
        </div>
        <p className="muted small" style={{ margin: 0 }}>
          {running ? "조사가 끝나면 위협 판단이 표시됩니다." : "위협 판단 없음 (페이지를 열지 못했거나 판단 불가)"}
        </p>
      </section>
    );
  }
  const risky = !["benign", "unknown"].includes(t.threat);
  const color = t.threat === "benign" ? "var(--teal-ink)" : risky ? "var(--orange-ink)" : "var(--muted)";
  const probs = Object.entries(t.probabilities).sort((a, b) => b[1] - a[1]).filter(([, v]) => v >= 0.01).slice(0, 4);
  const R = 36;
  const C = 2 * Math.PI * R;
  return (
    <section className="panel card" aria-label="AI 의견">
      <div className="card-head">
        <h2 className="lbl">AI 의견</h2>
        <span className="faint small">기술적 의심 유형 · 법적 판단 아님</span>
      </div>
      <div className="opinion">
        <svg width="80" height="80" viewBox="0 0 88 88" role="img" aria-label={`${THREAT_LABEL[t.threat] ?? t.threat} 확률 ${pct(t.probability)}`} style={{ color }}>
          <circle cx="44" cy="44" r={R} fill="none" stroke="var(--track)" strokeWidth="7" />
          <circle className="ring-fill" cx="44" cy="44" r={R} fill="none" stroke="currentColor" strokeWidth="7" strokeLinecap="round" strokeDasharray={`${C * t.probability} ${C}`} transform="rotate(-90 44 44)" />
          <text x="44" y="50" textAnchor="middle" fontFamily="Geist Mono Variable, monospace" fontSize="18" fill="currentColor">
            {pct(t.probability)}
          </text>
        </svg>
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <span className="opinion-name" style={{ color }}>
            {THREAT_LABEL[t.threat] ?? t.threat}
            {risky ? " 의심" : ""}
          </span>
          <span className="muted small">{t.hold ? "확신 부족 → 담당자 검토" : "판단 확신 기준 충족"}</span>
          <span className="mono faint small">
            {t.model} · 근거 {t.evidence_seqs.slice(-4).map((s) => `EV-${s}`).join(" ")}
          </span>
        </div>
      </div>
      <div className="bars" style={{ color }}>
        {probs.map(([k, v], i) => (
          <div className="bar" key={k}>
            <span style={{ color: "var(--ink)" }}>{THREAT_LABEL[k] ?? k}</span>
            <span className="bar-track">
              <span className={i === 0 ? "bar-fill top" : "bar-fill"} style={{ width: `${Math.round(v * 100)}%` }} />
            </span>
            <span className="bar-val" style={{ color: "var(--ink)" }}>
              {pct(v)}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

function Evidence({ c, id, running }: { c: CaseOut | null; id: string; running: boolean }) {
  const [verify, setVerify] = useState<{ ok: boolean; records: number; errors: string[] } | null>(null);
  const [busy, setBusy] = useState(false);
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
    <section className="panel card" aria-label="외부 평판과 증거">
      <h2 className="lbl">외부 평판 · 증거</h2>
      <div className="tiles">
        <div className="sunken tile">
          <span className="muted">Safe Browsing</span>
          <span className={`mono ${sb?.status === "match" ? "bad" : ""}`}>{sbText}</span>
        </div>
        <div className="sunken tile">
          <span className="muted">경유 도메인</span>
          <span className={`mono ${c?.candidates?.length ? "warn" : ""}`}>{c?.candidates?.length ? c.candidates.join(", ") : "없음"}</span>
        </div>
      </div>
      {sb?.status === "no_match" && <p className="faint small" style={{ margin: 0 }}>일치 없음은 정상이라는 뜻이 아닙니다.</p>}
      <div className={`integrity ${verify ? (verify.ok ? "good" : "fail") : ""}`}>
        <Icon name="lock" />
        <span className="integrity-text">
          {verify ? (
            verify.ok ? (
              <>
                <span>해시 체인 · HMAC 서명 통과</span>
                <span className="mono faint small">증거 {verify.records}건</span>
              </>
            ) : (
              <>
                <span>검증 실패</span>
                <span className="mono small">{verify.errors.slice(0, 3).join(", ")}</span>
              </>
            )
          ) : (
            <>
              <span style={{ color: "var(--ink)" }}>증거 무결성</span>
              <span className="faint small">{running ? "조사가 끝나면 검증할 수 있습니다" : "검증 전"}</span>
            </>
          )}
        </span>
        <button
          type="button"
          className="btn btn-ghost"
          style={{ padding: "7px 10px", fontSize: 12 }}
          disabled={busy || running}
          onClick={async () => {
            setBusy(true);
            try {
              setVerify(await verifyCase(id));
            } catch (e) {
              setVerify({ ok: false, records: 0, errors: [e instanceof Error ? e.message : "검증 실패"] });
            } finally {
              setBusy(false);
            }
          }}
        >
          {verify ? "다시 검증" : "검증"}
        </button>
      </div>
    </section>
  );
}

// 증거 파일은 인증 헤더가 필요하므로 blob URL 로 보여 준다
// 조사 녹화(영상)
function Recording({ caseId, name }: { caseId: string; name: string }) {
  const [src, setSrc] = useState("");
  useEffect(() => {
    let alive = true;
    let u = "";
    fileUrl(caseId, name)
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
  return src ? <video src={src} controls /> : <span className="muted small">불러오는 중…</span>;
}

// 실시간 화면: 새 화면을 다 받아 그릴 준비가 끝날 때까지 이전 화면을 그대로 두고(이중 버퍼) 교차 페이드로 바꾼다.
// 표시 방식은 한 가지: 폭에 맞추되 창 한 화면(1280×800 비율)이 칸 높이에 들어가게, 더 길면 세로 스크롤.
type Frame = { url: string; name: string };
function LiveScreen({ caseId, name }: { caseId: string; name: string }) {
  const [cur, setCur] = useState<Frame | null>(null);
  const [prev, setPrev] = useState<Frame | null>(null);
  const [atEnd, setAtEnd] = useState(true);
  const curRef = useRef<Frame | null>(null);
  const prevRef = useRef<Frame | null>(null);
  const box = useRef<HTMLDivElement>(null);

  const measure = useCallback(() => {
    const el = box.current;
    if (el) setAtEnd(el.scrollTop + el.clientHeight >= el.scrollHeight - 2);
  }, []);

  useEffect(() => {
    let alive = true;
    (async () => {
      let url = "";
      try {
        url = await fileUrl(caseId, name, true);
        const img = new Image();
        img.src = url;
        await img.decode().catch(() => undefined);
      } catch {
        return; // 못 받으면 이전 화면 유지
      }
      if (!alive) {
        URL.revokeObjectURL(url);
        return;
      }
      if (prevRef.current) URL.revokeObjectURL(prevRef.current.url);
      prevRef.current = curRef.current;
      curRef.current = { url, name };
      setPrev(prevRef.current);
      setCur(curRef.current);
      box.current?.scrollTo({ top: 0, behavior: "smooth" });
    })();
    return () => {
      alive = false;
    };
  }, [caseId, name]);

  // 교차 페이드가 끝나면 이전 화면을 치운다
  useEffect(() => {
    if (!prev) return;
    const t = setTimeout(() => {
      if (prevRef.current === prev) {
        URL.revokeObjectURL(prev.url);
        prevRef.current = null;
        setPrev(null);
      }
    }, 260);
    return () => clearTimeout(t);
  }, [prev]);

  useEffect(
    () => () => {
      for (const f of [curRef.current, prevRef.current]) if (f) URL.revokeObjectURL(f.url);
    },
    [],
  );

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

  if (!cur) return <span className="muted small">화면을 불러오는 중…</span>;
  return (
    <>
      <div ref={box} className="screen-scroll" tabIndex={0} aria-label="조사 화면 (길면 세로 스크롤)" onScroll={measure}>
        {/* 이전 화면은 불투명하게 아래에 두고 새 화면만 위에서 나타나게 한다(둘 다 반투명해지면 어두운 바탕이 비쳐 깜빡임) */}
        <div className="frame">
          {prev && <img key={prev.url} className="frame-img under" src={prev.url} alt="" aria-hidden="true" />}
          <img key={cur.url} className="frame-img enter" src={cur.url} alt={`증거 화면 ${cur.name}`} onLoad={measure} />
        </div>
        {!atEnd && <div className="more-hint" aria-hidden="true" />}
      </div>
      <button type="button" className="btn btn-ghost open-orig" onClick={openOriginal} title="원본 PNG 를 새 탭에서 보기">
        원본
      </button>
    </>
  );
}

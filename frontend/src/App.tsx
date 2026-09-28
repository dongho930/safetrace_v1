import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
  REVIEW_REQUIRED: "담당자 검토 필요",
  FAILED: "실패",
  UNREACHABLE: "접속 불가",
  BLOCKED: "차단(정책)",
};
const THREAT_LABEL: Record<string, string> = {
  phishing: "피싱",
  scam: "사기",
  illegal_gambling: "불법 도박 의심",
  malware: "악성코드",
  benign: "정상",
  unknown: "판단 불가",
};
const KIND_LABEL: Record<string, string> = {
  start: "조사 시작",
  browser: "브라우저",
  navigation: "최초 접속",
  observe: "관찰",
  decision: "Jev 행동 선택",
  gate: "안전 게이트",
  action: "실행",
  blocked_request: "요청 차단",
  dialog: "대화상자 자동 닫기",
  new_window: "새 창",
  action_error: "실행 오류",
  decision_error: "판단 실패",
  finish: "조사 종료",
  threat: "Jev 위협 판단",
  recording: "녹화",
  safebrowsing: "Safe Browsing",
  unreachable: "접속 불가",
  escalation: "담당자 검토로 전환",
  error: "오류",
};
const REASON_LABEL: Record<string, string> = {
  unreachable_reputation_match: "접속 불가 · Safe Browsing 위험 일치",
  goto_failed: "최초 접속 실패",
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

export default function App() {
  const [token, setTok] = useState(getToken());
  const [cases, setCases] = useState<CaseOut[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState("");

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

  if (!token) return <Login onLogin={(t) => (setToken(t), setTok(t))} />;

  return (
    <div className="layout">
      <aside className="side">
        <header className="brand">
          <span className="logo">SafeTrace</span>
          <button className="link" onClick={() => (clearToken(), setTok(""))}>
            로그아웃
          </button>
        </header>
        <NewCase
          onCreated={(c) => {
            setSelected(c.id);
            refresh();
          }}
        />
        {error && <p className="err">{error}</p>}
        <ul className="cases">
          {cases.map((c) => (
            <li key={c.id}>
              <button className={c.id === selected ? "case active" : "case"} onClick={() => setSelected(c.id)}>
                <span className={`badge s-${c.status}`}>{STATUS_LABEL[c.status] ?? c.status}</span>
                <span className="url">{c.url}</span>
                {c.threat && <span className="threat-mini">{THREAT_LABEL[c.threat.threat]}</span>}
              </button>
            </li>
          ))}
          {cases.length === 0 && <li className="muted">접수된 사건이 없습니다.</li>}
        </ul>
      </aside>
      <main className="main">
        {selected ? <CaseView key={selected} id={selected} /> : <Empty />}
      </main>
    </div>
  );
}

function Login({ onLogin }: { onLogin: (t: string) => void }) {
  const [t, setT] = useState("");
  return (
    <div className="login">
      <h1>SafeTrace 조사 콘솔</h1>
      <p className="muted">발급받은 API 토큰을 입력하세요. 토큰은 이 탭에만 보관됩니다.</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (t.trim()) onLogin(t.trim());
        }}
      >
        <input type="password" value={t} onChange={(e) => setT(e.target.value)} placeholder="API 토큰" autoFocus />
        <button type="submit">접속</button>
      </form>
    </div>
  );
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
      <label>신고 URL 접수</label>
      <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://..." maxLength={2048} required />
      <div className="row">
        <select value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="report">신고</option>
          <option value="kisa">KISA 피싱 URL</option>
          <option value="test">시험 페이지</option>
        </select>
        <button type="submit" disabled={busy}>
          {busy ? "접수 중…" : "조사 시작"}
        </button>
      </div>
      {msg && <p className="err">{msg}</p>}
    </form>
  );
}

function Empty() {
  return (
    <div className="empty">
      <h2>사건을 선택하거나 새 URL을 접수하세요</h2>
      <p className="muted">
        AI 에이전트가 격리 브라우저에서 버튼을 눌러 가며 숨겨진 화면까지 조사합니다. 입력·제출·결제·다운로드는 코드가
        막으며, 모든 행동과 화면은 서명된 증거로 남습니다. 최종 판정은 담당자가 합니다.
      </p>
    </div>
  );
}

function CaseView({ id }: { id: string }) {
  const [c, setC] = useState<CaseOut | null>(null);
  const [events, setEvents] = useState<EvidenceEvent[]>([]);
  const [status, setStatus] = useState<string>("");
  const [live, setLive] = useState(false);
  const [verify, setVerify] = useState<{ ok: boolean; records: number; errors: string[] } | null>(null);

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

  const steps = useMemo(() => groupSteps(events), [events]);
  const recording = events.find((e) => e.kind === "recording")?.files[0];
  const st = status || c?.status || "";

  return (
    <div className="caseview">
      <section className="head">
        <div>
          <div className="url-big">{c?.url}</div>
          <div className="meta">
            <span className={`badge s-${st}`}>{STATUS_LABEL[st] ?? st}</span>
            {live && <span className="live">● 실시간</span>}
            {c?.finish_reason && (
              <span className="muted">종료 사유: {REASON_LABEL[c.finish_reason] ?? c.finish_reason}</span>
            )}
          </div>
        </div>
        <div className="actions">
          <button
            onClick={async () => {
              try {
                setVerify(await verifyCase(id));
              } catch (e) {
                setVerify({ ok: false, records: 0, errors: [e instanceof Error ? e.message : "검증 실패"] });
              }
            }}
          >
            증거 무결성 검증
          </button>
        </div>
      </section>

      {verify && (
        <div className={verify.ok ? "verify ok" : "verify bad"}>
          {verify.ok
            ? `✔ 증거 ${verify.records}건 해시 체인·서명 검증 통과`
            : `✖ 검증 실패: ${verify.errors.slice(0, 5).join(", ")}`}
        </div>
      )}

      {c?.threat && <ThreatCard c={c} />}

      {recording && <Video caseId={id} name={recording} />}

      <section className="timeline">
        <h3>에이전트 행동 기록</h3>
        {steps.map((g, i) => (
          <StepCard key={i} caseId={id} items={g} />
        ))}
        {steps.length === 0 && <p className="muted">기록을 기다리는 중…</p>}
      </section>
    </div>
  );
}

function groupSteps(events: EvidenceEvent[]): EvidenceEvent[][] {
  const out: EvidenceEvent[][] = [];
  for (const e of [...events].sort((a, b) => a.seq - b.seq)) {
    if (e.kind === "observe" || out.length === 0) out.push([e]);
    else out[out.length - 1].push(e);
  }
  return out;
}

function ThreatCard({ c }: { c: CaseOut }) {
  const t = c.threat!;
  const probs = Object.entries(t.probabilities).sort((a, b) => b[1] - a[1]);
  return (
    <section className="card threat">
      <div className="threat-head">
        <div>
          <div className="muted">AI 의견 (기술적 의심 유형, 법적 판단 아님)</div>
          <div className="threat-name">
            {THREAT_LABEL[t.threat] ?? t.threat} <span className="pct">{(t.probability * 100).toFixed(0)}%</span>
          </div>
        </div>
        {t.hold && <span className="badge s-REVIEW_REQUIRED">확신 부족 · 보류</span>}
      </div>
      <Bars probs={probs.map(([k, v]) => [THREAT_LABEL[k] ?? k, v])} />
      <div className="muted small">
        판단 모델 {t.model} ({t.provider}) · 근거 증거 {t.evidence_seqs.map((s) => `EV-${s}`).join(", ")}
      </div>
      <div className="small">
        Safe Browsing:{" "}
        {c.safebrowsing?.status === "match"
          ? c.safebrowsing.matches.map((m) => `${m.threat_type}`).join(", ")
          : c.safebrowsing?.status === "no_match"
            ? "일치 없음 (정상이라는 뜻은 아님)"
            : (c.safebrowsing?.status ?? "-")}
      </div>
      {c.candidates && c.candidates.length > 0 && (
        <div className="small">경유·연관 도메인 후보: {c.candidates.join(", ")}</div>
      )}
      <p className="muted small">최종 판정은 담당자가 확정합니다. AI 는 판정을 확정할 수 없습니다.</p>
    </section>
  );
}

function Bars({ probs }: { probs: [string, number][] }) {
  return (
    <div className="bars">
      {probs.slice(0, 6).map(([k, v]) => (
        <div className="bar" key={k}>
          <span className="bar-label">{k}</span>
          <span className="bar-track">
            <span className="bar-fill" style={{ width: `${Math.round(v * 100)}%` }} />
          </span>
          <span className="bar-val">{(v * 100).toFixed(0)}%</span>
        </div>
      ))}
    </div>
  );
}

function StepCard({ caseId, items }: { caseId: string; items: EvidenceEvent[] }) {
  const obs = items.find((e) => e.kind === "observe");
  const d = (obs?.data ?? {}) as {
    step?: number;
    url?: string;
    title?: string;
    candidates?: { id: string; text: string; href_host?: string | null }[];
    forbidden?: string[];
  };
  return (
    <div className="card step">
      {obs ? (
        <div className="step-head">
          <span className="step-no">STEP {d.step}</span>
          <span className="step-url">{d.url}</span>
          <span className="muted">EV-{obs.seq}</span>
        </div>
      ) : null}
      <div className="step-body">
        {obs && obs.files[0] && <Shot caseId={caseId} name={obs.files[0]} />}
        <div className="step-events">
          {obs && (
            <div className="small">
              <b>{d.title}</b> · 클릭 후보 {d.candidates?.length ?? 0}개
              {d.forbidden && d.forbidden.length > 0 && (
                <span className="forbid"> · 금지 요소 {d.forbidden.length}개 제외</span>
              )}
            </div>
          )}
          {items
            .filter((e) => e.kind !== "observe")
            .map((e) => (
              <EventLine key={e.seq} caseId={caseId} e={e} candidates={d.candidates ?? []} />
            ))}
        </div>
      </div>
    </div>
  );
}

function EventLine({
  caseId,
  e,
  candidates,
}: {
  caseId: string;
  e: EvidenceEvent;
  candidates: { id: string; text: string }[];
}) {
  const data = e.data as Record<string, unknown>;
  const label = KIND_LABEL[e.kind] ?? e.kind;
  let body: React.ReactNode = null;
  if (e.kind === "decision") {
    const choice = String(data.choice);
    const eid = choice.startsWith("click_") ? choice.slice(6) : "";
    const text = candidates.find((c) => c.id === eid)?.text;
    body = (
      <>
        <b>{eid ? `클릭 “${text ?? eid}”` : choice}</b> {(Number(data.probability) * 100).toFixed(0)}%{" "}
        <span className="muted">
          ({String(data.provider)} · {String(data.model)})
        </span>
      </>
    );
  } else if (e.kind === "gate") {
    body = data.allowed ? <span className="ok">통과</span> : <span className="forbid">차단 — {String(data.reason)}</span>;
  } else if (e.kind === "action") {
    body = (
      <>
        {String(data.outcome)} → <span className="muted">{String(data.result_url)}</span>
      </>
    );
  } else if (e.kind === "blocked_request") {
    body = (
      <span className="forbid">
        {String(data.reason)} {String(data.url)}
      </span>
    );
  } else if (e.kind === "finish") {
    body = <>사유: {String(data.reason)}</>;
  } else if (e.kind === "dialog") {
    body = <span className="muted">{String(data.message)}</span>;
  } else if (e.kind === "threat") {
    body = <>{THREAT_LABEL[String(data.threat)]}</>;
  } else if (e.kind === "safebrowsing") {
    body = <>{String(data.status)}</>;
  } else if (e.kind === "browser") {
    body = <span className="muted">Chromium {String(data.version)} · {String(data.user_agent)}</span>;
  } else if (e.kind === "unreachable") {
    body = (
      <>
        {NET_CATEGORY_LABEL[String(data.category)] ?? String(data.error)}{" "}
        {data.net_error ? <span className="muted">({String(data.net_error)})</span> : null}
      </>
    );
  } else if (e.kind === "escalation") {
    body = (
      <span className="forbid">
        Safe Browsing {(data.threat_types as string[] | undefined)?.join(", ")} — 페이지 증거 없음, 위협 유형 미확정
      </span>
    );
  }
  return (
    <div className={`ev k-${e.kind}${e.kind === "gate" && !data.allowed ? " blocked" : ""}`}>
      <span className="ev-kind">{label}</span> {body}
      {e.kind === "action" && e.files.length > 1 && (
        <div className="pair">
          {e.files.map((f) => (
            <Shot key={f} caseId={caseId} name={f} small />
          ))}
        </div>
      )}
    </div>
  );
}

function Shot({ caseId, name, small }: { caseId: string; name: string; small?: boolean }) {
  const [src, setSrc] = useState<string>("");
  const ref = useRef<string>("");
  useEffect(() => {
    let alive = true;
    fileUrl(caseId, name)
      .then((u) => {
        ref.current = u;
        if (alive) setSrc(u);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
      if (ref.current) URL.revokeObjectURL(ref.current);
    };
  }, [caseId, name]);
  if (!src) return <div className={small ? "shot small ph" : "shot ph"} />;
  return (
    <a href={src} target="_blank" rel="noopener noreferrer">
      <img className={small ? "shot small" : "shot"} src={src} alt={`증거 화면 ${name}`} />
    </a>
  );
}

function Video({ caseId, name }: { caseId: string; name: string }) {
  const [src, setSrc] = useState("");
  useEffect(() => {
    let u = "";
    fileUrl(caseId, name)
      .then((x) => {
        u = x;
        setSrc(x);
      })
      .catch(() => undefined);
    return () => {
      if (u) URL.revokeObjectURL(u);
    };
  }, [caseId, name]);
  return (
    <section className="card">
      <h3>조사 녹화</h3>
      {src ? <video src={src} controls className="video" /> : <p className="muted">불러오는 중…</p>}
    </section>
  );
}

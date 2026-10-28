// API 클라이언트. 로그인으로 받은 세션 토큰은 sessionStorage 에만 두고(탭 종료 시 삭제), 모든 요청에 Bearer 로 붙인다.
export type Threat = {
  threat: string;
  probability: number;
  probabilities: Record<string, number>;
  hold: boolean;
  provider: string;
  model: string;
  evidence_seqs: number[];
  // 코드 규칙이 모델 판단을 바꾼 경우: 공식 사행사업자 도메인(official_betting_domain → 정상),
  // 단축 URL 서비스의 위험 경고(shortener_warning → 피싱, 담당자 검토),
  // 단축·호스팅 서비스가 링크를 정지한 안내 화면(link_takedown → 피싱, 담당자 검토),
  // 신고 주소가 조사 전에 브랜드 공식 사이트로 넘김(official_redirect → 피싱, 담당자 검토),
  // 화면 내용이 없는 브랜드 사칭 도메인(brand_lookalike → 피싱, 담당자 검토)
  override?: { reason: string; operators?: string[]; brand?: string; destination?: string; original: { threat: string; probability: number; provider: string } };
};

// 연관 후보(경유 도메인·외부 링크). sub 가 있으면 1단계 하위 조사를 한 후보다. 모든 값은 조사 대상 페이지에서 온 글자다
export type Candidate = {
  url: string;
  host?: string;
  source?: "via" | "link";
  reputation_match?: boolean;
  reputation_unchecked?: boolean; // 평판 조회를 못 한 주소가 있음(실패·한도·개인정보 포함 주소)
  sub?: number;
  status?: string;
  reason?: string;
  final_url?: string;
  threat?: string | null;
  probability?: number | null;
  hold?: boolean | null;
  blocked?: boolean; // 하위 조사에서 회선이 도메인 이름을 보고 막은 것으로 추정(조사 대상 서버가 흉내 낼 수 있어 확정이 아니다)
  score?: number; // 고른 순서 점수 0~3(경유 3 · 위협 단서 2 · 이름 조각 1)
  text?: string; // 링크의 앵커 글자(개인정보를 가림)
};

export type CaseOut = {
  id: string;
  url: string;
  source: string;
  status: string;
  finish_reason: string | null;
  final_url: string | null;
  threat: Threat | null;
  safebrowsing: { status: string; matches: { url: string; threat_type: string }[] } | null;
  candidates: (Candidate | string)[] | null; // 예전 사건은 도메인 이름 목록
  head_seq: number | null;
  created_at: string;
  verdict: Verdict | null; // 담당자의 현재 판정(없으면 null)
  phase: "related" | null; // 원래 결과가 나왔고 연관 사이트를 조사하는 중
  main_status: string | null; // 원래 결과의 상태(phase 가 related 일 때 폴더·판정에 쓴다)
  main_reason?: string | null; // 연관 조사 중에도 원래 결과의 검토 사유를 표시한다(이전 서버는 없을 수 있음)
  parent_id: string | null; // 연관 사건이면 그 후보가 나온 부모 사건
  parent_url: string | null;
  auto: boolean | null; // 자동으로 만든 연관 사건인지(PR 4b)
  children: ChildCase[] | null; // 이 사건의 후보로 만든 사건(상세에만)
  auto_skipped: { url: string; reason: string }[] | null; // 하위 조사했지만 자동 사건이 없는 후보와 이유(상세에만)
};


// 연관 후보로 만든 사건(부모 사건 상세의 요약)
export type ChildCase = { id: string; url: string; candidate_url: string; status: string; threat: string | null; verdict: string | null; auto: boolean };

// 담당자 판정. 덮어쓰지 않고 판(rev)을 쌓는다. 저장할 때 보고 있던 판 번호를 보내 동시 수정을 막는다(409)
export type Decision = "threat" | "benign" | "hold";
export type Verdict = {
  rev: number;
  decision: Decision;
  threat: string | null;
  note: string | null;
  reviewer: string;
  ai_threat: string | null;
  head_seq: number | null;
  created_at: string;
};

export type EvidenceEvent = {
  type: "evidence";
  seq: number;
  kind: string;
  data: Record<string, unknown>;
  files: string[];
  hash: string;
};
// phase="related": 원래 결과가 나왔고 연관 사이트를 조사하는 중(related-sites PR 3)
export type StatusEvent = { type: "status"; status: string; reason: string | null; threat?: Threat | null; phase?: "related" };
export type StepEvent = { type: "step"; step: number; url: string };
export type AgentEvent = EvidenceEvent | StatusEvent | StepEvent;

const TOKEN_KEY = "st_token";
export const getToken = () => sessionStorage.getItem(TOKEN_KEY) ?? "";
export const setToken = (t: string) => sessionStorage.setItem(TOKEN_KEY, t);
export const clearToken = () => sessionStorage.removeItem(TOKEN_KEY);

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const r = await send(path, init);
  return r.json() as Promise<T>;
}
async function reqNoBody(path: string, init: RequestInit = {}): Promise<void> {
  await send(path, init);
}
async function send(path: string, init: RequestInit): Promise<Response> {
  const r = await fetch(path, {
    ...init,
    headers: { ...(init.headers ?? {}), Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" },
  });
  if (!r.ok) {
    let msg = `요청 실패 (${r.status})`;
    try {
      const j = await r.json();
      if (typeof j.detail === "string") msg = j.detail;
    } catch {
      /* 본문 없음 */
    }
    throw new ApiError(r.status, msg);
  }
  return r;
}

// ── 로그인·계정 ─────────────────────────────────────
export type Role = "viewer" | "investigator" | "reviewer" | "admin";
export const ROLE_RANK: Record<Role, number> = { viewer: 0, investigator: 1, reviewer: 2, admin: 3 };
export type Me = { name: string; role: Role; kind: "user" | "service" };
export type UserOut = { username: string; role: Role; active: boolean; locked: boolean; created_at: string };

// 로그인 요청은 아직 토큰이 없으므로 Authorization 없이 보낸다
export async function login(username: string, password: string): Promise<Me> {
  const r = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!r.ok) {
    const msg =
      r.status === 401 ? "아이디 또는 비밀번호가 올바르지 않습니다"
      : r.status === 429 ? `로그인 시도가 너무 많습니다. ${Math.ceil(Number(r.headers.get("Retry-After") ?? 900) / 60)}분 뒤 다시 시도하세요`
      : `로그인 실패 (${r.status})`;
    throw new ApiError(r.status, msg);
  }
  const j = (await r.json()) as { token: string; user: Me };
  setToken(j.token);
  return j.user;
}
export async function logout() {
  try {
    await fetch("/api/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${getToken()}` } });
  } finally {
    clearToken();
  }
}
export const me = () => req<Me>("/api/auth/me");
export const changePassword = (current: string, next: string) =>
  reqNoBody("/api/auth/password", { method: "POST", body: JSON.stringify({ current, new: next }) });
export const listUsers = () => req<UserOut[]>("/api/users");
export const createUser = (username: string, password: string, role: Role) =>
  req<UserOut>("/api/users", { method: "POST", body: JSON.stringify({ username, password, role }) });
export const patchUser = (username: string, patch: Partial<{ role: Role; active: boolean; password: string; unlock: boolean }>) =>
  req<UserOut>(`/api/users/${encodeURIComponent(username)}`, { method: "PATCH", body: JSON.stringify(patch) });

// 사건 목록 한 쪽: 폴더 건수는 서버가 전체 사건으로 세고, 목록은 폴더·검색·출처로 거른 한 쪽만 받는다
export const FOLDER_IDS = ["review", "running", "suspect", "decided", "unreachable", "all"] as const;
export type FolderId = (typeof FOLDER_IDS)[number];
export type CasePage = {
  items: CaseOut[];
  total: number;
  offset: number;
  limit: number;
  counts: Record<FolderId, number>;
  live: CaseOut | null;
  queued: CaseOut | null;
};
export const PAGE_SIZE = 50;
const nonNeg = (v: unknown) => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : 0);
export const casePage = async (p: { folder: FolderId; q: string; source: string; offset: number }): Promise<CasePage> => {
  const qs = new URLSearchParams({ folder: p.folder, q: p.q.slice(0, 200), source: p.source, offset: String(p.offset), limit: String(PAGE_SIZE) });
  const v = await req<unknown>(`/api/cases/page?${qs}`);
  if (!isObj(v)) throw new ApiError(500, "목록 형식 오류");
  const counts = Object.fromEntries(FOLDER_IDS.map((f) => [f, nonNeg(isObj(v.counts) ? v.counts[f] : 0)])) as Record<FolderId, number>;
  return {
    items: list(v.items).slice(0, 200).flatMap((x) => cleanCase(x) ?? []),
    total: nonNeg(v.total),
    offset: nonNeg(v.offset),
    limit: nonNeg(v.limit) || PAGE_SIZE,
    counts,
    live: v.live == null ? null : cleanCase(v.live),
    queued: v.queued == null ? null : cleanCase(v.queued),
  };
};
export const getCase = async (id: string) => {
  const c = cleanCase(await req<unknown>(`/api/cases/${encodeURIComponent(id)}`));
  if (!c) throw new ApiError(500, "사건 형식 오류");
  return c;
};
export const createCase = (url: string, source: string) =>
  req<CaseOut>("/api/cases", {
    method: "POST",
    body: JSON.stringify({ url, source }),
    headers: { "Idempotency-Key": crypto.randomUUID() },
  });
// 사건 간 연결(related-sites PR 5). 값은 조사 대상 페이지에서 온 글자라 정해진 모양만 남긴다
// source: 위협 판단을 낸 쪽(model = AI, rule = 코드 규칙, null = 알 수 없음·예전 서버)
export type CaseBrief = { id: string; url: string; status: string; threat: string | null; source: "model" | "rule" | null; verdict: string | null };
export type CaseLinks = { parent: CaseBrief | null; children: (CaseBrief & { auto: boolean })[]; shared: { site: string; hosts: string[]; roles: string[]; cases: CaseBrief[] }[] };
const brief = (x: unknown): CaseBrief[] =>
  isObj(x) && typeof x.id === "string" && typeof x.url === "string" && typeof x.status === "string"
    ? [{ id: x.id.slice(0, 36), url: x.url.slice(0, 2000), status: x.status.slice(0, 24), threat: strOr(x.threat)?.slice(0, 32) ?? null,
         source: x.source === "model" || x.source === "rule" ? x.source : null, verdict: strOr(x.verdict)?.slice(0, 16) ?? null }]
    : [];
export const getLinks = async (id: string): Promise<CaseLinks> => {
  const v = await req<unknown>(`/api/cases/${encodeURIComponent(id)}/links`);
  const o = isObj(v) ? v : {};
  return {
    parent: brief(o.parent)[0] ?? null,
    children: list(o.children).slice(0, 50).flatMap((x) => brief(x).map((b) => ({ ...b, auto: isObj(x) && x.auto === true }))),
    shared: list(o.shared)
      .slice(0, 50)
      .flatMap((g) => (isObj(g) && typeof g.site === "string" ? [{ site: g.site.slice(0, 253), hosts: strs(g.hosts).slice(0, 10), roles: strs(g.roles).slice(0, 5), cases: list(g.cases).slice(0, 50).flatMap(brief) }] : [])),
  };
};

// IOC 내보내기(검토관 이상): 담당자가 위협으로 확정한 사건의 지표. 미리 보기는 수만(값 없음), 내려받기는 감사로그
export type IocSummary = {
  days: number;
  cases: number;
  truncated: boolean;
  groups: number;
  indicators: number;
  byType: [string, number][];
  byThreat: [string, number][];
  excluded: [string, number][];
  stixSkipped: number;
  limits: { cases: number; chainCases: number; indicators: number };
  ms: number;
};
const count = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);
const counts = (v: unknown): [string, number][] =>
  isObj(v) ? Object.entries(v).slice(0, 20).flatMap(([k, n]): [string, number][] => (typeof n === "number" ? [[k.slice(0, 32), count(n)]] : [])) : [];
export const iocSummary = async (days: number): Promise<IocSummary> => {
  const o = await req<unknown>(`/api/ioc?days=${days}`);
  const v = isObj(o) ? o : {};
  const l = isObj(v.limits) ? v.limits : {};
  return {
    days: count(v.days),
    cases: count(v.cases),
    truncated: v.truncated === true,
    groups: count(v.groups),
    indicators: count(v.indicators),
    byType: counts(v.by_type),
    byThreat: counts(v.by_threat),
    excluded: counts(v.excluded),
    stixSkipped: count(v.stix_skipped),
    limits: { cases: count(l.cases), chainCases: count(l.chain_cases), indicators: count(l.indicators) },
    ms: count(v.ms),
  };
};
export async function downloadIoc(fmt: "csv" | "stix", days: number): Promise<void> {
  const r = await send(`/api/ioc.${fmt}?days=${days}`, {});
  const name = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") ?? "")?.[1] ?? `safetrace-ioc.${fmt === "csv" ? "csv" : "stix.json"}`;
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

// 연관 후보 하나를 새 사건으로 접수(조사관 이상). 이미 만든 후보면 그 사건을 돌려준다
export const createRelated = async (id: string, url: string) => {
  const c = cleanCase(await req<unknown>(`/api/cases/${encodeURIComponent(id)}/related`, { method: "POST", body: JSON.stringify({ url }) }));
  if (!c) throw new ApiError(500, "사건 형식 오류");
  return c;
};
export const verifyCase = (id: string) =>
  req<{ ok: boolean; records: number; errors: string[] }>(`/api/cases/${encodeURIComponent(id)}/verify`, {
    method: "POST",
  });

export const listVerdicts = (id: string) => req<Verdict[]>(`/api/cases/${encodeURIComponent(id)}/verdicts`);
export const saveVerdict = (id: string, v: { rev: number; decision: Decision; threat: string | null; note: string }) =>
  req<Verdict>(`/api/cases/${encodeURIComponent(id)}/verdicts`, { method: "POST", body: JSON.stringify(v) });

// 검토 패키지(ZIP: package.json·체인 원본·파일·SHA256SUMS·서명). 인증 헤더가 필요하므로 blob 으로 받아 저장한다
// 검토 패키지(ZIP) 또는 보고서 초안(PDF·JSON) 내려받기
export type ExportKind = "package.zip" | "report.pdf" | "report.json";

export async function downloadExport(caseId: string, kind: ExportKind): Promise<void> {
  const r = await send(`/api/cases/${encodeURIComponent(caseId)}/${kind}`, {});
  const name = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") ?? "")?.[1] ?? `safetrace-${caseId.slice(0, 8)}-${kind}`;
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

// 증거 파일은 인증 헤더가 필요하므로 blob 으로 받아 object URL 로 보여준다
// preview=true 면 화면 표시용으로 줄인 이미지(증거 아님). 원본 확인·검증은 preview 없이
export async function fileUrl(caseId: string, name: string, preview = false): Promise<string> {
  const q = preview ? "?preview=1" : "";
  const r = await fetch(`/api/cases/${encodeURIComponent(caseId)}/files/${encodeURIComponent(name)}${q}`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!r.ok) throw new ApiError(r.status, "파일을 불러오지 못함");
  return URL.createObjectURL(await r.blob());
}

// 증거 파일을 maxBytes 까지만 받는다(넘으면 413). 여러 파일을 미리 받을 때 합계를 묶는 데 쓴다.
// 크기 머리글을 먼저 보고, 없거나 틀려도 받은 만큼 세어 넘는 순간 끊는다
export async function fileBlob(caseId: string, name: string, maxBytes: number): Promise<Blob> {
  if (maxBytes <= 0) throw new ApiError(413, "파일이 너무 큼");
  const r = await fetch(`/api/cases/${encodeURIComponent(caseId)}/files/${encodeURIComponent(name)}`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!r.ok) throw new ApiError(r.status, "파일을 불러오지 못함");
  const len = Number(r.headers.get("Content-Length") ?? "");
  if ((Number.isFinite(len) && len > maxBytes) || !r.body) {
    await r.body?.cancel().catch(() => undefined);
    throw new ApiError(413, "파일이 너무 큼");
  }
  const reader = r.body.getReader();
  const parts: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new ApiError(413, "파일이 너무 큼");
    }
    parts.push(value);
  }
  return new Blob(parts as BlobPart[], { type: r.headers.get("Content-Type") ?? "" });
}

// SSE: EventSource 는 헤더를 못 붙이므로 fetch 스트림을 직접 파싱한다
export async function streamEvents(caseId: string, onEvent: (e: AgentEvent) => void, signal: AbortSignal) {
  const r = await fetch(`/api/cases/${encodeURIComponent(caseId)}/events`, {
    headers: { Authorization: `Bearer ${getToken()}` },
    signal,
  });
  if (!r.ok || !r.body) throw new ApiError(r.status, "실시간 연결 실패");
  const reader = r.body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += value;
    let idx;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const data = chunk
        .split("\n")
        .filter((l) => l.startsWith("data: "))
        .map((l) => l.slice(6))
        .join("\n");
      if (data && data.length <= MAX_EVENT_CHARS) {
        let ev: AgentEvent | null = null;
        try {
          ev = cleanEvent(JSON.parse(data));
        } catch {
          /* 형식 오류 이벤트는 무시 */
        }
        if (ev) onEvent(ev);
      }
    }
  }
}

// 이벤트 하나의 최대 크기(글자). 정상 기록은 수 KB 이고, 더 크면 화면에 쓰지 않고 버린다(콘솔 메모리 보호)
export const MAX_EVENT_CHARS = 256 * 1024;

// 기록은 격리된 에이전트(믿지 않는 쪽)에서 온다. 화면이 기대하는 모양이 아니면 버린다(렌더링 중 예외로 콘솔이 멈추지 않게)
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
export function cleanEvent(raw: unknown): AgentEvent | null {
  if (!isObj(raw)) return null;
  if (raw.type === "evidence") {
    const { seq, kind, data, files, hash } = raw;
    if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 0 || typeof kind !== "string" || !isObj(data)) return null;
    if (!Array.isArray(files) || !files.every((f) => typeof f === "string")) return null;
    return { type: "evidence", seq, kind: kind.slice(0, 40), data, files, hash: typeof hash === "string" ? hash : "" };
  }
  if (raw.type === "status") {
    if (typeof raw.status !== "string") return null;
    return {
      type: "status",
      status: raw.status.slice(0, 24),
      reason: typeof raw.reason === "string" ? raw.reason : null,
      ...(raw.phase === "related" ? { phase: "related" as const } : {}),
    };
  }
  if (raw.type === "step") {
    if (typeof raw.step !== "number" || typeof raw.url !== "string") return null;
    return { type: "step", step: raw.step, url: raw.url };
  }
  return null;
}
// 기록 안의 목록 값: 배열이 아니면 빈 목록, 항목은 원하는 모양만
export const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
export const strs = (v: unknown): string[] => list(v).slice(0, 200).filter((x): x is string => typeof x === "string").map((x) => x.slice(0, 2000));
export const clickables = (v: unknown): { id: string; text: string }[] =>
  list(v)
    .slice(0, 200)
    .flatMap((x) => (isObj(x) && typeof x.id === "string" ? [{ id: x.id.slice(0, 40), text: typeof x.text === "string" ? x.text.slice(0, 200) : "" }] : []));
// 기록의 값을 화면 글자·숫자로: 글자·숫자·참거짓만 받는다(객체를 String() 하면 조작된 toString 으로 예외가 날 수 있다)
export const text = (v: unknown, n = 2000): string =>
  typeof v === "string" ? v.slice(0, n) : typeof v === "number" || typeof v === "boolean" ? String(v) : "";
export const num = (v: unknown): number => (typeof v === "number" ? v : NaN);
// 고정 문구 표: 자체 키만 찾는다(toString·constructor 같은 상속 키로 함수가 나오지 않게)
export const dict = <T,>(o: Record<string, T>): Record<string, T> => Object.assign(Object.create(null) as Record<string, T>, o);

// 사건의 위협 판단·후보는 워커가 보낸 값을 API 가 저장한 것이다. 화면이 쓰는 모양으로만 받는다(목록 한 줄 때문에 콘솔 전체가 멈추지 않게)
const strOr = (v: unknown, d: string | null = null) => (typeof v === "string" ? v : d);
// 누락·비정상 확률은 실제 0.00으로 보이지 않도록 표시 불가값으로 남긴다.
const probabilityOrNaN = (v: unknown) =>
  typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1 ? v : NaN;
function cleanThreat(v: unknown): Threat | null {
  if (!isObj(v) || typeof v.threat !== "string") return null;
  const probs: Record<string, number> = {};
  if (isObj(v.probabilities)) for (const [k, p] of Object.entries(v.probabilities).slice(0, 20)) if (Number.isFinite(probabilityOrNaN(p))) probs[k] = p as number;
  const o = v.override;
  const original = isObj(o) && isObj(o.original) ? o.original : null;
  return {
    threat: v.threat.slice(0, 32),
    probability: probabilityOrNaN(v.probability),
    probabilities: probs,
    hold: v.hold === true,
    provider: strOr(v.provider, "") as string,
    model: strOr(v.model, "") as string,
    evidence_seqs: list(v.evidence_seqs).filter((x): x is number => typeof x === "number").slice(0, 50),
    override:
      isObj(o) && typeof o.reason === "string"
        ? {
            reason: o.reason,
            operators: strs(o.operators),
            brand: strOr(o.brand) ?? undefined,
            destination: strOr(o.destination) ?? undefined,
            original: { threat: strOr(original?.threat, "") as string, probability: probabilityOrNaN(original?.probability), provider: strOr(original?.provider, "") as string },
          }
        : undefined,
  };
}
// 후보의 값은 근거 카드·경로 지도가 글자에 넣는다: 정해진 자료형만 남긴다
function cleanCandidate(x: unknown): Candidate[] {
  if (!isObj(x) || typeof x.url !== "string") return [];
  const sub = typeof x.sub === "number" && Number.isInteger(x.sub) && x.sub > 0 ? x.sub : undefined;
  return [{
    url: x.url.slice(0, 2000),
    host: strOr(x.host)?.slice(0, 300) ?? undefined,
    source: x.source === "via" || x.source === "link" ? x.source : undefined,
    reputation_match: x.reputation_match === true,
    reputation_unchecked: x.reputation_unchecked === true,
    sub,
    status: strOr(x.status)?.slice(0, 32) ?? undefined,
    reason: strOr(x.reason)?.slice(0, 200) ?? undefined,
    final_url: strOr(x.final_url)?.slice(0, 2000) ?? undefined,
    threat: strOr(x.threat)?.slice(0, 32) ?? null,
    probability: typeof x.probability === "number" && Number.isFinite(x.probability) ? x.probability : null,
    hold: x.hold === true,
    blocked: x.blocked === true,
    score: typeof x.score === "number" && Number.isInteger(x.score) && x.score >= 0 && x.score <= 3 ? x.score : undefined,
    text: strOr(x.text)?.slice(0, 80) ?? undefined,
  }];
}
function cleanChild(x: unknown): ChildCase[] {
  if (!isObj(x) || typeof x.id !== "string" || typeof x.url !== "string" || typeof x.status !== "string") return [];
  return [{
    id: x.id.slice(0, 36),
    url: x.url.slice(0, 2000),
    candidate_url: strOr(x.candidate_url)?.slice(0, 2000) ?? x.url.slice(0, 2000),
    status: x.status.slice(0, 24),
    threat: strOr(x.threat)?.slice(0, 32) ?? null,
    verdict: strOr(x.verdict)?.slice(0, 16) ?? null,
    auto: x.auto === true,
  }];
}
export function cleanCase(v: unknown): CaseOut | null {
  if (!isObj(v) || typeof v.id !== "string" || typeof v.url !== "string" || typeof v.status !== "string" || typeof v.created_at !== "string") return null;
  const sb = isObj(v.safebrowsing) && typeof v.safebrowsing.status === "string"
    ? { status: v.safebrowsing.status, matches: list(v.safebrowsing.matches).flatMap((m) => (isObj(m) ? [{ url: strOr(m.url, "") as string, threat_type: strOr(m.threat_type, "") as string }] : [])) }
    : null;
  const ver = isObj(v.verdict) && typeof v.verdict.rev === "number" && typeof v.verdict.decision === "string" ? (v.verdict as unknown as Verdict) : null;
  return {
    id: v.id,
    url: v.url,
    source: strOr(v.source, "") as string,
    status: v.status,
    finish_reason: strOr(v.finish_reason),
    final_url: strOr(v.final_url),
    threat: cleanThreat(v.threat),
    safebrowsing: sb,
    candidates: list(v.candidates).slice(0, 200).flatMap((x): (Candidate | string)[] => (typeof x === "string" ? [x.slice(0, 2000)] : cleanCandidate(x))),
    head_seq: typeof v.head_seq === "number" ? v.head_seq : null,
    created_at: v.created_at,
    verdict: ver,
    phase: v.phase === "related" ? "related" : null,
    main_status: strOr(v.main_status)?.slice(0, 24) ?? null,
    main_reason: strOr(v.main_reason)?.slice(0, 200) ?? null,
    parent_id: strOr(v.parent_id)?.slice(0, 36) ?? null,
    parent_url: strOr(v.parent_url)?.slice(0, 2000) ?? null,
    auto: typeof v.auto === "boolean" ? v.auto : null,
    children: Array.isArray(v.children) ? list(v.children).slice(0, 50).flatMap(cleanChild) : null,
    auto_skipped: Array.isArray(v.auto_skipped)
      ? list(v.auto_skipped)
          .slice(0, 20)
          .flatMap((x) => (isObj(x) && typeof x.url === "string" && typeof x.reason === "string" ? [{ url: x.url.slice(0, 2000), reason: x.reason.slice(0, 32) }] : []))
      : null,
  };
}

// 현황판(열람자 이상): 기간 안 사건의 접수·처리·판정 수. 서버가 센 값이지만 모양을 다시 맞춘다
export type Pair = [string, number];
export type Stats = {
  days: number;
  cases: number;
  truncated: boolean;
  ms: number;
  kpi: { received: number; finished: number; pending: number; other: number; aiThreat: number; confirmed: number; waiting: number };
  daily: { date: string; received: number; aiThreat: number; confirmed: number }[];
  ai: Pair[];
  decisions: Pair[];
  confirmed: Pair[];
  rules: Pair[];
  rulesConfirmed: Record<string, number>;
  brands: Pair[];
  hosting: Pair[];
  tlds: Pair[];
  timing: { toMainS: { n: number; median: number | null; p90: number | null }; toVerdictH: { n: number; median: number | null; p90: number | null }; waitingH: { n: number; median: number | null; max: number | null } };
  agreement: { pairs: number; sameClass: number; bothThreat: number; sameType: number; aiThreatReviewerBenign: number; aiBenignReviewerThreat: number };
  related: { auto: number; manual: number; autoAiThreat: number; autoConfirmed: number };
};
const statN = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0);
const statOpt = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const statObj = (v: unknown): Record<string, unknown> => (isObj(v) ? v : {});
const statPairs = (v: unknown): Pair[] =>
  list(v).slice(0, 20).flatMap((x): Pair[] => (Array.isArray(x) && typeof x[0] === "string" && typeof x[1] === "number" ? [[x[0].slice(0, 40), statN(x[1])]] : []));
const statDict = (v: unknown): Pair[] =>
  isObj(v) ? Object.entries(v).slice(0, 20).flatMap(([k, n]): Pair[] => (typeof n === "number" ? [[k.slice(0, 40), statN(n)]] : [])) : [];
const timing = (v: unknown) => {
  const o = statObj(v);
  return { n: statN(o.n), median: statOpt(o.median), p90: statOpt(o.p90), max: statOpt(o.max) };
};
export const getStats = async (days: number): Promise<Stats> => {
  const v = statObj(await req<unknown>(`/api/stats?days=${days}`));
  const k = statObj(v.kpi);
  const t = statObj(v.timing);
  const a = statObj(v.agreement);
  const r = statObj(v.related);
  return {
    days: statN(v.days),
    cases: statN(v.cases),
    truncated: v.truncated === true,
    ms: statN(v.ms),
    kpi: { received: statN(k.received), finished: statN(k.finished), pending: statN(k.pending), other: statN(k.other), aiThreat: statN(k.ai_threat), confirmed: statN(k.confirmed), waiting: statN(k.waiting) },
    daily: list(v.daily)
      .slice(0, 100)
      .flatMap((x) => {
        const d = statObj(x);
        return typeof d.date === "string" && /^\d{4}-\d\d-\d\d$/.test(d.date) ? [{ date: d.date, received: statN(d.received), aiThreat: statN(d.ai_threat), confirmed: statN(d.confirmed) }] : [];
      }),
    ai: statDict(v.ai),
    decisions: statDict(v.decisions),
    confirmed: statDict(v.confirmed),
    rules: statPairs(v.rules),
    rulesConfirmed: Object.fromEntries(statDict(v.rules_confirmed)),
    brands: statPairs(v.brands),
    hosting: statPairs(v.hosting),
    tlds: statPairs(v.tlds),
    timing: { toMainS: timing(t.to_main_s), toVerdictH: timing(t.to_verdict_h), waitingH: timing(t.waiting_h) },
    agreement: { pairs: statN(a.pairs), sameClass: statN(a.same_class), bothThreat: statN(a.both_threat), sameType: statN(a.same_type), aiThreatReviewerBenign: statN(a.ai_threat_reviewer_benign), aiBenignReviewerThreat: statN(a.ai_benign_reviewer_threat) },
    related: { auto: statN(r.auto), manual: statN(r.manual), autoAiThreat: statN(r.auto_ai_threat), autoConfirmed: statN(r.auto_confirmed) },
  };
};

// 자동 수집(공개 피싱 피드 → 조사 접수). 상태는 열람자 이상, 켜기·끄기는 사람 관리자만. 주소 값은 오지 않는다
// nextAt: 다음 받기 시각(켜져 있을 때 기준, 받는 중이면 null), intervalH: 받는 주기(시간)
export type IntakeSource = { state: string; requestedAt: string; doneAt: string | null; got: number | null; picked: number | null; reason: string | null; nextAt: string | null; intervalH: number | null } | null;
export type Intake = { enabled: boolean; updatedBy: string | null; updatedAt: string | null; sources: [string, IntakeSource][]; queued: number; pending: number; created24h: number };
const cleanIntake = (v: unknown): Intake => {
  const o = isObj(v) ? v : {};
  const n = (x: unknown) => (typeof x === "number" && Number.isFinite(x) && x >= 0 ? x : 0);
  const srcs = isObj(o.sources) ? o.sources : {};
  return {
    enabled: o.enabled === true,
    updatedBy: strOr(o.updated_by)?.slice(0, 64) ?? null,
    updatedAt: strOr(o.updated_at)?.slice(0, 40) ?? null,
    sources: Object.entries(srcs)
      .slice(0, 5)
      .map(([k, x]): [string, IntakeSource] => [
        k.slice(0, 16),
        isObj(x) && typeof x.state === "string" && typeof x.requested_at === "string"
          ? {
              state: x.state.slice(0, 12),
              requestedAt: x.requested_at.slice(0, 40),
              doneAt: strOr(x.done_at)?.slice(0, 40) ?? null,
              got: typeof x.got === "number" ? x.got : null,
              picked: typeof x.picked === "number" ? x.picked : null,
              reason: strOr(x.reason)?.slice(0, 64) ?? null,
              nextAt: strOr(x.next_at)?.slice(0, 40) ?? null,
              intervalH: typeof x.interval_h === "number" && Number.isFinite(x.interval_h) && x.interval_h > 0 ? x.interval_h : null,
            }
          : null,
      ]),
    queued: n(o.queued),
    pending: n(o.pending),
    created24h: n(o.created_24h),
  };
};
export const getIntake = async () => cleanIntake(await req<unknown>("/api/intake"));
export const setIntake = async (enabled: boolean) => cleanIntake(await req<unknown>("/api/intake", { method: "POST", body: JSON.stringify({ enabled }) }));

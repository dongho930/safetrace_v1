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
  parent_id: string | null; // 연관 사건이면 그 후보가 나온 부모 사건
  parent_url: string | null;
  auto: boolean | null; // 자동으로 만든 연관 사건인지(PR 4b)
  children: ChildCase[] | null; // 이 사건의 후보로 만든 사건(상세에만)
  auto_skipped: { url: string; reason: string }[] | null; // 하위 조사했지만 자동 사건이 없는 후보와 이유(상세에만)
  action: Action | null; // 현재 조치(요청함·차단 확인·삭제 확인·다시 나타남·종결)
};

// 조치 추적(모니터링 담당자): 위협 확정 뒤 기관에 요청 → 차단·삭제 확인 → 재확인에서 다시 나타남 → 종결. 판(rev)을 쌓는다
export type ActionState = "requested" | "blocked" | "removed" | "reappeared" | "closed";
export type Action = { rev: number; state: ActionState; agency: string | null; ref: string | null; note: string | null; actor: string; check_id: number | null; created_at: string };
// 재확인: 신고 주소에 다시 접속해 본 결과(격리된 조사 컨테이너가 한다). 값은 조사 대상 서버가 정한 글자를 포함한다
export type Check = { id: number; state: string; requested_by: string; requested_at: string; done_at: string | null; result: string | null; reason: string | null; http_status: number | null; final_host: string | null; title: string | null };
const ACTION_STATES = ["requested", "blocked", "removed", "reappeared", "closed"];
function cleanAction(x: unknown): Action | null {
  if (!isObj(x) || typeof x.rev !== "number" || typeof x.state !== "string" || !ACTION_STATES.includes(x.state)) return null;
  return {
    rev: x.rev,
    state: x.state as ActionState,
    agency: strOr(x.agency)?.slice(0, 16) ?? null,
    ref: strOr(x.ref)?.slice(0, 100) ?? null,
    note: strOr(x.note)?.slice(0, 1000) ?? null,
    actor: text(x.actor, 64),
    check_id: typeof x.check_id === "number" ? x.check_id : null,
    created_at: text(x.created_at, 40),
  };
}
function cleanCheck(x: unknown): Check[] {
  if (!isObj(x) || typeof x.id !== "number" || typeof x.state !== "string") return [];
  return [{
    id: x.id,
    state: x.state.slice(0, 12),
    requested_by: text(x.requested_by, 64),
    requested_at: text(x.requested_at, 40),
    done_at: strOr(x.done_at)?.slice(0, 40) ?? null,
    result: strOr(x.result)?.slice(0, 16) ?? null,
    reason: strOr(x.reason)?.slice(0, 64) ?? null,
    http_status: typeof x.http_status === "number" ? x.http_status : null,
    final_host: strOr(x.final_host)?.slice(0, 253) ?? null,
    title: strOr(x.title)?.slice(0, 200) ?? null,
  }];
}
export const getActions = async (id: string): Promise<{ actions: Action[]; checks: Check[]; interval: number }> => {
  const v = await req<unknown>(`/api/cases/${encodeURIComponent(id)}/actions`);
  const o = isObj(v) ? v : {};
  return {
    actions: list(o.actions).slice(0, 50).flatMap((x) => cleanAction(x) ?? []),
    checks: list(o.checks).slice(0, 20).flatMap(cleanCheck),
    interval: typeof o.recheck_interval_hours === "number" ? o.recheck_interval_hours : 24,
  };
};
export const saveAction = async (id: string, a: { rev: number; state: ActionState; agency: string | null; ref: string; note: string }) => {
  const v = cleanAction(await req<unknown>(`/api/cases/${encodeURIComponent(id)}/actions`, { method: "POST", body: JSON.stringify(a) }));
  if (!v) throw new ApiError(500, "조치 형식 오류");
  return v;
};
export const requestRecheck = (id: string) => req<unknown>(`/api/cases/${encodeURIComponent(id)}/recheck`, { method: "POST" });

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

export const listCases = async () => (await req<unknown[]>("/api/cases?limit=50")).flatMap((x) => cleanCase(x) ?? []);
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
export type CaseBrief = { id: string; url: string; status: string; threat: string | null; verdict: string | null };
// 이은 열쇠의 종류: site(사이트) | contact(운영 정보: 텔레그램·계좌 등, 페이지에 적힌 값) | kit(키트 지문)
export type LinkKind = "site" | "contact" | "kit";
const linkKind = (v: unknown): LinkKind => (v === "contact" || v === "kit" ? v : "site");
export type CaseLinks = { parent: CaseBrief | null; children: (CaseBrief & { auto: boolean })[]; shared: { site: string; kind: LinkKind; hosts: string[]; roles: string[]; cases: CaseBrief[] }[] };
export type GroupSite = { site: string; kind: LinkKind; hosts: string[]; threat: string | null; blocked: boolean; cases: number; candidate: { case_id: string; host: string } | null };
export type RelatedGroup = { key: string; cases: CaseBrief[]; sites: GroupSite[]; threat_sites: number; blocked_estimate_sites: number };
const brief = (x: unknown): CaseBrief[] =>
  isObj(x) && typeof x.id === "string" && typeof x.url === "string" && typeof x.status === "string"
    ? [{ id: x.id.slice(0, 36), url: x.url.slice(0, 2000), status: x.status.slice(0, 24), threat: strOr(x.threat)?.slice(0, 32) ?? null, verdict: strOr(x.verdict)?.slice(0, 16) ?? null }]
    : [];
export const getLinks = async (id: string): Promise<CaseLinks> => {
  const v = await req<unknown>(`/api/cases/${encodeURIComponent(id)}/links`);
  const o = isObj(v) ? v : {};
  return {
    parent: brief(o.parent)[0] ?? null,
    children: list(o.children).slice(0, 50).flatMap((x) => brief(x).map((b) => ({ ...b, auto: isObj(x) && x.auto === true }))),
    shared: list(o.shared)
      .slice(0, 50)
      .flatMap((g) => (isObj(g) && typeof g.site === "string" ? [{ site: g.site.slice(0, 253), kind: linkKind(g.kind), hosts: strs(g.hosts).slice(0, 10), roles: strs(g.roles).slice(0, 5), cases: list(g.cases).slice(0, 50).flatMap(brief) }] : [])),
  };
};
export const listGroups = async (): Promise<{ groups: RelatedGroup[]; truncated: boolean; ms: number }> => {
  const v = await req<unknown>("/api/related-groups?min=2&limit=50");
  const o = isObj(v) ? v : {};
  const groups = list(o.groups)
    .slice(0, 50)
    .flatMap((g): RelatedGroup[] =>
      isObj(g) && typeof g.key === "string" && /^[0-9a-f]{16}$/.test(g.key)
        ? [{
            key: g.key,
            cases: list(g.cases).slice(0, 200).flatMap(brief),
            sites: list(g.sites)
              .slice(0, 300)
              .flatMap((x): GroupSite[] =>
                isObj(x) && typeof x.site === "string"
                  ? [{
                      site: x.site.slice(0, 253),
                      kind: linkKind(x.kind),
                      hosts: strs(x.hosts).slice(0, 10),
                      threat: strOr(x.threat)?.slice(0, 32) ?? null,
                      blocked: x.blocked === true,
                      cases: typeof x.cases === "number" ? x.cases : 0,
                      candidate: isObj(x.candidate) && typeof x.candidate.case_id === "string" && typeof x.candidate.host === "string" ? { case_id: x.candidate.case_id.slice(0, 36), host: x.candidate.host.slice(0, 253) } : null,
                    }]
                  : [],
              ),
            threat_sites: typeof g.threat_sites === "number" ? g.threat_sites : 0,
            blocked_estimate_sites: typeof g.blocked_estimate_sites === "number" ? g.blocked_estimate_sites : 0,
          }]
        : [],
    );
  return { groups, truncated: o.truncated === true, ms: typeof o.ms === "number" ? o.ms : 0 };
};
export async function downloadGroupCsv(key: string): Promise<void> {
  const r = await send(`/api/related-groups/${encodeURIComponent(key)}.csv`, {});
  const name = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") ?? "")?.[1] ?? `safetrace-related-${key.slice(0, 8)}.csv`;
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

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
  contacts: { included: boolean; verified: number; unverified: number; overLimit: number };
  limits: { cases: number; contactCases: number; indicators: number };
  ms: number;
};
const count = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);
const counts = (v: unknown): [string, number][] =>
  isObj(v) ? Object.entries(v).slice(0, 20).flatMap(([k, n]): [string, number][] => (typeof n === "number" ? [[k.slice(0, 32), count(n)]] : [])) : [];
export const iocSummary = async (days: number, contacts: boolean): Promise<IocSummary> => {
  const o = await req<unknown>(`/api/ioc?days=${days}&contacts=${contacts}`);
  const v = isObj(o) ? o : {};
  const c = isObj(v.contacts) ? v.contacts : {};
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
    contacts: { included: c.included === true, verified: count(c.verified), unverified: count(c.unverified), overLimit: count(c.over_limit) },
    limits: { cases: count(l.cases), contactCases: count(l.contact_cases), indicators: count(l.indicators) },
    ms: count(v.ms),
  };
};
export async function downloadIoc(fmt: "csv" | "stix", days: number, contacts: boolean): Promise<void> {
  const r = await send(`/api/ioc.${fmt}?days=${days}&contacts=${contacts}`, {});
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
const numOr = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : 0);
function cleanThreat(v: unknown): Threat | null {
  if (!isObj(v) || typeof v.threat !== "string") return null;
  const probs: Record<string, number> = {};
  if (isObj(v.probabilities)) for (const [k, p] of Object.entries(v.probabilities).slice(0, 20)) if (typeof p === "number" && Number.isFinite(p)) probs[k] = p;
  const o = v.override;
  const original = isObj(o) && isObj(o.original) ? o.original : null;
  return {
    threat: v.threat.slice(0, 32),
    probability: numOr(v.probability),
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
            original: { threat: strOr(original?.threat, "") as string, probability: numOr(original?.probability), provider: strOr(original?.provider, "") as string },
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
    parent_id: strOr(v.parent_id)?.slice(0, 36) ?? null,
    parent_url: strOr(v.parent_url)?.slice(0, 2000) ?? null,
    auto: typeof v.auto === "boolean" ? v.auto : null,
    children: Array.isArray(v.children) ? list(v.children).slice(0, 50).flatMap(cleanChild) : null,
    auto_skipped: Array.isArray(v.auto_skipped)
      ? list(v.auto_skipped)
          .slice(0, 20)
          .flatMap((x) => (isObj(x) && typeof x.url === "string" && typeof x.reason === "string" ? [{ url: x.url.slice(0, 2000), reason: x.reason.slice(0, 32) }] : []))
      : null,
    action: cleanAction(v.action),
  };
}

// 처리 기관 안내·요청서 초안(조사관 이상). 기관·조문은 서버의 고정 표에서, 요청서 글의 제목·주소는 조사 대상 페이지 값을
// 서버가 한 줄로 정리한 것이다. 화면에는 글자로만 넣는다(링크로 만드는 것은 서버 고정 표의 기관 주소뿐)
export type Agency = { id: string; name: string; phone: string; url: string; does: string; when?: string };
export type Referral =
  | { applicable: false; reason_ko: string; notice: string }
  | { applicable: true; threat_ko: string; basis: "confirmed" | "ai"; draft: boolean; agency: Agency; also: Agency[]; laws: { cite: string; text: string }[]; subject: string; text: string; notice: string };
const agency = (x: unknown): Agency[] =>
  isObj(x) && typeof x.name === "string" && typeof x.url === "string" && /^https:\/\/[a-z0-9.-]+\/$/.test(x.url)
    ? [{ id: text(x.id, 16), name: x.name.slice(0, 80), phone: text(x.phone, 16), url: x.url, does: text(x.does, 120), when: text(x.when, 120) }]
    : [];
export const getReferral = async (id: string): Promise<Referral> => {
  const v = await req<unknown>(`/api/cases/${encodeURIComponent(id)}/referral`);
  const o = isObj(v) ? v : {};
  const ag = agency(o.agency)[0];
  if (o.applicable !== true || !ag) return { applicable: false, reason_ko: text(o.reason_ko, 200), notice: text(o.notice, 400) };
  return {
    applicable: true,
    threat_ko: text(o.threat_ko, 32),
    basis: o.basis === "confirmed" ? "confirmed" : "ai",
    draft: o.draft !== false,
    agency: ag,
    also: list(o.also).slice(0, 5).flatMap(agency),
    laws: list(o.laws).slice(0, 5).flatMap((x) => (isObj(x) && typeof x.cite === "string" ? [{ cite: x.cite.slice(0, 120), text: text(x.text, 300) }] : [])),
    subject: text(o.subject, 300),
    text: text(o.text, 8000),
    notice: text(o.notice, 400),
  };
};

// 운영 정보(조사관 이상): 화면에 적힌 운영 연락처·입금 계좌·입력값을 보내는 곳과 키트 지문, 같은 열쇠가 나온 다른 사건.
// 값은 조사 대상 페이지가 적은 글자다(확인 안 됨). 화면에는 글자로만 넣는다
export type IntelItem = { kind: string; value: string; src: string | null; step: number | null; others: CaseBrief[] };
export type KitPrint = { kind: "dom" | "res"; hash: string; host: string; step: number | null; others: CaseBrief[] };
export type CaseIntel = { items: IntelItem[]; kits: KitPrint[] };
export const getIntel = async (id: string): Promise<CaseIntel> => {
  const v = await req<unknown>(`/api/cases/${encodeURIComponent(id)}/intel`);
  const o = isObj(v) ? v : {};
  const step = (x: unknown) => (typeof x === "number" && Number.isInteger(x) && x >= 0 ? x : null);
  return {
    items: list(o.items)
      .slice(0, 50)
      .flatMap((x): IntelItem[] =>
        isObj(x) && typeof x.kind === "string" && typeof x.value === "string"
          ? [{ kind: x.kind.slice(0, 16), value: x.value.slice(0, 200), src: strOr(x.src)?.slice(0, 8) ?? null, step: step(x.step), others: list(x.others).slice(0, 50).flatMap(brief) }]
          : [],
      ),
    kits: list(o.kits)
      .slice(0, 20)
      .flatMap((x): KitPrint[] =>
        isObj(x) && (x.kind === "dom" || x.kind === "res") && typeof x.hash === "string" && /^[0-9a-f]{32}$/.test(x.hash)
          ? [{ kind: x.kind, hash: x.hash, host: text(x.host, 253), step: step(x.step), others: list(x.others).slice(0, 50).flatMap(brief) }]
          : [],
      ),
  };
};

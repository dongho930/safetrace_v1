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
  // 화면 내용이 없는 브랜드 사칭 도메인(brand_lookalike → 피싱, 담당자 검토)
  override?: { reason: string; operators?: string[]; brand?: string; destination?: string; original: { threat: string; probability: number; provider: string } };
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
  candidates: string[] | null;
  head_seq: number | null;
  created_at: string;
  verdict: Verdict | null; // 담당자의 현재 판정(없으면 null)
};

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
export type StatusEvent = { type: "status"; status: string; reason: string | null; threat?: Threat | null };
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
  if (!r.ok) throw new ApiError(r.status, r.status === 401 ? "아이디 또는 비밀번호가 올바르지 않습니다" : `로그인 실패 (${r.status})`);
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

export const listCases = () => req<CaseOut[]>("/api/cases?limit=50");
export const getCase = (id: string) => req<CaseOut>(`/api/cases/${encodeURIComponent(id)}`);
export const createCase = (url: string, source: string) =>
  req<CaseOut>("/api/cases", {
    method: "POST",
    body: JSON.stringify({ url, source }),
    headers: { "Idempotency-Key": crypto.randomUUID() },
  });
export const verifyCase = (id: string) =>
  req<{ ok: boolean; records: number; errors: string[] }>(`/api/cases/${encodeURIComponent(id)}/verify`, {
    method: "POST",
  });

export const listVerdicts = (id: string) => req<Verdict[]>(`/api/cases/${encodeURIComponent(id)}/verdicts`);
export const saveVerdict = (id: string, v: { rev: number; decision: Decision; threat: string | null; note: string }) =>
  req<Verdict>(`/api/cases/${encodeURIComponent(id)}/verdicts`, { method: "POST", body: JSON.stringify(v) });

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
      if (data) {
        try {
          onEvent(JSON.parse(data) as AgentEvent);
        } catch {
          /* 형식 오류 이벤트는 무시 */
        }
      }
    }
  }
}

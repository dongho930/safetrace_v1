// API 클라이언트. 토큰은 sessionStorage 에만 두고(탭 종료 시 삭제), 모든 요청에 Bearer 로 붙인다.
export type Threat = {
  threat: string;
  probability: number;
  probabilities: Record<string, number>;
  hold: boolean;
  provider: string;
  model: string;
  evidence_seqs: number[];
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
  return r.json() as Promise<T>;
}

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

// 증거 파일은 인증 헤더가 필요하므로 blob 으로 받아 object URL 로 보여준다
export async function fileUrl(caseId: string, name: string): Promise<string> {
  const r = await fetch(`/api/cases/${encodeURIComponent(caseId)}/files/${encodeURIComponent(name)}`, {
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

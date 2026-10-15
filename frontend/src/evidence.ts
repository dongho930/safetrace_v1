// 근거 카드·근거 화면·경로 지도: 콘솔이 이미 받은 사건(CaseOut)과 서명된 기록(/events)으로만 계산한다.
// 문장은 고정 문구 + 기록 값으로만 만든다(AI 가 새로 쓰는 문장 없음). 페이지에서 온 글자는 잘라서 글자로만 쓴다.
import { type Candidate, type CaseOut, type EvidenceEvent, clickables, strs, text as str } from "./api";
import { ACTION_LABEL, overrideLabel, THREAT_LABEL } from "./labels";

export type Tone = "threat" | "review" | "safe" | "idle";
export const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const pct = (v: number) => (Number.isFinite(v) ? v.toFixed(2) : "-");
const isSub = (e: EvidenceEvent) => typeof e.data.sub === "number";
const png = (e: EvidenceEvent | undefined) => e?.files.find((f) => f.endsWith(".png")) ?? null;
// 기록 값은 str(=api.text)·strs·clickables 로만 읽는다(모양이 틀린 기록·조작된 toString 으로 예외가 나지 않게)

// 주소의 호스트 또는 파일 이름(카드·지도에 짧게 쓴다)
export function hostOrFile(u: string): string {
  try {
    const x = new URL(u);
    const file = x.pathname.split("/").filter(Boolean).pop();
    return file && /\.[a-z0-9]{2,5}$/i.test(file) ? file : x.host;
  } catch {
    return u;
  }
}
export function hostPath(u: string): string {
  try {
    const x = new URL(u);
    return x.host + (x.pathname === "/" ? "" : x.pathname);
  } catch {
    return u;
  }
}

// 관찰 기록의 클릭 후보(id → 글자)
function candidateText(observe: EvidenceEvent | undefined, id: string): string {
  return clickables(observe?.data.candidates).find((c) => c.id === id)?.text || id;
}
const lastBefore = (events: EvidenceEvent[], seq: number, f: (e: EvidenceEvent) => boolean) =>
  [...events].reverse().find((e) => e.seq < seq && f(e));

// ── 근거 카드(최대 3장) ─────────────────────────────────
export type Reason = {
  key: string;
  title: string;
  text: string;
  ev: string; // "EV-12" 또는 "하위 조사 1"
  tone: Tone;
  shot: string | null; // 연결 화면(증거 파일 이름)
  shotSeq: number | null; // 그 화면을 남긴 관찰 기록
};

export function buildReasons(events: EvidenceEvent[], c: CaseOut): Reason[] {
  const main = events.filter((e) => !isSub(e));
  const observes = main.filter((e) => e.kind === "observe" && png(e));
  const out: Reason[] = [];
  const push = (r: Reason) => {
    if (out.length < 3) out.push(r);
  };
  const last = (f: (e: EvidenceEvent) => boolean) => [...main].reverse().find(f);

  // ① 안전 게이트가 막은 클릭
  const gate = last((e) => e.kind === "gate" && e.data.allowed === false);
  if (gate) {
    const obs = lastBefore(main, gate.seq, (e) => e.kind === "observe");
    const action = str(gate.data.action);
    const what = action === "click" ? `“${clip(candidateText(obs, str(gate.data.element)), 40)}” 클릭` : (ACTION_LABEL[action] ?? action);
    const shotObs = lastBefore(main, gate.seq, (e) => e.kind === "observe" && !!png(e));
    push({ key: "gate", title: "입력·제출 차단", text: `${what}을 안전 게이트가 막음 (${clip(str(gate.data.reason), 40)})`, ev: `EV-${gate.seq}`, tone: "threat", shot: png(shotObs), shotSeq: shotObs?.seq ?? null });
  }
  // ② 검문 프록시가 막은 페이지 이동
  const nav = last((e) => e.kind === "blocked_request" && e.data.navigation === true);
  if (nav) {
    const shotObs = lastBefore(main, nav.seq, (e) => e.kind === "observe" && !!png(e));
    push({ key: "nav", title: "이동 차단", text: `${clip(hostOrFile(str(nav.data.url)), 40)}(으)로 이동하려 해 검문 프록시가 막음 (${clip(str(nav.data.reason), 40)})`, ev: `EV-${nav.seq}`, tone: "threat", shot: png(shotObs), shotSeq: shotObs?.seq ?? null });
  }
  // ③ 입력 칸 등 금지 요소가 있는 화면(형식 reason:type:label, label 만 보여 준다)
  const forb = [...observes].reverse().find((e) => strs(e.data.forbidden).length > 0);
  if (forb) {
    const list = strs(forb.data.forbidden);
    const label = list[0].split(":").slice(2).join(":") || list[0];
    push({ key: "forbidden", title: "입력 요구 화면", text: `입력 칸 등 금지 요소 ${list.length}개가 있는 화면 (${clip(label, 40)})`, ev: `EV-${forb.seq}`, tone: "threat", shot: png(forb), shotSeq: forb.seq });
  }
  // ④ 담당자 검토 전환(행동 기록과 같은 문구)
  const esc = last((e) => e.kind === "escalation");
  if (esc) {
    const why = esc.data.reason === "unreachable_network_filtered" ? "회선의 도메인 차단 감지" : `Safe Browsing ${strs(esc.data.threat_types).join(", ")}`;
    push({ key: "escalation", title: "담당자 검토 전환", text: why, ev: `EV-${esc.seq}`, tone: "review", shot: null, shotSeq: null });
  }
  // ⑤ 연관 사이트도 의심: Safe Browsing 위험 일치(AI 유형과 무관하게 먼저), 없으면 하위 조사에서 AI 가 위협으로 본 후보.
  // 아직 차단되지 않은 위협 후보를 먼저 고른다(이미 차단된 곳은 따로 차단 요청할 필요가 적다)
  const cands = (c.candidates ?? []).filter((x): x is Candidate => typeof x !== "string");
  const rep = [...cands].reverse().find((x) => x.reputation_match);
  const threats = [...cands].reverse().filter((x) => x.sub && x.threat && x.threat !== "benign");
  const sus = rep ?? threats.find((x) => !x.blocked) ?? threats[0];
  if (sus) {
    const first = sus.sub ? events.find((e) => e.kind === "observe" && e.data.sub === sus.sub && png(e)?.startsWith(`c${sus.sub}_`)) : undefined;
    const where = sus.source === "via" ? "경유" : "링크";
    const host = clip(sus.host ?? sus.url, 40) + (sus.blocked ? "(이미 차단됨)" : "");
    const ai = sus.threat ? `${THREAT_LABEL[sus.threat] ?? sus.threat}${sus.probability != null ? ` ${pct(sus.probability)}` : ""}` : "";
    if (rep) {
      const sb = last((e) => e.kind === "candidate_safebrowsing");
      push({
        key: "candidate", title: "연관 사이트 평판 위험",
        text: `${where} ${host}(또는 그 이동 주소)이 Safe Browsing 위험 일치${ai ? ` · AI 판단 ${ai}` : ""}`,
        ev: sb ? `EV-${sb.seq}` : sus.sub ? `하위 조사 ${sus.sub}` : "평판", tone: "threat", shot: png(first), shotSeq: first?.seq ?? null,
      });
    } else {
      push({
        key: "candidate", title: "연관 사이트도 의심",
        text: `${where} ${host}도 ${ai}${sus.hold ? "(보류)" : ""}`,
        ev: `하위 조사 ${sus.sub}`, tone: sus.hold ? "review" : "threat", shot: png(first), shotSeq: first?.seq ?? null,
      });
    }
  }
  // ⑥ Safe Browsing 일치
  if (c.safebrowsing?.status === "match") {
    const sb = last((e) => e.kind === "safebrowsing");
    const types = [...new Set(c.safebrowsing.matches.map((m) => str(m.threat_type)))].join(", ");
    push({ key: "safebrowsing", title: "Safe Browsing 일치", text: clip(types, 80), ev: sb ? `EV-${sb.seq}` : "평판", tone: "threat", shot: null, shotSeq: null });
  }
  // ⑦ 코드 규칙 판단
  if (c.threat?.override) {
    const th = last((e) => e.kind === "threat");
    push({ key: "override", title: "코드 규칙 판단", text: overrideLabel(c.threat.override), ev: th ? `EV-${th.seq}` : "판단", tone: "review", shot: null, shotSeq: null });
  }
  if (out.length === 0) {
    const lastObs = observes[observes.length - 1];
    out.push(
      lastObs
        ? { key: "none", title: "뚜렷한 위험 근거 없음", text: "마지막 화면을 확인하세요", ev: `EV-${lastObs.seq}`, tone: "idle", shot: png(lastObs), shotSeq: lastObs.seq }
        : { key: "none", title: "근거 없음", text: "페이지를 열지 못해 화면 기록이 없습니다. 행동 기록을 확인하세요", ev: "-", tone: "idle", shot: null, shotSeq: null },
    );
  }
  return out;
}

// ── 근거 화면(최대 4장): 카드 순서 → 첫 화면 → 마지막 화면 ─────────────
export type Screen = { n: number; title: string; note: string; ev: string; seq: number | null; url: string; file: string; tone: Tone; reason: string | null };

export function buildScreens(reasons: Reason[], events: EvidenceEvent[]): Screen[] {
  const bySeq = new Map(events.map((e) => [e.seq, e]));
  const out: Screen[] = [];
  const add = (file: string | null, seq: number | null, title: string, note: string, tone: Tone, reason: string | null) => {
    if (!file || out.length >= 4 || out.some((s) => s.file === file)) return;
    const obs = seq != null ? bySeq.get(seq) : undefined;
    out.push({ n: out.length + 1, title, note, ev: seq != null ? `EV-${seq}` : "-", seq, url: str(obs?.data.url), file, tone, reason });
  };
  for (const r of reasons) add(r.shot, r.shotSeq, r.title, r.text, r.tone, r.key);
  const observes = events.filter((e) => e.kind === "observe" && !isSub(e) && png(e));
  const first = observes[0];
  const lastObs = observes[observes.length - 1];
  add(png(first), first?.seq ?? null, "첫 화면", "조사를 시작한 화면", "idle", null);
  add(png(lastObs), lastObs?.seq ?? null, "마지막 화면", "탐색이 끝난 화면", "idle", null);
  return out;
}

// ── 경로 지도 ────────────────────────────────────────
export type PathNode = { url: string; label: string; newWindow: boolean; last: boolean; fold?: number };
export type Branch = { kind: "block" | "gate" | "cand" | "cand-record"; title: string; sub: string; tone: Tone; dashed: boolean };
export type PathMap = { nodes: PathNode[]; branches: Branch[][]; more: number };

export function buildPath(c: CaseOut, events: EvidenceEvent[]): PathMap {
  const main = events.filter((e) => !isSub(e));
  const urls: { url: string; kind: string }[] = [{ url: c.url, kind: "신고 URL" }];
  const navigation = main.find((e) => e.kind === "navigation");
  for (const r of strs(navigation?.data.redirects)) urls.push({ url: r, kind: "리다이렉트" });
  const finish = main.find((e) => e.kind === "finish");
  for (const u of strs(finish?.data.nav_chain)) urls.push({ url: u, kind: "이동" });
  if (c.final_url) urls.push({ url: c.final_url, kind: "최종" });
  const windows = new Set(main.filter((e) => e.kind === "new_window").map((e) => str(e.data.url)));
  // 같은 주소는 한 번만(처음 나온 자리)
  const seen = new Set<string>();
  const line = urls.filter((u) => u.url && !seen.has(u.url) && seen.add(u.url));
  const nodes: PathNode[] = line.map((u, i) => ({ url: u.url, label: i === 0 ? "신고 URL" : i === line.length - 1 && line.length > 1 ? "최종" : u.kind, newWindow: windows.has(u.url), last: i === line.length - 1 }));
  const branches: Branch[][] = nodes.map(() => []);
  const at = (url: string) => {
    const i = nodes.findIndex((n) => n.url === url);
    return i >= 0 ? i : nodes.length - 1;
  };
  // 그 시점의 현재 주소: 바로 앞 관찰의 주소
  const current = (seq: number) => str(lastBefore(main, seq, (e) => e.kind === "observe")?.data.url) || c.url;
  for (const e of main) {
    if (e.kind === "blocked_request" && e.data.navigation === true) {
      branches[at(current(e.seq))].push({ kind: "block", title: `이동 차단 · EV-${e.seq}`, sub: clip(hostOrFile(str(e.data.url)), 24), tone: "threat", dashed: true });
    } else if (e.kind === "gate" && e.data.allowed === false) {
      const obs = lastBefore(main, e.seq, (x) => x.kind === "observe");
      branches[at(current(e.seq))].push({ kind: "gate", title: `안전 게이트 · EV-${e.seq}`, sub: `“${clip(candidateText(obs, str(e.data.element)), 16)}” 차단`, tone: "threat", dashed: true });
    }
  }
  // 연관 후보는 마지막 주소에 붙인다(후보는 조사가 끝난 뒤 고른다). 3개만 그리고 나머지는 +n개
  const cands = (c.candidates ?? []).map((x) => (typeof x === "string" ? ({ url: x, host: x } as Candidate) : x));
  const lastIdx = nodes.length - 1;
  // 평판 위험 후보를 앞에 둔다(3개만 그릴 때 빠지지 않게)
  const ordered = [...cands.filter((x) => x.reputation_match), ...cands.filter((x) => !x.reputation_match)];
  for (const x of ordered.slice(0, 3)) {
    const where = x.source === "via" ? "경유" : "링크";
    // 평판은 AI 유형과 따로 표시한다: 위험 일치는 AI 가 정상으로 봐도 빨강, 조회 못 한 주소가 있으면 '평판 미확인'
    const repNote = (x.reputation_match ? " · 평판 위험" : x.reputation_unchecked ? " · 평판 미확인" : "") + (x.blocked ? " · 이미 차단됨" : "");
    if (x.sub) {
      const th = x.threat ?? "";
      const tone: Tone = x.reputation_match ? "threat" : !th || th === "benign" ? (x.hold ? "review" : "idle") : x.hold ? "review" : "threat";
      const verdict = th ? `${THREAT_LABEL[th] ?? th}${x.hold ? "(보류)" : ""}` : "판단 없음";
      branches[lastIdx].push({ kind: "cand", title: `${where} 후보 · ${verdict}${repNote}`, sub: clip(str(x.host ?? x.url), 24), tone, dashed: false });
    } else {
      branches[lastIdx].push({ kind: "cand-record", title: `${where} 후보 · 기록만${repNote}`, sub: clip(str(x.host ?? x.url), 24), tone: x.reputation_match ? "threat" : "idle", dashed: true });
    }
  }
  return fold({ nodes, branches, more: Math.max(0, cands.length - 3) });
}

// 본 줄이 5개를 넘으면 가운데를 "… n곳" 하나로 접는다(가지는 접힌 노드에 모은다)
function fold(m: PathMap): PathMap {
  if (m.nodes.length <= 5) return m;
  const keepHead = 2;
  const keepTail = 2;
  const mid = m.nodes.slice(keepHead, m.nodes.length - keepTail);
  const midBranches = m.branches.slice(keepHead, m.nodes.length - keepTail).flat();
  return {
    nodes: [...m.nodes.slice(0, keepHead), { url: "", label: "", newWindow: false, last: false, fold: mid.length }, ...m.nodes.slice(-keepTail)],
    branches: [...m.branches.slice(0, keepHead), midBranches, ...m.branches.slice(-keepTail)],
    more: m.more,
  };
}

// ── 화면 위 표시: 관찰 기록의 boxes(에이전트가 캡처 직전에 잰 요소 상자, 서명 기록 안) ─────────────
// 금지 요소(빨간 점선) · Jev 가 고른 버튼(파랑) · 안전 게이트가 막은 버튼(빨간 실선). 좌표는 캡처 이미지 픽셀.
export type MarkKind = "forbidden" | "picked" | "blocked";
export type Mark = { kind: MarkKind; x: number; y: number; w: number; h: number; label: string };
export type Overlay = { w: number; h: number; marks: Mark[] };
const MAX_MARKS = 60;
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);
// 기록 값(믿지 않음): 정수 4개이고 캡처 크기 안의 상자만
function box(v: unknown, w: number, h: number): [number, number, number, number] | null {
  if (!Array.isArray(v) || v.length !== 4 || !v.every(isInt)) return null;
  const [x, y, bw, bh] = v as number[];
  return x >= 0 && y >= 0 && bw > 0 && bh > 0 && x + bw <= w && y + bh <= h ? [x, y, bw, bh] : null;
}

export function buildOverlay(events: EvidenceEvent[], seq: number | null): Overlay | null {
  if (seq == null) return null;
  const obs = events.find((e) => e.seq === seq && e.kind === "observe");
  const raw = obs?.data.boxes;
  if (!obs || !raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const b = raw as Record<string, unknown>;
  const size = b.size;
  if (!Array.isArray(size) || size.length !== 2 || !size.every(isInt)) return null;
  const [w, h] = size as number[];
  if (w <= 0 || h <= 0 || w > 10000 || h > 20000) return null;
  const marks: Mark[] = [];
  // 금지 요소: forbidden 글자 목록과 같은 순서
  const names = strs(obs.data.forbidden);
  const fb = Array.isArray(b.forbidden) ? b.forbidden.slice(0, 50) : [];
  fb.forEach((v, i) => {
    const r = box(v, w, h);
    // 이름 형식 reason:type:label — 근거 카드처럼 label 만(없으면 전체)
    const name = names[i] ?? "";
    const label = name.split(":").slice(2).join(":") || name;
    if (r) marks.push({ kind: "forbidden", x: r[0], y: r[1], w: r[2], h: r[3], label: `금지 요소 · ${clip(label, 40)}` });
  });
  // 이 화면에서 Jev 가 고른 버튼과, 그 클릭을 안전 게이트가 막았는지
  const cand = b.cand && typeof b.cand === "object" && !Array.isArray(b.cand) ? (b.cand as Record<string, unknown>) : {};
  const dec = events.find((e) => e.kind === "decision" && e.data.observe_seq === seq);
  const choice = dec ? str(dec.data.choice) : "";
  if (dec && choice.startsWith("click_")) {
    const id = choice.slice(6);
    // 요소 ID 는 에이전트가 붙인 e숫자 형식만(상속 키·임의 키를 찾지 않게)
    const r = /^e\d{1,6}$/.test(id) && Object.prototype.hasOwnProperty.call(cand, id) ? box(cand[id], w, h) : null;
    if (r) {
      // 요소 ID 는 관찰마다 다시 쓰이므로 같은 조사(sub)·같은 단계(step)의 게이트만 본다
      const gate = events.find((e) => e.kind === "gate" && e.seq > dec.seq && e.data.sub === obs.data.sub && e.data.step === dec.data.step && str(e.data.element) === id);
      const blocked = gate?.data.allowed === false;
      const label = `${blocked ? "안전 게이트가 막은 클릭" : "Jev 가 고른 버튼"} · “${clip(candidateText(obs, id), 40)}”`;
      marks.push({ kind: blocked ? "blocked" : "picked", x: r[0], y: r[1], w: r[2], h: r[3], label });
    }
  }
  return marks.length ? { w, h, marks: marks.slice(0, MAX_MARKS) } : null;
}

// ── 클릭 표시: 게이트를 통과한 클릭의 창 기준 상자(에이전트가 누르기 직전에 잼, 화면 1280×800 픽셀)와 시각 ─────────────
// 실시간 화면과 녹화 재생 위에 커서·클릭 물결로 그린다. 녹화 파일은 바꾸지 않는다.
export const SCREEN_W = 1280;
export const SCREEN_H = 800;
export type ClickPoint = { x: number; y: number; w: number; h: number };
// 기록 값(믿지 않음): 정수 4개이고 화면 안의 상자만
export function clickPoint(v: unknown): ClickPoint | null {
  const r = box(v, SCREEN_W, SCREEN_H);
  return r ? { x: r[0], y: r[1], w: r[2], h: r[3] } : null;
}
// JPEG 머리에서 [폭, 높이]. JPEG 가 아니거나 앞부분에서 찾지 못하면 null(실시간 프레임을 디코드하기 전에 크기를 본다)
export function jpegSize(b: Uint8Array): [number, number] | null {
  if (b.length < 4 || b[0] !== 0xff || b[1] !== 0xd8) return null;
  let i = 2;
  while (i + 8 < b.length) {
    if (b[i] !== 0xff) return null;
    const m = b[i + 1];
    if (m === 0xff) {
      i += 1; // 채움 바이트
      continue;
    }
    if (m === 0x01 || (m >= 0xd0 && m <= 0xd8)) {
      i += 2; // 길이 없는 표식
      continue;
    }
    const len = (b[i + 2] << 8) | b[i + 3];
    if (len < 2) return null;
    // SOF(프레임 시작): 정밀도 1바이트 뒤 높이·폭
    if ((m >= 0xc0 && m <= 0xc3) || (m >= 0xc5 && m <= 0xc7) || (m >= 0xc9 && m <= 0xcb) || (m >= 0xcd && m <= 0xcf)) {
      return [(b[i + 7] << 8) | b[i + 8], (b[i + 5] << 8) | b[i + 6]];
    }
    i += 2 + len;
  }
  return null;
}

// 실시간 화면 통로로 온 클릭 표시 {"click":[x,y,폭,높이]}(에이전트가 보낸 값, 믿지 않음)
export function liveClick(text: string): ClickPoint | null {
  try {
    const v: unknown = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? clickPoint((v as { click?: unknown }).click) : null;
  } catch {
    return null;
  }
}
export type RecClick = ClickPoint & { t: number };
// 녹화 위 클릭: 게이트 기록의 클릭 시각(at) - 녹화 0초 시각(t0) = 영상 시간(초). 둘 다 에이전트 쪽 같은 시계(epoch 초)
export function recordingClicks(events: EvidenceEvent[], rec: EvidenceEvent | undefined): RecClick[] {
  const t0 = rec?.data.t0;
  if (!rec || typeof t0 !== "number" || !Number.isFinite(t0)) return [];
  const out: RecClick[] = [];
  for (const e of events) {
    // 같은 조사(하위 조사 번호)의 클릭만: 하위 조사는 녹화가 따로 있다
    if (e.kind !== "gate" || e.data.allowed !== true || e.data.sub !== rec.data.sub) continue;
    const p = clickPoint(e.data.point);
    const at = e.data.at;
    if (!p || typeof at !== "number" || !Number.isFinite(at)) continue;
    const t = at - t0;
    if (t >= 0 && t < 3600) out.push({ ...p, t });
    if (out.length >= 200) break;
  }
  return out.sort((a, b) => a.t - b.t);
}

// 조사 녹화 목록: 원래 주소(sub 없음)와 연관 후보 하위 조사(sub 1~)마다 하나씩. 실시간 화면은 하위 조사까지 이어지므로
// 녹화도 모두 고를 수 있게 한다(예전엔 첫 녹화만 보여 후보 조사 부분이 콘솔에서 빠졌다). 주소는 같은 조사의 시작 기록에서
export type RecItem = { ev: EvidenceEvent; file: string; sub: number; host: string; seconds: number | null };
export function recordings(events: EvidenceEvent[]): RecItem[] {
  const out: RecItem[] = [];
  const seen = new Set<number>();
  for (const e of events) {
    if (e.kind !== "recording") continue;
    const sub = isSub(e) ? (e.data.sub as number) : 0;
    const file = e.files.find((f) => f.endsWith(".webm"));
    if (!file || !Number.isInteger(sub) || sub < 0 || sub > 99 || seen.has(sub)) continue;
    seen.add(sub);
    const start = events.find((x) => x.kind === "start" && (sub ? x.data.sub === sub : !isSub(x)));
    const d = e.data.duration_s;
    out.push({
      ev: e, file, sub, host: hostOrFile(str(start?.data.url, 300)),
      seconds: typeof d === "number" && Number.isFinite(d) && d >= 0 ? d : null,
    });
    if (out.length >= 10) break;
  }
  return out.sort((a, b) => a.sub - b.sub);
}

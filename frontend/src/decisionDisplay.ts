// 조사 기록은 그대로 두고, 모델 선택값과 규칙 판단을 화면에서 구분한다.
import type { Candidate, CaseOut, EvidenceEvent } from "./api";
import { dict } from "./api";
import { overrideLabel, REASON_LABEL, THREAT_LABEL } from "./labels";

// model: Jev(AI) · rule: 코드 규칙(판단 엔진의 override 등) · fallback: Jev 가 응답하지 않을 때(장애·미설정) 판단 엔진이 쓰는
// 대체 판단기(화면 글자의 낱말 점수, provider "rules"·model "rules-1"). 대체 판단의 점수는 AI 확률도 코드 규칙도 아니다
export type ThreatPresentation = {
  source: "model" | "rule" | "fallback" | "unknown";
  sourceLabel: string;
  threat: string;
  typeLabel: string;
  probability: number | null;
  ruleLabel: string | null;
  ruleDescription: string | null;
  originalOpinion: string | null;
};

const RULE_LABEL = dict({
  shortener_warning: "단축 서비스 위험 경고",
  link_takedown: "링크 정지 안내 감지",
  official_redirect: "조사 전 공식 사이트 이동 감지",
  brand_lookalike: "브랜드 사칭 도메인 규칙 감지",
  brand_name_domain: "브랜드 사칭 도메인 규칙 감지",
  brand_typo_domain: "브랜드 오타 도메인 규칙 감지",
  brand_login_shared_hosting: "공용 호스팅 브랜드 규칙 감지",
  brand_clone_title: "브랜드 화면 복제 규칙 감지",
  official_betting_domain: "공식 사행사업자 도메인 확인",
  official_domain: "공식 사행사업자 도메인 확인",
});
// 서버 decision/schema.py 의 FALLBACK_PROVIDERS 와 같은 목록(시험이 맞춰 본다)
const FALLBACK_PROVIDERS = ["rules"];
const FALLBACK_LABEL = "대체 판단(Jev 장애)";

const object = (v: unknown): Record<string, unknown> | null =>
  v !== null && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null;
const str = (v: unknown, max = 200): string => typeof v === "string" ? v.slice(0, max) : "";
const probability = (v: unknown): number | null =>
  typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1 ? v : null;
const modelProvider = (v: unknown): boolean => ["jev_typesafe", "jev_openrouter"].includes(str(v, 64));

export function threatPresentation(input: unknown): ThreatPresentation {
  const t = object(input);
  const threat = str(t?.threat, 32);
  const provider = str(t?.provider, 64);
  const override = object(t?.override);
  const rule = !!override || Object.hasOwn(RULE_LABEL, provider);
  const fallback = !rule && (FALLBACK_PROVIDERS.includes(provider) || str(t?.model) === "rules-1");
  const source = rule ? "rule" : fallback ? "fallback" : modelProvider(provider) ? "model" : "unknown";
  const original = object(override?.original);
  const originalThreat = str(original?.threat, 32);
  const originalProbability = probability(original?.probability);
  let originalOpinion: string | null = null;
  if (original && Object.hasOwn(THREAT_LABEL, originalThreat)) {
    if (modelProvider(original.provider) && originalProbability !== null)
      originalOpinion = `모델 원래 의견: ${THREAT_LABEL[originalThreat]} ${originalProbability.toFixed(2)}`;
    else if (FALLBACK_PROVIDERS.includes(str(original.provider)))
      originalOpinion = `규칙 적용 전 의견: ${THREAT_LABEL[originalThreat]} · 대체 판단`;
  }
  const ruleKey = str(override?.reason, 64) || provider;
  // 원시 행동 기록도 입력되므로 표시용 규칙 객체만 만들고, 누락된 원모델 값을 만들어 내지 않는다.
  const safeOverride = override ? {
    reason: str(override.reason, 64),
    brand: str(override.brand),
    destination: str(override.destination, 300),
    operators: Array.isArray(override.operators) ? override.operators.filter((v): v is string => typeof v === "string").slice(0, 20) : [],
    original: { threat: originalThreat, probability: originalProbability ?? NaN, provider: str(original?.provider, 64) },
  } : undefined;
  return {
    source,
    sourceLabel: source === "rule" ? "규칙 판단" : source === "fallback" ? "대체 판단" : source === "model" ? "AI 판단" : "판단 기록",
    threat,
    typeLabel: THREAT_LABEL[threat] ?? (threat || "판단 없음"),
    probability: source === "model" && threat && threat !== "unknown" ? probability(t?.probability) : null,
    ruleLabel: rule ? RULE_LABEL[ruleKey] ?? "규칙 기반 판단" : fallback ? FALLBACK_LABEL : null,
    ruleDescription: rule ? (safeOverride ? overrideLabel(safeOverride) : "관찰한 화면과 주소의 규칙에 따른 분류입니다")
      : fallback ? "Jev 판단 서비스가 응답하지 않아(장애·미설정) 화면 글자의 낱말로 정한 대체 판단입니다 · AI 확률이 아닙니다" : null,
    originalOpinion,
  };
}

// Safe Browsing 위험 일치가 신고·경유 주소에 있는지, 연관 후보에만 있는지. 서버(runner 의 only_cands)와 같은 기준:
// 일치한 주소가 모두 연관 후보 주소면 후보만, 하나라도 후보가 아니면(또는 일치 주소가 비었으면) 이 사건의 주소다.
export function reputationHit(c: CaseOut | null): "own" | "candidate" | null {
  const sb = c?.safebrowsing;
  if (!c || sb?.status !== "match") return null;
  const cands = new Set((c.candidates ?? []).map((x) => (typeof x === "string" ? x : x.url)));
  return sb.matches.length === 0 || sb.matches.some((m) => !cands.has(m.url)) ? "own" : "candidate";
}

// 조사는 정상으로 봤는데 이 사건의 주소가 Safe Browsing 위험 일치. AI 가 보류한 사건은 서버 사유가 reputation_match 로
// 바뀌지 않아(runner 는 COMPLETED 일 때만 바꾼다) 사유가 아니라 평판 결과로 본다
export function reputationConflict(c: CaseOut | null): boolean {
  return c?.threat?.threat === "benign" && reputationHit(c) === "own";
}

// 원래 조사의 종료 사유(연관 사이트를 조사하는 중이면 원래 결과의 사유)
const mainReason = (c: CaseOut | null): string | null =>
  c?.status === "RUNNING" && c.phase === "related" && c.main_status ? c.main_reason ?? c.finish_reason : c?.finish_reason ?? null;

export function casePresentation(c: CaseOut | null): ThreatPresentation {
  const p = threatPresentation(c?.threat);
  // 평판과 모델 의견이 충돌한 사건은 큰 숫자보다 검토 사유를 먼저 보여 준다.
  return mainReason(c) === "reputation_match" || reputationConflict(c) ? { ...p, probability: null } : p;
}

// 판단의 hold 는 담당자의 '보류' 판정과 다르다: AI(모델)는 확신이 낮아서, 코드 규칙·판단 불가는 담당자가 보라고 넘긴 것이다
export function holdLabel(p: ThreatPresentation, hold: unknown): string | null {
  if (hold !== true) return null;
  return p.source === "model" && p.threat !== "unknown" ? "확신 낮음" : "검토 필요";
}

// 정상 판단을 '안전'(초록)으로 보이는 AI 확신의 하한. 평가 기록(모델 판단, 단계형 시험 페이지 제외)에서 보류 아닌 정상
// 0.9 이상은 1,953/1,960 이 실제 정상이었지만 0.6~0.7 은 14/62, 0.7~0.8 은 62/88 뿐이었다(2026-10-28). 판단·상태는 그대로다
export const BENIGN_SURE = 0.9;
export function lowBenign(p: ThreatPresentation, hold: unknown): boolean {
  return p.source === "model" && p.threat === "benign" && hold !== true && p.probability !== null && p.probability < BENIGN_SURE;
}
// 사건 단위: 담당자가 확정했거나 이미 검토 사유가 있으면(그쪽이 말한다) 따로 알리지 않는다
export function lowConfidenceBenign(c: CaseOut | null): boolean {
  if (!c || reviewParts(c) !== null || c.verdict?.decision === "threat" || c.verdict?.decision === "benign") return false;
  return lowBenign(casePresentation(c), c.threat?.hold);
}

// 검토 요청은 없지만 화면을 확인하라고 알릴 사건(초록으로 보이지 않게): Jev 대신 대체 판단기가 판단했거나, AI 정상의 확신이 낮다.
// 담당자가 확정했거나 이미 검토 사유가 있으면(그쪽이 말한다) null
export function attentionNote(c: CaseOut | null): string | null {
  if (!c || !c.threat || reviewParts(c) !== null || c.verdict?.decision === "threat" || c.verdict?.decision === "benign") return null;
  if (casePresentation(c).source === "fallback") return "대체 판단(Jev 장애) · 화면 확인 권장";
  return lowConfidenceBenign(c) ? "AI 확신 낮음(정상 0.9 미만) · 화면 확인 권장" : null;
}

// 행동 선택(decision 기록)을 낸 쪽. Jev 만 확률을 보인다: 대체 판단기의 점수와, 남은 행동이 없어 코드가 끝낸 것(exhausted, 1.0)은
// 모델 확률이 아니다. 조사 컨테이너가 쓴 기록이라 글자로만 본다
export function decisionActor(d: unknown): { label: string; probability: number | null } {
  const provider = str(object(d)?.provider, 64);
  if (modelProvider(provider)) return { label: "Jev 선택", probability: probability(object(d)?.probability) };
  if (provider === "exhausted") return { label: "남은 행동 없음", probability: null };
  if (FALLBACK_PROVIDERS.includes(provider)) return { label: "대체 판단 선택(Jev 장애)", probability: null };
  return { label: "행동 선택", probability: null };
}

// 판단하지 못한 까닭이 될 수 있는 탐색 종료(검토 사유가 아니라 사정 설명). '에이전트가 조사 완료 판단'은 설명이 안 돼 뺀다
const EXPLORE_END = new Set(["low_confidence_action", "loop_detected", "dead_end", "step_budget", "time_budget", "goto_failed"]);
export function exploreNote(c: CaseOut | null): string | null {
  const reason = mainReason(c);
  return reason && EXPLORE_END.has(reason) ? REASON_LABEL[reason] ?? null : null;
}

const SB_REASONS = new Set(["reputation_match", "candidate_reputation_match", "unreachable_reputation_match"]);

// 검토가 필요한 까닭(앞에서부터 중요한 순서). 검토할 것이 없으면 null, 따로 댈 까닭이 없으면 빈 목록.
// 판단 불가는 유형 문구('판단 불가'·'판단할 수 없습니다')가 이미 말하고, 탐색 종료 까닭은 검토의 원인이 아니라서 여기 넣지 않는다
export function reviewParts(c: CaseOut | null): string[] | null {
  if (!c) return null;
  if (c.verdict?.decision === "threat" || c.verdict?.decision === "benign") return null;
  const related = c.status === "RUNNING" && c.phase === "related" && !!c.main_status;
  const status = related ? c.main_status : c.status;
  if (status !== "REVIEW_REQUIRED" && !c.threat?.hold) return null;
  const reason = mainReason(c);
  const p = threatPresentation(c.threat);
  const conflict = `${p.source === "rule" ? "규칙 판단" : p.source === "fallback" ? "대체 판단" : "AI 의견"}과 Safe Browsing 위험 평판 불일치`;
  const reasons = dict({
    reputation_match: conflict,
    candidate_reputation_match: "연관 후보의 Safe Browsing 위험 일치",
    unreachable_reputation_match: "접속 불가 · Safe Browsing 위험 일치",
    unreachable_network_filtered: "회선 차단 추정",
    threat_decision_unavailable: "위협 판단 서비스 실패",
    decision_unavailable: "행동 판단 서비스 실패",
    page_unresponsive: "페이지 무응답",
  });
  // 서버 사유에 평판이 없어도(보류 사건) 평판 일치는 따로 앞에 적는다
  const hit = reason && SB_REASONS.has(reason) ? null : reputationHit(c);
  const sb = hit === "own" ? (c.threat?.threat === "benign" ? conflict : "Safe Browsing 위험 일치")
    : hit === "candidate" ? "연관 후보의 Safe Browsing 위험 일치" : null;
  const base = (reason && reasons[reason])
    || ((p.source === "rule" || p.source === "fallback") && p.ruleLabel)
    || (c.threat?.hold && p.source === "model" && p.threat !== "unknown" && "AI 판단 불확실")
    || null;
  return [sb, base].filter((x): x is string => !!x);
}

export function reviewReason(c: CaseOut | null): string | null {
  const parts = reviewParts(c);
  return parts ? [...parts, "담당자 검토 필요"].join(" · ") : null;
}

// 목록과 경로 지도의 짧은 판단 문구. 규칙 점수나 출처가 없는 값은 붙이지 않는다.
// explain: 판단 불가면 판단하지 못한 사정(탐색 종료 까닭)을 괄호로 붙인다(목록 줄)
export function caseDecisionText(c: CaseOut, explain = false): string {
  const p = casePresentation(c);
  if (!p.threat) return "판단 없음";
  const note = explain && p.threat === "unknown" ? exploreNote(c) : null;
  if (note) return `${p.typeLabel}(${note})`;
  const suspect = !["benign", "unknown"].includes(p.threat);
  const label = `${p.typeLabel}${suspect && (c.threat?.hold || p.source === "rule" || p.source === "fallback") ? " 의심" : ""}`;
  if (p.source === "rule") return `${label} · 규칙 판단`;
  if (p.source === "fallback") return `${label} · 대체 판단`;
  if (p.probability !== null) return `${label} · ${p.probability.toFixed(2)}`;
  return label;
}

export function candidatePresentation(candidate: Candidate, events: EvidenceEvent[]): ThreatPresentation {
  const last = candidate.sub ? [...events].reverse().find((e) => e.kind === "threat" && e.data.sub === candidate.sub) : undefined;
  const d = last?.data;
  // 하위 조사 기록이 후보의 현재 의견과 일치할 때만 모델/규칙 출처를 복원한다.
  if (d && d.threat === candidate.threat && probability(d.probability) !== null
      && probability(d.probability) === probability(candidate.probability)) return threatPresentation(d);
  return threatPresentation({ threat: candidate.threat });
}

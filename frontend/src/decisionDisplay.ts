// 조사 기록은 그대로 두고, 모델 선택값과 규칙 판단을 화면에서 구분한다.
import type { Candidate, CaseOut, EvidenceEvent } from "./api";
import { dict } from "./api";
import { overrideLabel, REASON_LABEL, THREAT_LABEL } from "./labels";

export type ThreatPresentation = {
  source: "model" | "rule" | "unknown";
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
  rules: "규칙 기반 판단",
});

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
  const rule = !!override || Object.hasOwn(RULE_LABEL, provider) || str(t?.model) === "rules-1";
  const source = rule ? "rule" : modelProvider(provider) ? "model" : "unknown";
  const original = object(override?.original);
  const originalThreat = str(original?.threat, 32);
  const originalProbability = probability(original?.probability);
  let originalOpinion: string | null = null;
  if (original && Object.hasOwn(THREAT_LABEL, originalThreat)) {
    if (modelProvider(original.provider) && originalProbability !== null)
      originalOpinion = `모델 원래 의견: ${THREAT_LABEL[originalThreat]} ${originalProbability.toFixed(2)}`;
    else if (str(original.provider) === "rules")
      originalOpinion = `규칙 적용 전 의견: ${THREAT_LABEL[originalThreat]} · 규칙 판단`;
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
    sourceLabel: source === "rule" ? "규칙 판단" : source === "model" ? "AI 판단" : "판단 기록",
    threat,
    typeLabel: THREAT_LABEL[threat] ?? (threat || "판단 없음"),
    probability: source === "model" && threat && threat !== "unknown" ? probability(t?.probability) : null,
    ruleLabel: rule ? RULE_LABEL[ruleKey] ?? "규칙 기반 판단" : null,
    ruleDescription: rule ? (safeOverride ? overrideLabel(safeOverride) : "관찰한 화면과 주소의 규칙에 따른 분류입니다") : null,
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

export function casePresentation(c: CaseOut | null): ThreatPresentation {
  const p = threatPresentation(c?.threat);
  const reason = c?.status === "RUNNING" && c.phase === "related" && c.main_status
    ? c.main_reason ?? c.finish_reason : c?.finish_reason;
  // 평판과 모델 의견이 충돌한 사건은 큰 숫자보다 검토 사유를 먼저 보여 준다.
  return reason === "reputation_match" || reputationConflict(c) ? { ...p, probability: null } : p;
}

const SB_REASONS = new Set(["reputation_match", "candidate_reputation_match", "unreachable_reputation_match"]);

// 검토가 필요한 까닭(앞에서부터 중요한 순서). 검토할 것이 없으면 null
export function reviewParts(c: CaseOut | null): string[] | null {
  if (!c) return null;
  if (c.verdict?.decision === "threat" || c.verdict?.decision === "benign") return null;
  const related = c.status === "RUNNING" && c.phase === "related" && !!c.main_status;
  const status = related ? c.main_status : c.status;
  if (status !== "REVIEW_REQUIRED" && !c.threat?.hold) return null;
  const reason = related ? c.main_reason ?? c.finish_reason : c.finish_reason;
  const p = threatPresentation(c.threat);
  const conflict = `${p.source === "rule" ? "규칙 판단" : "AI 의견"}과 Safe Browsing 위험 평판 불일치`;
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
    || (p.source === "rule" && p.ruleLabel)
    || (p.threat === "unknown" && "유형을 판단하지 못했습니다")
    || (c.threat?.hold && p.source === "model" && "AI 판단 불확실")
    || null;
  const parts = [sb, base].filter((x): x is string => !!x);
  return parts.length ? parts : [(reason && REASON_LABEL[reason]) || "조사 결과 확인"];
}

export function reviewReason(c: CaseOut | null): string | null {
  const parts = reviewParts(c);
  return parts ? `${parts.join(" · ")} · 담당자 검토 필요` : null;
}

// 목록과 경로 지도의 짧은 판단 문구. 규칙 점수나 출처가 없는 값은 붙이지 않는다.
export function caseDecisionText(c: CaseOut): string {
  const p = casePresentation(c);
  if (!p.threat) return "판단 없음";
  const suspect = !["benign", "unknown"].includes(p.threat);
  const label = `${p.typeLabel}${suspect && (c.threat?.hold || p.source === "rule") ? " 의심" : ""}`;
  if (p.source === "rule") return `${label} · 규칙 판단`;
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

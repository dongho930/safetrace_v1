// 화면에 쓰는 고정 문구(App 과 근거 계산 evidence.ts 가 함께 쓴다)
import { dict, strs, text, type Threat } from "./api";

export const THREAT_LABEL: Record<string, string> = dict({
  phishing: "피싱",
  scam: "사기",
  illegal_gambling: "불법 도박",
  malware: "악성 앱",
  benign: "정상",
  unknown: "판단 불가",
});
// 코드 규칙이 모델 판단을 바꾼 이유
export function overrideLabel(o: Threat["override"]): string {
  // 행동 기록의 threat 기록(믿지 않는 값)에서도 부르므로 글자로만 읽는다
  if (!o || typeof o !== "object") return "";
  const brand = text(o.brand);
  const dest = text(o.destination);
  if (o.reason === "shortener_warning") return "단축 URL 서비스의 위험 경고 → 담당자 검토";
  if (o.reason === "link_takedown") return "단축·호스팅 서비스가 불법·약관 위반으로 링크를 정지 → 담당자 검토";
  if (o.reason === "official_redirect") return `조사 전에 공식 사이트(${brand} · ${dest})로 바로 넘김(봇 회피 흔적) → 담당자 검토`;
  if (o.reason === "brand_lookalike")
    return dest
      ? `열리지 않은 목적지가 브랜드 사칭 도메인(${brand} · ${dest}) → 담당자 검토`
      : `브랜드 사칭 도메인(${brand}), 화면 내용 없음 → 담당자 검토`;
  if (o.reason === "official_betting_domain") {
    const ops = strs(o.operators);
    return `공식 사행사업자 도메인${ops.length ? ` · ${ops.join(", ")}` : ""}`;
  }
  return `코드 규칙(${text(o.reason)})`; // 모르는 규칙: 다른 규칙 이름으로 보이지 않게 그대로 적는다
}
export const REASON_LABEL: Record<string, string> = dict({
  reputation_match: "Safe Browsing 위험 일치(AI 는 정상으로 봄)",
  candidate_reputation_match: "연관 후보가 Safe Browsing 위험 일치(AI 는 정상으로 봄)",
  unreachable_reputation_match: "접속 불가 · Safe Browsing 위험 일치",
  unreachable_network_filtered: "접속 불가 · 회선이 도메인 이름을 보고 차단(이미 차단 목록에 오른 사이트)",
  goto_failed: "최초 접속 실패",
  low_confidence_action: "다음 행동 확신 부족으로 탐색 종료",
  loop_detected: "같은 화면 반복으로 탐색 종료",
  dead_end: "더 갈 수 없는 화면(오류·차단)에서 탐색 종료",
  agent_finished: "에이전트가 조사 완료 판단",
  step_budget: "최대 단계 도달",
  time_budget: "최대 시간 도달",
  page_unresponsive: "페이지가 응답하지 않아 시간 예산에서 강제 종료(무한 스크립트 등)",
  threat_decision_unavailable: "위협 판단 불가(판단 서비스 장애)",
  "ssrf:dns_failure": "도메인 없음(DNS)",
  "ssrf:non_public_ip": "내부 주소라 접속하지 않음(정책)",
  "ssrf:port_not_allowed": "허용하지 않는 포트(정책)",
});
export const NET_CATEGORY_LABEL: Record<string, string> = dict({
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
});
export const ACTION_LABEL: Record<string, string> = dict({ scroll: "스크롤", back: "뒤로 가기", close_popup: "팝업 닫기", finish: "조사 끝내기" });

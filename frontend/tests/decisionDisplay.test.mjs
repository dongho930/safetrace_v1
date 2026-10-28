import assert from "node:assert/strict";
import { after, test } from "node:test";
import { createRequire } from "node:module";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

// Compile the production helper with the project's TypeScript dependency. This
// avoids adding a second TS runtime or changing the application build settings.
const frontend = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tempRoot = realpathSync(tmpdir());
const scratch = mkdtempSync(join(tempRoot, "safetrace-display-"));
function cleanup() {
  const target = resolve(scratch);
  const inside = relative(tempRoot, target);
  assert.ok(inside && !inside.startsWith(`..${sep}`) && !isAbsolute(inside));
  assert.ok(basename(target).startsWith("safetrace-display-"));
  rmSync(target, { recursive: true, force: true });
}
after(cleanup);

let presentation;
let cleanCase;
let evidence;
try {
  const program = ts.createProgram([join(frontend, "src", "decisionDisplay.ts"), join(frontend, "src", "evidence.ts")], {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.CommonJS,
    moduleResolution: ts.ModuleResolutionKind.Node10,
    lib: ["lib.es2022.d.ts", "lib.dom.d.ts", "lib.dom.iterable.d.ts"],
    rootDir: join(frontend, "src"),
    outDir: scratch,
    strict: true,
    skipLibCheck: true,
    types: [],
    noEmitOnError: true,
  });
  const emission = program.emit();
  const diagnostics = [...ts.getPreEmitDiagnostics(program), ...emission.diagnostics];
  assert.equal(
    diagnostics.length,
    0,
    ts.formatDiagnosticsWithColorAndContext(diagnostics, {
      getCanonicalFileName: (name) => name,
      getCurrentDirectory: () => frontend,
      getNewLine: () => "\n",
    }),
  );
  writeFileSync(join(scratch, "package.json"), '{"type":"commonjs"}\n');
  const requireCompiled = createRequire(join(scratch, "package.json"));
  presentation = requireCompiled(join(scratch, "decisionDisplay.js"));
  cleanCase = requireCompiled(join(scratch, "api.js")).cleanCase;
  evidence = requireCompiled(join(scratch, "evidence.js"));
} catch (error) {
  cleanup();
  throw error;
}
const { threatPresentation, casePresentation, reviewReason, reviewParts, caseDecisionText, candidatePresentation, reputationHit, reputationConflict,
  holdLabel, lowBenign, lowConfidenceBenign, exploreNote, BENIGN_SURE } = presentation;

function modelThreat(patch = {}) {
  return {
    threat: "phishing",
    probability: 0.8,
    probabilities: { phishing: 0.8, benign: 0.2 },
    hold: false,
    provider: "jev_typesafe",
    model: "jev-1.13.0",
    evidence_seqs: [4],
    ...patch,
  };
}
function ruleThreat(reason = "brand_name_domain", patch = {}) {
  return modelThreat({
    probability: 1,
    probabilities: { phishing: 1 },
    hold: true,
    provider: reason,
    override: {
      reason,
      brand: "roblox",
      destination: "roblox.example",
      original: { threat: "benign", probability: 0.55, provider: "jev_typesafe" },
    },
    ...patch,
  });
}
function caseOut(patch = {}) {
  return {
    id: "case-1",
    url: "https://reported.example/",
    source: "report",
    status: "COMPLETED",
    finish_reason: "agent_finished",
    final_url: "https://reported.example/",
    threat: modelThreat(),
    safebrowsing: { status: "no_match", matches: [] },
    candidates: [],
    head_seq: 4,
    created_at: "2026-10-28T00:00:00Z",
    verdict: null,
    phase: null,
    main_status: null,
    parent_id: null,
    parent_url: null,
    auto: null,
    children: null,
    auto_skipped: null,
    ...patch,
  };
}
function event(seq, data) {
  return { type: "evidence", seq, kind: "threat", data, files: [], hash: "hash" };
}
function candidate(patch = {}) {
  return { url: "https://candidate.example/", sub: 2, threat: "phishing", probability: 1, hold: true, ...patch };
}

test("Roblox rule score is hidden while the original model opinion stays distinguishable", () => {
  const p = threatPresentation(ruleThreat());
  assert.equal(p.source, "rule");
  assert.equal(p.probability, null);
  assert.match(p.sourceLabel, /규칙/);
  assert.match(p.ruleLabel, /브랜드|도메인/);
  assert.match(p.originalOpinion, /정상/);
  assert.match(p.originalOpinion, /0\.55/);
  assert.doesNotMatch(p.originalOpinion, /피싱 0\.55/);
  const reason = reviewReason(caseOut({ status: "REVIEW_REQUIRED", threat: ruleThreat() }));
  assert.match(reason, /브랜드|도메인|규칙/);
  assert.doesNotMatch(reason, /확신이 부족|AI 판단 불확실/);
});

const rules = [
  "shortener_warning",
  "link_takedown",
  "official_redirect",
  "brand_lookalike",
  "brand_name_domain",
  "brand_typo_domain",
  "brand_login_shared_hosting",
  "brand_clone_title",
];
for (const reason of rules) {
  test(`${reason} never exposes the rule's one-hot score as model probability`, () => {
    const p = threatPresentation(ruleThreat(reason));
    assert.equal(p.source, "rule");
    assert.equal(p.probability, null);
    assert.ok(p.ruleLabel);
  });
}

test("ordinary Jev probability remains available and is identified as a model opinion", () => {
  for (const provider of ["jev_typesafe", "jev_openrouter"]) {
    const p = threatPresentation(modelThreat({ provider }));
    assert.equal(p.source, "model");
    assert.equal(p.probability, 0.8);
    assert.match(p.sourceLabel, /AI|모델/);
    assert.equal(p.originalOpinion, null);
  }
});

test("an unknown decision provider is not silently presented as an AI probability", () => {
  const p = threatPresentation(modelThreat({ provider: "legacy_unknown_provider", model: "" }));
  assert.equal(p.source, "unknown");
  assert.equal(p.probability, null);
});

test("model uncertainty is the review reason only when that is the actual basis", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", threat: modelThreat({ probability: 0.36, hold: true }) });
  assert.equal(threatPresentation(c.threat).probability, 0.36);
  assert.match(reviewReason(c), /AI|모델/);
  assert.match(reviewReason(c), /불확실|확신/);
});

test("unknown with a one-hot distribution remains an inability to classify", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", threat: modelThreat({ threat: "unknown", probability: 1, hold: true }) });
  assert.equal(threatPresentation(c.threat).probability, null);
  assert.match(caseDecisionText(c), /^판단 불가/);
  assert.doesNotMatch(reviewReason(c), /AI 판단 불확실/);
  assert.doesNotMatch(caseDecisionText(c), /1\.00/);
});

test("Safe Browsing conflict does not turn a high-confidence benign model opinion into model uncertainty", () => {
  const c = caseOut({
    status: "REVIEW_REQUIRED",
    finish_reason: "reputation_match",
    threat: modelThreat({ threat: "benign", probability: 0.99 }),
    safebrowsing: { status: "match", matches: [{ url: "https://reported.example/", threat_type: "SOCIAL_ENGINEERING" }] },
  });
  const reason = reviewReason(c);
  assert.match(reason, /Safe Browsing|평판/);
  assert.doesNotMatch(reason, /확신이 부족|AI 판단 불확실/);
  assert.equal(threatPresentation(c.threat).probability, 0.99);
  assert.equal(casePresentation(c).probability, null);
  assert.doesNotMatch(caseDecisionText(c), /0\.99/);
});

test("a reputation match on a related candidate is named separately", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", finish_reason: "candidate_reputation_match" });
  assert.match(reviewReason(c), /연관|후보/);
  assert.match(reviewReason(c), /Safe Browsing|평판/);
});

test("page unresponsiveness remains visible even with a high benign model value", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", finish_reason: "page_unresponsive", threat: modelThreat({ threat: "benign", probability: 0.95 }) });
  assert.match(reviewReason(c), /응답|무응답/);
  assert.doesNotMatch(reviewReason(c), /확신이 부족|AI 판단 불확실/);
});

test("service failure and unavailable navigation carry their actual review reasons", () => {
  for (const finish_reason of ["threat_decision_unavailable", "decision_unavailable"]) {
    const c = caseOut({ status: "REVIEW_REQUIRED", finish_reason, threat: null });
    assert.match(reviewReason(c), /서비스|장애|실패|불가/);
  }
  const reputation = caseOut({ status: "REVIEW_REQUIRED", finish_reason: "unreachable_reputation_match", threat: null });
  assert.match(reviewReason(reputation), /접속/);
  assert.match(reviewReason(reputation), /Safe Browsing|평판/);
  const network = caseOut({ status: "REVIEW_REQUIRED", finish_reason: "unreachable_network_filtered", threat: null });
  assert.match(reviewReason(network), /회선|차단/);
  assert.match(reviewReason(network), /추정/);
});

test("a normal official-domain rule hides its score without forcing human review", () => {
  const t = ruleThreat("official_betting_domain", {
    threat: "benign",
    hold: false,
    provider: "official_domain",
    override: {
      reason: "official_betting_domain",
      operators: ["official.example"],
      original: { threat: "illegal_gambling", probability: 0.91, provider: "jev_typesafe" },
    },
  });
  assert.equal(threatPresentation(t).source, "rule");
  assert.equal(threatPresentation(t).probability, null);
  assert.equal(reviewReason(caseOut({ threat: t })), null);
  assert.doesNotMatch(caseDecisionText(caseOut({ threat: t })), /1\.00|담당자 검토/);
});

test("fallback rules and legacy rule providers are never labelled with model probability", () => {
  for (const t of [
    modelThreat({ provider: "rules", model: "rules-1" }),
    modelThreat({ provider: "", model: "rules-1" }),
    modelThreat({ provider: "brand_name_domain" }),
  ]) {
    const p = threatPresentation(t);
    assert.equal(p.source, "rule");
    assert.equal(p.probability, null);
  }
});

test("missing original model data does not manufacture an original 0.00 opinion", () => {
  const t = ruleThreat();
  t.override.original = { threat: "", probability: 0, provider: "" };
  assert.equal(threatPresentation(t).originalOpinion, null);
  assert.equal(threatPresentation({ ...t, override: { reason: "new_rule" } }).originalOpinion, null);
});

test("API cleanup keeps missing and invalid model values undisplayable instead of manufacturing zero", () => {
  for (const probability of [undefined, null, "0.80", NaN, Infinity, -Infinity, -0.1, 1.1, {}, []]) {
    const c = cleanCase(caseOut({ threat: modelThreat({ probability }) }));
    assert.ok(c?.threat);
    assert.ok(Number.isNaN(c.threat.probability));
    assert.equal(threatPresentation(c.threat).probability, null);
    assert.equal(casePresentation(c).probability, null);
    assert.doesNotMatch(caseDecisionText(c), /0\.00/);
  }
});

test("API cleanup cannot create an original model 0.00 opinion from an absent or invalid value", () => {
  for (const probability of [undefined, null, "0.55", NaN, Infinity, -0.1, 1.1]) {
    const t = ruleThreat();
    t.override.original.probability = probability;
    const c = cleanCase(caseOut({ threat: t }));
    assert.ok(c?.threat?.override);
    assert.ok(Number.isNaN(c.threat.override.original.probability));
    assert.equal(threatPresentation(c.threat).originalOpinion, null);
  }
});

test("API cleanup preserves a real zero model probability", () => {
  const c = cleanCase(caseOut({ threat: modelThreat({ probability: 0, hold: true }) }));
  assert.ok(c?.threat);
  assert.equal(c.threat.probability, 0);
  assert.equal(casePresentation(c).probability, 0);
  assert.match(caseDecisionText(c), /0\.00/);
  const t = ruleThreat();
  t.override.original.probability = 0;
  assert.match(threatPresentation(cleanCase(caseOut({ threat: t })).threat).originalOpinion, /0\.00/);
});

test("API cleanup discards invalid alternative probabilities without changing valid alternatives", () => {
  const c = cleanCase(caseOut({ threat: modelThreat({ probabilities: { phishing: 0.8, benign: 0.2, unknown: "0.1", scam: 1.1, malware: Infinity } }) }));
  assert.deepEqual(c.threat.probabilities, { phishing: 0.8, benign: 0.2 });
});

test("an original fallback rule opinion is labelled as a rule without its numeric score", () => {
  const t = ruleThreat();
  t.override.original = { threat: "benign", probability: 0.72, provider: "rules" };
  const original = threatPresentation(t).originalOpinion;
  assert.equal(original, "규칙 적용 전 의견: 정상 · 규칙 판단");
  assert.doesNotMatch(original, /모델|0\.72/);
});

test("an original opinion from an unknown provider is not presented as a model opinion", () => {
  const t = ruleThreat();
  t.override.original = { threat: "benign", probability: 0.55, provider: "legacy_unknown_provider" };
  assert.equal(threatPresentation(t).originalOpinion, null);
});

test("an original opinion with missing provider provenance is hidden", () => {
  const t = ruleThreat();
  t.override.original = { threat: "benign", probability: 0.55 };
  assert.equal(threatPresentation(t).originalOpinion, null);
});

test("malformed evidence is handled as data without invoking object string conversion", () => {
  const untrusted = { toString() { throw new Error("must not run page data"); } };
  for (const value of [null, [], "phishing", {}, { threat: untrusted }, { ...modelThreat(), override: untrusted }]) {
    assert.doesNotThrow(() => threatPresentation(value));
  }
  for (const probability of [NaN, Infinity, -Infinity, "1.00", -0.1, 1.1]) {
    assert.equal(threatPresentation(modelThreat({ probability })).probability, null);
  }
});

test("compact labels used by list and path keep rule and model values apart", () => {
  const rule = caseDecisionText(caseOut({ status: "REVIEW_REQUIRED", threat: ruleThreat() }));
  assert.match(rule, /피싱/);
  assert.match(rule, /규칙/);
  assert.doesNotMatch(rule, /1\.00|0\.55/);
  const model = caseDecisionText(caseOut());
  assert.match(model, /0\.80/);
  assert.doesNotMatch(model, /AI 판단값/);
});

test("an associated investigation uses its preserved main review status", () => {
  const c = caseOut({ status: "RUNNING", phase: "related", main_status: "REVIEW_REQUIRED", finish_reason: "reputation_match", threat: modelThreat({ threat: "benign", probability: 0.99 }) });
  assert.match(reviewReason(c), /Safe Browsing|평판/);
  const running = caseOut({ status: "RUNNING", phase: null, main_status: null });
  assert.equal(reviewReason(running), null);
});

test("main review reason takes precedence over the ongoing associated investigation reason", () => {
  const c = caseOut({
    status: "RUNNING",
    phase: "related",
    main_status: "REVIEW_REQUIRED",
    main_reason: "reputation_match",
    finish_reason: "page_unresponsive",
    threat: modelThreat({ threat: "benign", probability: 0.99 }),
  });
  assert.match(reviewReason(c), /Safe Browsing|평판/);
  assert.doesNotMatch(reviewReason(c), /응답|무응답/);
  assert.equal(casePresentation(c).probability, null);
  assert.doesNotMatch(caseDecisionText(c), /0\.99/);
});

test("a finished case does not adopt a stale associated-investigation reason", () => {
  const c = caseOut({ status: "COMPLETED", phase: null, main_status: "REVIEW_REQUIRED", main_reason: "reputation_match", threat: modelThreat({ threat: "benign", probability: 0.99 }) });
  assert.equal(casePresentation(c).probability, 0.99);
  assert.match(caseDecisionText(c), /0\.99/);
});

test("a final human verdict removes the outstanding review request while a hold retains it", () => {
  for (const decision of ["threat", "benign"]) {
    const c = cleanCase(caseOut({ status: "REVIEW_REQUIRED", threat: ruleThreat(), verdict: { rev: 1, decision } }));
    assert.equal(reviewReason(c), null);
  }
  const held = cleanCase(caseOut({ status: "REVIEW_REQUIRED", threat: ruleThreat(), verdict: { rev: 2, decision: "hold" } }));
  assert.match(reviewReason(held), /담당자 검토 필요/);
});

test("legacy benign records are not described as a low-confidence threat judgment", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", finish_reason: "low_confidence_action", threat: modelThreat({ threat: "benign", probability: 0.99, hold: false }) });
  const reason = reviewReason(c);
  assert.ok(reason);
  assert.doesNotMatch(reason, /AI 판단 불확실|위협.*확신이 부족/);
  // 탐색 종료 까닭을 검토 원인처럼 붙이지 않는다
  assert.equal(reason, "담당자 검토 필요");
});

test("candidate source comes from the matching final sub-investigation evidence", () => {
  const c = candidate();
  const events = [
    event(2, { ...modelThreat({ probability: 0.7 }), sub: 2 }),
    event(5, { ...ruleThreat(), sub: 2 }),
    event(6, { ...modelThreat({ probability: 0.9 }), sub: 3 }),
  ];
  const p = candidatePresentation(c, events);
  assert.equal(p.source, "rule");
  assert.equal(p.probability, null);
  assert.match(p.originalOpinion, /정상.*0\.55/);
});

test("candidate model evidence retains its actual model value", () => {
  const p = candidatePresentation(candidate({ probability: 0.81 }), [event(3, { ...modelThreat({ probability: 0.81 }), sub: 2 })]);
  assert.equal(p.source, "model");
  assert.equal(p.probability, 0.81);
});

test("candidate scores without provenance are hidden, even when the number is 1.00", () => {
  for (const events of [[], [event(1, ruleThreat())], [event(1, { ...modelThreat(), sub: 3 })], [event(1, { ...modelThreat(), sub: "2" })]]) {
    const p = candidatePresentation(candidate(), events);
    assert.equal(p.source, "unknown");
    assert.equal(p.probability, null);
  }
});

test("stale candidate evidence cannot supply a different type or value's provenance", () => {
  for (const t of [
    modelThreat({ probability: 0.81 }),
    modelThreat({ threat: "benign", probability: 1 }),
  ]) {
    const p = candidatePresentation(candidate(), [event(1, { ...t, sub: 2 })]);
    assert.equal(p.source, "unknown");
    assert.equal(p.probability, null);
  }
});

test("presentation does not rewrite the stored decision or verdict", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", threat: ruleThreat() });
  const before = JSON.stringify(c);
  Object.freeze(c.threat.override.original);
  Object.freeze(c.threat.override);
  Object.freeze(c.threat);
  Object.freeze(c);
  threatPresentation(c.threat);
  reviewReason(c);
  caseDecisionText(c);
  assert.equal(JSON.stringify(c), before);
});

// Safe Browsing match on a case the model already held: the server keeps finish_reason (agent_finished /
// low_confidence_action) because runner only rewrites COMPLETED cases, so the display must read the reputation itself.
const ownMatch = { status: "match", matches: [{ url: "https://reported.example/", threat_type: "SOCIAL_ENGINEERING" }] };

test("a held benign opinion with its own Safe Browsing match is shown as a reputation conflict", () => {
  for (const finish_reason of ["agent_finished", "low_confidence_action"]) {
    const c = caseOut({ status: "REVIEW_REQUIRED", finish_reason, threat: modelThreat({ threat: "benign", probability: 0.49, hold: true }), safebrowsing: ownMatch });
    assert.equal(reputationHit(c), "own");
    assert.equal(reputationConflict(c), true);
    assert.equal(casePresentation(c).probability, null);
    assert.doesNotMatch(caseDecisionText(c), /0\.49/);
    const reason = reviewReason(c);
    assert.match(reason, /^AI 의견과 Safe Browsing 위험 평판 불일치/);
    assert.match(reason, /AI 판단 불확실/);
    // the raw model value is still kept for the action log
    assert.equal(threatPresentation(c.threat).probability, 0.49);
  }
});

test("a held threat opinion with its own Safe Browsing match keeps its number and names the match", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", finish_reason: "low_confidence_action", threat: modelThreat({ probability: 0.55, hold: true }), safebrowsing: ownMatch });
  assert.equal(reputationConflict(c), false);
  assert.equal(casePresentation(c).probability, 0.55);
  assert.deepEqual(reviewParts(c), ["Safe Browsing 위험 일치", "AI 판단 불확실"]);
});

test("an unknown opinion with its own Safe Browsing match names the match", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", threat: modelThreat({ threat: "unknown", probability: 0.4, hold: true }), safebrowsing: ownMatch });
  assert.deepEqual(reviewParts(c), ["Safe Browsing 위험 일치"]);
});

test("a match only on related candidates is not a conflict about the reported address", () => {
  const sb = { status: "match", matches: [{ url: "https://candidate.example/", threat_type: "MALWARE" }] };
  const c = caseOut({ status: "REVIEW_REQUIRED", threat: modelThreat({ threat: "benign", probability: 0.5, hold: true }), safebrowsing: sb, candidates: [candidate({ reputation_match: true })] });
  assert.equal(reputationHit(c), "candidate");
  assert.equal(reputationConflict(c), false);
  assert.equal(casePresentation(c).probability, 0.5);
  assert.deepEqual(reviewParts(c), ["연관 후보의 Safe Browsing 위험 일치", "AI 판단 불확실"]);
  // legacy string candidates count as candidate addresses too
  assert.equal(reputationHit({ ...c, candidates: ["https://candidate.example/"] }), "candidate");
});

test("a match without listed addresses is treated as the case's own address", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", threat: modelThreat({ threat: "benign", probability: 0.5, hold: true }), safebrowsing: { status: "match", matches: [] } });
  assert.equal(reputationHit(c), "own");
  assert.equal(reputationConflict(c), true);
});

test("server reputation reasons are not repeated by the reputation note", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", finish_reason: "reputation_match", threat: modelThreat({ threat: "benign", probability: 0.99 }), safebrowsing: ownMatch });
  assert.deepEqual(reviewParts(c), ["AI 의견과 Safe Browsing 위험 평판 불일치"]);
  const u = caseOut({ status: "REVIEW_REQUIRED", finish_reason: "unreachable_reputation_match", threat: null, safebrowsing: ownMatch });
  assert.deepEqual(reviewParts(u), ["접속 불가 · Safe Browsing 위험 일치"]);
});

test("a rule decision in conflict with Safe Browsing is not called an AI opinion", () => {
  const t = ruleThreat("official_betting_domain", { threat: "benign", hold: false, provider: "official_domain" });
  const c = caseOut({ status: "REVIEW_REQUIRED", finish_reason: "reputation_match", threat: t, safebrowsing: ownMatch });
  assert.match(reviewReason(c), /^규칙 판단과 Safe Browsing/);
  assert.doesNotMatch(reviewReason(c), /AI 의견/);
});

test("an agreeing completed threat with a Safe Browsing match asks for no review", () => {
  const c = caseOut({ threat: modelThreat({ probability: 0.9 }), safebrowsing: ownMatch });
  assert.equal(reviewReason(c), null);
  assert.equal(casePresentation(c).probability, 0.9);
});

// ── 판단 문구 정리(2026-10-28): '보류'는 담당자 판정에만, 확신 낮은 정상은 초록이 아니게, 판단 불가는 사정을 함께 ──

test("a model hold is low confidence while a rule or unknown hold asks for review, never 'hold'", () => {
  assert.equal(holdLabel(threatPresentation(modelThreat({ probability: 0.5, hold: true })), true), "확신 낮음");
  assert.equal(holdLabel(threatPresentation(modelThreat({ threat: "benign", probability: 0.5, hold: true })), true), "확신 낮음");
  assert.equal(holdLabel(threatPresentation(modelThreat({ threat: "unknown", hold: true })), true), "검토 필요");
  assert.equal(holdLabel(threatPresentation(ruleThreat()), true), "검토 필요");
  assert.equal(holdLabel(threatPresentation(modelThreat()), false), null);
});

test("a confident-looking but sub-0.9 benign model opinion is flagged as low confidence without changing the case", () => {
  const c = caseOut({ threat: modelThreat({ threat: "benign", probability: 0.65, hold: false }) });
  assert.equal(BENIGN_SURE, 0.9);
  assert.equal(lowConfidenceBenign(c), true);
  assert.equal(reviewReason(c), null); // 상태·검토 요청은 그대로
  assert.equal(casePresentation(c).probability, 0.65); // 숫자도 그대로
  assert.equal(lowConfidenceBenign(caseOut({ threat: modelThreat({ threat: "benign", probability: 0.9 }) })), false);
  assert.equal(lowConfidenceBenign(caseOut({ threat: modelThreat({ threat: "benign", probability: 0.97 }) })), false);
  // 담당자 확정·규칙 정상·이미 검토 사유가 있는 사건은 따로 알리지 않는다
  assert.equal(lowConfidenceBenign({ ...c, verdict: { rev: 1, decision: "benign", threat: null } }), false);
  assert.equal(lowConfidenceBenign(caseOut({ threat: ruleThreat("official_betting_domain", { threat: "benign", hold: false, provider: "official_domain" }) })), false);
  assert.equal(lowConfidenceBenign(caseOut({ status: "REVIEW_REQUIRED", finish_reason: "page_unresponsive", threat: modelThreat({ threat: "benign", probability: 0.7 }) })), false);
  assert.equal(lowConfidenceBenign(caseOut({ threat: modelThreat({ threat: "benign", probability: 0.65, provider: "legacy_unknown_provider" }) })), false);
  assert.equal(lowBenign(threatPresentation(modelThreat({ threat: "benign", probability: 0.65 })), true), false); // 보류는 '확신 낮음'이 말한다
});

test("an unknown case explains why it could not be judged instead of repeating it", () => {
  const c = caseOut({ status: "REVIEW_REQUIRED", finish_reason: "low_confidence_action", threat: modelThreat({ threat: "unknown", probability: 0.4, hold: true }) });
  assert.equal(exploreNote(c), "다음 행동 확신 부족으로 탐색 종료");
  assert.equal(caseDecisionText(c, true), "판단 불가(다음 행동 확신 부족으로 탐색 종료)");
  assert.equal(caseDecisionText(c), "판단 불가"); // 경로 지도는 짧게
  assert.deepEqual(reviewParts(c), []);
  assert.equal(reviewReason(c), "담당자 검토 필요");
  const done = { ...c, finish_reason: "agent_finished" };
  assert.equal(exploreNote(done), null);
  assert.equal(caseDecisionText(done, true), "판단 불가");
  // 판단 불가가 아니면 사정을 붙이지 않는다
  assert.equal(caseDecisionText(caseOut({ finish_reason: "low_confidence_action" }), true), "피싱 · 0.80");
});

test("calm (gray safety-rule) treatment needs a confident or confirmed benign", () => {
  const benign = (probability, patch = {}) => caseOut({ threat: modelThreat({ threat: "benign", probability, hold: false }), ...patch });
  assert.equal(evidence.calmCase(benign(0.95)), true);
  assert.equal(evidence.calmCase(benign(0.65)), false);
  assert.equal(evidence.calmCase(benign(0.65, { verdict: { rev: 1, decision: "benign", threat: null } })), true);
  assert.equal(evidence.calmCase(caseOut({ threat: ruleThreat("official_betting_domain", { threat: "benign", hold: false, provider: "official_domain" }) })), true);
});

test("path and reason labels say low confidence or review instead of the reviewer's 'hold'", () => {
  const sub = [
    { type: "evidence", seq: 9, kind: "threat", data: { sub: 2, ...modelThreat({ probability: 0.55, hold: true }) }, files: [], hash: "h" },
    { type: "evidence", seq: 10, kind: "threat", data: { sub: 3, ...ruleThreat() }, files: [], hash: "h" },
  ];
  const cands = [candidate({ probability: 0.55, hold: true }), candidate({ url: "https://rule.example/", host: "rule.example", sub: 3 })];
  const path = evidence.buildPath(caseOut({ candidates: cands }), sub);
  const titles = path.branches.flat().map((b) => b.title);
  assert.ok(titles.some((t) => t.includes("피싱(확신 낮음) · AI 판단")), titles.join(" / "));
  assert.ok(titles.some((t) => t.includes("피싱(검토 필요) · 규칙 판단")), titles.join(" / "));
  assert.ok(titles.every((t) => !t.includes("보류")));
  const cards = evidence.buildReasons(sub, caseOut({ candidates: [cands[0]] }));
  const card = cards.find((r) => r.key === "candidate");
  assert.match(card.text, /확신 낮음/);
  assert.doesNotMatch(card.text, /보류/);
});

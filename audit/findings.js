// 심층 점검 결과 기록(findings.json) 검증기. 의존성 없음.
// 판정은 셋이다(cloudflare/security-audit-skill(MIT) report-schema 와 같은 필드 이름을 쓴다):
//   confirmed         확인한 위험 — 코드 경로 전체와 작은 로컬 시험 결과가 있고, 심각도가 붙는다.
//   needs_validation  미확인 — 코드상 근거는 있으나 저장소 밖 사실 하나가 결정적이다. 심각도 없음.
//   rejected          기각 — 코드·시험으로 반박됐다. 다음 점검이 같은 주장을 반복하지 않게 남긴다.
import { FINGERPRINT_RE, isRepoRelative } from './ledger.js';

export const VERDICTS = ['confirmed', 'needs_validation', 'rejected'];
export const SCORES = ['informational', 'low', 'medium', 'high', 'critical'];
const RANK = Object.fromEntries(SCORES.map((s, i) => [s, i]));
const CONDITION_KINDS = ['authentication_level', 'authorization_role', 'user_interaction', 'system_configuration', 'network_routing',
  'environmental_dependency', 'data_state', 'timing_dependency', 'third_party_dependency'];

const FIELDS = {
  confirmed: {
    required: ['verdict', 'fingerprint', 'title', 'description', 'root_cause', 'intended_behavior', 'trace', 'evidence', 'conditions', 'execution', 'remediation', 'severity', 'confidence'],
    forbidden: ['claimed_root_cause', 'blockers', 'validation_plan', 'reason'],
  },
  needs_validation: {
    required: ['verdict', 'fingerprint', 'title', 'description', 'claimed_root_cause', 'trace', 'evidence', 'blockers', 'validation_plan'],
    forbidden: ['root_cause', 'intended_behavior', 'conditions', 'execution', 'remediation', 'severity', 'confidence', 'reason'],
  },
  rejected: {
    required: ['verdict', 'fingerprint', 'title', 'description', 'claimed_root_cause', 'trace', 'evidence', 'reason'],
    forbidden: ['root_cause', 'intended_behavior', 'conditions', 'execution', 'remediation', 'severity', 'confidence', 'blockers', 'validation_plan'],
  },
};

const visible = v => typeof v === 'string' && /[^\s\u200B-\u200F\u2060\uFEFF]/u.test(v);

function checkTrace(trace, label, errors) {
  if (!Array.isArray(trace) || !trace.length) { errors.push(`${label}.trace: 한 개 이상의 경로 단계가 필요합니다.`); return; }
  const seen = new Set();
  trace.forEach((t, i) => {
    const l = `${label}.trace[${i}]`;
    if (!t || typeof t !== 'object') { errors.push(`${l}: 객체가 아닙니다.`); return; }
    const extra = Object.keys(t).filter(k => !['kind', 'file', 'line', 'scope', 'description'].includes(k));
    if (extra.length) errors.push(`${l}: 모르는 필드 ${extra.join(', ')}`);
    if (!['entrypoint', 'propagation', 'sink'].includes(t.kind)) errors.push(`${l}.kind: entrypoint·propagation·sink 중 하나여야 합니다.`);
    if (!isRepoRelative(t.file)) errors.push(`${l}.file: 저장소 기준 상대 경로여야 합니다.`);
    if (!Number.isInteger(t.line) || t.line < 1) errors.push(`${l}.line: 1 이상의 정수여야 합니다.`);
    if (!visible(t.scope)) errors.push(`${l}.scope: 비었습니다.`);
    if (!visible(t.description)) errors.push(`${l}.description: 비었습니다.`);
    const key = JSON.stringify(t);
    if (seen.has(key)) errors.push(`${l}: 같은 단계가 중복됐습니다.`);
    seen.add(key);
  });
  if (trace.length > 1) {
    if (trace[0]?.kind !== 'entrypoint') errors.push(`${label}.trace: 여러 단계면 entrypoint 로 시작해야 합니다.`);
    if (trace[trace.length - 1]?.kind !== 'sink') errors.push(`${label}.trace: 여러 단계면 sink 로 끝나야 합니다.`);
    trace.slice(1, -1).forEach((t, i) => { if (t?.kind !== 'propagation') errors.push(`${label}.trace[${i + 1}]: 중간 단계는 propagation 이어야 합니다.`); });
  } else if (trace[0] && trace[0].kind === 'propagation') errors.push(`${label}.trace: 한 단계짜리는 entrypoint 또는 sink 여야 합니다.`);
}

function checkEvidence(list, label, errors) {
  if (!Array.isArray(list) || !list.length) { errors.push(`${label}.evidence: 한 개 이상의 근거가 필요합니다.`); return; }
  list.forEach((e, i) => {
    const l = `${label}.evidence[${i}]`;
    if (!e || typeof e !== 'object') { errors.push(`${l}: 객체가 아닙니다.`); return; }
    const extra = Object.keys(e).filter(k => !['file', 'line', 'description'].includes(k));
    if (extra.length) errors.push(`${l}: 모르는 필드 ${extra.join(', ')}`);
    if (!isRepoRelative(e.file)) errors.push(`${l}.file: 저장소 기준 상대 경로여야 합니다.`);
    if (!Number.isInteger(e.line) || e.line < 1) errors.push(`${l}.line: 1 이상의 정수여야 합니다.`);
    if (!visible(e.description)) errors.push(`${l}.description: 비었습니다.`);
  });
}

function checkScore(obj, label, errors, enumList = SCORES) {
  if (!obj || typeof obj !== 'object') { errors.push(`${label}: 객체가 필요합니다.`); return; }
  if (!enumList.includes(obj.score)) errors.push(`${label}.score: ${enumList.join('·')} 중 하나여야 합니다.`);
  if (!visible(obj.reason)) errors.push(`${label}.reason: 이유가 비었습니다.`);
}

// mode 'final' 은 verdict, 'candidate' 는 찾는 사람이 내는 proposed_verdict 를 본다.
export function validateFinding(f, label = 'finding', { mode = 'final' } = {}) {
  const errors = [];
  if (!f || typeof f !== 'object' || Array.isArray(f)) return [`${label}: 객체가 아닙니다.`];
  const key = mode === 'candidate' ? 'proposed_verdict' : 'verdict';
  const verdict = f[key];
  const allowed = mode === 'candidate' ? ['confirmed', 'needs_validation'] : VERDICTS;
  if (!allowed.includes(verdict)) return [`${label}.${key}: ${allowed.join('·')} 중 하나여야 합니다.`];
  const spec = FIELDS[verdict];
  const required = spec.required.map(k => (k === 'verdict' ? key : k));
  for (const k of required) if (f[k] === undefined) errors.push(`${label}.${k}: 빠졌습니다.`);
  for (const k of spec.forbidden) if (f[k] !== undefined) errors.push(`${label}.${k}: ${verdict} 기록에는 쓰지 않는 필드입니다.`);
  const known = new Set([...required]);
  const extra = Object.keys(f).filter(k => !known.has(k));
  if (extra.length) errors.push(`${label}: 이 판정에 없는 필드 ${extra.join(', ')}`);
  if (typeof f.fingerprint !== 'string' || !FINGERPRINT_RE.test(f.fingerprint)) errors.push(`${label}.fingerprint: 형식이 맞지 않습니다(영문·숫자·._:/@+- , 줄 번호·담당자·판정 넣지 않기).`);
  for (const k of ['title', 'description', 'root_cause', 'intended_behavior', 'claimed_root_cause', 'reason']) {
    if (f[k] !== undefined && !visible(f[k])) errors.push(`${label}.${k}: 비었습니다.`);
  }
  checkTrace(f.trace, label, errors);
  checkEvidence(f.evidence, label, errors);

  if (verdict === 'confirmed') {
    if (!Array.isArray(f.conditions)) errors.push(`${label}.conditions: 배열이어야 합니다.`);
    else f.conditions.forEach((c, i) => {
      if (!c || !CONDITION_KINDS.includes(c.kind)) errors.push(`${label}.conditions[${i}].kind: ${CONDITION_KINDS.join('·')} 중 하나여야 합니다.`);
      if (!visible(c?.description)) errors.push(`${label}.conditions[${i}].description: 비었습니다.`);
    });
    const ex = f.execution;
    if (!ex || typeof ex !== 'object') errors.push(`${label}.execution: 객체가 필요합니다.`);
    else {
      if (!visible(ex.attacker_perspective)) errors.push(`${label}.execution.attacker_perspective: 비었습니다.`);
      if (!Array.isArray(ex.payloads) || !ex.payloads.length) errors.push(`${label}.execution.payloads: 최소 시험 입력이 필요합니다.`);
      if (!Array.isArray(ex.instructions) || !ex.instructions.length || !ex.instructions.every(visible)) errors.push(`${label}.execution.instructions: 재현 순서가 필요합니다.`);
      if (!visible(ex.observed_result)) errors.push(`${label}.execution.observed_result: 실제로 관찰한 결과가 필요합니다.`);
    }
    if (!f.remediation || !visible(f.remediation.strategy)) errors.push(`${label}.remediation.strategy: 수정 방향이 필요합니다.`);
    else if (f.remediation.code_changes !== undefined && (!Array.isArray(f.remediation.code_changes) || f.remediation.code_changes.some(c => !c || !visible(c.file_name) || typeof c.fixed_code !== 'string'))) {
      errors.push(`${label}.remediation.code_changes: file_name·fixed_code 쌍의 배열이어야 합니다.`);
    }
    const sev = f.severity;
    if (!sev || typeof sev !== 'object') errors.push(`${label}.severity: 객체가 필요합니다.`);
    else {
      checkScore(sev.likelihood, `${label}.severity.likelihood`, errors);
      checkScore(sev.impact, `${label}.severity.impact`, errors);
      if (!SCORES.includes(sev.overall_severity)) errors.push(`${label}.severity.overall_severity: ${SCORES.join('·')} 중 하나여야 합니다.`);
      else if (SCORES.includes(sev.impact?.score) && RANK[sev.overall_severity] > RANK[sev.impact.score]) {
        errors.push(`${label}.severity.overall_severity: 관찰한 영향(${sev.impact.score})보다 높을 수 없습니다.`);
      }
    }
    checkScore(f.confidence, `${label}.confidence`, errors, ['low', 'medium', 'high']);
  }
  if (verdict === 'needs_validation') {
    if (!Array.isArray(f.blockers) || !f.blockers.length || !f.blockers.every(visible)) errors.push(`${label}.blockers: 막힌 사실을 한 개 이상 적어야 합니다.`);
    const vp = f.validation_plan;
    if (!vp || typeof vp !== 'object' || (!visible(vp.local) && !visible(vp.deployment))) errors.push(`${label}.validation_plan: local 또는 deployment 확인 방법이 하나 이상 필요합니다.`);
    else if (Object.keys(vp).some(k => !['local', 'deployment'].includes(k))) errors.push(`${label}.validation_plan: local·deployment 외의 필드는 쓰지 않습니다.`);
  }
  return errors;
}

export function validateFindings(list) {
  if (!Array.isArray(list)) return ['findings.json 은 배열이어야 합니다.'];
  if (list.length > 1000) return ['기록이 1,000 건을 넘습니다.'];
  const errors = [];
  const fps = new Set();
  list.forEach((f, i) => {
    errors.push(...validateFinding(f, `findings[${i}]`));
    if (f && fps.has(f.fingerprint)) errors.push(`findings[${i}].fingerprint: 같은 지문이 두 번 있습니다(지문 하나에 최종 기록 하나).`);
    if (f) fps.add(f.fingerprint);
  });
  return errors.slice(0, 100);
}

export function severityOf(f) {
  return f?.verdict === 'confirmed' ? f.severity?.overall_severity : null;
}

// 판정 → 도름스체크 보고 어휘.
export const VERDICT_LABEL = { confirmed: '확인한 위험', needs_validation: '미확인(확인 방법 있음)', rejected: '기각' };
export const SEVERITY_LABEL = { critical: '매우 높음', high: '높음', medium: '보통', low: '낮음', informational: '참고' };

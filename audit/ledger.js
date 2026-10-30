// 심층 점검 범위표(coverage ledger). 무엇을 봤고 무엇을 못 봤는지가 곧 점검 범위 주장이다.
// cloudflare/security-audit-skill(MIT) 의 coverage-ledger 계약(안정 ID·상태표·소유자·근거)을 따르되
// 교사 앱 표면(audit/inventory.js)과 분류표(audit/classes.js)에 맞춰 줄였다.
import { AUDIT_CLASSES, EXCLUDED_CLASSES, classAppliesTo } from './classes.js';

export const PROFILES = ['quick', 'standard', 'deep'];
export const QUICK_SUBSYSTEM = 'profile/quick/all-in-scope-subsystems';
export const STATUSES = ['planned', 'in_progress', 'covered', 'candidate', 'blocked', 'deferred', 'not_applicable', 'out_of_scope'];
export const PRIOR_STATUSES = ['none', 'new', 'prior_confirmed_same_source', 'prior_confirmed_changed_source', 'prior_needs_validation',
  'prior_deferred', 'prior_blocked', 'prior_out_of_scope', 'prior_covered_same_source', 'prior_covered_changed_source', 'prior_rejected_claim_changed'];
export const AGENT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const WINDOWS_DEVICES = new Set(['con', 'prn', 'aux', 'nul', ...Array.from({ length: 9 }, (_, i) => `com${i + 1}`), ...Array.from({ length: 9 }, (_, i) => `lpt${i + 1}`)]);
export const FINGERPRINT_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;
const MAX_STARTING_PATHS = 40;

// 표면 종류별로 지켜야 할 경계(사람이 읽는 이름).
const BOUNDARY = {
  'api-route': '서버가 매 요청 확인하는 로그인·권한',
  'server-action': '서버 액션의 로그인·권한 확인',
  'edge-function': '엣지 함수의 호출자 확인',
  'cron-route': '예약 작업 경로의 비밀값 확인',
  'auth-flow': '로그인·콜백·재설정 흐름의 묶음 확인',
  webhook: '웹훅 서명 확인',
  'service-client': '서비스 키로 RLS 를 건너뛰는 서버 경로',
  storage: '파일 저장소 경로·서명 URL 범위',
  upload: '업로드 크기·형식·저장 위치',
  export: '내보내기 범위',
  'ai-call': 'AI 맥락 분리와 운영자 요금',
  'mail-send': '메일 발송 횟수·대상',
  'outbound-fetch': '서버가 가져가는 주소 제한',
  'html-sink': '브라우저에 그리는 HTML 의 이스케이프',
  'client-message': '창 사이 메시지 출처 확인',
  redirect: '이동 주소 제한',
  'service-worker': '서비스 워커 캐시와 범위',
  'browser-storage': '브라우저 저장소의 계정 구분',
  'static-html': '정적 페이지 스크립트',
  'db-function': 'SECURITY DEFINER 함수의 호출자 확인',
  'db-migration': 'RLS 정책·GRANT·뷰',
  manifest: '설치하는 의존성',
  ci: '자동 실행·배포 권한',
  'native-shell': '앱 껍데기와 웹 화면 사이 권한',
  repo: '저장소 전체',
};

const CONTROL_TEXT = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u061C\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u;

export function isSafeAgentId(id) {
  return typeof id === 'string' && AGENT_ID_RE.test(id) && !WINDOWS_DEVICES.has(id);
}

// 저장소 기준 상대 경로만 받는다(절대 경로·.. 금지).
export function isRepoRelative(p) {
  if (typeof p !== 'string' || !p || p.length > 1024) return false;
  if (p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p) || p.includes('\\') || p.includes('\0')) return false;
  return !p.split('/').some(seg => seg === '..' || seg === '');
}

// 보이지 않는 문자·제어 문자가 없는 NFC 문자열인가.
const INVISIBLE = /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\uFFF0-\uFFFB]/u;
export function isCleanRef(ref) {
  return typeof ref === 'string' && ref.length > 0 && ref === ref.trim() && ref === ref.normalize('NFC')
    && !INVISIBLE.test(ref) && /\S/.test(ref) && !/[\uD800-\uDFFF]/.test(ref.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, ''));
}

// RFC 3986 퍼센트 인코딩(비예약 문자만 그대로). 사람이 읽는 이름이 아니라 출처 참조로 ID 를 만든다.
export function encodeRef(ref) {
  if (!isCleanRef(ref)) throw new Error(`범위표 참조 값이 올바르지 않습니다: ${JSON.stringify(String(ref).slice(0, 80))}`);
  let out = '';
  for (const byte of Buffer.from(ref, 'utf8')) {
    const ch = String.fromCharCode(byte);
    out += /[A-Za-z0-9\-._~]/.test(ch) ? ch : '%' + byte.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

export function coverageId(refs) {
  const parts = [refs.surface, refs.boundary, refs.subsystem, refs.attack_class].map(encodeRef);
  if (refs.lifecycle) parts.push(encodeRef(refs.lifecycle));
  return parts.join('::');
}

function emptyUnit(base) {
  return {
    ...base,
    prior_status: base.prior_status || 'none',
    attempts: [],
    wave: base.wave || 1,
    status: base.status || 'planned',
    agent_id: null,
    reviewed_paths: [],
    local_checks: [],
    result_fingerprints: [],
    unresolved: base.unresolved || [],
  };
}

function makeUnit({ kind, subsystem, cls, surfaceRef, paths, status = 'planned', unresolved = [], prior_status }) {
  const refs = {
    surface: surfaceRef,
    boundary: `boundary/${kind}`,
    subsystem,
    attack_class: `audit/classes.js#${cls.id}`,
  };
  const sorted = [...new Set(paths)].sort();
  return emptyUnit({
    coverage_id: coverageId(refs),
    canonical_refs: refs,
    surface: surfaceRef,
    boundary: BOUNDARY[kind] || kind,
    subsystem,
    attack_class: cls.title,
    class_id: cls.id,
    source_ref: cls.cf,
    starting_paths: sorted.slice(0, MAX_STARTING_PATHS),
    starting_paths_total: sorted.length,
    status,
    unresolved,
    prior_status,
  });
}

// 프로필별 단위 크기:
//   quick    표면 종류 × 분류 (하위 영역은 하나로 묶음)
//   standard 표면 종류 × 하위 영역 × 분류
//   deep     표면 파일 하나하나 × 분류
export function buildLedger(inventory, { profile = 'standard' } = {}) {
  if (!PROFILES.includes(profile)) throw new Error(`알 수 없는 점검 깊이: ${profile}`);
  const units = new Map();
  const put = u => { if (units.has(u.coverage_id)) throw new Error(`범위표 ID 충돌: ${u.coverage_id}`); units.set(u.coverage_id, u); };
  const kinds = new Set(inventory.surfaces.map(s => s.kind));

  const groups = new Map();
  for (const s of inventory.surfaces) {
    const sub = profile === 'quick' ? QUICK_SUBSYSTEM : s.subsystem;
    const surfaceRef = profile === 'deep' ? `${s.file}#${s.scope}` : `kind/${s.kind}`;
    const key = `${s.kind}|${sub}|${surfaceRef}`;
    if (!groups.has(key)) groups.set(key, { kind: s.kind, subsystem: sub, surfaceRef, paths: [] });
    groups.get(key).paths.push(s.file);
  }

  for (const cls of AUDIT_CLASSES) {
    if (cls.applies.includes('always')) {
      put(makeUnit({ kind: 'repo', subsystem: profile === 'quick' ? QUICK_SUBSYSTEM : '.', cls, surfaceRef: 'repo/whole', paths: [] }));
      continue;
    }
    if (!classAppliesTo(cls, kinds)) {
      put(makeUnit({ kind: 'repo', subsystem: profile === 'quick' ? QUICK_SUBSYSTEM : '.', cls, surfaceRef: 'repo/whole', paths: [],
        status: 'not_applicable', unresolved: [`이 분류가 다루는 표면(${cls.applies.join(', ')})이 저장소에서 보이지 않았습니다.`] }));
      continue;
    }
    for (const g of [...groups.values()].sort((a, b) => (a.kind + a.subsystem + a.surfaceRef).localeCompare(b.kind + b.subsystem + b.surfaceRef))) {
      if (!cls.applies.includes(g.kind)) continue;
      put(makeUnit({ kind: g.kind, subsystem: g.subsystem, cls, surfaceRef: g.surfaceRef, paths: g.paths }));
    }
  }

  // 범위에서 뺀 표면도 다음 점검이 이어받도록 out_of_scope 로 남긴다.
  for (const s of inventory.scoped_out || []) {
    for (const cls of AUDIT_CLASSES) {
      if (!cls.applies.includes(s.kind)) continue;
      const sub = profile === 'quick' ? QUICK_SUBSYSTEM : s.subsystem;
      const u = makeUnit({ kind: s.kind, subsystem: sub, cls, surfaceRef: `kind/${s.kind}`, paths: [s.file], status: 'out_of_scope',
        unresolved: ['이번 점검 범위(--scope) 밖입니다.'] });
      if (!units.has(u.coverage_id)) units.set(u.coverage_id, u);
    }
  }
  if (inventory.native_code) {
    const cls = { id: 'memory-safety', title: '메모리 안전(네이티브 코드)', cf: 'MEMORY-SAFETY-AND-BINARY.md' };
    put(makeUnit({ kind: 'repo', subsystem: '.', cls, surfaceRef: 'repo/native-code', paths: [], status: 'out_of_scope',
      unresolved: ['C·C++·러스트 코드가 있습니다. 이 도구의 기본 범위 밖이라 따로 점검이 필요합니다.'] }));
  }
  return [...units.values()].sort((a, b) => a.coverage_id.localeCompare(b.coverage_id));
}

export function excludedClassesSummary() {
  return EXCLUDED_CLASSES.map(x => ({ ...x }));
}

// 우선순위: 로그인 없이 닿는 표면 → 값비싼 자원(비밀·다른 사람 자료·코드 실행) → 이전 빈칸 → 나머지. 동률은 ID 순.
const KIND_RANK = { 'cron-route': 0, webhook: 0, 'auth-flow': 0, 'edge-function': 1, 'api-route': 1, 'db-function': 1, 'service-client': 1,
  'server-action': 2, 'db-migration': 2, storage: 2, 'ai-call': 2, upload: 2, export: 2, 'outbound-fetch': 2, 'mail-send': 3,
  'html-sink': 3, 'client-message': 3, redirect: 3, 'service-worker': 4, 'browser-storage': 4, 'static-html': 4, 'native-shell': 4,
  manifest: 5, ci: 5, repo: 6 };
export function unitPriority(u) {
  const kind = String(u.canonical_refs?.boundary || '').replace('boundary/', '');
  const prior = /changed_source|needs_validation|deferred|blocked/.test(u.prior_status) ? 0 : 1;
  return [prior, KIND_RANK[kind] ?? 5, u.coverage_id];
}
export function sortByPriority(units) {
  return [...units].sort((a, b) => {
    const pa = unitPriority(a), pb = unitPriority(b);
    for (let i = 0; i < pa.length; i++) {
      if (pa[i] < pb[i]) return -1;
      if (pa[i] > pb[i]) return 1;
    }
    return 0;
  });
}

// ── 검증 ──
const STATE_TABLE = {
  planned: { owner: false, evidence: 'empty', fingerprints: 'empty', unresolved: 'empty' },
  not_applicable: { owner: false, evidence: 'empty', fingerprints: 'empty', unresolved: 'nonempty' },
  out_of_scope: { owner: false, evidence: 'empty', fingerprints: 'empty', unresolved: 'nonempty' },
  deferred: { owner: false, evidence: 'empty', fingerprints: 'empty', unresolved: 'nonempty' },
  in_progress: { owner: true, evidence: 'empty', fingerprints: 'empty', unresolved: 'empty' },
  blocked: { owner: true, evidence: 'nonempty', fingerprints: 'empty', unresolved: 'nonempty' },
  covered: { owner: true, evidence: 'nonempty', fingerprints: 'empty', unresolved: 'empty' },
  candidate: { owner: true, evidence: 'nonempty', fingerprints: 'nonempty', unresolved: 'any' },
};

function checkEvidenceState(u, label, errors, { archived = false } = {}) {
  const rule = STATE_TABLE[u.status];
  if (!rule) { errors.push(`${label}.status: 알 수 없는 상태 ${JSON.stringify(u.status)}`); return; }
  if (archived && !['blocked', 'covered', 'candidate'].includes(u.status)) errors.push(`${label}: 보관 기록은 blocked·covered·candidate 만 됩니다.`);
  if (rule.owner && !isSafeAgentId(u.agent_id)) errors.push(`${label}.agent_id: ${u.status} 상태에는 안전한 소문자 담당자 ID 가 필요합니다.`);
  if (!rule.owner && u.agent_id !== null) errors.push(`${label}.agent_id: ${u.status} 상태에는 담당자가 없어야 합니다.`);
  const reviewed = Array.isArray(u.reviewed_paths) ? u.reviewed_paths : null;
  const checks = Array.isArray(u.local_checks) ? u.local_checks : null;
  if (!reviewed || !checks) { errors.push(`${label}: reviewed_paths·local_checks 는 배열이어야 합니다.`); return; }
  if (rule.evidence === 'empty' && (reviewed.length || checks.length)) errors.push(`${label}: ${u.status} 상태에는 근거가 비어 있어야 합니다.`);
  if (rule.evidence === 'nonempty' && (!reviewed.length || !checks.length)) errors.push(`${label}: ${u.status} 상태에는 읽은 경로와 확인 기록이 모두 필요합니다.`);
  const fps = Array.isArray(u.result_fingerprints) ? u.result_fingerprints : [];
  if (rule.fingerprints === 'empty' && fps.length) errors.push(`${label}: ${u.status} 상태에는 후보 지문이 없어야 합니다.`);
  if (rule.fingerprints === 'nonempty' && !fps.length) errors.push(`${label}: candidate 상태에는 후보 지문이 필요합니다.`);
  for (const f of fps) if (!FINGERPRINT_RE.test(String(f))) errors.push(`${label}.result_fingerprints: 지문 형식이 맞지 않습니다 ${JSON.stringify(String(f).slice(0, 60))}`);
  const unresolved = Array.isArray(u.unresolved) ? u.unresolved : [];
  if (rule.unresolved === 'empty' && unresolved.length) errors.push(`${label}: ${u.status} 상태에는 남은 질문이 없어야 합니다.`);
  if (rule.unresolved === 'nonempty' && !unresolved.length) errors.push(`${label}: ${u.status} 상태에는 이유가 필요합니다.`);
  for (const p of reviewed) if (!isRepoRelative(p)) errors.push(`${label}.reviewed_paths: 저장소 기준 상대 경로가 아닙니다 ${JSON.stringify(String(p).slice(0, 80))}`);
  const union = new Set();
  checks.forEach((c, i) => {
    const cl = `${label}.local_checks[${i}]`;
    if (!c || typeof c !== 'object') { errors.push(`${cl}: 객체가 아닙니다.`); return; }
    if (!isSafeAgentId(c.agent_id)) errors.push(`${cl}.agent_id: 안전한 소문자 ID 가 아닙니다.`);
    if (!Array.isArray(c.reviewed_paths) || !c.reviewed_paths.length) errors.push(`${cl}.reviewed_paths: 비어 있으면 안 됩니다.`);
    else for (const p of c.reviewed_paths) { if (!isRepoRelative(p)) errors.push(`${cl}.reviewed_paths: 상대 경로가 아닙니다.`); union.add(p); }
    if (!c.invariant || !String(c.invariant).trim()) errors.push(`${cl}.invariant: 확인한 규칙이 비었습니다.`);
    if ([c.invariant, c.result].some(x => typeof x === 'string' && CONTROL_TEXT.test(x))) errors.push(`${cl}: 제어 문자·보이지 않는 문자는 받지 않습니다.`);
    if (!c.result || !String(c.result).trim()) errors.push(`${cl}.result: 확인 결과가 비었습니다.`);
    if (c.method === 'source') { if (c.artifact !== null) errors.push(`${cl}.artifact: 코드 읽기 확인에는 산출물이 없어야 합니다(null).`); }
    else if (c.method === 'local') {
      const prefix = `agents/${c.agent_id}/artifacts/`;
      if (typeof c.artifact !== 'string' || !c.artifact.startsWith(prefix) || !isRepoRelative(c.artifact) || c.artifact.length <= prefix.length) {
        errors.push(`${cl}.artifact: 로컬 확인 산출물은 ${prefix} 아래 파일이어야 합니다.`);
      }
    } else errors.push(`${cl}.method: source 또는 local 이어야 합니다.`);
  });
  if (checks.length) {
    const a = [...union].sort().join('\n'), b = [...new Set(reviewed)].sort().join('\n');
    if (a !== b) errors.push(`${label}.reviewed_paths: 확인 기록들의 읽은 경로 합과 같아야 합니다.`);
  }
}

export function validateLedger(ledger) {
  const errors = [];
  if (!Array.isArray(ledger)) return ['범위표는 배열이어야 합니다.'];
  if (ledger.length > 10000) errors.push('범위표 단위가 10,000 개를 넘습니다.');
  const ids = new Set();
  const tuples = new Map();
  ledger.forEach((u, i) => {
    const label = `units[${i}]`;
    if (!u || typeof u !== 'object') { errors.push(`${label}: 객체가 아닙니다.`); return; }
    const refs = u.canonical_refs || {};
    let expected = null;
    try { expected = coverageId(refs); } catch (e) { errors.push(`${label}.canonical_refs: ${e.message}`); }
    if (expected && u.coverage_id !== expected) errors.push(`${label}.coverage_id: canonical_refs 로 만든 ID 와 다릅니다.`);
    if (ids.has(u.coverage_id)) errors.push(`${label}.coverage_id: 중복 ID ${u.coverage_id}`);
    ids.add(u.coverage_id);
    const tuple = [u.surface, u.boundary, u.subsystem, u.attack_class, u.lifecycle || ''].join('\u0001');
    if (tuples.has(tuple) && tuples.get(tuple) !== u.coverage_id) errors.push(`${label}: 같은 뜻의 단위가 다른 참조로 두 번 있습니다.`);
    tuples.set(tuple, u.coverage_id);
    if (!PRIOR_STATUSES.includes(u.prior_status)) errors.push(`${label}.prior_status: 알 수 없는 값 ${JSON.stringify(u.prior_status)}`);
    if (!Number.isInteger(u.wave) || u.wave < 1) errors.push(`${label}.wave: 1 이상의 정수여야 합니다.`);
    for (const p of u.starting_paths || []) if (!isRepoRelative(p)) errors.push(`${label}.starting_paths: 상대 경로가 아닙니다.`);
    checkEvidenceState(u, label, errors);
    let lastWave = 0;
    // 다시 맡긴 단위는 새 담당자의 새 근거로만 닫는다. 보관된 담당자·확인·산출물을 지금 기록에 다시 쓰지 않는다.
    const archivedOwners = new Set();
    const archivedArtifacts = new Set();
    for (const a of u.attempts || []) {
      if (a?.agent_id) archivedOwners.add(a.agent_id);
      for (const c of a?.local_checks || []) { if (c?.agent_id) archivedOwners.add(c.agent_id); if (c?.artifact) archivedArtifacts.add(c.artifact); }
    }
    for (const c of Array.isArray(u.local_checks) ? u.local_checks : []) {
      if (archivedOwners.has(c?.agent_id)) errors.push(`${label}: 이전 담당자(${c.agent_id})의 확인 기록을 다시 맡긴 단위의 지금 기록에 쓸 수 없습니다.`);
      if (c?.artifact && archivedArtifacts.has(c.artifact)) errors.push(`${label}: 보관된 시도의 산출물을 다시 쓸 수 없습니다.`);
    }
    if (u.agent_id && archivedOwners.has(u.agent_id)) errors.push(`${label}: 다시 맡긴 단위는 이전과 다른 담당자여야 합니다.`);
    (u.attempts || []).forEach((a, j) => {
      checkEvidenceState(a, `${label}.attempts[${j}]`, errors, { archived: true });
      if (!Number.isInteger(a.wave) || a.wave <= lastWave || a.wave >= u.wave) errors.push(`${label}.attempts[${j}].wave: 보관 기록의 차수는 늘어나야 하고 지금 차수보다 작아야 합니다.`);
      lastWave = a.wave || lastWave;
      if (!a.reassignment_reason || !String(a.reassignment_reason).trim()) errors.push(`${label}.attempts[${j}].reassignment_reason: 다시 맡긴 이유가 필요합니다.`);
      if (u.agent_id && a.agent_id === u.agent_id) errors.push(`${label}: 다시 맡긴 단위는 이전과 다른 담당자여야 합니다.`);
    });
  });
  return errors.slice(0, 100);
}

export function ledgerCounts(ledger) {
  const counts = Object.fromEntries(STATUSES.map(s => [s, 0]));
  for (const u of ledger) counts[u.status] = (counts[u.status] || 0) + 1;
  return counts;
}

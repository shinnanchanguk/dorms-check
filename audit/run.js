// 심층 점검 한 회차(run)를 관리한다. 공유 파일은 이 모듈(부모)만 쓴다.
// 찾는 사람·검증하는 사람은 JSON 을 돌려줄 뿐이고, 범위표·결과 기록은 여기서만 바뀐다.
// 흐름: plan → prompt(배정) → merge(찾은 결과·범위 비평) → record(반박 검증) → check → report
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { buildInventory } from './inventory.js';
import { auditClass, AUDIT_CLASSES, CORE_PRINCIPLES } from './classes.js';
import { buildLedger, validateLedger, coverageId, isSafeAgentId, isRepoRelative, isCleanRef, sortByPriority, ledgerCounts, QUICK_SUBSYSTEM, PROFILES, excludedClassesSummary } from './ledger.js';
import { validateFinding, validateFindings, VERDICT_LABEL, SEVERITY_LABEL } from './findings.js';
import { renderHunterPrompt, renderVerifierPrompt, renderCriticPrompt } from './prompts.js';

const ARTIFACT_FILE_LIMIT = 1024 * 1024;
const ARTIFACT_TOTAL_LIMIT = 5 * 1024 * 1024;
const RUN_FILES = ['run-metadata.json', 'inventory.json', 'coverage-ledger.json', 'candidates.json', 'findings.json', 'hardening.json', 'verification.json'];

// ── 공용 입출력 ──
function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJsonAtomic(file, value) {
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  fs.renameSync(tmp, file);
}
function writeTextAtomic(file, text) {
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmp, text, { mode: 0o600, flag: 'wx' });
  fs.renameSync(tmp, file);
}
function readInput(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile()) throw new Error('입력 파일이 일반 파일이 아닙니다.');
  if (stat.size > 5 * 1024 * 1024) throw new Error('입력 파일이 5MB 를 넘습니다.');
  const text = fs.readFileSync(file, 'utf8').trim();
  try { return JSON.parse(text); } catch { throw new Error('JSON 이 아닙니다. 설명 문장 없이 JSON 만 넣어 주세요.'); }
}

function git(root, args) {
  try { return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 4 * 1024 * 1024 }).trim(); }
  catch { return null; }
}
function isGitRepo(root) { return git(root, ['rev-parse', '--is-inside-work-tree']) === 'true'; }
function gitIgnored(root, rel) {
  try { execFileSync('git', ['-C', root, 'check-ignore', '-q', rel], { stdio: 'ignore' }); return true; } catch { return false; }
}
function sourceRef(root) {
  const head = git(root, ['rev-parse', 'HEAD']);
  if (!head) return { commit: null, dirty: null };
  const status = git(root, ['status', '--porcelain', '--untracked-files=no']);
  return { commit: head, dirty: Boolean(status) };
}
function digestFile(root, rel) {
  try {
    const full = path.join(root, rel);
    const st = fs.lstatSync(full);
    if (!st.isFile()) return 'not-a-file';
    return crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
  } catch { return 'missing'; }
}

// ── 결과 폴더 ──
function repoKey(root) {
  const name = path.basename(root).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 40) || 'app';
  return `${name}-${crypto.createHash('sha256').update(path.resolve(root)).digest('hex').slice(0, 8)}`;
}
export function auditRoots(root) {
  return { inRepo: path.join(root, '.dorms-check', 'audit'), external: path.join(os.homedir(), '.dorms-check-audit', repoKey(root)) };
}
function isInside(parent, child) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}
// 점검 결과에는 약점 설명이 들어간다. 버전 관리에 올라가지 않는 곳에만 쓴다.
export function resolveOutputRoot(root, out) {
  const roots = auditRoots(root);
  if (out) {
    const abs = path.resolve(root, out);
    if (!isInside(root, abs)) return { dir: abs, why: '지정한 앱 폴더 밖 경로' };
    const rel = path.relative(root, abs);
    if (isGitRepo(root) && gitIgnored(root, rel + '/probe')) return { dir: abs, why: '지정한 경로(git 이 무시함)' };
    throw new Error('앱 폴더 안에 쓰려면 그 경로가 .gitignore 에 들어 있어야 합니다. 점검 결과에는 약점 설명이 담깁니다.');
  }
  if (!isGitRepo(root)) return { dir: roots.inRepo, why: 'git 저장소가 아니라 .dorms-check/audit 에 둡니다' };
  if (gitIgnored(root, '.dorms-check/audit/probe')) return { dir: roots.inRepo, why: '.dorms-check 가 .gitignore 에 있어 앱 폴더 안에 둡니다' };
  return { dir: roots.external, why: '.dorms-check 가 .gitignore 에 없어 앱 폴더 밖(홈 폴더)에 둡니다' };
}
function runNumbers(dir) {
  try { return fs.readdirSync(dir).map(n => /^run-(\d+)$/.exec(n)).filter(Boolean).map(m => Number(m[1])).sort((a, b) => a - b); }
  catch { return []; }
}
export function latestRunDir(root) {
  for (const dir of [auditRoots(root).inRepo, auditRoots(root).external]) {
    const nums = runNumbers(dir);
    if (nums.length) return path.join(dir, `run-${nums[nums.length - 1]}`);
  }
  return null;
}
export function resolveRunDir(root, runOpt) {
  const dir = runOpt ? path.resolve(root, runOpt) : latestRunDir(root);
  if (!dir || !fs.existsSync(path.join(dir, 'run-metadata.json'))) throw new Error('점검 회차를 찾지 못했습니다. 먼저 dcheck audit plan 을 실행하세요.');
  return dir;
}

export function loadRun(runDir) {
  const st = {};
  for (const f of RUN_FILES) st[f] = readJson(path.join(runDir, f), f === 'run-metadata.json' || f === 'verification.json' ? {} : []);
  st.architecture = (() => { try { return fs.readFileSync(path.join(runDir, 'architecture.md'), 'utf8'); } catch { return ''; } })();
  return st;
}
function saveLedger(runDir, ledger) {
  const errors = validateLedger(ledger);
  if (errors.length) throw new Error('범위표 검증 실패:\n- ' + errors.slice(0, 20).join('\n- '));
  writeJsonAtomic(path.join(runDir, 'coverage-ledger.json'), ledger);
}

// ── 이전 회차 이어받기 ──
function revalidationUnit(f, priorStatus, files, subsystem) {
  const refs = { surface: `prior/${f.fingerprint}`, boundary: 'boundary/prior-finding', subsystem, attack_class: 'audit/classes.js#revalidate' };
  return {
    coverage_id: coverageId(refs), canonical_refs: refs, surface: refs.surface, boundary: '이전 결과 다시 확인', subsystem,
    attack_class: '이전 결과 다시 확인', class_id: 'revalidate', source_ref: 'SKILL.md#Coverage and prior runs',
    starting_paths: files.slice(0, 40), starting_paths_total: files.length, prior_status: priorStatus, attempts: [], wave: 1,
    status: 'planned', agent_id: null, reviewed_paths: [], local_checks: [], result_fingerprints: [], unresolved: [],
    prior_fingerprint: f.fingerprint,
  };
}
function filesOf(f) {
  return [...new Set([...(f.trace || []), ...(f.evidence || [])].map(x => x.file).filter(isRepoRelative))].sort();
}
function applyPrior(root, ledger, priorDir, profile) {
  const info = { prior_run: null, carried: [], revalidate: [], exclusions: [], rejected_claims: [] };
  if (!priorDir) { for (const u of ledger) u.prior_status = 'none'; return info; }
  const prior = loadRun(priorDir);
  const digests = readJson(path.join(priorDir, 'source-digests.json'), {});
  const same = files => files.length > 0 && files.every(f => digests[f] && digests[f] === digestFile(root, f));
  info.prior_run = path.basename(priorDir);
  const subsystem = profile === 'quick' ? QUICK_SUBSYSTEM : '.';
  const byId = new Map(ledger.map(u => [u.coverage_id, u]));
  for (const f of prior['findings.json'] || []) {
    const files = filesOf(f);
    if (f.verdict === 'confirmed') {
      const unchanged = same(files);
      const u = revalidationUnit(f, unchanged ? 'prior_confirmed_same_source' : 'prior_confirmed_changed_source', files, subsystem);
      if (!byId.has(u.coverage_id)) { ledger.push(u); byId.set(u.coverage_id, u); }
      if (unchanged) { info.carried.push(f.fingerprint); info.exclusions.push(`${f.fingerprint}: ${f.title} (원인: ${f.root_cause})`); }
      else info.revalidate.push(f.fingerprint);
    } else if (f.verdict === 'needs_validation') {
      const u = revalidationUnit(f, 'prior_needs_validation', files, subsystem);
      if (!byId.has(u.coverage_id)) { ledger.push(u); byId.set(u.coverage_id, u); }
      info.revalidate.push(f.fingerprint);
    } else if (f.verdict === 'rejected' && same(files)) {
      info.rejected_claims.push(`${f.fingerprint}: ${f.title}`);
    }
  }
  const priorUnits = new Map((prior['coverage-ledger.json'] || []).map(u => [u.coverage_id, u]));
  for (const u of ledger) {
    if (u.class_id === 'revalidate') continue;
    const p = priorUnits.get(u.coverage_id);
    if (!p) { u.prior_status = 'new'; continue; }
    if (p.status === 'deferred') u.prior_status = 'prior_deferred';
    else if (p.status === 'blocked') u.prior_status = 'prior_blocked';
    else if (p.status === 'out_of_scope') u.prior_status = 'prior_out_of_scope';
    else if (p.status === 'covered' || p.status === 'candidate') u.prior_status = same(p.reviewed_paths || []) ? 'prior_covered_same_source' : 'prior_covered_changed_source';
    else u.prior_status = 'new';
  }
  return info;
}

// ── plan ──
function architectureSkeleton(meta, inventory) {
  const kinds = Object.entries(inventory.kinds).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k} ${n}`).join(', ');
  return [
    `# 앱 구조 요약 (${meta.repo})`,
    '',
    '> 부모(점검을 이끄는 AI)가 정찰 뒤 1,000 단어 안으로 채운다. 아래 자동 수집 사실은 지우지 말고 그 위에 보탠다.',
    '',
    '## 1. 제품·사용자·보호할 자원',
    '(누가 쓰는가: 교사·학생·관리자·로그인 안 한 사람. 무엇을 지켜야 하는가: 학생 개인정보, 성적, 운영자 API 요금 등)',
    '',
    '## 2. 기술 구성과 배포',
    '(프레임워크·DB·호스팅·외부 서비스. 저장소에서 확인한 것만)',
    '',
    '## 3. 진입 표면과 중요한 경로',
    `자동 수집: ${kinds || '없음'}`,
    '',
    '## 4. 신뢰 경계와 가장 강한 통제',
    '(경계마다 코드 위치 한 줄)',
    '',
    '## 5. 시작 경로',
    '',
    '## 6. 이전 점검의 빈칸',
    meta.prior.prior_run ? `이전 회차 ${meta.prior.prior_run}: 이어받은 확인 ${meta.prior.carried.length}건, 다시 볼 것 ${meta.prior.revalidate.length}건` : '이전 회차 없음(첫 점검).',
    '',
    '## 7. 분류 선택',
    '(audit/classes.js 분류 가운데 이 앱에서 고른 것과 이유, 뺀 것과 이유)',
    '',
  ].join('\n');
}

function hunterGroups(ledger, profile) {
  const planned = sortByPriority(ledger.filter(u => u.status === 'planned'));
  const byClass = new Map();
  for (const u of planned) {
    if (!byClass.has(u.class_id)) byClass.set(u.class_id, []);
    byClass.get(u.class_id).push(u);
  }
  const size = profile === 'quick' ? 1000 : profile === 'standard' ? 8 : 4;
  const groups = [];
  for (const [cls, units] of byClass) {
    for (let i = 0; i < units.length; i += size) groups.push({ class_id: cls, ids: units.slice(i, i + size).map(u => u.coverage_id) });
  }
  return groups.map((g, i) => ({ ...g, group: i + 1, suggested_agent: `h${String(i + 1).padStart(2, '0')}-${g.class_id}`.slice(0, 64) }));
}

function budgetEstimate(profile, hunters, budget) {
  const recon = 4;
  const critics = profile === 'quick' ? 1 : 2;
  const verifierReserve = Math.max(1, Math.ceil(hunters * (profile === 'quick' ? 0.5 : 1)));
  const planned = recon + hunters + critics + verifierReserve;
  return { recon, hunters, critics, verifier_reserve: verifierReserve, planned, budget: budget ?? null, fits: budget == null ? null : budget >= recon + critics + 1 };
}

function renderPlanMd(meta, ledger, groups) {
  const counts = ledgerCounts(ledger);
  const lines = [
    `# 심층 점검 계획 (${meta.run_id})`, '',
    `- 점검 깊이: ${meta.profile}${meta.profile === 'quick' ? ' (부분 점검: 찾기 한 차례 + 범위 비평 한 번)' : ''}`,
    `- 범위: ${meta.scope_paths.length ? meta.scope_paths.join(', ') : '저장소 전체'}`,
    `- 코드 기준: ${meta.source_ref.commit || '(git 아님)'}${meta.source_ref.dirty ? ' · 커밋 안 된 변경 있음' : ''}`,
    `- 결과 폴더: ${meta.output_dir} (${meta.output_reason})`,
    `- 범위표 단위: 예정 ${counts.planned} · 해당 없음 ${counts.not_applicable} · 범위 밖 ${counts.out_of_scope}`,
    `- 예상 에이전트 수: 정찰 ${meta.budget_estimate.recon} + 찾기 ${meta.budget_estimate.hunters} + 범위 비평 ${meta.budget_estimate.critics} + 반박 검증 예비 ${meta.budget_estimate.verifier_reserve} = ${meta.budget_estimate.planned}`,
  ];
  if (meta.budget != null) lines.push(`- 예산: ${meta.budget}${meta.budget_estimate.fits ? '' : ' · 정찰과 필수 비평·검증 예비도 못 채웁니다. 범위를 좁히거나 깊이를 낮추세요.'}`);
  lines.push('', '## 순서', '',
    '1. 정찰: architecture.md 를 채운다(1,000 단어 안). 앱 코드는 실행하지 않는다.',
    '2. 찾기: 아래 묶음마다 `dcheck audit prompt --role hunter --agent <ID> --group <번호>` 로 지시문을 받아 서로 다른 에이전트에게 맡긴다.',
    '3. 병합: 돌아온 JSON 을 `dcheck audit merge --agent <ID> --in <파일>` 로 범위표에 넣는다.',
    '4. 범위 비평: `dcheck audit prompt --role critic --agent <ID>` → 결과를 merge. standard·deep 은 빈칸이 없을 때까지 찾기·비평을 되풀이하고 마지막에 깨끗한 비평 한 번 더.',
    '5. 반박 검증: 후보마다 찾지 않은 새 에이전트에게 `dcheck audit prompt --role verifier --agent <ID> --fingerprint <지문>` → 결과를 `dcheck audit record --agent <ID> --in <파일>`.',
    '6. 최종 확인: quick 이 아니면 확인한 위험·미확인 기록마다 또 다른 새 에이전트가 기록을 다시 확인한다(같은 record 명령, decision: verified 또는 replace).',
    '7. `dcheck audit check` → `dcheck audit report`.',
    '', '## 찾기 묶음', '', '| 묶음 | 제안 ID | 분류 | 단위 수 |', '|---|---|---|---|');
  for (const g of groups) lines.push(`| ${g.group} | ${g.suggested_agent} | ${auditClass(g.class_id)?.title || g.class_id} | ${g.ids.length} |`);
  lines.push('', '## 원칙', '', ...CORE_PRINCIPLES.map(x => `- ${x}`));
  return lines.join('\n') + '\n';
}

export function planRun(root, { profile = 'standard', scope = [], out = null, budget = null, scanSummary = null } = {}) {
  if (!PROFILES.includes(profile)) throw new Error(`점검 깊이는 ${PROFILES.join('·')} 중 하나입니다.`);
  for (const s of scope) if (!isRepoRelative(s.replace(/\/$/, ''))) throw new Error(`--scope 는 앱 폴더 기준 상대 경로여야 합니다: ${s}`);
  const output = resolveOutputRoot(root, out);
  fs.mkdirSync(output.dir, { recursive: true, mode: 0o700 });
  const nums = runNumbers(output.dir);
  // 이어받는 기준은 보고서까지 마친(코드 지문을 남긴) 가장 최근 회차다. 중간에 멈춘 회차는 건너뛴다.
  const reported = nums.filter(k => fs.existsSync(path.join(output.dir, `run-${k}`, 'source-digests.json')));
  const priorDir = reported.length ? path.join(output.dir, `run-${reported[reported.length - 1]}`) : null;
  const n = (nums[nums.length - 1] || 0) + 1;
  const runDir = path.join(output.dir, `run-${n}`);
  fs.mkdirSync(runDir, { mode: 0o700 });
  fs.mkdirSync(path.join(runDir, 'agents'), { mode: 0o700 });

  const inventory = buildInventory(root, { scope: scope.map(s => s.replace(/\/$/, '')) });
  const ledger = buildLedger(inventory, { profile });
  const prior = applyPrior(root, ledger, priorDir, profile);
  ledger.sort((a, b) => a.coverage_id.localeCompare(b.coverage_id));
  const groups = hunterGroups(ledger, profile);
  const meta = {
    run_id: `run-${n}`, repo: path.basename(root), target: path.resolve(root), source_ref: sourceRef(root), profile, scope_paths: scope,
    budget: budget ?? null, execution_policy: 'sandboxed-source-and-local-only', tool: 'dorms-check audit',
    output_dir: runDir, output_reason: output.why, shared_file_owner: 'dcheck audit(부모)',
    prior, deterministic_scan: scanSummary, budget_estimate: budgetEstimate(profile, groups.length, budget),
    hunter_groups: groups, critic_passes: [], assignments: [], run_status: 'in_progress', created_at: new Date().toISOString(),
    excluded_classes: excludedClassesSummary(),
  };
  if (budget != null && !meta.budget_estimate.fits) { meta.run_status = 'incomplete'; meta.incomplete_reason = 'budget_cannot_fund_reconnaissance_and_reserves'; }
  saveLedger(runDir, ledger);
  writeJsonAtomic(path.join(runDir, 'run-metadata.json'), meta);
  writeJsonAtomic(path.join(runDir, 'inventory.json'), inventory);
  for (const f of ['candidates.json', 'findings.json', 'hardening.json']) writeJsonAtomic(path.join(runDir, f), []);
  writeJsonAtomic(path.join(runDir, 'verification.json'), {});
  writeTextAtomic(path.join(runDir, 'architecture.md'), architectureSkeleton(meta, inventory));
  writeTextAtomic(path.join(runDir, 'AUDIT-PLAN.md'), renderPlanMd(meta, ledger, groups));
  return { runDir, meta, ledger, inventory };
}

// ── 배정과 지시문 ──
function ensureAgentDirs(runDir, agentId) {
  const base = path.join(runDir, 'agents', agentId);
  for (const d of [base, path.join(base, 'scratch'), path.join(base, 'artifacts')]) {
    try { fs.mkdirSync(d, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
    const st = fs.lstatSync(d);
    if (!st.isDirectory() || st.isSymbolicLink()) throw new Error(`담당자 폴더가 일반 폴더가 아닙니다: ${d}`);
  }
}

export function huntPrompt(runDir, { agentId, unitIds = [], group = null }) {
  if (!isSafeAgentId(agentId)) throw new Error('담당자 ID 는 소문자·숫자·-_ 만, 64자 이하로 정하세요.');
  const st = loadRun(runDir);
  const meta = st['run-metadata.json'];
  const ledger = st['coverage-ledger.json'];
  let ids = unitIds;
  if (group != null) {
    const g = (meta.hunter_groups || []).find(x => x.group === Number(group));
    if (!g) throw new Error(`찾기 묶음 ${group} 이 없습니다.`);
    ids = g.ids;
  }
  if (!ids.length) throw new Error('--units 또는 --group 이 필요합니다.');
  const byId = new Map(ledger.map(u => [u.coverage_id, u]));
  const units = [];
  for (const id of ids) {
    const u = byId.get(id);
    if (!u) throw new Error(`범위표에 없는 단위: ${id}`);
    if (u.status === 'in_progress' && u.agent_id === agentId) { units.push(u); continue; }
    if (u.status !== 'planned') { if (group != null) continue; throw new Error(`예정(planned) 상태가 아닌 단위는 맡길 수 없습니다: ${id} (${u.status})`); }
    if ((u.attempts || []).some(a => a.agent_id === agentId)) throw new Error(`다시 맡긴 단위는 이전과 다른 담당자여야 합니다: ${id}`);
    u.status = 'in_progress';
    u.agent_id = agentId;
    units.push(u);
  }
  if (!units.length) throw new Error('맡길 예정 단위가 없습니다.');
  ensureAgentDirs(runDir, agentId);
  saveLedger(runDir, ledger);
  meta.assignments = [...(meta.assignments || []), { agent_id: agentId, role: 'hunter', units: units.map(u => u.coverage_id), at: new Date().toISOString() }];
  writeJsonAtomic(path.join(runDir, 'run-metadata.json'), meta);
  const peerIds = ledger.filter(u => u.status === 'in_progress' && u.agent_id !== agentId).map(u => u.coverage_id);
  return renderHunterPrompt({ agentId, units, architecture: st.architecture, runDir, exclusions: meta.prior?.exclusions || [], peerIds, rejectedClaims: meta.prior?.rejected_claims || [] });
}

export function verifierPrompt(runDir, { agentId, fingerprint }) {
  if (!isSafeAgentId(agentId)) throw new Error('담당자 ID 형식이 맞지 않습니다.');
  const st = loadRun(runDir);
  const cands = st['candidates.json'];
  let cand = cands.find(c => c.fingerprint === fingerprint);
  const ledger = st['coverage-ledger.json'];
  const findings = st['findings.json'];
  if (!cand) {
    const reval = ledger.find(u => u.prior_fingerprint === fingerprint);
    if (!reval) throw new Error(`후보 지문을 찾지 못했습니다: ${fingerprint}`);
    const priorFindings = readJson(path.join(path.dirname(runDir), st['run-metadata.json'].prior?.prior_run || '', 'findings.json'), []);
    cand = { fingerprint, found_by: null, proposed: priorFindings.find(f => f.fingerprint === fingerprint) || { fingerprint } };
  }
  if (cand.found_by === agentId) throw new Error('후보를 찾은 담당자는 그 후보를 검증할 수 없습니다. 새 담당자 ID 를 쓰세요.');
  if ((cand.verifiers || []).includes(agentId) && findings.some(f => f.fingerprint === fingerprint)) {
    // 최종 기록 확인(5단계)은 3단계 검증자와 다른 사람이 해야 한다.
    if (st['run-metadata.json'].profile !== 'quick') throw new Error('최종 기록 확인은 앞서 검증한 담당자와 다른 새 담당자가 해야 합니다.');
  }
  ensureAgentDirs(runDir, agentId);
  const linked = ledger.filter(u => (u.result_fingerprints || []).includes(fingerprint) || u.prior_fingerprint === fingerprint);
  const finalRecord = findings.find(f => f.fingerprint === fingerprint);
  const candidate = finalRecord ? { stage: '최종 기록 확인', record: finalRecord } : cand.proposed;
  return renderVerifierPrompt({ agentId, candidate, linkedUnits: linked, architecture: st.architecture, runDir, prior: null });
}

export function criticPrompt(runDir, { agentId }) {
  if (!isSafeAgentId(agentId)) throw new Error('담당자 ID 형식이 맞지 않습니다.');
  const st = loadRun(runDir);
  const cands = st['candidates.json'].map(c => ({ fingerprint: c.fingerprint, state: c.state }));
  return renderCriticPrompt({ agentId, ledger: st['coverage-ledger.json'], architecture: st.architecture, candidates: cands, profile: st['run-metadata.json'].profile });
}

// ── 병합 ──
function artifactOk(runDir, rel, agentId) {
  if (typeof rel !== 'string' || !rel.startsWith(`agents/${agentId}/artifacts/`) || !isRepoRelative(rel)) return false;
  let cur = runDir;
  for (const seg of rel.split('/')) {
    cur = path.join(cur, seg);
    let st;
    try { st = fs.lstatSync(cur); } catch { return false; }
    if (st.isSymbolicLink()) return false;
  }
  const st = fs.lstatSync(cur);
  return st.isFile() && st.nlink === 1 && st.size <= ARTIFACT_FILE_LIMIT;
}

function newUnitFromProposal(x, wave, status, unresolved = []) {
  const cls = auditClass(String(x.attack_class || '').replace(/^audit\/classes\.js#/, ''));
  if (!cls) throw new Error(`알 수 없는 분류: ${x.attack_class}`);
  const refs = { surface: String(x.surface || '').trim(), boundary: `boundary/${String(x.boundary || '').trim()}`, subsystem: String(x.subsystem || '').trim(), attack_class: `audit/classes.js#${cls.id}` };
  for (const v of Object.values(refs)) if (!isCleanRef(v) || v.length > 300) throw new Error('새 범위 단위의 참조 값이 올바르지 않습니다.');
  const paths = (x.starting_paths || []).filter(isRepoRelative).slice(0, 40);
  return {
    coverage_id: coverageId(refs), canonical_refs: refs, surface: refs.surface, boundary: String(x.boundary).trim(), subsystem: refs.subsystem,
    attack_class: cls.title, class_id: cls.id, source_ref: cls.cf, starting_paths: paths, starting_paths_total: paths.length,
    prior_status: 'new', attempts: [], wave, status, agent_id: null, reviewed_paths: [], local_checks: [], result_fingerprints: [], unresolved,
    proposed_reason: String(x.reason || '').slice(0, 500),
  };
}

export function mergeResult(runDir, { agentId, input }) {
  if (!isSafeAgentId(agentId)) throw new Error('담당자 ID 형식이 맞지 않습니다.');
  const st = loadRun(runDir);
  const meta = st['run-metadata.json'];
  const ledger = st['coverage-ledger.json'];
  const report = { accepted: [], reopened: [], candidates: 0, uncovered: 0, errors: [] };
  const maxWave = Math.max(1, ...ledger.map(u => u.wave || 1));
  const quick = meta.profile === 'quick';

  if (input && Array.isArray(input.missing_units)) {
    // 범위 비평 결과
    let added = 0, reassigned = 0;
    for (const x of input.missing_units) {
      try {
        const u = newUnitFromProposal(x, maxWave + 1, quick ? 'deferred' : 'planned', quick ? ['quick 점검: 범위 비평이 찾은 빈칸을 다음 점검으로 미룸'] : []);
        if (ledger.some(v => v.coverage_id === u.coverage_id)) continue;
        ledger.push(u); added++;
      } catch (e) { report.errors.push(`missing_units: ${e.message}`); }
    }
    for (const id of input.reassign_ids || []) {
      const u = ledger.find(v => v.coverage_id === id);
      if (!u || !['blocked', 'covered', 'candidate'].includes(u.status)) { report.errors.push(`reassign_ids: 다시 맡길 수 없는 단위 ${id}`); continue; }
      u.attempts = [...(u.attempts || []), { wave: u.wave, status: u.status, agent_id: u.agent_id, reviewed_paths: u.reviewed_paths, local_checks: u.local_checks,
        result_fingerprints: u.result_fingerprints, unresolved: u.unresolved, reassignment_reason: `범위 비평가 ${agentId} 가 근거가 부족하다고 보고 다시 맡김` }];
      Object.assign(u, { wave: Math.max(u.wave + 1, maxWave + 1), status: quick ? 'deferred' : 'planned', agent_id: null, reviewed_paths: [], local_checks: [], result_fingerprints: [],
        unresolved: quick ? ['quick 점검: 다시 맡길 단위를 다음 점검으로 미룸'] : [] });
      reassigned++;
    }
    ledger.sort((a, b) => a.coverage_id.localeCompare(b.coverage_id));
    saveLedger(runDir, ledger);
    meta.critic_passes = [...(meta.critic_passes || []), { agent_id: agentId, at: new Date().toISOString(), added, reassigned, stop: input.stop === true,
      clean: added === 0 && reassigned === 0, resolved_prior_leads: (input.resolved_prior_leads || []).slice(0, 200) }];
    writeJsonAtomic(path.join(runDir, 'run-metadata.json'), meta);
    return { kind: 'critic', added, reassigned, errors: report.errors };
  }

  if (!input || !Array.isArray(input.units)) throw new Error('찾기 결과(units 배열) 또는 범위 비평 결과(missing_units 배열)가 아닙니다.');
  const mine = ledger.filter(u => u.status === 'in_progress' && u.agent_id === agentId);
  const seen = new Set();
  const fpsInUnits = new Set();
  for (const r of input.units) {
    const u = mine.find(x => x.coverage_id === r?.coverage_id);
    if (!u) { report.errors.push(`맡지 않은 단위의 결과: ${r?.coverage_id}`); continue; }
    if (seen.has(u.coverage_id)) { report.errors.push(`같은 단위가 두 번 있습니다: ${u.coverage_id}`); continue; }
    seen.add(u.coverage_id);
    const trial = { ...u, status: r.disposition, reviewed_paths: r.reviewed_paths || [], local_checks: r.checks || [], result_fingerprints: r.candidate_fingerprints || [], unresolved: r.unresolved || [] };
    const errs = ['covered', 'candidate', 'blocked'].includes(r.disposition) ? validateLedger([trial]) : ['disposition 은 covered·candidate·blocked 중 하나여야 합니다.'];
    for (const c of trial.local_checks) if (c?.method === 'local' && !artifactOk(runDir, c.artifact, c.agent_id)) errs.push(`승격되지 않은 로컬 산출물: ${c.artifact}`);
    if (errs.length) { report.errors.push(`${u.coverage_id}: ${errs.slice(0, 3).join(' / ')}`); report.reopened.push(u.coverage_id); continue; }
    Object.assign(u, trial);
    if (Array.isArray(input.hardening) && input.hardening.length) u.hardening = [...new Set([...(u.hardening || []), ...input.hardening.map(String).slice(0, 50)])];
    for (const f of u.result_fingerprints) fpsInUnits.add(f);
    report.accepted.push(u.coverage_id);
  }
  // 결과가 없거나 거부된 단위는 다시 맡길 수 있게 예정으로 돌린다.
  for (const u of mine) {
    if (report.accepted.includes(u.coverage_id)) continue;
    u.status = 'planned'; u.agent_id = null;
    if (!report.reopened.includes(u.coverage_id)) report.reopened.push(u.coverage_id);
  }
  const cands = st['candidates.json'];
  for (const [i, c] of (input.candidates || []).entries()) {
    const errs = validateFinding(c, `candidates[${i}]`, { mode: 'candidate' });
    if (!fpsInUnits.has(c?.fingerprint)) errs.push(`candidates[${i}]: 받아들인 단위의 candidate_fingerprints 에 없는 지문입니다.`);
    if (errs.length) { report.errors.push(...errs.slice(0, 5)); continue; }
    const existing = cands.find(x => x.fingerprint === c.fingerprint);
    const unitIds = ledger.filter(u => (u.result_fingerprints || []).includes(c.fingerprint)).map(u => u.coverage_id);
    if (existing) { existing.units = [...new Set([...existing.units, ...unitIds])]; existing.duplicates = (existing.duplicates || 0) + 1; }
    else cands.push({ fingerprint: c.fingerprint, state: 'unvalidated', found_by: agentId, units: unitIds, proposed: c, verifiers: [] });
    report.candidates++;
  }
  for (const x of input.uncovered || []) {
    try {
      const u = newUnitFromProposal(x, maxWave + 1, quick ? 'deferred' : 'planned', quick ? ['quick 점검: 찾는 중 발견한 새 경계를 다음 점검으로 미룸'] : []);
      if (!ledger.some(v => v.coverage_id === u.coverage_id)) { ledger.push(u); report.uncovered++; }
    } catch (e) { report.errors.push(`uncovered: ${e.message}`); }
  }
  ledger.sort((a, b) => a.coverage_id.localeCompare(b.coverage_id));
  saveLedger(runDir, ledger);
  cands.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
  writeJsonAtomic(path.join(runDir, 'candidates.json'), cands);
  const hard = st['hardening.json'];
  for (const h of input.hardening || []) if (typeof h === 'string' && h.trim()) hard.push({ agent_id: agentId, note: h.slice(0, 1000), units: report.accepted });
  writeJsonAtomic(path.join(runDir, 'hardening.json'), hard);
  return { kind: 'hunter', ...report };
}

// ── 반박 검증 기록 ──
const MATERIAL_KEYS = ['verdict', 'root_cause', 'claimed_root_cause', 'trace', 'execution', 'severity'];
function isMaterialChange(a, b) {
  return MATERIAL_KEYS.some(k => JSON.stringify(a?.[k] ?? null) !== JSON.stringify(b?.[k] ?? null));
}
const VERDICT_STRENGTH = { rejected: 0, needs_validation: 1, confirmed: 2 };

export function recordDecision(runDir, { agentId, input }) {
  if (!isSafeAgentId(agentId)) throw new Error('담당자 ID 형식이 맞지 않습니다.');
  const st = loadRun(runDir);
  const meta = st['run-metadata.json'];
  const ledger = st['coverage-ledger.json'];
  const cands = st['candidates.json'];
  const findings = st['findings.json'];
  const verification = st['verification.json'];
  const list = Array.isArray(input) ? input : [input];
  const out = { applied: [], pending: [], errors: [] };

  for (const [i, d] of list.entries()) {
    const label = `decisions[${i}]`;
    if (!d || typeof d !== 'object') { out.errors.push(`${label}: 객체가 아닙니다.`); continue; }
    const fp = d.fingerprint || d.record?.fingerprint;
    const cand = cands.find(c => c.fingerprint === fp);
    const reval = ledger.find(u => u.prior_fingerprint === fp);
    if (!cand && !reval) { out.errors.push(`${label}: 이 회차의 후보·이어받은 기록이 아닌 지문입니다(${fp}).`); continue; }
    if (cand && cand.found_by === agentId) { out.errors.push(`${label}: 찾은 담당자는 자기 후보를 검증할 수 없습니다.`); continue; }
    const v = verification[fp] || { phase3: null, phase5: [], pending_replacement: null };

    if (['confirmed', 'needs_validation', 'rejected'].includes(d.decision)) {
      const rec = d.record;
      if (!rec || rec.verdict !== d.decision) { out.errors.push(`${label}: record.verdict 가 decision 과 같아야 합니다.`); continue; }
      const errs = validateFinding(rec, `${label}.record`);
      if (rec.fingerprint !== fp) errs.push(`${label}: 같은 원인이면 지문을 바꾸지 않습니다.`);
      if (errs.length) { out.errors.push(...errs.slice(0, 6)); continue; }
      if (v.phase3) { out.errors.push(`${label}: 이미 반박 검증한 후보입니다. 최종 확인은 decision: verified 또는 replace 로 보냅니다.`); continue; }
      const idx = findings.findIndex(f => f.fingerprint === fp);
      if (idx >= 0) findings[idx] = rec; else findings.push(rec);
      v.phase3 = { agent_id: agentId, decision: d.decision, at: new Date().toISOString() };
      if (cand) { cand.state = d.decision; cand.verifiers = [...new Set([...(cand.verifiers || []), agentId])]; }
      if (reval && ['planned', 'in_progress'].includes(reval.status)) {
        const files = filesOf(rec);
        Object.assign(reval, { status: 'candidate', agent_id: agentId, reviewed_paths: files, result_fingerprints: [fp], unresolved: [],
          local_checks: [{ agent_id: agentId, reviewed_paths: files, invariant: '이전 결과가 지금 코드에서도 성립하는가', method: 'source', result: `${VERDICT_LABEL[d.decision]}로 판정`, artifact: null }] });
      }
      for (const u of ledger) if ((u.result_fingerprints || []).includes(fp)) u.decisions = { ...(u.decisions || {}), [fp]: d.decision };
      out.applied.push(fp);
    } else if (d.decision === 'verified' || d.decision === 'replace') {
      const current = findings.find(f => f.fingerprint === fp);
      if (!current) { out.errors.push(`${label}: 최종 기록이 아직 없습니다. 먼저 반박 검증을 기록하세요.`); continue; }
      const used = new Set([cand?.found_by, v.phase3?.agent_id, ...(v.phase5 || []).map(x => x.agent_id), v.pending_replacement?.proposed_by].filter(Boolean));
      if (meta.profile !== 'quick' && used.has(agentId)) { out.errors.push(`${label}: 최종 확인은 앞서 찾거나 검증한 적 없는 새 담당자가 해야 합니다.`); continue; }
      if (d.decision === 'verified') {
        if (v.pending_replacement) {
          const idx = findings.findIndex(f => f.fingerprint === fp);
          findings[idx] = v.pending_replacement.record;
          v.phase5.push({ agent_id: agentId, decision: 'verified-replacement', at: new Date().toISOString() });
          v.pending_replacement = null;
        } else v.phase5.push({ agent_id: agentId, decision: 'verified', at: new Date().toISOString() });
        out.applied.push(fp);
      } else {
        const rec = d.record;
        const errs = rec ? validateFinding(rec, `${label}.record`) : [`${label}: replace 에는 record 가 필요합니다.`];
        if (!d.reason || !String(d.reason).trim()) errs.push(`${label}: replace 에는 reason 이 필요합니다.`);
        if (errs.length) { out.errors.push(...errs.slice(0, 6)); continue; }
        const stronger = VERDICT_STRENGTH[rec.verdict] > VERDICT_STRENGTH[current.verdict];
        if (stronger || isMaterialChange(current, rec)) {
          // 뜻이 바뀌는 교체는 또 다른 새 담당자의 확인을 받은 뒤에만 적용한다.
          v.pending_replacement = { record: rec, reason: String(d.reason).slice(0, 1000), proposed_by: agentId, at: new Date().toISOString() };
          out.pending.push(fp);
        } else {
          const idx = findings.findIndex(f => f.fingerprint === fp);
          findings[idx] = rec;
          v.phase5.push({ agent_id: agentId, decision: 'minor-correction', at: new Date().toISOString() });
          out.applied.push(fp);
        }
      }
    } else out.errors.push(`${label}.decision: confirmed·needs_validation·rejected·verified·replace 중 하나여야 합니다.`);
    verification[fp] = v;
  }
  const fErrs = validateFindings(findings);
  if (fErrs.length) throw new Error('findings.json 검증 실패:\n- ' + fErrs.slice(0, 20).join('\n- '));
  findings.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
  writeJsonAtomic(path.join(runDir, 'findings.json'), findings);
  writeJsonAtomic(path.join(runDir, 'candidates.json'), cands);
  writeJsonAtomic(path.join(runDir, 'verification.json'), verification);
  saveLedger(runDir, ledger);
  return out;
}

// ── 산출물 승격(부모만) ──
export function promoteArtifact(runDir, { agentId, file }) {
  if (!isSafeAgentId(agentId)) throw new Error('담당자 ID 형식이 맞지 않습니다.');
  if (!isRepoRelative(file)) throw new Error('scratch 기준 상대 경로만 승격합니다.');
  const scratch = path.join(runDir, 'agents', agentId, 'scratch');
  const artifacts = path.join(runDir, 'agents', agentId, 'artifacts');
  for (const d of [scratch, artifacts]) { const s = fs.lstatSync(d); if (!s.isDirectory() || s.isSymbolicLink()) throw new Error('담당자 폴더가 올바르지 않습니다.'); }
  const segs = file.split('/');
  let cur = scratch;
  for (const seg of segs.slice(0, -1)) { cur = path.join(cur, seg); const s = fs.lstatSync(cur); if (!s.isDirectory() || s.isSymbolicLink()) throw new Error('경로 중간에 폴더가 아닌 것이 있습니다.'); }
  const src = path.join(scratch, file);
  const O = fs.constants;
  const fd = fs.openSync(src, O.O_RDONLY | (O.O_NOFOLLOW || 0) | (O.O_NONBLOCK || 0));
  let buf;
  try {
    const a = fs.fstatSync(fd);
    if (!a.isFile() || a.nlink !== 1) throw new Error('일반 파일(링크 1개)만 승격합니다.');
    if (a.size > ARTIFACT_FILE_LIMIT) throw new Error('파일당 1MB 를 넘습니다.');
    const used = dirSize(artifacts);
    if (used + a.size > ARTIFACT_TOTAL_LIMIT) throw new Error('담당자 산출물 합계가 5MB 를 넘습니다.');
    buf = Buffer.alloc(a.size);
    let off = 0;
    while (off < a.size) { const n = fs.readSync(fd, buf, off, a.size - off, off); if (n <= 0) break; off += n; }
    const b = fs.fstatSync(fd);
    if (off !== a.size || b.size !== a.size || b.ino !== a.ino || b.nlink !== 1 || b.mtimeMs !== a.mtimeMs) throw new Error('읽는 동안 파일이 바뀌었습니다.');
  } finally { fs.closeSync(fd); }
  let dest = artifacts;
  for (const seg of segs.slice(0, -1)) {
    dest = path.join(dest, seg);
    try { fs.mkdirSync(dest, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
    const s = fs.lstatSync(dest);
    if (!s.isDirectory() || s.isSymbolicLink()) throw new Error('산출물 폴더가 올바르지 않습니다.');
  }
  const out = fs.openSync(path.join(artifacts, file), O.O_WRONLY | O.O_CREAT | O.O_EXCL | (O.O_NOFOLLOW || 0), 0o600);
  try {
    fs.writeSync(out, buf);
    const s = fs.fstatSync(out);
    if (!s.isFile() || s.nlink !== 1) throw new Error('승격한 파일 확인에 실패했습니다.');
  } finally { fs.closeSync(out); }
  return `agents/${agentId}/artifacts/${file}`;
}
function dirSize(dir) {
  let total = 0;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) total += dirSize(p); else if (e.isFile()) total += fs.lstatSync(p).size;
  }
  return total;
}

// ── 점검과 보고 ──
export function checkRun(runDir) {
  const st = loadRun(runDir);
  const meta = st['run-metadata.json'];
  const ledger = st['coverage-ledger.json'];
  const findings = st['findings.json'];
  const cands = st['candidates.json'];
  const verification = st['verification.json'];
  const errors = [...validateLedger(ledger), ...validateFindings(findings)];
  const reasons = [];
  const ledgerFps = new Set(ledger.flatMap(u => u.result_fingerprints || []));
  for (const fp of ledgerFps) if (!cands.some(c => c.fingerprint === fp) && !ledger.some(u => u.prior_fingerprint === fp)) errors.push(`범위표의 후보 지문 ${fp} 가 candidates.json 에 없습니다.`);
  for (const f of findings) if (!cands.some(c => c.fingerprint === f.fingerprint) && !ledger.some(u => u.prior_fingerprint === f.fingerprint)) errors.push(`기록 ${f.fingerprint} 이 이 회차 후보가 아닙니다.`);
  const unvalidated = cands.filter(c => c.state === 'unvalidated').map(c => c.fingerprint);
  if (unvalidated.length) reasons.push(`반박 검증을 받지 못한 후보 ${unvalidated.length}건: ${unvalidated.join(', ')}`);
  const carried = ledger.filter(u => u.class_id === 'revalidate' && ['planned', 'in_progress'].includes(u.status)).map(u => u.prior_fingerprint);
  if (carried.length) reasons.push(`이어받은 이전 기록 중 다시 확인하지 못한 것 ${carried.length}건: ${carried.join(', ')}`);
  if (meta.profile !== 'quick') {
    const missing5 = findings.filter(f => f.verdict !== 'rejected' && !(verification[f.fingerprint]?.phase5 || []).some(x => x.decision !== 'minor-correction')).map(f => f.fingerprint);
    if (missing5.length) reasons.push(`최종 기록 확인이 없는 기록 ${missing5.length}건: ${missing5.join(', ')}`);
  }
  const pending = Object.entries(verification).filter(([, v]) => v.pending_replacement).map(([fp]) => fp);
  if (pending.length) reasons.push(`새 담당자 확인을 기다리는 교체 ${pending.length}건: ${pending.join(', ')}`);
  const live = ledger.filter(u => ['planned', 'in_progress'].includes(u.status) && u.class_id !== 'revalidate');
  if (live.length) reasons.push(`아직 맡기지 않았거나 진행 중인 범위 단위 ${live.length}개`);
  const critics = meta.critic_passes || [];
  if (!critics.length) reasons.push('범위 비평을 한 번도 받지 않았습니다.');
  else if (meta.profile !== 'quick' && !critics[critics.length - 1].clean) reasons.push('마지막 범위 비평이 빈칸을 찾았습니다. 찾기와 비평을 한 번 더 하세요.');
  if (meta.incomplete_reason) reasons.push(`계획 단계: ${meta.incomplete_reason}`);
  return { errors: errors.slice(0, 100), reasons, complete: errors.length === 0 && reasons.length === 0, counts: ledgerCounts(ledger) };
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
const cell = s => String(s ?? '').replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' ').slice(0, 300);

export function renderAuditReport(st, chk) {
  const meta = st['run-metadata.json'];
  const ledger = st['coverage-ledger.json'];
  const findings = st['findings.json'];
  const confirmed = findings.filter(f => f.verdict === 'confirmed').sort((a, b) => SEV_ORDER[a.severity.overall_severity] - SEV_ORDER[b.severity.overall_severity]);
  const needs = findings.filter(f => f.verdict === 'needs_validation');
  const rejected = findings.filter(f => f.verdict === 'rejected');
  const partial = meta.profile === 'quick' || meta.scope_paths?.length || !chk.complete;
  const L = [];
  L.push(`# 심층 보안 점검 보고서 (${meta.repo} · ${meta.run_id})`, '');
  L.push(`- 점검 깊이: ${meta.profile}${meta.scope_paths?.length ? ` · 범위 ${meta.scope_paths.join(', ')}` : ' · 저장소 전체'}`);
  L.push(`- 코드 기준: ${meta.source_ref?.commit || '(git 아님)'}${meta.source_ref?.dirty ? ' · 커밋 안 된 변경 포함' : ''}`);
  L.push('- 실행 방식: 코드 읽기와 내 컴퓨터 안의 작은 확인만 했습니다. 배포된 서버에 공격 요청을 보내지 않았습니다.');
  L.push(`- 이전 점검: ${meta.prior?.prior_run ? `${meta.prior.prior_run} 이어받음 (그대로인 확인 ${meta.prior.carried.length}건, 다시 본 것 ${meta.prior.revalidate.length}건)` : '없음. 첫 점검입니다.'}`);
  if (meta.budget != null) L.push(`- 예산: 에이전트 ${meta.budget}회 (계획 ${meta.budget_estimate?.planned}회)`);
  L.push(`- 진행 상태: ${chk.complete ? '완료' : '미완료'}`);
  if (partial) L.push('', '> 이번 점검은 부분 점검입니다. 아래 "범위 요약"의 미룸·범위 밖 항목은 보지 않았거나 덜 봤습니다. 한 번의 점검으로 전체가 안전하다고 말할 수 없고, 같은 저장소를 다시 점검하면 이번 빈칸부터 이어서 봅니다.');
  if (!chk.complete) L.push('', '미완료 이유:', ...chk.reasons.map(r => `- ${r}`));
  L.push('', '## 한 줄 요약', '');
  const bySev = confirmed.reduce((m, f) => ({ ...m, [f.severity.overall_severity]: (m[f.severity.overall_severity] || 0) + 1 }), {});
  L.push(confirmed.length
    ? `확인한 위험 ${confirmed.length}건(${Object.entries(bySev).map(([k, n]) => `${SEVERITY_LABEL[k]} ${n}`).join(', ')}), 확인이 더 필요한 것 ${needs.length}건입니다.`
    : `확인한 위험은 없습니다. 확인이 더 필요한 것 ${needs.length}건이 남았습니다. 위험이 없다는 뜻이 아니라 이번 범위에서 증거로 확인된 것이 없다는 뜻입니다.`);
  L.push('', `## 확인한 위험 (${confirmed.length}건)`, '');
  if (confirmed.length) {
    L.push('| 심각도 | 제목 | 넘은 경계 | 관찰한 결과 |', '|---|---|---|---|');
    for (const f of confirmed) L.push(`| ${SEVERITY_LABEL[f.severity.overall_severity]} | ${cell(f.title)} | ${cell(f.trace[f.trace.length - 1].scope)} | ${cell(f.execution.observed_result)} |`);
    for (const f of confirmed) {
      L.push('', `### ${f.title}`, '', `- 지문: \`${f.fingerprint}\``, `- 위치: ${f.trace.map(t => `${t.file}:${t.line}`).join(' → ')}`,
        `- 누가: ${f.execution.attacker_perspective}`, `- 조건: ${f.conditions.length ? f.conditions.map(c => c.description).join(' / ') : '특별한 조건 없음'}`,
        `- 로컬 재현: ${f.execution.instructions.join(' → ')}`, `- 관찰한 결과: ${f.execution.observed_result}`,
        `- 영향: ${f.severity.impact.reason}`, `- 우선순위 이유: 가능성 ${SEVERITY_LABEL[f.severity.likelihood.score]}(${f.severity.likelihood.reason})`,
        `- 원인: ${f.root_cause}`, `- 가장 작은 수정: ${f.remediation.strategy}`);
    }
  } else L.push('없음.');
  L.push('', `## 확인이 더 필요한 것 (${needs.length}건, 심각도 없음)`, '');
  if (needs.length) {
    L.push('| 제목 | 코드 경로 | 막힌 사실 | 내 컴퓨터에서 확인 | 운영자가 직접 확인 |', '|---|---|---|---|---|');
    for (const f of needs) L.push(`| ${cell(f.title)} | ${cell(f.trace.map(t => `${t.file}:${t.line}`).join(' → '))} | ${cell(f.blockers.join(' / '))} | ${cell(f.validation_plan.local || '-')} | ${cell(f.validation_plan.deployment || '-')} |`);
  } else L.push('없음.');
  const hardening = [...new Set((st['hardening.json'] || []).map(h => h.note))];
  L.push('', `## 권고 (위험은 아님, ${hardening.length}건)`, '', ...(hardening.length ? hardening.map(h => `- ${h}`) : ['없음.']));
  const c = chk.counts;
  L.push('', '## 범위 요약', '', `- 본 단위 ${c.covered} · 후보가 나온 단위 ${c.candidate} · 막힌 단위 ${c.blocked} · 미룸 ${c.deferred} · 범위 밖 ${c.out_of_scope} · 해당 없음 ${c.not_applicable} · 남은 예정·진행 ${c.planned + c.in_progress}`);
  const lastCritic = (meta.critic_passes || []).slice(-1)[0];
  L.push(`- 마지막 범위 비평: ${lastCritic ? (lastCritic.clean ? `${lastCritic.agent_id}, 새 빈칸 없음` : `${lastCritic.agent_id}, 빈칸 ${lastCritic.added}개·다시 맡김 ${lastCritic.reassigned}개`) : '받지 않음'}`);
  const gaps = ledger.filter(u => ['deferred', 'blocked', 'out_of_scope'].includes(u.status)).slice(0, 30);
  if (gaps.length) L.push('', '못 보거나 막힌 범위(최대 30개):', ...gaps.map(u => `- [${u.status}] ${u.attack_class} · ${u.surface} · ${u.subsystem}: ${(u.unresolved || []).join(' / ')}`));
  L.push('', '뺀 분류:', ...(meta.excluded_classes || []).map(x => `- ${x.ref}: ${x.reason}`));
  if (rejected.length) L.push('', `## 기각한 주장 (${rejected.length}건)`, '', '다음 점검이 근거 없이 같은 주장을 반복하지 않도록 지문만 남깁니다: ' + rejected.map(f => `\`${f.fingerprint}\``).join(', '));
  L.push('', '---', '이 점검의 흐름과 분류 일부는 cloudflare/security-audit-skill(MIT)을 한국어로 옮겨 교사 앱에 맞게 고친 것입니다.');
  return L.join('\n') + '\n';
}

export function reportRun(root, runDir) {
  const chk = checkRun(runDir);
  const st = loadRun(runDir);
  const meta = st['run-metadata.json'];
  const files = new Set();
  for (const f of st['findings.json']) for (const p of filesOf(f)) files.add(p);
  for (const u of st['coverage-ledger.json']) for (const p of u.reviewed_paths || []) files.add(p);
  const digests = {};
  for (const p of [...files].sort()) digests[p] = digestFile(root, p);
  writeJsonAtomic(path.join(runDir, 'source-digests.json'), digests);
  meta.run_status = chk.complete ? 'complete' : 'incomplete';
  meta.incomplete_reasons = chk.reasons;
  meta.reported_at = new Date().toISOString();
  writeJsonAtomic(path.join(runDir, 'run-metadata.json'), meta);
  const md = renderAuditReport(st, chk);
  writeTextAtomic(path.join(runDir, 'AUDIT.md'), md);
  return { chk, md, meta };
}

export function latestAuditSummary(root) {
  const dir = latestRunDir(root);
  if (!dir) return null;
  const st = loadRun(dir);
  const f = st['findings.json'] || [];
  return {
    runDir: dir, run_status: st['run-metadata.json'].run_status, profile: st['run-metadata.json'].profile,
    confirmed: f.filter(x => x.verdict === 'confirmed').map(x => ({ title: x.title, severity: x.severity.overall_severity })),
    needs_validation: f.filter(x => x.verdict === 'needs_validation').map(x => x.title),
  };
}

export { AUDIT_CLASSES };

import runtime from './strict-runtime.cjs';
import fs from 'node:fs';
import path from 'node:path';
import { SECURITY_ITEMS } from '../catalog/security.js';
import { SEVERITY_RANK } from './tracks.js';

export const STRICT_EXIT = runtime.EXIT;
export const STRICT_GATE_SCHEMA = runtime.GATE_SCHEMA;
export const STRICT_RUNTIME_DIGEST = runtime.RUNTIME_DIGEST;
export const SUPPORTED_VERCEL_CLI_VERSION = runtime.SUPPORTED_VERCEL_CLI_VERSION;
export const {
  projectIdentity,
  normalizeDeploymentUrl,
  createReceipt,
  storeReceipt,
  invalidateReceipt,
  verifyCodeGate,
  verifyGate,
  evaluateVercelCommand,
  verifyVercelCliVersion,
} = runtime;

const LIVE_NA_ALLOWED = new Set([
  'code.rls.anon-read',
  'code.firebase.public-read',
]);

function liveRequiredIds() {
  return SECURITY_ITEMS
    .filter(item => item.gate && item.serverVerifiable && SEVERITY_RANK[item.severity] >= SEVERITY_RANK.high)
    .map(item => item.id);
}

export function strictRequiredIds(phase) {
  const catalogRequired = phase === 'live'
    ? [...new Set([...runtime.REQUIRED_BY_PHASE.code, ...liveRequiredIds()])]
    : [...runtime.REQUIRED_BY_PHASE.code];
  const runtimeRequired = runtime.REQUIRED_BY_PHASE[phase] || runtime.REQUIRED_BY_PHASE.code;
  if ([...catalogRequired].sort().join('\n') !== [...runtimeRequired].sort().join('\n')) {
    throw new Error(`strict runtime required list is out of sync for ${phase}`);
  }
  return [...runtimeRequired];
}

function statusOf(result) {
  if (!result) return 'missing';
  return String(result.status || 'missing').toLowerCase();
}

export function evaluateStrictSecurity(results, phase) {
  const byId = new Map();
  for (const result of results || []) {
    if (result?.id) byId.set(result.id, result);
  }
  const expected = strictRequiredIds(phase);
  const blockers = [];
  const incomplete = [];
  for (const id of expected) {
    const result = byId.get(id);
    const status = statusOf(result);
    if (status === 'fail') blockers.push(id);
    else if (status === 'pass') continue;
    else if (status === 'na' && phase === 'live' && LIVE_NA_ALLOWED.has(id) && result?.evidence?.providerDetected === false) continue;
    else incomplete.push(id);
  }
  const status = blockers.length ? 'SECURITY_BLOCKED' : (incomplete.length ? 'INCOMPLETE' : 'PASS');
  return {
    status,
    expected,
    observed: expected.filter(id => byId.has(id)),
    blockers,
    incomplete,
    exitCode: status === 'PASS' ? STRICT_EXIT.PASS : (status === 'SECURITY_BLOCKED' ? STRICT_EXIT.SECURITY_BLOCKED : STRICT_EXIT.INCOMPLETE),
  };
}

function parseInspectJson(stdout) {
  try {
    const value = JSON.parse(String(stdout || ''));
    return value && !Array.isArray(value) && typeof value === 'object' ? value : null;
  } catch {
    return null;
  }
}

function readLinkedVercelProject(cwd) {
  const file = path.join(cwd, '.vercel', 'project.json');
  let linked;
  try { linked = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: '.vercel/project.json을 읽지 못했습니다. 이 앱 폴더에서 vercel link를 완료하세요.' };
  }
  const projectId = String(linked?.projectId || '').trim();
  const orgId = String(linked?.orgId || '').trim();
  const projectName = String(linked?.projectName || '').trim();
  if (!/^[A-Za-z0-9_-]+$/.test(projectId) || !/^[A-Za-z0-9_-]+$/.test(orgId)) {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: '.vercel/project.json에 projectId와 orgId가 모두 있어야 합니다.' };
  }
  return { ok: true, projectId, orgId, projectName };
}

function uniqueStrings(values) {
  return [...new Set(values.filter(value => typeof value === 'string').map(value => value.trim()).filter(Boolean))];
}

function inspectedDeploymentBinding(inspected) {
  const shapes = [inspected, inspected?.deployment].filter(value => value && typeof value === 'object');
  return {
    githubDeployments: uniqueStrings(shapes.flatMap(value => [value.meta?.githubDeployment])),
    githubCommitShas: uniqueStrings(shapes.flatMap(value => [value.meta?.githubCommitSha])),
    gitSourceShas: uniqueStrings(shapes.flatMap(value => [value.gitSource?.sha])),
    additionalSourceGitShas: uniqueStrings(shapes.flatMap(value => [value.gitMetadata?.commitSha])),
    projectIds: uniqueStrings(shapes.flatMap(value => [value.projectId, value.project?.id])),
    orgIds: uniqueStrings(shapes.flatMap(value => [value.orgId, value.teamId, value.ownerId, value.team?.id])),
    projectNames: uniqueStrings(shapes.flatMap(value => [value.projectName, value.project?.name])),
  };
}

export function inspectVercelDeployment({ cwd, deployment, url, gitSha }, options = {}) {
  const reference = String(deployment || '').trim();
  if (!reference) {
    return { ok: false, exitCode: STRICT_EXIT.USAGE_CONFIG, reason: 'Vercel 배포 URL 또는 ID가 필요합니다.' };
  }
  if (!/^https?:\/\//i.test(reference) && !/^dpl_[A-Za-z0-9]+$/.test(reference)) {
    return { ok: false, exitCode: STRICT_EXIT.USAGE_CONFIG, reason: 'Vercel 배포 ID는 dpl_로 시작해야 합니다. 가능하면 배포 URL을 그대로 쓰세요.' };
  }
  if (!/^[a-f0-9]{40}$/i.test(String(gitSha || ''))) {
    return { ok: false, exitCode: STRICT_EXIT.USAGE_CONFIG, reason: 'Vercel 배포 아티팩트를 확인할 현재 Git SHA 40자리가 필요합니다.' };
  }

  const linked = readLinkedVercelProject(cwd);
  if (!linked.ok) return linked;

  const cliVersion = runtime.verifyVercelCliVersion({ cwd }, options);
  if (!cliVersion.ok) return cliVersion;

  let requestedUrl;
  try { requestedUrl = normalizeDeploymentUrl(url); }
  catch (error) { return { ok: false, exitCode: STRICT_EXIT.USAGE_CONFIG, reason: error.message }; }

  let deploymentUrl = '';
  if (/^https?:\/\//i.test(reference)) {
    try { deploymentUrl = normalizeDeploymentUrl(reference); }
    catch (error) { return { ok: false, exitCode: STRICT_EXIT.USAGE_CONFIG, reason: `--vercel-deployment URL이 올바르지 않습니다: ${error.message}` }; }
    if (deploymentUrl !== requestedUrl) {
      return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: '--vercel-deployment URL과 --url은 정확히 같은 staged 배포여야 합니다.' };
    }
  }

  let stdout;
  const inspectReference = /^dpl_/i.test(reference) ? reference : new URL(deploymentUrl).hostname;
  try {
    stdout = runtime.runVercelCli(['inspect', inspectReference, '--format=json', '--non-interactive'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }, options);
  } catch (error) {
    const hint = error?.code === 'ENOENT'
      ? 'Vercel CLI가 없습니다. Vercel CLI를 설치하고 로그인한 뒤 다시 검사하세요.'
      : 'Vercel CLI 로그인, 프로젝트 연결, 배포 상태를 확인한 뒤 다시 검사하세요.';
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: `Vercel 배포 정보를 확인하지 못했습니다. ${hint}` };
  }

  const inspected = parseInspectJson(stdout);
  if (!inspected || typeof inspected.id !== 'string' || typeof inspected.url !== 'string') {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'vercel inspect --format=json 결과에서 배포 ID와 URL을 확인하지 못했습니다. Vercel CLI를 최신 버전으로 업데이트하세요.' };
  }
  let inspectedUrl;
  try { inspectedUrl = normalizeDeploymentUrl(inspected.url); }
  catch { return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'Vercel이 돌려준 배포 URL 형식이 올바르지 않습니다.' }; }
  if (!/^dpl_[A-Za-z0-9]+$/.test(inspected.id)) {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'Vercel이 돌려준 배포 ID 형식이 올바르지 않습니다.' };
  }
  if (requestedUrl !== inspectedUrl) {
    return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: '--url이 Vercel에서 확인한 배포 URL과 다릅니다.' };
  }
  if (/^dpl_/i.test(reference) && reference !== inspected.id) {
    return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: '--vercel-deployment ID가 Vercel에서 확인한 배포 ID와 다릅니다.' };
  }
  if (String(inspected.readyState || '').toUpperCase() !== 'READY') {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: `Vercel 배포가 READY 상태가 아닙니다: ${inspected.readyState || 'unknown'}` };
  }
  if (String(inspected.target || '').toLowerCase() !== 'production') {
    return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: '검사 대상은 vercel --prod --skip-domain으로 만든 staged production 배포여야 합니다.' };
  }

  let rawStdout;
  const rawEndpoint = `/v13/deployments/${encodeURIComponent(inspected.id)}?teamId=${encodeURIComponent(linked.orgId)}`;
  try {
    rawStdout = runtime.runVercelCli(['api', rawEndpoint, '--non-interactive'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }, options);
  } catch {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'Vercel 배포 metadata를 읽지 못했습니다. 고정 Vercel CLI 로그인과 프로젝트 접근 권한을 확인하세요.' };
  }
  const rawDeployment = parseInspectJson(rawStdout);
  if (!rawDeployment || typeof rawDeployment.id !== 'string' || typeof rawDeployment.url !== 'string') {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'Vercel deployment GET 응답에서 배포 ID와 URL을 확인하지 못했습니다.' };
  }
  let rawUrl;
  try { rawUrl = normalizeDeploymentUrl(rawDeployment.url); }
  catch { return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'Vercel deployment GET 응답의 URL 형식이 올바르지 않습니다.' }; }
  if (rawDeployment.id !== inspected.id || rawUrl !== inspectedUrl) {
    return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: 'Vercel inspect 결과와 deployment GET metadata의 ID 또는 URL이 다릅니다.' };
  }
  if (String(rawDeployment.readyState || '').toUpperCase() !== 'READY') {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'Vercel deployment GET metadata가 READY 상태를 확인하지 못했습니다.' };
  }
  if (String(rawDeployment.target || '').toLowerCase() !== 'production') {
    return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: 'Vercel deployment GET metadata가 production target과 일치하지 않습니다.' };
  }
  const binding = inspectedDeploymentBinding(rawDeployment);
  if (!binding.githubDeployments.length || !binding.githubCommitShas.length) {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'Vercel 배포 정보에 canonical Git metadata가 없습니다. staged 배포에 --meta githubDeployment=1과 --meta githubCommitSha=<현재 HEAD>를 모두 넣으세요.' };
  }
  if (binding.githubDeployments.some(value => value !== '1')) {
    return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: 'Vercel 배포의 githubDeployment metadata가 정확히 1이 아닙니다.' };
  }
  if (binding.githubCommitShas.some(value => value !== gitSha)) {
    return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: 'Vercel 배포의 githubCommitSha metadata가 현재 HEAD와 다릅니다.' };
  }
  if (!binding.gitSourceShas.length) {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'Vercel deployment GET 정보에 canonical gitSource.sha가 없습니다.' };
  }
  if ([...binding.gitSourceShas, ...binding.additionalSourceGitShas].some(value => value !== gitSha)) {
    return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: 'Vercel 배포의 Git source SHA가 현재 HEAD와 다릅니다.' };
  }
  if (!binding.projectIds.length || !binding.orgIds.length) {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'Vercel 배포 정보에서 projectId와 orgId/teamId를 확인하지 못했습니다.' };
  }
  if (binding.projectIds.some(value => value !== linked.projectId) || binding.orgIds.some(value => value !== linked.orgId)) {
    return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: '검사한 배포가 현재 폴더에 연결된 Vercel 프로젝트 또는 팀과 다릅니다.' };
  }
  if (linked.projectName && binding.projectNames.length && binding.projectNames.some(value => value !== linked.projectName)) {
    return { ok: false, exitCode: STRICT_EXIT.BINDING_MISMATCH, reason: '검사한 배포의 Vercel 프로젝트 이름이 현재 링크와 다릅니다.' };
  }
  return {
    ok: true,
    exitCode: STRICT_EXIT.PASS,
    id: inspected.id,
    url: inspectedUrl,
    gitSha,
    projectId: linked.projectId,
    orgId: linked.orgId,
    projectName: linked.projectName || binding.projectNames[0] || '',
    target: 'production',
    readyState: 'READY',
  };
}

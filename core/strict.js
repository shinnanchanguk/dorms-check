import runtime from './strict-runtime.cjs';
import { execFileSync } from 'node:child_process';
import { SECURITY_ITEMS } from '../catalog/security.js';
import { SEVERITY_RANK } from './tracks.js';

export const STRICT_EXIT = runtime.EXIT;
export const {
  projectIdentity,
  normalizeDeploymentUrl,
  createReceipt,
  storeReceipt,
  invalidateReceipt,
  verifyCodeGate,
  verifyGate,
  evaluateVercelCommand,
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

export function inspectVercelDeployment({ cwd, deployment, url }, options = {}) {
  const reference = String(deployment || '').trim();
  if (!reference) {
    return { ok: false, exitCode: STRICT_EXIT.USAGE_CONFIG, reason: 'Vercel 배포 URL 또는 ID가 필요합니다.' };
  }
  if (!/^https?:\/\//i.test(reference) && !/^dpl_[A-Za-z0-9]+$/.test(reference)) {
    return { ok: false, exitCode: STRICT_EXIT.USAGE_CONFIG, reason: 'Vercel 배포 ID는 dpl_로 시작해야 합니다. 가능하면 배포 URL을 그대로 쓰세요.' };
  }

  let requestedUrl;
  try { requestedUrl = normalizeDeploymentUrl(url); }
  catch (error) { return { ok: false, exitCode: STRICT_EXIT.USAGE_CONFIG, reason: error.message }; }

  let stdout;
  try {
    stdout = (options.execFileSync || execFileSync)('vercel', ['inspect', reference, '--json', '--non-interactive'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const hint = error?.code === 'ENOENT'
      ? 'Vercel CLI가 없습니다. Vercel CLI를 설치하고 로그인한 뒤 다시 검사하세요.'
      : 'Vercel CLI 로그인, 프로젝트 연결, 배포 상태를 확인한 뒤 다시 검사하세요.';
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: `Vercel 배포 정보를 확인하지 못했습니다. ${hint}` };
  }

  const inspected = parseInspectJson(stdout);
  if (!inspected || typeof inspected.id !== 'string' || typeof inspected.url !== 'string') {
    return { ok: false, exitCode: STRICT_EXIT.INCOMPLETE, reason: 'vercel inspect --json 결과에서 배포 ID와 URL을 확인하지 못했습니다. Vercel CLI를 최신 버전으로 업데이트하세요.' };
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
  return { ok: true, exitCode: STRICT_EXIT.PASS, id: inspected.id, url: inspectedUrl, target: 'production', readyState: 'READY' };
}

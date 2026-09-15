// Optional runtime observations share the caller's deadline and fetch boundary.
import { rlsProbe } from './rls-probe.js';
import { firebaseProbe } from './firebase-probe.js';
import { endpointAuthProbe } from './endpoint-auth.js';
import { normalizeSecurityItems } from '../../core/minimum-policy.js';
export async function runRuntimeProbe(rawUrl, opts = {}) {
  const options = { ...opts, deadlineAt: opts.deadlineAt ?? Date.now() + (opts.totalTimeout || 45000) };
  const probes = [[rlsProbe, 'code.rls.anon-read'], [firebaseProbe, 'code.firebase.public-read'], [endpointAuthProbe, 'code.endpoint.unauth']];
  const groups = await Promise.all(probes.map(async ([probe, id]) => {
    try { return await probe(rawUrl, options); }
    catch { return [{ id, status: 'unknown', observed: '내부 접근 권한을 확인하지 못했습니다.', evidence: { probeError: true } }]; }
  }));
  return { items: normalizeSecurityItems(groups.flat()) };
}
export { rlsProbe, firebaseProbe, endpointAuthProbe };

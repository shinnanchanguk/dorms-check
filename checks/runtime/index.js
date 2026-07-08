// 능동 런타임 프로브 오케스트레이터 — CLI와 도름스 서버가 공유.
// 코드 항목을 '모델 판단' 없이 실제 요청으로 실측한다(할루시네이션 방지).
import { rlsProbe } from './rls-probe.js';
import { endpointAuthProbe } from './endpoint-auth.js';

export async function runRuntimeProbe(rawUrl, opts = {}) {
  const items = [];
  try { items.push(...await rlsProbe(rawUrl, opts)); }
  catch (e) { items.push({ id: 'code.rls.anon-read', status: 'na', observed: `RLS 프로브 실패: ${e.message}`, evidence: {} }); }
  try { items.push(...await endpointAuthProbe(rawUrl, opts)); }
  catch (e) { items.push({ id: 'code.endpoint.unauth', status: 'na', observed: `엔드포인트 프로브 실패: ${e.message}`, evidence: {} }); }
  return { items };
}

export { rlsProbe, endpointAuthProbe };

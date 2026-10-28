// Local code observations are advisory; they do not claim public-page coverage.
import { checkSecrets } from './secrets.js';
import { checkClientBundle } from './client-bundle.js';
import { checkHeadersConfig } from './headers-config.js';
import { checkDangerous } from './dangerous.js';
import { checkSupabaseProject, SUPABASE_IDS } from './supabase-sql.js';
import { normalizeSecurityItems } from '../../core/minimum-policy.js';
export function runStaticScan(root) {
  const items = [];
  for (const [check, id] of [[checkSecrets, 'code.hardcoded-secret'], [checkClientBundle, 'code.client-secret-leak'], [checkHeadersConfig, 'code.headers-config'], [checkDangerous, 'code.dangerous-pattern']]) {
    try { items.push(...check(root)); }
    catch { items.push({ id, status: 'unknown', observed: '이 코드 항목을 확인하지 못했습니다.', evidence: { probeError: true } }); }
  }
  // 학교 개인정보 자체점검 대비 항목(Supabase). 여러 항목을 한 번에 내므로 실패하면 모두 미확인으로 남긴다.
  try { items.push(...checkSupabaseProject(root)); }
  catch {
    for (const id of [...SUPABASE_IDS, 'ops.school-selfcheck']) items.push({ id, status: 'unknown', observed: '이 코드 항목을 확인하지 못했습니다.', evidence: { probeError: true } });
  }
  return { items: normalizeSecurityItems(items) };
}

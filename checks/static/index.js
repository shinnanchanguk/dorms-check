// Local code observations are advisory; they do not claim public-page coverage.
import { checkSecrets } from './secrets.js';
import { checkClientBundle } from './client-bundle.js';
import { checkHeadersConfig } from './headers-config.js';
import { checkDangerous } from './dangerous.js';
import { normalizeSecurityItems } from '../../core/minimum-policy.js';
export function runStaticScan(root) {
  const items = [];
  for (const [check, id] of [[checkSecrets, 'code.hardcoded-secret'], [checkClientBundle, 'code.client-secret-leak'], [checkHeadersConfig, 'code.headers-config'], [checkDangerous, 'code.dangerous-pattern']]) {
    try { items.push(...check(root)); }
    catch { items.push({ id, status: 'unknown', observed: '이 코드 항목을 확인하지 못했습니다.', evidence: { probeError: true } }); }
  }
  return { items: normalizeSecurityItems(items) };
}

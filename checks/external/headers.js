// Header quality is useful advice. It is not a requirement for the minimum mark.
import { evaluateSecurityHeaders } from './header-policy.js';
const WANT = [
  ['sec.header.csp', 'content-security-policy'], ['sec.header.hsts', 'strict-transport-security'],
  ['sec.header.frame', 'x-frame-options'], ['sec.header.nosniff', 'x-content-type-options'],
  ['sec.header.referrer', 'referrer-policy'], ['sec.header.permissions', 'permissions-policy'],
];
export function checkHeaders(mainRes) {
  const headers = mainRes.headers || {};
  const evaluated = evaluateSecurityHeaders(headers);
  const results = WANT.map(([id, header]) => {
    const verdict = evaluated[id];
    const value = headers[header] || (id === 'sec.header.frame' && verdict.valid ? '(CSP frame-ancestors)' : null);
    return {
      id, status: verdict.valid ? 'pass' : 'info',
      observed: verdict.valid ? `${header} 설정 확인` : `${header} 보완 권장: ${verdict.reason || '누락'}`,
      evidence: { header, value, validation: verdict.reason || 'valid', observedAt: new Date().toISOString() },
    };
  });
  return { results, bonus: [] };
}

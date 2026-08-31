// 보안 응답 헤더 6종 + 가점(CSP nonce/hash, HSTS 장기, Referrer 엄격).
// 결정적: 라이브 응답 헤더의 존재와 실제 방어 값을 함께 검증한다.
import { evaluateSecurityHeaders } from './header-policy.js';

const WANT = [
  { id: 'sec.header.csp', header: 'content-security-policy' },
  { id: 'sec.header.hsts', header: 'strict-transport-security' },
  { id: 'sec.header.frame', header: 'x-frame-options', altCsp: 'frame-ancestors' },
  { id: 'sec.header.nosniff', header: 'x-content-type-options' },
  { id: 'sec.header.referrer', header: 'referrer-policy' },
  { id: 'sec.header.permissions', header: 'permissions-policy' },
];

export function checkHeaders(mainRes) {
  const h = mainRes.headers || {};
  const evaluated = evaluateSecurityHeaders(h);
  const results = [];
  for (const w of WANT) {
    const value = h[w.header];
    const verdict = evaluated[w.id];
    const shownValue = w.altCsp && verdict.valid && !value ? `(csp ${w.altCsp})` : value;
    results.push({
      id: w.id,
      status: verdict.valid ? 'pass' : 'fail',
      observed: verdict.valid
        ? `${w.header}: ${shownValue}`
        : `${value ? '무효하거나 약한 값' : '누락'}: ${w.header}${verdict.reason ? ` (${verdict.reason})` : ''}`,
      evidence: { header: w.header, value: shownValue || null, validation: verdict.reason || 'valid', observedAt: new Date().toISOString() },
    });
  }
  // 가점(bonus): 점수에만 반영, 게이트 무관.
  const bonus = [];
  const csp = h['content-security-policy'] || '';
  if (evaluated['sec.header.csp'].valid && /nonce-|sha256-|sha384-|sha512-/.test(csp)) bonus.push({ id: 'sec.header.csp.nonce', points: 10, observed: 'CSP nonce/hash 사용' });
  const hsts = h['strict-transport-security'] || '';
  const maxAge = /max-age=(\d+)/.exec(hsts);
  if (evaluated['sec.header.hsts'].valid && maxAge && Number(maxAge[1]) >= 15552000) bonus.push({ id: 'sec.header.hsts.long', points: 5, observed: 'HSTS max-age >= 180일' });
  const ref = (h['referrer-policy'] || '').toLowerCase();
  if (evaluated['sec.header.referrer'].valid && /no-referrer|strict-origin/.test(ref)) bonus.push({ id: 'sec.header.referrer.strict', points: 5, observed: 'Referrer 엄격' });
  return { results, bonus };
}

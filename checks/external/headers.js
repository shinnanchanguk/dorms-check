// 보안 응답 헤더 6종 + 가점(CSP nonce/hash, HSTS 장기, Referrer 엄격).
// 결정적: 라이브 응답 헤더를 직접 관측한다. 모델 판단 없음.

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
  const results = [];
  for (const w of WANT) {
    let value = h[w.header];
    // x-frame-options 대체: CSP frame-ancestors 로도 클릭재킹 방어 가능
    if (!value && w.altCsp && (h['content-security-policy'] || '').includes(w.altCsp)) {
      value = `(csp ${w.altCsp})`;
    }
    results.push({
      id: w.id,
      status: value ? 'pass' : 'fail',
      observed: value ? `${w.header}: ${value}` : `누락: ${w.header}`,
      evidence: { header: w.header, value: value || null, observedAt: new Date().toISOString() },
    });
  }
  // 가점(bonus): 점수에만 반영, 게이트 무관.
  const bonus = [];
  const csp = h['content-security-policy'] || '';
  if (/nonce-|sha256-|sha384-|sha512-/.test(csp)) bonus.push({ id: 'sec.header.csp.nonce', points: 10, observed: 'CSP nonce/hash 사용' });
  const hsts = h['strict-transport-security'] || '';
  const maxAge = /max-age=(\d+)/.exec(hsts);
  if (maxAge && Number(maxAge[1]) >= 15552000) bonus.push({ id: 'sec.header.hsts.long', points: 5, observed: 'HSTS max-age >= 180일' });
  const ref = (h['referrer-policy'] || '').toLowerCase();
  if (/no-referrer|strict-origin/.test(ref)) bonus.push({ id: 'sec.header.referrer.strict', points: 5, observed: 'Referrer 엄격' });
  return { results, bonus };
}

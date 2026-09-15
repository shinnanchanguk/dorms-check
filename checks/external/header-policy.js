// 보안 헤더의 '존재'가 아니라 브라우저가 실제 방어로 해석할 수 있는 값을 검증한다.
// 이 파일은 네트워크 요청을 하지 않는 순수 판정기라 CLI와 서버가 같은 결과를 재사용할 수 있다.

const SAFE_REFERRER_POLICIES = new Set([
  'no-referrer',
  'same-origin',
  'origin',
  'origin-when-cross-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
]);
const HSTS_MIN_MAX_AGE = 15552000; // 180일. 더 짧으면 HTTPS 강제 보호가 사실상 지속되지 않는다.

function result(valid, reason = '') {
  return { valid, reason };
}

function parseCsp(value) {
  const directives = new Map();
  for (const raw of String(value || '').split(';')) {
    const part = raw.trim();
    if (!part) continue;
    const [rawName, ...tokens] = part.split(/\s+/);
    const name = rawName.toLowerCase();
    if (!/^[a-z][a-z0-9-]*$/.test(name) || directives.has(name)) return null;
    directives.set(name, tokens.map(t => t.toLowerCase()));
  }
  return directives;
}

function hasNonceOrHash(tokens) {
  return tokens.some(t => /^'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'$/.test(t));
}

function validateScriptSources(tokens, name, { disallowUnsafeInline = false } = {}) {
  if (tokens.includes("'unsafe-eval'")) return result(false, `${name}에 'unsafe-eval' 사용`);
  if (tokens.includes("'unsafe-inline'") && (disallowUnsafeInline || !hasNonceOrHash(tokens))) {
    return result(false, `${name}에 nonce/hash 없는 'unsafe-inline' 사용`);
  }
  const trusted = new Set(["'self'", "'none'", "'strict-dynamic'", "'unsafe-inline'"]);
  for (const token of tokens) {
    if (trusted.has(token) || /^'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'$/.test(token)) continue;
    if (/^(?:https:\/\/|[a-z0-9*.-]+\.)[a-z0-9*./:_-]*$/i.test(token)) continue;
    return result(false, `${name}에 검증할 수 없는 스크립트 출처 사용`);
  }
  return result(true);
}

export function validateCsp(value) {
  if (!value) return result(false, '누락');
  const directives = parseCsp(value);
  if (!directives) return result(false, '문법 오류 또는 중복 지시어');
  const fallback = directives.get('default-src');
  if (!fallback || fallback.length === 0) return result(false, 'default-src 없음');

  const script = directives.get('script-src') || fallback;
  const scriptResult = validateScriptSources(script, 'script-src');
  if (!scriptResult.valid) return scriptResult;
  const scriptElement = directives.get('script-src-elem') || script;
  const scriptElementResult = validateScriptSources(scriptElement, 'script-src-elem');
  if (!scriptElementResult.valid) return scriptElementResult;
  const scriptAttr = directives.get('script-src-attr');
  if (scriptAttr) {
    const scriptAttrResult = validateScriptSources(scriptAttr, 'script-src-attr', { disallowUnsafeInline: true });
    if (!scriptAttrResult.valid) return scriptAttrResult;
  }

  const object = directives.get('object-src') || fallback;
  if (!(object.length === 1 && object[0] === "'none'")) return result(false, "object-src 'none' 없음");

  const base = directives.get('base-uri');
  if (!base || base.length !== 1 || !["'self'", "'none'"].includes(base[0])) {
    return result(false, "base-uri 'self' 또는 'none' 없음");
  }

  const form = directives.get('form-action');
  if (!form || form.length === 0 || form.includes('*') || form.includes('http:') || form.includes('https:')) {
    return result(false, 'form-action 제한 없음');
  }
  return result(true);
}

export function validateFrameProtection(xFrameOptions, cspValue) {
  const xfo = String(xFrameOptions || '').trim().toUpperCase();
  if (xfo === 'DENY' || xfo === 'SAMEORIGIN') return result(true, `x-frame-options: ${xfo}`);

  const directives = parseCsp(cspValue);
  const ancestors = directives && directives.get('frame-ancestors');
  if (!ancestors || ancestors.length === 0) {
    return result(false, xFrameOptions ? 'X-Frame-Options 값이 DENY/SAMEORIGIN이 아님' : 'X-Frame-Options와 CSP frame-ancestors 모두 없음');
  }
  if (ancestors.includes('*') || ancestors.includes('http:') || ancestors.includes('https:')) {
    return result(false, 'CSP frame-ancestors 범위가 너무 넓음');
  }
  if (ancestors.includes("'none'") && ancestors.length !== 1) {
    return result(false, "CSP frame-ancestors의 'none'과 다른 출처를 함께 사용");
  }
  return result(true, 'CSP frame-ancestors');
}

export function validateHsts(value) {
  if (!value) return result(false, '누락');
  const match = /(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i.exec(String(value));
  return match && Number(match[1]) >= HSTS_MIN_MAX_AGE
    ? result(true)
    : result(false, `max-age가 ${HSTS_MIN_MAX_AGE}초(180일)보다 짧음`);
}

export function validateNoSniff(value) {
  return String(value || '').trim().toLowerCase() === 'nosniff'
    ? result(true)
    : result(false, value ? '값이 nosniff가 아님' : '누락');
}

export function validateReferrerPolicy(value) {
  if (!value) return result(false, '누락');
  const policies = String(value).toLowerCase().split(',').map(v => v.trim()).filter(Boolean);
  return policies.length > 0 && policies.every(v => SAFE_REFERRER_POLICIES.has(v))
    ? result(true)
    : result(false, '정보 노출을 줄이는 유효한 정책이 아님');
}

export function validatePermissionsPolicy(value) {
  if (!value) return result(false, '누락');
  const directives = String(value).split(',').map(v => v.trim()).filter(Boolean);
  if (directives.length === 0) return result(false, '정책 지시어 없음');
  for (const directive of directives) {
    const match = /^([a-z][a-z0-9-]*)\s*=\s*(\([^()]*\)|\*)$/i.exec(directive);
    if (!match) return result(false, '문법 오류');
    if (match[2] === '*') return result(false, `${match[1]} 권한을 모든 출처에 허용`);
  }
  return result(true);
}

export function evaluateSecurityHeaders(headers = {}) {
  const csp = headers['content-security-policy'] || '';
  return {
    'sec.header.csp': validateCsp(csp),
    'sec.header.hsts': validateHsts(headers['strict-transport-security']),
    'sec.header.frame': validateFrameProtection(headers['x-frame-options'], csp),
    'sec.header.nosniff': validateNoSniff(headers['x-content-type-options']),
    'sec.header.referrer': validateReferrerPolicy(headers['referrer-policy']),
    'sec.header.permissions': validatePermissionsPolicy(headers['permissions-policy']),
  };
}

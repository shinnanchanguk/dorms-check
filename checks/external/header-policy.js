// Security headers are only useful when browsers can enforce their values.
// Keep this module pure so the CLI and server-side verifier share one policy.

const SAFE_REFERRER_POLICIES = new Set([
  'no-referrer',
  'same-origin',
  'origin',
  'origin-when-cross-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
]);
const HSTS_MIN_MAX_AGE = 15552000;

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
    directives.set(name, tokens.map(token => token.toLowerCase()));
  }
  return directives;
}

function hasNonceOrHash(tokens) {
  return tokens.some(token => /^'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'$/.test(token));
}

function validateScriptSources(tokens, name, { disallowUnsafeInline = false } = {}) {
  if (tokens.includes("'unsafe-eval'")) return result(false, `${name} uses 'unsafe-eval'`);
  if (tokens.includes("'unsafe-inline'") && (disallowUnsafeInline || !hasNonceOrHash(tokens))) {
    return result(false, `${name} uses 'unsafe-inline' without a nonce or hash`);
  }
  const trusted = new Set(["'self'", "'none'", "'strict-dynamic'", "'unsafe-inline'"]);
  for (const token of tokens) {
    if (trusted.has(token) || /^'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'$/.test(token)) continue;
    return result(false, `${name} contains an unverified script source`);
  }
  return result(true);
}

export function validateCsp(value) {
  if (!value) return result(false, 'missing');
  const directives = parseCsp(value);
  if (!directives) return result(false, 'syntax error or duplicate directive');
  const fallback = directives.get('default-src');
  if (!fallback || fallback.length === 0) return result(false, 'default-src is missing');

  const script = directives.get('script-src') || fallback;
  const scriptResult = validateScriptSources(script, 'script-src');
  if (!scriptResult.valid) return scriptResult;
  const scriptElementResult = validateScriptSources(directives.get('script-src-elem') || script, 'script-src-elem');
  if (!scriptElementResult.valid) return scriptElementResult;
  const scriptAttr = directives.get('script-src-attr');
  if (scriptAttr) {
    const scriptAttrResult = validateScriptSources(scriptAttr, 'script-src-attr', { disallowUnsafeInline: true });
    if (!scriptAttrResult.valid) return scriptAttrResult;
  }

  const object = directives.get('object-src') || fallback;
  if (!(object.length === 1 && object[0] === "'none'")) return result(false, "object-src 'none' is missing");

  const base = directives.get('base-uri');
  if (!base || base.length !== 1 || !["'self'", "'none'"].includes(base[0])) {
    return result(false, "base-uri must be 'self' or 'none'");
  }

  const form = directives.get('form-action');
  if (!form || form.length !== 1 || !["'self'", "'none'"].includes(form[0])) {
    return result(false, "form-action must be exactly 'self' or 'none'");
  }
  return result(true);
}

export function validateFrameProtection(xFrameOptions, cspValue) {
  const xfo = String(xFrameOptions || '').trim().toUpperCase();
  if (xfo === 'DENY' || xfo === 'SAMEORIGIN') return result(true, `x-frame-options: ${xfo}`);

  const directives = parseCsp(cspValue);
  const ancestors = directives && directives.get('frame-ancestors');
  if (!ancestors || ancestors.length === 0) {
    return result(false, xFrameOptions ? 'X-Frame-Options is not DENY or SAMEORIGIN' : 'frame protection is missing');
  }
  if (ancestors.length !== 1 || !["'self'", "'none'"].includes(ancestors[0])) {
    return result(false, "frame-ancestors must be exactly 'self' or 'none'");
  }
  return result(true, 'CSP frame-ancestors');
}

export function validateHsts(value) {
  if (!value) return result(false, 'missing');
  const match = /(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i.exec(String(value));
  return match && Number(match[1]) >= HSTS_MIN_MAX_AGE
    ? result(true)
    : result(false, `max-age is shorter than ${HSTS_MIN_MAX_AGE} seconds`);
}

export function validateNoSniff(value) {
  return String(value || '').trim().toLowerCase() === 'nosniff'
    ? result(true)
    : result(false, value ? 'value is not nosniff' : 'missing');
}

export function validateReferrerPolicy(value) {
  if (!value) return result(false, 'missing');
  const policies = String(value).toLowerCase().split(',').map(item => item.trim()).filter(Boolean);
  return policies.length > 0 && policies.every(item => SAFE_REFERRER_POLICIES.has(item))
    ? result(true)
    : result(false, 'policy does not sufficiently limit referrer data');
}

export function validatePermissionsPolicy(value) {
  if (!value) return result(false, 'missing');
  const directives = String(value).split(',').map(item => item.trim()).filter(Boolean);
  if (directives.length === 0) return result(false, 'no directives');
  for (const directive of directives) {
    const match = /^([a-z][a-z0-9-]*)\s*=\s*(\([^()]*\)|\*)$/i.exec(directive);
    if (!match) return result(false, 'syntax error');
    if (match[2] === '*') return result(false, `${match[1]} is allowed for every origin`);
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

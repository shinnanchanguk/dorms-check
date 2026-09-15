import { SECURITY_ITEMS } from '../catalog/security.js';

// Public surface observations are evidence, not a claim that an entire app is safe.
export const MINIMUM_SECURITY_POLICY_VERSION = 'minimum-2026-09-15';

const EXPOSURE_IDS = new Set(['info.secret-exposed', 'code.rls.anon-read', 'code.firebase.public-read', 'code.client-secret-leak']);
const UNKNOWN_STATUSES = new Set(['unknown', 'pending', 'error', 'skipped', 'missing']);
const securityCatalog = new Map(SECURITY_ITEMS.map(item => [item.id, item]));

function plausibleSecret(value) {
  return value.length >= 20 && new Set(value).size >= 8
    && !/example|placeholder|your[-_]|sample|changeme|dummy/i.test(value);
}

// Inspect disjoint PEM payloads once. Ambiguous whitespace regexes can stall a scan.
function containsPrivateKey(text) {
  const markers = /-----((?:BEGIN|END)) ((?:RSA |EC |OPENSSH )?PRIVATE KEY)-----/g;
  let opening = null;
  for (const marker of text.matchAll(markers)) {
    if (marker[1] === 'BEGIN') {
      opening = { kind: marker[2], offset: marker.index + marker[0].length };
      continue;
    }
    if (opening?.kind === marker[2]) {
      const payload = text.slice(opening.offset, marker.index).trim();
      let encodedLength = 0;
      let valid = true;
      for (let i = 0; i < payload.length; i++) {
        const code = payload.charCodeAt(i);
        if (code === 10 || code === 13) continue;
        if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)
          || (code >= 48 && code <= 57) || code === 43 || code === 47 || code === 61) {
          encodedLength++;
        } else {
          valid = false;
          break;
        }
      }
      if (valid && encodedLength >= 80) return true;
    }
    opening = null;
  }
  return false;
}

// Return the type of evidence only. Never return a matched credential or personal value.
export function classifySensitiveExposure(body, { path = '' } = {}) {
  if (typeof body !== 'string' || !body) return { confirmed: false };
  const text = body.slice(0, 4 * 1024 * 1024);
  const credential = /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}|(?:sk|rk)_live_[A-Za-z0-9]{24,}|sb_secret_[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{24,})\b/g;
  for (const match of text.matchAll(credential)) {
    if (plausibleSecret(match[0])) return { confirmed: true, kind: 'private-credential' };
  }
  for (const match of text.matchAll(/\beyJ[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{16,}\b/g)) {
    try {
      if (JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8'))?.role === 'service_role') {
        return { confirmed: true, kind: 'service-role-credential' };
      }
    } catch { /* A name or malformed example is not an exposed credential. */ }
  }
  if (containsPrivateKey(text)) {
    return { confirmed: true, kind: 'private-key' };
  }
  const awsSecret = /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{40})/.exec(text);
  if (/\bAKIA[0-9A-Z]{16}\b/.test(text) && awsSecret && plausibleSecret(awsSecret[1])) {
    return { confirmed: true, kind: 'private-credential' };
  }

  let data;
  try { data = JSON.parse(text); } catch { return { confirmed: false }; }
  const demonstrationPath = /(?:^|[\/_.-])(?:demo|sample|example|fixture|mock|test)s?(?:[\/_.-]|$)/i.test(path);
  const queue = [{ value: data, depth: 0, sample: demonstrationPath }];
  let visited = 0;
  while (queue.length && visited++ < 300) {
    const { value, depth, sample } = queue.shift();
    if (!value || typeof value !== 'object' || depth > 5) continue;
    if (Array.isArray(value)) {
      queue.push(...value.slice(0, 30).map(item => ({ value: item, depth: depth + 1, sample })));
      continue;
    }
    const fields = Object.entries(value).filter(([, v]) => typeof v === 'string' && v.trim() && !/^(?:\*+|redacted|masked|hidden|null)$/i.test(v));
    const demonstration = sample || Object.entries(value).some(([key, v]) => /^(?:is_?)?(?:demo|sample|example|mock|test|synthetic)$/i.test(key) && (v === true || v === 'true'))
      || fields.some(([, v]) => /@(?:[^@.]+\.)*(?:example\.(?:com|net|org)|localhost|[^@.]+\.(?:test|invalid|example))$/i.test(v.trim()));
    const identity = fields.some(([key]) => /^(?:name|full_name|student_name|user_name|email|username|이름|성명)$/i.test(key));
    const password = fields.some(([key, v]) => /^(?:password_hash|hashed_password|encrypted_password)$/i.test(key) && /^(?:\$2[aby]\$|\$argon2|pbkdf2)/.test(v));
    const student = /(?:^|[\/_.-])students?(?:[\/_.-]|$)|학생/i.test(path);
    const studentName = fields.some(([key, v]) => /^(?:name|full_name|student_name|이름|성명)$/i.test(key)
      && !/^(?:학생\d*|홍길동|김철수|김영희|student\s*\d*|test|sample|example|demo)$/i.test(v.trim()));
    const guardianContact = fields.some(([key, v]) => /^(?:parent_phone|guardian_phone|보호자연락처|보호자전화번호)$/i.test(key)
      && /^\+?[\d\s()-]+$/.test(v) && /^\d{10,15}$/.test(v.replace(/\D/g, ''))
      && !/^(?:01012345678|0100{8}|0+|1+)$/.test(v.replace(/\D/g, '')));
    const privateDetail = fields.some(([key, v]) => (/^(?:birth_date|birthdate|생년월일)$/i.test(key) && /^(?:19|20)\d{2}[-/.]\d{1,2}[-/.]\d{1,2}$/.test(v))
      || (/^(?:medical_history|medical_condition|health_condition|병력|질환)$/i.test(key) && v.length >= 3 && !/^(?:none|없음|해당없음|example|sample|test)$/i.test(v.trim())));
    if (!demonstration && ((identity && password) || (student && studentName && guardianContact && privateDetail))) {
      return { confirmed: true, kind: password ? 'private-account-data' : 'private-student-data' };
    }
    queue.push(...Object.values(value).filter(v => v && typeof v === 'object').slice(0, 30).map(v => ({ value: v, depth: depth + 1, sample: demonstration })));
  }
  return { confirmed: false };
}

export function normalizeSecurityItems(items = []) {
  return (Array.isArray(items) ? items : []).filter(item => item && typeof item.id === 'string').map(item => {
    if (/^(?:edzip|protection)\./.test(item.id)) return item;
    const evidence = item.evidence && typeof item.evidence === 'object' ? item.evidence : {};
    let status = item.status;
    if (UNKNOWN_STATUSES.has(status) || evidence.probeError || evidence.incomplete) status = 'unknown';
    if (status === 'na' && /^code\.(?:rls|firebase|endpoint)/.test(item.id) && evidence.notApplicable !== true) status = 'unknown';
    const confirmedExposure = EXPOSURE_IDS.has(item.id) && evidence.confirmedSensitiveExposure === true;
    const invalidTls = item.id === 'sec.transport.ssl-valid' && evidence.tlsInvalid === true;
    const unsafeTransport = item.id === 'meta.public-surface' && evidence.unsafeTransport === true;
    const malicious = item.id === 'security.malicious' && evidence.confirmedMalicious === true;
    if (item.status === 'fail' && (confirmedExposure || invalidTls || unsafeTransport || malicious)) status = 'fail';
    else if (status === 'fail') status = 'info';
    if (!['pass', 'fail', 'info', 'unknown', 'na'].includes(status)) status = 'unknown';
    return { ...item, status, evidence };
  });
}

export function evaluateMinimumSecurity(scan = {}, { malicious = false } = {}) {
  const items = normalizeSecurityItems(scan.items || scan.results || []).filter(item => !/^(?:edzip|protection)\./.test(item.id));
  if (malicious && !items.some(item => item.id === 'security.malicious' && item.status === 'fail')) {
    items.push({ id: 'security.malicious', status: 'fail', observed: '공개 주소에서 확인된 위험이 있습니다.', evidence: { confirmedMalicious: true } });
  }
  const surface = scan.raw?.publicSurface || items.find(item => item.id === 'meta.public-surface')?.evidence;
  let https = false;
  try { https = new URL(surface?.finalUrl || '').protocol === 'https:'; } catch { /* Unobserved URL. */ }
  const available = scan.reachable !== false && items.length > 0 && https
    && surface?.httpStatus >= 200 && surface.httpStatus < 300
    && surface.transportChecked === true && surface.bodyChecked === true;
  const blockingFails = items.filter(item => item.status === 'fail').map(item => ({
    ...item,
    severity: securityCatalog.get(item.id)?.severity || 'high',
    title: securityCatalog.get(item.id)?.title || item.observed || '공개 주소에서 확인된 위험',
  }));
  const outcome = blockingFails.length ? 'blocked' : (available ? 'eligible' : 'unavailable');
  return {
    eligible: outcome === 'eligible', outcome, items, blockingFails,
    coverage: {
      checked: items.filter(item => ['pass', 'fail', 'info'].includes(item.status)).length,
      unverified: items.filter(item => item.status === 'unknown').length,
      notApplicable: items.filter(item => item.status === 'na').length,
    },
    policyVersion: MINIMUM_SECURITY_POLICY_VERSION,
  };
}

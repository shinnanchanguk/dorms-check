import assert from 'node:assert/strict';
import { runServerVerification, evaluateMinimumSecurity, normalizeSecurityItems, classifySensitiveExposure, scoreSecurity } from '../core/index.js';
import { checkHeaders } from '../checks/external/headers.js';
import { validateCsp, validateFrameProtection } from '../checks/external/header-policy.js';
import { checkTls } from '../checks/external/tls.js';
import { rlsProbe } from '../checks/runtime/rls-probe.js';
import { firebaseProbe } from '../checks/runtime/firebase-probe.js';
import { renderReportMd } from '../core/report.js';

let passed = 0;
function check(name, fn) { fn(); passed++; console.log(`  v ${name}`); }
const app = 'https://app.example/';
// Generate noncredential fixture bytes locally, without storing key-shaped literals.
const fixtureToken = Buffer.from('minimum inspection fixture 2026').toString('hex');
const privateKey = 'sk-proj-' + fixtureToken;
const anonJwt = 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ role: 'anon', iss: 'supabase' })).toString('base64url') + '.abcdef1234567890signature';
function response(url, { status = 200, body = '', headers = {}, finalUrl } = {}) {
  return { status, url: finalUrl || url, headers: new Headers(headers), text: async () => body };
}
function fixture({ body = '<html><div id="root"></div></html>', status = 200, routes = {}, headers = {}, finalUrl } = {}) {
  return async (url, options = {}) => {
    const parsed = new URL(url);
    if (routes[url]) return response(url, routes[url]);
    if (url === app) return response(url, { status, body, headers, finalUrl });
    if (parsed.protocol === 'http:') return response(url, { status: 308, headers: { location: app } });
    return response(url, { status: 404 });
  };
}
async function inspect(options = {}) {
  const scan = await runServerVerification(app, { fetchImpl: fixture(options), timeout: 100, totalTimeout: 1000 });
  return { scan, verdict: evaluateMinimumSecurity(scan) };
}

const basic = await inspect();
check('SPA with missing headers, policy and private DB visibility receives a minimum mark', () => {
  assert.equal(basic.verdict.outcome, 'eligible');
  assert.ok(basic.verdict.coverage.unverified > 0);
  assert.equal(basic.scan.raw.publicSurface.bodyChecked, true);
  assert.equal(basic.verdict.items.find(item => item.id === 'legal.privacy-policy').status, 'unknown');
  assert.equal(basic.verdict.items.find(item => item.id === 'code.rls.anon-read').status, 'unknown');
});
check('legacy scorer uses the same measured public surface and no numeric safety score', () => {
  const score = scoreSecurity(basic.scan.items);
  assert.equal(score.eligible, true);
  assert.equal(score.score, null);
  assert.deepEqual(score.coverage, basic.verdict.coverage);
  const md = renderReportMd({ config: { tracks: ['security'], app: { url: app } }, results: basic.scan.items, security: score });
  assert.ok(md.includes('미확인'));
  assert.ok(!md.includes('/100'));
});
check('empty or code-only results do not claim a live scan or generate missing failures', () => {
  assert.equal(scoreSecurity([]).outcome, 'unavailable');
  const code = scoreSecurity([{ id: 'code.hardcoded-secret', status: 'pass', evidence: {} }]);
  assert.equal(code.outcome, 'unavailable');
  assert.deepEqual(code.blockingFails, []);
});
for (const status of [403, 404, 429, 500, 503]) {
  const result = await inspect({ status });
  check(`HTTP ${status} cannot receive a mark`, () => assert.equal(result.verdict.outcome, 'unavailable'));
}
const login = await inspect({ body: '<html><form>로그인</form></html>' });
check('a public login page with HTTP 200 is a valid limited observation', () => assert.equal(login.verdict.eligible, true));
const unreadable = await runServerVerification(app, { fetchImpl: async url => ({ ...response(url), text: async () => { throw new Error('body failed'); } }) });
check('body read failures do not masquerade as inspected empty pages', () => assert.equal(evaluateMinimumSecurity(unreadable).outcome, 'unavailable'));
const certFailure = await runServerVerification(app, { fetchImpl: async () => { throw Object.assign(new Error('certificate rejected'), { cause: { code: 'CERT_HAS_EXPIRED' } }); } });
check('a verified fetch certificate rejection is an observed transport problem', () => assert.equal(evaluateMinimumSecurity(certFailure).outcome, 'blocked'));
const networkFailure = await runServerVerification(app, { fetchImpl: async () => { throw new Error('network timeout'); } });
check('a generic connection failure remains unavailable rather than an invalid certificate', () => assert.equal(evaluateMinimumSecurity(networkFailure).outcome, 'unavailable'));
const popup = await inspect({ body: '<html><button>개인정보처리방침</button><div id="privacy-dialog"></div></html>' });
check('popup policy and missing /privacy HTML do not block', () => assert.equal(popup.verdict.eligible, true));
const wildcard = await inspect({ headers: { 'access-control-allow-origin': '*' } });
check('public CORS wildcard is advisory', () => {
  assert.equal(wildcard.verdict.eligible, true);
  assert.equal(wildcard.verdict.items.find(item => item.id === 'cors.policy').status, 'info');
});
check('missing, invalid and weak headers stay advisory', () => {
  assert.ok(checkHeaders({ headers: {} }).results.every(item => item.status === 'info'));
  assert.equal(checkHeaders({ headers: { 'content-security-policy': 'garbage' } }).results[0].status, 'info');
  assert.equal(checkHeaders({ headers: { 'strict-transport-security': 'max-age=1' } }).results[1].status, 'info');
  const csp = "default-src 'self'; script-src https://cdn.example; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'";
  assert.equal(validateCsp(csp).valid, true);
  assert.equal(validateFrameProtection('', csp).valid, true);
  assert.equal(validateCsp(csp.replace('https://cdn.example', "'unsafe-eval'")).valid, false);
});
const nominalEnv = await inspect({ routes: { 'https://app.example/.env': { body: 'PUBLIC_THEME=blue\nPUBLIC_SIZE=large' }, 'https://app.example/.git/config': { body: '[core]\nrepositoryformatversion=0' } } });
check('configuration shape alone is not a secret', () => assert.equal(nominalEnv.verdict.eligible, true));
const exposed = await inspect({ routes: { 'https://app.example/.env': { body: `API_KEY=${privateKey}` } } });
check('actual credential exposure blocks and values never enter evidence', () => {
  assert.equal(exposed.verdict.outcome, 'blocked');
  assert.ok(exposed.verdict.blockingFails.some(item => item.id === 'info.secret-exposed'));
  assert.ok(!JSON.stringify(exposed).includes(privateKey));
});
const bundleExposure = await inspect({ body: '<html><script src="/bundle.js"></script></html>', routes: { 'https://app.example/bundle.js': { body: `const key="${privateKey}";` } } });
check('a credential in a fetched public bundle blocks without exposing its value', () => {
  assert.equal(bundleExposure.verdict.outcome, 'blocked');
  assert.ok(!JSON.stringify(bundleExposure).includes(privateKey));
});
const oversizedChunk = await runServerVerification(app, {
  fetchImpl: (url, options) => url === 'https://app.example/.env'
    ? new Response(`API_KEY=${privateKey}\n` + 'x'.repeat(70 * 1024))
    : fixture()(url, options),
});
check('a large first response chunk still has its bounded prefix inspected', () => {
  assert.equal(evaluateMinimumSecurity(oversizedChunk).outcome, 'blocked');
  assert.ok(!JSON.stringify(oversizedChunk).includes(privateKey));
});
check('names and public database values do not become private data', () => {
  for (const text of ['service_role', 'SUPABASE_SERVICE_ROLE_KEY', 'VITE_API_KEY', '[{"name":"덧셈 수업"}]', '{"public_lesson_topics":true}']) {
    assert.equal(classifySensitiveExposure(text, { path: 'lessons' }).confirmed, false);
  }
  assert.equal(classifySensitiveExposure(JSON.stringify([{ name: '김하진', email: 'student@school.kr' }]), { path: 'students' }).confirmed, false);
  assert.equal(normalizeSecurityItems([{ id: 'cors.policy', status: 'info' }, { id: 'code.rls.anon-read', status: 'pending' }])[1].status, 'unknown');
});
check('public student examples and explicitly synthetic records do not block', () => {
  for (const example of [
    { name: '학생', email: 'student@example.test' },
    { name: '홍길동', guardian_phone: '010-9372-6841', birthdate: '2015-05-12' },
    { name: '김하진', email: 'student@example.com', guardian_phone: '010-9372-6841', birthdate: '2015-05-12' },
    { sample: true, students: [{ name: '김하진', guardian_phone: '010-9372-6841', birthdate: '2015-05-12' }] },
  ]) assert.equal(classifySensitiveExposure(JSON.stringify(example), { path: 'students' }).confirmed, false);
});
check('combined student identity, guardian contact and private details remain detectable', () => {
  const body = JSON.stringify([{ name: '김하진', guardian_phone: '010-9372-6841', birthdate: '2015-05-12' }]);
  assert.deepEqual(classifySensitiveExposure(body, { path: 'students' }), { confirmed: true, kind: 'private-student-data' });
  assert.equal(classifySensitiveExposure(body, { path: 'sample/students' }).confirmed, false);
});
check('Stripe private keys are distinguished from publishable keys', () => {
  assert.equal(classifySensitiveExposure('sk_live_' + fixtureToken).confirmed, true);
  assert.equal(classifySensitiveExposure('pk_live_' + fixtureToken).confirmed, false);
});
function dbFixture(rows, { error = false, listed = true } = {}) {
  return async (url) => {
    if (url === app) return response(url, { body: `<script>const u="https://abcdefghijklmno.supabase.co";const k="${anonJwt}";</script>` });
    if (error) throw new Error('network unavailable');
    if (url.endsWith('/rest/v1/')) return response(url, { status: listed ? 200 : 401, body: JSON.stringify({ definitions: { lessons: {} } }) });
    return response(url, { status: 200, body: JSON.stringify(rows) });
  };
}
const publicRows = await rlsProbe(app, { fetchImpl: dbFixture([{ name: '덧셈 수업' }]) });
check('public lesson name is advisory, not a PII leak', () => assert.equal(publicRows[0].status, 'info'));
const failedRls = await rlsProbe(app, { fetchImpl: dbFixture([], { error: true }), timeout: 20, totalTimeout: 100 });
check('RLS request errors never become a pass', () => assert.equal(failedRls[0].status, 'unknown'));
const lockedRls = await rlsProbe(app, { fetchImpl: dbFixture([]) });
check('explicit empty responses are scoped observations', () => assert.equal(lockedRls[0].status, 'pass'));
async function firebaseFixture(status, body) {
  return firebaseProbe(app, { fetchImpl: async url => url === app
    ? response(url, { body: '<script>const db="https://demo.firebaseio.com";</script>' })
    : (status === 0 ? Promise.reject(new Error('offline')) : response(url, { status, body })) });
}
const publicFirebase = await firebaseFixture(200, '{"public_lesson_topics":true}');
check('Firebase shallow public keys do not establish sensitive exposure', () => assert.equal(publicFirebase[0].status, 'info'));
const unavailableFirebase = await firebaseFixture(0, '');
check('Firebase connection errors never become locked/pass', () => assert.equal(unavailableFirebase[0].status, 'unknown'));
const malformedFirebase = await firebaseFixture(200, 'unexpected response');
check('a malformed Firebase response is unknown', () => assert.equal(malformedFirebase[0].status, 'unknown'));
const lockedFirebase = await firebaseFixture(403, '{"error":"Permission denied"}');
check('explicit Firebase denial remains a scoped pass', () => assert.equal(lockedFirebase[0].status, 'pass'));
const tlsOptions = { requestImpl: async () => ({ status: 0, headers: {} }), negotiateImpl: async () => ({ error: 'timeout', protocol: null }) };
const unknownTls = await checkTls({ ok: true, finalUrl: app, headers: {} }, app, tlsOptions);
check('TLS measurement timeout is unknown', () => assert.equal(unknownTls.find(item => item.id === 'sec.transport.ssl-valid').status, 'unknown'));
const badTls = await checkTls({ ok: true, finalUrl: app, headers: {} }, app, { ...tlsOptions, negotiateImpl: async () => ({ protocol: 'TLSv1.3', authorized: false, authError: 'CERT_HAS_EXPIRED' }) });
check('observed invalid TLS stays distinct from a timeout', () => assert.equal(normalizeSecurityItems(badTls).find(item => item.id === 'sec.transport.ssl-valid').status, 'fail'));
check('confirmed malicious service appears in both the verdict and displayed findings', () => {
  const result = evaluateMinimumSecurity(basic.scan, { malicious: true });
  assert.equal(result.outcome, 'blocked');
  assert.ok(result.items.some(item => item.id === 'security.malicious' && item.status === 'fail'));
  assert.ok(result.blockingFails.every(item => typeof item.title === 'string' && typeof item.severity === 'string'));
  assert.equal(result.coverage.checked, basic.verdict.coverage.checked + 1);
  assert.equal(scoreSecurity(result.items).outcome, 'blocked');
});

let startedRequests = 0;
const started = Date.now();
const budgetScan = await runServerVerification(app, {
  timeout: 30, totalTimeout: 80,
  fetchImpl: async (url, options) => {
    startedRequests++;
    if (url === app) return response(url, { body: '<html>앱</html>' });
    return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
  },
});
check('optional deadline exhaustion preserves an already inspected public surface', () => {
  assert.ok(Date.now() - started < 500);
  assert.equal(evaluateMinimumSecurity(budgetScan).eligible, true);
  assert.ok(evaluateMinimumSecurity(budgetScan).coverage.unverified > 0);
  assert.ok(startedRequests < 30);
});
console.log(`minimum result: ${passed} pass, 0 fail`);

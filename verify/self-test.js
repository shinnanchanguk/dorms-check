// 의존성 0 자체검증. 스캐너 회귀 + 할루시네이션 방지 프로브의 양성/음성 케이스.
// 외부 네트워크 없이 mock fetchImpl 로 결정적으로 돌린다.
import { checkHeaders } from '../checks/external/headers.js';
import { checkExposure } from '../checks/external/exposure.js';
import { checkCors } from '../checks/external/cors.js';
import { rlsProbe } from '../checks/runtime/rls-probe.js';
import { scoreSecurity } from '../core/score.js';

let pass = 0, fail = 0;
function ok(name, cond) { if (cond) { pass++; console.log('  v', name); } else { fail++; console.error('  x', name); } }

// ── mock fetch: url → {status, headers, body} 라우트 ──
function fakeHeaders(obj) {
  const map = new Map(Object.entries(obj || {}).map(([k, v]) => [k.toLowerCase(), v]));
  return { entries: () => map.entries(), get: k => map.get(String(k).toLowerCase()) };
}
function makeRes({ status = 200, headers = {}, body = '', url = '' }) {
  return { status, url, redirected: false, headers: fakeHeaders(headers), text: async () => body };
}
function mockFetch(routes) {
  return async (url) => {
    for (const [pattern, res] of routes) {
      if (typeof pattern === 'string' ? url === pattern : pattern.test(url)) {
        return makeRes(typeof res === 'function' ? res(url) : { ...res, url });
      }
    }
    return makeRes({ status: 404, url, body: 'not found' });
  };
}

async function run() {
  console.log('\n[1] 보안 헤더 — 전부 없으면 fail, 있으면 pass');
  const noHdr = checkHeaders({ headers: {} });
  ok('헤더 없음 → csp fail', noHdr.results.find(r => r.id === 'sec.header.csp').status === 'fail');
  const withHdr = checkHeaders({ headers: { 'content-security-policy': "default-src 'self'; script-src 'nonce-abc'", 'strict-transport-security': 'max-age=63072000' } });
  ok('CSP 있음 → pass', withHdr.results.find(r => r.id === 'sec.header.csp').status === 'pass');
  ok('CSP nonce → 가점', withHdr.bonus.some(b => b.id === 'sec.header.csp.nonce'));

  console.log('\n[2] .env 오탐 방지 — 진짜 env 는 fail, SPA fallback(HTML) 은 pass');
  const envReal = mockFetch([
    [/\/\.env$/, { status: 200, headers: { 'content-type': 'text/plain' }, body: 'SUPABASE_URL=https://x.supabase.co\nSERVICE_ROLE=eyJabc.def.ghi\nAPI_KEY=sk-123' }],
    [/./, { status: 404, body: '' }],
  ]);
  const expReal = await checkExposure({ headers: {}, body: '', finalUrl: 'https://app' }, 'https://app', (u, o) => reqWith(envReal, u, o));
  ok('진짜 .env 노출 → fail', expReal.find(r => r.id === 'info.secret-exposed').status === 'fail');

  const envHtml = mockFetch([
    [/./, { status: 200, headers: { 'content-type': 'text/html' }, body: '<!doctype html><html><body>SPA</body></html>' }],
  ]);
  const expHtml = await checkExposure({ headers: {}, body: '', finalUrl: 'https://app' }, 'https://app', (u, o) => reqWith(envHtml, u, o));
  ok('SPA fallback(HTML) → pass(오탐 아님)', expHtml.find(r => r.id === 'info.secret-exposed').status === 'pass');

  console.log('\n[3] CORS — 임의 Origin 반사 + credentials → fail');
  const corsBad = mockFetch([[/./, { status: 200, headers: { 'access-control-allow-origin': 'https://dorms-check-probe.example', 'access-control-allow-credentials': 'true' } }]]);
  const cors = await checkCors('https://app', (u, o) => reqWith(corsBad, u, o));
  ok('reflect+creds → fail', cors[0].status === 'fail');

  console.log('\n[4] RLS 프로브 — 열린 개인정보 테이블을 실제로 잡는다(양성)');
  const anonJwt = 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ role: 'anon', iss: 'supabase' })).toString('base64url') + '.abcdef1234567890signature';
  const vulnRoutes = [
    [/^https:\/\/app\/?$/, { status: 200, headers: { 'content-type': 'text/html' }, body: `<html><script src="https://app/bundle.js"></script></html>` }],
    [/bundle\.js$/, { status: 200, body: `const u="https://abcdefghijklmno.supabase.co";const k="${anonJwt}";` }],
    [/supabase\.co\/rest\/v1\/$/, { status: 200, body: JSON.stringify({ definitions: { students: {}, config: {} } }) }],
    [/students\?/, { status: 200, body: JSON.stringify([{ id: 1, name: '홍길동', email: 'a@b.kr' }]) }],
    [/config\?/, { status: 200, body: JSON.stringify([{ id: 1, key: 'theme' }]) }],
    [/./, { status: 404, body: '' }],
  ];
  const vuln = await rlsProbe('https://app', { fetchImpl: mockFetch(vulnRoutes) });
  const rls = vuln.find(r => r.id === 'code.rls.anon-read');
  ok('개인정보 테이블 열림 → fail', rls.status === 'fail');
  ok('piiLeaks 에 students 포함', rls.evidence.piiLeaks.some(l => l.table === 'students'));

  console.log('\n[5] RLS 프로브 — 잠긴 앱은 pass(음성)');
  const safeRoutes = [
    [/^https:\/\/app\/?$/, { status: 200, headers: { 'content-type': 'text/html' }, body: `<html><script src="https://app/bundle.js"></script></html>` }],
    [/bundle\.js$/, { status: 200, body: `const u="https://abcdefghijklmno.supabase.co";const k="${anonJwt}";` }],
    [/supabase\.co\/rest\/v1\//, { status: 401, body: JSON.stringify({ message: 'permission denied' }) }],
    [/./, { status: 401, body: '{}' }],
  ];
  const safe = await rlsProbe('https://app', { fetchImpl: mockFetch(safeRoutes) });
  ok('잠긴 앱 → pass', safe.find(r => r.id === 'code.rls.anon-read').status === 'pass');

  console.log('\n[6] 마크 게이트 — critical/high fail 이면 미충족');
  const gateFail = scoreSecurity([{ id: 'code.rls.anon-read', status: 'fail', evidence: {} }]);
  ok('RLS fail → 마크 미충족', gateFail.eligible === false);
  const gatePass = scoreSecurity([{ id: 'code.rls.anon-read', status: 'pass', evidence: {} }, { id: 'sec.header.referrer', status: 'fail', evidence: {} }]);
  ok('low 항목만 fail → 마크 충족', gatePass.eligible === true);

  console.log(`\n결과: ${pass} pass, ${fail} fail`);
  if (fail) process.exit(1);
}

// checkExposure/checkCors 는 (mainRes, url, request) 시그니처의 request 로 http.request 를 기대.
// mock 을 http.request 형태로 감싸는 헬퍼.
import { request as realRequest } from '../core/http.js';
function reqWith(fetchImpl, u, o = {}) { return realRequest(u, { ...o, fetchImpl }); }

run().catch(e => { console.error(e); process.exit(1); });

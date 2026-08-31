// 의존성 0 자체검증. 스캐너 회귀 + 할루시네이션 방지 프로브의 양성/음성 케이스.
// 외부 네트워크 없이 mock fetchImpl 로 결정적으로 돌린다.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkHeaders } from '../checks/external/headers.js';
import { checkTls } from '../checks/external/tls.js';
import { checkExposure } from '../checks/external/exposure.js';
import { checkCors } from '../checks/external/cors.js';
import { rlsProbe } from '../checks/runtime/rls-probe.js';
import { firebaseProbe } from '../checks/runtime/firebase-probe.js';
import { scoreSecurity } from '../core/score.js';
import { scoreProtection, PROTECTION_STATE_LABELS } from '../core/tracks.js';
import { runProtectionScan } from '../checks/protection/index.js';
import { canonicalStringify, planSha256, checkPlanApproval } from '../core/protection-plan.js';
import { redactPayload } from '../core/redact.js';
import { buildPayload } from '../core/payload.js';
import { PROTECTION_ITEMS } from '../catalog/protection.js';
import { SECURITY_ITEMS } from '../catalog/security.js';
import { trackMenu, parseTrackSelection } from '../core/config.js';
import { parseEdzipApprovalUrl, safeEdzipApproval } from '../core/edzip-autopilot.js';

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
  console.log('\n[1] 보안 헤더, 누락·무효·약한 값은 fail, 실제 방어 값만 pass');
  const noHdr = checkHeaders({ headers: {} });
  ok('헤더 없음 → csp fail', noHdr.results.find(r => r.id === 'sec.header.csp').status === 'fail');
  const withHdr = checkHeaders({ headers: {
    'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    'strict-transport-security': 'max-age=63072000',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=()',
  } });
  ok('강한 CSP → pass', withHdr.results.find(r => r.id === 'sec.header.csp').status === 'pass');
  ok('CSP nonce → 가점', withHdr.bonus.some(b => b.id === 'sec.header.csp.nonce'));
  const garbage = checkHeaders({ headers: {
    'content-security-policy': 'garbage',
    'strict-transport-security': 'garbage',
    'x-frame-options': 'ALLOWALL',
    'x-content-type-options': 'garbage',
    'referrer-policy': 'garbage',
    'permissions-policy': 'not a policy',
  } });
  ok('문법 없는 헤더 문자열 → 전부 fail', garbage.results.every(r => r.status === 'fail'));
  const weakCsp = checkHeaders({ headers: {
    'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'; form-action 'self'",
  } });
  ok('unsafe-inline·unsafe-eval CSP → fail', weakCsp.results.find(r => r.id === 'sec.header.csp').status === 'fail');
  const shortHsts = checkHeaders({ headers: { 'strict-transport-security': 'max-age=1' } });
  ok('너무 짧은 HSTS → fail', shortHsts.results.find(r => r.id === 'sec.header.hsts').status === 'fail');

  console.log('\n[1-1] TLS, HTTPS 주소 문자열이 아니라 실제 인증서 승인 결과로 판정');
  const tlsBad = await checkTls(
    { finalUrl: 'https://app.example', headers: {} },
    'https://app.example',
    {
      requestImpl: async () => ({ status: 308, headers: { location: 'https://app.example' }, finalUrl: 'http://app.example' }),
      negotiateImpl: async () => ({ protocol: 'TLSv1.3', authorized: false, authError: 'CERT_HAS_EXPIRED' }),
    },
  );
  ok('HTTPS여도 인증서 승인 실패 → ssl fail', tlsBad.find(r => r.id === 'sec.transport.ssl-valid').status === 'fail');
  const tlsGood = await checkTls(
    { finalUrl: 'https://app.example', headers: {} },
    'https://app.example',
    {
      requestImpl: async () => ({ status: 308, headers: { location: 'https://app.example' }, finalUrl: 'http://app.example' }),
      negotiateImpl: async () => ({ protocol: 'TLSv1.3', authorized: true, validTo: 'future' }),
    },
  );
  ok('TLS 1.3 + 승인된 인증서 → ssl pass', tlsGood.find(r => r.id === 'sec.transport.ssl-valid').status === 'pass');

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

  console.log('\n[6] Firebase 프로브 — 공개 RTDB 는 잡고(양성), 잠긴 DB 는 pass, 없으면 na');
  const fbPublic = [
    [/^https:\/\/app\/?$/, { status: 200, headers: { 'content-type': 'text/html' }, body: `<html><script src="https://app/b.js"></script></html>` }],
    [/b\.js$/, { status: 200, body: `const c={databaseURL:"https://demo-default-rtdb.firebaseio.com"};` }],
    [/firebaseio\.com\/\.json/, { status: 200, body: JSON.stringify({ users: true, posts: true }) }],
    [/./, { status: 200, body: '{}' }],
  ];
  const fbP = await firebaseProbe('https://app', { fetchImpl: mockFetch(fbPublic) });
  ok('공개 Firebase RTDB → fail', fbP.find(r => r.id === 'code.firebase.public-read').status === 'fail');
  const fbLocked = [
    [/^https:\/\/app\/?$/, { status: 200, headers: { 'content-type': 'text/html' }, body: `<html><script src="https://app/b.js"></script></html>` }],
    [/b\.js$/, { status: 200, body: `const c={databaseURL:"https://demo-default-rtdb.firebaseio.com"};` }],
    [/firebaseio\.com\/\.json/, { status: 401, body: JSON.stringify({ error: 'Permission denied' }) }],
    [/./, { status: 401, body: '{}' }],
  ];
  const fbL = await firebaseProbe('https://app', { fetchImpl: mockFetch(fbLocked) });
  ok('잠긴 Firebase RTDB → pass', fbL.find(r => r.id === 'code.firebase.public-read').status === 'pass');
  const fbNone = [[/./, { status: 200, headers: { 'content-type': 'text/html' }, body: '<html><script src="https://app/x.js"></script></html>' }], [/x\.js$/, { status: 200, body: 'const a=1;' }]];
  const fbN = await firebaseProbe('https://app', { fetchImpl: mockFetch(fbNone) });
  ok('Firebase 없음 → na', fbN.find(r => r.id === 'code.firebase.public-read').status === 'na');

  console.log('\n[7] 마크 게이트 — critical/high fail 이면 미충족');
  const gateFail = scoreSecurity([{ id: 'code.rls.anon-read', status: 'fail', evidence: {} }]);
  ok('RLS fail → 마크 미충족', gateFail.eligible === false);
  const gateFbFail = scoreSecurity([{ id: 'code.firebase.public-read', status: 'fail', evidence: {} }]);
  ok('Firebase 공개 → 마크 미충족', gateFbFail.eligible === false);
  const requiredPass = SECURITY_ITEMS
    .filter(item => item.gate && item.serverVerifiable && ['critical', 'high'].includes(item.severity))
    .map(item => ({ id: item.id, status: 'pass', evidence: {} }));
  const gatePass = scoreSecurity([...requiredPass, { id: 'sec.header.referrer', status: 'fail', evidence: {} }]);
  ok('low 항목만 fail → 마크 충족', gatePass.eligible === true);
  const providerAbsent = requiredPass.map(item => ['code.rls.anon-read', 'code.firebase.public-read'].includes(item.id)
    ? { ...item, status: 'na', evidence: { providerDetected: false } }
    : item);
  ok('실측으로 provider 없음이 확인된 RLS/Firebase na → 마크 충족', scoreSecurity(providerAbsent).eligible === true);
  const probeFailedNa = providerAbsent.map(item => item.id === 'code.rls.anon-read' ? { ...item, evidence: { probeError: true } } : item);
  ok('프로브 실패를 na로 둔 RLS → 마크 미충족', scoreSecurity(probeFailedNa).eligible === false);
  const invalidNa = requiredPass.map(item => item.id === 'sec.transport.ssl-valid' ? { ...item, status: 'na' } : item);
  ok('SSL critical na는 통과로 계산하지 않음', scoreSecurity(invalidNa).eligible === false);
  ok('검사 결과가 비어 있으면 마크 미충족', scoreSecurity([]).eligible === false);

  console.log('\n[8] protection 결정적 검사 — 새는 빌드는 잡고(양성), 깨끗한 빌드는 통과(음성)');
  {
    // 양성: 시크릿·소스맵·프롬프트 후보가 든 빌드 산출물
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dcheck-selftest-'));
    fs.mkdirSync(path.join(tmp, 'dist', 'assets'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'dist', 'index.html'), '<!doctype html><html><head></head><body>ok<script src="/assets/a.js"></script></body></html>');
    fs.writeFileSync(path.join(tmp, 'dist', 'assets', 'a.js'), 'const k="sk-abcdefghijklmnopqrstuvwx123456";const p="You are a strict teacher assistant";\n//# sourceMappingURL=a.js.map');
    fs.writeFileSync(path.join(tmp, 'dist', 'assets', 'a.js.map'), '{}');
    const vuln = runProtectionScan(tmp);
    const get = id => vuln.items.find(r => r.id === id);
    ok('배포물 시크릿 → fail', get('protection.boundary.client-secrets').status === 'fail');
    ok('프롬프트 후보 → pending(문맥 판단으로 넘김)', get('protection.boundary.prompt').status === 'pending');
    ok('소스맵 → fail', get('protection.release.sourcemap').status === 'fail');
    ok('권리 설문 전 → owner-status pending', get('protection.rights.owner-status').status === 'pending');

    // 음성: 깨끗한 빌드
    fs.writeFileSync(path.join(tmp, 'dist', 'assets', 'a.js'), 'console.warn("hello");fetch("/api/x");');
    fs.rmSync(path.join(tmp, 'dist', 'assets', 'a.js.map'));
    const clean = runProtectionScan(tmp);
    const get2 = id => clean.items.find(r => r.id === id);
    ok('깨끗한 빌드 → 시크릿 pass', get2('protection.boundary.client-secrets').status === 'pass');
    ok('깨끗한 빌드 → 소스맵 pass', get2('protection.release.sourcemap').status === 'pass');
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  console.log('\n[9] protection 6상태 채점 — 미확인은 보수적(공개 자산·권리관계 확인 필요)');
  {
    const allPending = PROTECTION_ITEMS.map(it => ({ id: it.id, status: 'pending', evidence: {} }));
    const s1 = scoreProtection(allPending);
    ok('전부 미확인 → 권리관계 확인 필요', s1.states.rights === 'unresolved' && s1.labels.rights === PROTECTION_STATE_LABELS.rights.unresolved);
    ok('전부 미확인 → 공개 자산 가정', s1.states.boundary === 'public_asset');
    ok('전부 미확인 → eligible 아님', s1.eligible === false);

    const allPass = PROTECTION_ITEMS.map(it => ({ id: it.id, status: 'pass', evidence: {} }));
    const s2 = scoreProtection(allPass);
    ok('전부 통과 → 서버 분리 확인 + 조치·안내 설정', s2.states.boundary === 'server_separated' && s2.states.release === 'copy_cost_raised' && s2.states.notice === 'notice_configured');
    ok('전부 통과 → eligible', s2.eligible === true);

    const promptLeak = allPass.map(r => r.id === 'protection.boundary.prompt' ? { ...r, status: 'fail' } : r);
    const s3 = scoreProtection(promptLeak);
    ok('프롬프트 유출만 fail → 일부 서버 분리', s3.states.boundary === 'partially_separated');
  }

  console.log('\n[10] 보호 계획 해시 — 키 순서 무관 동일, 변조는 감지');
  {
    const a = { b: 1, a: { d: [1, 2], c: 'x' } };
    const b = { a: { c: 'x', d: [1, 2] }, b: 1 };
    ok('정규화 직렬화: 키 순서 무관 동일', canonicalStringify(a) === canonicalStringify(b));
    const plan = { schemaVersion: 1, steps: [{ id: 'sourcemap', willChange: ['dist/a.js'] }] };
    plan.planSha256 = planSha256(plan);
    ok('올바른 해시 → 승인', checkPlanApproval(plan, plan.planSha256).ok === true);
    ok('다른 해시 → 거부', checkPlanApproval(plan, 'deadbeef').ok === false);
    const tampered = { ...plan, steps: [{ id: 'sourcemap', willChange: ['dist/a.js', 'dist/b.js'] }] };
    ok('계획 변조 → 거부(내장 해시 불일치)', checkPlanApproval(tampered, plan.planSha256).ok === false);
  }

  console.log('\n[11] 제출 마스킹(redact) — 시크릿·개인 경로는 가리고 앱 주소는 보존');
  {
    const payload = {
      app: { url: 'https://my-app.example' },
      items: [{ observed: '키 sk-abcdefghijklmnopqrstuvwx123456 가 /Users/kim/proj 에서 발견', evidence: { hits: [{ file: 'a.js', kind: 'AKIAABCDEFGHIJKLMNOP' }] } }],
    };
    const r = redactPayload(payload);
    const s = JSON.stringify(r);
    ok('sk- 키 마스킹', !s.includes('sk-abcdefghijklmnopqrstuvwx123456') && s.includes('마스킹'));
    ok('절대 경로 마스킹', !s.includes('/Users/kim'));
    ok('AWS 키 마스킹', !s.includes('AKIAABCDEFGHIJKLMNOP'));
    ok('앱 주소는 보존', r.app.url === 'https://my-app.example');
  }

  console.log('\n[12] 페이로드 하위 호환 — v1 트랙만이면 schemaVersion 1 + protection 키 없음');
  {
    const cfg = { app: { name: 'x', url: 'https://x', stack: 'next' }, tracks: ['security'], teacher: {} };
    const results = [{ id: 'sec.header.csp', status: 'pass', observed: 'ok', evidence: {} }];
    const v1 = buildPayload({ config: cfg, results, trackResults: { security: scoreSecurity(results) }, bonus: [], toolVersion: 't' });
    ok('security 만 → schemaVersion 1', v1.schemaVersion === 1);
    ok('v1 tracks 에 security/edzip 키 유지', 'security' in v1.tracks && 'edzip' in v1.tracks);
    ok('v1 tracks 에 protection 키 없음', !('protection' in v1.tracks));
    const cfg2 = { ...cfg, tracks: ['security', 'protection'] };
    const v2 = buildPayload({ config: cfg2, results, trackResults: { security: scoreSecurity(results), protection: scoreProtection([]) }, bonus: [], toolVersion: 't' });
    ok('protection 포함 → schemaVersion 2 + tracks.protection', v2.schemaVersion === 2 && Boolean(v2.tracks.protection));
  }

  console.log('\n[13] 트랙 선택 파서 — 대화형 init 에서 고른 축(번호·이름)을 부분집합으로 정규화');
  {
    const menu = trackMenu();
    ok('메뉴는 레지스트리 3축(순서 보존)', menu.length === 3 && menu[0].id === 'security' && menu[1].id === 'edzip' && menu[2].id === 'protection');
    ok("번호 '1' → security 단일", JSON.stringify(parseTrackSelection('1', menu)) === JSON.stringify(['security']));
    ok("번호 '1,3' → security+protection(부분집합)", JSON.stringify(parseTrackSelection('1,3', menu)) === JSON.stringify(['security', 'protection']));
    ok("이름 'security,protection' → 동일", JSON.stringify(parseTrackSelection('security,protection', menu)) === JSON.stringify(['security', 'protection']));
    ok('공백 구분·중복 제거', JSON.stringify(parseTrackSelection('2 2 security', menu)) === JSON.stringify(['edzip', 'security']));
    ok('빈 입력 → 빈 배열(호출부가 기본값 처리)', parseTrackSelection('', menu).length === 0);
    ok('전부 유효하지 않은 입력 → 빈 배열', parseTrackSelection('9,xyz', menu).length === 0);
    ok('일부만 유효 → 유효한 것만(순서 보존)', JSON.stringify(parseTrackSelection('9,3,x,1', menu)) === JSON.stringify(['protection', 'security']));
  }

  console.log('\n[14] 에듀집 승인 주소 — 고정 호스트·경로·안전 필드만 허용');
  {
    const id = '6a0fd9e85a2ee7c772401a32';
    const legacy = parseEdzipApprovalUrl(`https://edzip.kr/utilization/learning-sw/${id}`);
    ok('과거 공식 경로 → 정규 주소', legacy.ok && legacy.normalizedUrl === `https://edzip.kr/learning-sw/${id}`);
    ok('외부 호스트 → 거부', parseEdzipApprovalUrl(`https://evil.example/learning-sw/${id}`).ok === false);
    ok('사용자정보 포함 URL → 거부', parseEdzipApprovalUrl(`https://name@edzip.kr/learning-sw/${id}`).ok === false);
    const approved = safeEdzipApproval({ data: { productName: '살핌', displayStatus: 'enable', confirmStatus: 'confirmed', email: 'private@example.com', phoneNumber: '010-0000-0000' } }, '살핌', legacy.normalizedUrl, id);
    ok('공개·확인 완료 + 제품명 일치 → 통과', approved.ok === true);
    ok('PII 필드는 반환하지 않음', !('email' in approved) && !('phoneNumber' in approved));
    ok('제품명 불일치 → 거부', safeEdzipApproval({ data: { productName: '다른 앱', displayStatus: 'enable', confirmStatus: 'confirmed' } }, '살핌', legacy.normalizedUrl, id).ok === false);
  }

  console.log(`\n결과: ${pass} pass, ${fail} fail`);
  if (fail) process.exit(1);
}

// checkExposure/checkCors 는 (mainRes, url, request) 시그니처의 request 로 http.request 를 기대.
// mock 을 http.request 형태로 감싸는 헬퍼.
import { request as realRequest } from '../core/http.js';
function reqWith(fetchImpl, u, o = {}) { return realRequest(u, { ...o, fetchImpl }); }

run().catch(e => { console.error(e); process.exit(1); });

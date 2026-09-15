// 의존성 0 자체검증. 스캐너 회귀 + 할루시네이션 방지 프로브의 양성/음성 케이스.
// 외부 네트워크 없이 mock fetchImpl 로 결정적으로 돌린다.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkSecrets } from '../checks/static/secrets.js';
import { scoreSecurity } from '../core/score.js';
import { scoreProtection, PROTECTION_STATE_LABELS } from '../core/tracks.js';
import { runProtectionScan } from '../checks/protection/index.js';
import { canonicalStringify, planSha256, checkPlanApproval } from '../core/protection-plan.js';
import { redactPayload } from '../core/redact.js';
import { buildPayload } from '../core/payload.js';
import { PROTECTION_ITEMS } from '../catalog/protection.js';
import { trackMenu, parseTrackSelection } from '../core/config.js';
import { parseEdzipApprovalUrl, safeEdzipApproval } from '../core/edzip-autopilot.js';

let pass = 0, fail = 0;
function ok(name, cond) { if (cond) { pass++; console.log('  v', name); } else { fail++; console.error('  x', name); } }

async function run() {
  const secretCase = (name, text) => {
    const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'dcheck-secret-fixture-'));
    fs.writeFileSync(path.join(fixture, name), text);
    try { return checkSecrets(fixture)[0].status === 'fail'; }
    finally { fs.rmSync(fixture, { recursive: true, force: true }); }
  };
  ok('대문자 SUPABASE_SERVICE_ROLE_KEY JWT → hardcoded secret fail', secretCase('legacy.env', 'SUPABASE_SERVICE_ROLE_KEY=eyJAAAAAAAAAAAA.eyJBBBBBBBBBBBB.signature\n'));
  ok('새 sb_secret_ Supabase key → hardcoded secret fail', secretCase('modern.env', 'SUPABASE_SECRET_KEY=sb_secret_abcdefghijklmnopqrstuvwxyz_123456\n'));
  ok('OpenAI sk-proj 형식 → hardcoded secret fail', secretCase('openai.env', `OPENAI_API_KEY=sk-proj-${'A'.repeat(32)}\n`));
  ok('Anthropic sk-ant 형식 → hardcoded secret fail', secretCase('anthropic.env', `ANTHROPIC_API_KEY=sk-ant-${'B'.repeat(32)}\n`));
  ok('GitHub fine-grained token 형식 → hardcoded secret fail', secretCase('github.env', `GITHUB_TOKEN=github_pat_${'C'.repeat(32)}\n`));
  const serviceRolePayload = Buffer.from(JSON.stringify({ role: 'service_role', ref: 'fixture' })).toString('base64url');
  ok('변수명 없는 service_role JWT payload → hardcoded secret fail', secretCase('payload.js', `export const token = "eyJhbGciOiJIUzI1NiJ9.${serviceRolePayload}.signature";\n`));

  // Public security scenarios are covered by verify/minimum-test.js.

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

run().catch(e => { console.error(e); process.exit(1); });

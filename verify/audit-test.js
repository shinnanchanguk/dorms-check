// 심층 점검(audit) 자체 시험. 네트워크 없이 임시 폴더의 가짜 앱으로 돈다.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { buildInventory } from '../audit/inventory.js';
import { buildLedger, validateLedger, encodeRef, isCleanRef, coverageId } from '../audit/ledger.js';
import { validateFinding, validateFindings } from '../audit/findings.js';
import { planRun, huntPrompt, verifierPrompt, criticPrompt, mergeResult, recordDecision, promoteArtifact, checkRun, reportRun, resolveOutputRoot, resolveRunDir, loadRun } from '../audit/run.js';
const resolveRunDirFor = (root, run) => resolveRunDir(root, run);

// 시험은 홈 폴더를 건드리지 않는다.
process.env.DORMS_CHECK_AUDIT_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'dcheck-audit-home-'));

let pass = 0, fail = 0;
function ok(name, cond) { if (cond) { pass++; console.log('  v', name); } else { fail++; console.error('  x', name); } }
function throws(fn, re) { try { fn(); return false; } catch (e) { return re ? re.test(String(e.message)) : true; } }
const write = (root, rel, text) => { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), text); };
const git = (root, ...a) => execFileSync('git', ['-C', root, ...a], { stdio: 'ignore' });

function fixture({ ignore = true } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dcheck-audit-'));
  write(root, 'package.json', JSON.stringify({ name: 'demo', dependencies: { next: '15.0.0', '@supabase/supabase-js': '2.0.0', openai: '4.0.0' } }));
  write(root, 'package-lock.json', '{}');
  write(root, 'app/api/notes/[id]/route.ts', "import { createClient } from '@/lib/s';\nexport async function GET(req) {\n  const id = req.nextUrl.searchParams.get('id');\n  return Response.json(await db(id));\n}\n");
  write(root, 'app/actions.ts', "'use server'\nexport async function save(v) { return v }\n");
  write(root, 'lib/ai.ts', "import OpenAI from 'openai';\nexport const ai = new OpenAI();\n");
  write(root, 'components/Note.tsx', "export function Note({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} /> }\n");
  write(root, 'supabase/migrations/0001.sql', 'create table notes(id uuid);\nalter table notes enable row level security;\ncreate policy p on notes for select using (true);\ncreate or replace function public.give(n int) returns void language plpgsql security definer as $$ begin end $$;\ncreate or replace function public.old_fn() returns void language plpgsql security definer as $$ begin end $$;\n');
  write(root, 'supabase/migrations/0002.sql', 'create or replace function public.old_fn() returns void language plpgsql security invoker as $$ begin end $$;\n');
  write(root, 'vercel.json', JSON.stringify({ crons: [{ path: '/api/cron/daily', schedule: '0 0 * * *' }] }));
  write(root, 'scripts/ops.mjs', 'export const x = 1;\n');
  write(root, 'tests/a.test.js', 'test()\n');
  write(root, '.gitignore', ignore ? '.dorms-check/\nnode_modules/\n' : 'node_modules/\n');
  git(root, 'init', '-q');
  git(root, 'add', '-A');
  execFileSync('git', ['-C', root, '-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-qm', 'init'], { stdio: 'ignore' });
  return root;
}

const goodConfirmed = fp => ({
  verdict: 'confirmed', fingerprint: fp, title: '노트 남의 것 읽기', description: '소유 확인 없이 id 로 조회', root_cause: '소유자 조건 없음', intended_behavior: '본인 노트만',
  trace: [{ kind: 'entrypoint', file: 'app/api/notes/[id]/route.ts', line: 2, scope: 'GET', description: 'id 입력' }, { kind: 'sink', file: 'app/api/notes/[id]/route.ts', line: 4, scope: 'GET', description: '조회 반환' }],
  evidence: [{ file: 'app/api/notes/[id]/route.ts', line: 4, description: '조건 없음' }],
  conditions: [{ kind: 'authentication_level', description: '로그인한 회원' }],
  execution: { attacker_perspective: '다른 회원', payloads: ['id=dummy-b'], instructions: ['가짜 계정 둘로 로컬 시험'], observed_result: 'B 의 가짜 노트가 반환됨' },
  remediation: { strategy: 'user_id = auth.uid() 조건 추가' },
  severity: { likelihood: { score: 'high', reason: '쉬움' }, impact: { score: 'high', reason: '다른 회원 노트' }, overall_severity: 'high' },
  confidence: { score: 'high', reason: '재현' },
});
const goodNeeds = fp => ({
  verdict: 'needs_validation', fingerprint: fp, title: '버킷 공개 여부', description: '정책이 저장소에 없음', claimed_root_cause: '버킷 설정 미확인',
  trace: [{ kind: 'sink', file: 'supabase/migrations/0001.sql', line: 3, scope: 'policy', description: '정책' }],
  evidence: [{ file: 'supabase/migrations/0001.sql', line: 3, description: '정책' }],
  blockers: ['운영 버킷 설정'], validation_plan: { deployment: '대시보드에서 버킷 공개 여부 확인' },
});

async function run() {
  console.log('\n[audit-1] 참조·ID');
  ok('퍼센트 인코딩: 비예약 문자만 그대로', encodeRef('a/b c#한') === 'a%2Fb%20c%23%ED%95%9C');
  ok('앞뒤 공백 참조 거부', !isCleanRef(' a'));
  ok('보이지 않는 문자 참조 거부', !isCleanRef('a​b'));
  ok('NFC 아닌 참조 거부', !isCleanRef('가'));
  ok('ID 는 참조 넷을 :: 로 잇는다', coverageId({ surface: 's', boundary: 'b', subsystem: 'x', attack_class: 'c' }) === 's::b::x::c');

  console.log('\n[audit-2] 표면 목록');
  const root = fixture();
  const inv = buildInventory(root);
  const has = (kind, file) => inv.surfaces.some(s => s.kind === kind && (!file || s.file === file));
  ok('API 경로와 메서드', inv.surfaces.some(s => s.kind === 'api-route' && s.scope === 'GET'));
  ok('서버 액션', has('server-action', 'app/actions.ts'));
  ok('AI 호출', has('ai-call', 'lib/ai.ts'));
  ok('HTML 그리기', has('html-sink', 'components/Note.tsx'));
  ok('cron 경로', inv.surfaces.some(s => s.kind === 'cron-route' && s.scope === '/api/cron/daily'));
  ok('마지막 정의가 SECURITY DEFINER 인 함수만', inv.surfaces.some(s => s.kind === 'db-function' && s.scope === 'give') && !inv.surfaces.some(s => s.kind === 'db-function' && s.scope === 'old_fn'));
  ok('운영 스크립트·시험은 표면에서 뺀다', !inv.surfaces.some(s => s.file.startsWith('scripts/') || s.file.startsWith('tests/')) && inv.operator_or_test_files.scripts === 1);
  const scoped = buildInventory(root, { scope: ['app/api'] });
  ok('--scope 밖 표면은 따로 남긴다', scoped.surfaces.every(s => s.file.startsWith('app/api/')) && scoped.scoped_out.length > 0);

  console.log('\n[audit-3] 범위표');
  for (const profile of ['quick', 'standard', 'deep']) {
    const l = buildLedger(inv, { profile });
    ok(`${profile}: 검증 통과`, validateLedger(l).length === 0);
  }
  const quick = buildLedger(inv, { profile: 'quick' });
  ok('표면 없는 분류는 해당 없음+이유', quick.some(u => u.class_id === 'native-shell' && u.status === 'not_applicable' && u.unresolved.length));
  ok('겹치는 결정적 분류(헤더·비밀값)는 범위표에 없다', !quick.some(u => /header|secret/.test(u.class_id)));
  const bad = JSON.parse(JSON.stringify(quick));
  bad[0].status = 'covered'; bad[0].agent_id = 'h1';
  ok('근거 없는 covered 거부', validateLedger(bad).some(e => /근거|확인 기록/.test(e)));
  const bad2 = JSON.parse(JSON.stringify(quick));
  Object.assign(bad2[0], { status: 'candidate', agent_id: 'h1', reviewed_paths: ['a.ts'], local_checks: [{ agent_id: 'h1', reviewed_paths: ['a.ts'], invariant: 'x', method: 'source', result: 'y', artifact: null }] });
  ok('지문 없는 candidate 거부', validateLedger(bad2).some(e => /지문/.test(e)));
  const bad3 = JSON.parse(JSON.stringify(quick));
  Object.assign(bad3[0], { status: 'covered', agent_id: 'h1', reviewed_paths: ['a.ts'], local_checks: [{ agent_id: 'h1', reviewed_paths: ['a.ts'], invariant: 'x', method: 'local', result: 'y', artifact: 'scratch/out.txt' }] });
  ok('담당자 artifacts 밖 산출물 거부', validateLedger(bad3).some(e => /artifacts/.test(e)));
  const bad4 = JSON.parse(JSON.stringify(quick));
  Object.assign(bad4[0], { status: 'covered', agent_id: 'h1', reviewed_paths: ['/etc/passwd'], local_checks: [{ agent_id: 'h1', reviewed_paths: ['/etc/passwd'], invariant: 'x', method: 'source', result: 'y', artifact: null }] });
  ok('절대 경로 거부', validateLedger(bad4).some(e => /상대 경로/.test(e)));
  const bad5 = JSON.parse(JSON.stringify(quick));
  bad5[1] = { ...bad5[0] };
  ok('중복 ID 거부', validateLedger(bad5).some(e => /중복/.test(e)));
  const bad6 = JSON.parse(JSON.stringify(quick));
  bad6[0].agent_id = 'CON';
  ok('대문자·장치 이름 담당자 거부', validateLedger(bad6).length > 0);

  console.log('\n[audit-4] 결과 기록 계약');
  ok('정상 confirmed 통과', validateFinding(goodConfirmed('notes.idor')).length === 0);
  ok('정상 needs_validation 통과', validateFinding(goodNeeds('bucket.public')).length === 0);
  const over = goodConfirmed('x'); over.severity.overall_severity = 'critical';
  ok('전체 심각도 > 관찰 영향 거부', validateFinding(over).some(e => /높을 수 없/.test(e)));
  ok('미확인에 심각도 붙이면 거부', validateFinding({ ...goodNeeds('y'), severity: goodConfirmed('y').severity }).some(e => /쓰지 않는/.test(e)));
  const noPlan = goodNeeds('z'); noPlan.validation_plan = {};
  ok('확인 방법 없는 미확인 거부', validateFinding(noPlan).some(e => /validation_plan/.test(e)));
  const rej = { verdict: 'rejected', fingerprint: 'r', title: 't', description: 'd', claimed_root_cause: 'c', trace: goodNeeds('r').trace, evidence: goodNeeds('r').evidence, reason: '코드가 막음' };
  ok('정상 rejected 통과', validateFinding(rej).length === 0);
  ok('rejected 에 수정안 넣으면 거부', validateFinding({ ...rej, remediation: { strategy: 'x' } }).length > 0);
  const wrongOrder = goodConfirmed('w'); wrongOrder.trace = [...wrongOrder.trace].reverse();
  ok('경로가 entrypoint 로 시작·sink 로 끝나야', validateFinding(wrongOrder).some(e => /entrypoint|sink/.test(e)));
  ok('공백 든 지문 거부', validateFinding(goodConfirmed('a b')).some(e => /fingerprint/.test(e)));
  ok('모르는 필드 거부', validateFinding({ ...goodConfirmed('u'), extra: 1 }).some(e => /없는 필드/.test(e)));
  ok('같은 지문 두 번 거부', validateFindings([goodConfirmed('d'), goodConfirmed('d')]).some(e => /두 번/.test(e)));

  console.log('\n[audit-5] 결과 폴더는 버전 관리 밖');
  const unignored = fixture({ ignore: false });
  const out = resolveOutputRoot(unignored, null);
  ok('.dorms-check 를 무시하지 않는 저장소면 앱 폴더 밖(홈 쪽)으로', !out.dir.startsWith(unignored) && out.dir.startsWith(process.env.DORMS_CHECK_AUDIT_HOME));
  ok('무시되지 않는 앱 안 경로 --out 거부', throws(() => resolveOutputRoot(unignored, 'audit-out'), /gitignore/));
  ok('무시하는 저장소면 .dorms-check/audit', resolveOutputRoot(root, null).dir === path.join(root, '.dorms-check', 'audit'));

  console.log('\n[audit-6] 한 회차 흐름(quick)');
  const { runDir, ledger } = planRun(root, { profile: 'quick' });
  ok('계획 파일 생성', ['run-metadata.json', 'coverage-ledger.json', 'architecture.md', 'AUDIT-PLAN.md'].every(f => fs.existsSync(path.join(runDir, f))));
  const planned = ledger.filter(u => u.status === 'planned').map(u => u.coverage_id);
  const routeUnit = ledger.find(u => u.class_id === 'access-control' && u.surface === 'kind/api-route');
  const prompt = huntPrompt(runDir, { agentId: 'h1', unitIds: planned });
  ok('지시문에 분류 내용이 그대로 들어간다', prompt.includes('같은 상태 변경에 이르는 다른 길') && prompt.includes('후보 문턱'));
  ok('배정하면 진행 중+담당자', loadRun(runDir)['coverage-ledger.json'].filter(u => u.agent_id === 'h1').length === planned.length);
  ok('진행 중 단위는 다른 담당자에게 못 맡김', throws(() => huntPrompt(runDir, { agentId: 'h2', unitIds: [planned[0]] }), /planned/));
  const check = (id, p) => ({ agent_id: 'h1', reviewed_paths: [p], invariant: '권한 확인', method: 'source', result: '확인함', artifact: null });
  const units = planned.map(id => id === routeUnit.coverage_id
    ? { coverage_id: id, disposition: 'candidate', reviewed_paths: ['app/api/notes/[id]/route.ts'], checks: [check(id, 'app/api/notes/[id]/route.ts')], candidate_fingerprints: ['notes.idor'], unresolved: [] }
    : { coverage_id: id, disposition: 'covered', reviewed_paths: ['app/actions.ts'], checks: [check(id, 'app/actions.ts')], candidate_fingerprints: [], unresolved: [] });
  const dropped = units.pop();
  const { verdict, ...cand } = goodConfirmed('notes.idor');
  const m = mergeResult(runDir, { agentId: 'h1', input: { units, candidates: [{ proposed_verdict: 'confirmed', ...cand }], hardening: ['CSP 에 unsafe-eval 이 남음'], uncovered: [] } });
  ok('찾기 결과 병합', m.accepted.length === units.length && m.candidates === 1 && m.errors.length === 0);
  ok('결과에 빠진 단위는 다시 예정으로', loadRun(runDir)['coverage-ledger.json'].find(u => u.coverage_id === dropped.coverage_id).status === 'planned');
  huntPrompt(runDir, { agentId: 'h3', unitIds: [dropped.coverage_id] });
  mergeResult(runDir, { agentId: 'h3', input: { units: [{ ...dropped, checks: dropped.checks.map(c => ({ ...c, agent_id: 'h3' })) }], candidates: [], hardening: [], uncovered: [] } });
  ok('맡지 않은 후보 지문은 거부', mergeResult(runDir, { agentId: 'h9', input: { units: [], candidates: [{ proposed_verdict: 'confirmed', ...cand, fingerprint: 'ghost' }] } }).errors.length > 0);
  ok('찾은 담당자는 자기 후보 검증 못 함', throws(() => verifierPrompt(runDir, { agentId: 'h1', fingerprint: 'notes.idor' }), /찾은/));
  ok('검증 지시문 생성', verifierPrompt(runDir, { agentId: 'v1', fingerprint: 'notes.idor' }).includes('반박'));
  const selfRec = recordDecision(runDir, { agentId: 'h1', input: { decision: 'confirmed', record: goodConfirmed('notes.idor') } });
  ok('찾은 담당자의 검증 기록 거부', selfRec.errors.length === 1 && selfRec.applied.length === 0);
  const rec = recordDecision(runDir, { agentId: 'v1', input: { decision: 'confirmed', record: goodConfirmed('notes.idor') } });
  ok('새 검증자의 기록 반영', rec.applied.includes('notes.idor'));
  let chk = checkRun(runDir);
  ok('범위 비평 전에는 미완료', !chk.complete && chk.reasons.some(r => /범위 비평/.test(r)));
  ok('비평 지시문 생성', criticPrompt(runDir, { agentId: 'c1' }).includes('빠진 범위'));
  mergeResult(runDir, { agentId: 'c1', input: { missing_units: [{ surface: 'kind/api-route', boundary: 'api-route', subsystem: 'app/api/admin', attack_class: 'access-control', starting_paths: ['app/api/notes/[id]/route.ts'], reason: '관리자 경로 빠짐' }], reassign_ids: [], resolved_prior_leads: [], stop: false } });
  ok('quick 비평이 찾은 빈칸은 미룸', loadRun(runDir)['coverage-ledger.json'].some(u => u.subsystem === 'app/api/admin' && u.status === 'deferred'));
  chk = checkRun(runDir);
  ok('quick 완료 판정', chk.complete && chk.errors.length === 0);
  const rep = reportRun(root, runDir);
  ok('보고서: 부분 점검 고지·확인한 위험·권고', rep.md.includes('부분 점검') && rep.md.includes('확인한 위험 (1건)') && rep.md.includes('unsafe-eval'));
  ok('보고서 작성 뒤 완료 상태', loadRun(runDir)['run-metadata.json'].run_status === 'complete');

  console.log('\n[audit-7] 산출물 승격');
  const scratch = path.join(runDir, 'agents', 'v1', 'scratch');
  fs.writeFileSync(path.join(scratch, 'out.txt'), 'observed');
  ok('일반 파일 승격', promoteArtifact(runDir, { agentId: 'v1', file: 'out.txt' }) === 'agents/v1/artifacts/out.txt');
  ok('같은 이름 다시 승격은 거부(덮어쓰지 않음)', throws(() => promoteArtifact(runDir, { agentId: 'v1', file: 'out.txt' })));
  fs.symlinkSync('/etc/hosts', path.join(scratch, 'link.txt'));
  ok('심볼릭 링크 승격 거부', throws(() => promoteArtifact(runDir, { agentId: 'v1', file: 'link.txt' })));
  ok('.. 경로 승격 거부', throws(() => promoteArtifact(runDir, { agentId: 'v1', file: '../x' })));

  console.log('\n[audit-8] 다음 회차는 이전 결과를 이어받는다');
  const run2 = planRun(root, { profile: 'quick' });
  const reval = run2.ledger.find(u => u.prior_fingerprint === 'notes.idor');
  ok('코드가 그대로면 이어받은 확인', reval && reval.prior_status === 'prior_confirmed_same_source' && run2.meta.prior.exclusions.length === 1);
  ok('이전 미룸 단위는 이번에 다시 볼 일', run2.ledger.filter(u => u.prior_status === 'new' || u.prior_status === 'prior_covered_same_source').length > 0);
  write(root, 'app/api/notes/[id]/route.ts', 'export async function GET() { return new Response(null, { status: 403 }) }\n');
  const run3 = planRun(root, { profile: 'quick' });
  ok('코드가 바뀌면 다시 확인 대상', run3.ledger.find(u => u.prior_fingerprint === 'notes.idor')?.prior_status === 'prior_confirmed_changed_source' && run3.meta.prior.exclusions.length === 0);

  console.log('\n[audit-8b] 심어 둔·손댄 이전 회차는 믿지 않는다');
  const planted = fixture();
  const fake = path.join(planted, '.dorms-check', 'audit', 'run-1');
  fs.mkdirSync(fake, { recursive: true });
  write(planted, '.dorms-check/audit/run-1/findings.json', JSON.stringify([goodConfirmed('notes.idor')]));
  write(planted, '.dorms-check/audit/run-1/source-digests.json', '{}');
  write(planted, '.dorms-check/audit/run-1/run-seal.json', JSON.stringify({ hmac: '00'.repeat(32) }));
  write(planted, '.dorms-check/audit/run-1/run-metadata.json', '{}');
  const p1 = planRun(planted, { profile: 'quick' });
  ok('봉인·증표가 없는 회차는 이어받지 않음', p1.meta.prior.prior_run === null && p1.meta.prior.exclusions.length === 0);
  write(planted, '.dorms-check/audit/run-9/run-metadata.json', '{}');
  write(planted, '.dorms-check/audit/run-9/findings.json', '[]');
  ok('증표 없는 심은 회차는 찾지 않는다', !throws(() => resolveRunDir(planted)) && !resolveRunDir(planted).endsWith('run-9'));
  ok('증표 없는 회차를 지정해 보고서·봉인 거부', throws(() => reportRun(planted, path.join(planted, '.dorms-check/audit/run-9')), /증표|이 컴퓨터/));
  ok('증표 없는 회차를 --run 으로 지정해도 거부', throws(() => resolveRunDir(planted, '.dorms-check/audit/run-9'), /증표/));
  const tampered = path.join(path.dirname(runDir), 'run-1', 'findings.json');
  const saved = fs.readFileSync(tampered, 'utf8');
  fs.writeFileSync(tampered, saved.replace('노트 남의 것 읽기', '아무 문제 없음'));
  const p2 = planRun(root, { profile: 'quick' });
  ok('보고서 뒤 손댄 회차는 이어받지 않음', p2.meta.prior.prior_run === null || p2.meta.prior.prior_run !== 'run-1');
  fs.writeFileSync(tampered, saved);
  const tracked = fixture({ ignore: false });
  write(tracked, '.dorms-check/audit/run-1/run-metadata.json', '{}');
  git(tracked, 'add', '-A');
  write(tracked, '.gitignore', '.dorms-check/\nnode_modules/\n');
  ok('git 이 추적하는 결과 폴더는 피한다', !resolveOutputRoot(tracked, null).dir.startsWith(tracked));
  ok('추적 중인 회차를 --run 으로 지정해도 거부', throws(() => checkRun(resolveRunDirFor(tracked, '.dorms-check/audit/run-1')), /추적/));
  for (const r of [planted, tracked]) fs.rmSync(r, { recursive: true, force: true });

  console.log('\n[audit-9] standard: 최종 확인과 뜻이 바뀌는 교체');
  const root2 = fixture();
  const s = planRun(root2, { profile: 'standard' });
  const sid = s.ledger.find(u => u.class_id === 'access-control' && u.status === 'planned').coverage_id;
  huntPrompt(s.runDir, { agentId: 'h1', unitIds: [sid] });
  const { verdict: _v, ...needsCand } = goodNeeds('bucket.public');
  mergeResult(s.runDir, { agentId: 'h1', input: { units: [{ coverage_id: sid, disposition: 'candidate', reviewed_paths: ['supabase/migrations/0001.sql'], checks: [{ agent_id: 'h1', reviewed_paths: ['supabase/migrations/0001.sql'], invariant: 'x', method: 'source', result: 'y', artifact: null }], candidate_fingerprints: ['bucket.public'], unresolved: [] }], candidates: [{ proposed_verdict: 'needs_validation', ...needsCand }] } });
  recordDecision(s.runDir, { agentId: 'v1', input: { decision: 'needs_validation', record: goodNeeds('bucket.public') } });
  ok('3단계 검증자는 최종 확인 못 함', recordDecision(s.runDir, { agentId: 'v1', input: { decision: 'verified', fingerprint: 'bucket.public' } }).errors.length === 1);
  const stronger = goodConfirmed('bucket.public');
  const rp = recordDecision(s.runDir, { agentId: 'v2', input: { decision: 'replace', reason: '로컬 재현됨', record: stronger } });
  ok('더 센 판정으로 교체는 대기', rp.pending.includes('bucket.public') && loadRun(s.runDir)['findings.json'][0].verdict === 'needs_validation');
  ok('제안자는 자기 교체를 확인 못 함', recordDecision(s.runDir, { agentId: 'v2', input: { decision: 'verified', fingerprint: 'bucket.public' } }).errors.length === 1);
  recordDecision(s.runDir, { agentId: 'v3', input: { decision: 'verified', fingerprint: 'bucket.public' } });
  ok('새 담당자 확인 뒤 교체 적용', loadRun(s.runDir)['findings.json'][0].verdict === 'confirmed');
  ok('standard 는 남은 단위·깨끗한 비평 전 미완료', !checkRun(s.runDir).complete);

  for (const r of [root, root2, unignored, process.env.DORMS_CHECK_AUDIT_HOME]) fs.rmSync(r, { recursive: true, force: true });
  console.log(`\naudit: ${pass} 통과 · ${fail} 실패`);
  if (fail) process.exit(1);
}

run().catch(e => { console.error(e); process.exit(1); });

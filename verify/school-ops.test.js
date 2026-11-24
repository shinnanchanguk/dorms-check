// 학교 운영 보안 절차(dcheck ops)의 결정적 시험. 네트워크 없음(설정 읽기는 가짜 fetch).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { SCHOOL_OPS, SHEET2_ROWS, SHEET3_ROWS } from '../catalog/school-ops.js';
import { opsCodeSignals, buildOpsState, makeDecision, sheetRows, renderOpsMd, renderSelfcheckMd } from '../core/school-ops.js';
import { mapSupabaseConfig, readSupabaseConfig, detectSupabaseRef } from '../checks/runtime/supabase-config.js';

let pass = 0, fail = 0;
function ok(name, cond) { if (cond) { pass++; console.log('  v', name); } else { fail++; console.error('  x', name); } }
const BIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'dcheck.js');
function project(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dcheck-ops-'));
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return root;
}

console.log('\n[운영 절차] 카탈로그');
{
  const ids = new Set(SCHOOL_OPS.map(o => o.id));
  ok('id 가 겹치지 않음', ids.size === SCHOOL_OPS.length);
  ok('모든 항목에 근거·이유·하는 법·부작용·질문이 있음', SCHOOL_OPS.every(o => o.law && o.why && o.how && o.side && o.ask));
  const sheet2Nos = new Set(SHEET2_ROWS.map(r => r[0]));
  ok('항목이 가리키는 붙임2 번호가 실제 표에 있음', SCHOOL_OPS.every(o => o.sheet2.every(n => sheet2Nos.has(n))));
  ok('붙임3 표가 가리키는 항목이 카탈로그에 있음', SHEET3_ROWS.every(r => r.ids.every(id => ids.has(id))));
  ok('붙임2 22칸', SHEET2_ROWS.length === 22);
  const text = JSON.stringify(SCHOOL_OPS);
  ok('사용자 문구에 긴 줄표 없음', !/—/.test(text));
}

console.log('\n[운영 절차] 코드 흔적');
{
  const root = project({
    'src/auth.ts': "import { createClient } from '@supabase/supabase-js'; await supabase.auth.mfa.challenge({ factorId }); const r = await rateLimit(ip);",
    'supabase/migrations/001.sql': 'create table public.access_logs (id bigint); create table public.login_attempts (id bigint);',
  });
  const s = opsCodeSignals(root);
  ok('2단계 인증 흔적', s.mfa === true);
  ok('접속기록 흔적', s.accessLog === true);
  ok('로그인 실패 흔적', s.lockout === true);
  ok('횟수 제한 흔적', s.rateLimit === true);
  ok('DB 직접 접속 흔적 없음', s.directDb === false);
  const root2 = project({ 'src/db.ts': "import { Pool } from 'pg'; const p = new Pool({ connectionString: process.env.DATABASE_URL });" });
  ok('pg 직접 접속은 잡음', opsCodeSignals(root2).directDb === true);
}

console.log('\n[운영 절차] Supabase 설정 해석(원문 값 비노출)');
{
  const raw = {
    auth: { password_min_length: 12, password_required_characters: 'abc:ABC:0123456789:!@#$', password_hibp_enabled: true, mfa_totp_enroll_enabled: true, mfa_totp_verify_enabled: true, sessions_inactivity_timeout: 0, sessions_timebox: 0, site_url: 'http://localhost:3000', uri_allow_list: '', rate_limit_verify: 30 },
    ssl: { currentConfig: { database: false } },
    network: { config: { dbAllowedCidrs: ['203.0.113.7/32'], dbAllowedCidrsV6: [] } },
    backups: { pitr_enabled: false, backups: [{}, {}] },
    advisors: { lints: [{ name: 'rls_disabled_in_public', level: 'ERROR' }, { name: 'anon_security_definer_function_executable', level: 'WARN' }] },
  };
  const m = mapSupabaseConfig(raw);
  ok('비밀번호 기준 on', m['ops.password-rules'].state === 'on');
  ok('TOTP 켜짐은 partial(앱 화면 필요)', m['ops.admin-mfa'].state === 'partial');
  ok('세션 제한 없음 off', m['ops.idle-logout'].state === 'off');
  ok('SSL 강제 꺼짐 off', m['ops.db-ssl'].state === 'off');
  ok('IP 제한 있음 on', m['ops.db-ip-allowlist'].state === 'on');
  ok('IP 원문을 출력하지 않음', !JSON.stringify(m).includes('203.0.113.7'));
  ok('localhost 사이트 주소 off', m['ops.auth-site-url'].state === 'off');
  ok('ERROR 경고 off', m['ops.security-advisor'].state === 'off');
  ok('백업 on', m['ops.backup'].state === 'on');
  const open = mapSupabaseConfig({ network: { config: { dbAllowedCidrs: ['0.0.0.0/0'], dbAllowedCidrsV6: ['::/0'] } } });
  ok('모든 IP 허용은 off', open['ops.db-ip-allowlist'].state === 'off');
}

console.log('\n[운영 절차] 설정 읽기는 GET 만, 토큰은 결과에 없음');
{
  const calls = [];
  const token = 'sbp_' + 'x'.repeat(40);
  const fakeFetch = async (url, init) => { calls.push({ url, method: init.method, auth: init.headers.Authorization }); return { ok: true, status: 200, text: async () => JSON.stringify({ currentConfig: { database: true } }) }; };
  const got = await readSupabaseConfig({ ref: 'abcdefghijklmnopqrst', token, fetchImpl: fakeFetch });
  ok('읽기 성공', got.ok === true);
  ok('모든 요청이 GET', calls.length === 5 && calls.every(c => c.method === 'GET'));
  ok('api.supabase.com 으로만', calls.every(c => c.url.startsWith('https://api.supabase.com/v1/projects/abcdefghijklmnopqrst/')));
  ok('결과에 토큰 없음', !JSON.stringify(got).includes(token));
  const bad = await readSupabaseConfig({ ref: '../evil', token, fetchImpl: fakeFetch });
  ok('이상한 프로젝트 번호는 거절', bad.ok === false);
  const none = await readSupabaseConfig({ ref: 'abcdefghijklmnopqrst', token: '', fetchImpl: fakeFetch });
  ok('토큰 없으면 요청하지 않음', none.ok === false && calls.length === 5);
  const root = project({ '.env.local': 'NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nSUPABASE_SERVICE_ROLE_KEY=secret' });
  ok('env 파일에서 프로젝트 번호만 읽음', detectSupabaseRef(root).ref === 'abcdefghijklmnopqrst');
  const root2 = project({ 'supabase/.temp/project-ref': 'bbbbbbbbbbbbbbbbbbbb', '.env.local': 'NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co' });
  ok('번호가 서로 다르면 conflict', detectSupabaseRef(root2).conflict === true);
}

console.log('\n[운영 절차] 결정과 학교 서류 초안');
{
  ok('사유 없는 skip 거절', makeDecision({ id: 'ops.admin-mfa', choice: 'skip', reason: '' }).ok === false);
  ok('모르는 항목 거절', makeDecision({ id: 'ops.nope', choice: 'do' }).ok === false);
  ok('모르는 선택 거절', makeDecision({ id: 'ops.admin-mfa', choice: 'yes' }).ok === false);
  const d = makeDecision({ id: 'ops.admin-mfa', choice: 'skip', reason: '인증 앱 초기화‮ 인력이 없음' });
  ok('사유의 방향 바꾸는 문자는 지움', d.ok && !d.value.reason.includes('‮'));
  const items = buildOpsState({ signals: {}, config: {}, decisions: { 'ops.admin-mfa': d.value } });
  const sheets = sheetRows(items, null);
  const row4 = sheets.sheet2.find(r => r.no === '④');
  ok('skip 이면 X 와 선생님 사유', row4.mark === 'X' && row4.why.includes('인증 앱 초기화'));
  ok('근거가 없으면 O 를 제안하지 않음', sheets.sheet2.every(r => !r.mark.startsWith('O')));
  const md = renderSelfcheckMd(sheets);
  ok('X 사유 표가 생김', md.includes('X 항목 사유'));
  ok('붙임3 9줄', sheets.sheet3.length === 9);
  const ops = renderOpsMd(items);
  ok('안내에 모든 항목', SCHOOL_OPS.every(o => ops.includes(o.id)));
}

console.log('\n[운영 절차] 심어 둔 결정·scan 파일은 다시 거른다');
{
  const items = buildOpsState({ signals: {}, decisions: {
    'ops.backup': { choice: 'done', reason: {} },
    'ops.db-ssl': { choice: 'skip', reason: 'ok\r\n## 가짜 제목 | 칸\u202E 깨기' },
    'ops.lockout': { choice: 'hacked' },
  }, scan: { at: 123, results: 'x' } });
  ok('사유 없는 done 은 결정 없음', items.find(i => i.id === 'ops.backup').decision === null);
  ok('모르는 choice 는 결정 없음', items.find(i => i.id === 'ops.lockout').decision === null);
  const ssl = items.find(i => i.id === 'ops.db-ssl').decision;
  ok('사유의 줄바꿈·방향 문자 제거', ssl && !/[\r\n\u202E]/.test(ssl.reason));
  const md = renderOpsMd(items) + renderSelfcheckMd(sheetRows(items, null));
  ok('결과에 줄 머리 가짜 제목 없음', !/^## 가짜/m.test(md) && !/[\r\u202E]/.test(md));
}

console.log('\n[운영 절차] 검증 봇이 찾은 경우들');
{
  // 정규화된 scan.json 모양: 확인된 문제도 status 가 info 이고 근거(hits)가 붙는다
  const scan = { at: '2026-11-24', results: [
    { id: 'code.plain-sensitive-column', status: 'info', evidence: { hits: [{ file: 'a.sql', line: 1 }] } },
    { id: 'code.rls.anon-read', status: 'pass', evidence: {} },
    { id: 'code.rls.anon-write', status: 'info', evidence: { hits: [{ file: 'a.sql', line: 2 }] } },
    { id: 'storage.upload-limits', status: 'info', evidence: { hits: [{ file: 'a.sql', line: 3 }] } },
  ] };
  const items = buildOpsState({ signals: { supabaseAuth: true }, scan });
  const sh = sheetRows(items, scan, { supabaseAuth: true });
  ok('평문 비밀번호 칸이 있으면 ⑪ X', sh.sheet2.find(r => r.no === '⑪').mark === 'X');
  ok('평문 칸이 있으면 ⑩ X', sh.sheet2.find(r => r.no === '⑩').mark === 'X');
  ok('RLS 꺼진 표가 있으면 붙임3 3번 X', sh.sheet3.find(r => r.label === '3. 접근통제').mark === 'X');
  const rlsOnly = { results: [{ id: 'code.rls.anon-write', status: 'info', evidence: { hits: [{ file: 'a.sql', line: 1, kind: 'public.t RLS 꺼짐' }] } }] };
  ok('마이그레이션에 RLS 문장만 없으면 X 가 아니라 확인 필요', sheetRows(buildOpsState({ signals: {} }), rlsOnly, {}).sheet3.find(r => r.label === '3. 접근통제').mark === '확인 필요');
  ok('버킷 제한 없으면 붙임3 4번 보완', sh.sheet3.find(r => r.label === '4. 보안 취약점 점검·조치').mark === 'X 또는 보완');

  const clean = { results: [{ id: 'code.rls.anon-read', status: 'pass' }, { id: 'sec.transport.https-redirect', status: 'pass' }, { id: 'sec.transport.ssl-valid', status: 'pass' }] };
  const d = makeDecision({ id: 'ops.db-ip-allowlist', choice: 'skip', reason: '학생·학부모가 집에서 접속해 IP 를 정할 수 없음' }).value;
  const items2 = buildOpsState({ signals: {}, decisions: { 'ops.db-ip-allowlist': d }, scan: clean, config: { 'ops.db-ssl': { state: 'off', observed: 'x' } } });
  const sh2 = sheetRows(items2, clean, {});
  ok('scan 이 좋아도 선생님 skip 은 X 로 남음', sh2.sheet3.find(r => r.label === '3. 접근통제').mark === 'X');
  ok('https 가 확인되면 DB SSL 만으로 ⑫ 를 X 로 만들지 않음', sh2.sheet2.find(r => r.no === '⑫').mark === 'O(확인 후)' && /권고/.test(sh2.sheet2.find(r => r.no === '⑫').why));
  ok('로그인 방식을 모르면 ⑪ 에 O 를 내지 않음', sh2.sheet2.find(r => r.no === '⑪').mark !== 'O(확인 후)');

  const m = mapSupabaseConfig({ auth: { hook_password_verification_attempt_enabled: true, sessions_timebox: 168, sessions_inactivity_timeout: 0, site_url: 'https://app.example', uri_allow_list: 'https://*.vercel.app/**' }, network: { config: { dbAllowedCidrs: ['0.0.0.0/1', '128.0.0.0/1'], dbAllowedCidrsV6: [] } } });
  ok('훅만 켜져 있으면 잠금은 partial', m['ops.lockout'].state === 'partial');
  ok('최대 유지 시간만 있으면 자동 로그아웃 partial', m['ops.idle-logout'].state === 'partial');
  ok('*.vercel.app 허용은 넓음', m['ops.auth-site-url'].state === 'partial');
  ok('/1 두 개는 사실상 전체 허용', m['ops.db-ip-allowlist'].state === 'off');
  ok('요청 제한 0종이면 상태를 만들지 않음', !m['ops.rate-limit']);

  const root = project({ 'src/theme.ts': "const c = '#429ff0';", 'src/x.ts': 'const IDLE_TIMEOUT_PRESETS = [10, 30];' });
  const sg = opsCodeSignals(root);
  ok('색 코드 #429 는 횟수 제한 흔적이 아님', sg.rateLimit === false);
  ok('대문자·스네이크 이름의 미사용 시간 흔적을 잡음', sg.idle === true);
  const root2 = project({ 'supabase/config.toml': '[auth.sessions]\ninactivity_timeout = "8h"\n' });
  ok('config.toml 의 세션 설정도 흔적', opsCodeSignals(root2).idle === true);
  const items3 = buildOpsState({ signals: opsCodeSignals(project({ 'a.js': 'x' })) });
  ok('코드에서 못 찾은 것은 "흔적 없음"', items3.find(i => i.id === 'ops.access-log').stateLabel === '흔적 없음');
}

console.log('\n[운영 절차] CLI');
{
  const root = project({ 'package.json': '{"name":"x"}' });
  const run = a => { try { return { code: 0, out: execFileSync(process.execPath, [BIN, ...a], { cwd: root, encoding: 'utf8', env: { ...process.env, SUPABASE_ACCESS_TOKEN: '' } }) }; } catch (e) { return { code: e.status, out: String(e.stdout) + String(e.stderr) }; } };
  const r1 = run(['ops']);
  ok('ops 실행', r1.code === 0 && fs.existsSync(path.join(root, '.dorms-check', 'OPS.md')) && fs.existsSync(path.join(root, '.dorms-check', 'SCHOOL-SELFCHECK.md')));
  const r2 = run(['ops', 'decide', '--id', 'ops.db-ssl', '--choice', 'skip']);
  ok('사유 없는 skip 은 실패 종료', r2.code !== 0);
  const r3 = run(['ops', 'decide', '--id', 'ops.db-ssl', '--choice', 'do']);
  ok('do 기록', r3.code === 0 && JSON.parse(fs.readFileSync(path.join(root, '.dorms-check', 'ops-decisions.json'), 'utf8'))['ops.db-ssl'].choice === 'do');
  const r4 = run(['ops', '--supabase-config', '--supabase-ref', 'abcdefghijklmnopqrst']);
  ok('토큰 없이 --supabase-config 는 안내만 하고 계속', r4.code === 0 && /SUPABASE_ACCESS_TOKEN/.test(r4.out));
  const before = fs.readdirSync(root).sort().join(',');
  ok('앱 소스는 그대로(.dorms-check 만 생김)', before === '.dorms-check,package.json');
}

console.log(`\n결과: ${pass} 통과, ${fail} 실패`);
if (fail) process.exit(1);

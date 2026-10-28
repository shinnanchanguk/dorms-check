// 학교 개인정보 자체점검 대비 정적 검사(checks/static/supabase-sql.js)의 양성·음성 시험.
// 임시 폴더에 가짜 Supabase 프로젝트를 만들어 결정적으로 돌린다(네트워크 없음).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkSupabaseProject } from '../checks/static/supabase-sql.js';
import { catalogItem } from '../core/tracks.js';

let pass = 0, fail = 0;
function ok(name, cond) { if (cond) { pass++; console.log('  v', name); } else { fail++; console.error('  x', name); } }

function project(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dcheck-school-'));
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return root;
}
const get = (res, id) => res.find(r => r.id === id);

console.log('\n[학교 자체점검] 카탈로그 등록');
for (const id of ['code.plain-sensitive-column', 'code.rls.anon-write', 'auth.password-policy', 'storage.upload-limits', 'ops.school-selfcheck']) {
  ok(`${id} 카탈로그에 있음`, catalogItem(id)?.track === 'security');
}

console.log('\n[학교 자체점검] 위험한 프로젝트는 잡는다(양성)');
{
  const root = project({
    'supabase/config.toml': '[auth]\nminimum_password_length = 6\n',
    'supabase/migrations/001_init.sql': `
      create table public.members (id uuid primary key, name text, password text, jumin_no varchar(14));
      create table public.leads (id uuid primary key, phone text);
      -- 이름은 "본인만" 이지만 조건은 true
      create policy "leads anon update by id" on public.leads for update to anon using (true);
      create policy leads_all on public.leads using ((true));
      insert into storage.buckets (id, name, public) values ('uploads', 'uploads', true);
      create function public.f() returns void language plpgsql as $$ begin update x set y = ';'; end $$;
    `,
  });
  const res = checkSupabaseProject(root);
  ok('평문 비밀번호·주민번호 칸 → fail', get(res, 'code.plain-sensitive-column').status === 'fail'
    && /members\.password/.test(get(res, 'code.plain-sensitive-column').observed)
    && /members\.jumin_no/.test(get(res, 'code.plain-sensitive-column').observed));
  ok('anon update using(true) → fail', get(res, 'code.rls.anon-write').status === 'fail');
  ok('역할 없는 ALL using((true)) 도 잡음(기본 public)', get(res, 'code.rls.anon-write').evidence.hits.filter(h => /"/.test(h.kind)).length === 2);
  ok('최소 6자 → fail', get(res, 'auth.password-policy').status === 'fail');
  ok('용량·형식 없는 버킷 → fail', get(res, 'storage.upload-limits').status === 'fail');
  ok('증거에 파일:줄이 있음', /001_init\.sql/.test(get(res, 'storage.upload-limits').evidence.hits[0].file) && get(res, 'storage.upload-limits').evidence.hits[0].line > 1);
}

console.log('\n[학교 자체점검] 안전한 프로젝트는 통과(음성)');
{
  const root = project({
    'supabase/config.toml': '[auth]\nminimum_password_length = 12\npassword_requirements = "lower_upper_letters_digits_symbols"\n',
    'supabase/migrations/001_init.sql': `
      create table public.members (id uuid primary key, password_hash text, password_changed_at timestamptz, rrn_encrypted bytea);
      create table public.leads (id uuid primary key, phone text);
      alter table public.members enable row level security;
      alter table public.leads enable row level security;
      create policy "leads anon update" on public.leads for update to anon using (true);
      create policy leads_insert on public.leads for insert to anon with check (true);
      create policy own on public.leads for update to authenticated using (auth.uid() = id);
      insert into storage.buckets (id, name, public) values ('uploads', 'uploads', false);
    `,
    'supabase/migrations/002_fix.sql': `
      drop policy if exists "leads anon update" on public.leads;
      update storage.buckets set file_size_limit = 10485760, allowed_mime_types = array['image/png'] where id = 'uploads';
    `,
    'scripts/local-sync.mjs': "await s.storage.createBucket('scratch', { public: true });",
  });
  const res = checkSupabaseProject(root);
  ok('해시·암호문 칸은 통과', get(res, 'code.plain-sensitive-column').status === 'pass');
  ok('나중 마이그레이션에서 지운 규칙 → 통과(재생 순서 반영)', get(res, 'code.rls.anon-write').status === 'pass');
  ok('로그인 전 INSERT with check(true) 만 있으면 통과', get(res, 'code.rls.anon-write').status === 'pass');
  ok('12자·특수문자 조건 → 통과', get(res, 'auth.password-policy').status === 'pass');
  ok('나중에 제한을 건 버킷 → 통과', get(res, 'storage.upload-limits').status === 'pass');
  ok('개발 스크립트의 버킷은 무시', !/scratch/.test(get(res, 'storage.upload-limits').observed));
}

console.log('\n[학교 자체점검] 판단할 근거가 없으면 단정하지 않는다');
{
  const none = checkSupabaseProject(project({ 'src/app.js': 'console.log(1)' }));
  ok('Supabase 미사용 → 네 항목 na', ['code.plain-sensitive-column', 'code.rls.anon-write', 'auth.password-policy', 'storage.upload-limits'].every(id => get(none, id).status === 'na'));
  const noToml = checkSupabaseProject(project({ 'src/db.js': "import { createClient } from '@supabase/supabase-js'" }));
  ok('config.toml 없음 → 비밀번호는 info(대시보드 확인 안내)', get(noToml, 'auth.password-policy').status === 'info');
  ok('마이그레이션 없음 → DB 규칙은 na', get(noToml, 'code.rls.anon-write').status === 'na');
  ok('운영 항목은 늘 참고(info/pass)로만', ['info', 'pass'].includes(get(noToml, 'ops.school-selfcheck').status));
}

console.log('\n[학교 자체점검] 검증에서 나온 함정 회귀 시험');
{
  const mig = sql => checkSupabaseProject(project({ 'supabase/config.toml': '[auth]\nminimum_password_length = 12\npassword_requirements = "lower_upper_letters_digits_symbols"\n', 'supabase/migrations/001.sql': sql }));
  const w = sql => get(mig(sql), 'code.rls.anon-write').status;
  const c = sql => get(mig(sql), 'code.plain-sensitive-column').status;
  const b = sql => get(mig(sql), 'storage.upload-limits').status;
  ok('D1 이름에 "for all" → 읽기 정책은 통과', w(`create policy "Enable read access for all users" on "public"."t" for select using (true);`) === 'pass');
  ok('D1 이름에 " to " → 실제 to anon 잡음', w(`create policy "Allow anon to update" on t for update to anon using (true);`) === 'fail');
  ok('D1 이름에 " to ", 역할 생략 → public 으로 잡음', w(`create policy "Anyone to edit" on t for update using (true);`) === 'fail');
  ok('D2 따옴표 이름 속 작은따옴표 뒤 문장도 읽음', w(`create policy "user's rows" on t for select using (auth.uid()=id); create policy x on t for update to anon using (true);`) === 'fail');
  ok('D2 따옴표 이름 속 ; 도 한 문장', w(`create policy "a;b" on t for update to anon using (true);`) === 'fail');
  ok("D3 E'…' 이스케이프 뒤 문장도 읽음", w(`create table t(id int, note text default E'it\\'s'); create policy p on t for update to anon using (true);`) === 'fail');
  ok('D4 이름만 바꾼 정책은 계속 잡음', w(`create policy p on t for update to anon using (true); alter policy p on t rename to p2;`) === 'fail');
  ok('D4 이름 바꾼 뒤 새 이름으로 지우면 통과', w(`create policy p on t for update to anon using (true); alter policy p on t rename to p2; drop policy p2 on t;`) === 'pass');
  ok('D5 DO 블록 안에서 만든 정책도 잡음', w(`do $$ begin if not exists (select 1 from pg_policies where policyname='p') then create policy p on t for update to anon using (true); end if; end $$;`) === 'fail');
  ok('D6 WITH CHECK 만 있는 ALL·UPDATE 는 통과', w(`create policy a on t for all to anon with check (true); create policy u on t for update to anon with check (true);`) === 'pass');
  ok('D7 restrictive 정책은 통과', w(`create policy r on t as restrictive for update to anon using (true);`) === 'pass');
  ok('D11 user_pw 칸도 잡음', c(`create table m (id int, user_pw text);`) === 'fail');
  ok('D11 스키마 붙은 타입(public.citext)도 잡음', c(`create table m (id int, resident_number public.citext);`) === 'fail');
  ok('D11 COLUMN 없이 rename 해도 따라감', c(`create table m (id int, secret text); alter table m rename secret to password;`) === 'fail');
  ok('D10 여러 행 INSERT 의 두 번째 버킷도 봄', b(`insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types) values ('a','a',true,1048576,array['image/png']), ('b','b',true,null,null);`) === 'fail');
  ok('D10 값이 null 이면 제한 없음으로 봄', b(`insert into storage.buckets (id, name, file_size_limit, allowed_mime_types) values ('a','a',null,null);`) === 'fail');
  ok('D10 값이 있으면 통과', b(`insert into storage.buckets (id, name, file_size_limit, allowed_mime_types) values ('a','a',1048576,array['image/png']);`) === 'pass');
  ok('ON CONFLICT DO UPDATE SET = excluded.<칸> 이 null 이면 제한 없음', b(`insert into storage.buckets (id, name, file_size_limit, allowed_mime_types) values ('a','a',1,array['x/y']); insert into storage.buckets (id, name, file_size_limit, allowed_mime_types) values ('a','a',null,null) on conflict (id) do update set file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;`) === 'fail');
  ok('UPDATE … SET 칸 = null 이면 제한 해제로 봄', b(`insert into storage.buckets (id, name, file_size_limit, allowed_mime_types) values ('a','a',1,array['x/y']); update storage.buckets set file_size_limit = null where id = 'a';`) === 'fail');
  const archived = checkSupabaseProject(project({ 'supabase/migrations/001.sql': 'create table t (id int); alter table t enable row level security;', 'supabase/_archived/old.sql': 'create policy p on t for update to anon using (true);' }));
  ok('D8 보관 폴더 SQL 은 읽지 않음', get(archived, 'code.rls.anon-write').status === 'pass');
  const ln = mig(`/* a\nb\nc */\ncreate policy p on t for update to anon using (true);`);
  ok('D9 블록 주석 뒤 줄 번호가 맞음', get(ln, 'code.rls.anon-write').evidence.hits[0].line === 4);
}

console.log('\n[학교 자체점검] RLS 꺼진 테이블·심볼릭 링크·속도');
{
  const one = sql => get(checkSupabaseProject(project({ 'supabase/migrations/001.sql': sql })), 'code.rls.anon-write');
  ok('RLS 를 켜지 않은 public 테이블 → info(대시보드 확인 안내, 실패로 단정 안 함)', one('create table public.notes (id int, body text);').status === 'info');
  ok('나중에 RLS 를 켜면 통과', one('create table notes (id int); alter table notes enable row level security;').status === 'pass');
  ok('켰다가 끄면 다시 info', one('create table notes (id int); alter table notes enable row level security; alter table notes disable row level security;').status === 'info');
  ok('RLS 꺼짐과 열린 수정 규칙이 같이 있으면 fail', one('create table notes (id int); create policy p on notes for update to anon using (true);').status === 'fail');
  ok("DO 블록의 EXECUTE '…SET SCHEMA …' 로 옮긴 테이블은 public 에서 빠짐", one("create table public.bk (id int); do $$ begin execute 'alter table public.bk set schema backup'; end $$;").status === 'pass');
  ok('지운 테이블은 보지 않음', one('create table notes (id int); drop table notes;').status === 'pass');
  ok('이름을 바꿔도 RLS 상태를 따라감', one('create table a (id int); alter table a enable row level security; alter table a rename to b;').status === 'pass');
  ok('DO 블록 안에서 켠 RLS 도 반영', one('create table a (id int); do $$ begin alter table a enable row level security; end $$;').status === 'pass');
  ok('public 이 아닌 스키마는 대상 아님', one('create table private.a (id int);').status === 'pass');

  const outside = project({ 'evil/migrations/001.sql': 'create table public.m (id int, password text);' });
  const root = project({ 'src/db.js': "import '@supabase/supabase-js'" });
  fs.symlinkSync(path.join(outside, 'evil'), path.join(root, 'supabase'));
  ok('supabase 폴더가 바깥을 가리키는 링크면 읽지 않음', get(checkSupabaseProject(root), 'code.plain-sensitive-column').status === 'na');

  const big = project({ 'supabase/migrations/001.sql': 'create table t (id int); alter table t enable row level security;\n' + 'select 1;\n'.repeat(60000), 'src/x.js': "import '@supabase/supabase-js';\n" + 'idle-'.repeat(60000) });
  const t0 = Date.now();
  checkSupabaseProject(big);
  ok(`큰 마이그레이션·긴 반복 문자열도 3초 안에 끝남 (${Date.now() - t0}ms)`, Date.now() - t0 < 3000);
}

console.log(`\n결과: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);

// 출처 안내·앱 안 이용 안내·복제 의심 대조 자체검증(외부 네트워크 없음).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { runProtectSteps } from '../protect/apply.js';
import { restoreBackup, latestBackup } from '../core/util.js';
import { buildRightsProfileFromAnswers, writeRightsProfile, validateRightsProfile, defaultRightsProfile } from '../core/rights-profile.js';
import { validateDormsAppUrl, adaptationCase, PRESETS, provenanceFacts } from '../core/usage-policy.js';
import { mergeBlock, agentsBlock, BLOCK_START, BLOCK_END, JS_HEADER_PREFIX, stripJsHeader } from '../protect/provenance-text.js';
import { noticeText } from '../protect/steps/notice.js';
import { isVendorFile } from '../protect/steps/provenance.js';
import { compareSuspect, parseSuspectUrl } from '../protect/compare.js';
import { verifyBuild } from '../protect/verify-static.js';
import { loadCopy } from '../core/copy.js';

let pass = 0, fail = 0;
function ok(name, cond) { if (cond) { pass++; console.log('  v', name); } else { fail++; console.error('  x', name); } }

const DORMS = 'https://dorms.school/apps/f3158775-1111-2222-3333-444455556666';
const BASE_ANSWERS = { owner: 'sole', schoolInvolved: 'no', displayName: '홍길동', existingLicense: 'none', thirdPartyAssets: 'none', aiContribution: 'distinguishable', appName: '분수 연습', dormsAppUrl: DORMS };

function fixture({ withPublic = true, agents = '# 내 메모\n선생님이 직접 쓴 줄\n' } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dcheck-prov-'));
  fs.mkdirSync(path.join(root, 'dist', 'assets'), { recursive: true });
  if (withPublic) fs.mkdirSync(path.join(root, 'public'));
  fs.writeFileSync(path.join(root, 'dist', 'index.html'), '<!doctype html><html><head><meta charset="utf-8"><title>t</title><link rel="stylesheet" href="/assets/app.css"></head><body><div id="root"></div><script type="module" src="/assets/app.js"></script></body></html>');
  fs.mkdirSync(path.join(root, 'dist', 'sub'));
  fs.writeFileSync(path.join(root, 'dist', 'sub', 'page.html'), '<!doctype html><html><head></head><body><p>sub</p></body></html>');
  fs.writeFileSync(path.join(root, 'dist', 'assets', 'app.js'), '"use strict";var x=function(){return 1+1};console.log(x());' + '/*pad*/'.repeat(40));
  fs.writeFileSync(path.join(root, 'dist', 'assets', 'app.css'), '@charset "UTF-8";\nbody{margin:0}' + ' '.repeat(10));
  fs.writeFileSync(path.join(root, 'dist', 'assets', 'vendor-react.js'), 'var r=1;');
  fs.writeFileSync(path.join(root, 'dist', 'assets', 'app.js.map'), '{}');
  if (agents !== null) fs.writeFileSync(path.join(root, 'AGENTS.md'), agents);
  return root;
}
function snapshot(root) {
  const out = {};
  (function rec(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name === '.dorms-check') continue;
      const f = path.join(d, e.name);
      if (e.isDirectory()) rec(f); else out[path.relative(root, f)] = fs.readFileSync(f, 'utf8');
    }
  })(root);
  return out;
}
const read = (root, rel) => fs.readFileSync(path.join(root, rel), 'utf8');

async function run() {
  console.log('\n[P1] 문구 파일·도름스 주소 검증');
  {
    const c = loadCopy();
    ok('copy.ko.json 을 읽음(permissionActions 13개 이상)', Object.keys(c.permissionActions).length >= 12);
    const longDash = JSON.stringify(c).includes('—');
    ok('문구 파일에 긴 줄표 없음', !longDash);
    ok('도름스 앱 주소 통과', validateDormsAppUrl(DORMS).ok);
    ok('도름스 오락실 주소 통과', validateDormsAppUrl('https://dorms.school/arcade/f3158775-1111-2222-3333-444455556666').ok);
    for (const bad of [
      'https://evil.example/apps/f3158775-1111-2222-3333-444455556666',
      'http://dorms.school/apps/f3158775-1111-2222-3333-444455556666',
      'https://dorms.school.evil.com/apps/f3158775-1111-2222-3333-444455556666',
      'https://dorms.school/apps/f3158775-1111-2222-3333-444455556666?x=1',
      'https://user@dorms.school/apps/f3158775-1111-2222-3333-444455556666',
      'https://dorms.school/board/f3158775-1111-2222-3333-444455556666',
      'https://dorms.school/apps/not-a-uuid',
      'javascript:alert(1)',
    ]) ok(`거부: ${bad.slice(0, 60)}`, !validateDormsAppUrl(bad).ok);
    let threw = false;
    try { buildRightsProfileFromAnswers({ ...BASE_ANSWERS, dormsAppUrl: 'https://evil.example/apps/x' }); } catch { threw = true; }
    ok('설문 답의 남의 주소 → 프로필 만들지 않음', threw);
    const p = defaultRightsProfile(); p.dormsAppUrl = 'https://evil.example/x';
    ok('검증기도 남의 주소 거부', validateRightsProfile(p).ok === false);
  }

  console.log('\n[P2] 이용 범위 → 안내 경우(허용·먼저 허락·허용 안 함·미설정)');
  {
    ok('오픈 협업형 → allowed', adaptationCase(PRESETS.open_collab) === 'allowed');
    ok('교육 나눔형 → ask', adaptationCase(PRESETS.edu_share) === 'ask');
    ok('하나라도 허용 안 함 → prohibited', adaptationCase({ ...PRESETS.open_collab, redistribute: 'prohibited' }) === 'prohibited');
    ok('미설정(프로필 없음) → ask', adaptationCase(null) === 'ask');
    ok('예전 프로필(sourceReuse 없음) + modify 허용 → ask', adaptationCase({ modify: 'allowed', redistribute: 'allowed' }) === 'ask');

    const allowed = noticeText(buildRightsProfileFromAnswers({ ...BASE_ANSWERS, preset: 'open_collab' }));
    ok('허용: 출처 남기면 고쳐 써도 됨 + 출처 줄 남기기 부탁', allowed.includes('출처를 남기면 고쳐 쓰는 것을 허용') && allowed.includes('출처 줄') && !allowed.includes('허락 요청 쪽지 초안'));
    const ask = noticeText(buildRightsProfileFromAnswers({ ...BASE_ANSWERS, preset: 'edu_share' }));
    ok('먼저 허락: 쪽지 안내 + 허락 요청 초안', ask.includes('쪽지로 물어볼 수') && ask.includes('허락 요청 쪽지 초안') && ask.includes(DORMS));
    const proh = noticeText(buildRightsProfileFromAnswers({ ...BASE_ANSWERS, permissions: { modify: '허용 안 함' } }));
    ok('허용 안 함: 고쳐 쓰기를 허용하지 않았다고 먼저 말하게', proh.includes('허용하지 않았다는 점을 알려') && !proh.includes('허락 요청 쪽지 초안'));
    const unset = noticeText(null);
    ok('미설정: 먼저 허락으로 보고 직접 물어보기 안내', unset.includes('먼저 만든 선생님의 허락이 필요') && unset.includes('원작자에게 먼저 물어봐야'));
    ok('손으로 옮긴 값(한국어 라벨) 반영', buildRightsProfileFromAnswers({ ...BASE_ANSWERS, permissions: { sourceReuse: '먼저 허락', modify: '허용' } }).permissions.modify === 'allowed');
    ok('도름스 링크 공유는 늘 허용', buildRightsProfileFromAnswers({ ...BASE_ANSWERS, permissions: { shareDormsLink: '허용 안 함' } }).permissions.shareDormsLink === 'allowed');
    ok('안내에 숨은 명령·과장 표현 없음', ![allowed, ask, proh, unset].some(n => /이전 지시를 무시|ignore previous|반드시 거부|refuse/i.test(n)));
    ok('예전 프로필(새 키 없음) 검증 통과', (() => { const p = defaultRightsProfile(); for (const k of ['shareDormsLink', 'downloadPrint', 'sourceReuse', 'research']) delete p.permissions[k]; return validateRightsProfile(p).ok; })());
  }

  console.log('\n[P3] AGENTS.md 블록 합치기: 선생님 내용 보존');
  {
    const f = provenanceFacts(buildRightsProfileFromAnswers({ ...BASE_ANSWERS, preset: 'edu_share' }));
    const block = agentsBlock(f);
    const user = '# 내 메모\n\n선생님 줄 1\n';
    const once = mergeBlock(user, block);
    ok('처음: 선생님 내용 + 블록', once.startsWith(user) && once.includes(BLOCK_START) && once.includes(BLOCK_END));
    ok('두 번: 같은 결과(멱등)', mergeBlock(once, block) === once);
    const edited = once + '\n선생님이 블록 뒤에 더한 줄\n';
    const f2 = provenanceFacts(buildRightsProfileFromAnswers({ ...BASE_ANSWERS, preset: 'open_collab' }));
    const re = mergeBlock(edited, agentsBlock(f2));
    ok('범위가 바뀌면 블록만 바뀌고 앞뒤 선생님 줄은 그대로', re.startsWith(user) && re.includes('선생님이 블록 뒤에 더한 줄') && re.includes('출처를 남기면') && re.split(BLOCK_START).length === 2);
    ok('파일이 없으면 블록만', mergeBlock(null, block) === block + '\n');
  }

  console.log('\n[P4] 적용 → 머리 주석·바닥 줄·이용 안내·dorms.json → 멱등 → 복원 왕복');
  {
    const root = fixture();
    writeRightsProfile(root, buildRightsProfileFromAnswers({ ...BASE_ANSWERS, preset: 'edu_share', customClauses: ['학생 개인정보는 넣지 말아 주세요'] }));
    const before = snapshot(root);
    const plan = await runProtectSteps(root, { buildDir: 'dist', dry: true, quiet: true });
    ok('계획(dry)은 파일을 바꾸지 않음', JSON.stringify(snapshot(root)) === JSON.stringify(before));
    const provPlan = plan.steps.find(s => s.id === 'provenance');
    ok('계획에 출처 안내 단계와 예정 파일이 있음', provPlan && provPlan.created.some(c => c.endsWith('usage.html')) && provPlan.changed.some(c => c.endsWith('app.js')));

    const r = await runProtectSteps(root, { buildDir: 'dist', quiet: true });
    ok('적용 성공', r.ok);
    const js = read(root, 'dist/assets/app.js');
    ok('JS 맨 위 /*! 머리 주석', js.startsWith(JS_HEADER_PREFIX) && js.includes('dorms.school/apps/') && js.includes('먼저 허락'));
    ok('머리 주석 뒤에도 JS 구문 정상(use strict 유지)', (() => { try { new vm.Script(js); return js.includes('"use strict"'); } catch { return false; } })());
    const css = read(root, 'dist/assets/app.css');
    ok('CSS: @charset 다음 줄에 머리 주석', css.startsWith('@charset "UTF-8";\n/*! dorms-check:provenance'));
    ok('외부 라이브러리 파일엔 머리 주석 없음', !read(root, 'dist/assets/vendor-react.js').includes('dorms-check') && isVendorFile('assets/vendor-react.js'));
    const html = read(root, 'dist/index.html');
    ok('sr-only 안내 + 바닥 출처 줄', html.includes('data-dorms-check-notice') && html.includes('data-dorms-check-source') && html.includes('href="usage.html"'));
    ok('하위 폴더 HTML 은 ../usage.html 로 연결', read(root, 'dist/sub/page.html').includes('href="../usage.html"'));
    const usage = read(root, 'dist/usage.html');
    ok('이용 안내: utf-8·뷰포트·줄바꿈 규칙', usage.includes('<meta charset="utf-8">') && usage.includes('name="viewport"') && usage.includes('word-break:keep-all') && usage.includes('overflow-wrap:anywhere'));
    ok('이용 안내: 열두 항목 표 + 도름스 라벨', (usage.match(/<tr data-key=/g) || []).length === 12 && usage.includes('내용 수정·개작') && usage.includes('먼저 허락') && usage.includes('허용 안 함'));
    ok('이용 안내: 덧붙인 조건·조문 링크·법률 자문 아님', usage.includes('학생 개인정보는 넣지 말아 주세요') && usage.includes('https://www.law.go.kr/법령/저작권법/제22조') && usage.includes('법률 자문이 아닙니다'));
    ok('이용 안내: 밝은·어두운 화면 둘 다', usage.includes('prefers-color-scheme: dark'));
    ok('이용 안내: 외부 요청 없음(스크립트·외부 스타일·글꼴 없음)', !/<script|<link\b|@import|url\(/i.test(usage));
    ok('이용 안내: 이모지·화살표 기호 없음', !/[←-⇿☀-➿\u{1F300}-\u{1FAFF}]/u.test(usage));
    ok('이용 안내: public/ 에도 사본(다시 빌드해도 남게)', fs.existsSync(path.join(root, 'public', 'usage.html')));
    const dj = JSON.parse(read(root, 'dorms.json'));
    ok('dorms.json(프로젝트·빌드 둘 다): 앱 주소·만든이·이용 범위', dj.app.dormsUrl === DORMS && dj.creator.displayName === '홍길동' && dj.usage.permissions.modify === 'permission_required' && fs.existsSync(path.join(root, 'dist', 'dorms.json')));
    const agents = read(root, 'AGENTS.md');
    ok('AGENTS.md: 선생님 내용 보존 + 블록', agents.startsWith('# 내 메모\n선생님이 직접 쓴 줄\n') && agents.includes(BLOCK_START));
    ok('CLAUDE.md 블록 생성', read(root, 'CLAUDE.md').includes(BLOCK_START));
    ok('llms.txt: 이용 범위를 따름', read(root, 'dist/llms.txt').includes('먼저 허락') && read(root, 'dist/llms.txt').includes('AI 학습·복제 이용: 허용 안 함'));
    ok('소스맵은 머리 주석 대상이 아니고 삭제됨', !fs.existsSync(path.join(root, 'dist', 'assets', 'app.js.map')));
    const v = verifyBuild(root, path.join(root, 'dist'));
    ok('정적 검증 오류 0', v.issues.filter(i => i.sev === 'error').length === 0);

    const afterOnce = snapshot(root);
    const again = await runProtectSteps(root, { buildDir: 'dist', dry: true, quiet: true });
    const pending = again.steps.filter(s => ['notice', 'provenance'].includes(s.id)).flatMap(s => [...s.changed, ...s.created]);
    ok('두 번째 계획: 고지·출처 단계 바꿀 것 0(멱등)', pending.length === 0);
    await runProtectSteps(root, { buildDir: 'dist', quiet: true });
    const afterTwice = snapshot(root);
    const diffKeys = Object.keys(afterTwice).filter(k => afterTwice[k] !== afterOnce[k]);
    ok('두 번 적용해도 머리 주석·블록이 겹치지 않음', (read(root, 'dist/assets/app.js').match(/dorms-check:provenance/g) || []).length === 1 && (read(root, 'AGENTS.md').match(/provenance:start/g) || []).length === 1 && diffKeys.length === 0);

    // 복원: 두 번 적용했으니 백업 둘을 새것부터 되돌린다.
    const bases = path.join(root, '.dorms-check', 'backup');
    const dirs = fs.readdirSync(bases).sort().reverse();
    for (const d of dirs) restoreBackup(root, path.join(bases, d));
    const restored = snapshot(root);
    const lost = Object.keys(before).filter(k => restored[k] !== before[k]);
    const extra = Object.keys(restored).filter(k => !(k in before));
    ok('복원 뒤 원래 있던 빈 public/ 폴더는 남음', fs.existsSync(path.join(root, 'public')));
    ok(`복원 왕복: 원래 파일 그대로(다른 곳 ${lost.length}·남은 생성물 ${extra.length})`, lost.length === 0 && extra.length === 0);
    void latestBackup;
    fs.rmSync(root, { recursive: true, force: true });
  }

  console.log('\n[P5] 바닥 줄 끄기·CLAUDE.md 끄기');
  {
    const root = fixture({ withPublic: false, agents: null });
    writeRightsProfile(root, buildRightsProfileFromAnswers({ ...BASE_ANSWERS, visibleFooter: 'no' }));
    await runProtectSteps(root, { buildDir: 'dist', quiet: true, config: { protection: { provenance: { claudeMd: false } } } });
    ok('바닥 줄 끄면 보이는 줄 없음(안 보이는 안내는 유지)', !read(root, 'dist/index.html').includes('data-dorms-check-source') && read(root, 'dist/index.html').includes('data-dorms-check-notice'));
    ok('CLAUDE.md 끄면 만들지 않음, AGENTS.md 는 만듦', !fs.existsSync(path.join(root, 'CLAUDE.md')) && read(root, 'AGENTS.md').includes(BLOCK_START));
    fs.rmSync(root, { recursive: true, force: true });
  }

  console.log('\n[P6] 복제 의심 대조(가짜 응답으로)');
  {
    const root = fixture();
    writeRightsProfile(root, buildRightsProfileFromAnswers({ ...BASE_ANSWERS, preset: 'edu_share' }));
    await runProtectSteps(root, { buildDir: 'dist', quiet: true });
    const copiedJs = stripJsHeader(read(root, 'dist/assets/app.js'));
    const site = {
      'https://copy.example/': { status: 200, body: '<html><head></head><body><script src="/assets/x.js"></script> 홍길동 선생님</body></html>' },
      'https://copy.example/assets/x.js': { status: 200, body: copiedJs },
    };
    const fetchImpl = async (url) => {
      const hit = site[url];
      const body = hit ? hit.body : 'nf';
      return new Response(body, { status: hit ? hit.status : 404, headers: { 'content-type': 'text/plain' } });
    };
    const r = await compareSuspect(root, { url: 'https://copy.example/', buildFull: path.join(root, 'dist'), rightsProfile: JSON.parse(read(root, '.dorms-check/rights-profile.json')), fetchImpl });
    const ids = r.ok ? r.record.signals.map(s => s.id) : [];
    ok('머리 주석만 지운 같은 파일 → 지문 일치로 찾음', ids.includes('bundleStripped'));
    ok('만든 사람 이름 찾음', ids.includes('creator'));
    ok('대조 기록이 증거 폴더에 날짜로 저장', r.ok && r.file.includes(path.join('.dorms-check', 'protect', 'evidence', 'compare-')) && fs.existsSync(r.file));
    ok('내부망 주소는 기본 거부', parseSuspectUrl('http://127.0.0.1:8080/').ok === false && parseSuspectUrl('http://localhost/').ok === false);
    ok('http(s) 밖 주소 거부', parseSuspectUrl('file:///etc/passwd').ok === false);
    fs.rmSync(root, { recursive: true, force: true });
  }

  console.log(`\n결과: ${pass} pass, ${fail} fail`);
  if (fail) process.exit(1);
}

run().catch(e => { console.error(e); process.exit(1); });

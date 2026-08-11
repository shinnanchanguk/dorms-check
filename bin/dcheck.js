#!/usr/bin/env node
// dorms-check CLI — 교사의 AI(코치)가 부르는 오케스트레이터.
// 이 도구는 앱을 고치지도, 인증을 발급하지도 않는다. 평가·안내·증빙만.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { color, log, exists, readJsonSafe, writeText, ensureDir } from '../core/util.js';
import { detectStack } from '../core/detect.js';
import { loadConfig, writeConfig, defaultConfig, unknownTracks } from '../core/config.js';
import { runExternalScan } from '../checks/external/index.js';
import { runRuntimeProbe } from '../checks/runtime/index.js';
import { runStaticScan } from '../checks/static/index.js';
import { renderReportMd, printSummary } from '../core/report.js';
import { buildPayload } from '../core/payload.js';
import { loadState, saveState, recordRound } from '../core/session.js';
import { catalogItem, TRACKS } from '../core/tracks.js';
import { INTERVIEW_QUESTIONS, buildRightsProfileFromAnswers, writeRightsProfile } from '../core/rights-profile.js';
import { buildProtectionPlan, writePlan, loadPlan, planPath, checkPlanApproval } from '../core/protection-plan.js';
import { runProtectSteps, runProtectVerify, resolveBuildDir, saveProtectState, loadProtectState } from '../protect/apply.js';
import { restoreBackup, latestBackup } from '../core/util.js';
import { verifyBuild } from '../protect/verify-static.js';

const root = process.cwd();
const [, , cmd, ...args] = process.argv;
const flag = n => args.includes('--' + n);
const opt = (n, d) => { const i = args.indexOf('--' + n); return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : d; };

const PKG = readJsonSafe(path.join(fileURLToPath(new URL('../package.json', import.meta.url)))) || { version: '0.1.0' };
const STATE_DIR = path.join(root, '.dorms-check');
const REVIEW = path.join(STATE_DIR, 'review.json');

function honesty() {
  log.plain(color.dim('  이 도구는 앱을 고치지도, 인증을 발급하지도 않습니다. 고치도록 돕는 코치입니다.'));
  log.plain(color.dim('  최종 마크는 도름스 서버가 스스로 다시 검증해 발급하며, 이 도구의 통과가 마크를 보장하지 않습니다.'));
}

function help() {
  log.title('dorms-check ' + color.dim('— 교사 앱 점검 코치 (보안 · 학운위 · 내 앱 보호)'));
  log.plain(`
  세 축(트랙):
  ${color.bold('security')}    보안 점검 (헤더·SSL·노출·CORS·RLS 실측)
  ${color.bold('edzip')}       학운위·개인정보 준비 (에듀집 필수기준 + 개인정보처리방침)
  ${color.bold('protection')}  내 앱 비법·저작권 보호 (권리 확인·서버 분리·고지·증거)

  ${color.bold('dcheck detect')}                 스택 감지(Next.js/Vite/정적, Supabase 여부, 빌드 산출물)
  ${color.bold('dcheck init')}  ${color.dim('--name --url --track security,edzip,protection --stack')}   설정 생성
  ${color.bold('dcheck scan')}  ${color.dim('--url <URL> [--code-only]')}   결정적 스캔(외부 표면+RLS 실측+정적+보호 상태) + 리포트
  ${color.bold('dcheck judge --in <answers.json>')}   교사 AI가 판단한 ai-review 항목 병합(증거 필수)
  ${color.bold('dcheck interview')} ${color.dim('[--answers <file>]')}   권리·허용범위 설문 문항 출력 / 답으로 권리 프로필 생성
  ${color.bold('dcheck protect plan')}           보호 계획 생성(무엇을 바꿀지 + 계획 해시. 파일 안 바꿈)
  ${color.bold('dcheck protect apply')} ${color.dim('--plan-sha256 <값> --confirm-apply')}   승인한 계획대로만 적용(백업 후)
  ${color.bold('dcheck protect restore')} ${color.dim('[--from <백업경로>]')}   마지막 백업으로 복원
  ${color.bold('dcheck verify')}                 적용 전후 산출물 정적 검사 비교(깨짐 확인)
  ${color.bold('dcheck status')}                 남은 미충족 항목 + 수정 프롬프트
  ${color.bold('dcheck report')}                 전체 리포트 출력(.dorms-check/REPORT.md)
  ${color.bold('dcheck submit')}                 증빙팩 생성 + 도름스 마크 신청 안내
  ${color.bold('dcheck help')}                   도움말
`);
  log.plain(color.dim('  security·edzip 은 검사만 합니다. protection 의 적용 단계만 파일을 바꾸며, 그것도'));
  log.plain(color.dim('  사용자가 승인한 계획 해시와 --confirm-apply 플래그가 있을 때만입니다. 자동 배포는 하지 않습니다.'));
  honesty();
}

function printDetect() {
  const d = detectStack(root);
  log.title('스택 감지');
  log.plain(`  프레임워크: ${color.bold(d.framework)}`);
  log.plain(`  Supabase : ${d.hasSupabase ? color.green('예') + ' — RLS 실측 프로브 대상' : '아니오'}`);
  log.plain(`  적용 태그: ${d.applies.join(', ') || '(없음)'}`);
  if (d.buildDir) log.plain(`  빌드 산출물: ${d.buildDir} ${color.dim('(protection 트랙 검사 대상)')}`);
  return d;
}

async function runScan() {
  const cfg = loadConfig(root);
  if (cfg._parseError) { log.err('dorms-check.config.json 파싱 실패. 고치거나 삭제 후 다시.'); process.exitCode = 1; return; }
  const url = opt('url', cfg.app?.url || '');
  const codeOnly = flag('code-only') || !url;
  const stack = cfg.app?.stack || detectStack(root).framework;
  const tracks = cfg.tracks && cfg.tracks.length ? cfg.tracks : ['security'];

  if (!cfg.ownershipConfirmed) {
    log.warn('본인이 만들고 운영하는 앱만 스캔하세요. init 에서 ownershipConfirmed:true 로 동의가 필요합니다.');
  }

  const results = [];
  let raw = {};
  if (!codeOnly) {
    log.step(`외부 표면 스캔: ${url}`);
    const ext = await runExternalScan(url);
    results.push(...ext.items);
    raw = ext.raw;
    if (ext.reachable) {
      log.step('능동 런타임 프로브(RLS 실측·엔드포인트) …');
      const rt = await runRuntimeProbe(url);
      results.push(...rt.items);
    } else {
      log.warn(`URL 접속 실패 — 코드 검사만 진행(${ext.error || ''})`);
    }
    var bonus = ext.bonus || [];
  } else {
    log.step('URL 없음 — 로컬 코드 검사만(--code-only)');
    var bonus = [];
  }

  log.step('로컬 코드 정적 검사 …');
  results.push(...runStaticScan(root).items);

  // ai-review 판단(review.json) 병합
  const review = readJsonSafe(REVIEW) || {};
  for (const [id, v] of Object.entries(review)) {
    const existing = results.find(r => r.id === id);
    if (existing) { existing.status = v.status; existing.observed = v.evidence || existing.observed; existing.evidence = { ...existing.evidence, aiJudgment: v }; }
    else results.push({ id, status: v.status, observed: v.evidence || '(AI 판단)', evidence: { aiJudgment: v } });
  }
  // 트랙별 항목 보충(레지스트리 경유): edzip pending seed·protection 결정적 검사 등
  for (const t of TRACKS) {
    if (!tracks.includes(t.id) || !t.collect) continue;
    results.push(...t.collect({ results, review, config: cfg, root }));
  }

  // 트랙별 채점(레지스트리 경유)
  const trackResults = {};
  for (const t of TRACKS) {
    if (!tracks.includes(t.id)) continue;
    trackResults[t.id] = t.score(results, { bonus, config: cfg, root });
  }

  // 상태 저장 + 리포트
  const state = loadState(root);
  recordRound(state, { trackResults, results });
  saveState(root, state);

  const md = renderReportMd({ config: { ...cfg, app: { ...cfg.app, stack } }, results, trackResults, bonus });
  ensureDir(STATE_DIR);
  writeText(path.join(STATE_DIR, 'REPORT.md'), md);
  writeText(path.join(STATE_DIR, 'scan.json'), JSON.stringify({ at: new Date().toISOString(), url, results, raw }, null, 2));

  printSummary({ trackResults, results, config: { ...cfg, app: { ...cfg.app, stack } } });

  // ai-review 해야 할 항목 안내(교사 AI에게)
  // protection 의 결정적(deterministic)·설문(declared) 항목은 judge 대상이 아니다
  // (결정적 검사가 자기신고를 덮고, 설문은 interview 가 채운다). ai 판단 항목만 남긴다.
  const pending = results.filter(r => {
    if (!(r.status === 'pending' || (r.status === 'info' && String(r.id).startsWith('code.')))) return false;
    const cat = catalogItem(r.id);
    if (cat && cat.track === 'protection' && cat.method !== 'ai') return false;
    return true;
  });
  if (pending.length) {
    log.title('AI가 판단해야 할 항목(judge 로 기록)');
    for (const r of pending) {
      const cat = catalogItem(r.id);
      log.plain(`  - ${r.id}: ${cat ? cat.title : ''} — 코드/방침을 확인하고 pass|fail|na 를 증거와 함께 judge 로 기록`);
    }
  }
  log.plain('');
  log.plain(color.dim('  리포트: .dorms-check/REPORT.md'));
  honesty();
}

function runInit() {
  const existing = loadConfig(root);
  if (existing._exists && !flag('force')) { log.warn('dorms-check.config.json 이미 존재(덮어쓰려면 --force).'); return; }
  const d = detectStack(root);
  const cfg = defaultConfig();
  cfg.app.name = opt('name', cfg.app.name);
  cfg.app.url = opt('url', cfg.app.url);
  cfg.app.stack = opt('stack', d.framework);
  const track = opt('track', 'security');
  cfg.tracks = track.split(',').map(s => s.trim()).filter(Boolean);
  cfg.teacher.dormsHandle = opt('handle', '');
  if (flag('confirm-ownership')) cfg.ownershipConfirmed = true;
  const p = writeConfig(root, cfg);
  log.ok(`설정 생성: ${path.relative(root, p) || 'dorms-check.config.json'}`);
  log.plain('  app.url(배포 주소)·tracks·ownershipConfirmed 를 확인해주세요.');
  const unknown = unknownTracks(cfg);
  if (unknown.length) log.warn(`알 수 없는 트랙: ${unknown.join(', ')} (사용 가능: ${TRACKS.map(t => t.id).join(', ')})`);
  for (const t of TRACKS) {
    if (cfg.tracks.includes(t.id) && t.initNotes) t.initNotes(cfg);
  }
}

function runJudge() {
  const inFile = opt('in', '');
  if (!inFile || !exists(path.resolve(root, inFile))) { log.err('--in <answers.json> 필요'); process.exitCode = 1; return; }
  const answers = readJsonSafe(path.resolve(root, inFile));
  if (!answers || typeof answers !== 'object') { log.err('answers.json 파싱 실패'); process.exitCode = 1; return; }
  const review = readJsonSafe(REVIEW) || {};
  let accepted = 0, rejected = 0;
  // answers: { "<id>": { status:"pass|fail|na", evidence:"파일:라인 or 실측요약" } }
  for (const [id, v] of Object.entries(answers)) {
    if (!v || !['pass', 'fail', 'na'].includes(v.status)) { rejected++; continue; }
    // 증거 없는 pass 는 거부(할루시네이션 방지: 서술만으로 통과 못 함)
    if (v.status === 'pass' && (!v.evidence || String(v.evidence).trim().length < 4)) {
      log.warn(`거부: ${id} — pass 에는 증거(파일:라인 또는 실측 요약)가 필요합니다.`);
      rejected++; continue;
    }
    review[id] = { status: v.status, evidence: v.evidence || '', by: v.by || 'teacher-assistant', at: new Date().toISOString() };
    accepted++;
  }
  ensureDir(STATE_DIR);
  writeText(REVIEW, JSON.stringify(review, null, 2) + '\n');
  log.ok(`판정 병합: ${accepted}건 수용, ${rejected}건 거부. 다시 scan 하세요.`);
}

function runStatus() {
  if (!exists(path.join(STATE_DIR, 'scan.json'))) { log.warn('먼저 scan 하세요.'); return; }
  const scan = readJsonSafe(path.join(STATE_DIR, 'scan.json'));
  const cfg = loadConfig(root);
  const stack = cfg.app?.stack || '내';
  const unmet = (scan.results || []).filter(r => (r.status === 'fail' || r.status === 'pending'));
  log.title(`남은 항목 ${unmet.length}건`);
  for (const r of unmet) {
    const cat = catalogItem(r.id); if (!cat) continue;
    log.plain(`  ${color.yellow('!')} [${cat.severity || cat.track}] ${cat.title}`);
    if (cat.plain) log.plain(`      ${cat.plain}`);
    if (cat.aiFix) log.plain(`      ${color.dim('AI에게:')} ${cat.aiFix.replaceAll('{stack}', stack)}`);
  }
  honesty();
}

function runReport() {
  const p = path.join(STATE_DIR, 'REPORT.md');
  if (!exists(p)) { log.warn('먼저 scan 하세요.'); return; }
  log.plain(readFileSync(p, 'utf8'));
}

function runSubmit() {
  const scanFile = path.join(STATE_DIR, 'scan.json');
  if (!exists(scanFile)) { log.warn('먼저 scan 하세요.'); return; }
  const cfg = loadConfig(root);
  const scan = readJsonSafe(scanFile);
  const stack = cfg.app?.stack || '';
  const results = scan.results || [];
  const bonus = [];
  const trackResults = {};
  for (const t of TRACKS) {
    if (!cfg.tracks?.includes(t.id)) continue;
    trackResults[t.id] = t.score(results, { bonus, config: cfg, root });
  }
  const payload = buildPayload({ config: { ...cfg, app: { ...cfg.app, stack } }, results, trackResults, bonus, toolVersion: PKG.version });

  const outDir = path.resolve(root, opt('out', '.dorms-check/evidence'));
  ensureDir(outDir);
  writeText(path.join(outDir, 'report.json'), JSON.stringify(payload, null, 2));
  writeText(path.join(outDir, 'REPORT.md'), readFileSync(path.join(STATE_DIR, 'REPORT.md'), 'utf8'));
  log.ok(`증빙팩 생성: ${path.relative(root, outDir)}/ (report.json · REPORT.md)`);

  const ready = TRACKS.every(t => !trackResults[t.id] || t.passed(trackResults[t.id]));
  log.title('도름스 마크 신청');
  if (!ready) {
    log.warn('아직 통과하지 못한 항목이 있어요. status 로 남은 항목을 고친 뒤 다시 scan → submit 하세요.');
  }
  log.plain('  1) 도름스(dorms.school)에 로그인하세요.');
  log.plain('  2) 내가 만든 앱의 앱 공유 페이지에서 "보안 검토 마크 신청"을 누르세요.');
  log.plain('  3) 도름스 서버가 이 앱의 주소를 스스로 다시 검사합니다(외부 표면 + RLS 실측).');
  log.plain(color.dim('     서버 재검사에서 통과하지 못하면 마크가 발급되지 않습니다. 이 도구의 통과는 신청 준비일 뿐입니다.'));
  for (const t of TRACKS) {
    if (cfg.tracks?.includes(t.id) && t.submitNotes) t.submitNotes({ config: cfg, root, outDir });
  }
  honesty();
}

// ── protection 트랙 명령 ──

// interview: 문항 JSON 출력(AI 가 교사에게 쉬운 선택지로 묻는다) / --answers 로 권리 프로필 생성.
function runInterview() {
  const answersFile = opt('answers', '');
  if (!answersFile) {
    // AI 코치가 파싱해 쓰도록 문항을 JSON 으로 출력한다.
    const out = {
      note: '아래 문항을 교사에게 쉬운 말로, 1~3문항씩 나눠 물어보세요. 답을 모아 {"owner":"sole", ...} 형식의 JSON 파일로 저장한 뒤 dcheck interview --answers <파일> 을 실행하면 권리 프로필이 생성됩니다. 보호할 자산(protectedAssets)에는 비밀 원문·파일 경로가 아니라 이름만 적으세요.',
      sections: INTERVIEW_QUESTIONS,
      answersTemplate: {
        owner: 'sole | joint | unconfirmed',
        schoolInvolved: 'no | yes_reviewed | yes_unreviewed',
        displayName: '권리자 표시 이름',
        existingLicense: 'none | open | unsure',
        thirdPartyAssets: 'none | licensed | unverified',
        aiContribution: 'distinguishable | mostly_ai | unsure',
        protectedAssets: [{ label: '채점 지시문(예시)', kind: 'prompt', location: 'unknown' }],
        audience: 'anyone | dorms_members | verified_teachers | invited',
        shareLevel: 'open | ask_first | strict',
        aiTraining: 'prohibited | permission_required | allowed',
      },
    };
    log.plain(JSON.stringify(out, null, 2));
    return;
  }
  const p = path.resolve(root, answersFile);
  if (!exists(p)) { log.err(`답 파일이 없습니다: ${answersFile}`); process.exitCode = 1; return; }
  const answers = readJsonSafe(p);
  if (!answers) { log.err('답 파일(JSON) 파싱 실패'); process.exitCode = 1; return; }
  const profile = buildRightsProfileFromAnswers(answers);
  let written;
  try { written = writeRightsProfile(root, profile); }
  catch (e) { log.err(String(e.message || e)); process.exitCode = 1; return; }
  log.ok(`권리 프로필 생성: ${path.relative(root, written)}`);

  // 설문에서 곧장 갈리는 declared 항목을 review 에 기록(증거 = 설문 답. 결정적 검사 항목은 덮지 못한다).
  const review = readJsonSafe(REVIEW) || {};
  const put = (id, status, evidence) => { review[id] = { status, evidence, by: 'interview', at: new Date().toISOString() }; };
  if (answers.thirdPartyAssets === 'none' || answers.thirdPartyAssets === 'licensed') {
    put('protection.rights.third-party', 'pass', `설문: 외부 재료 ${answers.thirdPartyAssets === 'none' ? '없음(또는 자유 이용만)' : '있음 · 이용 조건 확인함'}`);
  } else if (answers.thirdPartyAssets) {
    put('protection.rights.third-party', 'pending', '설문: 외부 재료 조건 미확인(확인 후 judge 로 기록)');
  }
  if (answers.aiContribution === 'distinguishable') {
    put('protection.rights.ai-contribution', 'pass', '설문: 직접 설계·작성한 부분이 구분됨');
  } else if (answers.aiContribution) {
    put('protection.rights.ai-contribution', 'pending', '설문: AI 기여 구분 필요(코드·기획 기록으로 확인 후 judge)');
  }
  if (answers.existingLicense === 'none') {
    put('protection.rights.license-consistency', 'pass', '설문: 기존 공개 라이선스 없음');
  } else if (answers.existingLicense) {
    put('protection.rights.license-consistency', 'pending', '설문: 기존 공개 이력 있음 또는 불확실(충돌 검토 후 judge 로 기록)');
  }
  ensureDir(STATE_DIR);
  writeText(REVIEW, JSON.stringify(review, null, 2) + '\n');
  log.plain('  설문에서 갈린 권리 항목을 기록했어요. 다시 scan 하면 반영됩니다.');
  log.plain(color.dim('  프로필에는 비밀 원문·민감 파일명이 들어가지 않아요(이름만).'));
}

// protect plan: 무엇을 바꿀지 계획 생성(파일 안 바꿈) + 계획 해시 출력.
async function runProtectPlan() {
  const cfg = loadConfig(root);
  const { plan, error } = await buildProtectionPlan(root, { config: cfg });
  if (error) { log.err(error); process.exitCode = 1; return; }
  const p = writePlan(root, plan);
  log.title('보호 계획 생성(아직 아무것도 바꾸지 않았어요)');
  log.plain(`  계획 파일: ${path.relative(root, p)}`);
  log.plain(`  빌드 산출물: ${plan.buildDir}`);
  for (const s of plan.steps) {
    log.plain(`  - ${s.title}: 변경 ${s.willChange.length}개 · 생성 ${s.willCreate.length}개`);
  }
  if (plan.serverMoveCandidates.length) {
    log.title(`서버 이전 후보 ${plan.serverMoveCandidates.length}건 (이 계획은 코드를 옮기지 않아요 — 교사 AI 가 별도 동의로)`);
    for (const c of plan.serverMoveCandidates.slice(0, 8)) log.plain(`  ! ${c.kind} @ ${c.file}`);
  }
  log.title('위험·복원');
  for (const r of plan.risks) log.plain(`  · ${r}`);
  log.plain(`  · 복원: ${plan.restore.method}`);
  log.title('계획 해시(동의 표식)');
  log.plain(`  ${color.bold(plan.planSha256)}`);
  log.plain('');
  log.plain('  계획을 읽고 동의하면 이렇게 적용하세요(이때만 파일이 바뀝니다):');
  log.plain(`  ${color.bold(`dcheck protect apply --plan-sha256 ${plan.planSha256} --confirm-apply`)}`);
}

// protect apply: 승인한 계획 해시 + --confirm-apply 가 있을 때만 파일 변경(백업 후, 실패 시 복원).
async function runProtectApply() {
  const cfg = loadConfig(root);
  const plan = loadPlan(root);
  const approval = checkPlanApproval(plan, opt('plan-sha256', ''));
  if (!approval.ok) { log.err(approval.reason); process.exitCode = 1; return; }
  if (!flag('confirm-apply')) {
    log.err('--confirm-apply 플래그가 필요합니다. 사용자가 계획에 동의했을 때만 적용하세요.');
    process.exitCode = 1; return;
  }
  const buildDir = plan.buildDir;
  if (!exists(path.join(root, buildDir))) { log.err(`계획의 빌드 산출물(${buildDir})이 없습니다. 다시 빌드 후 protect plan 부터.`); process.exitCode = 1; return; }

  // 적용 전 기준선(비교용): 지금 산출물의 정적 검사 결과를 기록해 둔다.
  const baseline = verifyBuild(root, path.join(root, buildDir));
  saveProtectState(root, { baseline: { at: new Date().toISOString(), buildDir, errors: baseline.issues.filter(i => i.sev === 'error').length, warnings: baseline.issues.filter(i => i.sev === 'warn').length } });

  log.title(`보호 적용  ${color.dim('buildDir=' + buildDir + ' · plan=' + approval.sha.slice(0, 12) + '…')}`);
  const res = await runProtectSteps(root, { buildDir, config: cfg, dry: false });
  if (!res.ok) { process.exitCode = 1; return; }
  saveProtectState(root, { lastApply: { ...loadProtectState(root).lastApply, planSha256: approval.sha } });

  log.title('적용 후 검증');
  const v = runProtectVerify(root, buildDir);
  if (v.errors) {
    log.err(`손상 ${v.errors}건 감지 — dcheck protect restore 로 되돌린 뒤 원인을 확인하세요.`);
    process.exitCode = 1;
  } else {
    log.ok(`산출물 정적 검증 통과${v.warnings ? color.dim(` (주의 ${v.warnings}건)`) : ''}. 다시 scan 하면 보호 상태에 반영됩니다.`);
  }
  log.plain(color.dim('  이 도구는 배포하지 않습니다. 배포는 사용자가 따로 승인해 진행하세요.'));
}

// protect restore: 마지막(또는 지정) 백업으로 복원.
function runProtectRestore() {
  const from = opt('from', '');
  const b = from ? path.resolve(root, from) : latestBackup(root);
  if (!b) { log.err('복원할 백업이 없습니다.'); process.exitCode = 1; return; }
  const r = restoreBackup(root, b);
  if (r.noManifest) { log.err(`백업 매니페스트를 찾을 수 없습니다: ${path.relative(root, b)}`); process.exitCode = 1; return; }
  log.ok(`복원 ${r.restored}개${r.removed ? `, 생성파일 ${r.removed}개 제거` : ''}${r.skipped ? color.yellow(`, 경계 밖 ${r.skipped}개 건너뜀`) : ''} ← ${color.dim(path.relative(root, b))}`);
}

// verify: 적용 전후 산출물 정적 검사 비교.
function runVerify() {
  const cfg = loadConfig(root);
  const plan = loadPlan(root);
  const buildDir = resolveBuildDir(root, (plan && plan.buildDir) || cfg?.protection?.buildDir);
  if (!buildDir) { log.err('빌드 산출물 디렉토리를 찾지 못했습니다. 먼저 빌드하세요.'); process.exitCode = 1; return; }
  log.title(`기능 무손상 검증  ${color.dim('buildDir=' + buildDir)}`);
  const v = runProtectVerify(root, buildDir);
  const st = loadProtectState(root);
  if (st.baseline && st.baseline.buildDir === buildDir) {
    const delta = v.errors - st.baseline.errors;
    log.plain(`  적용 전 기준선: 오류 ${st.baseline.errors}건 → 지금 ${v.errors}건${delta > 0 ? color.red(` (+${delta} — 적용으로 생긴 손상 의심)`) : delta < 0 ? color.green(` (${delta})`) : color.dim(' (변화 없음)')}`);
  }
  if (v.errors) {
    log.err(`검증 실패: 오류 ${v.errors}건. dcheck protect restore 로 되돌릴 수 있습니다.`);
    process.exitCode = 1;
  } else {
    log.ok(`정적 검증 통과${v.warnings ? color.dim(` (주의 ${v.warnings}건)`) : ''}.`);
  }
}

async function runProtectCmd() {
  const sub = args[0];
  const subArgs = args.slice(1);
  // opt/flag 는 args 전역을 보므로 서브커맨드 이름만 건너뛰면 그대로 쓸 수 있다.
  void subArgs;
  switch (sub) {
    case 'plan': await runProtectPlan(); break;
    case 'apply': await runProtectApply(); break;
    case 'restore': runProtectRestore(); break;
    default:
      log.err('사용법: dcheck protect plan | dcheck protect apply --plan-sha256 <값> --confirm-apply | dcheck protect restore [--from <경로>]');
      process.exitCode = 1;
  }
}

async function main() {
  switch (cmd) {
    case 'detect': printDetect(); break;
    case 'init': runInit(); break;
    case 'scan': await runScan(); break;
    case 'judge': runJudge(); break;
    case 'interview': runInterview(); break;
    case 'protect': await runProtectCmd(); break;
    case 'verify': runVerify(); break;
    case 'status': runStatus(); break;
    case 'report': runReport(); break;
    case 'submit': runSubmit(); break;
    case 'help': case undefined: help(); break;
    default: log.err(`알 수 없는 명령: ${cmd}`); help(); process.exitCode = 1;
  }
}
main().catch(e => { log.err(String(e && e.stack ? e.stack : e)); process.exitCode = 1; });

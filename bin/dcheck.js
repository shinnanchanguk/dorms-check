#!/usr/bin/env node
// dorms-check CLI, 교사의 AI(코치)가 부르는 오케스트레이터.
// 이 도구는 앱을 고치지도, 인증을 발급하지도 않는다. 평가·안내·증빙만.
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { color, log, exists, readJsonSafe, writeText, ensureDir } from '../core/util.js';
import { detectStack } from '../core/detect.js';
import { loadConfig, writeConfig, defaultConfig, unknownTracks, trackMenu, parseTrackSelection } from '../core/config.js';
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
import { applyEdzipPlan, buildEdzipPlan, prepareCouncilDocuments, writeEdzipPlan } from '../core/edzip-autopilot.js';
import { ALL_AGENTS, hookStatus, uninstallHooks } from '../core/hooks.js';
import { planRun, resolveRunDir, huntPrompt, verifierPrompt, criticPrompt, mergeResult, recordDecision, promoteArtifact, checkRun, reportRun, latestAuditSummary } from '../audit/run.js';
import { SEVERITY_LABEL } from '../audit/findings.js';

const root = process.cwd();
const [, , cmd, ...args] = process.argv;
const flag = n => args.includes('--' + n);
const opt = (n, d) => { const i = args.indexOf('--' + n); return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : d; };

const PKG = readJsonSafe(path.join(fileURLToPath(new URL('../package.json', import.meta.url)))) || { version: '0.1.0' };
const STATE_DIR = path.join(root, '.dorms-check');
const REVIEW = path.join(STATE_DIR, 'review.json');

function honesty() {
  log.plain(color.dim('  보안 점검은 공개 응답과 확인 가능한 코드를 살펴보는 최소 점검입니다.'));
  log.plain(color.dim('  확인하지 못한 항목은 미확인으로 남깁니다. 전체 안전을 보장하거나 앱 등록을 막지 않습니다.'));
  log.plain(color.dim('  도름스 마크는 서버가 공개 주소를 다시 검사해 발급합니다.'));
}

function help() {
  log.title('dorms-check ' + PKG.version + ' · 교사 앱 최소 점검');
  log.plain('  dcheck detect                              프로젝트 구성 확인');
  log.plain('  dcheck init --name <앱> --url <주소>         점검 설정 생성');
  log.plain('  dcheck scan --url <주소> [--json]           공개 응답·로컬 코드 검사와 결과 저장');
  log.plain('  dcheck scan --code-only [--json]            로컬 코드만 검사');
  log.plain('  dcheck status                              확인한 위험·권고·미확인 항목 보기');
  log.plain('  dcheck report                              저장한 점검 보고서 보기');
  log.plain('  dcheck submit                              보관용 증빙팩 생성');
  log.plain('');
  log.plain('  필요한 경우 --track security,edzip,protection 중 원하는 항목을 고르세요.');
  log.plain('  기본값은 security입니다. 서류와 앱 보호 기능은 별도로 선택합니다.');
  log.plain('  dcheck judge --in <JSON>                    직접 확인한 추가 근거 기록');
  log.plain('  dcheck edzip prepare                       에듀집 서류 작성 계획 저장');
  log.plain('  dcheck edzip prepare --apply --plan-sha256 <값> --confirm-apply --answers <JSON>');
  log.plain('  dcheck edzip council --approved-url <주소> --confirm-apply');
  log.plain('  dcheck interview [--answers <JSON>]         권리·이용 범위 질문 또는 답변 저장');
  log.plain('  dcheck protect plan                        앱 보호 변경 계획 저장');
  log.plain('  dcheck protect apply --plan-sha256 <값> --confirm-apply');
  log.plain('  dcheck protect restore [--from <경로>]      적용 전 백업 복원');
  log.plain('  dcheck verify                              앱 보호 적용 전후 산출물 비교');
  log.plain('');
  log.plain('  심층 점검(정밀 보안 감사, 요청할 때만):');
  log.plain('  dcheck audit plan [--profile quick|standard|deep] [--scope <경로,경로>] [--budget <N>]');
  log.plain('  dcheck audit prompt --role hunter|verifier|critic --agent <ID> [--group <N>|--units <ID,..>|--fingerprint <지문>]');
  log.plain('  dcheck audit lint --agent <ID> --in <JSON>       돌려주기 전 형식만 확인(바꾸지 않음)');
  log.plain('  dcheck audit merge --agent <ID> --in <JSON>      찾은 결과·범위 비평을 범위표에 넣기');
  log.plain('  dcheck audit record --agent <ID> --in <JSON>     반박 검증·최종 확인 기록');
  log.plain('  dcheck audit promote --agent <ID> --file <경로>   scratch 산출물을 증거로 옮기기');
  log.plain('  dcheck audit check | report [--run <폴더>]');
  log.plain('');
  log.plain('  이전 버전 정리: dcheck hooks status|uninstall [--agents ' + ALL_AGENTS.join(',') + '] [--json]');
  log.plain('  status는 기존 설정을 읽고, uninstall은 백업 후 도름스가 넣은 항목만 제거합니다.');
  log.plain('  init은 설정 파일, scan은 .dorms-check의 검사 결과·보고서·이력을 저장합니다.');
  log.plain('  서류 생성과 앱 보호 적용은 각 명령의 승인 절차를 따릅니다.');
  honesty();
}

function printDetect() {
  const d = detectStack(root);
  log.title('스택 감지');
  log.plain(`  프레임워크: ${color.bold(d.framework)}`);
  log.plain(`  Supabase : ${d.hasSupabase ? color.green('예') + ', RLS 실측 프로브 대상' : '아니오'}`);
  log.plain(`  적용 태그: ${d.applies.join(', ') || '(없음)'}`);
  if (d.buildDir) log.plain(`  빌드 산출물: ${d.buildDir} ${color.dim('(protection 트랙 검사 대상)')}`);
  return d;
}

async function runScan() {
  const json = flag('json');
  const cfg = loadConfig(root);
  if (cfg._parseError) {
    outputMachineResult({ ok: false, code: 'INVALID_CONFIG', exitCode: 2, reason: 'dorms-check.config.json을 읽지 못했습니다. JSON 형식을 확인하세요.' }, { json });
    return;
  }
  const url = opt('url', cfg.app?.url || '');
  const codeOnly = flag('code-only') || !url;
  const stack = cfg.app?.stack || detectStack(root).framework;
  const trackArg = opt('track', '');
  const tracks = trackArg ? trackArg.split(',').map(item => item.trim()).filter(Boolean) : (cfg.tracks?.length ? cfg.tracks : ['security']);
  const invalid = tracks.filter(id => !TRACKS.some(track => track.id === id));
  if (invalid.length) {
    outputMachineResult({ ok: false, code: 'INVALID_TRACK', exitCode: 2, reason: '알 수 없는 점검 종류: ' + invalid.join(', ') }, { json });
    return;
  }
  if (!cfg.ownershipConfirmed && !json) log.warn('본인이 만들고 운영하는 앱만 점검하세요.');

  let results = [];
  let raw = {};
  let bonus = [];
  let reachable = false;
  const scanOptions = { timeout: 5000, totalTimeout: 45000, deadlineAt: Date.now() + 45000 };
  if (!codeOnly) {
    if (!json) log.step('공개 응답 점검: ' + url);
    let external;
    try { external = await runExternalScan(url, scanOptions); }
    catch (error) {
      external = { reachable: false, items: [], raw: {}, error: String(error?.message || error) };
    }
    results.push(...external.items);
    raw = external.raw || {};
    bonus = external.bonus || [];
    reachable = external.reachable === true;
    if (reachable) {
      if (!json) log.step('공개된 데이터 접근 설정 점검');
      try { results.push(...(await runRuntimeProbe(url, scanOptions)).items); }
      catch (error) {
        results.push({ id: 'meta.runtime-probe', status: 'unknown', observed: '데이터 접근 설정을 확인하지 못했습니다.', evidence: { error: String(error?.message || error) } });
      }
    } else {
      results.push({ id: 'meta.public-surface', status: 'unknown', observed: '공개 응답 검사를 완료하지 못했습니다.', evidence: { error: external.error || 'unavailable' } });
      if (!json) log.warn('주소를 확인하지 못한 항목은 미확인으로 남기고 로컬 코드 검사를 계속합니다.');
    }
  } else if (!json) log.step('로컬 코드만 점검합니다. 공개 주소 검사는 미확인으로 남습니다.');

  results.push(...runStaticScan(root).items);
  const review = readJsonSafe(REVIEW) || {};
  for (const [id, value] of Object.entries(review)) {
    const existing = results.find(item => item.id === id);
    const catalog = catalogItem(id);
    const reviewable = ['ai', 'hybrid', 'declared'].includes(catalog?.method);
    if (existing && reviewable) {
      existing.status = value.status;
      existing.observed = value.evidence || existing.observed;
      existing.evidence = { ...existing.evidence, aiJudgment: value };
    } else if (!existing && reviewable) {
      results.push({ id, status: value.status, observed: value.evidence || '(AI 판단)', evidence: { aiJudgment: value } });
    }
  }
  for (const track of TRACKS) {
    if (tracks.includes(track.id) && track.collect) results.push(...track.collect({ results, review, config: cfg, root }));
  }

  const scan = { reachable, items: results, raw };
  const trackResults = {};
  for (const track of TRACKS) {
    if (tracks.includes(track.id)) trackResults[track.id] = track.score(results, { bonus, config: cfg, root, scan });
  }
  const normalized = new Map((trackResults.security?.items || []).map(item => [item.id, item]));
  results = results.map(item => normalized.get(item.id) || (item.status === 'pending' ? { ...item, status: 'unknown' } : item));

  const state = loadState(root);
  recordRound(state, { trackResults, results });
  saveState(root, state);
  const config = { ...cfg, app: { ...cfg.app, stack }, tracks };
  const md = renderReportMd({ config, results, trackResults, bonus });
  ensureDir(STATE_DIR);
  writeText(path.join(STATE_DIR, 'REPORT.md'), md);
  const saved = { at: new Date().toISOString(), url, reachable, results, bonus, raw, trackResults };
  writeText(path.join(STATE_DIR, 'scan.json'), JSON.stringify(saved, null, 2));
  if (json) {
    console.log(JSON.stringify({ ok: true, command: 'scan', ...saved }, null, 2));
    return;
  }
  printSummary({ trackResults, results, config });
  log.plain(color.dim('  리포트: .dorms-check/REPORT.md'));
  log.plain(color.dim('  미확인은 실패도 통과도 아닙니다. 필요한 근거가 있으면 judge로 추가할 수 있습니다.'));
  honesty();
}

// 사람이 터미널에서 직접 실행할 때(TTY) 세 축 중 원하는 것만 고르게 물어본다.
// AI 가 파이프로 실행할 때(비대화형)는 호출하지 않는다, 그때는 --track 플래그/기본값을 쓴다.
const AXIS_LABELS = {
  security: '보안',
  edzip: '학운위·개인정보',
  protection: '내 앱 비법·저작권 보호',
};
async function promptTracks() {
  const menu = trackMenu();
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = q => new Promise(res => rl.question(q, a => res(a)));
  try {
    log.title('어떤 축을 점검할까요? (쉼표로 여러 개)');
    for (const m of menu) log.plain(`  ${m.n}) ${AXIS_LABELS[m.id] || m.id}`);
    log.plain(color.dim('  보안 마크만 원하면 1 · 보안과 보호면 1,3 · 그냥 Enter 면 보안(1)만.'));
    for (let attempt = 0; attempt < 3; attempt++) {
      const ans = (await ask('선택> ')).trim();
      if (!ans) return ['security'];
      const ids = parseTrackSelection(ans, menu);
      if (ids.length) {
        const chosen = new Set(ids);
        const tokens = ans.split(/[\s,]+/).filter(Boolean).length;
        if (tokens > chosen.size) log.warn('알아듣지 못한 항목은 넘겼어요.');
        return ids;
      }
      log.warn('숫자(1~3) 또는 축 이름을 쉼표로 골라주세요.');
    }
    log.warn('입력을 알아듣지 못해 보안(security)만 점검합니다.');
    return ['security'];
  } finally {
    rl.close();
  }
}

async function runInit() {
  const existing = loadConfig(root);
  if (existing._exists && !flag('force')) { log.warn('dorms-check.config.json 이미 존재(덮어쓰려면 --force).'); return; }
  const d = detectStack(root);
  const cfg = defaultConfig();
  cfg.app.name = opt('name', cfg.app.name);
  cfg.app.url = opt('url', cfg.app.url);
  cfg.app.stack = opt('stack', d.framework);
  // 트랙 선택 우선순위: ① --track 플래그가 있으면 그대로(비대화형 회귀 없음)
  //   ② 플래그 없고 사람이 터미널에서 실행 중(TTY)이면 물어본다
  //   ③ 플래그 없고 비대화형(파이프)이면 기존 기본값(security) 유지
  let tracks;
  if (args.includes('--track')) {
    tracks = opt('track', 'security').split(',').map(s => s.trim()).filter(Boolean);
  } else if (process.stdin.isTTY) {
    tracks = await promptTracks();
  } else {
    tracks = defaultConfig().tracks; // ['security'], 기존 비대화형 동작 그대로
  }
  cfg.tracks = tracks.length ? tracks : ['security'];
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
    const cat = catalogItem(id);
    if (cat && (cat.method === 'deterministic' || (cat.track === 'security' && cat.method !== 'ai'))) {
      log.warn(`거부: ${id}, 결정적 검사 결과는 judge로 덮어쓸 수 없습니다.`);
      rejected++; continue;
    }
    // 증거 없는 pass 는 거부(할루시네이션 방지: 서술만으로 통과 못 함)
    if (v.status === 'pass' && (!v.evidence || String(v.evidence).trim().length < 4)) {
      log.warn(`거부: ${id}, pass 에는 증거(파일:라인 또는 실측 요약)가 필요합니다.`);
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
  const file = path.join(STATE_DIR, 'scan.json');
  if (!exists(file)) { log.warn('먼저 scan을 실행하세요.'); return; }
  const scan = readJsonSafe(file);
  const cfg = loadConfig(root);
  const stack = cfg.app?.stack || '내';
  const items = (scan?.results || []).filter(item => ['fail', 'info', 'unknown', 'pending'].includes(item.status));
  log.title('확인한 위험·권고·미확인 ' + items.length + '건');
  for (const item of items) {
    const catalog = catalogItem(item.id);
    const label = item.status === 'fail' ? '확인한 문제' : item.status === 'info' ? '권고' : '미확인';
    log.plain('  [' + label + '] ' + (catalog?.title || item.id));
    if (item.observed) log.plain('      ' + item.observed);
    if (item.status === 'fail' && catalog?.aiFix) log.plain('      AI에게: ' + catalog.aiFix.replaceAll('{stack}', stack));
  }
  printAuditSummary();
  honesty();
}

function printAuditSummary() {
  let summary = null;
  try { summary = latestAuditSummary(root); } catch { summary = null; }
  if (!summary) return;
  log.title(`심층 점검(${summary.profile}, ${summary.run_status === 'complete' ? '완료' : '미완료'})`);
  for (const f of summary.confirmed) log.plain(`  [확인한 위험 · ${SEVERITY_LABEL[f.severity] || f.severity}] ${f.title}`);
  for (const t of summary.needs_validation) log.plain(`  [미확인] ${t}`);
  if (!summary.confirmed.length && !summary.needs_validation.length) log.plain('  기록된 위험·미확인이 없습니다. 범위와 빈칸은 보고서에서 확인하세요.');
  log.plain(color.dim('  보고서: ' + path.join(summary.runDir, 'AUDIT.md')));
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
  const bonus = Array.isArray(scan.bonus) ? scan.bonus : [];
  const trackResults = {};
  for (const t of TRACKS) {
    if (!cfg.tracks?.includes(t.id)) continue;
    trackResults[t.id] = t.score(results, { bonus, config: cfg, root, scan: { reachable: scan.reachable, items: results, raw: scan.raw || {} } });
  }
  const payload = buildPayload({ config: { ...cfg, app: { ...cfg.app, stack } }, results, trackResults, bonus, toolVersion: PKG.version });

  const outDir = path.resolve(root, opt('out', '.dorms-check/evidence'));
  ensureDir(outDir);
  writeText(path.join(outDir, 'report.json'), JSON.stringify(payload, null, 2));
  writeText(path.join(outDir, 'REPORT.md'), readFileSync(path.join(STATE_DIR, 'REPORT.md'), 'utf8'));
  log.ok(`증빙팩 생성: ${path.relative(root, outDir)}/ (report.json · REPORT.md)`);

  log.title('도름스 마크 신청');
  log.plain('  도름스 앱 공유 화면에서 공개 주소의 최소 점검을 신청할 수 있습니다.');
  log.plain('  도름스 서버가 공개 응답을 직접 확인하며, 이 파일만으로 마크를 발급하지 않습니다.');
  log.plain('  미확인 항목이나 아직 받지 못한 마크 때문에 앱 등록을 중단할 필요는 없습니다.');
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
    log.title(`서버 이전 후보 ${plan.serverMoveCandidates.length}건 (이 계획은 코드를 옮기지 않아요, 교사 AI 가 별도 동의로)`);
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
    log.err(`손상 ${v.errors}건 감지, dcheck protect restore 로 되돌린 뒤 원인을 확인하세요.`);
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
    log.plain(`  적용 전 기준선: 오류 ${st.baseline.errors}건 → 지금 ${v.errors}건${delta > 0 ? color.red(` (+${delta}, 적용으로 생긴 손상 의심)`) : delta < 0 ? color.green(` (${delta})`) : color.dim(' (변화 없음)')}`);
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

async function runEdzipCmd() {
  const sub = args[0];
  if (!['prepare', 'council'].includes(sub)) {
    log.err('사용법: dcheck edzip prepare [...] | dcheck edzip council --approved-url <에듀집 주소> --confirm-apply [--source-dir <폴더>]');
    process.exitCode = 1;
    return;
  }
  if (sub === 'council') {
    try {
      const result = await prepareCouncilDocuments(root, {
        approvedUrl: opt('approved-url', ''), confirmApply: flag('confirm-apply'), sourceDir: opt('source-dir', ''),
      });
      log.ok(`내부 기안문·학운위 안건 초안 생성: ${path.relative(root, result.outDir)}`);
      log.plain(`  에듀집 확인 완료: ${result.approval.productName}  ${result.approval.normalizedUrl}`);
      log.plain('  05·06·07 HWPX의 Ctrl+F 안내로 학교명·기안자·결재선·일정을 직접 채우세요. 개인정보는 저장하지 않았습니다.');
      log.plain('  한글에서 표 글자가 겹쳐 보이면 문서 전체를 드래그해 복사한 다음, 전체가 선택된 그 상태에서 바로 붙여넣으면 해결됩니다.');
      log.plain('  내부 결재와 학운위 제출은 자동으로 하지 않았습니다. 학교 규정에 맞게 검토한 뒤 제출하세요.');
    } catch (error) {
      log.err(String(error?.message || error));
      process.exitCode = 1;
    }
    return;
  }
  if (!flag('apply')) {
    const plan = buildEdzipPlan(root);
    const file = writeEdzipPlan(root, plan);
    log.ok(`에듀집 제출·통과 준비 계획: ${path.relative(root, file)}`);
    log.plain(`  계획 SHA-256: ${plan.sha256}`);
    log.title('개인정보를 받지 않는 5가지 확인');
    for (const q of plan.questions) log.plain(`  - ${q.id}: ${q.ask} (${q.values.join('|')})`);
    log.plain(color.dim('  답은 JSON 파일에 저장하세요. 이름·학교·연락처·서명은 넣지 마세요.'));
    log.plain(color.dim('  계획을 확인한 뒤 --apply --plan-sha256 <값> --confirm-apply --answers <JSON>로 생성합니다.'));
    return;
  }
  let result;
  try {
    result = await applyEdzipPlan(root, {
      planSha256: opt('plan-sha256', ''),
      confirmApply: flag('confirm-apply'),
      answersFile: opt('answers', ''),
      continueOutOfScope: flag('continue-out-of-scope'),
    });
  } catch (error) {
    log.err(String(error?.message || error));
    process.exitCode = 1;
    return;
  }
  if (result.needsContinueConfirmation) {
    log.warn(`현재 답변으로는 선정 기준 적용 대상이 아닐 가능성이 큽니다: ${result.scope.reason}`);
    for (const source of result.sources) log.plain(`  - ${source.title}: ${source.url}`);
    log.plain('  그래도 자료를 준비하려면 같은 명령에 --continue-out-of-scope를 추가하세요.');
    return;
  }
  log.ok(`에듀집 제출용 HWPX·PDF 서류 생성: ${path.relative(root, result.outDir)}`);
  log.plain(`  적용 판정: ${result.scope.status}  ${result.scope.reason}`);
  log.plain('  이름·소속·연락처·서명·인영은 빈칸으로 남겼습니다. 04-submission-guide.hwpx의 Ctrl+F 검색어로 찾아 직접 채우세요.');
  log.plain('  구글폼 제출 뒤 며칠이 지나도 결과나 연락이 없으면 KERIS 교수학습지원부(053-714-0357, 053-714-0308)로 문의해 보세요.');
  log.plain('  한글에서 표 글자가 겹쳐 보이면 문서 전체를 드래그해 복사한 다음, 전체가 선택된 그 상태에서 바로 붙여넣으면 해결됩니다.');
  log.plain('  에듀집 제출은 하지 않았습니다. 확인 완료 뒤 edzip council에 공식 주소를 넣으면 내부 기안문과 학운위 안건 초안을 만듭니다.');
}

function auditScanSummary() {
  const scan = readJsonSafe(path.join(STATE_DIR, 'scan.json'));
  if (!scan?.results) return null;
  const pick = st => scan.results.filter(r => r.status === st).map(r => r.id);
  return { fail: pick('fail'), unknown: pick('unknown'), at: scan.at || scan.scannedAt || null };
}

function readAuditInput() {
  const file = opt('in', '');
  if (!file) throw new Error('--in <JSON 파일> 이 필요합니다.');
  const text = readFileSync(path.resolve(root, file), 'utf8').trim();
  if (Buffer.byteLength(text) > 5 * 1024 * 1024) throw new Error('입력 파일이 5MB 를 넘습니다.');
  try { return JSON.parse(text); } catch { throw new Error('JSON 이 아닙니다. 설명 문장 없이 JSON 만 넣어 주세요.'); }
}

async function runAuditCmd() {
  const sub = args[0];
  const runOpt = opt('run', '');
  try {
    if (sub === 'plan') {
      const budgetRaw = opt('budget', '');
      const budget = budgetRaw ? Number(budgetRaw) : null;
      if (budgetRaw && (!Number.isInteger(budget) || budget < 1)) throw new Error('--budget 은 1 이상의 정수입니다.');
      const scope = opt('scope', '') ? opt('scope', '').split(',').map(x => x.trim()).filter(Boolean) : [];
      const { runDir, meta, ledger } = planRun(root, { profile: opt('profile', 'standard'), scope, out: opt('out', '') || null, budget, scanSummary: auditScanSummary() });
      const planned = ledger.filter(u => u.status === 'planned').length;
      log.ok(`심층 점검 계획을 만들었습니다: ${runDir}`);
      log.plain(`  ${meta.output_reason}`);
      log.plain(`  범위표 ${ledger.length}단위(예정 ${planned}) · 찾기 묶음 ${meta.hunter_groups.length}개 · 예상 에이전트 ${meta.budget_estimate.planned}회`);
      if (meta.prior.prior_run) log.plain(`  이전 회차 ${meta.prior.prior_run} 이어받음: 그대로인 확인 ${meta.prior.carried.length}건, 다시 볼 것 ${meta.prior.revalidate.length}건`);
      if (meta.run_status === 'incomplete') log.warn('  예산이 정찰과 필수 비평·검증도 못 채웁니다. 범위를 좁히거나 깊이를 낮추세요.');
      log.plain('  다음: architecture.md 를 채우고 AUDIT-PLAN.md 의 순서를 따르세요.');
      return;
    }
    if (sub === 'prompt') {
      const runDir = resolveRunDir(root, runOpt);
      const role = opt('role', '');
      const agentId = opt('agent', '');
      let text;
      if (role === 'hunter') text = huntPrompt(runDir, { agentId, group: opt('group', '') || null, unitIds: opt('units', '') ? opt('units', '').split(',').map(x => x.trim()).filter(Boolean) : [] });
      else if (role === 'verifier') text = verifierPrompt(runDir, { agentId, fingerprint: opt('fingerprint', '') });
      else if (role === 'critic') text = criticPrompt(runDir, { agentId });
      else throw new Error('--role 은 hunter·verifier·critic 중 하나입니다.');
      process.stdout.write(text);
      return;
    }
    if (sub === 'merge') {
      const r = mergeResult(resolveRunDir(root, runOpt), { agentId: opt('agent', ''), input: readAuditInput() });
      if (r.kind === 'critic') log.ok(`범위 비평 반영: 새 단위 ${r.added}개, 다시 맡김 ${r.reassigned}개`);
      else log.ok(`찾기 결과 반영: 받아들인 단위 ${r.accepted.length}개, 다시 맡길 단위 ${r.reopened.length}개, 후보 ${r.candidates}건, 새 경계 ${r.uncovered}개${r.normalized ? `, 읽은 경로를 확인 기록 기준으로 맞춘 단위 ${r.normalized}개` : ''}`);
      for (const e of r.errors.slice(0, 20)) log.warn('  ' + e);
      if (r.errors.length) process.exitCode = 2;
      return;
    }
    if (sub === 'lint') {
      // 찾는 사람이 돌려주기 전에 스스로 형식을 확인한다. 범위표·결과는 바꾸지 않는다.
      const r = mergeResult(resolveRunDir(root, runOpt), { agentId: opt('agent', ''), input: readAuditInput(), dryRun: true });
      if (r.errors.length) { log.err(`형식 오류 ${r.errors.length}건`); for (const e of r.errors.slice(0, 40)) log.plain('  - ' + e); process.exitCode = 2; }
      else log.ok(`형식이 맞습니다. 받아들일 단위 ${r.accepted?.length ?? 0}개, 후보 ${r.candidates ?? 0}건`);
      return;
    }
    if (sub === 'record') {
      const r = recordDecision(resolveRunDir(root, runOpt), { agentId: opt('agent', ''), input: readAuditInput() });
      log.ok(`검증 기록: 반영 ${r.applied.length}건, 새 담당자 확인 대기 ${r.pending.length}건`);
      for (const e of r.errors.slice(0, 20)) log.warn('  ' + e);
      if (r.errors.length) process.exitCode = 2;
      return;
    }
    if (sub === 'promote') {
      const rel = promoteArtifact(resolveRunDir(root, runOpt), { agentId: opt('agent', ''), file: opt('file', '') });
      log.ok(`산출물 승격: ${rel}`);
      return;
    }
    if (sub === 'check') {
      const r = checkRun(resolveRunDir(root, runOpt));
      if (r.errors.length) { log.err(`형식 오류 ${r.errors.length}건`); for (const e of r.errors.slice(0, 30)) log.plain('  - ' + e); process.exitCode = 1; }
      else log.ok('범위표와 결과 기록의 형식이 맞습니다.');
      if (r.reasons.length) { log.warn('아직 완료가 아닙니다:'); for (const x of r.reasons) log.plain('  - ' + x); }
      return;
    }
    if (sub === 'report') {
      const runDir = resolveRunDir(root, runOpt);
      const { chk } = reportRun(root, runDir);
      log.ok(`보고서: ${path.join(runDir, 'AUDIT.md')} (${chk.complete ? '완료' : '미완료'})`);
      if (chk.errors.length) { log.err(`형식 오류 ${chk.errors.length}건이 있어 보고서를 믿기 어렵습니다. dcheck audit check 로 확인하세요.`); process.exitCode = 1; }
      printAuditSummary();
      return;
    }
    log.err('사용법: dcheck audit plan|prompt|lint|merge|record|promote|check|report (dcheck help 참고)');
    process.exitCode = 1;
  } catch (error) {
    log.err(String(error?.message || error));
    process.exitCode = 1;
  }
}

function outputMachineResult(result, { json = false, success = '' } = {}) {
  process.exitCode = result.exitCode ?? (result.ok ? 0 : 2);
  if (json) console.log(JSON.stringify(result, null, 2));
  else if (result.ok) log.ok(success || '요청을 완료했습니다.');
  else log.err((result.code ? result.code + ': ' : '') + (result.reason || '요청을 완료하지 못했습니다.'));
}

function removedFeature() {
  const removedOptions = new Set(['--strict', '--git-sha', '--vercel-deployment', '--require-canonical-git-source', '--provider', '--security-only', '--receipt', '--receipt-file']);
  const option = [cmd, ...args].find(value => typeof value === 'string' && removedOptions.has(value.split('=')[0]));
  if (!option && !['gate', 'receipt', 'proxy'].includes(cmd) && !(cmd === 'hooks' && args[0] === 'install')) return false;
  outputMachineResult({
    ok: false, code: 'FEATURE_REMOVED', exitCode: 2,
    reason: '전역 훅 설치와 배포 차단 기능은 제거됐습니다. 점검은 scan으로 새로 요청하고, 이전 설치는 hooks status와 hooks uninstall로 정리하세요.',
  }, { json: flag('json') });
  return true;
}

function runHooksCmd() {
  const sub = args[0];
  const json = flag('json');
  if (!['status', 'uninstall'].includes(sub)) {
    outputMachineResult({ ok: false, code: 'INVALID_COMMAND', exitCode: 2, reason: '사용법: dcheck hooks status|uninstall [--agents codex,claude,gemini,antigravity] [--json]' }, { json });
    return;
  }
  try {
    const selected = opt('agents', ALL_AGENTS.join(','));
    const result = sub === 'status' ? hookStatus({ agents: selected }) : uninstallHooks({ agents: selected });
    outputMachineResult({ ...result, ok: result.ok, exitCode: result.ok ? 0 : 2 }, { json, success: sub === 'status' ? '이전 설치 상태를 확인했습니다.' : '선택한 에이전트의 도름스 훅을 정리했습니다.' });
    if (!json) {
      const status = sub === 'status' ? result : result.status;
      for (const [agent, info] of Object.entries(status.agents)) log.plain('  ' + agent + ': ' + (info.error || (info.managedPresent ? '이전 도름스 훅이 남아 있습니다.' : '도름스 훅이 없습니다.')));
      for (const change of result.changes || []) if (change.backup) log.plain('  원본 백업: ' + change.backup);
      if (result.retainedFiles?.length) log.plain('  참조가 남거나 소유 여부를 확인하지 못한 공용 파일은 보존했습니다.');
    }
  } catch (error) {
    outputMachineResult({ ok: false, code: 'CLEANUP_FAILED', exitCode: 2, reason: error.message }, { json });
  }
}

async function main() {
  if (removedFeature()) return;
  switch (cmd) {
    case 'detect': printDetect(); break;
    case 'init': await runInit(); break;
    case 'scan': await runScan(); break;
    case 'judge': runJudge(); break;
    case 'interview': runInterview(); break;
    case 'protect': await runProtectCmd(); break;
    case 'edzip': await runEdzipCmd(); break;
    case 'audit': await runAuditCmd(); break;
    case 'hooks': runHooksCmd(); break;
    case 'verify': runVerify(); break;
    case 'status': runStatus(); break;
    case 'report': runReport(); break;
    case 'submit': runSubmit(); break;
    case 'help': case '--help': case '-h': case undefined: help(); break;
    default: log.err(`알 수 없는 명령: ${cmd}`); help(); process.exitCode = 1;
  }
}
main().catch(error => {
  outputMachineResult({ ok: false, code: 'COMMAND_FAILED', exitCode: 1, reason: String(error?.message || error) }, { json: flag('json') });
});

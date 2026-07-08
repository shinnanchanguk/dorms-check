#!/usr/bin/env node
// dorms-check CLI — 교사의 AI(코치)가 부르는 오케스트레이터.
// 이 도구는 앱을 고치지도, 인증을 발급하지도 않는다. 평가·안내·증빙만.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { color, log, exists, readJsonSafe, writeText, ensureDir } from '../core/util.js';
import { detectStack } from '../core/detect.js';
import { loadConfig, writeConfig, defaultConfig } from '../core/config.js';
import { runExternalScan } from '../checks/external/index.js';
import { runRuntimeProbe } from '../checks/runtime/index.js';
import { runStaticScan } from '../checks/static/index.js';
import { scoreSecurity, scoreEdzip } from '../core/score.js';
import { renderReportMd, printSummary } from '../core/report.js';
import { buildPayload } from '../core/payload.js';
import { loadState, saveState, recordRound } from '../core/session.js';
import { catalogItem, EDZIP_ITEMS, EDZIP_CASE_QUESTIONS } from '../catalog/index.js';

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
  log.title('dorms-check ' + color.dim('— 교사 앱 보안·개인정보 점검 코치'));
  log.plain(`
  ${color.bold('dcheck detect')}                 스택 감지(Next.js/Vite/정적, Supabase 여부)
  ${color.bold('dcheck init')}  ${color.dim('--name --url --track security,edzip --stack')}   설정 생성
  ${color.bold('dcheck scan')}  ${color.dim('--url <URL> [--code-only]')}   결정적 스캔(외부 표면+RLS 실측+정적) + 리포트
  ${color.bold('dcheck judge --in <answers.json>')}   교사 AI가 판단한 ai-review 항목 병합(증거 필수)
  ${color.bold('dcheck status')}                 남은 미충족 항목 + 수정 프롬프트
  ${color.bold('dcheck report')}                 전체 리포트 출력(.dorms-check/REPORT.md)
  ${color.bold('dcheck submit')}                 증빙팩 생성 + 도름스 마크 신청 안내
  ${color.bold('dcheck help')}                   도움말
`);
  honesty();
}

function printDetect() {
  const d = detectStack(root);
  log.title('스택 감지');
  log.plain(`  프레임워크: ${color.bold(d.framework)}`);
  log.plain(`  Supabase : ${d.hasSupabase ? color.green('예') + ' — RLS 실측 프로브 대상' : '아니오'}`);
  log.plain(`  적용 태그: ${d.applies.join(', ') || '(없음)'}`);
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
  // edzip 항목 seed(판단 안 된 건 pending)
  if (tracks.includes('edzip')) {
    for (const it of EDZIP_ITEMS) {
      if (!results.find(r => r.id === it.id)) {
        const rv = review[it.id];
        results.push({ id: it.id, status: rv ? rv.status : 'pending', observed: rv ? rv.evidence : '아직 판단 안 됨(judge 필요)', evidence: rv ? { aiJudgment: rv } : {} });
      }
    }
  }

  const security = tracks.includes('security') ? scoreSecurity(results, bonus) : null;
  const edzip = tracks.includes('edzip') ? scoreEdzip(results) : null;

  // 상태 저장 + 리포트
  const state = loadState(root);
  recordRound(state, { securityResult: security, edzipResult: edzip, results });
  saveState(root, state);

  const md = renderReportMd({ config: { ...cfg, app: { ...cfg.app, stack } }, results, security, edzip, bonus });
  ensureDir(STATE_DIR);
  writeText(path.join(STATE_DIR, 'REPORT.md'), md);
  writeText(path.join(STATE_DIR, 'scan.json'), JSON.stringify({ at: new Date().toISOString(), url, results, raw }, null, 2));

  printSummary({ security, edzip, results, config: { ...cfg, app: { ...cfg.app, stack } } });

  // ai-review 해야 할 항목 안내(교사 AI에게)
  const pending = results.filter(r => r.status === 'pending' || (r.status === 'info' && String(r.id).startsWith('code.')));
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
  if (cfg.tracks.includes('edzip')) {
    log.title('학운위(에듀집) 케이스 진단 — 아래 3문항 답을 config.edzipCase 에 A/B/C/D 로 기록');
    for (const q of EDZIP_CASE_QUESTIONS) log.plain(`  - ${q.id}: ${q.ask}`);
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
  const security = cfg.tracks?.includes('security') ? scoreSecurity(results, bonus) : null;
  const edzip = cfg.tracks?.includes('edzip') ? scoreEdzip(results) : null;
  const payload = buildPayload({ config: { ...cfg, app: { ...cfg.app, stack } }, results, security, edzip, bonus, toolVersion: PKG.version });

  const outDir = path.resolve(root, opt('out', '.dorms-check/evidence'));
  ensureDir(outDir);
  writeText(path.join(outDir, 'report.json'), JSON.stringify(payload, null, 2));
  writeText(path.join(outDir, 'REPORT.md'), readFileSync(path.join(STATE_DIR, 'REPORT.md'), 'utf8'));
  log.ok(`증빙팩 생성: ${path.relative(root, outDir)}/ (report.json · REPORT.md)`);

  const ready = (security ? security.eligible : true) && (edzip ? edzip.eligible : true);
  log.title('도름스 마크 신청');
  if (!ready) {
    log.warn('아직 통과하지 못한 항목이 있어요. status 로 남은 항목을 고친 뒤 다시 scan → submit 하세요.');
  }
  log.plain('  1) 도름스(dorms.school)에 로그인하세요.');
  log.plain('  2) 내가 만든 앱의 앱 공유 페이지에서 "보안 검토 마크 신청"을 누르세요.');
  log.plain('  3) 도름스 서버가 이 앱의 주소를 스스로 다시 검사합니다(외부 표면 + RLS 실측).');
  log.plain(color.dim('     서버 재검사에서 통과하지 못하면 마크가 발급되지 않습니다. 이 도구의 통과는 신청 준비일 뿐입니다.'));
  honesty();
}

async function main() {
  switch (cmd) {
    case 'detect': printDetect(); break;
    case 'init': runInit(); break;
    case 'scan': await runScan(); break;
    case 'judge': runJudge(); break;
    case 'status': runStatus(); break;
    case 'report': runReport(); break;
    case 'submit': runSubmit(); break;
    case 'help': case undefined: help(); break;
    default: log.err(`알 수 없는 명령: ${cmd}`); help(); process.exitCode = 1;
  }
}
main().catch(e => { log.err(String(e && e.stack ? e.stack : e)); process.exitCode = 1; });

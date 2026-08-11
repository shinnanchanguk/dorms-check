// 보호 단계 오케스트레이터 (ai-clone-shield core/apply.js 흡수 — ESM·계획 게이트 방식으로 개편).
// 등록된 단계를 순서대로 실행한다. dry=true 면 파일을 바꾸지 않고 변경 예정 목록만 모은다(계획용).
// 실제 적용은 반드시 백업을 먼저 만들고, 단계 실패 시 즉시 백업으로 복원한다.
import path from 'node:path';
import { log, color, exists, createBackup, restoreBackup, writeText, readJsonSafe } from '../core/util.js';
import { detectStack } from '../core/detect.js';
import { loadRightsProfile } from '../core/rights-profile.js';
import { verifyBuild } from './verify-static.js';
import { sourcemapStep } from './steps/sourcemap.js';
import { noticeStep } from './steps/notice.js';
import { legalStep } from './steps/legal.js';
import { evidenceStep } from './steps/evidence.js';

// 실행 순서 고정: 산출물 정리 → 고지 주입 → 기계용 안내·무결성 → 증거팩
export const PROTECT_STEPS = [sourcemapStep, noticeStep, legalStep, evidenceStep];

const STATE_FILE = path.join('.dorms-check', 'protect', 'state.json');

export function resolveBuildDir(root, preferred) {
  if (preferred && preferred !== '.' && exists(path.join(root, preferred))) return preferred;
  const d = detectStack(root);
  if (d.buildDir && d.buildDir !== '.' && exists(path.join(root, d.buildDir))) return d.buildDir;
  return null;
}

export function loadProtectState(root) {
  return readJsonSafe(path.join(root, STATE_FILE)) || {};
}

export function saveProtectState(root, patch) {
  const cur = loadProtectState(root);
  const next = { ...cur, ...patch };
  writeText(path.join(root, STATE_FILE), JSON.stringify(next, null, 2) + '\n');
  return next;
}

// 단계 실행. dry=true → 변경 없음(계획 수집). dry=false → 백업 + 적용 + 실패 시 복원.
// 반환: { ok, steps: [{id, title, changed, created, notes, error?}], backupDir, restored? }
export async function runProtectSteps(root, { buildDir, config, dry = false, quiet = false } = {}) {
  const rightsProfile = loadRightsProfile(root);
  const buildFull = path.join(root, buildDir);
  const backup = dry ? null : createBackup(root);
  const ctx = { root, buildDir, buildFull, config, rightsProfile, dry, backup };

  const results = [];
  for (const step of PROTECT_STEPS) {
    if (!quiet) log.title(`${step.title}  ${color.dim('[' + step.id + ']')}${dry ? color.yellow('  (계획 — 미적용)') : ''}`);
    try {
      const r = step.run(ctx) || {};
      results.push({ id: step.id, title: step.title, changed: r.changed || [], created: r.created || [], notes: r.notes || [] });
      if (!quiet) {
        for (const n of r.notes || []) log.plain('  ' + color.dim(n));
        log.ok(`  변경 ${(r.changed || []).length}개 · 생성 ${(r.created || []).length}개${dry ? color.yellow(' (계획)') : ''}`);
      }
    } catch (e) {
      results.push({ id: step.id, title: step.title, changed: [], created: [], notes: [], error: e.message });
      if (!dry && backup) {
        // 실패 시 즉시 복원(부분 적용 상태로 남기지 않는다)
        const b = backup.finalize();
        const restored = b.count || b.created ? restoreBackup(root, b.dir) : { restored: 0, removed: 0 };
        if (!quiet) log.err(`단계 실패(${step.id}): ${e.message} — 백업으로 복원함(파일 ${restored.restored}개 되돌림·생성물 ${restored.removed}개 제거).`);
        return { ok: false, steps: results, backupDir: b.dir, restored };
      }
      if (!quiet) log.err(`단계 실패(${step.id}): ${e.message}`);
      return { ok: false, steps: results, backupDir: null };
    }
  }

  let backupDir = null;
  if (backup) {
    const b = backup.finalize();
    backupDir = b.count || b.created ? b.dir : null;
    if (!quiet && backupDir) log.info(`백업 ${b.count + b.created}개 → ${color.dim(path.relative(root, b.dir))}  ${color.dim('(복원: dcheck protect restore)')}`);
  }

  if (!dry) {
    saveProtectState(root, { lastApply: { at: new Date().toISOString(), buildDir, backupDir: backupDir ? path.relative(root, backupDir) : null } });
  }
  return { ok: true, steps: results, backupDir };
}

// 적용 후(또는 임의 시점) 산출물 정적 검증 + 상태 기록.
export function runProtectVerify(root, buildDir, { quiet = false } = {}) {
  const buildFull = path.join(root, buildDir);
  const r = verifyBuild(root, buildFull);
  const errs = r.issues.filter(i => i.sev === 'error');
  const warns = r.issues.filter(i => i.sev === 'warn');
  saveProtectState(root, { lastVerify: { at: new Date().toISOString(), buildDir, errors: errs.length, warnings: warns.length } });
  if (!quiet) {
    log.plain(`  HTML ${r.checkedHtml}개 · JS ${r.checkedJs}개 검사`);
    for (const i of errs) log.err(`  손상: ${i.file} — ${i.msg}`);
    for (const i of warns.slice(0, 5)) log.warn(`  주의: ${i.file} — ${i.msg}`);
    if (warns.length > 5) log.plain(color.dim(`  ...주의 ${warns.length - 5}개 더`));
  }
  return { ...r, errors: errs.length, warnings: warns.length };
}

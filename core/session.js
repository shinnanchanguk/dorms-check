// 협업 완주 루프 상태(.dorms-check/state.json). 라운드 누적 → "어디까지 통과했나" 세션 간 유지.
import path from 'node:path';
import { exists, readJsonSafe, writeText, ensureDir } from './util.js';

const DIR = '.dorms-check';

function statePath(root) { return path.join(root, DIR, 'state.json'); }

export function loadState(root) {
  const p = statePath(root);
  return exists(p) ? (readJsonSafe(p) || newState()) : newState();
}

function newState() {
  return { version: 1, rounds: [], items: {}, passed: { security: false, edzip: false }, submitted: {} };
}

export function saveState(root, state) {
  const p = statePath(root);
  ensureDir(path.dirname(p));
  writeText(p, JSON.stringify(state, null, 2) + '\n');
  return p;
}

// 한 라운드 기록. results 로 항목별 최신 status 갱신 + 회귀 감지.
export function recordRound(state, { securityResult, edzipResult, results }) {
  const n = state.rounds.length + 1;
  const round = { n, at: new Date().toISOString() };
  if (securityResult) round.security = { score: securityResult.score, grade: securityResult.grade, eligible: securityResult.eligible, blocking: securityResult.blockingFails.map(f => f.id) };
  if (edzipResult) round.edzip = { eligible: edzipResult.eligible, unmet: edzipResult.unmet.map(u => u.id) };
  state.rounds.push(round);
  for (const r of results || []) {
    const prev = state.items[r.id];
    const fixedRound = (prev && prev.status !== 'pass' && r.status === 'pass') ? n : (prev && prev.fixedRound) || null;
    const regressed = prev && prev.status === 'pass' && r.status === 'fail';
    state.items[r.id] = { status: r.status, firstFailRound: (prev && prev.firstFailRound) || (r.status === 'fail' ? n : null), fixedRound, regressed: regressed || false };
  }
  if (securityResult) state.passed.security = securityResult.eligible;
  if (edzipResult) state.passed.edzip = edzipResult.eligible;
  return state;
}

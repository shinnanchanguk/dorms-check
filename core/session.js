// 협업 완주 루프 상태(.dorms-check/state.json). 라운드 누적 → "어디까지 통과했나" 세션 간 유지.
// 트랙별 라운드 요약·통과 판정은 레지스트리(core/tracks.js)가 소유한다.
import path from 'node:path';
import { exists, readJsonSafe, writeText, ensureDir } from './util.js';
import { TRACKS } from './tracks.js';

const DIR = '.dorms-check';

function statePath(root) { return path.join(root, DIR, 'state.json'); }

export function loadState(root) {
  const p = statePath(root);
  const state = exists(p) ? (readJsonSafe(p) || newState()) : newState();
  // 이전 버전 state 에 없는 트랙 키 보충(예: protection 추가 후 기존 state 로드)
  state.passed = { ...emptyPassed(), ...(state.passed || {}) };
  return state;
}

function emptyPassed() {
  return Object.fromEntries(TRACKS.map(t => [t.id, false]));
}

function newState() {
  return { version: 1, rounds: [], items: {}, passed: emptyPassed(), submitted: {} };
}

export function saveState(root, state) {
  const p = statePath(root);
  ensureDir(path.dirname(p));
  writeText(p, JSON.stringify(state, null, 2) + '\n');
  return p;
}

// 레거시 인자(securityResult/edzipResult)도 받아 trackResults 로 정규화(하위 호환).
function normalizeTrackResults({ trackResults, securityResult, edzipResult }) {
  if (trackResults) return trackResults;
  const out = {};
  if (securityResult) out.security = securityResult;
  if (edzipResult) out.edzip = edzipResult;
  return out;
}

// 한 라운드 기록. results 로 항목별 최신 status 갱신 + 회귀 감지.
export function recordRound(state, { securityResult, edzipResult, trackResults, results }) {
  const tr = normalizeTrackResults({ trackResults, securityResult, edzipResult });
  const n = state.rounds.length + 1;
  const round = { n, at: new Date().toISOString() };
  for (const t of TRACKS) {
    const result = tr[t.id];
    if (result) round[t.id] = t.roundSummary(result);
  }
  state.rounds.push(round);
  for (const r of results || []) {
    const prev = state.items[r.id];
    const fixedRound = (prev && prev.status !== 'pass' && r.status === 'pass') ? n : (prev && prev.fixedRound) || null;
    const regressed = prev && prev.status === 'pass' && r.status === 'fail';
    state.items[r.id] = { status: r.status, firstFailRound: (prev && prev.firstFailRound) || (r.status === 'fail' ? n : null), fixedRound, regressed: regressed || false };
  }
  for (const t of TRACKS) {
    const result = tr[t.id];
    if (result) state.passed[t.id] = t.passed(result);
  }
  return state;
}

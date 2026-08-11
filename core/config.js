// 설정 로드/저장 (dorms-check.config.json). 파싱 실패는 조용히 기본값으로 가지 않음.
import path from 'node:path';
import { exists, readJsonSafe, writeText } from './util.js';

// 유효한 트랙 목록은 레지스트리(core/tracks.js)가 SSOT.
import { trackIds } from './tracks.js';

export function defaultConfig() {
  return {
    app: { name: '', url: '', stack: '' },
    tracks: ['security'], // 레지스트리 참조: 'security' | 'edzip' | 'protection'
    edzipCase: null,       // 'A' | 'B' | 'C' | 'D'
    teacher: { dormsHandle: '' },
    // 본인이 만들고 운영하는 앱만 스캔한다는 동의(비파괴 스캔 윤리).
    ownershipConfirmed: false,
  };
}

// config.tracks 중 레지스트리에 없는 트랙을 반환(오타 경고용).
export function unknownTracks(cfg) {
  const known = new Set(trackIds());
  return (cfg.tracks || []).filter(t => !known.has(t));
}

export function loadConfig(root) {
  const p = path.join(root, 'dorms-check.config.json');
  const fileExists = exists(p);
  const user = fileExists ? readJsonSafe(p) : null;
  const base = defaultConfig();
  const cfg = { ...base, ...(user || {}) };
  cfg.app = { ...base.app, ...((user && user.app) || {}) };
  cfg.teacher = { ...base.teacher, ...((user && user.teacher) || {}) };
  cfg._exists = Boolean(user);
  cfg._parseError = fileExists && user === null;
  cfg._path = p;
  return cfg;
}

export function writeConfig(root, cfg) {
  const p = path.join(root, 'dorms-check.config.json');
  const clean = { ...cfg };
  delete clean._exists; delete clean._parseError; delete clean._path;
  writeText(p, JSON.stringify(clean, null, 2) + '\n');
  return p;
}

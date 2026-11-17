// 공통 유틸 (의존성 0 — Node 내장 모듈만). ESM.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const wrap = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
export const color = {
  dim: s => wrap('2', s),
  bold: s => wrap('1', s),
  red: s => wrap('31', s),
  green: s => wrap('32', s),
  yellow: s => wrap('33', s),
  blue: s => wrap('34', s),
  magenta: s => wrap('35', s),
  cyan: s => wrap('36', s),
};

export const log = {
  info: (...a) => console.log(color.cyan('i'), ...a),
  ok: (...a) => console.log(color.green('v'), ...a),
  warn: (...a) => console.log(color.yellow('!'), ...a),
  err: (...a) => console.error(color.red('x'), ...a),
  step: (...a) => console.log(color.blue('>'), ...a),
  plain: (...a) => console.log(...a),
  title: s => console.log('\n' + color.bold(s)),
};

export function exists(p) {
  try { fs.accessSync(p); return true; } catch { return false; }
}
export function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }
export function readText(p) { return fs.readFileSync(p, 'utf8'); }
export function readTextSafe(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }
export function writeText(p, s) { ensureDir(path.dirname(p)); fs.writeFileSync(p, s); }
export function readJsonSafe(p) { try { return JSON.parse(readText(p)); } catch { return null; } }
export function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

const DEFAULT_IGNORE = new Set(['node_modules', '.git', '.dorms-check', 'cache', 'dist', '.next', 'out', 'build']);

// 재귀 파일 워크. exts 지정 시 해당 확장자만.
export function walk(dir, { exts = null, ignore = DEFAULT_IGNORE, maxFiles = 200000 } = {}) {
  const out = [];
  (function rec(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.length >= maxFiles) return;
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (ignore.has(e.name)) continue;
        rec(full);
      } else if (e.isFile()) {
        if (exts) {
          const ext = path.extname(e.name).toLowerCase();
          if (!exts.includes(ext)) continue;
        }
        out.push(full);
      }
    }
  })(dir);
  return out;
}

// 사람이 읽는 짧은 요약(민감값 노출 방지: 원본이 아니라 관측 사실만).
export function truncate(s, n = 200) {
  if (s == null) return '';
  s = String(s).replace(/\s+/g, ' ').trim();
  return s.length > n ? s.slice(0, n) + '…' : s;
}

// ── ai-clone-shield 흡수 유틸 (protection 트랙의 적용·복원에 사용) ──

// top-level static import/export 가 있으면 ESM 으로 본다(동적 import() 는 제외 → 일반 구문검사 가능).
export function isLikelyESM(code) {
  return /^[ \t]*import[ \t][^\n]*\bfrom\b/m.test(code)
    || /^[ \t]*import[ \t]*['"]/m.test(code)
    || /^[ \t]*import[ \t]*\{/m.test(code)
    || /^[ \t]*export[ \t]/m.test(code)
    || /^[ \t]*export\{/m.test(code);
}

// rel 이 root 경계 안에 있는지(경로 트래버설 방지)
export function withinRoot(root, rel) {
  if (path.isAbsolute(rel)) return false;
  const rootAbs = path.resolve(root);
  const resolved = path.resolve(rootAbs, rel);
  return resolved === rootAbs || resolved.startsWith(rootAbs + path.sep);
}

// ── 안전한 쓰기: 프로젝트 폴더 밖으로 새지 않게 ──
// 보호 단계는 남이 만든 저장소(리믹스·템플릿)에서도 돈다. 저장소에 심어 둔 심볼릭 링크를 따라
// 프로젝트 밖 파일(예: ~/.ssh/authorized_keys)을 덮어쓰지 않도록, 쓰기 전에 경로의 모든 마디를 lstat 으로 보고
// 실제 위치(realpath)가 root 안인지 확인한다. 쓰기는 같은 폴더의 임시 파일(wx) + rename 으로 한다.
export class UnsafePathError extends Error {
  constructor(rel, reason) {
    super(unsafeMessage(rel, reason));
    this.name = 'UnsafePathError';
    this.rel = rel;
    this.reason = reason;
  }
}
function unsafeMessage(rel, reason) {
  // 문구는 copy.ko.json 에 있다(순환 참조를 피하려고 필요할 때 읽는다).
  try {
    const copy = JSON.parse(fs.readFileSync(new URL('../templates/copy.ko.json', import.meta.url), 'utf8'));
    const tpl = copy.cli.unsafeWrite;
    const why = copy.cli.unsafeWriteReason[reason] || reason;
    return tpl.replace('{file}', rel).replace('{reason}', why);
  } catch { return `unsafe write target: ${rel} (${reason})`; }
}
function insideReal(baseReal, p) { return p === baseReal || p.startsWith(baseReal + path.sep); }

export function assertSafeTarget(root, file) {
  const rootAbs = path.resolve(root);
  const abs = path.resolve(file);
  const rel = path.relative(rootAbs, abs) || path.basename(abs);
  if (!(abs === rootAbs || abs.startsWith(rootAbs + path.sep))) throw new UnsafePathError(rel, 'outside');
  let rootReal;
  try { rootReal = fs.realpathSync(rootAbs); } catch { throw new UnsafePathError(rel, 'outside'); }
  const parts = path.relative(rootAbs, abs).split(path.sep).filter(Boolean);
  let cur = rootAbs;
  for (let i = 0; i < parts.length; i++) {
    cur = path.join(cur, parts[i]);
    let st;
    try { st = fs.lstatSync(cur); } catch (e) { if (e.code === 'ENOENT') break; throw e; }
    if (st.isSymbolicLink()) throw new UnsafePathError(rel, 'symlink');
    const last = i === parts.length - 1;
    if (!last && !st.isDirectory()) throw new UnsafePathError(rel, 'notdir');
    if (last && !st.isFile()) throw new UnsafePathError(rel, 'notfile');
  }
  let p = path.dirname(abs);
  while (!lexists(p) && p !== path.dirname(p)) p = path.dirname(p);
  let pr;
  try { pr = fs.realpathSync(p); } catch { throw new UnsafePathError(rel, 'outside'); }
  if (!insideReal(rootReal, pr)) throw new UnsafePathError(rel, 'outside');
  return abs;
}

export function lexists(p) { try { fs.lstatSync(p); return true; } catch { return false; } }

export function safeWrite(root, file, data) {
  const abs = assertSafeTarget(root, file);
  const dir = path.dirname(abs);
  fs.mkdirSync(dir, { recursive: true });
  assertSafeTarget(root, file); // 만든 폴더까지 다시 확인
  let mode = 0o644;
  try { mode = fs.statSync(abs).mode & 0o777; } catch { /* 새 파일 */ }
  const tmp = path.join(dir, `.${path.basename(abs)}.dcheck-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`);
  try {
    fs.writeFileSync(tmp, data, { flag: 'wx', mode });
    fs.renameSync(tmp, abs);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch { /* 없음 */ }
    throw e;
  }
}

export function safeUnlink(root, file) {
  assertSafeTarget(root, file);
  fs.unlinkSync(file);
}

// .dorms-check 상태 폴더 트리 어디에든 링크가 있으면(남의 저장소가 심어 둔 경우) 백업·상태·증거가 밖으로 새거나
// 밖의 파일을 끌어온다. 폴더 자신과 그 안 모든 항목을 lstat 해서 링크·이상한 항목을 거부한다.
// (상태·백업·증거 쓰기는 이것과 별도로 모두 safeWrite 를 거친다.)
export function assertStateDirSafe(root) {
  const st = path.join(root, '.dorms-check');
  if (!lexists(st)) return;
  const top = fs.lstatSync(st);
  if (top.isSymbolicLink() || !top.isDirectory()) throw new UnsafePathError('.dorms-check', 'symlink');
  let seen = 0;
  (function rec(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (++seen > 200000) throw new UnsafePathError('.dorms-check', 'toomany');
      const full = path.join(d, e.name);
      const rel = path.relative(root, full);
      if (e.isSymbolicLink()) throw new UnsafePathError(rel, 'symlink');
      if (e.isDirectory()) rec(full);
      else if (!e.isFile()) throw new UnsafePathError(rel, 'notfile');
    }
  })(st);
}

// 읽기 쪽 검사: base 안의 file 을 읽기 전에 root 부터 file 까지 모든 마디가 링크가 아니고, 마지막이 보통 파일이며,
// realpath(file) 이 realpath(base) 안인지 확인한다(백업 안 링크로 로컬 파일을 끌어오지 못하게).
export function assertSafeSource(root, base, file) {
  const rootAbs = path.resolve(root);
  const abs = path.resolve(file);
  const baseAbs = path.resolve(base);
  const rel = path.relative(rootAbs, abs) || path.basename(abs);
  const inside = (b, p) => p === b || p.startsWith(b + path.sep);
  if (!inside(rootAbs, baseAbs) || !inside(baseAbs, abs)) throw new UnsafePathError(rel, 'outside');
  const parts = path.relative(rootAbs, abs).split(path.sep).filter(Boolean);
  let cur = rootAbs;
  for (let i = 0; i < parts.length; i++) {
    cur = path.join(cur, parts[i]);
    let st;
    try { st = fs.lstatSync(cur); } catch { throw new UnsafePathError(rel, 'notfile'); }
    if (st.isSymbolicLink()) throw new UnsafePathError(rel, 'symlink');
    const last = i === parts.length - 1;
    if (!last && !st.isDirectory()) throw new UnsafePathError(rel, 'notdir');
    if (last && !st.isFile()) throw new UnsafePathError(rel, 'notfile');
  }
  let br, fr;
  try { br = fs.realpathSync(baseAbs); fr = fs.realpathSync(abs); } catch { throw new UnsafePathError(rel, 'outside'); }
  if (!inside(br, fr)) throw new UnsafePathError(rel, 'outside');
  return abs;
}

// 표식 블록 안만 우리 것인 파일(AGENTS.md·CLAUDE.md)에서 블록을 원래 상태로 되돌린다.
// original 에 같은 블록이 있었으면 그 블록으로, 없었으면 블록과 우리가 붙인 빈 줄만 뺀다. 블록 밖 내용은 그대로.
export function restoreMarkedBlock(current, original, { start, end }) {
  const s = current.indexOf(start);
  const e = current.indexOf(end);
  if (s === -1 || e === -1 || e < s) return current;
  const before = current.slice(0, s);
  const after = current.slice(e + end.length);
  if (original !== null && original !== undefined) {
    const os = original.indexOf(start);
    const oe = original.indexOf(end);
    if (os !== -1 && oe > os) return before + original.slice(os, oe + end.length) + after;
  }
  const rest = after.startsWith('\n') ? after.slice(1) : after;
  let head = before;
  if (!rest.trim()) head = head.replace(/\n{2,}$/, '\n');
  return head + rest;
}

const BACKUP_BASE = path.join('.dorms-check', 'backup');

// ── 백업 출처 확인: 이 컴퓨터의 dorms-check 가 만든 백업만 복원한다 ──
// 백업 폴더는 저장소 안이라, 남의 저장소에 평범한 파일로 가짜 백업(.git/config 를 덮는 매니페스트 등)을
// 심어 둘 수 있다. 그래서 매니페스트를 사용자별 비밀 열쇠(~/.config/dorms-check/backup.key, 0600)로
// HMAC 서명하고, 서명이 맞는 것만 믿는다. 시험에서는 DORMS_CHECK_CONFIG_HOME 으로 열쇠 위치를 바꾼다.
function configHome() {
  return process.env.DORMS_CHECK_CONFIG_HOME || path.join(os.homedir(), '.config', 'dorms-check');
}
export function backupKey({ create = true } = {}) {
  const dir = configHome();
  const file = path.join(dir, 'backup.key');
  try {
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile()) throw new UnsafePathError(file, 'notfile');
    const key = fs.readFileSync(file);
    if (key.length < 32) throw new UnsafePathError(file, 'notfile');
    return key;
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    if (!create) return null;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const key = crypto.randomBytes(32);
    try { fs.writeFileSync(file, key, { mode: 0o600, flag: 'wx' }); }
    catch (err) { if (err.code === 'EEXIST') return backupKey({ create: false }); throw err; }
    return key;
  }
}
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v === undefined ? null : v);
}
function realOr(p) { try { return fs.realpathSync(p); } catch { return path.resolve(p); } }
// 서명은 매니페스트 내용 + 그 프로젝트의 실제 위치 + 백업 폴더 이름에 묶인다(다른 곳으로 옮겨 쓰지 못하게).
function manifestSig(man, root, backupDir, key) {
  const { sig: _omit, ...rest } = man;
  return crypto.createHmac('sha256', key)
    .update('dorms-check-backup\0' + realOr(root) + '\0' + path.basename(backupDir) + '\0' + canonical(rest))
    .digest('hex');
}
// 'ok' | 'missing' | 'bad'
export function manifestStatus(man, root, backupDir) {
  if (!man || typeof man.sig !== 'string' || !man.sig) return 'missing';
  const key = backupKey({ create: false });
  if (!key) return 'bad';
  const want = Buffer.from(manifestSig(man, root, backupDir, key), 'hex');
  const got = Buffer.from(man.sig, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want) ? 'ok' : 'bad';
}

// 복원 대상 허용 목록: 보호 단계가 쓰는 자리(루트 안내 파일, public/usage.html, 기록한 빌드 폴더 아래)만.
// .git·.dorms-check·편집기·CI 설정·package.json·루트의 점 파일은 서명과 상관없이 늘 거부한다.
const DENY_SEGMENTS = new Set(['.git', '.dorms-check', '.github', '.vscode', '.husky', '.idea', 'node_modules']);
const DENY_BASENAMES = new Set(['package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', '.npmrc']);
const ROOT_TARGETS = new Set(['AGENTS.md', 'CLAUDE.md', 'dorms.json', 'LICENSE', 'public/usage.html']);
// 대소문자를 가리지 않는 파일 체계(macOS·Windows)에서 .GIT 같은 이름이 거부 목록을 빠져나가지 않게
// 비교 전에 유니코드 정규화(NFKC)와 소문자로 맞춘다. 끝의 점·공백(Windows 가 떼어 냄)도 지운다.
function foldSeg(x) { return String(x).normalize('NFKC').toLowerCase().replace(/[. ]+$/, ''); }
const ROOT_TARGETS_FOLDED = new Set([...ROOT_TARGETS].map((t) => t.split('/').map(foldSeg).join('/')));
function safeBuildDir(buildDir) {
  if (typeof buildDir !== 'string' || !buildDir || path.isAbsolute(buildDir)) return null;
  const segs = buildDir.split(/[\\/]+/).filter(Boolean);
  if (!segs.length || segs.some(x => x === '.' || x === '..' || DENY_SEGMENTS.has(foldSeg(x)))) return null;
  return segs.join('/');
}
export function restoreTargetAllowed(rel, buildDir) {
  if (typeof rel !== 'string' || !rel || path.isAbsolute(rel)) return false;
  const segs = rel.split(/[\\/]+/).filter(Boolean);
  if (!segs.length || segs.some(x => x === '..' || x === '.' || DENY_SEGMENTS.has(foldSeg(x)))) return false;
  const folded = segs.map(foldSeg);
  if (DENY_BASENAMES.has(folded[folded.length - 1])) return false;
  if (ROOT_TARGETS_FOLDED.has(folded.join('/'))) return true;
  if (segs.length === 1 && folded[0].startsWith('.')) return false;
  const bd = safeBuildDir(buildDir);
  if (!bd) return false;
  const bdFolded = bd.split('/').map(foldSeg).join('/');
  return folded.join('/').startsWith(bdFolded + '/');
}

// 변경 전 원본을 보존하는 백업 세션(.dorms-check/backup/<ts>/).
// - 파일 수정 직전 backup(file) 호출 → 원본 보존(restore 시 되돌림)
// - 신규 생성 파일은 markCreated(file) 호출 → restore 시 제거(원래 없던 파일 정리)
// - 쓴 직후 recordWritten(file, text) → 우리가 쓴 내용의 sha256. restore 때 지금 내용이 이것과 다르면
//   선생님이 그 뒤에 고친 것이므로 덮거나 지우지 않는다(표식 블록 파일은 블록만 되돌린다).
export function createBackup(root, { buildDir = null } = {}) {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.join(root, BACKUP_BASE, ts);
  const manifest = [];
  const createdFiles = [];
  const keepDirs = {}; // 생성 파일마다 원래 있던 가장 가까운 상위 폴더(복원 때 그 폴더는 비어도 지우지 않는다)
  const written = {};
  const blocks = {};
  const seen = new Set();
  const signManifest = (man) => ({ ...man, sig: manifestSig(man, root, dir, backupKey()) });
  return {
    dir,
    backup(file) {
      if (!exists(file)) return;
      const rel = path.relative(root, file);
      if (seen.has(rel) || createdFiles.includes(rel)) return; // 같은 파일 첫 변경분만 백업(멱등), 이번에 만든 파일은 원본이 없다
      seen.add(rel);
      const dest = path.join(dir, rel);
      safeWrite(root, dest, fs.readFileSync(file));
      manifest.push(rel);
    },
    markCreated(file) {
      const rel = path.relative(root, file);
      if (!createdFiles.includes(rel)) {
        createdFiles.push(rel);
        let d = path.dirname(path.resolve(file));
        while (!exists(d) && d !== path.dirname(d)) d = path.dirname(d);
        keepDirs[rel] = path.relative(root, d);
      }
    },
    recordWritten(file, data, { block } = {}) {
      const rel = path.relative(root, file);
      written[rel] = sha256(Buffer.isBuffer(data) ? data : String(data));
      if (block) blocks[rel] = block;
    },
    recordRemoved(file) {
      const rel = path.relative(root, file);
      written[rel] = null; // 지운 파일: 지금도 없으면 원본을 되살린다
    },
    finalize() {
      if (manifest.length || createdFiles.length) {
        safeWrite(
          root,
          path.join(dir, '_manifest.json'),
          JSON.stringify(signManifest({ at: new Date().toISOString(), version: 2, buildDir, files: manifest, createdFiles, keepDirs, written, blocks }), null, 2)
        );
      }
      return { dir, count: manifest.length, created: createdFiles.length };
    },
  };
}

export function listBackups(root) {
  const base = path.join(root, BACKUP_BASE);
  if (!exists(base)) return [];
  return fs.readdirSync(base)
    .filter(d => exists(path.join(base, d, '_manifest.json')))
    .sort()
    .map(d => path.join(base, d));
}
export function latestBackup(root) {
  const all = listBackups(root);
  return all.length ? all[all.length - 1] : null;
}

// 삭제 후 비게 된 부모 디렉토리를 root 경계까지만 정리
function cleanupEmptyDirs(dir, rootAbs, keepAbs = null) {
  let cur = path.resolve(dir);
  while (cur.startsWith(rootAbs + path.sep) && cur !== rootAbs && cur !== keepAbs) {
    try {
      if (fs.readdirSync(cur).length === 0) { fs.rmdirSync(cur); cur = path.dirname(cur); }
      else break;
    } catch { break; }
  }
}

function fileSha(p) {
  try { return sha256(fs.readFileSync(p)); } catch { return undefined; }
}
function validBlock(b) { return b && typeof b.start === 'string' && typeof b.end === 'string' && b.start && b.end; }

// 복원. 반환: { restored, removed, skipped, kept: [rel], blockRestored: [rel] }
// - kept: 적용 뒤에 선생님이 고친 파일이라 그대로 둔 것(force 면 원본으로 덮는다)
// - blockRestored: 표식 블록만 원래대로 되돌리고 블록 밖 선생님 내용은 남긴 것
export function restoreBackup(root, backupDir, { force = false } = {}) {
  assertStateDirSafe(root);
  // 백업 폴더도 프로젝트 안이어야 하고, 매니페스트부터 링크가 아닌 보통 파일이어야 읽는다.
  let man;
  if (!lexists(path.join(backupDir, '_manifest.json'))) return { restored: 0, removed: 0, noManifest: true, kept: [], blockRestored: [] };
  try { man = JSON.parse(fs.readFileSync(assertSafeSource(root, backupDir, path.join(backupDir, '_manifest.json')), 'utf8')); }
  catch (e) { if (e instanceof UnsafePathError) throw e; man = null; }
  if (!man) return { restored: 0, removed: 0, noManifest: true, kept: [], blockRestored: [] };
  // 출처 확인: 서명이 틀리면 늘 거부, 서명이 없거나(예전 판·가짜) 쓴 내용 기록이 없으면 --force 없이는 거부.
  const status = manifestStatus(man, root, backupDir);
  const empty = { restored: 0, removed: 0, skipped: 0, kept: [], blockRestored: [], rejected: [] };
  if (status === 'bad') return { ...empty, refused: 'badSignature' };
  if (status === 'missing' && !force) return { ...empty, refused: 'unsigned' };
  if ((!(man.version >= 2) || !man.written || typeof man.written !== 'object') && !force) return { ...empty, refused: 'legacy' };
  const rejected = [];
  // 서명이 확인된 매니페스트만 빌드 폴더 범위를 정할 수 있다(--force 로 연 서명 없는 백업은 루트 대상만).
  const trustedBuildDir = status === 'ok' ? man.buildDir : null;
  const rootAbs = path.resolve(root);
  const written = man.written && typeof man.written === 'object' ? man.written : null;
  const blocks = man.blocks && typeof man.blocks === 'object' ? man.blocks : {};
  let n = 0, removed = 0, skipped = 0;
  const kept = [], blockRestored = [];
  const editedSince = (rel, cur) => {
    if (force || !written || !(rel in written)) return false;
    const w = written[rel];
    if (w === null) return cur !== undefined; // 우리가 지운 파일이 다시 생겼다
    return cur !== w;
  };
  for (const rel of man.files || []) {
    // 경로 트래버설 방어: 매니페스트의 상대경로가 root(및 backupDir) 경계를 벗어나면 건너뜀
    if (!withinRoot(root, rel) || !withinRoot(backupDir, rel)) { skipped++; continue; }
    if (!restoreTargetAllowed(rel, trustedBuildDir)) { rejected.push(rel); continue; }
    const src = path.join(backupDir, rel);
    const dest = path.resolve(rootAbs, rel);
    if (!lexists(src)) continue;
    const cur = fileSha(dest);
    try {
      assertSafeSource(root, backupDir, src); // 백업 안 링크로 로컬 파일을 끌어오지 않게
      if (editedSince(rel, cur)) {
        if (validBlock(blocks[rel]) && cur !== undefined) {
          const next = restoreMarkedBlock(fs.readFileSync(dest, 'utf8'), fs.readFileSync(src, 'utf8'), blocks[rel]);
          safeWrite(root, dest, next);
          blockRestored.push(rel);
        } else kept.push(rel);
        continue;
      }
      safeWrite(root, dest, fs.readFileSync(src));
      n++;
    } catch (e) {
      if (e instanceof UnsafePathError) { skipped++; continue; }
      throw e;
    }
  }
  for (const rel of man.createdFiles || []) {
    if (!withinRoot(root, rel)) { skipped++; continue; }
    if (!restoreTargetAllowed(rel, trustedBuildDir)) { rejected.push(rel); continue; }
    const p = path.resolve(rootAbs, rel);
    if (!lexists(p)) continue;
    const keep = man.keepDirs && typeof man.keepDirs[rel] === 'string' && withinRoot(root, man.keepDirs[rel] || '.')
      ? path.resolve(rootAbs, man.keepDirs[rel]) : null;
    try {
      const cur = fileSha(p);
      if (editedSince(rel, cur)) {
        if (validBlock(blocks[rel])) {
          const next = restoreMarkedBlock(fs.readFileSync(p, 'utf8'), null, blocks[rel]);
          if (next.trim()) { safeWrite(root, p, next); blockRestored.push(rel); continue; }
        } else { kept.push(rel); continue; }
      }
      safeUnlink(root, p); removed++; cleanupEmptyDirs(path.dirname(p), rootAbs, keep);
    } catch (e) {
      if (e instanceof UnsafePathError) { skipped++; continue; }
      /* 그 밖의 오류는 건너뜀 */
    }
  }
  return { restored: n, removed, skipped, kept, blockRestored, rejected, status };
}

// 이 컴퓨터의 열쇠로 서명이 맞는 백업만(이름순). 서명이 없거나 틀린 백업 수도 함께 돌려준다.
export function verifiedBackups(root) {
  const ok = [], other = [];
  for (const d of listBackups(root)) {
    let man = null;
    try { man = JSON.parse(fs.readFileSync(assertSafeSource(root, d, path.join(d, '_manifest.json')), 'utf8')); } catch { /* 깨짐 */ }
    (manifestStatus(man, root, d) === 'ok' ? ok : other).push(d);
  }
  return { ok, other };
}

export { DEFAULT_IGNORE };

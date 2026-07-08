// 공통 유틸 (의존성 0 — Node 내장 모듈만). ESM.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

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

export { DEFAULT_IGNORE };

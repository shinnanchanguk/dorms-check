// 학교 개인정보 자체점검 대비 정적 검사(Supabase 마이그레이션·config.toml·코드).
// 항목 출처: 교육부「개인정보보호 자체 점검표」(공문 붙임2) ③ 비밀번호 복잡성, ⑩ 고유식별정보 암호화,
// ⑪ 비밀번호 일방향 저장 / 개인정보위「외부 접속 가능 시스템 점검항목」(붙임3) 3. 접근통제,
// 4. 위험 파일 업로드. 코드만으로 확정할 수 없는 운영 항목(계정 말소·2단계 인증·실패 잠금·자동 로그아웃·
// 접속기록 보관·요청 횟수 제한)은 흔적만 참고로 보여 준다.
// 라이브 RLS 프로브는 "로그인 없이 읽기"만 실측하므로, 여기서는 그 밖의 것을 코드 근거로 본다.
// 한계: 대시보드에서 직접 바꾼 설정과 EXECUTE 로 만드는 동적 SQL 은 코드에 남지 않아 보지 못한다.
import fs from 'node:fs';
import path from 'node:path';
import { walk, readTextSafe, exists } from '../../core/util.js';

const MAX_FILE_BYTES = 2 * 1024 * 1024; // 이보다 큰 파일은 생성물·덤프로 보고 건너뛴다(느려짐 방지)

// 저장소 안에 실제로 있는 파일·폴더만 읽는다(심볼릭 링크로 바깥을 가리키면 건너뜀).
function insideRoot(root, p) {
  try {
    const real = fs.realpathSync(p);
    const base = fs.realpathSync(root);
    return real === base || real.startsWith(base + path.sep);
  } catch { return false; }
}
function readCapped(root, p) {
  try {
    if (!insideRoot(root, p) || fs.statSync(p).size > MAX_FILE_BYTES) return null;
  } catch { return null; }
  return readTextSafe(p);
}

// ── SQL 전처리 ──
// 문자열('…', E'…')·따옴표 식별자("…")·달러 인용 본문 길이를 돌려준다(시작 위치 i). 아니면 0.
function quotedSpan(sql, i) {
  const c = sql[i];
  if (c === "'" || c === '"') {
    const esc = c === "'" && /[eE]/.test(sql[i - 1] || '') && !/[\w$]/.test(sql[i - 2] || '');
    let j = i + 1;
    while (j < sql.length) {
      if (esc && sql[j] === '\\') { j += 2; continue; }
      if (sql[j] === c && sql[j + 1] === c) { j += 2; continue; }
      if (sql[j] === c) break;
      j++;
    }
    return Math.min(sql.length, j + 1) - i;
  }
  if (c === '$' && !/[\w$]/.test(sql[i - 1] || '')) {
    const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64));
    if (m) {
      const e = sql.indexOf(m[0], i + m[0].length);
      return (e < 0 ? sql.length : e + m[0].length) - i;
    }
  }
  return 0;
}

// 주석 제거(문자열·식별자·달러 인용 안은 보존). 줄 번호가 어긋나지 않게 줄바꿈은 남긴다.
export function stripSqlComments(sql) {
  let out = '';
  let i = 0;
  while (i < sql.length) {
    if (sql[i] === '-' && sql[i + 1] === '-') { const e = sql.indexOf('\n', i); i = e < 0 ? sql.length : e; continue; }
    if (sql[i] === '/' && sql[i + 1] === '*') {
      const e = sql.indexOf('*/', i + 2);
      const end = e < 0 ? sql.length : e + 2;
      out += sql.slice(i, end).replace(/[^\n]/g, ' ');
      i = end;
      continue;
    }
    const q = quotedSpan(sql, i);
    if (q) { out += sql.slice(i, i + q); i += q; continue; }
    out += sql[i]; i++;
  }
  return out;
}

// 문자열·식별자·달러 인용을 건너뛰며 ';' 로 문장을 나눈다. [{text, offset}]
export function splitStatements(sql) {
  const out = [];
  let start = 0;
  let i = 0;
  const push = end => {
    const t = sql.slice(start, end);
    if (t.trim()) out.push({ text: t.trim(), offset: start + (t.length - t.trimStart().length) });
  };
  while (i < sql.length) {
    const q = quotedSpan(sql, i);
    if (q) { i += q; continue; }
    if (sql[i] === ';') { push(i); start = i + 1; }
    i++;
  }
  push(sql.length);
  return out;
}

// 괄호·따옴표 밖 쉼표로 나눈다(컬럼 정의·ALTER 동작 목록·역할 목록·VALUES 행).
function splitTop(s) {
  const out = [];
  let depth = 0;
  let cur = '';
  let i = 0;
  while (i < s.length) {
    const q = quotedSpan(s, i);
    if (q) { cur += s.slice(i, i + q); i += q; continue; }
    const ch = s[i];
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; i++; continue; }
    cur += ch; i++;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

const unq = s => String(s || '').trim().replace(/"/g, '').toLowerCase();
const qualify = name => { const n = unq(name); return n.includes('.') ? n : `public.${n}`; };
const rolesOf = list => splitTop(String(list || '')).map(unq).filter(Boolean);
const NON_COLUMN = /^(constraint|primary|unique|foreign|check|exclude|like)$/i;
const IDENT = String.raw`(?:"(?:[^"]|"")+"|[\w]+)`;
const QNAME = String.raw`${IDENT}(?:\s*\.\s*${IDENT})?`;
const TYPE = String.raw`([\w.\s()[\]"]+)`;

function isTrueExpr(expr) {
  if (expr == null) return false;
  let e = String(expr).trim().toLowerCase();
  while (e.startsWith('(') && e.endsWith(')')) e = e.slice(1, -1).trim();
  return e === 'true';
}

// "using (...)" 처럼 괄호 짝을 맞춰 절 내용을 꺼낸다.
function clause(stmt, kw) {
  const m = new RegExp(`\\b${kw}\\s*\\(`, 'i').exec(stmt);
  if (!m) return null;
  let i = m.index + m[0].length;
  const start = i;
  let depth = 1;
  while (i < stmt.length && depth > 0) {
    const q = quotedSpan(stmt, i);
    if (q) { i += q; continue; }
    if (stmt[i] === '(') depth++;
    else if (stmt[i] === ')') depth--;
    i++;
  }
  return stmt.slice(start, i - 1);
}

// 정책 이름·표 뒤의 절만 순서대로 읽는다(이름 안의 "for all"·"to" 를 절로 오인하지 않게).
function policyClauses(rest) {
  const m = /^\s*(?:as\s+(permissive|restrictive)\s*)?(?:for\s+(all|select|insert|update|delete)\s*)?(?:to\s+([\s\S]+?))?\s*(?=\busing\b|\bwith\s+check\b|$)/i.exec(rest);
  return {
    restrictive: !!m && (m[1] || '').toLowerCase() === 'restrictive',
    cmd: m && m[2] ? m[2].toLowerCase() : null,
    roles: m && m[3] ? rolesOf(m[3]) : null,
    using: clause(rest, 'using'),
    check: clause(rest, 'with\\s+check'),
  };
}

// 마이그레이션 폴더만 적용 순서(파일 이름)대로 읽는다. 보관·시드·시험 SQL 은 적용된 적이 없을 수 있어 뺀다.
export function sqlFiles(root) {
  for (const sub of ['migrations', 'schemas']) {
    const dir = path.join(root, 'supabase', sub);
    if (!exists(dir) || !insideRoot(root, dir)) continue;
    const files = walk(dir, { exts: ['.sql'], maxFiles: 5000 })
      .sort((a, b) => path.relative(root, a).localeCompare(path.relative(root, b)));
    if (files.length) return files;
  }
  return [];
}

// SET 목록에서 <칸> = 값 을 찾아 제한 여부로 바꾼다. 없으면 null(그대로), excluded.<칸> 이면 rowVal.
function assigned(setList, col, rowVal) {
  for (const part of splitTop(setList)) {
    const m = new RegExp(`^\\s*${col}\\s*=\\s*([\\s\\S]+)$`, 'i').exec(part);
    if (!m) continue;
    const v = m[1].trim();
    if (new RegExp(`^excluded\\s*\\.\\s*${col}$`, 'i').test(v)) return rowVal;
    return !/^null$/i.test(v);
  }
  return null;
}

// storage.buckets INSERT 를 행마다 읽어 {id, size, mime} 로 돌려준다(값이 null 이면 제한 없음).
function bucketRows(head) {
  const m = /^insert\s+into\s+storage\s*\.\s*buckets\s*(\(([^)]*)\))?\s*values\s*([\s\S]+?)(?:\s+on\s+conflict\b[\s\S]*)?$/i.exec(head);
  if (!m) return [];
  const cols = m[2] ? splitTop(m[2]).map(unq) : null;
  const rows = [];
  for (const tuple of splitTop(m[3])) {
    const inner = tuple.trim().replace(/^\(/, '').replace(/\)$/, '');
    const vals = splitTop(inner).map(v => v.trim());
    const at = name => (cols ? vals[cols.indexOf(name)] : undefined);
    const id = cols ? at('id') : vals[0];
    const lit = /^'([^']+)'/.exec(id || '');
    if (!lit) continue;
    const set = v => v != null && v !== '' && !/^null$/i.test(v);
    rows.push({ id: lit[1], size: set(at('file_size_limit')), mime: set(at('allowed_mime_types')) });
  }
  return rows;
}

// 마이그레이션을 순서대로 재생해 정책·버킷·컬럼의 최종 상태를 만든다.
// entries: [{file, text}]
export function replaySupabaseSql(entries) {
  const policies = new Map(); // table|name → {table, name, cmd, roles, restrictive, using, check, file, line}
  const buckets = new Map();  // id → {file, line, size, mime}
  const columns = new Map();  // table.column → {table, column, type, file, line}
  const tables = new Map();   // table → {file, line, rls}  (마이그레이션으로 만든 일반 테이블)
  const setCol = (table, name, type, file, line) => {
    if (NON_COLUMN.test(unq(name))) return;
    columns.set(`${table}.${unq(name)}`, { table, column: unq(name), type: String(type).trim().toLowerCase(), file, line });
  };
  const moveKeys = (map, from, to, sep) => {
    for (const [k, v] of [...map.entries()]) {
      if (!k.startsWith(`${from}${sep}`)) continue;
      map.delete(k);
      map.set(`${to}${sep}${k.slice(from.length + 1)}`, { ...v, table: to });
    }
  };

  function apply(head, file, line, depth) {
    const low = head.toLowerCase();
    let m;

    // DO $$ … $$ 블록 안의 정책·표 문장도 재생한다(멱등 마이그레이션 패턴). EXECUTE 동적 SQL 은 볼 수 없다.
    if (/^do\b/i.test(head) && depth < 2) {
      const b = /\$([A-Za-z_][A-Za-z0-9_]*)?\$([\s\S]*?)\$\1\$/.exec(head);
      if (b) {
        for (const { text } of splitStatements(b[2])) {
          // EXECUTE '…' 문자열에 정적으로 적힌 문장도 읽는다(format(%I) 처럼 값이 바뀌는 건 못 읽는다).
          const ex = /\bexecute\s+'((?:[^']|'')*)'\s*$/i.exec(text);
          const inner = ex ? ex[1].replace(/''/g, "'") : text;
          const k = /\b(create|drop|alter)\s+(policy|table)\b/i.exec(inner);
          if (k) apply(inner.slice(k.index), file, line, depth + 1);
        }
      }
      return;
    }

    if ((m = new RegExp(String.raw`^create\s+(?:unlogged\s+|temp(?:orary)?\s+)?table\s+(?:if\s+not\s+exists\s+)?(${QNAME})\s*\(([\s\S]*)\)`, 'i').exec(head))) {
      const table = qualify(m[1]);
      if (!/^create\s+temp/i.test(head) && !tables.has(table)) tables.set(table, { file, line, rls: false });
      for (const def of splitTop(m[2])) {
        const c = new RegExp(String.raw`^\s*(${IDENT})\s+${TYPE}`).exec(def);
        if (c) setCol(table, c[1], c[2], file, line);
      }
      return;
    }
    if ((m = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${QNAME})\s+([\s\S]+)$`, 'i').exec(head))) {
      const table = qualify(m[1]);
      const rt = /^\s*rename\s+to\s+("?[\w]+"?)\s*$/i.exec(m[2]);
      const ss = /^\s*set\s+schema\s+("?[\w]+"?)\s*$/i.exec(m[2]);
      if (rt || ss) {
        const to = rt ? `${table.split('.')[0]}.${unq(rt[1])}` : `${unq(ss[1])}.${table.split('.').slice(1).join('.')}`;
        moveKeys(columns, table, to, '.');
        moveKeys(policies, table, to, '|');
        if (tables.has(table)) { tables.set(to, tables.get(table)); tables.delete(table); }
        return;
      }
      for (const act of splitTop(m[2])) {
        let a;
        if (/^\s*(enable|force)\s+row\s+level\s+security\b/i.test(act)) { const t = tables.get(table); if (t) t.rls = true; continue; }
        if (/^\s*disable\s+row\s+level\s+security\b/i.test(act)) { const t = tables.get(table); if (t) t.rls = false; continue; }
        if ((a = new RegExp(String.raw`^\s*add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(${IDENT})\s+${TYPE}`, 'i').exec(act))) setCol(table, a[1], a[2], file, line);
        else if ((a = new RegExp(String.raw`^\s*drop\s+(?:column\s+)?(?:if\s+exists\s+)?(${IDENT})`, 'i').exec(act)) && !/^\s*drop\s+(constraint|default|not\s+null|identity)\b/i.test(act)) columns.delete(`${table}.${unq(a[1])}`);
        else if ((a = new RegExp(String.raw`^\s*rename\s+(?:column\s+)?(${IDENT})\s+to\s+(${IDENT})`, 'i').exec(act)) && !/^\s*rename\s+constraint\b/i.test(act)) {
          const old = columns.get(`${table}.${unq(a[1])}`);
          if (old) { columns.delete(`${table}.${unq(a[1])}`); columns.set(`${table}.${unq(a[2])}`, { ...old, column: unq(a[2]) }); }
        } else if ((a = new RegExp(String.raw`^\s*alter\s+(?:column\s+)?(${IDENT})\s+(?:set\s+data\s+)?type\s+${TYPE}`, 'i').exec(act))) {
          const c = columns.get(`${table}.${unq(a[1])}`);
          if (c) c.type = a[2].trim().toLowerCase();
        }
      }
      return;
    }
    if ((m = /^drop\s+table\s+(?:if\s+exists\s+)?([\s\S]+?)(?:\s+(?:cascade|restrict))?$/i.exec(head))) {
      for (const t of splitTop(m[1]).map(qualify)) {
        for (const k of [...policies.keys()]) if (k.startsWith(`${t}|`)) policies.delete(k);
        for (const k of [...columns.keys()]) if (k.startsWith(`${t}.`)) columns.delete(k);
        tables.delete(t);
      }
      return;
    }

    if ((m = new RegExp(String.raw`^create\s+policy\s+(${IDENT})\s+on\s+(${QNAME})`, 'i').exec(head))) {
      const table = qualify(m[2]);
      const name = unq(m[1]);
      const c = policyClauses(head.slice(m[0].length));
      policies.set(`${table}|${name}`, {
        table, name,
        cmd: c.cmd || 'all',
        roles: c.roles || ['public'],
        restrictive: c.restrictive,
        using: c.using,
        check: c.check,
        file, line,
      });
      return;
    }
    if ((m = new RegExp(String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+(${QNAME})`, 'i').exec(head))) {
      policies.delete(`${qualify(m[2])}|${unq(m[1])}`);
      return;
    }
    if ((m = new RegExp(String.raw`^alter\s+policy\s+(${IDENT})\s+on\s+(${QNAME})`, 'i').exec(head))) {
      const key = `${qualify(m[2])}|${unq(m[1])}`;
      const p = policies.get(key);
      const rest = head.slice(m[0].length);
      const rn = new RegExp(String.raw`^\s*rename\s+to\s+(${IDENT})`, 'i').exec(rest);
      if (rn) {
        if (p) { policies.delete(key); policies.set(`${p.table}|${unq(rn[1])}`, { ...p, name: unq(rn[1]) }); }
        return;
      }
      if (p) {
        const c = policyClauses(rest);
        if (c.roles) p.roles = c.roles;
        if (c.using != null) p.using = c.using;
        if (c.check != null) p.check = c.check;
      }
      return;
    }

    if (/\bstorage\s*\.\s*buckets\b/.test(low)) {
      if (/^insert\s+into\s+storage/i.test(head)) {
        for (const r of bucketRows(head)) {
          const b = buckets.get(r.id) || { file, line, size: false, mime: false };
          b.size = b.size || r.size; b.mime = b.mime || r.mime;
          buckets.set(r.id, b);
        }
        // ON CONFLICT … DO UPDATE SET 는 기존 버킷 설정을 덮어쓴다. excluded.<칸> 이면 그 행의 값이 그대로 들어간다.
        const upd = /\bon\s+conflict\b[\s\S]*\bdo\s+update\s+set\b([\s\S]*)$/i.exec(head);
        if (upd) for (const r of bucketRows(head)) {
          const bk = buckets.get(r.id);
          if (!bk) continue;
          const sz = assigned(upd[1], 'file_size_limit', r.size);
          const mm = assigned(upd[1], 'allowed_mime_types', r.mime);
          if (sz != null) bk.size = sz;
          if (mm != null) bk.mime = mm;
        }
      } else if (/^update\s+storage/i.test(head)) {
        const ids = [...head.matchAll(/'([a-z0-9][a-z0-9._-]{0,62})'/gi)].map(x => x[1]);
        const setPart = (/\bset\b([\s\S]*?)(?:\bwhere\b|$)/i.exec(head) || [])[1] || '';
        for (const id of ids) {
          const bk = buckets.get(id);
          if (!bk) continue;
          const sz = assigned(setPart, 'file_size_limit', bk.size);
          const mm = assigned(setPart, 'allowed_mime_types', bk.mime);
          if (sz != null) bk.size = sz;
          if (mm != null) bk.mime = mm;
        }
      } else if (/^delete\s+from\s+storage/i.test(head)) {
        for (const x of head.matchAll(/'([a-z0-9][a-z0-9._-]{0,62})'/gi)) buckets.delete(x[1]);
      }
    }
  }

  for (const { file, text } of entries) {
    const clean = stripSqlComments(text);
    // 줄 번호는 문장 시작 위치까지의 줄바꿈 수(한 번 훑기)
    const nl = [];
    for (let i = 0; i < clean.length; i++) if (clean[i] === '\n') nl.push(i);
    const lineAt = off => { let lo = 0, hi = nl.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (nl[mid] < off) lo = mid + 1; else hi = mid; } return lo + 1; };
    for (const { text: head, offset } of splitStatements(clean)) apply(head, file, lineAt(offset), 0);
  }
  return { policies, buckets, columns, tables };
}

// config.toml 의 [section] → {key: value}. 따옴표 안의 # 은 주석이 아니다.
export function parseToml(text) {
  const out = {};
  let sec = '';
  for (const rawLine of String(text || '').split(/\r?\n/)) {
    let line = '';
    let inStr = false;
    for (const ch of rawLine) {
      if (ch === '"') inStr = !inStr;
      if (ch === '#' && !inStr) break;
      line += ch;
    }
    line = line.trim();
    if (!line) continue;
    const s = /^\[([^\]]+)\]$/.exec(line);
    if (s) { sec = s[1].trim(); out[sec] = out[sec] || {}; continue; }
    const kv = /^([\w.-]+)\s*=\s*(.+)$/.exec(line);
    if (kv) { out[sec] = out[sec] || {}; out[sec][kv[1]] = kv[2].trim().replace(/^"(.*)"$/, '$1'); }
  }
  return out;
}

// 글자 그대로 담기면 안 되는 칸 이름. 해시·암호문·정책·시각처럼 보이는 이름은 뺀다.
const PW_COL_RE = /^(password|passwd|pwd|pw|pass_?word|비밀번호)$|^\w+_(password|passwd|pwd|pw)$/i;
const RRN_COL_RE = /(^|_)(rrn|ssn|jumin|resident_?(registration_?)?(no|num|number)|주민(등록)?번호)($|_)/i;
const SAFE_COL_RE = /(hash|digest|encrypt|enc$|_enc_|cipher|crypt|salt|_iv$|mask|last4|tail|_ref$|policy|reset|changed|updated|expire|required|must_change|length)/i;
const TEXT_TYPE_RE = /^(?:"?\w+"?\s*\.\s*)?"?(text|varchar|character\s+varying|char|character|citext|bpchar)\b/;
const DEV_PATH_RE = /(^|[\\/])(scripts|tests?|__tests__|e2e|fixtures|seed)([\\/]|$)|\.(test|spec)\.[cm]?[jt]sx?$/i;
const CODE_EXT = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
export const SUPABASE_IDS = ['code.plain-sensitive-column', 'code.rls.anon-write', 'auth.password-policy', 'storage.upload-limits'];

export function checkSupabaseProject(root) {
  const files = sqlFiles(root);
  const entries = files.map(f => ({ file: path.relative(root, f), text: readCapped(root, f) || '' }));
  const toml = parseToml(readCapped(root, path.join(root, 'supabase', 'config.toml')) || '');
  const codeTexts = walk(root, { exts: CODE_EXT, maxFiles: 6000 })
    .map(f => ({ file: path.relative(root, f), text: readCapped(root, f) || '' }));
  const usesSupabase = exists(path.join(root, 'supabase')) || codeTexts.some(c => /@supabase\//.test(c.text));

  const results = [];
  if (!usesSupabase) {
    for (const id of SUPABASE_IDS) results.push({ id, status: 'na', observed: 'Supabase 를 쓰지 않아 생략', evidence: { notApplicable: true } });
  } else {
    const { policies, buckets, columns, tables } = replaySupabaseSql(entries);
    const noSql = !entries.length;

    // 1) 주민번호·비밀번호를 글자 그대로 담는 칸 (붙임2 ⑩·⑪)
    const plainCols = [...columns.values()].filter(c =>
      TEXT_TYPE_RE.test(c.type) && !SAFE_COL_RE.test(c.column) && (PW_COL_RE.test(c.column) || RRN_COL_RE.test(c.column)));
    results.push({
      id: 'code.plain-sensitive-column',
      status: noSql ? 'na' : plainCols.length ? 'fail' : 'pass',
      observed: noSql
        ? '마이그레이션 SQL이 없어 저장 칸을 확인하지 못함(대시보드에서 만든 표는 직접 확인)'
        : plainCols.length
          ? `주민번호·비밀번호를 글자 그대로 담는 칸 ${plainCols.length}개: ${plainCols.slice(0, 8).map(c => `${c.table}.${c.column}`).join(', ')}`
          : `주민번호·비밀번호를 그대로 담는 칸 없음(칸 ${columns.size}개 확인)`,
      evidence: { hits: plainCols.slice(0, 40).map(c => ({ file: c.file, line: c.line, kind: `${c.table}.${c.column} ${c.type}` })) },
    });

    // 2) 로그인 없이 수정·삭제가 조건 없이 열린 정책 (붙임3 3. 접근통제)
    const openWrites = [...policies.values()].filter(p =>
      (p.roles.includes('anon') || p.roles.includes('public'))
      && !p.restrictive
      && ['update', 'delete', 'all'].includes(p.cmd)
      // 기존 행을 고치거나 지울 수 있는지는 USING 이 정한다(WITH CHECK 만 있으면 새 행 추가만 열린다).
      && isTrueExpr(p.using));
    // RLS 를 켜지 않은 public 테이블은 Supabase 기본 권한 때문에 로그인 없이 읽고 쓸 수 있다(가장 흔한 사고).
    const noRls = [...tables.entries()].filter(([t, v]) => t.startsWith('public.') && !v.rls);
    const writeTables = [...new Set(openWrites.map(p => p.table))];
    const problems = [
      ...(noRls.length ? [`마이그레이션에서 RLS(행 단위 보안)를 켜지 않은 테이블 ${noRls.length}개: ${noRls.slice(0, 8).map(([t]) => t).join(', ')}`] : []),
      ...(openWrites.length ? [`로그인 없이 누구나 고치거나 지울 수 있는 규칙 ${openWrites.length}개: ${writeTables.slice(0, 8).join(', ')}`] : []),
    ];
    results.push({
      id: 'code.rls.anon-write',
      // 정책을 열어 둔 것은 코드가 증거라 실패로 본다. RLS 꺼짐은 대시보드에서 켰을 수 있어 참고로만 알린다
      // (실제로 로그인 없이 읽히는지는 라이브 RLS 실측 code.rls.anon-read 가 판정한다).
      status: noSql ? 'na' : openWrites.length ? 'fail' : noRls.length ? 'info' : 'pass',
      observed: noSql
        ? '마이그레이션 SQL이 없어 DB 규칙을 확인하지 못함(대시보드에서 직접 확인)'
        : problems.length
          ? problems.join(' / ') + (noRls.length ? '. RLS 는 마이그레이션에 켜는 문장이 없다는 뜻이에요. 대시보드에서 켰다면 괜찮고, 안 켰다면 로그인 없이 읽고 쓸 수 있어요' : '')
          : `마이그레이션으로 만든 테이블 ${tables.size}개 모두 RLS 켜짐, 로그인 없이 수정·삭제를 여는 규칙 없음(규칙 ${policies.size}개 확인. 대시보드에서 바꾼 설정은 따로 확인)`,
      evidence: { hits: [
        ...noRls.slice(0, 20).map(([t, v]) => ({ file: v.file, line: v.line, kind: `${t} RLS 꺼짐` })),
        ...openWrites.slice(0, 20).map(p => ({ file: p.file, line: p.line, kind: `${p.table} "${p.name}" (${p.cmd})` })),
      ] },
    });

    // 3) 비밀번호 기준 (붙임2 ③). 로컬 config.toml 기준이고 운영값은 대시보드가 정본이다.
    const auth = toml.auth || {};
    const minLen = auth.minimum_password_length != null ? Number(auth.minimum_password_length) : null;
    const rawReq = auth.password_requirements;
    const req = typeof rawReq === 'string' && /^[a-z_]{1,60}$/i.test(rawReq) ? rawReq : (rawReq ? '알 수 없는 값' : rawReq);
    const strongReq = typeof req === 'string' && /symbol/i.test(req);
    let pwStatus;
    let pwObserved;
    if (!Object.keys(toml).length) {
      pwStatus = 'info';
      pwObserved = 'supabase/config.toml 이 없어 코드로 확인하지 못함. 운영 대시보드(Authentication > Policies)에서 8자 이상·특수문자 조건을 확인하세요';
    } else if (minLen != null && minLen < 8) {
      pwStatus = 'fail';
      pwObserved = `최소 길이가 ${minLen}자로 설정됨(8자 미만)`;
    } else if (minLen != null && minLen >= 8 && strongReq) {
      pwStatus = 'pass';
      pwObserved = `최소 ${minLen}자, 문자 조건 "${req}"(로컬 설정 기준. 운영 대시보드 값도 같게 맞추세요)`;
    } else {
      pwStatus = 'info';
      pwObserved = `로컬 설정: 최소 길이 ${minLen ?? '미설정(기본 6자)'}, 문자 조건 ${req ? `"${req}"` : '없음'}. 운영 대시보드 값을 8자 이상·특수문자 포함으로 맞췄는지 확인하세요`;
    }
    results.push({ id: 'auth.password-policy', status: pwStatus, observed: pwObserved, evidence: {} });

    // 4) 업로드 저장 공간의 용량·형식 제한 (붙임3 4. 위험 파일 업로드)
    for (const [k, v] of Object.entries(toml)) {
      const bm = /^storage\.buckets\.(.+)$/.exec(k);
      if (!bm) continue;
      const id = unq(bm[1]);
      const b = buckets.get(id) || { file: 'supabase/config.toml', line: 1, size: false, mime: false };
      b.size = b.size || v.file_size_limit != null;
      b.mime = b.mime || v.allowed_mime_types != null;
      buckets.set(id, b);
    }
    // 개발·시험용 스크립트가 로컬 DB에 만드는 버킷은 운영 설정이 아니므로 뺀다.
    for (const { file, text } of codeTexts.filter(c => !DEV_PATH_RE.test(c.file))) {
      const re = /\b(?:createBucket|updateBucket)\s*\(\s*['"`]([\w.-]{1,63})['"`]\s*(?:,\s*(\{[\s\S]{0,400}?\}))?/g;
      let m;
      while ((m = re.exec(text))) {
        const b = buckets.get(m[1]) || { file, line: text.slice(0, m.index).split('\n').length, size: false, mime: false };
        b.size = b.size || /fileSizeLimit/.test(m[2] || '');
        b.mime = b.mime || /allowedMimeTypes/.test(m[2] || '');
        buckets.set(m[1], b);
      }
    }
    const loose = [...buckets.entries()].filter(([, b]) => !b.size || !b.mime);
    results.push({
      id: 'storage.upload-limits',
      status: !buckets.size ? 'na' : loose.length ? 'fail' : 'pass',
      observed: !buckets.size
        ? '코드에서 파일 저장 공간(버킷) 생성을 찾지 못함(대시보드에서 만든 버킷은 대시보드에서 확인)'
        : loose.length
          ? `용량·형식 제한이 빠진 저장 공간 ${loose.length}개: ${loose.slice(0, 8).map(([id, b]) => `${id}(${[!b.size && '용량', !b.mime && '형식'].filter(Boolean).join('·')} 없음)`).join(', ')}`
          : `저장 공간 ${buckets.size}개 모두 용량·형식 제한 있음`,
      evidence: { hits: loose.slice(0, 40).map(([id, b]) => ({ file: b.file, line: b.line, kind: id })) },
    });
  }

  // 5) 코드만으로 확정할 수 없는 운영 항목(참고). 흔적이 있는지만 본다.
  const allCode = codeTexts.map(c => c.text).join('\n');
  const allSql = entries.map(e => e.text).join('\n');
  const signals = [
    { label: '탈퇴·퇴직 계정 삭제 기능', found: /auth\.admin\.deleteUser|deleteUser\s*\(|delete_?account|deactivate_?account|withdraw/i.test(allCode) },
    { label: '관리자 2단계 인증', found: /\bauth\.mfa\b|mfa\.(enroll|challenge|verify)|\baal2\b/.test(allCode) || /\baal2\b/.test(allSql) || toml['auth.mfa.totp']?.enroll_enabled === 'true' },
    { label: '로그인 실패 제한(캡차·잠금)', found: toml['auth.captcha']?.enabled === 'true' || /captchaToken|turnstile|hcaptcha|failed_login|login_attempt/i.test(allCode) || /failed_login|login_attempt|password_verification_attempt/i.test(allSql) },
    { label: '오래 쓰지 않으면 자동 로그아웃', found: toml['auth.sessions']?.inactivity_timeout != null || toml['auth.sessions']?.timebox != null || codeTexts.some(c => /\b(idle|inactivity)[\w-]{0,40}(timeout|logout)\b/i.test(c.text)) },
    { label: '접속·권한 변경 기록 보관', found: /\b(audit_logs?|access_logs?|activity_logs?|admin_logs?)\b/i.test(allSql) || /\bfrom\(\s*['"`](audit_logs?|access_logs?|activity_logs?)['"`]/.test(allCode) },
    { label: '요청 횟수 제한', found: /rate.?limit|@upstash\/ratelimit|too\s+many\s+requests/i.test(allCode) },
  ];
  const found = signals.filter(s => s.found).map(s => s.label);
  const missing = signals.filter(s => !s.found).map(s => s.label);
  results.push({
    id: 'ops.school-selfcheck',
    status: missing.length ? 'info' : 'pass',
    observed: missing.length
      ? `코드에서 흔적을 찾지 못한 항목: ${missing.join(', ')}${found.length ? ` (흔적 있음: ${found.join(', ')})` : ''}`
      : '학교 자체점검표 운영 항목 여섯 가지의 흔적이 모두 코드에 있음',
    evidence: {},
  });

  return results;
}

// 심층 점검 1단계(정찰)의 결정적 부분: 저장소를 읽어 공격 표면 목록을 만든다.
// 실행·네트워크 없이 파일만 읽는다. 결과는 범위표(coverage ledger)의 재료이고 위험 판정이 아니다.
import fs from 'node:fs';
import path from 'node:path';
import { readJsonSafe, readTextSafe } from '../core/util.js';

const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro']);
const SKIP_DIRS = new Set(['node_modules', '.git', '.dorms-check', 'cache', 'dist', '.next', 'out', 'build', 'coverage',
  '.vercel', '.turbo', '.svelte-kit', '.output', 'vendor', 'target', '.cache', '.idea', '.vscode']);
// 운영자 도구·문서·시험은 공격 표면이 아니다. 범위 밖으로 따로 센다.
const OPERATOR_DIRS = new Set(['scripts', 'docs', '.claude', '.github', 'archive', 'design-assets', 'screenshots']);
const TEST_PATH = /(^|\/)(__tests__|__mocks__|tests?|e2e|fixtures?|spec)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$/;
const ENTRY_FILE = /(^|\/)(route|page|actions?|middleware)\.[cm]?[jt]sx?$|(^|\/)(api|server|functions)\//;
const MAX_FILES = 40000;
const MAX_BYTES = 1024 * 1024;

function walkRepo(root) {
  const out = [];
  (function rec(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.length >= MAX_FILES) return;
      if (e.isSymbolicLink()) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || e.name.startsWith('.next')) continue;
        rec(full);
      } else if (e.isFile()) {
        out.push(path.relative(root, full).split(path.sep).join('/'));
      }
    }
  })(root);
  return out.sort();
}

function lineOf(text, re) {
  const m = re.exec(text);
  if (!m) return 0;
  return text.slice(0, m.index).split('\n').length;
}

function firstSeg(rel) { return rel.split('/')[0]; }
function countNewlines(text, from, to) { let n = 0; for (let i = from; i < to; i++) if (text.charCodeAt(i) === 10) n++; return n; }
function sizeOk(full, max) { try { const st = fs.lstatSync(full); return st.isFile() && st.size <= max; } catch { return false; } }
// 보이지 않는 문자, 또는 앞뒤 공백(NBSP·전각 공백 포함)이 붙은 폴더·파일 이름.
const INVISIBLE_PATH = /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF]|(^|\/)[\s\u00A0\u3000]|[\s\u00A0\u3000](\/|$)/u;

// 경로에서 하위 영역(subsystem)을 정한다. API 는 api/ 다음 한 칸까지, 그 밖은 앞쪽 세 칸 폴더.
export function subsystemOf(rel) {
  const parts = rel.split('/');
  const apiIdx = parts.indexOf('api');
  if (apiIdx >= 0 && apiIdx < parts.length - 2) return parts.slice(0, apiIdx + 2).join('/');
  const dir = parts.slice(0, -1);
  return dir.slice(0, 3).join('/') || '.';
}

const RULES = [
  { kind: 'api-route', path: /(^|\/)app\/(.+\/)?route\.[cm]?[jt]sx?$|(^|\/)pages\/api\/.+\.[cm]?[jt]sx?$|^api\/.+\.[cm]?[jt]s$|(^|\/)server\/(api|routes)\/.+\.[cm]?[jt]s$/ },
  { kind: 'server-action', text: /^[ \t]*['"]use server['"]/m },
  { kind: 'edge-function', path: /(^|\/)supabase\/functions\/[^/]+\/index\.[cm]?[jt]s$|(^|\/)netlify\/functions\/.+\.[cm]?[jt]s$|(^|\/)functions\/src\/.+\.[cm]?[jt]s$/ },
  { kind: 'auth-flow', path: /(^|\/)(auth|login|logout|signin|signup|sign-in|sign-up|callback|oauth|reset-password|password|verify-email)(\/|\.|-|_)/i, codeOnly: true },
  { kind: 'auth-flow', text: /\b(exchangeCodeForSession|signInWith(OAuth|Password|Otp|IdToken)|resetPasswordForEmail|verifyOtp|updateUser\(\s*\{\s*password|signInWithPopup|getRedirectResult)\b/ },
  { kind: 'webhook', path: /(^|\/)(webhooks?|hooks?)(\/|\.)/i, codeOnly: true },
  { kind: 'webhook', text: /\b(webhooks\.constructEvent|x-hub-signature|svix-signature|x-signature|createHmac\(\s*['"]sha256)/ },
  { kind: 'service-client', text: /\b(SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY|service_role|createAdminClient|createServiceClient|supabaseAdmin|firebase-admin)\b|(?:from\s+|require\(\s*)['"][^'"]*\/supabase\/(service|admin)(\.[cm]?[jt]s)?['"]/ },
  { kind: 'storage', text: /\.storage\s*\.from\(|storage\.buckets|getSignedUrl|createSignedUrl|createSignedUploadUrl|putObject\(|PutObjectCommand/ },
  { kind: 'upload', text: /\.upload\(|request\.formData\(\)|req\.formData\(\)|multer\(|busboy|type=["']file["']|createSignedUploadUrl/ },
  { kind: 'export', path: /(export|download|backup|csv|xlsx)/i, codeOnly: true },
  { kind: 'ai-call', text: /from\s+['"](openai|@anthropic-ai\/sdk|@google\/generative-ai|@google\/genai|ai|@ai-sdk\/[a-z-]+|groq-sdk|@mistralai\/[a-z-]+)['"]|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|openrouter\.ai\/api/ },
  { kind: 'mail-send', text: /from\s+['"](resend|nodemailer|@sendgrid\/mail|mailgun\.js|postmark)['"]|api\.resend\.com|\bsendEmail\(/ },
  { kind: 'outbound-fetch', serverOnly: true, text: /\bfetch\(\s*(?!['"`]https?:\/\/|['"`]\/)[A-Za-z_$`]|axios\.(get|post)\(\s*(?!['"`]https?:)[A-Za-z_$]|\bgot\(\s*[A-Za-z_$]/ },
  { kind: 'html-sink', text: /dangerouslySetInnerHTML|\.innerHTML\s*[+]?=|insertAdjacentHTML\(|document\.write\(|\bv-html\b|\{@html\b|\bmarked\(|markdown-it|rehype-raw/ },
  { kind: 'client-message', text: /addEventListener\(\s*['"]message['"]|\.onmessage\s*=|\.postMessage\(/ },
  { kind: 'redirect', text: /(redirect\(|NextResponse\.redirect|location\.(href|assign|replace)|router\.(push|replace)\()[^\n]{0,200}?(next|returnTo|return_to|redirect_to|redirectTo|callbackUrl|continue|goto)\b|searchParams\.get\(\s*['"](next|returnTo|return_to|redirect|redirect_to|redirectTo|callbackUrl|continue|goto)['"]/ },
  { kind: 'service-worker', text: /serviceWorker\.register\(|self\.addEventListener\(\s*['"]fetch['"]/ },
  { kind: 'browser-storage', text: /\b(localStorage|sessionStorage|indexedDB)\b/ },
];

function isServerFile(rel, text) {
  if (/^[ \t]*['"]use client['"]/m.test(text)) return false;
  return /(^|\/)(api|server|actions?|lib\/server|supabase\/functions|functions|middleware)(\/|\.|$)/.test(rel) || /^[ \t]*['"]use server['"]/m.test(text) || /\broute\.[cm]?[jt]s$/.test(rel);
}

// SQL 파일에서 함수 정의(마지막 정의가 이긴다)와 정책·뷰·저장소 표면을 뽑는다.
function sqlSurfaces(rel, text, functions) {
  const out = [];
  const fnRe = /create\s+(?:or\s+replace\s+)?function\s+([\w."]{1,200})\s*\(/ig;
  let m, count = 0, lastIdx = 0, lastLine = 1;
  // 줄 번호는 앞에서부터 이어 세고(매번 처음부터 자르지 않음), 한 파일의 함수 수도 묶는다.
  while ((m = fnRe.exec(text)) && count++ < 3000) {
    lastLine += countNewlines(text, lastIdx, m.index); lastIdx = m.index;
    const end = text.slice(m.index, m.index + 6000).search(/;\s*\n\s*(?:create|alter|grant|revoke|drop|comment)\b/i);
    const body = text.slice(m.index, m.index + (end < 0 ? 6000 : end));
    const name = m[1].replaceAll('"', '').replace(/^public\./, '');
    functions.set(name, { file: rel, line: lastLine, definer: /\bsecurity\s+definer\b/i.test(body) });
  }
  for (const d of text.matchAll(/drop\s+function\s+(?:if\s+exists\s+)?([\w."]+)/ig)) functions.delete(d[1].replaceAll('"', '').replace(/^public\./, ''));
  if (/create\s+(?:or\s+replace\s+)?view\b/i.test(text) || /\bpolicy\b|\bgrant\b|row\s+level\s+security/i.test(text)) {
    out.push({ kind: 'db-migration', file: rel, line: lineOf(text, /create\s+(?:or\s+replace\s+)?view\b|create\s+policy|\bgrant\b|row\s+level\s+security/i) || 1, scope: 'policies' });
  }
  if (/storage\.buckets|storage\.objects/i.test(text)) out.push({ kind: 'storage', file: rel, line: lineOf(text, /storage\.(buckets|objects)/i) || 1, scope: 'storage-policy' });
  return out;
}

// inventory: { root, surfaces[], kinds{}, outOfScope[], manifests[], stack hints }
export function buildInventory(root, { scope = [] } = {}) {
  const files = walkRepo(root);
  const surfaces = [];
  const outOfScope = new Map();
  const add = s => surfaces.push(s);
  let nativeCode = false;
  const functions = new Map();
  const invisible = [];

  for (const rawRel of files) {
    // 보이지 않는 문자가 든 경로는 건너뛰고, 한글 경로는 NFC 로 맞춘다(맥 NFD 이름도 같은 ID 가 되게).
    // 보이지 않는 문자가 든 경로는 범위표 ID 로 쓸 수 없지만 숨겨 두면 점검을 피하는 길이 된다. 따로 모아 우선 확인 단위로 넘긴다.
    if (INVISIBLE_PATH.test(rawRel)) { invisible.push(encodeURI(rawRel)); continue; }
    const rel = rawRel.normalize('NFC');
    const top = firstSeg(rel);
    const ext = path.extname(rel).toLowerCase();
    if (OPERATOR_DIRS.has(top) && !rel.startsWith('.github/workflows/')) {
      if (CODE_EXT.has(ext) || ext === '.sql') outOfScope.set(top, (outOfScope.get(top) || 0) + 1);
      continue;
    }
    if (TEST_PATH.test(rel)) { outOfScope.set('tests', (outOfScope.get('tests') || 0) + 1); continue; }
    if (/\.(c|cc|cpp|h|hpp)$/.test(ext) || (ext === '.rs' && !rel.startsWith('src-tauri/'))) nativeCode = true;

    if (rel.startsWith('.github/workflows/') && /\.ya?ml$/.test(rel)) { add({ kind: 'ci', file: rel, line: 1, scope: path.basename(rel) }); continue; }
    if (/(^|\/)package\.json$/.test(rel) && !rel.includes('/node_modules/')) {
      if (rel === 'package.json' || rel.split('/').length <= 3) add({ kind: 'manifest', file: rel, line: 1, scope: 'dependencies' });
      continue;
    }
    if (/^(capacitor\.config\.(json|ts|js)|src-tauri\/tauri\.conf\.json|electron-builder\.(json|ya?ml))$/.test(rel) || /^src-tauri\/src\/.+\.rs$/.test(rel)) {
      add({ kind: 'native-shell', file: rel, line: 1, scope: 'shell' });
      continue;
    }
    if (rel === 'vercel.json') {
      const v = sizeOk(path.join(root, rawRel), 1024 * 1024) ? (readJsonSafe(path.join(root, rawRel)) || {}) : {};
      for (const c of v.crons || []) if (c?.path) add({ kind: 'cron-route', file: rel, line: 1, scope: String(c.path).slice(0, 200) });
      continue;
    }
    if (ext === '.sql') {
      const text = sizeOk(path.join(root, rawRel), MAX_BYTES * 2) ? readTextSafe(path.join(root, rawRel)) : null;
      if (text) surfaces.push(...sqlSurfaces(rel, text, functions));
      continue;
    }
    if (ext === '.html' && rel.split('/').length <= 2) {
      const text = sizeOk(path.join(root, rawRel), MAX_BYTES) ? (readTextSafe(path.join(root, rawRel)) || '') : '';
      if (/<script\b/i.test(text)) add({ kind: 'static-html', file: rel, line: lineOf(text, /<script\b/i) || 1, scope: 'inline-script' });
      continue;
    }
    if (!CODE_EXT.has(ext)) continue;
    let stat;
    try { stat = fs.statSync(path.join(root, rawRel)); } catch { continue; }
    if (stat.size > MAX_BYTES) continue;
    const text = readTextSafe(path.join(root, rawRel));
    if (!text) continue;
    // 묶어 낸(minified) 외부 라이브러리는 앱이 쓴 코드가 아니다.
    if (text.length > 20000 && text.split('\n').length < text.length / 400) continue;
    const server = isServerFile(rel, text);
    const seen = new Set();
    for (const rule of RULES) {
      if (seen.has(rule.kind)) continue;
      if (rule.serverOnly && !server) continue;
      let line = 0;
      if (rule.path) {
        if (!rule.path.test(rel)) continue;
        line = 1;
        // 경로 이름만으로 잡는 규칙은 서버 경로·화면 진입 파일에 한정한다(버튼 같은 부품 파일은 제외).
        if (rule.codeOnly && (!ENTRY_FILE.test(rel) || !/\bexport\b|\bfunction\b/.test(text))) continue;
      } else if (rule.text) {
        // RULES 정규식은 g 플래그가 없어 exec 가 상태를 남기지 않는다.
        line = lineOf(text, rule.text);
        if (!line) continue;
      }
      seen.add(rule.kind);
      let scope = rule.kind;
      if (rule.kind === 'api-route') {
        const methods = [...text.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g)].map(m => m[1]);
        scope = methods.length ? [...new Set(methods)].join(',') : 'handler';
      }
      add({ kind: rule.kind, file: rel, line, scope });
    }
  }

  // 마이그레이션 순서상 마지막 정의가 SECURITY DEFINER 인 함수만 표면으로 센다.
  for (const [name, f] of [...functions.entries()].sort()) {
    if (f.definer) surfaces.push({ kind: 'db-function', file: f.file, line: f.line, scope: name });
  }

  // 같은 파일의 같은 종류는 하나로. 정렬해 결과를 결정적으로 만든다.
  const uniq = new Map();
  for (const s of surfaces) {
    const key = `${s.kind}|${s.file}|${s.scope}`;
    if (!uniq.has(key)) uniq.set(key, { ...s, subsystem: subsystemOf(s.file) });
  }
  let list = [...uniq.values()].sort((a, b) => (a.kind + a.file + a.scope).localeCompare(b.kind + b.file + b.scope));

  const inScope = s => !scope.length || scope.some(p => s.file === p || s.file.startsWith(p.replace(/\/?$/, '/')));
  const outScoped = list.filter(s => !inScope(s));
  list = list.filter(inScope);

  const kinds = {};
  for (const s of list) kinds[s.kind] = (kinds[s.kind] || 0) + 1;
  return {
    root_name: path.basename(root),
    file_count: files.length,
    surfaces: list,
    kinds,
    scoped_out: outScoped,
    operator_or_test_files: Object.fromEntries([...outOfScope.entries()].sort()),
    native_code: nativeCode,
    invisible_paths: invisible.slice(0, 200),
    invisible_path_count: invisible.length,
  };
}

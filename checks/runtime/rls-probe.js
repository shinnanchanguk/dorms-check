// 능동 RLS 프로브 (할루시네이션 방지 핵심).
// 배포된 앱의 클라 번들에서 공개 SUPABASE_URL + anon 키(원래 공개값)를 추출해,
// Supabase REST 에 '미인증 SELECT'를 실제로 보내 익명 사용자가 어떤 행을 읽을 수 있는지 프로그램이 실측한다.
// 판정은 모델이 아니라 관측된 응답. 비파괴: SELECT(limit) 만, 쓰기 프로브 없음.
import { request, normalizeUrl } from '../../core/http.js';

const SUPABASE_URL_RE = /https:\/\/([a-z0-9]{15,30})\.supabase\.co/gi;
const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

// 개인정보로 보이는 컬럼명(한/영) — 익명이 읽으면 위험 판정 근거.
const PII_COL_RE = /email|phone|tel|mobile|passwo?rd|passwd|secret|token|birth|ssn|resident|social|address|name|user_?id|uid|account|card|기이메일|전화|휴대폰|비밀번호|주민|생년|주소|이름|계좌|카드/i;

// 루트 스키마가 잠겼을 때 직접 찔러볼 흔한 테이블 이름(바이브코딩 앱 단골).
const COMMON_TABLES = [
  'users', 'user', 'profiles', 'profile', 'accounts', 'members', 'students', 'teachers',
  'posts', 'post', 'comments', 'messages', 'chats', 'orders', 'payments', 'subscriptions',
  'todos', 'tasks', 'notes', 'feedback', 'contacts', 'submissions', 'responses', 'reviews',
  'files', 'uploads', 'documents', 'sessions', 'logs', 'events', 'notifications', 'settings',
];

function b64urlDecode(s) {
  try {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Buffer.from(s, 'base64').toString('utf8');
  } catch { return ''; }
}
function jwtRole(jwt) {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try { return JSON.parse(b64urlDecode(parts[1])); } catch { return null; }
}

async function fetchScripts(url, req) {
  const main = await req(url, { method: 'GET', redirect: 'follow' });
  const body = main.body || '';
  const srcs = [];
  const re = /<script\b[^>]*src=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(body)) && srcs.length < 20) srcs.push(m[1]);
  const base = new URL(main.finalUrl || url);
  const abs = srcs.map(s => { try { return new URL(s, base).href; } catch { return null; } }).filter(Boolean);
  return { body, scripts: abs };
}

// 앱에서 공개 Supabase 자격을 추출(원래 클라에 공개된 값).
export async function extractSupabase(url, req) {
  const { body, scripts } = await fetchScripts(url, req);
  const texts = [body];
  for (const s of scripts.slice(0, 12)) {
    const r = await req(s, { method: 'GET', redirect: 'follow', maxBody: 4 * 1024 * 1024 });
    if (r.ok && r.body) texts.push(r.body);
  }
  const joined = texts.join('\n');
  const urls = [...new Set((joined.match(SUPABASE_URL_RE) || []).map(u => u.toLowerCase()))];
  const jwts = [...new Set(joined.match(JWT_RE) || [])];
  let anonKey = null;
  for (const j of jwts) {
    const role = jwtRole(j);
    if (role && (role.role === 'anon' || role.role === 'authenticated')) { anonKey = j; if (role.role === 'anon') break; }
  }
  return { supabaseUrl: urls[0] || null, anonKey, foundUrls: urls, foundJwts: jwts.length };
}

async function listTables(supabaseUrl, anonKey, req) {
  const r = await req(`${supabaseUrl}/rest/v1/`, {
    method: 'GET',
    headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}` },
    redirect: 'manual',
  });
  if (!r.ok || r.status !== 200) return { tables: [], swaggerStatus: r.status };
  let spec;
  try { spec = JSON.parse(r.body); } catch { return { tables: [], swaggerStatus: r.status }; }
  const tables = spec && spec.definitions ? Object.keys(spec.definitions) : (spec && spec.paths ? Object.keys(spec.paths).filter(p => p !== '/').map(p => p.replace(/^\//, '')) : []);
  return { tables, swaggerStatus: r.status };
}

async function probeTable(supabaseUrl, anonKey, table, req) {
  const r = await req(`${supabaseUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, {
    method: 'GET',
    headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}` },
    redirect: 'manual',
    maxBody: 256 * 1024,
  });
  let rows = null;
  try { rows = JSON.parse(r.body); } catch { /* not json */ }
  const readable = r.status === 200 && Array.isArray(rows);
  const sampleKeys = readable && rows[0] && typeof rows[0] === 'object' ? Object.keys(rows[0]) : [];
  return { table, status: r.status, readable, rowCount: Array.isArray(rows) ? rows.length : 0, sampleKeys };
}

// 메인: url 을 받아 RLS 실측 결과 반환.
export async function rlsProbe(rawUrl, opts = {}) {
  const url = normalizeUrl(rawUrl);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const req = (u, o = {}) => request(u, { ...o, fetchImpl });

  const creds = await extractSupabase(url, req);
  if (!creds.supabaseUrl || !creds.anonKey) {
    return [{
      id: 'code.rls.anon-read',
      status: 'na',
      observed: 'Supabase 공개 자격을 앱에서 찾지 못함(비-Supabase 앱이거나 자격 비노출) — RLS 실측 생략',
      evidence: { supabaseUrl: creds.supabaseUrl, foundJwts: creds.foundJwts },
    }];
  }

  let { tables, swaggerStatus } = await listTables(creds.supabaseUrl, creds.anonKey, req);
  // 루트 스키마가 잠겨(401) 테이블을 못 나열해도, 개별 테이블은 열려 있을 수 있다 → 흔한 이름 폴백 프로브.
  let usedFallback = false;
  if (!tables.length) {
    usedFallback = true;
    tables = COMMON_TABLES;
  }
  const readableTables = [];
  const piiLeaks = [];
  // 과도한 요청 방지: 상위 40개 테이블까지만
  for (const t of tables.slice(0, 40)) {
    const p = await probeTable(creds.supabaseUrl, creds.anonKey, t, req);
    if (p.readable && p.rowCount > 0) {
      readableTables.push({ table: t, sampleKeys: p.sampleKeys });
      if (p.sampleKeys.some(k => PII_COL_RE.test(k))) {
        piiLeaks.push({ table: t, piiColumns: p.sampleKeys.filter(k => PII_COL_RE.test(k)) });
      }
    }
  }

  let status, observed;
  if (piiLeaks.length) {
    status = 'fail';
    observed = `익명 사용자가 개인정보로 보이는 컬럼을 읽을 수 있는 테이블: ${piiLeaks.map(l => `${l.table}(${l.piiColumns.join(',')})`).join(' / ')}`;
  } else if (readableTables.length) {
    status = 'info';
    observed = `익명이 읽을 수 있는 테이블 있음(개인정보 컬럼은 미검출): ${readableTables.map(t => t.table).join(', ')} — 공개 의도면 괜찮고, 아니면 RLS 필요`;
  } else if (tables.length === 0 && swaggerStatus !== 200) {
    status = 'pass';
    observed = 'REST 스키마가 익명에 노출되지 않음(양호)';
  } else {
    status = 'pass';
    observed = '익명 SELECT로 행이 새는 테이블 없음(RLS 양호)';
  }

  return [{
    id: 'code.rls.anon-read',
    status,
    observed,
    evidence: {
      supabaseUrl: creds.supabaseUrl,
      swaggerStatus,
      tablesTested: Math.min(tables.length, 40),
      usedCommonTableFallback: usedFallback,
      readableTables: readableTables.map(t => t.table),
      piiLeaks,
      method: '익명 anon 키로 /rest/v1 SELECT limit 1 (비파괴)',
    },
  }];
}

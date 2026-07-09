// 능동 Firebase Realtime Database 공개 읽기 프로브.
// 배포된 앱의 클라 번들에서 Firebase RTDB URL(databaseURL, firebaseio.com / firebasedatabase.app)을 추출해,
// 미인증으로 `/.json?shallow=true`(키만, 값 미조회 = 비파괴)를 실제로 요청해 익명 읽기가 열려 있는지 프로그램이 실측한다.
// Supabase 만이 아니라 Firebase 를 쓰는 앱도 '로그인 없이 남의 데이터 접근'을 자동으로 잡기 위함.
// 판정은 모델이 아니라 관측된 응답. (Firestore 는 REST 로 규칙을 확인하기 어려워 이 프로브 대상이 아니며 코드/자기점검으로 다룬다.)
import { request, normalizeUrl } from '../../core/http.js';

// RTDB 호스트: <name>.firebaseio.com, <name>-default-rtdb.firebaseio.com, <name>-default-rtdb.<region>.firebasedatabase.app
const FIREBASE_DB_RE = /https:\/\/[a-z0-9.-]+\.(?:firebaseio\.com|firebasedatabase\.app)/gi;

async function fetchBundle(url, req) {
  const main = await req(url, { method: 'GET', redirect: 'follow' });
  const body = main.body || '';
  const srcs = [];
  const re = /<script\b[^>]*src=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(body)) && srcs.length < 20) srcs.push(m[1]);
  const base = new URL(main.finalUrl || url);
  const texts = [body];
  for (const s of srcs.slice(0, 12)) {
    const abs = (() => { try { return new URL(s, base).href; } catch { return null; } })();
    if (!abs) continue;
    const r = await req(abs, { method: 'GET', redirect: 'follow', maxBody: 4 * 1024 * 1024 });
    if (r.ok && r.body) texts.push(r.body);
  }
  return texts.join('\n');
}

export async function firebaseProbe(rawUrl, opts = {}) {
  const url = normalizeUrl(rawUrl);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const req = (u, o = {}) => request(u, { ...o, fetchImpl });

  const joined = await fetchBundle(url, req);
  const dbUrls = [...new Set((joined.match(FIREBASE_DB_RE) || []).map((u) => u.replace(/\/$/, '')))].slice(0, 4);
  if (!dbUrls.length) {
    return [{ id: 'code.firebase.public-read', status: 'na', observed: 'Firebase 실시간 DB 주소를 앱에서 찾지 못함(비-Firebase 앱이거나 미사용) — 프로브 생략', evidence: {} }];
  }

  const publicDbs = [];
  const emptyOpen = [];
  const locked = [];
  for (const db of dbUrls) {
    // shallow=true 는 값이 아닌 최상위 '키'만 반환한다(비파괴 최소 조회).
    const r = await req(`${db}/.json?shallow=true`, { method: 'GET', redirect: 'follow', maxBody: 256 * 1024 });
    let parsed = null;
    try { parsed = JSON.parse(r.body); } catch { /* not json */ }
    const denied = r.status === 401 || r.status === 403 || (parsed && typeof parsed === 'object' && typeof parsed.error === 'string' && /permission/i.test(parsed.error));
    if (denied) { locked.push(db); continue; }
    if (r.status === 200 && parsed && typeof parsed === 'object' && Object.keys(parsed).length > 0) {
      publicDbs.push({ db, keys: Object.keys(parsed).slice(0, 8) });
    } else if (r.status === 200) {
      emptyOpen.push(db);
    } else {
      locked.push(db); // 그 외 응답은 접근 불가로 간주(보수적)
    }
  }

  let status, observed;
  if (publicDbs.length) {
    status = 'fail';
    observed = `로그인 없이 읽히는 Firebase 실시간 DB가 있어요: ${publicDbs.map((p) => `${p.db} (최상위 키: ${p.keys.join(', ')})`).join(' / ')} — 보안 규칙으로 익명 읽기를 막아야 해요.`;
  } else if (emptyOpen.length) {
    status = 'info';
    observed = `익명 읽기가 허용돼 있으나 데이터는 비어 있어요: ${emptyOpen.join(', ')} — 규칙을 확인해 두세요.`;
  } else {
    status = 'pass';
    observed = `Firebase 실시간 DB가 익명 읽기를 막고 있어요(양호): ${locked.join(', ')}`;
  }
  return [{ id: 'code.firebase.public-read', status, observed, evidence: { dbUrls, publicDbs, emptyOpen, locked } }];
}

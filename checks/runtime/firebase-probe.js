// 능동 Firebase Realtime Database 공개 읽기 프로브.
// 배포된 앱의 클라 번들에서 Firebase RTDB URL(databaseURL, firebaseio.com / firebasedatabase.app)을 추출해,
// 미인증으로 `/.json?shallow=true`(키만, 값 미조회 = 비파괴)를 실제로 요청해 익명 읽기가 열려 있는지 프로그램이 실측한다.
// Supabase 만이 아니라 Firebase 를 쓰는 앱도 '로그인 없이 남의 데이터 접근'을 자동으로 잡기 위함.
// 판정은 모델이 아니라 관측된 응답. (Firestore 는 REST 로 규칙을 확인하기 어려워 이 프로브 대상이 아니며 코드/자기점검으로 다룬다.)
import { normalizeUrl } from '../../core/http.js';
import { createScanRequest } from '../request.js';

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
  const req = createScanRequest(opts);

  const joined = await fetchBundle(url, req);
  const dbUrls = [...new Set((joined.match(FIREBASE_DB_RE) || []).map((u) => u.replace(/\/$/, '')))].slice(0, 4);
  if (!dbUrls.length) {
    return [{ id: 'code.firebase.public-read', status: 'unknown', observed: '공개 응답에서 Firebase 실시간 DB 주소를 찾지 못했습니다. 내부 접근 권한은 확인하지 않았습니다.', evidence: { providerDetected: false } }];
  }

  const publicDbs = [];
  const emptyOpen = [];
  const locked = [];
  const unverified = [];
  for (const db of dbUrls) {
    // shallow=true 는 값이 아닌 최상위 '키'만 반환한다(비파괴 최소 조회).
    const r = await req(`${db}/.json?shallow=true`, { method: 'GET', redirect: 'follow', maxBody: 256 * 1024 });
    let parsed = null;
    try { parsed = JSON.parse(r.body); } catch { /* not json */ }
    const denied = r.status === 401 || r.status === 403 || (parsed && typeof parsed === 'object' && typeof parsed.error === 'string' && /permission/i.test(parsed.error));
    if (denied) { locked.push(db); continue; }
    if (r.status === 200 && parsed && typeof parsed === 'object' && Object.keys(parsed).length > 0) {
      publicDbs.push({ db, keyCount: Object.keys(parsed).length });
    } else if (r.status === 200 && r.body.trim() === 'null') {
      emptyOpen.push(db);
    } else {
      unverified.push(db);
    }
  }

  let status, observed;
  if (publicDbs.length) {
    status = 'info';
    observed = 'Firebase에 공개로 읽히는 경로가 있습니다. 값과 공개 의도를 확인하지 않아 위험으로 판정하지 않았습니다.';
  } else if (emptyOpen.length) {
    status = 'info';
    observed = `익명 읽기가 허용돼 있으나 데이터는 비어 있어요: ${emptyOpen.join(', ')} — 규칙을 확인해 두세요.`;
  } else if (unverified.length || !locked.length) {
    status = 'unknown';
    observed = 'Firebase 응답을 확인하지 못해 내부 접근 권한을 판단할 수 없습니다.';
  } else {
    status = 'pass';
    observed = '점검한 Firebase 경로가 인증 없는 요청을 거부했습니다.';
  }
  return [{ id: 'code.firebase.public-read', status, observed, evidence: { dbUrls, publicDbs, emptyOpen, locked, unverified } }];
}

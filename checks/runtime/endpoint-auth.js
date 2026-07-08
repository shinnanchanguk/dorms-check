// 능동 엔드포인트 인증 프로브 (보조 신호, advisory).
// 앱 번들에서 참조되는 내부 API 경로(/api/...)를 수집해 '미인증'으로 실제 호출,
// 200 + JSON 데이터가 돌아오면 인증 게이트가 없을 가능성으로 표시한다.
// 공개 엔드포인트도 200 을 주므로 결정적 마크 게이트가 아니라 '검토 후보'로만 낸다.
import { request, normalizeUrl } from '../../core/http.js';

const API_PATH_RE = /["'`](\/api\/[a-z0-9_\-/]{2,60})["'`]/gi;

async function collectApiPaths(url, req) {
  const main = await req(url, { method: 'GET', redirect: 'follow' });
  const texts = [main.body || ''];
  const srcs = [];
  const re = /<script\b[^>]*src=["']([^"']+)["']/gi;
  let m;
  const base = new URL(main.finalUrl || url);
  while ((m = re.exec(main.body || '')) && srcs.length < 12) {
    try { srcs.push(new URL(m[1], base).href); } catch { /* ignore */ }
  }
  for (const s of srcs) {
    const r = await req(s, { method: 'GET', maxBody: 3 * 1024 * 1024 });
    if (r.ok && r.body) texts.push(r.body);
  }
  const paths = new Set();
  const joined = texts.join('\n');
  let mm;
  while ((mm = API_PATH_RE.exec(joined)) && paths.size < 30) {
    // 동적 세그먼트([id] 등)나 확장자 없는 순수 경로만
    if (!/\$\{|\[/.test(mm[1])) paths.add(mm[1]);
  }
  return { base, paths: [...paths] };
}

export async function endpointAuthProbe(rawUrl, opts = {}) {
  const url = normalizeUrl(rawUrl);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const req = (u, o = {}) => request(u, { ...o, fetchImpl });

  const { base, paths } = await collectApiPaths(url, req);
  if (!paths.length) {
    return [{ id: 'code.endpoint.unauth', status: 'na', observed: '앱에서 내부 API 경로를 찾지 못함 — 미인증 호출 프로브 생략', evidence: {} }];
  }
  const openCandidates = [];
  for (const p of paths.slice(0, 20)) {
    const r = await req(new URL(p, base).href, { method: 'GET', redirect: 'manual', maxBody: 128 * 1024 });
    // 200 + JSON 배열/객체(데이터로 보이는) 이면 후보
    if (r.status === 200 && /application\/json/i.test(r.headers['content-type'] || '')) {
      let parsed;
      try { parsed = JSON.parse(r.body); } catch { /* ignore */ }
      const hasData = Array.isArray(parsed) ? parsed.length > 0 : (parsed && typeof parsed === 'object' && Object.keys(parsed).length > 0);
      if (hasData) openCandidates.push(p);
    }
  }
  return [{
    id: 'code.endpoint.unauth',
    status: openCandidates.length ? 'info' : 'pass',
    observed: openCandidates.length
      ? `미인증 GET에 JSON 데이터를 반환하는 API 후보(검토 필요, 공개 API면 정상): ${openCandidates.join(', ')}`
      : '미인증 호출로 데이터를 반환하는 API 후보 없음',
    evidence: { tested: paths.slice(0, 20), openCandidates },
  }];
}

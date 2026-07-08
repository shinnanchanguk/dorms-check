// 안전한 fetch 래퍼 (Node 18+ 내장 fetch). 의존성 0.
// 서버(도름스)가 import할 때는 SSRF 방어를 적용한 fetch 구현을 opts.fetchImpl로 주입한다.
// (CLI는 교사 자기 앱만 스캔하므로 기본 전역 fetch.)

const DEFAULT_TIMEOUT = 15000;
const MAX_BODY = 2 * 1024 * 1024; // 2MB 상한 (거대 응답으로 인한 메모리·egress 폭주 방지)

function headersToObject(h) {
  const o = {};
  try { for (const [k, v] of h.entries()) o[k.toLowerCase()] = v; } catch { /* ignore */ }
  return o;
}

// URL 정규화: 스킴 없으면 https 부여, 선두 대시 거부(플래그 인젝션 방지).
export function normalizeUrl(input) {
  if (typeof input !== 'string') throw new Error('url must be string');
  const u = input.trim();
  if (u.startsWith('-')) throw new Error('invalid url (leading dash)');
  if (/^https?:\/\//i.test(u)) return u;
  return 'https://' + u;
}

// 단일 요청. 리다이렉트는 수동 추적(체인 관측 + 서버 SSRF 재검증 훅 자리).
export async function request(url, {
  method = 'GET',
  headers = {},
  timeout = DEFAULT_TIMEOUT,
  redirect = 'follow',
  fetchImpl = globalThis.fetch,
  captureBody = true,
  maxBody = MAX_BODY,
} = {}) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeout);
  const started = Date.now();
  try {
    const res = await fetchImpl(url, {
      method,
      headers,
      redirect,
      signal: ac.signal,
    });
    const hdrs = headersToObject(res.headers);
    let body = '';
    if (captureBody && method !== 'HEAD') {
      const reader = res.body?.getReader?.();
      if (reader) {
        let total = 0;
        const dec = new TextDecoder();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          if (total <= maxBody) body += dec.decode(value, { stream: true });
          if (total > maxBody) { try { await reader.cancel(); } catch { /* ignore */ } break; }
        }
      } else {
        try { body = (await res.text()).slice(0, maxBody); } catch { body = ''; }
      }
    }
    return {
      ok: true,
      status: res.status,
      headers: hdrs,
      redirected: res.redirected,
      finalUrl: res.url || url,
      body,
      ms: Date.now() - started,
    };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      headers: {},
      redirected: false,
      finalUrl: url,
      body: '',
      error: String(e && e.message ? e.message : e),
      aborted: ac.signal.aborted,
      ms: Date.now() - started,
    };
  } finally {
    clearTimeout(t);
  }
}

// 경로 존재/노출 프로빙. opts.req 로 바인딩된 request(주입 fetchImpl 포함)를 넘길 수 있다.
// (서버는 SSRF 방어 fetch 를 주입하므로 반드시 req 를 통해야 한다.)
export async function probePath(baseUrl, p, opts = {}) {
  const url = baseUrl.replace(/\/$/, '') + p;
  const req = opts.req || request;
  const r = await req(url, { method: 'GET', redirect: 'manual', captureBody: true, maxBody: 64 * 1024 });
  return { path: p, url, status: r.status, headers: r.headers, body: r.body, error: r.error };
}

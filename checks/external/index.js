// 외부 표면 스캔 오케스트레이터 — CLI와 도름스 서버가 공유하는 단일 엔진.
// 순수 fetch/tls. 판정(pass/fail/na/info)만 내고 심각도·설명은 카탈로그가 SSOT.
import { request, normalizeUrl } from '../../core/http.js';
import { checkHeaders } from './headers.js';
import { checkExposure } from './exposure.js';
import { checkTls } from './tls.js';
import { checkCors } from './cors.js';
import { checkSeoPerf } from './seo-perf.js';
import { checkLegalPages } from './legal-pages.js';
import { checkFingerprint } from './fingerprint.js';

export function validateFinalOrigin(expectedUrl, finalUrl) {
  try {
    const expectedOrigin = new URL(normalizeUrl(expectedUrl)).origin;
    const finalOrigin = new URL(normalizeUrl(finalUrl)).origin;
    return expectedOrigin === finalOrigin
      ? { ok: true, expectedOrigin, finalOrigin }
      : { ok: false, expectedOrigin, finalOrigin, reason: `최종 응답 origin(${finalOrigin})이 검사한 Vercel 배포 origin(${expectedOrigin})과 다릅니다.` };
  } catch {
    return { ok: false, expectedOrigin: '', finalOrigin: '', reason: '최종 응답 URL의 origin을 확인하지 못했습니다.' };
  }
}

// url 을 스캔해 { items, bonus, raw } 반환.
// opts.fetchImpl: 서버가 SSRF 방어 fetch 를 주입(기본 전역 fetch).
export async function runExternalScan(rawUrl, opts = {}) {
  const url = normalizeUrl(rawUrl);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const req = (u, o = {}) => request(u, { ...o, fetchImpl });

  const mainRes = await req(url, { method: 'GET', redirect: 'follow', timeout: opts.timeout || 15000 });
  if (!mainRes.ok) {
    return {
      reachable: false,
      error: mainRes.error || 'unreachable',
      items: [{ id: 'meta.reachable', status: 'fail', observed: `URL 접속 실패: ${mainRes.error || '알 수 없음'}`, evidence: {} }],
      bonus: [],
      raw: { url, mainStatus: mainRes.status, error: mainRes.error },
    };
  }

  const binding = opts.expectedOrigin
    ? validateFinalOrigin(opts.expectedOrigin, mainRes.finalUrl || url)
    : null;
  if (binding && !binding.ok) {
    return {
      reachable: false,
      binding,
      error: binding.reason,
      items: [],
      bonus: [],
      raw: { url, finalUrl: mainRes.finalUrl, mainStatus: mainRes.status, binding },
    };
  }

  const items = [];
  const hdr = checkHeaders(mainRes);
  items.push(...hdr.results);
  items.push(...checkFingerprint(mainRes));
  items.push(...(await checkTls(mainRes, url, { requestImpl: req })));
  items.push(...(await checkExposure(mainRes, url, req)));
  items.push(...(await checkCors(url, req)));
  items.push(...checkSeoPerf(mainRes));
  items.push(...(await checkLegalPages(mainRes, url, req)));

  return {
    reachable: true,
    binding,
    items,
    bonus: hdr.bonus,
    raw: {
      url,
      finalUrl: mainRes.finalUrl,
      httpStatus: mainRes.status,
      ttfbMs: mainRes.ms,
      observedHeaders: Object.keys(mainRes.headers),
      scannedAt: new Date().toISOString(),
    },
  };
}

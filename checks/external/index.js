// CLI and server share public-page observations and one bounded probe budget.
import { normalizeUrl } from '../../core/http.js';
import { normalizeSecurityItems } from '../../core/minimum-policy.js';
import { createScanRequest } from '../request.js';
import { checkHeaders } from './headers.js';
import { checkExposure } from './exposure.js';
import { checkTls } from './tls.js';
import { checkCors } from './cors.js';
import { checkSeoPerf } from './seo-perf.js';
import { checkLegalPages } from './legal-pages.js';
import { checkFingerprint } from './fingerprint.js';

export async function runExternalScan(rawUrl, opts = {}) {
  const url = normalizeUrl(rawUrl);
  const req = createScanRequest(opts);
  const mainRes = await req(url, { method: 'GET', redirect: 'follow', timeout: 15000 });
  const finalUrl = mainRes.finalUrl || url;
  let https = false;
  try { https = new URL(finalUrl).protocol === 'https:'; } catch { /* Not an observed HTTPS response. */ }
  const reachable = mainRes.ok && mainRes.bodyRead === true && mainRes.status >= 200 && mainRes.status < 300;
  const publicSurface = {
    httpStatus: mainRes.status, finalUrl,
    transportChecked: Boolean(mainRes.ok), bodyChecked: false,
    unsafeTransport: Boolean(reachable && !https),
  };
  const surfaceItem = {
    id: 'meta.public-surface', status: reachable ? (https ? 'pass' : 'fail') : 'unknown',
    observed: reachable ? (https ? '공개 HTTPS 응답과 받은 본문을 확인했습니다.' : '공개 응답이 암호화되지 않은 HTTP 주소로 연결됩니다.') : '공개 화면을 확인하지 못했습니다.',
    evidence: publicSurface,
  };
  const raw = { url, finalUrl, httpStatus: mainRes.status, publicSurface, scannedAt: new Date().toISOString() };
  if (!reachable) {
    const invalidCertificate = /^(?:CERT_|ERR_TLS_CERT_|DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_VERIFY_LEAF_SIGNATURE|UNABLE_TO_GET_ISSUER_CERT_LOCALLY)/.test(mainRes.errorCode || '');
    const items = [surfaceItem];
    if (invalidCertificate) items.push({ id: 'sec.transport.ssl-valid', status: 'fail', observed: '공개 HTTPS 연결에서 인증서 오류를 확인했습니다.', evidence: { tlsInvalid: true, errorCode: mainRes.errorCode } });
    return { reachable: false, error: mainRes.error || `HTTP ${mainRes.status}`, items, bonus: [], raw };
  }
  const hdr = checkHeaders(mainRes);
  const optional = await Promise.all([
    checkTls(mainRes, url, { requestImpl: req, negotiateImpl: opts.negotiateImpl }),
    checkExposure(mainRes, url, req), checkCors(url, req), checkLegalPages(mainRes, url, req),
  ].map((promise, index) => promise.catch(() => [{
    id: ['sec.transport.ssl-valid', 'info.secret-exposed', 'cors.policy', 'legal.privacy-policy'][index],
    status: 'unknown', observed: '추가 점검을 완료하지 못했습니다.', evidence: { probeError: true },
  }])));
  publicSurface.bodyChecked = mainRes.bodyRead === true && optional[1].some(item => item.id === 'info.secret-exposed' && item.evidence?.mainBodyChecked === true);
  publicSurface.bodyTruncated = mainRes.bodyTruncated === true;
  const items = normalizeSecurityItems([surfaceItem, ...hdr.results, ...checkFingerprint(mainRes), ...optional.flat(), ...checkSeoPerf(mainRes)]);
  return { reachable: true, items, bonus: [], raw: { ...raw, ttfbMs: mainRes.ms, observedHeaders: Object.keys(mainRes.headers) } };
}

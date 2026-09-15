// 전송 보안: HTTPS 강제(HTTP→HTTPS 리다이렉트), 인증서 유효, 구버전 TLS, 쿠키 플래그.
import { request } from '../../core/http.js';

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

export function validateHttpsRedirect(expectedUrl, status, location, finalUrl = '') {
  let expected;
  try { expected = new URL(expectedUrl); }
  catch { return { ok: false, reason: 'expected URL is malformed' }; }
  expected.protocol = 'https:';
  if (expected.port === '80') expected.port = '';
  const isRedirect = status >= 300 && status < 400;
  const candidates = isRedirect ? (location ? [location] : []) : (finalUrl ? [finalUrl] : []);
  for (const value of candidates) {
    try {
      const candidate = new URL(value, `http://${expected.host}/`);
      if (candidate.protocol === 'https:' && candidate.origin === expected.origin) {
        return { ok: true, url: candidate.toString(), origin: candidate.origin };
      }
    } catch { /* A malformed redirect is not an HTTPS enforcement result. */ }
  }
  return { ok: false, reason: 'redirect is not HTTPS on the exact expected deployment origin' };
}

export async function checkTls(mainRes, url, opts = {}) {
  const results = [];
  const isHttps = (mainRes.finalUrl || url).startsWith('https://');

  // Use the injected request path for HTTP probes too; never bypass server SSRF checks.
  const host = hostOf(url);
  let redirectStatus = 'unknown';
  let httpObserved = 'HTTP 응답을 확인하지 못했습니다.';
  let redirectsHttps = false;
  if (host) {
    const requestImpl = opts.requestImpl || request;
    const r = await requestImpl('http://' + host, { redirect: 'manual', captureBody: false, timeout: 8000 });
    const loc = r.headers?.location || '';
    redirectsHttps = validateHttpsRedirect(url, r.status, loc, r.finalUrl || '').ok;
    redirectStatus = !r.status || r.status >= 500 || r.status === 429 ? 'unknown' : (redirectsHttps ? 'pass' : 'info');
    httpObserved = r.status ? `HTTP ${r.status}${loc ? ' -> ' + loc : ''}` : httpObserved;
  }
  results.push({ id: 'sec.transport.https-redirect', status: redirectStatus, observed: httpObserved, evidence: { redirectsHttps } });

  // A completed HTTPS fetch already validated transport. Additional socket negotiation is opt-in.
  const cert = opts.negotiateImpl && host ? await opts.negotiateImpl(host)
    : { authorized: Boolean(isHttps && mainRes.ok), method: 'https-response', protocol: null };
  const tlsInvalid = Boolean(cert.protocol && cert.authorized === false && cert.authError && !cert.error);
  const certStatus = tlsInvalid ? 'fail' : (cert.error ? 'unknown' : (cert.authorized === true ? 'pass' : 'unknown'));
  results.push({
    id: 'sec.transport.ssl-valid', status: certStatus,
    observed: tlsInvalid ? 'TLS 연결에서 인증서 오류를 확인했습니다.' : (certStatus === 'pass' ? 'HTTPS 연결을 확인했습니다.' : '인증서 추가 정보를 확인하지 못했습니다.'),
    evidence: { ...cert, tlsInvalid },
  });
  const old = cert.protocol && /TLSv1(\.[01])?$/.test(cert.protocol);
  results.push({ id: 'sec.transport.old-tls', status: !cert.protocol ? 'unknown' : (old ? 'info' : 'pass'),
    observed: cert.protocol ? `협상된 TLS 버전: ${cert.protocol}` : 'TLS 세부 버전은 별도로 측정하지 않았습니다.', evidence: { protocol: cert.protocol } });

  // 쿠키 플래그(HttpOnly/Secure)
  const setCookie = mainRes.headers['set-cookie'];
  if (setCookie) {
    const low = String(setCookie).toLowerCase();
    const missingHttpOnly = !low.includes('httponly');
    const missingSecure = !low.includes('secure');
    results.push({
      id: 'sec.transport.cookie-flags',
      status: (missingHttpOnly || missingSecure) ? 'info' : 'pass',
      observed: (missingHttpOnly || missingSecure)
        ? `쿠키 플래그 누락${missingHttpOnly ? ' HttpOnly' : ''}${missingSecure ? ' Secure' : ''}`
        : '쿠키 HttpOnly/Secure 설정됨',
      evidence: { missingHttpOnly, missingSecure },
    });
  } else {
    results.push({ id: 'sec.transport.cookie-flags', status: 'na', observed: '응답에 쿠키 없음', evidence: {} });
  }

  return results;
}

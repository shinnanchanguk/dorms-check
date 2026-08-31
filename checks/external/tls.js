// 전송 보안: HTTPS 강제(HTTP→HTTPS 리다이렉트), 인증서 유효, 구버전 TLS, 쿠키 플래그.
import tls from 'node:tls';
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

// 협상된 TLS 프로토콜 버전·인증서 유효성 '관측'(구버전 TLS·인증서 경고 보고용). 실패해도 스캔은 계속.
// 주의: rejectUnauthorized:false 는 '나쁜 인증서를 신뢰'하려는 게 아니라, 잘못된 인증서에서도
// 연결을 끊지 않고 sock.authorized / authorizationError 를 읽어 '인증서 무효'를 결함으로 보고하기 위함이다.
// true 로 두면 무효 인증서에서 예외가 나 그 사실을 판정·보고할 수 없다(이 도구는 데이터를 주고받지 않고 관측만 한다).
export function negotiatedProtocol(host, port = 443, timeout = 8000) {
  return new Promise(resolve => {
    let done = false;
    const finish = v => { if (!done) { done = true; try { sock.destroy(); } catch { /* ignore */ } resolve(v); } };
    const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      const peer = sock.getPeerCertificate();
      finish({
        protocol: sock.getProtocol(),
        authorized: sock.authorized,
        authError: sock.authorizationError && String(sock.authorizationError),
        validFrom: peer?.valid_from || null,
        validTo: peer?.valid_to || null,
      });
    });
    sock.setTimeout(timeout, () => finish({ protocol: null, error: 'timeout' }));
    sock.on('error', e => finish({ protocol: null, error: String(e && e.message ? e.message : e) }));
  });
}

export async function checkTls(mainRes, url, opts = {}) {
  const results = [];
  const isHttps = (mainRes.finalUrl || url).startsWith('https://');

  // HTTP -> HTTPS 리다이렉트 실측
  const host = hostOf(url);
  let redirectsHttps = false, httpObserved = 'n/a';
  if (host) {
    const requestImpl = opts.requestImpl || request;
    const r = await requestImpl('http://' + host, { redirect: 'manual', captureBody: false, timeout: 12000 });
    const loc = r.headers['location'] || '';
    redirectsHttps = validateHttpsRedirect(url, r.status, loc, r.finalUrl || '').ok;
    httpObserved = `HTTP ${r.status}${loc ? ' -> ' + loc : ''}`;
  }
  results.push({
    id: 'sec.transport.https-redirect',
    status: redirectsHttps ? 'pass' : (isHttps ? 'fail' : 'fail'),
    observed: redirectsHttps ? `HTTP 요청이 HTTPS로 리다이렉트됨 (${httpObserved})` : `HTTP 요청이 HTTPS로 강제되지 않음 (${httpObserved})`,
    evidence: { httpProbe: httpObserved, redirectsHttps },
  });

  // 인증서 유효(협상 + authorized)
  let cert = { protocol: null };
  if (host) cert = await (opts.negotiateImpl || negotiatedProtocol)(host);
  results.push({
    id: 'sec.transport.ssl-valid',
    status: isHttps && cert.protocol && cert.authorized === true && !cert.error ? 'pass' : 'fail',
    observed: cert.protocol ? `TLS 연결 성공 (${cert.protocol}${cert.authorized === false ? ', 인증서 경고: ' + cert.authError : ''})` : `TLS 연결 실패: ${cert.error || '알 수 없음'}`,
    evidence: cert,
  });

  // 구버전 TLS 사용(TLSv1/1.1) 경고
  const old = cert.protocol && /TLSv1(\.[01])?$/.test(cert.protocol);
  results.push({
    id: 'sec.transport.old-tls',
    status: !cert.protocol ? 'pending' : (old ? 'fail' : 'pass'),
    observed: !cert.protocol ? `TLS 버전 측정 실패: ${cert.error || '알 수 없음'}` : (old ? `구버전 TLS 협상됨: ${cert.protocol}` : `TLS 버전 양호: ${cert.protocol}`),
    evidence: { protocol: cert.protocol },
  });

  // 쿠키 플래그(HttpOnly/Secure)
  const setCookie = mainRes.headers['set-cookie'];
  if (setCookie) {
    const low = String(setCookie).toLowerCase();
    const missingHttpOnly = !low.includes('httponly');
    const missingSecure = !low.includes('secure');
    results.push({
      id: 'sec.transport.cookie-flags',
      status: (missingHttpOnly || missingSecure) ? 'fail' : 'pass',
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

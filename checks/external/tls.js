// 전송 보안: HTTPS 강제(HTTP→HTTPS 리다이렉트), 인증서 유효, 구버전 TLS, 쿠키 플래그.
import tls from 'node:tls';
import { request } from '../../core/http.js';

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

// 협상된 TLS 프로토콜 버전·인증서 유효성 '관측'(구버전 TLS·인증서 경고 보고용). 실패해도 스캔은 계속.
// 주의: rejectUnauthorized:false 는 '나쁜 인증서를 신뢰'하려는 게 아니라, 잘못된 인증서에서도
// 연결을 끊지 않고 sock.authorized / authorizationError 를 읽어 '인증서 무효'를 결함으로 보고하기 위함이다.
// true 로 두면 무효 인증서에서 예외가 나 그 사실을 판정·보고할 수 없다(이 도구는 데이터를 주고받지 않고 관측만 한다).
function negotiatedProtocol(host, port = 443, timeout = 8000) {
  return new Promise(resolve => {
    let done = false;
    const finish = v => { if (!done) { done = true; try { sock.destroy(); } catch { /* ignore */ } resolve(v); } };
    const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      finish({ protocol: sock.getProtocol(), authorized: sock.authorized, authError: sock.authorizationError && String(sock.authorizationError) });
    });
    sock.setTimeout(timeout, () => finish({ protocol: null, error: 'timeout' }));
    sock.on('error', e => finish({ protocol: null, error: String(e && e.message ? e.message : e) }));
  });
}

export async function checkTls(mainRes, url) {
  const results = [];
  const isHttps = (mainRes.finalUrl || url).startsWith('https://');

  // HTTP -> HTTPS 리다이렉트 실측
  const host = hostOf(url);
  let redirectsHttps = false, httpObserved = 'n/a';
  if (host) {
    const r = await request('http://' + host, { redirect: 'manual', captureBody: false, timeout: 12000 });
    const loc = r.headers['location'] || '';
    redirectsHttps = (r.status >= 300 && r.status < 400 && /^https:\/\//i.test(loc)) || (r.finalUrl || '').startsWith('https://');
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
  if (host) cert = await negotiatedProtocol(host);
  results.push({
    id: 'sec.transport.ssl-valid',
    status: cert.protocol && cert.authorized !== false && !cert.error ? 'pass' : (isHttps && !cert.error ? 'pass' : 'fail'),
    observed: cert.protocol ? `TLS 연결 성공 (${cert.protocol}${cert.authorized === false ? ', 인증서 경고: ' + cert.authError : ''})` : `TLS 연결 실패: ${cert.error || '알 수 없음'}`,
    evidence: cert,
  });

  // 구버전 TLS 사용(TLSv1/1.1) 경고
  const old = cert.protocol && /TLSv1(\.[01])?$/.test(cert.protocol);
  results.push({
    id: 'sec.transport.old-tls',
    status: old ? 'fail' : 'pass',
    observed: old ? `구버전 TLS 협상됨: ${cert.protocol}` : `TLS 버전 양호: ${cert.protocol || '(측정 실패)'}`,
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

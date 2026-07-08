// CORS 설정 실측: 위조된 Origin 헤더로 GET 요청 → 응답의 CORS 헤더 반응 관측.
// 4종: wildcard(*), wildcard+credentials, origin reflect, reflect+credentials.
// 비파괴: GET만, 실제 데이터 변경 없음.
import { request } from '../../core/http.js';

const EVIL_ORIGIN = 'https://dorms-check-probe.example';

export async function checkCors(url, requestImpl = request) {
  const r = await requestImpl(url, {
    method: 'GET',
    headers: { Origin: EVIL_ORIGIN },
    redirect: 'manual',
    captureBody: false,
    timeout: 12000,
  });
  const acao = (r.headers['access-control-allow-origin'] || '').trim();
  const acac = (r.headers['access-control-allow-credentials'] || '').trim().toLowerCase();

  const wildcard = acao === '*';
  const reflects = acao && acao === EVIL_ORIGIN;
  const withCreds = acac === 'true';

  let status = 'pass';
  let observed = 'CORS가 임의 Origin을 허용하지 않음(양호)';
  if (reflects && withCreds) { status = 'fail'; observed = '임의 Origin 반사 + credentials 허용(가장 위험)'; }
  else if (reflects) { status = 'fail'; observed = '임의 Origin 반사 허용'; }
  else if (wildcard && withCreds) { status = 'fail'; observed = '와일드카드(*) + credentials 허용'; }
  else if (wildcard) { status = 'info'; observed = '와일드카드(*) 허용 — 공개 API면 무방, 인증 API면 위험'; }

  return [{
    id: 'cors.policy',
    status,
    observed,
    evidence: { allowOrigin: acao || null, allowCredentials: withCreds, reflectsOrigin: reflects, wildcard },
  }];
}

// 핑거프린트: 서버·프레임워크 버전 노출(x-powered-by, Server), 알려진 취약 버전 힌트.
export function checkFingerprint(mainRes) {
  const h = mainRes.headers || {};
  const results = [];
  const poweredBy = h['x-powered-by'] || '';
  const server = h['server'] || '';
  results.push({
    id: 'sec.fingerprint.powered-by',
    status: poweredBy ? 'info' : 'pass',
    observed: poweredBy ? `x-powered-by 노출: ${poweredBy}` : 'x-powered-by 미노출(양호)',
    evidence: { poweredBy: poweredBy || null, server: server || null },
  });
  return results;
}

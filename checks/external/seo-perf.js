// SEO 위생 + 성능(응답 시간·페이지 크기·압축). 마크 게이트는 아니고 점수·권고용(recommended).
export function checkSeoPerf(mainRes) {
  const results = [];
  const body = mainRes.body || '';
  const h = mainRes.headers || {};
  const head = body.slice(0, 60000);

  const has = re => re.test(head);
  results.push({ id: 'seo.title', status: has(/<title[\s>]/i) ? 'pass' : 'fail', observed: has(/<title[\s>]/i) ? '<title> 있음' : '<title> 없음', evidence: {} });
  results.push({ id: 'seo.description', status: /<meta[^>]+name=["']description["']/i.test(head) ? 'pass' : 'fail', observed: '설명 메타', evidence: {} });
  results.push({ id: 'seo.viewport', status: /<meta[^>]+name=["']viewport["']/i.test(head) ? 'pass' : 'fail', observed: 'viewport 메타', evidence: {} });
  results.push({ id: 'seo.og', status: /<meta[^>]+property=["']og:/i.test(head) ? 'pass' : 'fail', observed: 'Open Graph 태그', evidence: {} });
  results.push({ id: 'seo.canonical', status: /<link[^>]+rel=["']canonical["']/i.test(head) ? 'pass' : 'info', observed: 'canonical 링크', evidence: {} });

  // 성능
  const ms = mainRes.ms || 0;
  results.push({
    id: 'perf.ttfb',
    status: ms > 2000 ? 'fail' : (ms > 800 ? 'info' : 'pass'),
    observed: `응답 시간 ${ms}ms`,
    evidence: { ms },
  });
  const bytes = Buffer.byteLength(body, 'utf8');
  results.push({
    id: 'perf.page-size',
    status: bytes > 500 * 1024 ? 'fail' : (bytes > 250 * 1024 ? 'info' : 'pass'),
    observed: `문서 크기 ${(bytes / 1024).toFixed(0)}KB`,
    evidence: { bytes },
  });
  const enc = h['content-encoding'] || '';
  results.push({
    id: 'perf.compression',
    status: /gzip|br|deflate/.test(enc) ? 'pass' : 'info',
    observed: enc ? `압축: ${enc}` : '압축 미표기',
    evidence: { encoding: enc || null },
  });
  return results;
}

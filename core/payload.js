// 서버 제출 페이로드(증빙팩 report.json) 빌드. 도름스 서버와의 계약(schema/submission.schema.json).
// 서버는 이 값을 '참고'로만 쓰고, 마크는 서버가 직접 재스캔한 결과로 발급한다.
import { catalogItem } from '../catalog/index.js';
import { sha256 } from './util.js';

export function buildPayload({ config, results, security, edzip, bonus, toolVersion }) {
  const items = results.map(r => {
    const cat = catalogItem(r.id) || {};
    return {
      id: r.id,
      track: cat.track || null,
      severity: cat.severity || null,
      method: cat.method || (String(r.id).startsWith('code.') ? 'ai' : 'deterministic'),
      serverVerifiable: cat.serverVerifiable === true,
      status: r.status,
      observed: r.observed,
      evidence: r.evidence || {},
    };
  });
  const payload = {
    schemaVersion: 1,
    tool: { name: 'dorms-check', version: toolVersion || '0.1.0' },
    generatedAt: new Date().toISOString(),
    app: {
      name: config.app?.name || null,
      url: config.app?.url || null,
      stack: config.app?.stack || null,
      tracks: config.tracks || [],
      edzipCase: config.edzipCase || null,
    },
    teacher: { dormsHandle: config.teacher?.dormsHandle || null },
    tracks: {
      security: security ? { claimed: config.tracks?.includes('security'), score: security.score, grade: security.grade, eligible: security.eligible } : null,
      edzip: edzip ? { claimed: config.tracks?.includes('edzip'), eligible: edzip.eligible, policyPresent: edzip.policyPresent } : null,
    },
    items,
    // 서버가 target.url 로 재스캔해 대조할 결정적 항목(스킬 자기신고가 아닌 것)
    reverifyHints: {
      revalidate: items.filter(i => i.serverVerifiable).map(i => i.id),
      note: '서버는 이 항목을 앱 URL 로 독립 재스캔해 대조한다. 불일치 시 발급 거부. 나머지(code.hardcoded-secret 등)는 자기신고로 투명 표기.',
    },
  };
  payload.manifestSha256 = sha256(JSON.stringify({ ...payload, manifestSha256: undefined }));
  return payload;
}

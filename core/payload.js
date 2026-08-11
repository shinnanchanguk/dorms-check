// 서버 제출 페이로드(증빙팩 report.json) 빌드. 도름스 서버와의 계약(schema/submission.schema.json · v2).
// 서버는 이 값을 '참고'로만 쓰고, 마크는 서버가 직접 재스캔한 결과로 발급한다.
// 트랙 조각은 레지스트리(core/tracks.js)의 payloadSection 이 소유한다.
// - v1(schemaVersion 1): tracks 에 security/edzip 만 있을 때 — 기존 구조 그대로(하위 호환).
// - v2(schemaVersion 2): protection 등 새 트랙이 포함될 때 — Record<string,object> + redact 적용.
import { catalogItem, TRACKS } from './tracks.js';
import { sha256 } from './util.js';
import { redactPayload } from './redact.js';

const V1_TRACK_IDS = ['security', 'edzip'];

// 레거시 인자(security/edzip)도 받아 trackResults 로 정규화(하위 호환).
function normalizeTrackResults({ trackResults, security, edzip }) {
  if (trackResults) return trackResults;
  const out = {};
  if (security) out.security = security;
  if (edzip) out.edzip = edzip;
  return out;
}

export function buildPayload({ config, results, security, edzip, bonus, toolVersion, trackResults }) {
  const tr = normalizeTrackResults({ trackResults, security, edzip });
  // v2 판단: v1 트랙(security/edzip) 밖의 트랙이 설정·결과에 하나라도 있으면 v2.
  const claimedTracks = config.tracks || [];
  const isV2 = [...claimedTracks, ...Object.keys(tr)].some(id => !V1_TRACK_IDS.includes(id));

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

  // 트랙 조각: v1 트랙은 미실행이어도 null 키 유지(v1 구조 보존), 새 트랙은 결과 있을 때만.
  const tracksSection = {};
  for (const t of TRACKS) {
    const result = tr[t.id];
    if (result) tracksSection[t.id] = t.payloadSection({ result, config });
    else if (t.alwaysInPayload) tracksSection[t.id] = null;
  }

  const payload = {
    schemaVersion: isV2 ? 2 : 1,
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
    tracks: tracksSection,
    items,
    // 서버가 target.url 로 재스캔해 대조할 결정적 항목(스킬 자기신고가 아닌 것)
    reverifyHints: {
      revalidate: items.filter(i => i.serverVerifiable).map(i => i.id),
      note: '서버는 이 항목을 앱 URL 로 독립 재스캔해 대조한다. 불일치 시 발급 거부. 나머지(code.hardcoded-secret 등)는 자기신고로 투명 표기.',
    },
  };

  // v2: 제출 전 시크릿·경로 마스킹(redact). v1 은 기존 출력 그대로(하위 호환).
  const finalPayload = isV2 ? redactPayload(payload) : payload;
  finalPayload.manifestSha256 = sha256(JSON.stringify({ ...finalPayload, manifestSha256: undefined }));
  return finalPayload;
}

// 교사 보관용 리포트 렌더 + 콘솔 출력 — 트랙별 섹션은 레지스트리(core/tracks.js)가 소유.
// 통과 항목 = 증빙 매핑(관측값·파일:라인). 미충족 항목 = 비개발자 설명 + AI 수정 프롬프트.
import { TRACKS } from './tracks.js';

// 레거시 인자(security/edzip)도 받아 trackResults 로 정규화(하위 호환).
function normalizeTrackResults({ trackResults, security, edzip }) {
  if (trackResults) return trackResults;
  const out = {};
  if (security) out.security = security;
  if (edzip) out.edzip = edzip;
  return out;
}

export function renderReportMd({ config, results, security, edzip, bonus, trackResults }) {
  const tr = normalizeTrackResults({ trackResults, security, edzip });
  const stack = (config.app && config.app.stack) || '내';
  const lines = [];
  lines.push(`# dorms-check 점검 리포트`);
  lines.push('');
  lines.push(`- 앱: ${config.app?.name || '(이름 없음)'}`);
  lines.push(`- 주소: ${config.app?.url || '(로컬)'} `);
  lines.push(`- 스택: ${stack}`);
  lines.push(`- 점검 트랙: ${(config.tracks || []).join(', ')}`);
  lines.push('');
  lines.push(`> 이 리포트는 dorms-check(코치)의 자체 점검 결과입니다. 최종 인증마크는 도름스 서버가 스스로 다시 검증해 발급하며, 이 리포트의 통과가 마크를 보장하지 않습니다.`);
  lines.push('');

  for (const t of TRACKS) {
    const result = tr[t.id];
    if (!result) continue;
    lines.push(...t.reportSection({ result, results, config, stack, bonus }));
  }
  return lines.join('\n') + '\n';
}

// 콘솔 요약 출력
export function printSummary({ security, edzip, results, config, trackResults }) {
  const tr = normalizeTrackResults({ trackResults, security, edzip });
  const stack = (config.app && config.app.stack) || '내';
  for (const t of TRACKS) {
    const result = tr[t.id];
    if (!result) continue;
    t.summaryLines({ result, results, config, stack });
  }
}

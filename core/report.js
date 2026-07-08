// 교사 보관용 리포트 렌더 + 콘솔 출력.
// 통과 항목 = 증빙 매핑(관측값·파일:라인). 미충족 항목 = 비개발자 설명 + AI 수정 프롬프트.
import { catalogItem, SEVERITY_RANK } from '../catalog/index.js';
import { color, log } from './util.js';

function fill(text, stack) {
  return (text || '').replaceAll('{stack}', stack || '내');
}

function evidenceLine(r) {
  const e = r.evidence || {};
  if (e.value) return `헤더값: ${e.value}`;
  if (Array.isArray(e.hits) && e.hits.length) return e.hits.slice(0, 3).map(h => `${h.file}:${h.line}`).join(', ') + (e.hits.length > 3 ? ` 외 ${e.hits.length - 3}건` : '');
  if (e.readableTables && e.readableTables.length) return `익명 읽기 가능 테이블: ${e.readableTables.join(', ')}`;
  if (e.exposedPaths && e.exposedPaths.length) return `노출 경로: ${e.exposedPaths.join(', ')}`;
  if (r.observed) return r.observed;
  return '';
}

export function renderReportMd({ config, results, security, edzip, bonus }) {
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

  if (security) {
    lines.push(`## 보안 검토`);
    lines.push(`- 점수: ${security.score}/100 (${security.grade})`);
    lines.push(`- 마크 자격(critical/high 0): ${security.eligible ? '충족' : '미충족'}`);
    lines.push('');
    lines.push(`### 통과 항목(증빙)`);
    for (const r of results.filter(x => x.status === 'pass')) {
      const cat = catalogItem(r.id); if (!cat || cat.track !== 'security') continue;
      lines.push(`- [v] ${cat.title} — ${evidenceLine(r)}`);
    }
    lines.push('');
    const unmet = results.filter(x => x.status === 'fail' && (catalogItem(x.id)?.track === 'security'));
    if (unmet.length) {
      lines.push(`### 아직 고쳐야 할 항목`);
      unmet.sort((a, b) => (SEVERITY_RANK[catalogItem(b.id).severity] - SEVERITY_RANK[catalogItem(a.id).severity]));
      for (const r of unmet) {
        const cat = catalogItem(r.id);
        lines.push(`#### [${cat.severity}] ${cat.title}`);
        lines.push(`- 무엇: ${fill(cat.plain, stack)}`);
        lines.push(`- 지금 상태: ${r.observed}`);
        if (cat.aiFix) lines.push(`- AI에게 이렇게 시켜주세요: \`${fill(cat.aiFix, stack)}\``);
        lines.push('');
      }
    }
    const info = results.filter(x => x.status === 'info' && catalogItem(x.id)?.track === 'security');
    if (info.length) {
      lines.push(`### 참고(검토 권장, 마크 게이트 아님)`);
      for (const r of info) lines.push(`- ${catalogItem(r.id).title}: ${r.observed}`);
      lines.push('');
    }
  }

  if (edzip) {
    lines.push(`## 학운위 심사 준비(에듀집 필수기준)`);
    lines.push(`- 준비 상태: ${edzip.eligible ? '충족(제출 서류 준비됨)' : '미충족'}`);
    lines.push(`- 개인정보처리방침 공개: ${edzip.policyPresent ? '있음' : '없음'}`);
    if (edzip.unmet && edzip.unmet.length) {
      lines.push('');
      lines.push(`### 아직 준비할 항목`);
      for (const u of edzip.unmet) {
        const cat = catalogItem(u.id);
        lines.push(`#### ${cat.title} (${cat.criterion})`);
        lines.push(`- 무엇: ${fill(cat.plain, stack)}`);
        if (cat.law) lines.push(`- 근거: ${cat.law}`);
        if (cat.aiFix) lines.push(`- AI에게: \`${fill(cat.aiFix, stack)}\``);
        lines.push('');
      }
    }
    lines.push('');
    lines.push(`> "학운위 심사 준비 완료"는 학교 심의에 낼 서류가 갖춰졌다는 뜻이며, 심의 통과를 보장하지 않습니다. 심의와 최종 결정은 각 학교가 합니다.`);
  }
  return lines.join('\n') + '\n';
}

// 콘솔 요약 출력
export function printSummary({ security, edzip, results, config }) {
  const stack = (config.app && config.app.stack) || '내';
  if (security) {
    log.title(`보안 검토  ${security.score}/100 (${security.grade})  마크자격: ${security.eligible ? color.green('충족') : color.yellow('미충족')}`);
    const unmet = results.filter(x => x.status === 'fail' && catalogItem(x.id)?.track === 'security');
    for (const r of unmet) {
      const cat = catalogItem(r.id);
      log.plain(`  ${color.red('x')} [${cat.severity}] ${cat.title} — ${fill(cat.plain, stack)}`);
    }
  }
  if (edzip) {
    log.title(`학운위 준비  ${edzip.eligible ? color.green('충족') : color.yellow('미충족')}`);
    for (const u of edzip.unmet || []) log.plain(`  ${color.yellow('!')} ${catalogItem(u.id).title}`);
  }
}

// 트랙 레지스트리 (SSOT) — 점검 축(트랙)의 정의·조회를 한 곳에 모은다.
// 각 트랙 정의: { id, name(화면 이름), description, items(카탈로그 항목 배열),
//   score(results, ctx) → 트랙 결과, reportSection(md 렌더), summaryLines(콘솔 요약),
//   payloadSection(제출 페이로드 조각), roundSummary/passed(세션 기록), collect(스캔 시 항목 보충),
//   initNotes/submitNotes(CLI 안내), alwaysInPayload(v1 호환: 미실행이어도 payload.tracks 에 null 로 유지) }
// 새 트랙은 카탈로그 파일을 만들고 여기 TRACKS 에 정의 하나를 추가하면
// catalog/score/report/payload/session/CLI 가 전부 레지스트리 경유로 따라온다.
import path from 'node:path';
import { SECURITY_ITEMS } from '../catalog/security.js';
import { EDZIP_ITEMS, EDZIP_CASE_QUESTIONS } from '../catalog/edzip.js';
import { PROTECTION_ITEMS } from '../catalog/protection.js';
import { runProtectionScan, pendingProtectionSeeds } from '../checks/protection/index.js';
import { color, log } from './util.js';

// ── 항목 인덱스(카탈로그 SSOT) ──
const byId = new Map();
function registerItems(track, items) {
  for (const it of items) byId.set(it.id, { ...it, track });
}
registerItems('security', SECURITY_ITEMS);
registerItems('edzip', EDZIP_ITEMS);
registerItems('protection', PROTECTION_ITEMS);

export function catalogItem(id) {
  return byId.get(id) || null;
}
export function allItems() {
  return [...byId.values()];
}
export function trackItems(track) {
  return [...byId.values()].filter(i => i.track === track);
}

// 심각도 순위(정렬·게이트용)
export const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function fill(text, stack) {
  return (text || '').replaceAll('{stack}', stack || '내');
}

function grade(score) {
  if (score >= 97) return 'A+';
  if (score >= 93) return 'A';
  if (score >= 90) return 'A-';
  if (score >= 87) return 'B+';
  if (score >= 83) return 'B';
  if (score >= 80) return 'B-';
  if (score >= 75) return 'C+';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
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

// ── 채점기 (기존 core/score.js 구현을 그대로 이전 — 로직 불변) ──

// results: [{id, status, observed, evidence}], bonus: [{id, points}]
export function scoreSecurity(results, bonus = []) {
  let score = 100;
  const failing = [];
  const failingBySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of results) {
    const cat = catalogItem(r.id);
    if (!cat || cat.track !== 'security') continue;
    if (r.status === 'fail') {
      score -= cat.weight || 0;
      failingBySeverity[cat.severity] = (failingBySeverity[cat.severity] || 0) + 1;
      if (cat.gate) failing.push({ id: r.id, severity: cat.severity, title: cat.title });
    }
  }
  for (const b of bonus) score += b.points || 0;
  score = Math.max(0, Math.min(100, score));

  // 마크 게이트: gate 항목 중 critical/high fail 이 0 이어야 자격.
  const blockingFails = failing.filter(f => f.severity === 'critical' || f.severity === 'high');
  return {
    score,
    grade: grade(score),
    eligible: blockingFails.length === 0,
    blockingFails,
    failingBySeverity,
  };
}

// edzip: gate 항목 전부 pass/na 이고 개인정보처리방침(legal.privacy-policy)이 존재해야 자격.
export function scoreEdzip(results) {
  const map = new Map(results.map(r => [r.id, r.status]));
  const unmet = [];
  for (const r of results) {
    const cat = catalogItem(r.id);
    if (!cat || cat.track !== 'edzip' || !cat.gate) continue;
    if (r.status !== 'pass' && r.status !== 'na') unmet.push({ id: r.id, title: cat.title, severity: cat.severity });
  }
  const policyPresent = map.get('legal.privacy-policy') === 'pass';
  return {
    eligible: unmet.length === 0 && policyPresent,
    unmet,
    policyPresent,
  };
}

// ── 트랙 정의 ──

const securityTrack = {
  id: 'security',
  name: '보안 검토',
  description: '보안 헤더·전송 보안·정보 유출·CORS·RLS 실측·코드 시크릿 점검',
  items: SECURITY_ITEMS,
  alwaysInPayload: true, // v1 호환: 미실행이어도 payload.tracks.security = null 유지

  score(results, ctx = {}) {
    return scoreSecurity(results, ctx.bonus || []);
  },

  reportSection({ result, results, stack }) {
    const security = result;
    const lines = [];
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
    return lines;
  },

  summaryLines({ result, results, stack }) {
    const security = result;
    log.title(`보안 검토  ${security.score}/100 (${security.grade})  마크자격: ${security.eligible ? color.green('충족') : color.yellow('미충족')}`);
    const unmet = results.filter(x => x.status === 'fail' && catalogItem(x.id)?.track === 'security');
    for (const r of unmet) {
      const cat = catalogItem(r.id);
      log.plain(`  ${color.red('x')} [${cat.severity}] ${cat.title} — ${fill(cat.plain, stack)}`);
    }
  },

  payloadSection({ result, config }) {
    return { claimed: config.tracks?.includes('security'), score: result.score, grade: result.grade, eligible: result.eligible };
  },

  roundSummary(result) {
    return { score: result.score, grade: result.grade, eligible: result.eligible, blocking: result.blockingFails.map(f => f.id) };
  },

  passed(result) {
    return result.eligible;
  },
};

const edzipTrack = {
  id: 'edzip',
  name: '학운위 심사 준비',
  description: '에듀집 필수기준 5대기준 9세부 + 개인정보처리방침 공개 준비',
  items: EDZIP_ITEMS,
  alwaysInPayload: true, // v1 호환

  score(results) {
    return scoreEdzip(results);
  },

  // 스캔 시 판단 안 된 edzip 항목을 pending 으로 보충(기존 bin 인라인 로직 이전)
  collect({ results, review }) {
    const out = [];
    for (const it of EDZIP_ITEMS) {
      if (!results.find(r => r.id === it.id)) {
        const rv = review[it.id];
        out.push({ id: it.id, status: rv ? rv.status : 'pending', observed: rv ? rv.evidence : '아직 판단 안 됨(judge 필요)', evidence: rv ? { aiJudgment: rv } : {} });
      }
    }
    return out;
  },

  reportSection({ result, stack }) {
    const edzip = result;
    const lines = [];
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
    return lines;
  },

  summaryLines({ result }) {
    const edzip = result;
    log.title(`학운위 준비  ${edzip.eligible ? color.green('충족') : color.yellow('미충족')}`);
    for (const u of edzip.unmet || []) log.plain(`  ${color.yellow('!')} ${catalogItem(u.id).title}`);
  },

  payloadSection({ result, config }) {
    return { claimed: config.tracks?.includes('edzip'), eligible: result.eligible, policyPresent: result.policyPresent };
  },

  roundSummary(result) {
    return { eligible: result.eligible, unmet: result.unmet.map(u => u.id) };
  },

  passed(result) {
    return result.eligible;
  },

  // init 시 트랙별 추가 안내(기존 bin 인라인 로직 이전)
  initNotes() {
    log.title('학운위(에듀집) 케이스 진단 — 아래 3문항 답을 config.edzipCase 에 A/B/C/D 로 기록');
    for (const q of EDZIP_CASE_QUESTIONS) log.plain(`  - ${q.id}: ${q.ask}`);
  },

  // submit 시 트랙별 추가 안내(기존 bin 인라인 로직 이전)
  submitNotes({ root, outDir }) {
    log.title('학운위 마크: 방침을 앱 안에서만 보여주는 앱이라면');
    log.plain('  도름스는 앱 주소를 바깥에서 열어 개인정보처리방침 글자를 읽습니다. 방침을 별도 주소 없이');
    log.plain('  앱 안 팝업으로만 띄우면(리액트·Vite 같은 한 장짜리 앱) 바깥에서는 빈 화면이라 못 읽을 수 있어요.');
    log.plain('  "개인정보처리방침 필수 항목이 확인되지 않는다"가 뜨면 둘 중 하나로 푸세요.');
    log.plain(`  · 방침을 /privacy 같은 주소로도 열리게 두기(권장)`);
    log.plain(`  · 방금 만든 ${path.relative(root, path.join(outDir, 'report.json'))} 를 신청 화면의 "dorms-check 결과 올리기"에 올리기`);
  },
};

// ── protection 채점기: 점수가 아니라 6상태를 계산한다 ──
// 상태 축 4개(권리·경계·배포·안내)의 값이 아래 6상태 라벨로 나온다.
// 미확인은 보수적으로 본다: 클라이언트로 전달된 것은 공개로 가정(공개 자산), 설문 전엔 권리관계 확인 필요.
export const PROTECTION_STATE_LABELS = {
  rights: { confirmed: '권리관계 확인됨', unresolved: '권리관계 확인 필요' },
  boundary: { server_separated: '서버 분리 확인', partially_separated: '일부 서버 분리', public_asset: '공개 자산' },
  release: { copy_cost_raised: '복제 비용 상승 조치', not_hardened: '복제 비용 상승 조치 전' },
  notice: { notice_configured: '권리·이용 안내 설정', not_configured: '권리·이용 안내 설정 전' },
};

const RIGHTS_IDS = ['protection.rights.owner-status', 'protection.rights.third-party', 'protection.rights.ai-contribution', 'protection.rights.license-consistency'];
const BOUNDARY_LEAK_IDS = ['protection.boundary.client-secrets', 'protection.boundary.prompt', 'protection.boundary.weights', 'protection.boundary.output-leak', 'protection.boundary.api-abuse'];
const RELEASE_IDS = ['protection.release.sourcemap', 'protection.release.debug', 'protection.release.private-identifiers', 'protection.release.separation', 'protection.release.integrity'];
const NOTICE_IDS = ['protection.notice.visible', 'protection.notice.machine-readable', 'protection.evidence.manifest'];

export function scoreProtection(results) {
  const st = new Map();
  for (const r of results) {
    const cat = catalogItem(r.id);
    if (cat && cat.track === 'protection') st.set(r.id, r.status);
  }
  const ok = id => st.get(id) === 'pass' || st.get(id) === 'na';

  const rights = RIGHTS_IDS.every(ok) ? 'confirmed' : 'unresolved';

  const serverOk = ok('protection.boundary.server');
  let boundary;
  if (serverOk && BOUNDARY_LEAK_IDS.every(ok)) boundary = 'server_separated';
  else if (serverOk || BOUNDARY_LEAK_IDS.some(id => st.get(id) === 'pass')) boundary = 'partially_separated';
  else boundary = 'public_asset';

  const release = RELEASE_IDS.every(ok) ? 'copy_cost_raised' : 'not_hardened';
  const notice = NOTICE_IDS.every(ok) ? 'notice_configured' : 'not_configured';

  const states = { rights, boundary, release, notice };
  const labels = {
    rights: PROTECTION_STATE_LABELS.rights[rights],
    boundary: PROTECTION_STATE_LABELS.boundary[boundary],
    release: PROTECTION_STATE_LABELS.release[release],
    notice: PROTECTION_STATE_LABELS.notice[notice],
  };

  const unmet = [];
  for (const [id, status] of st) {
    const cat = catalogItem(id);
    if (!cat || !cat.gate) continue;
    if (status !== 'pass' && status !== 'na') unmet.push({ id, title: cat.title, severity: cat.severity });
  }
  return {
    states,
    labels,
    unmet,
    eligible: rights === 'confirmed' && unmet.length === 0,
  };
}

const protectionTrack = {
  id: 'protection',
  name: '내 앱 보호',
  description: '내 앱의 비법(프롬프트·로직·데이터)과 저작권을 지키는 준비 상태 점검. 점수가 아니라 상태를 구분해 보여준다.',
  items: PROTECTION_ITEMS,
  alwaysInPayload: false, // v2 전용 트랙: 실행했을 때만 payload.tracks 에 포함(v1 구조 불변)

  score(results) {
    return scoreProtection(results);
  },

  // 스캔 시 결정적 검사 실행 + ai/declared 미판정 항목 pending seed.
  // 결정적 항목은 judge 자기신고보다 우선한다(결정적 우선 원칙 — 스캔 결과가 review 를 덮는다).
  collect({ results, root }) {
    const { items: scanned } = runProtectionScan(root);
    const AUTHORITATIVE = new Set([
      'protection.boundary.client-secrets', 'protection.boundary.weights',
      'protection.release.sourcemap', 'protection.release.debug', 'protection.release.private-identifiers',
      'protection.release.separation', 'protection.release.integrity',
      'protection.notice.visible', 'protection.notice.machine-readable',
      'protection.evidence.manifest', 'protection.evidence.timestamp', 'protection.verify.functional',
      'protection.rights.owner-status', 'protection.asset.inventory',
    ]);
    const out = [];
    for (const it of scanned) {
      const existing = results.find(r => r.id === it.id);
      if (existing) {
        if (AUTHORITATIVE.has(it.id)) {
          const aiJ = existing.evidence && existing.evidence.aiJudgment;
          existing.status = it.status;
          existing.observed = it.observed;
          existing.evidence = { ...it.evidence, ...(aiJ ? { aiJudgment: aiJ } : {}) };
        }
        // 비권위 항목(프롬프트 문맥 판단 등)은 judge 판정을 유지한다.
      } else {
        out.push(it);
      }
    }
    const existingIds = new Set([...results.map(r => r.id), ...out.map(r => r.id)]);
    out.push(...pendingProtectionSeeds(existingIds));
    return out;
  },

  reportSection({ result, results, stack }) {
    const p = result;
    const lines = [];
    lines.push(`## 내 앱 보호(비법·저작권)`);
    lines.push(`- 권리관계: ${p.labels.rights}`);
    lines.push(`- 비법 경계: ${p.labels.boundary}`);
    lines.push(`- 배포 위생: ${p.labels.release}`);
    lines.push(`- 안내·증거: ${p.labels.notice}`);
    lines.push('');
    lines.push(`### 통과 항목(증빙)`);
    for (const r of results.filter(x => x.status === 'pass')) {
      const cat = catalogItem(r.id); if (!cat || cat.track !== 'protection') continue;
      lines.push(`- [v] ${cat.title} — ${evidenceLine(r)}`);
    }
    lines.push('');
    const unmet = results.filter(x => (x.status === 'fail' || x.status === 'pending') && catalogItem(x.id)?.track === 'protection');
    if (unmet.length) {
      lines.push(`### 아직 진행할 항목`);
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
    lines.push('');
    lines.push(`> 정직 고지: 난독화나 Base64 인코딩은 비밀이 아니에요. 브라우저로 전달된 코드·데이터는 공개된 것으로 봐야 해요. 이 트랙은 "완전 보호"를 약속하지 않아요. 서버 분리, 복제 비용 상승 조치, 권리·이용 안내, 증거 준비의 현재 상태를 구분해 보여줄 뿐이에요.`);
    return lines;
  },

  summaryLines({ result, results }) {
    const p = result;
    log.title(`내 앱 보호  권리: ${p.labels.rights} · 경계: ${p.labels.boundary} · 배포: ${p.labels.release} · 안내: ${p.labels.notice}`);
    const unmet = results.filter(x => (x.status === 'fail' || x.status === 'pending') && catalogItem(x.id)?.track === 'protection');
    for (const r of unmet.slice(0, 12)) {
      const cat = catalogItem(r.id);
      const mark = r.status === 'fail' ? color.red('x') : color.yellow('!');
      log.plain(`  ${mark} [${cat.severity}] ${cat.title} — ${r.observed}`);
    }
    if (unmet.length > 12) log.plain(color.dim(`  ...${unmet.length - 12}건 더(REPORT.md 참고)`));
  },

  payloadSection({ result, config }) {
    return { claimed: config.tracks?.includes('protection'), states: result.states, labels: result.labels, eligible: result.eligible };
  },

  roundSummary(result) {
    return { states: result.states, eligible: result.eligible, unmet: result.unmet.map(u => u.id) };
  },

  passed(result) {
    return result.eligible;
  },

  initNotes() {
    log.title('내 앱 보호 트랙 시작 안내');
    log.plain('  1) dcheck interview 로 권리·허용범위 설문 문항을 확인하고, 교사에게 쉬운 선택지로 물어보세요.');
    log.plain('  2) 답을 파일로 모아 dcheck interview --answers <파일> 로 rights-profile 을 만드세요.');
    log.plain('  3) scan → protect plan → (동의 후) protect apply --plan-sha256 <값> --confirm-apply → verify 순서로 진행하세요.');
    log.plain(color.dim('  이 트랙의 적용 단계만 파일을 바꾸며, 반드시 계획 해시와 --confirm-apply 동의가 있어야 해요. 자동 배포는 하지 않아요.'));
  },
};

// ── 레지스트리 ──
export const TRACKS = [securityTrack, edzipTrack, protectionTrack];

export function getTrack(id) {
  return TRACKS.find(t => t.id === id) || null;
}
export function trackIds() {
  return TRACKS.map(t => t.id);
}

// 보호 계획(protection plan) — "무엇을 바꿀지"를 먼저 문서로 만들고, 사용자가 그 계획의
// 해시(planSha256)에 동의했을 때만 파일을 바꾼다(protect apply --plan-sha256 <값> --confirm-apply).
// 계획에는 대상 자산, 변경 파일 목록, 서버 이전 후보, 위험, 복원 방법이 들어간다.
// 철학: security·edzip 은 검사만 한다. protection 의 적용 단계만 파일을 바꾸며,
//   그것도 승인된 계획 해시 + --confirm-apply 가 있을 때만이다. 자동 배포는 하지 않는다.
import path from 'node:path';
import { exists, readJsonSafe, writeText, sha256 } from './util.js';
import { loadRightsProfile, rightsConfirmed } from './rights-profile.js';
import { runProtectSteps, resolveBuildDir } from '../protect/apply.js';
import { runProtectionScan } from '../checks/protection/index.js';

const PLAN_FILE = path.join('.dorms-check', 'protection-plan.json');

export function planPath(root) {
  return path.join(root, PLAN_FILE);
}

// 정규화 직렬화: 객체 키를 재귀 정렬해 같은 내용이면 언제나 같은 문자열이 되게 한다.
export function canonicalStringify(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalStringify).join(',') + ']';
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

// 계획의 정규화 SHA-256. planSha256 필드 자신은 계산에서 제외한다.
export function planSha256(plan) {
  const { planSha256: _omit, ...rest } = plan;
  return sha256(canonicalStringify(rest));
}

// 계획 생성: 단계를 dry 로 돌려 변경 예정 파일을 모으고, 스캔 결과에서 서버 이전 후보·위험을 뽑는다.
export async function buildProtectionPlan(root, { config } = {}) {
  const buildDir = resolveBuildDir(root, config?.protection?.buildDir);
  if (!buildDir) {
    return { error: '빌드 산출물 디렉토리를 찾지 못했습니다. 먼저 프로젝트를 빌드하세요(예: npm run build).' };
  }
  const rightsProfile = loadRightsProfile(root);
  const dry = await runProtectSteps(root, { buildDir, config, dry: true, quiet: true });

  // 서버 이전 후보: 결정적 스캔에서 잡힌 클라이언트 노출(비밀키·프롬프트 후보·모델파일)
  const scan = runProtectionScan(root);
  const serverMoveCandidates = [];
  for (const it of scan.items) {
    if (!['protection.boundary.client-secrets', 'protection.boundary.prompt', 'protection.boundary.weights'].includes(it.id)) continue;
    for (const h of (it.evidence && it.evidence.hits) || []) {
      serverMoveCandidates.push({ file: h.file, kind: h.kind, item: it.id });
    }
  }

  const plan = {
    schemaVersion: 1,
    createdAt: new Date().toISOString(),
    app: { name: config?.app?.name || null, url: config?.app?.url || null },
    buildDir,
    rightsConfirmed: rightsConfirmed(rightsProfile),
    // 대상 자산: 권리 프로필의 보호 자산(이름·종류만 — 원문 없음)
    targets: (rightsProfile?.protectedAssets || []).map(a => ({ label: a.label, kind: a.kind, location: a.location || 'unknown' })),
    // 변경 파일 목록(단계별): dry 실행이 수집한 실제 예정 목록
    steps: dry.steps.map(s => ({ id: s.id, title: s.title, willChange: s.changed, willCreate: s.created })),
    // 서버 이전 후보: 이 계획은 파일을 서버로 옮기지 않는다(코드 이전은 교사 AI 가 별도 동의로).
    serverMoveCandidates: serverMoveCandidates.slice(0, 50),
    risks: [
      '빌드 산출물의 HTML·JS 를 수정하므로, 적용 후 반드시 verify 로 깨짐을 확인해야 합니다.',
      '빌드를 다시 하면 적용이 사라집니다(빌드 후 재적용 필요).',
      'robots.txt 차단·고지는 지키지 않는 수집기에게는 효력이 없습니다(완전 보호 아님).',
      plan_riskLicense(rightsProfile),
    ].filter(Boolean),
    restore: {
      method: 'dcheck protect restore (마지막 백업으로 복원)',
      backupBase: '.dorms-check/backup/',
      note: '적용 직전 원본이 자동 백업되며, 단계 실패 시에는 즉시 자동 복원됩니다.',
    },
  };
  plan.planSha256 = planSha256(plan);
  return { plan };
}

function plan_riskLicense(rightsProfile) {
  if (rightsConfirmed(rightsProfile)) return null;
  return '권리관계가 아직 확인되지 않아 LICENSE 는 생성하지 않습니다(interview 로 확인 후 다시 계획).';
}

export function writePlan(root, plan) {
  const p = planPath(root);
  writeText(p, JSON.stringify(plan, null, 2) + '\n');
  return p;
}

export function loadPlan(root) {
  const p = planPath(root);
  if (!exists(p)) return null;
  return readJsonSafe(p);
}

// 적용 게이트: 저장된 계획의 해시를 다시 계산해 (1) 계획 파일이 변조되지 않았고
// (2) 사용자가 준 --plan-sha256 값과 일치하는지 검사한다.
export function checkPlanApproval(plan, givenSha) {
  if (!plan) return { ok: false, reason: '계획 파일이 없습니다. 먼저 dcheck protect plan 을 실행하세요.' };
  const actual = planSha256(plan);
  if (plan.planSha256 && plan.planSha256 !== actual) {
    return { ok: false, reason: '계획 파일이 만들어진 뒤 수정됐습니다(내장 해시 불일치). protect plan 을 다시 실행하세요.' };
  }
  if (!givenSha) return { ok: false, reason: '--plan-sha256 <값> 이 필요합니다. 계획을 읽고 동의한 해시를 그대로 전달하세요.' };
  if (givenSha !== actual) {
    return { ok: false, reason: `계획 해시 불일치: 전달값 ${givenSha.slice(0, 12)}… vs 실제 ${actual.slice(0, 12)}…. 최신 계획을 다시 확인하세요.` };
  }
  return { ok: true, sha: actual };
}

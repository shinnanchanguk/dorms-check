// 권리 프로필(rights-profile.json) 생성·검증 — schema/rights-profile.schema.json 과 짝.
// 원칙: 비공개 프롬프트 원문·민감 파일명은 프로필에 넣지 않는다(자산은 이름·종류만).
// 의존성 0: 스키마 검증은 수기 검증기로(스키마 파일은 문서·서버 계약용).
import path from 'node:path';
import { exists, readJsonSafe, writeText } from './util.js';

const FILE = path.join('.dorms-check', 'rights-profile.json');

export const RIGHTSHOLDER_STATUS = ['sole', 'joint', 'school_work_related', 'third_party_included', 'unconfirmed'];
export const WORK_FOR_HIRE_REVIEW = ['not_needed', 'needed', 'done', 'unknown'];
export const AUDIENCE = ['anyone', 'dorms_members', 'verified_teachers', 'invited'];
export const PERMISSION_VALUES = ['allowed', 'permission_required', 'prohibited'];
export const PERMISSION_KEYS = [
  'useAsIs', 'shareOriginalLink', 'shareLockedAccess', 'screenshotsWithAttribution',
  'modify', 'redistribute', 'commercialUse', 'uploadPrivateAssetsToAI', 'aiTrainingOrClone',
];
export const ASSET_KINDS = ['prompt', 'logic', 'data', 'design', 'content', 'other'];
export const ASSET_LOCATIONS = ['server', 'client', 'mixed', 'unknown'];
export const LEGAL_REVIEW = ['not_done', 'recommended', 'done'];

export function defaultRightsProfile() {
  const permissions = {};
  for (const k of PERMISSION_KEYS) permissions[k] = 'permission_required'; // 기본은 보수적(허락 필요)
  return {
    schemaVersion: 1,
    appId: undefined,
    policyVersion: new Date().toISOString().slice(0, 10) + '.1',
    rightsholder: { status: 'unconfirmed', displayName: '', workForHireReview: 'unknown' },
    audience: 'anyone',
    permissions,
    attribution: { required: true, text: '' },
    protectedAssets: [],
    appSpecificAcceptance: false,
    customClauses: [],
    legalReview: 'not_done',
  };
}

// 자산 라벨에 비밀 원문·경로가 섞여 들어오는 것을 막는 보수적 검사.
function looksLikeSensitive(label) {
  const s = String(label || '');
  if (s.length > 80) return '라벨이 너무 깁니다(원문 붙여넣기 의심, 80자 이내)';
  if (/\/Users\/|\/home\/|[A-Za-z]:\\/.test(s)) return '파일 경로가 들어 있습니다';
  if (/\bsk-[A-Za-z0-9]{8,}|\bAKIA[0-9A-Z]{8,}|\beyJ[A-Za-z0-9_-]{10,}\./.test(s)) return '키·토큰으로 보이는 값이 들어 있습니다';
  return null;
}

// 프로필 검증. { ok, errors } 반환(에러는 사람이 읽는 한국어).
export function validateRightsProfile(p) {
  const errors = [];
  const push = m => errors.push(m);
  if (!p || typeof p !== 'object') return { ok: false, errors: ['프로필이 객체가 아닙니다'] };
  if (p.schemaVersion !== 1) push('schemaVersion 은 1 이어야 합니다');
  if (!p.policyVersion || typeof p.policyVersion !== 'string') push('policyVersion(판 표기)이 필요합니다');
  const rh = p.rightsholder;
  if (!rh || typeof rh !== 'object') push('rightsholder 가 필요합니다');
  else {
    if (!RIGHTSHOLDER_STATUS.includes(rh.status)) push(`rightsholder.status 는 ${RIGHTSHOLDER_STATUS.join('|')} 중 하나여야 합니다`);
    if (rh.workForHireReview !== undefined && !WORK_FOR_HIRE_REVIEW.includes(rh.workForHireReview)) push('rightsholder.workForHireReview 값이 올바르지 않습니다');
  }
  if (!AUDIENCE.includes(p.audience)) push(`audience 는 ${AUDIENCE.join('|')} 중 하나여야 합니다`);
  const perms = p.permissions;
  if (!perms || typeof perms !== 'object') push('permissions 가 필요합니다');
  else {
    for (const k of PERMISSION_KEYS) {
      if (!PERMISSION_VALUES.includes(perms[k])) push(`permissions.${k} 는 ${PERMISSION_VALUES.join('|')} 중 하나여야 합니다`);
    }
    for (const k of Object.keys(perms)) {
      if (!PERMISSION_KEYS.includes(k)) push(`permissions 에 알 수 없는 키: ${k}`);
    }
  }
  if (p.protectedAssets !== undefined) {
    if (!Array.isArray(p.protectedAssets)) push('protectedAssets 는 배열이어야 합니다');
    else for (const [i, a] of p.protectedAssets.entries()) {
      if (!a || typeof a !== 'object') { push(`protectedAssets[${i}] 형식 오류`); continue; }
      if (!a.label) push(`protectedAssets[${i}].label 이 필요합니다`);
      const sens = looksLikeSensitive(a.label);
      if (sens) push(`protectedAssets[${i}].label: ${sens}. 자산은 이름만 적으세요(원문·경로 금지)`);
      if (!ASSET_KINDS.includes(a.kind)) push(`protectedAssets[${i}].kind 는 ${ASSET_KINDS.join('|')} 중 하나여야 합니다`);
      if (a.location !== undefined && !ASSET_LOCATIONS.includes(a.location)) push(`protectedAssets[${i}].location 값이 올바르지 않습니다`);
    }
  }
  if (p.legalReview !== undefined && !LEGAL_REVIEW.includes(p.legalReview)) push('legalReview 값이 올바르지 않습니다');
  if (p.customClauses !== undefined && !Array.isArray(p.customClauses)) push('customClauses 는 배열이어야 합니다');
  return { ok: errors.length === 0, errors };
}

// 권리관계가 '확정'인가 — LICENSE 자동 생성 등 파일 변경의 게이트.
// 단독/공동 소유는 확정. 학교 업무 관련은 기관 검토가 끝났을 때만 확정.
export function rightsConfirmed(p) {
  if (!p || !p.rightsholder) return false;
  const s = p.rightsholder.status;
  if (s === 'sole' || s === 'joint') return true;
  if (s === 'school_work_related') return p.rightsholder.workForHireReview === 'done' || p.rightsholder.workForHireReview === 'not_needed';
  return false;
}

export function rightsProfilePath(root) {
  return path.join(root, FILE);
}

export function loadRightsProfile(root) {
  const p = rightsProfilePath(root);
  if (!exists(p)) return null;
  return readJsonSafe(p);
}

export function writeRightsProfile(root, profile) {
  const v = validateRightsProfile(profile);
  if (!v.ok) throw new Error('rights-profile 검증 실패:\n  - ' + v.errors.join('\n  - '));
  const p = rightsProfilePath(root);
  const clean = JSON.parse(JSON.stringify(profile)); // undefined 필드 제거
  writeText(p, JSON.stringify(clean, null, 2) + '\n');
  return p;
}

// ── interview 문항 (교사에게 AI 가 물을 질문 — 쉬운 선택지, 1~3문항씩) ──
// dcheck interview 가 이 JSON 을 출력하고, 답 파일을 받아 buildRightsProfileFromAnswers 로 프로필을 만든다.
export const INTERVIEW_QUESTIONS = [
  {
    section: '권리자',
    questions: [
      { id: 'owner', ask: '이 앱은 누가 만들었나요?', choices: { sole: '나 혼자 만들었어요', joint: '다른 사람과 같이 만들었어요(합의됨)', unconfirmed: '아직 정리가 안 됐어요' } },
      { id: 'schoolInvolved', ask: '학교 업무(수업 준비·업무 지시)와 관련해 만들었나요?', choices: { no: '아니요, 개인 작업이에요', yes_reviewed: '네, 그런데 기관과 권리 정리를 확인했어요', yes_unreviewed: '네, 아직 확인 안 했어요' } },
      { id: 'displayName', ask: '권리자 표시 이름(안내문에 적을 이름)을 알려주세요.', free: true },
    ],
  },
  {
    section: '기존 조건·재료',
    questions: [
      { id: 'existingLicense', ask: '이 앱을 이미 오픈소스 등으로 공개한 적이 있나요?', choices: { none: '없어요', open: '있어요(오픈소스·공개 라이선스)', unsure: '잘 모르겠어요' } },
      { id: 'thirdPartyAssets', ask: '남이 만든 재료(이미지·글꼴·코드·템플릿)를 쓰나요?', choices: { none: '없거나 자유 이용 재료만 써요', licensed: '있고, 이용 조건을 확인했어요', unverified: '있는데 조건을 확인 안 했어요' } },
      { id: 'aiContribution', ask: 'AI 가 만든 부분과 내가 만든 부분을 구분할 수 있나요?', choices: { distinguishable: '네, 내가 설계·작성한 부분이 분명해요', mostly_ai: '거의 AI 가 만들었어요', unsure: '잘 모르겠어요' } },
    ],
  },
  {
    section: '보호할 자산',
    questions: [
      { id: 'protectedAssets', ask: '이 앱의 비법이라 지키고 싶은 것을 이름만 적어주세요(예: 채점 지시문, 문항 데이터). 원문은 적지 마세요.', free: true, list: true },
    ],
  },
  {
    section: '허용 범위',
    questions: [
      { id: 'audience', ask: '누구까지 쓰게 할까요?', choices: { anyone: '누구나', dorms_members: '도름스 회원만', verified_teachers: '인증된 교사만', invited: '내가 초대한 사람만' } },
      { id: 'shareLevel', ask: '다른 사람이 이 앱을 어디까지 쓰게 할까요?', choices: { open: '그대로 쓰고 링크 공유까지 자유롭게', ask_first: '쓰는 건 좋은데 그 외에는 허락받게', strict: '허락 없이는 쓰지 못하게' } },
      { id: 'aiTraining', ask: 'AI 학습·복제(내 앱을 본떠 만들기)는요?', choices: { prohibited: '금지할래요', permission_required: '허락받으면 돼요', allowed: '허용할래요' } },
    ],
  },
];

// 답 파일(answers) → 프로필. answers 형식: { owner, schoolInvolved, displayName, existingLicense,
//   thirdPartyAssets, aiContribution, protectedAssets: [{label,kind,location}|문자열], audience, shareLevel, aiTraining }
export function buildRightsProfileFromAnswers(answers = {}) {
  const p = defaultRightsProfile();

  // 권리자 상태
  if (answers.owner === 'sole') p.rightsholder.status = 'sole';
  else if (answers.owner === 'joint') p.rightsholder.status = 'joint';
  else p.rightsholder.status = 'unconfirmed';
  if (answers.schoolInvolved === 'yes_reviewed') { p.rightsholder.status = 'school_work_related'; p.rightsholder.workForHireReview = 'done'; }
  else if (answers.schoolInvolved === 'yes_unreviewed') { p.rightsholder.status = 'school_work_related'; p.rightsholder.workForHireReview = 'needed'; }
  else if (answers.schoolInvolved === 'no') { if (p.rightsholder.workForHireReview === 'unknown') p.rightsholder.workForHireReview = 'not_needed'; }
  if (answers.thirdPartyAssets === 'unverified' && p.rightsholder.status !== 'unconfirmed') p.rightsholder.status = 'third_party_included';
  if (typeof answers.displayName === 'string') p.rightsholder.displayName = answers.displayName.slice(0, 100);

  // 청중·허용 범위
  if (AUDIENCE.includes(answers.audience)) p.audience = answers.audience;
  const level = answers.shareLevel;
  if (level === 'open') {
    Object.assign(p.permissions, {
      useAsIs: 'allowed', shareOriginalLink: 'allowed', shareLockedAccess: 'permission_required',
      screenshotsWithAttribution: 'allowed', modify: 'permission_required', redistribute: 'permission_required',
      commercialUse: 'permission_required', uploadPrivateAssetsToAI: 'prohibited', aiTrainingOrClone: 'permission_required',
    });
  } else if (level === 'strict') {
    for (const k of PERMISSION_KEYS) p.permissions[k] = 'prohibited';
    p.permissions.useAsIs = 'permission_required';
  } // ask_first(기본): defaultRightsProfile 의 permission_required 유지
  if (PERMISSION_VALUES.includes(answers.aiTraining)) p.permissions.aiTrainingOrClone = answers.aiTraining;
  if (p.permissions.aiTrainingOrClone === 'prohibited') p.permissions.uploadPrivateAssetsToAI = 'prohibited';

  // 보호 자산(이름만)
  if (Array.isArray(answers.protectedAssets)) {
    p.protectedAssets = answers.protectedAssets.map(a => {
      if (typeof a === 'string') return { label: a.slice(0, 80), kind: 'other', location: 'unknown' };
      return { label: String(a.label || '').slice(0, 80), kind: ASSET_KINDS.includes(a.kind) ? a.kind : 'other', location: ASSET_LOCATIONS.includes(a.location) ? a.location : 'unknown' };
    }).filter(a => a.label);
  }

  // 기존 공개 조건 메모(충돌 판단은 AI judge 몫 — 프로필엔 사실만)
  if (answers.existingLicense === 'open') p.customClauses.push('이미 공개 라이선스로 배포한 적이 있음(새 조건과의 충돌 검토 필요)');
  if (answers.aiContribution === 'mostly_ai') p.customClauses.push('AI 생성 비중이 큼(권리 주장 범위 검토 필요)');

  if (p.rightsholder.displayName) p.attribution.text = `만든이 ${p.rightsholder.displayName}`;
  return p;
}

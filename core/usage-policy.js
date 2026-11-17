// 도름스 '이용·보호 안내'와 같은 항목·묶음(dorms src/lib/usagePolicyLabels.ts · usagePolicyPresets.ts 의 사본).
// 표기 문구는 templates/copy.ko.json 에 있고, 여기는 키·순서·묶음 값과 판정만 가진다.
import { t } from './copy.js';
import { sha256 } from './util.js';

export const PERMISSION_VALUES = ['allowed', 'permission_required', 'prohibited'];

// 도름스 표시 순서(PERMISSION_ORDER)와 같다. shareLockedAccess 는 예전 dorms-check 전용 키(하위 호환).
export const DORMS_PERMISSION_ORDER = [
  'useAsIs', 'shareDormsLink', 'shareOriginalLink', 'screenshotsWithAttribution', 'downloadPrint',
  'modify', 'sourceReuse', 'redistribute', 'commercialUse', 'uploadPrivateAssetsToAI', 'aiTrainingOrClone', 'research',
];
export const LOCKED_ALLOWED = new Set(['shareDormsLink']);

export const PRESETS = {
  edu_share: {
    useAsIs: 'allowed', shareOriginalLink: 'allowed', screenshotsWithAttribution: 'allowed', downloadPrint: 'allowed',
    modify: 'permission_required', sourceReuse: 'permission_required', redistribute: 'permission_required',
    commercialUse: 'prohibited', uploadPrivateAssetsToAI: 'prohibited', aiTrainingOrClone: 'prohibited', research: 'permission_required',
  },
  restricted: {
    useAsIs: 'allowed', shareOriginalLink: 'permission_required', screenshotsWithAttribution: 'permission_required', downloadPrint: 'permission_required',
    modify: 'permission_required', sourceReuse: 'permission_required', redistribute: 'permission_required',
    commercialUse: 'permission_required', uploadPrivateAssetsToAI: 'permission_required', aiTrainingOrClone: 'permission_required', research: 'permission_required',
  },
  open_collab: {
    useAsIs: 'allowed', shareOriginalLink: 'allowed', screenshotsWithAttribution: 'allowed', downloadPrint: 'allowed',
    modify: 'allowed', sourceReuse: 'allowed', redistribute: 'allowed',
    commercialUse: 'permission_required', uploadPrivateAssetsToAI: 'permission_required', aiTrainingOrClone: 'prohibited', research: 'allowed',
  },
};
PRESETS.custom = PRESETS.edu_share;
export const PRESET_IDS = ['edu_share', 'restricted', 'open_collab', 'custom'];

// 사람이 옮겨 적은 값('허용'·'먼저 허락'·'허용 안 함' 또는 영문 id)을 id 로.
export function normalizePermissionValue(v) {
  if (PERMISSION_VALUES.includes(v)) return v;
  const s = String(v || '').replace(/\s+/g, '');
  if (s === '허용') return 'allowed';
  if (s === '먼저허락' || s === '허락필요') return 'permission_required';
  if (s === '허용안함' || s === '금지') return 'prohibited';
  return null;
}

// 고쳐 쓰기 판정: modify·sourceReuse·redistribute 중 가장 엄격한 값. 비었거나 없으면 '먼저 허락'으로 본다.
export const ADAPTATION_KEYS = ['modify', 'sourceReuse', 'redistribute'];
export function adaptationValue(permissions) {
  const rank = { allowed: 0, permission_required: 1, prohibited: 2 };
  let worst = 'allowed';
  for (const k of ADAPTATION_KEYS) {
    const v = permissions && PERMISSION_VALUES.includes(permissions[k]) ? permissions[k] : 'permission_required';
    if (rank[v] > rank[worst]) worst = v;
  }
  return worst;
}
export function adaptationCase(permissions) {
  const v = adaptationValue(permissions);
  return v === 'allowed' ? 'allowed' : v === 'prohibited' ? 'prohibited' : 'ask';
}

// 도름스 앱 주소 검증: https://dorms.school/apps/<uuid> 또는 /arcade/<uuid> 만. 그 밖은 모두 거부.
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const DORMS_RE = new RegExp(`^https://dorms\\.school/(apps|arcade)/(${UUID})/?$`, 'i');
export function validateDormsAppUrl(input) {
  if (typeof input !== 'string') return { ok: false };
  const s = input.trim();
  if (!s || s.length > 120) return { ok: false };
  const m = DORMS_RE.exec(s);
  if (!m) return { ok: false };
  return { ok: true, url: `https://dorms.school/${m[1].toLowerCase()}/${m[2].toLowerCase()}` };
}

// 저작권법 조문(korean-law MCP 로 현행 조문 제목·존재 확인: 2026-11-17, MST 285693, 시행 2026-10-29).
export const LAW_ARTICLES = [
  { key: '12', jo: '제12조', title: '성명표시권' },
  { key: '16', jo: '제16조', title: '복제권' },
  { key: '18', jo: '제18조', title: '공중송신권' },
  { key: '20', jo: '제20조', title: '배포권' },
  { key: '22', jo: '제22조', title: '2차적저작물작성권' },
  { key: '35-5', jo: '제35조의5', title: '저작물의 공정한 이용' },
  { key: '37', jo: '제37조', title: '출처의 명시' },
  { key: '136', jo: '제136조', title: '벌칙' },
];
export function lawUrl(jo) { return `https://www.law.go.kr/법령/저작권법/${jo}`; }

// 프로필 글자를 안내에 넣기 전 한 줄로 정리한다: 제어 문자(줄바꿈 포함)·보이지 않는 방향 문자 제거,
// HTML 주석 표식(<!-- -->) 제거, 공백 합치기, 길이 제한. 이렇게 하면 AGENTS.md 블록 표식을 끊거나
// 줄 머리(## 제목·명령 줄)를 끼워 넣을 수 없다.
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;
export function oneLine(value, max = 200) {
  if (value === null || value === undefined) return '';
  let s = String(value).replace(CONTROL_RE, ' ');
  for (let i = 0; i < 3; i++) s = s.replace(/<!--|-->|<!-|--!>/g, ' ');
  s = s.replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max).trim() : s;
}
export function hasControlChars(value) { CONTROL_RE.lastIndex = 0; return CONTROL_RE.test(String(value)); }

// 이름이 이미 '선생님'·'쌤'으로 끝나면 '선생님'을 또 붙이지 않는다("홍길동선생님 선생님" 겹침 막기).
const TITLE_SUFFIX_RE = /(선생님|쌤)$/;
export function creatorWithTitle(creator) {
  if (!creator) return t('creator.unknown');
  return TITLE_SUFFIX_RE.test(creator) ? creator : t('creator.withTitle', { creator });
}

// 덧붙인 조건 가운데 AI 에게 일을 시키는 문장은 이용 안내에 싣지 않는다(0.5.2, 회원 검토 허점 11).
// 이용 안내 화면은 베끼는 사람의 AI 가 읽는 자리라, 조건 칸이 그 AI 에게 명령을 보내는 통로가 되면 안 된다.
// 사람에게 하는 부탁(예: '학급 밖 행사에서 쓸 때는 미리 알려 주세요')은 그대로 둔다.
const AI_ADDRESS_RE = /(\bAI\b|에이아이|인공지능|챗봇|어시스턴트|assistant|agent|에이전트|LLM|GPT|Claude|클로드|Codex|코덱스|Gemini|제미나이|copilot|코파일럿|모델\s*(?:에게|께|은|는))/i;
const AI_COMMAND_RE = /(무시(?:하|해)|ignore\s+(?:all|any|the|previous|prior|above)|disregard|forget\s+(?:all|previous|your)|override|system\s*prompt|시스템\s*프롬프트|지시(?:사항|문)?\s*(?:을|를)?\s*(?:무시|따르지)|명령(?:을|를)?\s*(?:실행|따라)|(?:명령|코드|스크립트)(?:을|를)?\s*실행|\brun\s+(?:this|the|a)\b|execute|curl\s|rm\s+-)/i;
const EXFIL_RE = /(붙여\s*넣|paste|보내|send\b|upload|업로드|읽어|print|출력|알려\s*(?:줘|주)|공유해|copy|복사)/i;
const SECRET_TARGET_RE = /(~\/|\.ssh|id_rsa|\.env\b|\.git\b|\/etc\/|passwd|비밀\s*번호|패스워드|password|토큰|token|api[_\s-]?key|키\s*값|secret|자격\s*증명|credential|쿠키|cookie|환경\s*변수)/i;
export function isAiInstructionClause(value) {
  const s = String(value || '');
  if (!s.trim()) return false;
  if (SECRET_TARGET_RE.test(s) && (EXFIL_RE.test(s) || AI_COMMAND_RE.test(s))) return true;
  if (AI_ADDRESS_RE.test(s) && AI_COMMAND_RE.test(s)) return true;
  if (/(ignore|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts?)/i.test(s)) return true;
  return false;
}
export function splitUserClauses(list) {
  const kept = [];
  const dropped = [];
  for (const c of Array.isArray(list) ? list : []) {
    const line = oneLine(c, 300);
    if (!line) continue;
    (isAiInstructionClause(line) ? dropped : kept).push(line);
  }
  return { kept: kept.slice(0, 10), dropped };
}

// 권리 프로필 → 안내를 만드는 데 필요한 사실 묶음(문구 아님).
export function provenanceFacts(profile, { year = new Date().getFullYear() } = {}) {
  const p = profile || {};
  const creator = oneLine(p.rightsholder && p.rightsholder.displayName, 100);
  const creatorTitle = creatorWithTitle(creator);
  const dormsUrl = p.dormsAppUrl && validateDormsAppUrl(p.dormsAppUrl).ok ? validateDormsAppUrl(p.dormsAppUrl).url : '';
  const appName = oneLine(p.appName, 100);
  const permissions = { ...(p.permissions || {}) };
  permissions.shareDormsLink = 'allowed';
  const kase = adaptationCase(profile ? p.permissions : null);
  // 도름스 주소가 없으면 '도름스'를 적지 않는다(도름스에 올라가 있다고 잘못 알리지 않게).
  const sl = dormsUrl ? 'sourceLine' : 'sourceLineNoDorms';
  const sourceLine = appName ? t(sl + '.withApp', { appName, creatorTitle }) : t(sl + '.text', { creatorTitle });
  const provenanceId = sha256(`dorms-check:${dormsUrl || ''}:${creator}:${appName}`).slice(0, 16);
  const preset = PRESET_ID_SET.has(p.preset) ? p.preset : '';
  return {
    creator, creatorTitle, creatorEn: creator || 'the creator', dormsUrl, appName,
    appTitle: appName || creatorTitle, permissions, case: kase, sourceLine, provenanceId, year,
    contact: oneLine(p.attribution && p.attribution.text, 200),
    attributionRequired: p.attribution ? p.attribution.required !== false : true,
    attributionMethod: oneLine(p.attribution && p.attribution.method, 200),
    userClauses: splitUserClauses(p.userClauses).kept,
    droppedClauses: splitUserClauses(p.userClauses).dropped,
    preset,
    policyVersion: oneLine(p.policyVersion, 40),
  };
}
const PRESET_ID_SET = new Set(['edu_share', 'restricted', 'open_collab', 'custom']);

// 표에 보일 행(도름스 순서). 값이 없는 항목은 '먼저 허락'으로 보인다(미설정 = 먼저 허락).
export function permissionRows(permissions) {
  // 예전 전용 키 shareLockedAccess 는 프로필에만 남기고 화면·안내에는 도름스 열두 항목만 보인다.
  return DORMS_PERMISSION_ORDER.map(key => {
    const value = LOCKED_ALLOWED.has(key) ? 'allowed'
      : (permissions && PERMISSION_VALUES.includes(permissions[key]) ? permissions[key] : 'permission_required');
    return { key, label: t('permissionActions.' + key), value, valueLabel: t('permissionValues.' + value) };
  });
}

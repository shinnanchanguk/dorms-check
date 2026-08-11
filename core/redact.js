// 제출 페이로드 마스킹(redact) — v2 제출(report.json)에서 시크릿·개인 경로가 밖으로 나가지 않게.
// 시크릿 패턴은 checks/static/secrets.js 의 SECRET_PATTERNS 를 재사용한다(SSOT).
// 원칙: 관측 사실(어디서 몇 건)은 남기고, 값 원문·개인 식별 경로는 가린다.
import { SECRET_PATTERNS } from '../checks/static/secrets.js';

// 추가 마스킹 패턴(시크릿 외 — 경로·저장소·PIN 후보)
const EXTRA_PATTERNS = [
  // JWT (SECRET_PATTERNS 의 service_role 은 라벨 조건이 붙어 있어 일반 JWT 를 따로 잡는다)
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{6,})?\b/g },
  // 4~6자리 PIN 후보(문맥 있는 것만 — 숫자 단독은 오탐이라 안 잡는다)
  { name: 'PIN 후보', re: /\b(?:pin|otp|passcode|비밀번호|인증번호)\s*[:=]?\s*["']?\d{4,6}["']?/gi },
  // 절대 경로(macOS·리눅스 홈·Windows) — 사용자명 노출 방지
  { name: '절대 경로', re: /(?:\/Users\/[^\s"'`,)\]}]+|\/home\/[^\s"'`,)\]}]+|[A-Za-z]:\\[^\s"'`,)\]}]+)/g },
  // 비공개일 수 있는 저장소 주소(ssh·https 원격) — 저장소명 노출 방지
  { name: '저장소 주소', re: /(?:git@[\w.-]+:[\w./-]+(?:\.git)?|https?:\/\/(?:github|gitlab|bitbucket)\.[\w.-]+\/[\w-]+\/[\w.-]+)/g },
];

function toGlobal(re) {
  return new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
}

// 문자열 하나를 마스킹. 매치는 종류 라벨로 치환한다(원문 미보존).
export function redactString(s) {
  if (typeof s !== 'string' || !s) return s;
  let out = s;
  for (const p of SECRET_PATTERNS) {
    // extra 조건이 붙은 패턴(예: service_role 단어 매치)은 단어 자체가 시크릿이 아니므로 건너뛴다.
    // 실제 토큰(JWT 등)은 아래 EXTRA_PATTERNS 가 잡는다.
    if (p.extra) continue;
    out = out.replace(toGlobal(p.re), `[마스킹:${p.name}]`);
  }
  for (const p of EXTRA_PATTERNS) {
    out = out.replace(toGlobal(p.re), `[마스킹:${p.name}]`);
  }
  return out;
}

// 객체/배열을 깊이 순회하며 모든 문자열 값을 마스킹한 사본을 반환.
export function redactDeep(value, depth = 0) {
  if (depth > 20) return value; // 순환·과깊이 방어
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map(v => redactDeep(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v, depth + 1);
    return out;
  }
  return value;
}

// 제출 페이로드 전용: 앱 주소(app.url)는 서버 재검증에 필요하므로 마스킹에서 제외한다.
export function redactPayload(payload) {
  const appUrl = payload?.app?.url ?? null;
  const out = redactDeep(payload);
  if (out && out.app) out.app.url = appUrl;
  return out;
}

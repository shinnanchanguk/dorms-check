// Supabase 프로젝트 운영 설정 읽기(선택). 학교 운영 보안 절차(catalog/school-ops.js)의 지금 상태를 본다.
// 선생님이 `dcheck ops --supabase-config` 로 명시했고 SUPABASE_ACCESS_TOKEN 환경 변수가 있을 때만
// api.supabase.com 에 GET 요청만 보낸다. 설정을 바꾸지 않고, 토큰·키·IP 목록 원문을 출력하거나 저장하지 않는다.
import fs from 'node:fs';
import path from 'node:path';

const API = 'https://api.supabase.com/v1/projects/';
const REF_RE = /^[a-z0-9]{20}$/;
const ENDPOINTS = {
  auth: '/config/auth',
  ssl: '/ssl-enforcement',
  network: '/network-restrictions',
  backups: '/database/backups',
  advisors: '/advisors/security',
};

function readSmall(p) {
  try {
    const st = fs.lstatSync(p);
    if (!st.isFile() || st.size > 256 * 1024) return null;
    return fs.readFileSync(p, 'utf8');
  } catch { return null; }
}

// 프로젝트 번호(ref)는 비밀이 아니다. supabase/.temp/project-ref 또는 env 파일의 *.supabase.co 주소에서만 읽는다.
// 출처가 여러 곳이고 서로 다르면 conflict 로 알려 --supabase-ref 로 고르게 한다(남의 저장소가 다른 번호를 심어 둔 경우).
export function detectSupabaseRef(root) {
  const found = [];
  const linked = (readSmall(path.join(root, 'supabase', '.temp', 'project-ref')) || '').trim();
  if (REF_RE.test(linked)) found.push({ ref: linked, from: 'supabase/.temp/project-ref' });
  for (const name of ['.env.local', '.env', '.env.production', '.env.development']) {
    const text = readSmall(path.join(root, name));
    if (!text) continue;
    const m = /https:\/\/([a-z0-9]{20})\.supabase\.co\b/.exec(text);
    if (m) found.push({ ref: m[1], from: name });
  }
  const refs = [...new Set(found.map(f => f.ref))];
  if (!found.length) return { ref: null, from: null, conflict: false };
  return { ref: found[0].ref, from: found[0].from, conflict: refs.length > 1, candidates: found };
}

export async function readSupabaseConfig({ ref, token, timeoutMs = 8000, fetchImpl = globalThis.fetch } = {}) {
  if (!REF_RE.test(String(ref || ''))) return { ok: false, reason: 'Supabase 프로젝트 번호(ref)를 찾지 못했어요.' };
  if (!token || typeof token !== 'string' || token.length < 20) return { ok: false, reason: 'SUPABASE_ACCESS_TOKEN 이 없어요.' };
  const raw = {};
  const errors = {};
  await Promise.all(Object.entries(ENDPOINTS).map(async ([key, p]) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetchImpl(API + ref + p, { method: 'GET', headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' }, signal: ctrl.signal, redirect: 'error' });
      if (!res.ok) { errors[key] = res.status; return; }
      const text = await res.text();
      if (text.length > 2 * 1024 * 1024) { errors[key] = 'too-large'; return; }
      raw[key] = JSON.parse(text);
    } catch { errors[key] = 'network'; }
    finally { clearTimeout(timer); }
  }));
  const denied = Object.values(errors).some(v => v === 401 || v === 403);
  if (!Object.keys(raw).length) return { ok: false, reason: denied ? '토큰으로 이 프로젝트 설정을 읽을 권한이 없어요.' : 'Supabase 설정을 읽지 못했어요.', errors };
  return { ok: true, raw, errors };
}

const num = v => (v == null || v === '' ? null : Number(v));

// 읽은 설정을 운영 절차별 상태로 바꾼다(순수 함수, 시험 가능).
// 상태: on(갖춤) · partial(일부) · off(안 됨) · unknown(못 봄). observed 는 쉬운 말, 원문 값(IP·토큰)은 넣지 않는다.
export function mapSupabaseConfig(raw = {}) {
  const out = {};
  const set = (id, state, observed) => { out[id] = { state, observed, source: 'Supabase 설정' }; };
  const a = raw.auth;
  if (a) {
    const min = num(a.password_min_length);
    const req = String(a.password_required_characters || '');
    const symbols = /[!@#$%^&*]/.test(req) && /[0-9]/.test(req) && /[A-Z]/.test(req);
    const hibp = a.password_hibp_enabled === true;
    if (min != null && min >= 8 && symbols) set('ops.password-rules', 'on', `인증 서버 최소 ${min}자, 대·소문자·숫자·특수문자 필수${hibp ? ', 유출 비밀번호 차단 켜짐' : ', 유출 비밀번호 차단 꺼짐(Pro 이상에서 켤 수 있음)'}`);
    else set('ops.password-rules', 'off', `인증 서버 최소 ${min ?? '?'}자, 문자 조건 ${symbols ? '있음' : '특수문자·숫자·대문자 필수 아님'}`);

    const totp = a.mfa_totp_enroll_enabled === true && a.mfa_totp_verify_enabled === true;
    set('ops.admin-mfa', totp ? 'partial' : 'off', totp ? '인증 앱(TOTP) 2단계 인증 기능은 켜져 있음. 앱에 등록·확인 화면과 관리자 화면의 2단계 확인이 있어야 실제로 적용돼요' : '2단계 인증(TOTP) 기능이 꺼져 있음');

    const idle = num(a.sessions_inactivity_timeout) || 0;
    const box = num(a.sessions_timebox) || 0;
    set('ops.idle-logout', idle > 0 ? 'on' : box > 0 ? 'partial' : 'off', idle > 0 || box > 0
      ? `로그인 유지 제한 있음(${[idle > 0 && '미사용 시간 제한', box > 0 && '최대 유지 시간'].filter(Boolean).join(', ')} 설정됨, 값은 대시보드 Authentication > Sessions 에서 확인)${idle > 0 ? '' : '. 최대 유지 시간만으로는 "안 쓰면 로그아웃"이 아니에요'}`
      : '인증 서버의 미사용 로그아웃·최대 유지 시간이 꺼져 있음(앱 화면에서 따로 할 수도 있음)');

    const hook = a.hook_password_verification_attempt_enabled === true;
    const captcha = a.security_captcha_enabled === true;
    set('ops.lockout', hook || captcha ? 'partial' : 'unknown', hook
      ? '인증 서버의 비밀번호 확인 훅이 켜져 있음(훅이 실제로 5회 실패에 잠그는지는 훅 코드에서 확인)'
      : `인증 서버 자체 잠금 설정은 없음${captcha ? ', CAPTCHA 켜짐' : ''}. 앱 코드에 잠금 기능이 있는지로 판단해요`);

    const limits = ['rate_limit_verify', 'rate_limit_token_refresh', 'rate_limit_otp', 'rate_limit_email_sent'].filter(k => num(a[k]) > 0).length;
    if (limits) set('ops.rate-limit', 'partial', `로그인 서버의 IP별 요청 횟수 제한 ${limits}종이 설정돼 있음(Authentication > Rate Limits). 앱의 로그인 전 함수·내려받기 횟수 제한은 코드에서 따로 봐요`);

    const site = String(a.site_url || '');
    const allow = String(a.uri_allow_list || '');
    const localSite = !site || /localhost|127\.0\.0\.1|^http:\/\//i.test(site);
    const wide = /(^|,)\s*\*\s*(,|$)|https?:\/\/\*\*|\*\.(vercel\.app|netlify\.app|pages\.dev|github\.io)/.test(allow);
    set('ops.auth-site-url', localSite ? 'off' : (wide ? 'partial' : 'on'), localSite
      ? '로그인 메일 링크의 기본 주소(Site URL)가 운영 주소가 아니에요(localhost 또는 http)'
      : wide ? '기본 주소는 운영 주소지만 돌아올 주소 허용 목록이 너무 넓어요' : '로그인 메일 링크 주소가 운영 주소로 맞춰져 있음');
  }
  if (raw.ssl) {
    const on = raw.ssl?.currentConfig?.database === true;
    set('ops.db-ssl', on ? 'on' : 'off', on ? 'DB 직접 접속은 암호화 연결만 받음' : 'DB 직접 접속이 암호화 없는 연결도 받음(켜면 DB 가 한 번 재시작돼요)');
  }
  if (raw.network) {
    const v4 = raw.network?.config?.dbAllowedCidrs || [];
    const v6 = raw.network?.config?.dbAllowedCidrsV6 || [];
    const prefix = c => Number(String(c).split('/')[1] ?? 128);
    const open = (!v4.length && !v6.length) || v4.some(c => prefix(c) < 8) || v6.some(c => prefix(c) < 16);
    set('ops.db-ip-allowlist', open ? 'off' : 'on', open ? 'DB 직접 접속을 모든 곳(IP)에서 받음' : `DB 직접 접속 허용 목록 ${v4.length + v6.length}개로 제한됨`);
  }
  if (raw.backups) {
    const b = raw.backups;
    const n = Array.isArray(b.backups) ? b.backups.length : 0;
    set('ops.backup', n || b.pitr_enabled ? 'on' : 'off', n || b.pitr_enabled
      ? `자동 백업 ${n}개 보관${b.pitr_enabled ? ', 특정 시각 되돌리기(PITR) 켜짐' : ', 특정 시각 되돌리기(PITR)는 꺼짐'}. 복구 연습은 따로 확인해요`
      : '자동 백업이 보이지 않음(무료 요금제면 직접 백업해야 해요)');
  }
  if (raw.advisors) {
    const lints = Array.isArray(raw.advisors.lints) ? raw.advisors.lints : [];
    const errors = lints.filter(l => l.level === 'ERROR');
    const warns = lints.filter(l => l.level === 'WARN');
    const anonFns = lints.filter(l => l.name === 'anon_security_definer_function_executable').length;
    const noRls = lints.filter(l => l.name === 'rls_disabled_in_public').length;
    set('ops.security-advisor', errors.length ? 'off' : warns.length ? 'partial' : 'on',
      `보안 경고 ERROR ${errors.length}개 · WARN ${warns.length}개${noRls ? ` (RLS 꺼진 공개 표 ${noRls}개)` : ''}${anonFns ? ` (로그인 없이 실행되는 함수 ${anonFns}개)` : ''}`);
  }
  return out;
}

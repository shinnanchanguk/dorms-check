// 학교 운영 보안 절차: 지금 상태(코드 흔적 + 선택한 Supabase 설정 읽기 + 지난 scan 결과) + 선생님 결정을 모아
// 선생님이 하나씩 고를 수 있는 안내(OPS.md)와 학교 서류 대응표 초안(SCHOOL-SELFCHECK.md)을 만든다.
// 이 결과는 점검 마크와 무관하고, 어떤 항목도 강제하지 않는다. 앱 소스는 바꾸지 않는다.
import fs from 'node:fs';
import path from 'node:path';
import { SCHOOL_OPS, SHEET2_ROWS, SHEET3_ROWS, OPS_CHOICES } from '../catalog/school-ops.js';
import { walk, readJsonSafe } from './util.js';
import { sqlFiles, parseToml } from '../checks/static/supabase-sql.js';

const CODE_EXT = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
const MAX_BYTES = 2 * 1024 * 1024;
export const OPS_DECISIONS_FILE = 'ops-decisions.json';

function readCapped(p) {
  try {
    const st = fs.lstatSync(p);
    if (!st.isFile() || st.size > MAX_BYTES) return '';
    return fs.readFileSync(p, 'utf8');
  } catch { return ''; }
}

// 코드·마이그레이션에서 운영 절차의 흔적을 찾는다. 흔적은 "있을 수 있다"는 뜻이지 제대로 동작한다는 증명이 아니다.
const TOTAL_BYTES = 64 * 1024 * 1024; // 저장소 전체에서 읽는 양의 상한(큰 저장소에서 멈추지 않게)
const SIGNALS = {
  lockout: ['both', /failed_login|login_attempt|login_failure|lockout|locked_until|password_verification_attempt/i],
  captcha: ['code', /captchaToken|turnstile|hcaptcha/i],
  mfa: ['both', /\bauth\.mfa\b|mfa\.(enroll|challenge|verify)|\baal2\b/],
  idle: ['code', /(idle|inactivity)[\w-]{0,40}(timeout|logout|timer)/i],
  accessLog: ['both', /\b(access_logs?|audit_logs?|activity_logs?|access_log_entries)\b/i],
  permissionHistory: ['both', /\b(permission|role|grant|privilege)_?(history|changes?|audit|logs?)\b/i],
  downloadReason: ['both', /download_(reason|logs?)|export_(reason|logs?)|내려받기\s*사유/i],
  rateLimit: ['both', /rate.?limit|@upstash\/ratelimit|too\s+many\s+requests|status\s*[:(=]\s*429\b/i],
  supabaseAuth: ['code', /\.auth\.(signInWithPassword|signUp|signInWithOtp|signInWithOAuth|getUser|getSession)\b/],
  directDb: ['code', /from\s+['"](pg|postgres|@prisma\/client|drizzle-orm[^'"]*|@neondatabase\/serverless)['"]|require\(\s*['"](pg|postgres)['"]\s*\)|process\.env\.(DATABASE_URL|POSTGRES_URL|DIRECT_URL)/],
  selectAll: ['code', /\.select\(\s*(?:['"`]\*['"`])?\s*\)|\.select\(\s*['"`]\s*\*\s*,/],
  retention: ['both', /\bpurge|retention|cron\.schedule|expire_old|delete_expired|graduat\w*_(cleanup|purge|delete)/i],
  accountDisable: ['code', /auth\.admin\.(deleteUser|updateUserById)|ban_duration|deactivate_?(user|account)|is_active\s*[:=]|softDelete/i],
};

export function opsCodeSignals(root) {
  const out = Object.fromEntries(Object.keys(SIGNALS).map(k => [k, false]));
  let budget = TOTAL_BYTES;
  const scanFiles = (files, kind) => {
    for (const f of files) {
      if (budget <= 0) break;
      const text = readCapped(f);
      budget -= text.length;
      for (const [k, [where, re]] of Object.entries(SIGNALS)) {
        if (!out[k] && (where === 'both' || where === kind) && re.test(text)) out[k] = true;
      }
    }
  };
  scanFiles(sqlFiles(root), 'sql');
  scanFiles(walk(root, { exts: CODE_EXT, maxFiles: 6000 }), 'code');
  // scan 쪽(ops.school-selfcheck)과 같게 supabase/config.toml 의 설정도 흔적으로 본다.
  const toml = parseToml(readCapped(path.join(root, 'supabase', 'config.toml')));
  if (toml['auth.mfa.totp']?.enroll_enabled === 'true') out.mfa = true;
  if (toml['auth.captcha']?.enabled === 'true') out.captcha = true;
  if (toml['auth.sessions']?.inactivity_timeout != null) out.idle = true;
  return out;
}

const STATE_LABEL = { on: '갖춤', partial: '일부 갖춤', off: '안 됨', none: '흔적 없음', unknown: '확인 못 함', manual: '선생님 확인 필요' };

function codeState(id, s) {
  switch (id) {
    case 'ops.lockout': return s.lockout ? ['partial', '코드에 로그인 실패를 세거나 잠그는 흔적이 있음(5회 잠금·관리자 해제가 되는지 직접 확인)'] : [s.captcha ? 'partial' : 'none', s.captcha ? '코드에 CAPTCHA 흔적은 있으나 실패 횟수 잠금 흔적은 없음' : '코드에서 로그인 실패 잠금 흔적을 찾지 못함'];
    case 'ops.admin-mfa': return s.mfa ? ['partial', '코드에 2단계 인증(mfa·aal2) 흔적이 있음(관리자 화면이 aal2 만 받는지 확인)'] : ['none', '코드에서 2단계 인증 흔적을 찾지 못함'];
    case 'ops.idle-logout': return s.idle ? ['partial', '코드에 미사용 로그아웃 흔적이 있음'] : ['none', '코드에서 미사용 로그아웃 흔적을 찾지 못함'];
    case 'ops.access-log': return s.accessLog ? ['partial', '코드·DB에 접속기록 표 흔적이 있음(보관 기간·고치기 막기·월간 점검은 직접 확인)'] : ['none', '코드·DB에서 접속기록 표를 찾지 못함'];
    case 'ops.permission-history': return s.permissionHistory ? ['partial', '권한 변경 이력 표 흔적이 있음(3년 보관·고치기 막기 확인)'] : ['none', '권한 변경 이력 표를 찾지 못함'];
    case 'ops.download-reason': return s.downloadReason ? ['partial', '내려받기 기록·사유 흔적이 있음'] : ['none', '내려받기 기록·사유 흔적을 찾지 못함(내려받기 기능이 없으면 해당 없음)'];
    case 'ops.rate-limit': return s.rateLimit ? ['partial', '코드에 요청 횟수 제한 흔적이 있음'] : ['none', '코드에서 요청 횟수 제한 흔적을 찾지 못함'];
    case 'ops.minimal-response': return s.selectAll ? ['off', '코드에 모든 칸을 받는 select(\'*\') 또는 select() 가 있음. 학생 정보를 받는 곳이면 필요한 칸만 받게 바꿔요'] : ['partial', '모든 칸을 받는 select(\'*\') 흔적은 없음(DB 규칙이 역할별로 좁혀져 있는지는 따로 확인)'];
    case 'ops.data-retention': return s.retention ? ['partial', '오래된 정보를 지우는 작업 흔적이 있음(보관 기간·파일 삭제·파기 기록 확인)'] : ['none', '보관 기간이 지난 정보를 지우는 작업 흔적을 찾지 못함'];
    case 'ops.stale-accounts': return [s.accountDisable ? 'manual' : 'none', s.accountDisable ? '계정 사용 중지·삭제 기능 흔적이 있음. 시험용·오래 안 쓴 계정이 남아 있는지는 DB 에서 확인' : '계정 사용 중지·삭제 기능 흔적을 찾지 못함'];
    default: return null;
  }
}

// 두 근거(코드·설정)를 합친다. 설정이 on 이면 on, 둘 중 하나라도 흔적이 있으면 partial, 둘 다 없으면 off.
function combine(a, b) {
  const rank = { on: 5, partial: 4, manual: 3, off: 2, none: 1, unknown: 0 };
  if (!a) return b; if (!b) return a;
  return rank[a.state] >= rank[b.state] ? a.state : b.state;
}

export function readOpsDecisions(stateDir) {
  const j = readJsonSafe(path.join(stateDir, OPS_DECISIONS_FILE));
  return j && typeof j === 'object' && !Array.isArray(j) ? j : {};
}

export function cleanReason(text) {
  return String(text ?? '').replace(/[\u0000-\u001F\u007F-\u009F؜​-‏‪-‮⁦-⁩﻿]+/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, 300);
}

// 결정 하나를 검증해 돌려준다(쓰기는 호출한 쪽이 safeWrite 로).
export function makeDecision({ id, choice, reason }) {
  if (!SCHOOL_OPS.some(o => o.id === id)) return { ok: false, reason: `알 수 없는 항목: ${cleanReason(id)} (dcheck ops 로 목록 확인)` };
  if (!Object.hasOwn(OPS_CHOICES, choice)) return { ok: false, reason: `--choice 는 ${Object.keys(OPS_CHOICES).join('|')} 중 하나` };
  const r = cleanReason(reason);
  if ((choice === 'skip' || choice === 'done') && r.length < 4) return { ok: false, reason: choice === 'skip' ? '하지 않기로 할 때는 학교 서류에 쓸 사유(--reason)를 적어 주세요.' : '이미 했다면 무엇으로 했는지(--reason, 예: 화면·설정 이름)를 적어 주세요.' };
  return { ok: true, value: { choice, reason: r, at: new Date().toISOString() } };
}

// 파일에서 읽은 결정도 CLI 로 기록할 때와 같은 조건을 다시 통과해야 화면·서류에 나온다
// (남의 저장소가 .dorms-check/ops-decisions.json 을 미리 심어 둘 수 있다).
function validDecision(d) {
  if (!d || typeof d !== 'object' || typeof d.choice !== 'string' || !Object.hasOwn(OPS_CHOICES, d.choice)) return null;
  const reason = typeof d.reason === 'string' ? cleanReason(d.reason) : '';
  if ((d.choice === 'skip' || d.choice === 'done') && reason.length < 4) return null;
  return { choice: d.choice, reason, at: typeof d.at === 'string' ? cleanReason(d.at).slice(0, 40) : '', label: OPS_CHOICES[d.choice] };
}

export function buildOpsState({ signals, config = {}, decisions = {}, scan = null }) {
  return SCHOOL_OPS.map(item => {
    const notes = [];
    const fromCode = codeState(item.id, signals || {});
    const fromCfg = config[item.id];
    let state = 'unknown';
    if (fromCode && fromCfg) state = combine({ state: fromCode[0] }, fromCfg);
    else if (fromCfg) state = fromCfg.state;
    else if (fromCode) state = fromCode[0];
    else if (item.detect === 'manual') state = 'manual';
    if (fromCfg) notes.push(`설정: ${fromCfg.observed}`);
    if (fromCode) notes.push(`코드: ${fromCode[1]}`);
    if (item.detect === 'config' && !fromCfg) notes.push('Supabase 설정을 읽지 않아 지금 값은 모름(dcheck ops --supabase-config 또는 대시보드에서 확인)');
    if (item.id === 'ops.db-ip-allowlist' && signals) notes.push(signals.directDb ? '주의: 앱 코드가 DB 에 직접 붙는 흔적이 있어요(pg·prisma·DATABASE_URL 등). IP 를 묶으면 호스팅 서버가 막힐 수 있어요' : '앱 코드가 DB 에 직접 붙는 흔적은 없어요(화면·REST API 는 IP 제한을 받지 않아요)');
    if (item.id === 'ops.password-rules' && scan) {
      const pw = (Array.isArray(scan.results) ? scan.results : []).find(r => r && r.id === 'auth.password-policy');
      if (pw && typeof pw.observed === 'string') notes.push(`지난 scan: ${cleanReason(pw.observed)}`);
    }
    if (item.id === 'ops.vuln-check' && scan) notes.push(`지난 scan: ${typeof scan.at === 'string' ? cleanReason(scan.at.slice(0, 10)) : '날짜 모름'}`);
    return { ...item, state, stateLabel: STATE_LABEL[state], notes, decision: validDecision(decisions[item.id]) };
  });
}

// scan.json 은 저장 전에 정규화돼서, 노출이 확인된 항목이 아니면 'fail' 이 'info' 로 바뀐다.
// 그래서 상태 글자만 보지 않고 "문제를 짚은 근거(hits)가 있는가"로 판정한다.
function scanFinding(scan, id) {
  const r = (Array.isArray(scan?.results) ? scan.results : []).find(x => x && x.id === id);
  if (!r) return null;
  const hits = Array.isArray(r.evidence?.hits) ? r.evidence.hits.length : 0;
  if (r.status === 'fail') return 'bad';
  // RLS 를 켜는 문장이 마이그레이션에 없다는 것만으로는 위험이 확인된 게 아니다(대시보드에서 켰을 수 있다).
  if (id === 'code.rls.anon-write' && hits > 0 && r.evidence.hits.every(h => /RLS 꺼짐$/.test(String(h?.kind || '')))) return 'check';
  if (r.status === 'info' && hits > 0) return 'bad';
  if (r.status === 'pass') return 'good';
  if (r.status === 'na') return 'na';
  return null;
}

// 표시의 나쁜 정도. 여러 근거를 합칠 때 더 나쁜 쪽을 고른다.
const MARK_RANK = { 'X': 5, 'X 또는 보완': 4, '확인 필요': 3, '해당없음 후보': 2, '해당없음 또는 O(확인 후)': 1, 'O(확인 후)': 0 };

function judgeItems(rowItems) {
  if (!rowItems.length) return null;
  const skip = rowItems.find(i => i.decision?.choice === 'skip');
  if (skip) return { mark: 'X', why: `${skip.title}: ${skip.decision.reason}` };
  const done = rowItems.every(i => i.state === 'on' || i.decision?.choice === 'done');
  if (done) return { mark: 'O(확인 후)', why: rowItems.map(i => i.decision?.choice === 'done' ? `${i.title}: ${i.decision.reason}` : `${i.title}: ${i.notes[0] || '갖춤'}`).join(' / ') };
  const off = rowItems.find(i => i.state === 'off');
  if (off) return { mark: 'X 또는 보완', why: `${off.title}: ${off.notes.find(n => n.startsWith('설정')) || off.notes[0] || '안 됨'}. 할지 말지 정한 뒤 다시 실행하세요` };
  const none = rowItems.find(i => i.state === 'none');
  if (none) return { mark: '확인 필요', why: `${none.title}: ${none.notes[0] || '흔적 없음'}. 코드에서 못 찾았을 뿐 없다는 뜻은 아니에요. 없다면 할지 말지 정해요` };
  return { mark: '확인 필요', why: rowItems.map(i => `${i.title}: ${i.notes[0] || i.stateLabel}`).join(' / ') };
}

// 고정 근거(scan·일반 사실)와 항목 판정을 합친다. 선생님의 skip 은 늘 X 로 남고, 더 나쁜 쪽이 이긴다.
function suggest(rowItems, extra) {
  const fromItems = judgeItems(rowItems);
  const parts = [extra, fromItems].filter(Boolean);
  if (!parts.length) return { mark: '확인 필요', why: '이 도구가 다루지 않는 항목이에요' };
  const worst = parts.reduce((a, b) => ((MARK_RANK[b.mark] ?? 3) > (MARK_RANK[a.mark] ?? 3) ? b : a));
  const why = [worst.why, ...parts.filter(p => p !== worst).map(p => p.why)].join(' / ');
  return { mark: worst.mark, why };
}

const RLS_CHECK = { mark: '확인 필요', why: '마이그레이션에 RLS 를 켜는 문장이 없는 표가 있음. 대시보드에서 켰다면 괜찮아요(Supabase Table Editor 또는 Security Advisor 에서 확인)' };

export function sheetRows(items, scan, signals = {}) {
  const f = id => scanFinding(scan, id);
  const httpsOk = f('sec.transport.https-redirect') === 'good' && f('sec.transport.ssl-valid') === 'good';
  const plain = f('code.plain-sensitive-column');
  const fixed2 = {
    '②': f('code.rls.anon-read') === 'bad' || f('code.rls.anon-write') === 'bad'
      ? { mark: 'X 또는 보완', why: '로그인 없이 읽히거나 고쳐지는 DB 경로가 있음(dcheck status 참고)' }
      : f('code.rls.anon-write') === 'check' ? RLS_CHECK
      : f('code.rls.anon-read') === 'good' ? { mark: 'O(확인 후)', why: '공개 키로 개인정보 표를 읽지 못함(dcheck scan 실측). 역할마다 볼 수 있는 범위가 업무에 맞는지는 직접 확인' } : null,
    '⑦': { mark: '확인 필요', why: '학교망(스쿨넷) 밖 클라우드면 지원청 장비를 거치지 않아요. Vercel·Cloudflare 기본 디도스 방어와 요청 횟수 제한이 전부라면 X 로 두고 사유를 적어요' },
    '⑩': plain === 'bad' ? { mark: 'X', why: '주민번호·비밀번호를 그대로 담는 칸이 있음(dcheck status 참고)' }
      : plain === 'good' ? { mark: '해당없음 또는 O(확인 후)', why: '마이그레이션에 주민번호·비밀번호를 그대로 담는 칸이 없음(고유식별정보를 수집하지 않으면 해당없음)' }
      : { mark: '확인 필요', why: '주민등록번호 등 고유식별정보를 수집하지 않으면 해당없음. dcheck scan 을 돌리면 저장 칸을 살펴봐요' },
    '⑪': plain === 'bad' ? { mark: 'X', why: '비밀번호를 글자 그대로 담는 칸이 있음(dcheck status 참고)' }
      : signals.supabaseAuth ? { mark: 'O(확인 후)', why: `Supabase 로그인(인증 서버)을 써서 비밀번호는 bcrypt 일방향 해시로 저장돼요${plain === 'good' ? '(지난 scan: 앱 DB 에 비밀번호 칸 없음)' : '. 앱 DB 에 비밀번호를 따로 담는 칸이 없는지 dcheck scan 으로 확인하세요'}` }
      : { mark: '확인 필요', why: '로그인을 어떻게 만들었는지 코드에서 확인하지 못했어요. 비밀번호를 직접 저장한다면 bcrypt 같은 일방향 해시인지 확인해요' },
    '⑫': httpsOk ? { mark: 'O(확인 후)', why: '공개 주소가 https 로만 열리고 인증서가 유효함(dcheck scan 실측)' } : null,
    '⑰': { mark: '해당없음 후보', why: '서버는 클라우드 제공사가 관리해요. 앱을 관리하는 선생님 PC 백신은 학교 PC 점검으로 해요' },
    '⑱': { mark: '해당없음 후보', why: '서버 OS 패치는 제공사가 해요. 앱이 쓰는 라이브러리 보안 업데이트(npm audit)는 붙임3 2번과 함께 확인해요' },
    '㉑': { mark: '해당없음 후보', why: '자체 전산실 없이 클라우드 데이터센터를 쓰면 해당없음' },
  };
  const sheet2 = SHEET2_ROWS.map(([no, label]) => {
    let rowItems = items.filter(i => i.sheet2.includes(no));
    let extra = fixed2[no] || null;
    // ⑫ 는 전송 구간 전체를 묻는다. 화면 https 가 확인되면 DB 직접 접속 SSL 은 칸을 X 로 만들지 않고 권고로만 붙인다.
    if (no === '⑫' && httpsOk) {
      const ssl = rowItems.find(i => i.id === 'ops.db-ssl');
      rowItems = rowItems.filter(i => i.id !== 'ops.db-ssl' || i.decision?.choice === 'skip');
      if (ssl && ssl.state !== 'on' && ssl.decision?.choice !== 'skip') extra = { ...extra, why: `${extra.why} / 권고: DB 직접 접속 SSL 강제(${ssl.stateLabel})` };
    }
    const r = suggest(rowItems, extra);
    return { no, label, ...r, items: rowItems.map(i => i.id) };
  });
  const s3extra = {
    '1. 자산 식별·현행화': { mark: '확인 필요', why: '도메인·호스팅·DB 위치·저장소·외부 API·보유 개인정보 종류와 규모를 한 쪽 목록으로 적어 두면 O 로 쓸 수 있어요' },
    '2. 보안 패치 적용': { mark: '확인 필요', why: 'npm audit --omit=dev 로 운영 라이브러리 취약점 0건인지, 프레임워크(Next.js 등)가 최신 보안판인지 확인해요' },
    '3. 접근통제': f('code.rls.anon-read') === 'bad' || f('code.rls.anon-write') === 'bad'
      ? { mark: 'X', why: '로그인 없이 읽히거나 고쳐지는 DB 경로가 확인됨(dcheck status 참고)' }
      : f('code.rls.anon-write') === 'check' ? RLS_CHECK
      : f('code.rls.anon-read') === 'good' ? { mark: 'O(확인 후)', why: '공개 키로 개인정보 표를 읽지 못함(dcheck scan 실측). 주소만으로 열리는 관리자 화면이 없는지도 확인' } : null,
    '4. 보안 취약점 점검·조치': f('storage.upload-limits') === 'bad' ? { mark: 'X 또는 보완', why: '용량·형식 제한이 없는 파일 저장 공간이 있음(dcheck status 참고)' } : null,
  };
  const sheet3 = SHEET3_ROWS.map(({ label, ids }) => {
    const rowItems = items.filter(i => ids.includes(i.id));
    return { label, ...suggest(rowItems, s3extra[label] || null), items: rowItems.map(i => i.id) };
  });
  return { sheet2, sheet3 };
}

const esc = t => cleanReason(t).replace(/\|/g, '\\|');

export function renderOpsMd(items, { configRead = null } = {}) {
  const L = ['# 학교 운영 보안 절차', '',
    '학교 개인정보 자체점검(교육청 공문 붙임2·붙임3)과 「개인정보의 안전성 확보조치 기준」이 묻는 운영 절차를 하나씩 정리했어요. 강제 항목이 아니에요. 지금 상태와 켜면 생기는 일을 보고, 할지 말지 골라 주세요.', '',
    `- Supabase 설정: ${configRead === true ? '읽음(읽기만 함)' : configRead === false ? '읽지 못함' : '읽지 않음(dcheck ops --supabase-config 로 읽을 수 있어요)'}`,
    '- 결정 기록: `dcheck ops decide --id <항목> --choice do|skip|later|done --reason "<사유>"`', '',
    '| 항목 | 지금 상태 | 선생님 결정 |', '|---|---|---|'];
  for (const i of items) L.push(`| ${esc(i.title)} | ${i.stateLabel} | ${i.decision ? esc(i.decision.label + (i.decision.reason ? `: ${i.decision.reason}` : '')) : '아직'} |`);
  L.push('');
  for (const i of items) {
    L.push(`## ${i.title}`, '', `- 항목 번호: \`${i.id}\``,
      `- 학교 서류: ${[...i.sheet2.map(n => `붙임2 ${n}`), ...i.sheet3.map(n => `붙임3 ${n}`)].join(', ') || '직접 대응 칸 없음'}`,
      `- 근거: ${i.law}`, `- 지금 상태: ${i.stateLabel}`, ...i.notes.map(n => `  - ${n}`),
      `- 왜 필요한가: ${i.why}`, `- 하는 법: ${i.how}`, `- 켜면 생기는 일: ${i.side}`, `- 선생님께 묻는 것: ${i.ask}`);
    if (i.skipReason) L.push(`- 하지 않기로 할 때 사유 예시: ${i.skipReason}`);
    L.push(`- 결정: ${i.decision ? `${i.decision.label}${i.decision.reason ? ` (${i.decision.reason})` : ''}` : '아직 정하지 않음'}`, '');
  }
  L.push('> 이 안내는 점검 마크의 조건이 아니고, 법률 판단을 대신하지 않아요. 학교 서류의 최종 표시는 학교 개인정보 담당자와 함께 정해요.');
  return L.join('\n') + '\n';
}

export function renderSelfcheckMd({ sheet2, sheet3 }, { appName = '' } = {}) {
  const L = [`# 학교 개인정보 자체점검 대응표 초안${appName ? ` · ${esc(appName)}` : ''}`, '',
    '교육청 공문 붙임2(개인정보보호 자체 점검표)·붙임3(외부 접속 가능 시스템 점검항목)에 적을 표시의 초안이에요. 도구가 근거를 본 칸만 O 를 제안하고, 그래도 "확인 후"를 붙였어요. X 칸의 사유는 선생님이 `dcheck ops decide` 로 남긴 문장을 그대로 씁니다.', '',
    '## 붙임2 개인정보보호 자체 점검표', '', '| 번호 | 점검 항목 | 제안 표시 | 근거·사유 |', '|---|---|---|---|'];
  for (const r of sheet2) L.push(`| ${r.no} | ${esc(r.label)} | ${r.mark} | ${esc(r.why)} |`);
  L.push('', '## 붙임3 외부 접속 가능 시스템 점검항목', '', '| 구분 | 제안 표시 | 근거·사유 |', '|---|---|---|');
  for (const r of sheet3) L.push(`| ${esc(r.label)} | ${r.mark} | ${esc(r.why)} |`);
  const xs = [...sheet2.filter(r => r.mark === 'X').map(r => [r.no + ' ' + r.label, r.why]), ...sheet3.filter(r => r.mark === 'X').map(r => [r.label, r.why])];
  if (xs.length) {
    L.push('', '## X 항목 사유(서류 끝에 붙이는 표)', '', '| 점검 항목 | X 사유 |', '|---|---|');
    for (const [k, v] of xs) L.push(`| ${esc(k)} | ${esc(v)} |`);
  }
  L.push('', '> 초안이에요. 학교·앱 상황에 맞게 선생님이 고쳐 쓰세요. 사유에 사람 이름·연락처는 적지 않아요.');
  return L.join('\n') + '\n';
}

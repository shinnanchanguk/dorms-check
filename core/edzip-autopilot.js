import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import PDFDocument from 'pdfkit';
import { markdownToHwpx } from 'hwp-convert';
import { detectStack } from './detect.js';
import { ensureDir, exists, readJsonSafe, readTextSafe, sha256, walk, writeText, withinRoot } from './util.js';
import { EDZIP_ITEMS, EDZIP_LEGAL_BASIS } from '../catalog/edzip.js';
import { EDZIP_CONTACTS, EDZIP_OFFICIAL_SOURCES } from '../catalog/edzip-sources.js';

const PACKAGE_ROOT = path.dirname(path.dirname(new URL(import.meta.url).pathname));
const PLAN_REL = path.join('.dorms-check', 'edzip-plan.json');
const PRIVATE_REL = path.join('.dorms-check', 'private', 'edzip');
const TEXT_EXTS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json', '.md', '.html', '.css', '.vue', '.svelte'];
const MAX_READ = 256_000;
const PII_ANSWER_KEYS = new Set(['name', 'email', 'phone', 'school', 'address', 'signature', 'seal']);
const EDZIP_HOSTS = new Set(['edzip.kr', 'www.edzip.kr']);
const EDZIP_ID_RE = /^[a-f0-9]{24}$/i;
const EDZIP_RESPONSE_LIMIT = 2_000_000;
const DOCUMENT_ATTRIBUTION = 'Team DoRm · 교사 홍창욱 제작 · https://dorms.school';

export const EDZIP_PREPARE_QUESTIONS = [
  { id: 'studentData', ask: '학생의 이름·답안·작성물·학습 기록 등을 처리하나요?', values: ['yes', 'no', 'unknown'] },
  { id: 'curriculumContent', ask: '교과 성취기준에 맞춰 제작한 학습 콘텐츠가 앱 안에 포함되나요?', values: ['yes', 'no', 'unknown'] },
  { id: 'externalTransfer', ask: '이용자·학생 정보가 호스팅·데이터베이스·외부 AI 등 학교 밖 서비스로 나가나요?', values: ['yes', 'no', 'unknown'] },
  { id: 'childDirectUse', ask: '만 14세 미만 학생이 직접 가입하거나 이용하나요?', values: ['yes', 'no', 'unknown'] },
  { id: 'publicPrivacyUrl', ask: '외부에서 바로 열 수 있는 개인정보처리방침 주소가 있나요?', values: ['yes', 'no', 'unknown'] },
];

function packageAsset(...parts) {
  const p = path.join(PACKAGE_ROOT, 'assets', ...parts);
  if (!withinRoot(path.join(PACKAGE_ROOT, 'assets'), path.relative(path.join(PACKAGE_ROOT, 'assets'), p))) throw new Error('자산 경로가 패키지 밖을 가리킵니다.');
  return p;
}

function safeRead(file) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_READ) return '';
    return fs.readFileSync(file, 'utf8');
  } catch { return ''; }
}

function inspectProject(root) {
  const detected = detectStack(root);
  const files = walk(root, { exts: TEXT_EXTS, maxFiles: 5000 });
  const evidence = [];
  const patterns = [
    ['supabase', /@supabase\/(?:supabase-js|ssr)|SUPABASE_URL/i],
    ['firebase', /firebase(?:-admin)?|FIREBASE_/i],
    ['openai', /\bopenai\b|OPENAI_API_KEY/i],
    ['anthropic', /\banthropic\b|ANTHROPIC_API_KEY/i],
    ['vercel', /\bvercel\b|VERCEL_URL/i],
    ['student-data', /학생|학번|답안|성취기준|student|learner|assignment|grade/i],
    ['privacy-page', /개인정보\s*처리방침|privacy\s*policy/i],
  ];
  const found = new Map(patterns.map(([id]) => [id, []]));
  for (const file of files) {
    const text = safeRead(file);
    if (!text) continue;
    for (const [id, re] of patterns) {
      if (re.test(text) && found.get(id).length < 12) found.get(id).push(path.relative(root, file));
    }
  }
  for (const [signal, matches] of found) if (matches.length) evidence.push({ signal, files: matches });
  return { detected, evidence, filesScanned: files.length };
}

function canonicalPlan(plan) {
  const clone = structuredClone(plan);
  delete clone.sha256;
  return JSON.stringify(clone, null, 2) + '\n';
}

export function buildEdzipPlan(root) {
  const inspection = inspectProject(root);
  const cfg = readJsonSafe(path.join(root, 'dorms-check.config.json')) || {};
  const privacySignal = inspection.evidence.find(x => x.signal === 'privacy-page');
  const pkg = readJsonSafe(path.join(root, 'package.json')) || {};
  const plan = {
    schemaVersion: 2,
    createdAt: new Date().toISOString(),
    root: '.',
    app: {
      name: cfg.app?.name || path.basename(root),
      url: cfg.app?.url || '',
      stack: cfg.app?.stack || inspection.detected.framework,
      description: cfg.app?.description || cfg.app?.tagline || pkg.description || '',
    },
    inspection,
    questions: EDZIP_PREPARE_QUESTIONS,
    proposedChanges: [
      { path: '.gitignore', action: 'append-if-missing', detail: '.dorms-check/private/ 생성물 Git 추적 차단' },
      { path: privacySignal?.files?.[0] || 'docs/privacy-policy.md', action: privacySignal ? 'review-and-supplement-by-agent' : 'create-by-agent', detail: '실제 데이터 흐름에 맞는 공개 개인정보처리방침' },
      { path: `${PRIVATE_REL}/YYYY-MM-DD/`, action: 'generate', detail: '에듀집 제출용 HWPX·PDF·Markdown 서류와 공식 원본·출처 복사본' },
    ],
    guardrails: [
      '개인정보·연락처·학교·서명·인영은 수집하지 않고 문서 빈칸으로 남긴다.',
      '외부 제출·배포·메시지 발송은 하지 않는다.',
      '적용은 이 계획의 sha256과 --confirm-apply가 모두 맞을 때만 한다.',
    ],
  };
  plan.sha256 = sha256(canonicalPlan(plan));
  return plan;
}

export function writeEdzipPlan(root, plan) {
  const p = path.join(root, PLAN_REL);
  writeText(p, JSON.stringify(plan, null, 2) + '\n');
  return p;
}

function validateAnswers(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('--answers <JSON> 파일이 필요합니다.');
  for (const key of Object.keys(raw)) {
    if (PII_ANSWER_KEYS.has(key.toLowerCase())) throw new Error(`개인정보 항목은 받지 않습니다: ${key}`);
  }
  const answers = {};
  for (const q of EDZIP_PREPARE_QUESTIONS) {
    const value = raw[q.id];
    if (!q.values.includes(value)) throw new Error(`${q.id}는 ${q.values.join('|')} 중 하나여야 합니다.`);
    answers[q.id] = value;
  }
  return answers;
}

function scopeAssessment(answers) {
  if (answers.studentData === 'yes' || answers.curriculumContent === 'yes') return { status: 'applicable', reason: '학생 정보 처리 또는 교과 학습 콘텐츠 요건에 해당합니다.' };
  if (answers.studentData === 'no' && answers.curriculumContent === 'no') return { status: 'out-of-scope', reason: '두 적용 요건에 모두 해당하지 않는다고 답했습니다.' };
  return { status: 'needs-review', reason: '적용 요건에 확인 전 답변이 있어 학교·교육청 확인이 필요합니다.' };
}

async function checkSources() {
  const checks = [];
  for (const source of EDZIP_OFFICIAL_SOURCES) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 7000);
    try {
      const response = await fetch(source.url, { method: 'GET', redirect: 'follow', signal: controller.signal, headers: { 'user-agent': 'dorms-check/edzip-prepare' } });
      checks.push({ id: source.id, ok: response.ok, status: response.status, finalUrl: response.url, checkedAt: new Date().toISOString() });
    } catch (error) {
      checks.push({ id: source.id, ok: false, status: 0, error: error?.name === 'AbortError' ? 'timeout' : 'network-error', checkedAt: new Date().toISOString() });
    } finally { clearTimeout(timer); }
  }
  return checks;
}

function detectedServices(plan) {
  const ids = new Set(plan.inspection.evidence.map(x => x.signal));
  const services = [];
  if (ids.has('supabase')) services.push('Supabase(데이터베이스·인증)');
  if (ids.has('firebase')) services.push('Firebase(호스팅·데이터·인증 가능성)');
  if (ids.has('openai')) services.push('OpenAI(외부 AI)');
  if (ids.has('anthropic')) services.push('Anthropic(외부 AI)');
  if (ids.has('vercel')) services.push('Vercel(웹 호스팅·접속 로그)');
  return services;
}

export function parseEdzipApprovalUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return { ok: false, error: '에듀집 확인 완료 주소를 입력하세요.' };
  let url;
  try { url = new URL(raw.trim()); } catch { return { ok: false, error: '에듀집 주소 형식을 확인하세요.' }; }
  if (url.protocol !== 'https:' || !EDZIP_HOSTS.has(url.hostname.toLowerCase()) || url.username || url.password || url.search || url.hash) {
    return { ok: false, error: 'https://edzip.kr 로 시작하는 제품 등록 주소만 사용할 수 있습니다.' };
  }
  const match = url.pathname.match(/^\/(?:utilization\/)?learning-sw\/([a-f0-9]{24})\/?$/i);
  if (!match || !EDZIP_ID_RE.test(match[1])) return { ok: false, error: '에듀집 학습지원 소프트웨어 제품 주소를 확인하세요.' };
  const id = match[1].toLowerCase();
  return { ok: true, id, normalizedUrl: `https://edzip.kr/learning-sw/${id}` };
}

function comparableName(value) {
  return String(value ?? '').normalize('NFKC').toLocaleLowerCase('ko-KR').replace(/[^0-9a-z가-힣]/g, '');
}

export function safeEdzipApproval(payload, appName, normalizedUrl, id) {
  const data = payload?.data;
  if (!data || typeof data !== 'object') return { ok: false, error: '에듀집 등록 정보를 확인하지 못했습니다.' };
  const productName = typeof data.productName === 'string' ? data.productName.trim() : '';
  const displayStatus = typeof data.displayStatus === 'string' ? data.displayStatus : '';
  const confirmStatus = typeof data.confirmStatus === 'string' ? data.confirmStatus : '';
  if (displayStatus !== 'enable' || confirmStatus !== 'confirmed') return { ok: false, error: '에듀집에서 공개와 확인이 모두 완료된 뒤 실행하세요.' };
  if (!productName || comparableName(productName) !== comparableName(appName)) return { ok: false, error: `에듀집 제품명(${productName || '확인 불가'})과 프로젝트 앱 이름이 같아야 합니다.` };
  return { ok: true, id, normalizedUrl, productName, displayStatus, confirmStatus, verifiedAt: new Date().toISOString() };
}

export async function verifyEdzipApproval({ url, appName, fetchImpl = fetch }) {
  const parsed = parseEdzipApprovalUrl(url);
  if (!parsed.ok) return parsed;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetchImpl(`https://api.edzip.kr/self-inspection/${parsed.id}`, {
      method: 'GET', headers: { accept: 'application/json', 'user-agent': 'dorms-check/edzip-council' }, redirect: 'error', signal: controller.signal,
    });
    if (!response.ok) return { ok: false, error: '에듀집 등록 정보를 찾지 못했습니다.' };
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > EDZIP_RESPONSE_LIMIT) return { ok: false, error: '에듀집 응답이 너무 커서 확인을 중단했습니다.' };
    return safeEdzipApproval(JSON.parse(text), appName, parsed.normalizedUrl, parsed.id);
  } catch (error) {
    return { ok: false, error: error?.name === 'AbortError' ? '에듀집 확인 시간이 초과되었습니다.' : '에듀집에 연결하지 못했습니다.' };
  } finally { clearTimeout(timer); }
}

function privacyMarkdown(plan, answers) {
  const app = plan.app.name || '소프트웨어';
  const services = detectedServices(plan);
  const external = answers.externalTransfer === 'yes';
  const child = answers.childDirectUse === 'yes';
  return `# ${app} 개인정보 처리방침

- 시행일: [작성자가 시행일을 입력하세요]
- 제공자: [작성자가 제공자명을 입력하세요]
- 공개 주소: ${plan.app.url ? `${plan.app.url.replace(/\/$/, '')}/privacy` : '[공개할 개인정보처리방침 URL을 입력하세요]'}

> 이 초안은 프로젝트 코드에서 관찰한 흐름과 작성자의 비개인정보 답변을 반영했습니다. 제출 전에 실제 동작과 맞는지 반드시 확인하세요.

## 제1조(총칙과 데이터 처리 구조)

${app}은 ${plan.app.stack} 기반 소프트웨어입니다. 작성자는 이용자 기기에만 남는 정보와 외부 서비스로 전송되는 정보를 구분해 관리합니다.

- 학생 정보 처리: ${answers.studentData === 'yes' ? '있음, 아래 빈칸에 실제 항목과 저장 위치를 확정해야 함' : answers.studentData === 'no' ? '없음으로 답변함' : '확인 전'}
- 외부 전송: ${external ? '있음' : answers.externalTransfer === 'no' ? '없음으로 답변함' : '확인 전'}
- 코드에서 탐지한 외부 서비스: ${services.length ? services.join(', ') : '탐지되지 않음'}

## 제2조(처리하는 개인정보 항목)

| 구분 | 항목 | 수집 방법 |
|---|---|---|
| [작성자가 구분을 입력하세요] | [실제 수집 항목을 입력하세요] | [수집 방법을 입력하세요] |

개인정보를 수집하지 않는다면 위 표를 지우고 “이용자의 개인정보를 수집하지 않습니다”로 확정하세요.

## 제3조(처리 목적)

[실제 항목별 처리 목적을 입력하세요]. 목적에 필요한 최소한의 정보만 처리합니다.

## 제4조(보유 기간과 파기)

| 항목 | 보유 기간 | 파기 방법 |
|---|---|---|
| [항목] | [보유 기간] | [복구할 수 없는 방법] |

## 제5조(제3자 제공)

[제3자 제공이 없으면 “개인정보를 제3자에게 제공하지 않습니다”로 확정하세요. 있으면 제공받는 자·목적·항목·보유 기간을 입력하세요].

## 제6조(업무위탁과 국외 이전)

${external ? `탐지된 후보는 ${services.join(', ') || '없음'}입니다. 각 서비스의 정확한 법인명·업무·전송 항목·국가·보유 기간·거부 방법을 공식 문서로 확인해 입력하세요.` : '개인정보를 외부에 위탁하거나 국외로 이전하지 않는다고 답했습니다. 실제 코드·호스팅 설정과 다르면 수정하세요.'}

## 제7조(정보주체의 권리와 행사 방법)

정보주체는 열람·정정·삭제·처리정지를 요구할 수 있습니다. 요청 방법: [작성자가 공개 문의 방법을 입력하세요].

## 제8조(만 14세 미만 아동의 개인정보)

${child ? '만 14세 미만 아동이 직접 이용합니다. [법정대리인 동의를 받고 확인하는 실제 절차를 입력하세요].' : '만 14세 미만 아동의 직접 가입·이용이 없다고 답했습니다. 학생 정보가 실제로 서버에 저장되면 법정대리인 동의 절차를 다시 확인하세요.'}

## 제9조(안전성 확보 조치)

- 관리적 조치: [접근권한 관리·정기 점검 등 실제 조치]
- 기술적 조치: [HTTPS·암호화·접근통제·RLS·로그 절제 등 실제 조치]
- 물리적 조치: [운영 기기 잠금·디스크 암호화 등 실제 조치]

## 제10조(개인정보 보호책임자)

| 구분 | 성명 | 소속 | 연락처 |
|---|---|---|---|
| 개인정보 보호책임자 | [작성자가 성명을 입력하세요] | [소속을 입력하세요] | [연락처를 입력하세요] |

## 제11조(변경 고지)

방침이 바뀌면 시행 7일 전부터 [공지 위치를 입력하세요]에 안내합니다.

## 법령 근거

${EDZIP_LEGAL_BASIS.map(x => `- ${x.law}: ${x.link}`).join('\n')}
`;
}

function checklistMarkdown(plan, answers, scope) {
  const app = plan.app.name;
  return `# 학습지원 소프트웨어 필수기준 자가점검표

| 항목 | 내용 |
|---|---|
| 제품·서비스명 | ${app} |
| 공급자 | [작성자가 성명 또는 팀명을 입력하세요] |
| 접속 경로 | ${plan.app.url || '[앱 주소를 입력하세요]'} |
| 적용 판정 | ${scope.status}: ${scope.reason} |
| 주요 기능 | [코드 분석 결과를 확인해 주요 기능을 입력하세요] |

| 선정기준 | 세부 내용 | 확인 | 증빙 |
|---|---|---|---|
${EDZIP_ITEMS.map(item => `| ${item.criterion} | ${item.title} | [충족/미충족/해당없음] | 개인정보 처리방침 ${item.policy.join('·')} |`).join('\n')}

- 개인정보처리방침 확인 방법: ${answers.publicPrivacyUrl === 'yes' && plan.app.url ? plan.app.url.replace(/\/$/, '') + '/privacy' : '[공개 URL을 입력하세요]'}
- 작성일: [작성자가 작성일을 입력하세요]
- 문의처: [작성자가 공개 문의처를 입력하세요]

> 입증 책임은 작성자에게 있으며, 이 자동 생성물은 학교운영위원회 심의 통과를 보장하지 않습니다.
`;
}

function providerBriefMarkdown(plan, scope) {
  return `# ${plan.app.name} 에듀집 등록 제품 설명자료

## 1. 서비스 개요

- 서비스명: ${plan.app.name}
- 접속 경로: ${plan.app.url || '[주소를 입력하세요]'}
- 제공자: [제공자명을 입력하세요]
- 적용 판정: ${scope.reason}

## 2. 주요 기능과 활용 목적

${plan.app.description || '[프로젝트 설명을 입력하세요]'}

## 3. 개인정보 처리와 안전조치

첨부한 개인정보 처리방침과 필수기준 자가점검표를 확인해 주세요. 실제 코드·배포 설정과 서류가 같은지 제출 전 다시 확인해야 합니다.

## 4. 법적 근거

${EDZIP_LEGAL_BASIS.map(x => `- ${x.law}: ${x.note} ${x.link}`).join('\n')}

## 5. 첨부 목록

1. 학습지원 소프트웨어 필수기준 자가점검표
2. 개인정보 처리방침
3. 에듀집 확인 페이지 [에듀집 확인 완료 뒤 주소를 입력하세요]

> 이 문서는 에듀집 제출과 학교 전달에 사용할 제품 설명 초안입니다. 에듀집 확인 완료 뒤 \`dcheck edzip council\`을 실행하면 학교 내부 기안문과 학운위 안건 초안을 별도로 만듭니다.
`;
}

function submissionMarkdown(sourceChecks) {
  const sourceMap = new Map(sourceChecks.map(x => [x.id, x]));
  const kerisContact = EDZIP_CONTACTS.find(c => c.organization === '한국교육학술정보원 교수학습지원부');
  if (!kerisContact?.phones?.length) throw new Error('KERIS 에듀집 업무 담당자 연락처를 찾지 못했습니다.');
  const kerisPhones = kerisContact.phones.join(', ');
  const line = source => {
    const check = sourceMap.get(source.id);
    const state = check?.ok ? `접속 확인 ${check.checkedAt}` : `실행 시 확인 전${check?.checkedAt ? ` ${check.checkedAt}` : ''}`;
    return `- [${source.title}](${source.url})  | ${state}`;
  };
  return `# 에듀집 제출·학교 전달 안내

## 제출 경로

- 교사 등 개인 제작자 구글폼: https://forms.gle/aCa4mjvgtmovEf1eA
- 에듀집 필수기준 점검결과: https://edzip.kr/learning-sw
- 이 도구는 제출 페이지를 안내하지만 로그인·서명·제출 버튼 클릭은 작성자가 직접 합니다.

## 구글폼 제출 뒤 확인

- 구글폼 제출을 마치면 접수 결과나 보완 연락을 기다립니다.
- 며칠이 지나도 결과나 연락이 없으면 한국교육학술정보원 교수학습지원부(${kerisPhones})로 접수 여부와 진행 상태를 문의해 보세요.
- 문의할 때는 제품명, 구글폼 제출일, 제출에 사용한 구글 계정을 확인할 수 있게 준비하되 이 문서에는 개인정보를 적지 않습니다.

## 문의처

${EDZIP_CONTACTS.map(c => `- ${c.topic}: ${c.organization}, ${(c.phones || []).join(', ')}${c.email ? `, ${c.email}` : ''}${c.hours ? `, ${c.hours}` : ''}`).join('\n')}

## 제출 전 작성자가 직접 채울 곳

| 무엇을 | Ctrl+F 검색어 | 할 일 |
|---|---|---|
| 시행일 | 작성자가 시행일을 입력하세요 | 방침 시행일 입력 |
| 제공자 | 작성자가 제공자명을 입력하세요 | 개인 또는 팀 이름 입력 |
| 수집 항목 | 실제 수집 항목을 입력하세요 | 실제 코드와 대조해 입력 |
| 아동 동의 | 법정대리인 동의를 받고 확인하는 실제 절차 | 해당하면 실제 절차 입력 |
| 보호책임자 | 작성자가 성명을 입력하세요 | 성명·소속·연락처 입력 |
| 에듀집 주소 | 에듀집 확인 완료 뒤 주소를 입력하세요 | 확인 완료 뒤 공식 제품 주소 입력 |

## 공식 근거 원문

${EDZIP_OFFICIAL_SOURCES.map(line).join('\n')}

## 한글 표의 글자가 겹쳐 보일 때

먼저 원본 파일의 복사본을 남기세요. 한글에서 문서 전체를 드래그하거나 Ctrl+A로 선택해 복사한 뒤, 새 빈 한글 문서에 다시 붙여넣으면 한글이 줄 배치를 다시 계산해 표 칸의 글자 겹침이 풀립니다. 붙여넣은 문서는 표와 쪽 나눔을 확인한 뒤 새 이름으로 저장하세요.
`;
}

function markdownToPlain(md) {
  return md
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/^>\s?/gm, '')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '$1  $2')
    .replace(/[*_`]/g, '')
    .replace(/^\|?\s*[-:]+(?:\s*\|\s*[-:]+)+\s*\|?$/gm, '')
    .replace(/\|/g, '  ');
}

function writePdf(file, title, markdown) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margins: { top: 50, right: 50, bottom: 50, left: 50 }, info: { Title: title, Author: 'dorms-check' } });
    const out = fs.createWriteStream(file, { flags: 'wx' });
    out.on('finish', resolve);
    out.on('error', reject);
    doc.on('error', reject);
    doc.pipe(out);
    doc.registerFont('NotoSansKR', packageAsset('fonts', 'NotoSansKR.ttf'));
    doc.font('NotoSansKR').fontSize(11).lineGap(3).text(markdownToPlain(markdown), { align: 'left' });
    doc.end();
  });
}

function appendPrivateIgnore(root) {
  const file = path.join(root, '.gitignore');
  const old = readTextSafe(file) || '';
  const rule = '.dorms-check/private/';
  if (old.split(/\r?\n/).map(x => x.trim()).includes(rule)) return false;
  const next = old + (old && !old.endsWith('\n') ? '\n' : '') + rule + '\n';
  writeText(file, next);
  return true;
}

function uniqueOutputDir(root) {
  const date = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
  const base = path.join(root, PRIVATE_REL, date);
  if (!exists(base)) return base;
  for (let n = 2; n < 100; n++) if (!exists(`${base}-${n}`)) return `${base}-${n}`;
  throw new Error('오늘 생성 폴더가 너무 많습니다.');
}

async function writeDocSet(outDir, stem, title, markdown) {
  const marked = `${markdown.trimEnd()}\n\n---\n\n${DOCUMENT_ATTRIBUTION}\n`;
  const mdFile = path.join(outDir, `${stem}.md`);
  const hwpxFile = path.join(outDir, `${stem}.hwpx`);
  const pdfFile = path.join(outDir, `${stem}.pdf`);
  writeText(mdFile, marked);
  const bytes = await markdownToHwpx(marked, { title, creator: 'Team DoRm · 교사 홍창욱' });
  fs.writeFileSync(hwpxFile, Buffer.from(bytes), { flag: 'wx' });
  await writePdf(pdfFile, title, marked);
  return [mdFile, hwpxFile, pdfFile];
}

function fillTemplate(template, values) {
  let result = template;
  for (const [key, value] of Object.entries(values)) result = result.replaceAll(`{{${key}}}`, String(value));
  const unresolved = result.match(/{{[A-Z_]+}}/g);
  if (unresolved) throw new Error(`기안문 양식에 채우지 못한 항목이 있습니다: ${[...new Set(unresolved)].join(', ')}`);
  return result;
}

function projectEvidenceMarkdown(plan) {
  const rows = plan.inspection?.evidence || [];
  if (!rows.length) return '- 자동 탐지된 근거 파일이 없습니다. 제출 전에 프로젝트 기능과 데이터 흐름을 직접 확인하세요.';
  return rows.map(row => `- ${row.signal}: ${(row.files || []).slice(0, 6).join(', ')}`).join('\n');
}

function internalApprovalMarkdown(plan, approval) {
  const template = readTextSafe(packageAsset('templates', 'school-internal-approval.md'));
  if (!template) throw new Error('내부 기안문 한글 양식을 찾지 못했습니다.');
  const privacyUrl = plan.app.url ? `${plan.app.url.replace(/\/$/, '')}/privacy` : '[개인정보처리방침 주소를 입력하세요]';
  return fillTemplate(template, {
    APP_NAME: plan.app.name,
    APP_URL: plan.app.url || '[소프트웨어 접속 주소를 입력하세요]',
    EDZIP_URL: approval.normalizedUrl,
    PRIVACY_URL: privacyUrl,
    APP_DESCRIPTION: plan.app.description || '[소프트웨어의 목적과 주요 기능을 입력하세요]',
    APP_STACK: plan.app.stack || '[기술 구성을 입력하세요]',
    DETECTED_SERVICES: detectedServices(plan).join(', ') || '자동 탐지되지 않음',
    PROJECT_EVIDENCE: projectEvidenceMarkdown(plan),
    LEGAL_BASIS: EDZIP_LEGAL_BASIS.map(x => `- ${x.law}: ${x.note} ${x.link}`).join('\n'),
  });
}

function councilAgendaMarkdown(plan, approval) {
  return `# 학교운영위원회 심의 안건문 초안

- 안건명: 학습지원 소프트웨어 '${plan.app.name}' 선정에 관한 사항
- 구분: 심의
- 작성일: [학교에서 작성일을 입력하세요]
- 회의명·회차: [학교에서 회의명과 회차를 입력하세요]

## 1. 제안 사유

${plan.app.description || `${plan.app.name}을 교육 자료로 선정해 수업과 학교 교육과정 운영에 활용하고자 합니다.`}

## 2. 주요 내용

- 소프트웨어명: ${plan.app.name}
- 접속 주소: ${plan.app.url || '[소프트웨어 접속 주소를 입력하세요]'}
- 기술 구성: ${plan.app.stack || '[기술 구성을 입력하세요]'}
- 코드에서 확인한 외부 서비스: ${detectedServices(plan).join(', ') || '자동 탐지되지 않음'}

## 3. 개인정보 보호 필수기준 확인

- 에듀집 확인 완료 주소: ${approval.normalizedUrl}
- 개인정보처리방침: ${plan.app.url ? `${plan.app.url.replace(/\/$/, '')}/privacy` : '[개인정보처리방침 주소를 입력하세요]'}
- 에듀집 제출에 사용한 개인정보 처리방침과 필수기준 자가점검표를 붙임으로 제출합니다.

## 4. 법적 근거

${EDZIP_LEGAL_BASIS.map(x => `- ${x.law}: ${x.note} ${x.link}`).join('\n')}

## 5. 심의 요청

위 학습지원 소프트웨어의 교육 자료 선정과 운영에 대한 심의를 요청합니다.

## 붙임

1. 학습지원 소프트웨어 필수기준 자가점검표 1부.
2. 개인정보 처리방침 1부.
3. 에듀집 제품 설명자료 1부.
4. 에듀집 확인 완료 주소 출력물 또는 링크 1부.  끝.

> 실제 심의와 최종 선정은 학교가 합니다. 비용·대상 학년·활용 교과·운영 기간처럼 학교별 내용은 제출 전에 확인해 주세요.
`;
}

function schoolSubmissionMarkdown(plan, approval, sourceDir) {
  return `# 에듀집 확인 완료 뒤 학교 제출 안내

## 준비 순서

1. 에듀집 제출 때 사용한 \`01-privacy-policy.hwpx\`, \`02-required-checklist.hwpx\`, \`03-edzip-provider-brief.hwpx\`를 그대로 준비합니다.
2. 에듀집 확인 완료 주소 ${approval.normalizedUrl}를 링크 또는 출력물로 붙입니다.
3. \`05-internal-approval-draft.hwpx\`의 학교명·수신자·결재 경로·기안자·작성일을 학교 양식에 맞게 채웁니다.
4. 내부 결재를 받아 \`06-council-agenda-draft.hwpx\`를 학교운영위원회 안건으로 제출합니다.
5. 심의 결과를 반영해 학교장이 최종 선정·결재합니다.

## 이 프로젝트에서 가져온 자료

- 에듀집 준비 자료 폴더: ${path.basename(sourceDir)}
- 제품명: ${plan.app.name}
- 앱 주소: ${plan.app.url || '[앱 주소를 입력하세요]'}
- 에듀집 확인 완료 주소: ${approval.normalizedUrl}

## Ctrl+F로 직접 채울 곳

| 무엇을 | 검색어 | 할 일 |
|---|---|---|
| 수신자 | 학교에서 수신자를 입력하세요 | 학교 결재 양식에 맞게 입력 |
| 결재 경로 | 학교에서 결재 경로를 입력하세요 | 교감·정보부장·개인정보 담당 등 학교 결재선 확인 |
| 기안자 | 기안자가 성명을 입력하세요 | 성명 입력 |
| 작성일 | 학교에서 작성일을 입력하세요 | 기안일과 안건 제출일 입력 |
| 회의 정보 | 학교에서 회의명과 회차를 입력하세요 | 학운위 회의명·회차 입력 |

이 도구는 내부 결재나 학운위 제출을 대신하지 않습니다. 학교 규정과 담당자 안내를 확인한 뒤 제출하세요.

## 한글 표의 글자가 겹쳐 보일 때

먼저 원본 파일의 복사본을 남기세요. 한글에서 문서 전체를 드래그하거나 Ctrl+A로 선택해 복사한 뒤, 새 빈 한글 문서에 다시 붙여넣으면 한글이 줄 배치를 다시 계산해 표 칸의 글자 겹침이 풀립니다. 붙여넣은 문서는 표와 쪽 나눔을 확인한 뒤 새 이름으로 저장하세요.
`;
}

function resolvePreparationDir(root, requested) {
  const privateRoot = path.join(root, PRIVATE_REL);
  if (requested) {
    const resolved = path.resolve(root, requested);
    if (!withinRoot(privateRoot, path.relative(privateRoot, resolved))) throw new Error('--source-dir는 이 프로젝트의 .dorms-check/private/edzip 안을 가리켜야 합니다.');
    if (!fs.statSync(resolved, { throwIfNoEntry: false })?.isDirectory()) throw new Error('--source-dir 폴더를 찾지 못했습니다.');
    const realPrivateRoot = fs.realpathSync(privateRoot);
    const realResolved = fs.realpathSync(resolved);
    if (!withinRoot(realPrivateRoot, path.relative(realPrivateRoot, realResolved))) throw new Error('--source-dir의 실제 경로가 프로젝트의 비공개 에듀집 폴더 밖을 가리킵니다.');
    return realResolved;
  }
  if (!exists(privateRoot)) throw new Error('먼저 dcheck edzip prepare --apply로 에듀집 제출 자료를 만드세요.');
  const candidates = fs.readdirSync(privateRoot, { withFileTypes: true })
    .filter(entry => entry.isDirectory() && exists(path.join(privateRoot, entry.name, 'manifest.json')))
    .map(entry => path.join(privateRoot, entry.name))
    .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
  if (!candidates.length) throw new Error('에듀집 제출 자료 manifest.json을 찾지 못했습니다.');
  return candidates[0];
}

export async function prepareCouncilDocuments(root, { approvedUrl, confirmApply, sourceDir, fetchImpl = fetch }) {
  if (!confirmApply) throw new Error('--confirm-apply가 필요합니다.');
  const resolvedSource = resolvePreparationDir(root, sourceDir);
  const manifestPath = path.join(resolvedSource, 'manifest.json');
  const manifest = readJsonSafe(manifestPath);
  if (!manifest || !manifest.planSha256 || manifest.piiStored !== false) throw new Error('에듀집 준비 자료의 manifest.json을 확인할 수 없습니다.');
  const plan = readJsonSafe(path.join(root, PLAN_REL));
  if (!plan || sha256(canonicalPlan(plan)) !== manifest.planSha256) throw new Error('현재 프로젝트 계획과 에듀집 제출 자료가 다릅니다. prepare부터 다시 실행하세요.');
  const manifestHashes = new Map((manifest.files || []).map(file => [file.name, file.sha256]));
  for (const name of ['01-privacy-policy.hwpx', '02-required-checklist.hwpx']) {
    if (!exists(path.join(resolvedSource, name))) throw new Error(`에듀집 제출에 사용한 서류가 없습니다: ${name}`);
    const actual = crypto.createHash('sha256').update(fs.readFileSync(path.join(resolvedSource, name))).digest('hex');
    if (!manifestHashes.get(name) || manifestHashes.get(name) !== actual) throw new Error(`에듀집 제출 서류가 생성 뒤 바뀌었거나 원본 기록이 없습니다: ${name}`);
  }
  const providerBriefName = ['03-edzip-provider-brief.hwpx', '03-council-provider-brief.hwpx'].find(name => exists(path.join(resolvedSource, name)));
  if (!providerBriefName) throw new Error('에듀집 제출에 사용한 제품 설명자료가 없습니다.');
  const providerHash = crypto.createHash('sha256').update(fs.readFileSync(path.join(resolvedSource, providerBriefName))).digest('hex');
  if (!manifestHashes.get(providerBriefName) || manifestHashes.get(providerBriefName) !== providerHash) throw new Error(`에듀집 제품 설명자료가 생성 뒤 바뀌었거나 원본 기록이 없습니다: ${providerBriefName}`);
  const approval = await verifyEdzipApproval({ url: approvedUrl, appName: plan.app.name, fetchImpl });
  if (!approval.ok) throw new Error(approval.error);
  const targetFiles = ['05-internal-approval-draft.hwpx', '06-council-agenda-draft.hwpx', '07-school-submission-guide.hwpx'];
  if (targetFiles.some(name => exists(path.join(resolvedSource, name)))) throw new Error('학교 제출 초안이 이미 있습니다. 기존 파일을 보존하기 위해 덮어쓰지 않았습니다.');

  const files = [];
  files.push(...await writeDocSet(resolvedSource, '05-internal-approval-draft', `${plan.app.name} 선정 심의 요청 기안`, internalApprovalMarkdown(plan, approval)));
  files.push(...await writeDocSet(resolvedSource, '06-council-agenda-draft', `${plan.app.name} 학교운영위원회 심의 안건`, councilAgendaMarkdown(plan, approval)));
  files.push(...await writeDocSet(resolvedSource, '07-school-submission-guide', '에듀집 확인 완료 뒤 학교 제출 안내', schoolSubmissionMarkdown(plan, approval, resolvedSource)));
  const templates = path.join(resolvedSource, 'templates');
  ensureDir(templates);
  files.push(copyAsset(packageAsset('forms', 'school-internal-approval-blank.hwpx'), path.join(templates, 'school-internal-approval-blank.hwpx')));
  manifest.schemaVersion = 2;
  manifest.schoolReviewGeneratedAt = new Date().toISOString();
  manifest.edzipApproval = approval;
  manifest.files = [...(manifest.files || []), ...files.map(file => ({ name: path.relative(resolvedSource, file), sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') }))];
  manifest.piiStored = false;
  manifest.automaticSubmission = false;
  writeText(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  return { applied: true, outDir: resolvedSource, approval, manifest, files };
}

function copyAsset(source, dest) {
  fs.copyFileSync(source, dest, fs.constants.COPYFILE_EXCL);
  return dest;
}

export async function applyEdzipPlan(root, { planSha256, confirmApply, answersFile, continueOutOfScope = false }) {
  if (!confirmApply) throw new Error('--confirm-apply가 필요합니다.');
  const plan = readJsonSafe(path.join(root, PLAN_REL));
  if (!plan) throw new Error('먼저 dcheck edzip prepare로 계획을 만드세요.');
  const expected = sha256(canonicalPlan(plan));
  if (!planSha256 || planSha256 !== expected || plan.sha256 !== expected) throw new Error('계획 해시가 다릅니다. 최신 계획을 다시 확인하세요.');
  const resolvedAnswers = path.resolve(root, answersFile || '');
  if (!answersFile || !withinRoot(root, path.relative(root, resolvedAnswers))) throw new Error('--answers는 프로젝트 안 JSON 파일을 가리켜야 합니다.');
  const answers = validateAnswers(readJsonSafe(resolvedAnswers));
  const scope = scopeAssessment(answers);
  if (scope.status === 'out-of-scope' && !continueOutOfScope) {
    return { applied: false, scope, needsContinueConfirmation: true, sources: EDZIP_OFFICIAL_SOURCES.filter(x => ['law.school-materials', 'moe.selection-guideline'].includes(x.id)) };
  }

  const outDir = uniqueOutputDir(root);
  ensureDir(outDir);
  appendPrivateIgnore(root);
  const sourceChecks = await checkSources();
  const files = [];
  files.push(...await writeDocSet(outDir, '01-privacy-policy', `${plan.app.name} 개인정보 처리방침`, privacyMarkdown(plan, answers)));
  files.push(...await writeDocSet(outDir, '02-required-checklist', `${plan.app.name} 필수기준 자가점검표`, checklistMarkdown(plan, answers, scope)));
  files.push(...await writeDocSet(outDir, '03-edzip-provider-brief', `${plan.app.name} 에듀집 등록 제품 설명자료`, providerBriefMarkdown(plan, scope)));
  files.push(...await writeDocSet(outDir, '04-submission-guide', '에듀집 제출 안내', submissionMarkdown(sourceChecks)));

  const originals = path.join(outDir, 'official-originals');
  ensureDir(originals);
  files.push(copyAsset(packageAsset('forms', 'edzip-checklist-original.hwp'), path.join(originals, 'edzip-checklist-original.hwp')));
  files.push(copyAsset(packageAsset('forms', 'edzip-consent-original.hwp'), path.join(originals, 'edzip-consent-original.hwp')));
  files.push(copyAsset(packageAsset('sources', 'moe-selection-guideline-2025-12.hwpx'), path.join(originals, 'moe-selection-guideline-2025-12.hwpx')));
  files.push(copyAsset(packageAsset('sources', 'edzip-registration-guide-2026-01-28.pdf'), path.join(originals, 'edzip-registration-guide-2026-01-28.pdf')));

  const manifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    planSha256: expected,
    scope,
    sourceChecks,
    files: files.map(file => ({ name: path.relative(outDir, file), sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') })),
    piiStored: false,
    automaticSubmission: false,
  };
  writeText(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return { applied: true, outDir, scope, manifest };
}

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
  const plan = {
    schemaVersion: 1,
    createdAt: new Date().toISOString(),
    root: '.',
    app: {
      name: cfg.app?.name || path.basename(root),
      url: cfg.app?.url || '',
      stack: cfg.app?.stack || inspection.detected.framework,
    },
    inspection,
    questions: EDZIP_PREPARE_QUESTIONS,
    proposedChanges: [
      { path: '.gitignore', action: 'append-if-missing', detail: '.dorms-check/private/ 생성물 Git 추적 차단' },
      { path: privacySignal?.files?.[0] || 'docs/privacy-policy.md', action: privacySignal ? 'review-and-supplement-by-agent' : 'create-by-agent', detail: '실제 데이터 흐름에 맞는 공개 개인정보처리방침' },
      { path: `${PRIVATE_REL}/YYYY-MM-DD/`, action: 'generate', detail: 'HWPX·PDF·Markdown 서류 패과 공식 원본·출처 복사본' },
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

function committeeMarkdown(plan, scope) {
  return `# ${plan.app.name} 학교운영위원회 심의 제공자 자료

## 1. 서비스 개요

- 서비스명: ${plan.app.name}
- 접속 경로: ${plan.app.url || '[주소를 입력하세요]'}
- 제공자: [제공자명을 입력하세요]
- 적용 판정: ${scope.reason}

## 2. 서비스 기능과 수업 활용

[작성자가 수업 목적·대상 학년·교과·사용 방법을 입력하세요]

## 3. 개인정보 처리와 안전조치

첨부한 개인정보 처리방침과 필수기준 자가점검표를 확인해 주세요. 실제 코드·배포 설정과 서류가 같은지 제출 전 다시 확인해야 합니다.

## 4. 법적 근거

${EDZIP_LEGAL_BASIS.map(x => `- ${x.law}: ${x.note} ${x.link}`).join('\n')}

## 5. 첨부 목록

1. 학습지원 소프트웨어 필수기준 자가점검표
2. 개인정보 처리방침
3. 에듀집 확인 페이지 [등록 후 URL을 입력하세요]

> 이 문서는 공급자가 학교에 제공할 수 있는 초안입니다. 학교 내부 안건 상정·의견서·의결서는 학교가 작성합니다.
`;
}

function submissionMarkdown(sourceChecks) {
  const sourceMap = new Map(sourceChecks.map(x => [x.id, x]));
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
| 서명·인영 | 등록 후 URL을 입력하세요 | 서명·인영 후 에듀집 URL 입력 |

## 공식 근거 원문

${EDZIP_OFFICIAL_SOURCES.map(line).join('\n')}
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
  const mdFile = path.join(outDir, `${stem}.md`);
  const hwpxFile = path.join(outDir, `${stem}.hwpx`);
  const pdfFile = path.join(outDir, `${stem}.pdf`);
  writeText(mdFile, markdown);
  const bytes = await markdownToHwpx(markdown, { title, creator: 'dorms-check' });
  fs.writeFileSync(hwpxFile, Buffer.from(bytes), { flag: 'wx' });
  await writePdf(pdfFile, title, markdown);
  return [mdFile, hwpxFile, pdfFile];
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
  files.push(...await writeDocSet(outDir, '03-council-provider-brief', `${plan.app.name} 학교운영위원회 제공자 자료`, committeeMarkdown(plan, scope)));
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

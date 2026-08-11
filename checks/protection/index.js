// protection 트랙 결정적 검사(로컬) — 빌드 산출물·안내 파일·증거 상태를 실측한다.
// 판정 원칙: 확인 전에는 보수적으로(공개로 가정). 빌드 산출물이 없으면 pending(빌드 후 재스캔).
// ai 판단 항목(server·output-leak·api-abuse·app-footer 등)은 여기서 pending seed 만 하고 judge 가 채운다.
import path from 'node:path';
import { exists, walk, readTextSafe, readJsonSafe } from '../../core/util.js';
import { detectStack } from '../../core/detect.js';
import { SECRET_PATTERNS } from '../static/secrets.js';
import { PROTECTION_ITEMS } from '../../catalog/protection.js';
import { loadRightsProfile, rightsConfirmed } from '../../core/rights-profile.js';

const PROTECT_DIR = path.join('.dorms-check', 'protect');

// 클라이언트 번들에서 '프롬프트로 보이는' 지시문 후보(결정적 그물 → 최종 판단은 AI judge).
const PROMPT_MARKERS = [
  { name: 'system prompt 표기', re: /\bsystem\s*[_-]?prompt\b/i },
  { name: '영문 역할 지시문', re: /you\s+are\s+an?\s+[a-z][a-z ]{2,40}(assistant|teacher|tutor|expert|bot)/i },
  { name: '한글 역할 지시문', re: /당신은\s.{0,40}(도우미|비서|선생님|교사|챗봇|전문가)/ },
  { name: '지시문 라벨', re: /(지시사항|지시문|프롬프트)\s*[:=]/ },
];

// 공개 경로에 있으면 위험한 모델·데이터 파일 확장자
const WEIGHT_EXTS = ['.onnx', '.gguf', '.pt', '.pth', '.tflite', '.safetensors', '.h5', '.pb'];

function buildDirOf(root) {
  const d = detectStack(root);
  if (!d.buildDir || d.buildDir === '.') return null;
  const full = path.join(root, d.buildDir);
  return exists(full) ? { rel: d.buildDir, full } : null;
}

function item(id, status, observed, evidence = {}) {
  return { id, status, observed, evidence };
}

function pendingNoBuild(id) {
  return item(id, 'pending', '빌드 산출물이 없어 아직 검사 못 함(빌드 후 다시 scan)');
}

// ── 개별 검사 ──

function checkClientSecrets(root, build) {
  const id = 'protection.boundary.client-secrets';
  if (!build) return pendingNoBuild(id);
  const files = walk(build.full, { exts: ['.js', '.mjs', '.html', '.htm', '.json'], maxFiles: 8000 });
  const hits = [];
  for (const f of files) {
    const text = readTextSafe(f);
    if (!text) continue;
    for (const p of SECRET_PATTERNS) {
      if (p.extra) { if (p.re.test(text) && p.extra.test(text)) hits.push({ file: path.relative(root, f), line: 0, kind: p.name }); continue; }
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (p.re.test(lines[i])) hits.push({ file: path.relative(root, f), line: i + 1, kind: p.name });
      }
    }
    if (hits.length > 100) break;
  }
  return item(id, hits.length ? 'fail' : 'pass',
    hits.length ? `배포 산출물에서 비밀 키 의심 ${hits.length}건` : '배포 산출물에서 비밀 키 미검출',
    { hits: hits.slice(0, 50) });
}

function checkPromptExposure(root, build) {
  const id = 'protection.boundary.prompt';
  if (!build) return pendingNoBuild(id);
  const files = walk(build.full, { exts: ['.js', '.mjs', '.html', '.htm'], maxFiles: 8000 });
  const hits = [];
  for (const f of files) {
    const text = readTextSafe(f);
    if (!text) continue;
    for (const m of PROMPT_MARKERS) {
      if (m.re.test(text)) hits.push({ file: path.relative(root, f), line: 0, kind: m.name });
    }
    if (hits.length > 60) break;
  }
  // 후보가 있으면 pending(문맥 확인 필요 — judge 로 판정), 없으면 pass.
  return item(id, hits.length ? 'pending' : 'pass',
    hits.length ? `프롬프트로 보이는 지시문 후보 ${hits.length}건(비법인지 judge 로 판정 필요)` : '배포 산출물에서 프롬프트성 지시문 미검출',
    { hits: hits.slice(0, 30) });
}

function checkWeights(root, build) {
  const id = 'protection.boundary.weights';
  const dirs = [];
  if (build) dirs.push(build.full);
  const pub = path.join(root, 'public');
  if (exists(pub)) dirs.push(pub);
  if (!dirs.length) return pendingNoBuild(id);
  const hits = [];
  for (const d of dirs) {
    for (const f of walk(d, { exts: WEIGHT_EXTS, maxFiles: 4000 })) {
      hits.push({ file: path.relative(root, f), line: 0, kind: '모델·데이터 파일' });
    }
  }
  return item(id, hits.length ? 'fail' : 'pass',
    hits.length ? `공개 경로에 모델·데이터 파일 ${hits.length}건` : '공개 경로에서 모델·데이터 파일 미검출',
    { hits: hits.slice(0, 30) });
}

function checkSourcemap(root, build) {
  const id = 'protection.release.sourcemap';
  if (!build) return pendingNoBuild(id);
  const maps = walk(build.full, { exts: ['.map'], maxFiles: 4000 });
  let refs = 0;
  if (!maps.length) {
    for (const f of walk(build.full, { exts: ['.js', '.mjs', '.css'], maxFiles: 4000 })) {
      const s = readTextSafe(f);
      if (s && /\/\/[#@]\s*sourceMappingURL=/.test(s)) refs++;
    }
  }
  const bad = maps.length + refs;
  return item(id, bad ? 'fail' : 'pass',
    bad ? `소스맵 ${maps.length}개·참조 주석 ${refs}건` : '소스맵 미포함',
    { hits: maps.slice(0, 20).map(m => ({ file: path.relative(root, m), line: 0, kind: '.map' })) });
}

function checkDebug(root, build) {
  const id = 'protection.release.debug';
  if (!build) return pendingNoBuild(id);
  const hits = [];
  for (const f of walk(build.full, { exts: ['.js', '.mjs'], maxFiles: 4000 })) {
    const text = readTextSafe(f);
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (/\bdebugger\s*;/.test(l)) hits.push({ file: path.relative(root, f), line: i + 1, kind: 'debugger 문' });
      else if (/console\.(log|debug|info)\s*\([^)]*(prompt|secret|token|api[_-]?key|비밀|프롬프트)/i.test(l)) hits.push({ file: path.relative(root, f), line: i + 1, kind: '민감값 콘솔 로그' });
    }
    if (hits.length > 60) break;
  }
  return item(id, hits.length ? 'fail' : 'pass',
    hits.length ? `디버그 흔적 ${hits.length}건` : '디버그 흔적 미검출',
    { hits: hits.slice(0, 30) });
}

function checkPrivateIdentifiers(root, build) {
  const id = 'protection.release.private-identifiers';
  if (!build) return pendingNoBuild(id);
  const re = /(?:\/Users\/[\w.-]+|\/home\/[\w.-]+|[A-Za-z]:\\Users\\[\w.-]+)/;
  const hits = [];
  for (const f of walk(build.full, { exts: ['.js', '.mjs', '.html', '.htm', '.css', '.json'], maxFiles: 6000 })) {
    const text = readTextSafe(f);
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) { hits.push({ file: path.relative(root, f), line: i + 1, kind: '절대 경로' }); break; }
    }
    if (hits.length > 30) break;
  }
  return item(id, hits.length ? 'fail' : 'pass',
    hits.length ? `내 컴퓨터 경로 노출 ${hits.length}개 파일` : '내 컴퓨터 경로 미노출',
    { hits: hits.slice(0, 20) });
}

function checkSeparation(root, build) {
  const id = 'protection.release.separation';
  if (!build) return pendingNoBuild(id);
  const srcFiles = walk(build.full, { exts: ['.ts', '.tsx', '.jsx'], maxFiles: 2000 })
    .filter(f => !/\.d\.ts$/.test(f)); // 타입 선언 파일은 소스 원본이 아님
  const hasSrcDir = exists(path.join(build.full, 'src'));
  const bad = srcFiles.length + (hasSrcDir ? 1 : 0);
  return item(id, bad ? 'fail' : 'pass',
    bad ? `산출물 안에 소스 원본(${srcFiles.length}개 파일${hasSrcDir ? ' + src 폴더' : ''})` : '산출물에 소스 원본 미포함',
    { hits: srcFiles.slice(0, 20).map(f => ({ file: path.relative(root, f), line: 0, kind: '소스 파일' })) });
}

function checkIntegrity(root) {
  const id = 'protection.release.integrity';
  const p = path.join(root, PROTECT_DIR, 'integrity.json');
  const integ = exists(p) ? readJsonSafe(p) : null;
  const count = integ && integ.files ? Object.keys(integ.files).length : 0;
  return item(id, count ? 'pass' : 'pending',
    count ? `산출물 지문 ${count}개 파일 기록됨(${integ.at || ''})` : '아직 지문 기록 없음(protect apply 로 생성)',
    count ? { count } : {});
}

function checkNoticeVisible(root, build) {
  const id = 'protection.notice.visible';
  const hasLicense = exists(path.join(root, 'LICENSE')) || exists(path.join(root, 'LICENSE.md'));
  let marked = false;
  if (build) {
    for (const f of walk(build.full, { exts: ['.html', '.htm'], maxFiles: 200 })) {
      const s = readTextSafe(f);
      if (s && s.includes('dorms-check:notice')) { marked = true; break; }
    }
  }
  const ok = hasLicense || marked;
  return item(id, ok ? 'pass' : 'pending',
    ok ? `권리 안내 있음(${[hasLicense ? 'LICENSE' : null, marked ? '페이지 안내' : null].filter(Boolean).join(' · ')})` : '아직 사람이 읽는 권리 안내 없음(interview 후 protect apply)');
}

function checkNoticeMachine(root, build) {
  const id = 'protection.notice.machine-readable';
  if (!build) return pendingNoBuild(id);
  const robots = readTextSafe(path.join(build.full, 'robots.txt'));
  const hasRobotsBlock = Boolean(robots && robots.includes('# dorms-check'));
  const hasLlms = exists(path.join(build.full, 'llms.txt'));
  const hasTdm = exists(path.join(build.full, '.well-known', 'tdmrep.json'));
  const found = [hasRobotsBlock ? 'robots.txt AI 차단' : null, hasLlms ? 'llms.txt' : null, hasTdm ? 'TDM 예약' : null].filter(Boolean);
  const ok = found.length >= 2; // robots 블록 + llms.txt(또는 TDM) 조합이면 설정으로 본다
  return item(id, ok ? 'pass' : 'pending',
    ok ? `기계용 안내 있음(${found.join(' · ')})` : (found.length ? `일부만 있음(${found.join(' · ')}) — protect apply 로 마저 생성` : '아직 기계용 안내 없음(protect apply 로 생성)'));
}

function checkEvidence(root) {
  const p = path.join(root, PROTECT_DIR, 'evidence', 'MANIFEST.json');
  const man = exists(p) ? readJsonSafe(p) : null;
  const manifest = item('protection.evidence.manifest',
    man ? 'pass' : 'pending',
    man ? `증거팩 있음(생성 ${man.generatedAt || '?'} · 파일 ${man.fileCount ?? '?'}개)` : '아직 증거팩 없음(protect apply 로 생성)');
  const hasOts = exists(p + '.ots');
  const timestamp = item('protection.evidence.timestamp',
    hasOts ? 'pass' : 'na',
    hasOts ? '시점 증명(.ots) 있음' : '시점 증명 없음(선택 사항 — ots 설치 시 자동 생성)');
  return [manifest, timestamp];
}

function checkVerifyFunctional(root) {
  const id = 'protection.verify.functional';
  const st = readJsonSafe(path.join(root, PROTECT_DIR, 'state.json'));
  if (!st || !st.lastApply) return item(id, 'pending', '아직 보호 적용 전(protect apply 후 verify)');
  if (!st.lastVerify) return item(id, 'pending', '적용 후 검증 전(dcheck verify 실행 필요)');
  const ok = st.lastVerify.errors === 0 && st.lastVerify.at >= st.lastApply.at;
  return item(id, ok ? 'pass' : 'fail',
    ok ? `적용 후 검증 통과(${st.lastVerify.at})` : `검증에서 손상 ${st.lastVerify.errors}건(protect restore 로 복원 가능)`,
    { states: st.lastVerify });
}

// 권리 프로필 → rights·asset 항목 상태(declared)
function rightsItems(root) {
  const profile = loadRightsProfile(root);
  const out = [];
  if (!profile) {
    for (const id of ['protection.rights.owner-status', 'protection.asset.inventory']) {
      out.push(item(id, 'pending', '권리 설문 미완(dcheck interview 로 진행)'));
    }
    return out;
  }
  out.push(item('protection.rights.owner-status',
    rightsConfirmed(profile) ? 'pass' : 'pending',
    rightsConfirmed(profile)
      ? `권리자 확인됨(${profile.rightsholder.status}${profile.rightsholder.displayName ? ' · ' + profile.rightsholder.displayName : ''})`
      : `권리관계 확인 필요(현재: ${profile.rightsholder.status}${profile.rightsholder.status === 'school_work_related' ? ' · 기관 검토 ' + profile.rightsholder.workForHireReview : ''})`));
  out.push(item('protection.asset.inventory',
    (profile.protectedAssets || []).length ? 'pass' : 'pending',
    (profile.protectedAssets || []).length
      ? `보호 자산 ${profile.protectedAssets.length}건 목록화(이름만 기록)`
      : '보호할 자산 목록이 비어 있음(interview 로 기록)'));
  return out;
}

// ── 오케스트레이터 ──
// 반환 항목은 protection 카탈로그 id 만. 이미 results 에 있는 id(judge 판정 등)는 호출측에서 걸러진다.
export function runProtectionScan(root) {
  const build = buildDirOf(root);
  const items = [];
  items.push(checkClientSecrets(root, build));
  items.push(checkPromptExposure(root, build));
  items.push(checkWeights(root, build));
  items.push(checkSourcemap(root, build));
  items.push(checkDebug(root, build));
  items.push(checkPrivateIdentifiers(root, build));
  items.push(checkSeparation(root, build));
  items.push(checkIntegrity(root));
  items.push(checkNoticeVisible(root, build));
  items.push(checkNoticeMachine(root, build));
  items.push(...checkEvidence(root));
  items.push(checkVerifyFunctional(root));
  items.push(...rightsItems(root));
  return { items, buildDir: build ? build.rel : null };
}

// scan 이 seed 할 ai/declared 항목(결정적 검사·judge 로 채워지지 않은 것) — pending 처리.
export function pendingProtectionSeeds(existingIds) {
  const out = [];
  for (const it of PROTECTION_ITEMS) {
    if (existingIds.has(it.id)) continue;
    out.push(item(it.id, 'pending', '아직 판단 안 됨(interview·judge 필요)'));
  }
  return out;
}

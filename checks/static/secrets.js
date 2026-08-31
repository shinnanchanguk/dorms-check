// 하드코딩 시크릿 정적 검출(로컬 코드). 결정적: 정규식 매치 위치(파일:라인) 를 증거로.
import path from 'node:path';
import { walk, readTextSafe } from '../../core/util.js';
import { readExactDeploymentFile } from './exact-file.js';

const CODE_EXT = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.env', '.json', '.yml', '.yaml', '.py', '.rb', '.go'];

// 대표 시크릿 패턴(오탐 줄이려 접두어 고정형 위주).
// core/redact.js(제출 페이로드 마스킹)가 같은 패턴을 재사용한다(SSOT).
export const SECRET_PATTERNS = [
  { name: 'OpenAI/유사 sk- 키', re: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { name: 'OpenAI project/Anthropic 키', re: /\bsk-(?:proj|ant)-[A-Za-z0-9_-]{16,}\b/ },
  { name: 'AWS Access Key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Supabase service_role JWT', re: /service_role/i, extra: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}/ },
  { name: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{16,}\b/ },
  { name: 'GitHub 토큰', re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/ },
  { name: 'GitHub fine-grained 토큰', re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { name: 'Google API 키', re: /\bAIza[0-9A-Za-z\-_]{30,}\b/ },
  { name: 'Slack 토큰', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'Private key 블록', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'Stripe 시크릿', re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/ },
];

function findServiceRoleJwt(text) {
  const jwt = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b/g;
  for (const match of text.matchAll(jwt)) {
    try {
      const payload = JSON.parse(Buffer.from(match[0].split('.')[1], 'base64url').toString('utf8'));
      if (payload?.role === 'service_role') return match.index ?? 0;
    } catch { /* Invalid JWT-like data is not a service-role key. */ }
  }
  return -1;
}

export function checkSecrets(root, options = {}) {
  const exactDeploymentFiles = Array.isArray(options.files);
  const files = exactDeploymentFiles ? options.files : walk(root, { exts: CODE_EXT, maxFiles: 5000 });
  const hits = [];
  for (const entry of files) {
    const exact = exactDeploymentFiles ? readExactDeploymentFile(root, entry) : null;
    const f = exactDeploymentFiles ? exact.file : entry;
    // .env.example / 샘플은 제외
    const base = path.basename(f).toLowerCase();
    if (!exactDeploymentFiles && /example|sample|template/.test(base)) continue;
    const text = exactDeploymentFiles ? exact.text : readTextSafe(f);
    if (text === null) {
      if (exactDeploymentFiles) throw new Error(`${f} 배포 입력을 시크릿 검사 중 읽지 못했습니다.`);
      continue;
    }
    if (!text) continue;
    const serviceRoleJwtIndex = findServiceRoleJwt(text);
    if (serviceRoleJwtIndex >= 0) {
      hits.push({
        file: exactDeploymentFiles ? exact.relativePath : path.relative(root, f),
        line: text.slice(0, serviceRoleJwtIndex).split(/\r?\n/).length,
        kind: 'Supabase service_role JWT payload',
      });
    }
    if (exactDeploymentFiles) {
      for (const p of SECRET_PATTERNS) {
        if (p.re.test(text) && (!p.extra || p.extra.test(text))) {
          const index = text.search(p.re);
          hits.push({ file: exact.relativePath, line: index < 0 ? 1 : text.slice(0, index).split(/\r?\n/).length, kind: p.name });
        }
      }
      continue;
    }
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const p of SECRET_PATTERNS) {
        if (p.re.test(line) && (!p.extra || p.extra.test(line) || p.extra.test(text))) {
          // 클라 노출 파일(.env는 서버측, NEXT_PUBLIC_ 접두 노출은 client-bundle 이 별도로 봄)
          hits.push({ file: path.relative(root, f), line: i + 1, kind: p.name });
        }
      }
    }
  }
  return [{
    id: 'code.hardcoded-secret',
    status: hits.length ? 'fail' : 'pass',
    observed: hits.length ? `하드코딩된 것으로 보이는 시크릿 ${hits.length}건` : '하드코딩 시크릿 미검출',
    evidence: { hits: hits.slice(0, 50) },
  }];
}

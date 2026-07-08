// 하드코딩 시크릿 정적 검출(로컬 코드). 결정적: 정규식 매치 위치(파일:라인) 를 증거로.
import path from 'node:path';
import { walk, readTextSafe } from '../../core/util.js';

const CODE_EXT = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.env', '.json', '.yml', '.yaml', '.py', '.rb', '.go'];

// 대표 시크릿 패턴(오탐 줄이려 접두어 고정형 위주).
const PATTERNS = [
  { name: 'OpenAI/유사 sk- 키', re: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { name: 'AWS Access Key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Supabase service_role JWT', re: /service_role/ , extra: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}/ },
  { name: 'GitHub 토큰', re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/ },
  { name: 'Google API 키', re: /\bAIza[0-9A-Za-z\-_]{30,}\b/ },
  { name: 'Slack 토큰', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'Private key 블록', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'Stripe 시크릿', re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/ },
];

export function checkSecrets(root) {
  const files = walk(root, { exts: CODE_EXT, maxFiles: 5000 });
  const hits = [];
  for (const f of files) {
    // .env.example / 샘플은 제외
    const base = path.basename(f).toLowerCase();
    if (/example|sample|template/.test(base)) continue;
    const text = readTextSafe(f);
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const p of PATTERNS) {
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

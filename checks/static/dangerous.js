// 위험 코드 패턴 그물질(로컬). eval/innerHTML/exec/rejectUnauthorized:false 등.
// 결정적 매치이지만 문맥 판단이 필요하므로 코치는 'ai-review 후보'로 넘긴다(마크 게이트 아님).
import path from 'node:path';
import { walk, readTextSafe } from '../../core/util.js';

const CODE_EXT = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
const PATTERNS = [
  { name: 'eval()', re: /\beval\s*\(/ },
  { name: 'new Function()', re: /new\s+Function\s*\(/ },
  { name: 'innerHTML 대입', re: /\.innerHTML\s*=/ },
  { name: 'dangerouslySetInnerHTML', re: /dangerouslySetInnerHTML/ },
  { name: 'child_process exec', re: /\bexec(?:Sync)?\s*\(/ },
  { name: 'TLS 검증 비활성', re: /rejectUnauthorized\s*:\s*false/ },
  { name: 'SQL 문자열 결합', re: /(?:query|sql)\s*\(\s*[`'"].*\$\{/i },
];

export function checkDangerous(root) {
  const files = walk(root, { exts: CODE_EXT, maxFiles: 6000 });
  const hits = [];
  for (const f of files) {
    const text = readTextSafe(f);
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      for (const p of PATTERNS) {
        if (p.re.test(lines[i])) hits.push({ file: path.relative(root, f), line: i + 1, kind: p.name });
      }
    }
  }
  return [{
    id: 'code.dangerous-pattern',
    status: hits.length ? 'info' : 'pass',
    observed: hits.length ? `검토가 필요한 위험 패턴 ${hits.length}건(문맥 확인 필요)` : '위험 코드 패턴 미검출',
    evidence: { hits: hits.slice(0, 60) },
  }];
}

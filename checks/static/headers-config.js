// 보안 헤더 '설정 존재' 정적 확인(라이브 관측을 보완).
// next.config / vercel.json / middleware / _headers 에 헤더 설정이 있으면 코치가 근거를 파일:라인으로 제시.
import path from 'node:path';
import { walk, readTextSafe } from '../../core/util.js';

const TARGET = /(?:next\.config\.(?:js|ts|mjs)|vercel\.json|middleware\.(?:js|ts)|_headers|netlify\.toml|\.htaccess)$/i;

export function checkHeadersConfig(root) {
  const files = walk(root, { maxFiles: 8000 }).filter(f => TARGET.test(path.basename(f)));
  const found = {};
  const wanted = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
  for (const f of files) {
    const text = (readTextSafe(f) || '').toLowerCase();
    for (const w of wanted) {
      if (text.includes(w)) {
        if (!found[w]) found[w] = [];
        found[w].push(path.relative(root, f));
      }
    }
  }
  return [{
    id: 'code.headers-config',
    status: Object.keys(found).length ? 'info' : 'info',
    observed: Object.keys(found).length ? `헤더 설정 발견: ${Object.keys(found).join(', ')}` : '헤더 설정 파일에서 보안 헤더 설정을 못 찾음(라이브 관측을 우선 신뢰)',
    evidence: { configuredHeaders: found, filesScanned: files.map(f => path.relative(root, f)) },
  }];
}

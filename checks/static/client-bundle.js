// 클라이언트 노출 위험: service_role/시크릿이 NEXT_PUBLIC_* 등 클라 노출 변수에 들어갔는지.
// 결정적: 소스에서 위험 대입 패턴을 파일:라인으로.
import path from 'node:path';
import { walk, readTextSafe } from '../../core/util.js';
import { readExactDeploymentFile } from './exact-file.js';

const CODE_EXT = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.env', '.env.local', '.env.production'];

export function checkClientBundle(root, options = {}) {
  const exactDeploymentFiles = Array.isArray(options.files);
  const files = exactDeploymentFiles ? options.files : walk(root, { exts: CODE_EXT, maxFiles: 5000 });
  const hits = [];
  for (const entry of files) {
    const exact = exactDeploymentFiles ? readExactDeploymentFile(root, entry) : null;
    const f = exactDeploymentFiles ? exact.file : entry;
    const text = exactDeploymentFiles ? exact.text : readTextSafe(f);
    if (text === null) {
      if (exactDeploymentFiles) throw new Error(`${f} 배포 입력을 클라이언트 시크릿 검사 중 읽지 못했습니다.`);
      continue;
    }
    if (!text) continue;
    if (exactDeploymentFiles) {
      const publicSecret = /(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE|PASSWORD)/i.exec(text);
      if (publicSecret) {
        hits.push({ file: exact.relativePath, line: text.slice(0, publicSecret.index).split(/\r?\n/).length, kind: '클라 노출 변수에 시크릿성 이름' });
      }
      const literalRole = /service_role/i.test(text)
        && /supabase|createClient/i.test(text)
        && /eyJ[A-Za-z0-9_-]{10,}\.eyJ/.test(text);
      if (literalRole) {
        const index = text.search(/service_role/i);
        hits.push({ file: exact.relativePath, line: index < 0 ? 1 : text.slice(0, index).split(/\r?\n/).length, kind: 'service_role 키 리터럴' });
      }
      continue;
    }
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      // NEXT_PUBLIC_ / VITE_ / PUBLIC_ / REACT_APP_ 접두 + service_role/secret/private 값
      if (/(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE|PASSWORD)/i.test(l)) {
        hits.push({ file: path.relative(root, f), line: i + 1, kind: '클라 노출 변수에 시크릿성 이름', snippet: l.trim().slice(0, 120) });
      }
      // service_role 키를 클라 코드에 직접
      if (/service_role/i.test(l) && /supabase|createClient/i.test(text) && !/process\.env/.test(l)) {
        // 서버 전용 파일이 아닌데 리터럴로 박혀 있으면 위험 후보
        if (/eyJ[A-Za-z0-9_-]{10,}\.eyJ/.test(l)) hits.push({ file: path.relative(root, f), line: i + 1, kind: 'service_role 키 리터럴', snippet: l.trim().slice(0, 60) + '…' });
      }
    }
  }
  return [{
    id: 'code.client-secret-leak',
    status: hits.length ? 'fail' : 'pass',
    observed: hits.length ? `클라이언트에 노출될 수 있는 시크릿 ${hits.length}건` : '클라 시크릿 노출 미검출',
    evidence: { hits: hits.slice(0, 50) },
  }];
}

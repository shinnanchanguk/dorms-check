// 다시 빌드해도 남는 자리 (0.5.2, 회원 검토 치명 1).
// 빌드 결과(dist 등)에만 쓴 안내는 Vercel·Netlify 처럼 서버에서 다시 빌드하면 사라진다.
// 그래서 빌드 도구가 그대로 복사하는 public/ 폴더와, 빌드가 출발하는 HTML 원본(Vite 의 index.html 등)에도 같은 안내를 둔다.
// JS·CSS 머리 주석은 빌드 결과에만 붙일 수 있어 다시 빌드하면 사라진다(README 에 붙이는 법을 안내한다).
import path from 'node:path';
import { exists } from '../core/util.js';
import { detectStack } from '../core/detect.js';

function inside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

// 반환: { publicDir: 절대경로|null, htmlTemplates: [절대경로], stack }
export function rebuildTargets(root, buildFull) {
  const d = detectStack(root);
  const buildAbs = path.resolve(buildFull);
  const rootAbs = path.resolve(root);
  let publicDir = path.join(rootAbs, 'public');
  if (!exists(publicDir) || inside(buildAbs, publicDir) || inside(publicDir, buildAbs)) publicDir = null;
  const htmlTemplates = [];
  const add = rel => {
    const p = path.join(rootAbs, rel);
    if (exists(p) && !inside(p, buildAbs)) htmlTemplates.push(p);
  };
  if (buildAbs !== rootAbs) {
    if (d.stack === 'cra') add(path.join('public', 'index.html'));
    else if (d.stack === 'sveltekit') add(path.join('src', 'app.html'));
    else if (['vite', 'vue', 'static', 'unknown'].includes(d.stack)) add('index.html');
  }
  return { publicDir, htmlTemplates, stack: d.stack };
}

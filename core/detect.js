// 스택 감지: 프레임워크 + Supabase/Vercel 흔적 + applies 태그(카탈로그 활성 필터 입력).
import fs from 'node:fs';
import path from 'node:path';
import { exists, readJsonSafe, readTextSafe, walk } from './util.js';

function listEntries(root) {
  try { return fs.readdirSync(root); } catch { return []; }
}

export function detectStack(root) {
  const pkg = readJsonSafe(path.join(root, 'package.json')) || {};
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const has = n => Object.prototype.hasOwnProperty.call(deps, n);
  const files = listEntries(root);
  const hasFile = re => files.some(f => re.test(f));

  let stack = 'unknown', framework = 'Unknown / 범용';
  const applies = [];
  const buildCandidates = []; // 스택별 빌드 산출물 후보(protection 트랙이 산출물 검사에 사용)

  if (has('next') || hasFile(/^next\.config\./)) { stack = 'next'; framework = 'Next.js'; applies.push('nextjs'); buildCandidates.push('.next', 'out'); }
  else if (has('vite') || hasFile(/^vite\.config\./)) { stack = 'vite'; framework = 'Vite'; applies.push('vite'); buildCandidates.push('dist'); }
  else if (has('react-scripts')) { stack = 'cra'; framework = 'Create React App'; applies.push('cra'); buildCandidates.push('build'); }
  else if (has('@sveltejs/kit')) { stack = 'sveltekit'; framework = 'SvelteKit'; applies.push('svelte'); buildCandidates.push('build', '.svelte-kit'); }
  else if (has('nuxt') || has('nuxt3')) { stack = 'nuxt'; framework = 'Nuxt'; applies.push('nuxt'); buildCandidates.push('.output', 'dist'); }
  else if (has('astro')) { stack = 'astro'; framework = 'Astro'; applies.push('astro'); buildCandidates.push('dist'); }
  else if (has('@remix-run/react') || has('@remix-run/node')) { stack = 'remix'; framework = 'Remix'; applies.push('remix'); buildCandidates.push('build', 'public/build'); }
  else if (has('@angular/core') || hasFile(/^angular\.json$/)) { stack = 'angular'; framework = 'Angular'; applies.push('angular'); buildCandidates.push('dist'); }
  else if (has('vue')) { stack = 'vue'; framework = 'Vue'; applies.push('vue'); buildCandidates.push('dist'); }
  else if (hasFile(/^index\.html$/)) { stack = 'static'; framework = '정적 HTML'; applies.push('static'); buildCandidates.push('.', 'public', '_site', 'dist'); }

  // Supabase / Firebase / Vercel 흔적
  const hasSupabase = has('@supabase/supabase-js') || has('@supabase/ssr') ||
    walk(root, { exts: ['.env', '.env.local'], maxFiles: 50 }).some(f => /SUPABASE/.test(readTextSafe(f) || ''));
  if (hasSupabase) applies.push('supabase');
  if (has('firebase') || has('firebase-admin')) applies.push('firebase');
  if (exists(path.join(root, 'vercel.json')) || has('vercel')) applies.push('vercel');

  // 실제 존재하는 빌드 산출물 디렉토리 탐색(ai-clone-shield detect 흡수 — 없으면 빌드 후 다시 감지)
  const allCandidates = [...buildCandidates, 'dist', 'build', 'out', 'public', '_site'];
  let buildDir = null;
  for (const cand of allCandidates) {
    const full = path.join(root, cand);
    if (exists(full) && exists(path.join(full, 'index.html'))) { buildDir = cand; break; }
  }
  if (!buildDir) {
    for (const cand of allCandidates) {
      if (exists(path.join(root, cand)) && cand !== '.') { buildDir = cand; break; }
    }
  }

  return {
    stack, framework, applies,
    buildDir, buildCandidates,
    hasPackageJson: exists(path.join(root, 'package.json')),
    hasSupabase,
  };
}

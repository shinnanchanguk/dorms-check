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

  if (has('next') || hasFile(/^next\.config\./)) { stack = 'next'; framework = 'Next.js'; applies.push('nextjs'); }
  else if (has('vite') || hasFile(/^vite\.config\./)) { stack = 'vite'; framework = 'Vite'; applies.push('vite'); }
  else if (has('react-scripts')) { stack = 'cra'; framework = 'Create React App'; applies.push('cra'); }
  else if (has('@sveltejs/kit')) { stack = 'sveltekit'; framework = 'SvelteKit'; applies.push('svelte'); }
  else if (has('nuxt') || has('nuxt3')) { stack = 'nuxt'; framework = 'Nuxt'; applies.push('nuxt'); }
  else if (has('astro')) { stack = 'astro'; framework = 'Astro'; applies.push('astro'); }
  else if (hasFile(/^index\.html$/)) { stack = 'static'; framework = '정적 HTML'; applies.push('static'); }

  // Supabase / Firebase / Vercel 흔적
  const hasSupabase = has('@supabase/supabase-js') || has('@supabase/ssr') ||
    walk(root, { exts: ['.env', '.env.local'], maxFiles: 50 }).some(f => /SUPABASE/.test(readTextSafe(f) || ''));
  if (hasSupabase) applies.push('supabase');
  if (has('firebase') || has('firebase-admin')) applies.push('firebase');
  if (exists(path.join(root, 'vercel.json')) || has('vercel')) applies.push('vercel');

  return {
    stack, framework, applies,
    hasPackageJson: exists(path.join(root, 'package.json')),
    hasSupabase,
  };
}

// HTML 후처리 헬퍼 (의존성 0, ai-clone-shield core/html.js 흡수 — ESM 변환).
// 어떤 스택이든 빌드 산출물 HTML 에 안전하게 주입하기 위한 공통 함수.
// 흡수하지 않은 것: 제로폭(ZWC) 워터마크 인코딩 — 편집·재작성으로 쉽게 사라지는 것을
// 증거처럼 표현하는 기능이라 정직성 원칙에 따라 폐기했다.

import fs from 'node:fs';
import path from 'node:path';

// 주의: replace 의 2번째 인자를 "문자열"로 주면 snippet 안의 $&, $$, $`, $1 등이
// 치환 특수패턴으로 해석돼 주입 HTML 이 깨진다. 반드시 콜백(함수)으로 넘긴다.
export function insertInHead(html, snippet) {
  if (/<\/head>/i.test(html)) return html.replace(/<\/head>/i, () => snippet + '\n</head>');
  if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, m => m + '\n' + snippet);
  if (/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i, m => m + '\n<head>\n' + snippet + '\n</head>');
  return snippet + '\n' + html;
}

export function insertBeforeBodyClose(html, snippet) {
  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, () => snippet + '\n</body>');
  if (/<\/html>/i.test(html)) return html.replace(/<\/html>/i, () => snippet + '\n</html>');
  return html + '\n' + snippet;
}

export function hasMarker(html, marker) { return html.indexOf(marker) !== -1; }

// HTML 주석 안에 안전하게 넣기 위해 주석 종료 시퀀스를 무력화
export function escapeForComment(s) {
  return String(s).replace(/--+/g, '-').replace(/>/g, ')');
}

export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function fill(tpl, vars) {
  return tpl.replace(/\{(\w+)\}/g, (m, k) => (vars[k] !== undefined && vars[k] !== null ? String(vars[k]) : ''));
}

// ── 화면 바탕(body) 배치 검사: 바닥 출처 줄을 body 의 마지막 자식으로 넣어도 화면이 그대로인지 ──
// body 가 grid·가로 flex 면 줄이 칸 하나를 차지해 기존 칸이 줄어들고, html/body 가 넘침을 숨기면
// 줄이 화면 밖에 놓여 보이지 않는다. 그런 페이지에는 줄을 넣지 않는다(정적 추정, CSS-in-JS 는 못 본다).
function stripCssComments(css) { return String(css).replace(/\/\*[\s\S]*?\*\//g, ''); }
const ROOT_SEL = /(^|[\s>~+])(html|body|:root)([.#:[][^\s>~+]*)?$/i;

function declsFor(css, which) {
  const out = {};
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m;
  const src = stripCssComments(css);
  while ((m = re.exec(src))) {
    const sels = m[1].split(',').map(x => x.trim()).filter(Boolean);
    const hits = sels.some(sel => {
      const mm = ROOT_SEL.exec(sel);
      if (!mm) return false;
      const tag = mm[2].toLowerCase();
      return which === 'body' ? tag === 'body' : (tag === 'html' || tag === ':root');
    });
    if (!hits) continue;
    for (const d of m[2].split(';')) {
      const i = d.indexOf(':');
      if (i === -1) continue;
      out[d.slice(0, i).trim().toLowerCase()] = d.slice(i + 1).replace(/!important/i, '').trim().toLowerCase();
    }
  }
  return out;
}

function attr(tagSrc, name) {
  const m = new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tagSrc || '');
  return m ? (m[2] ?? m[3] ?? m[4] ?? '') : '';
}

export function bodyLayoutRisk(html, cssTexts = []) {
  const bodyTag = (/<body\b[^>]*>/i.exec(html) || [''])[0];
  const htmlTag = (/<html\b[^>]*>/i.exec(html) || [''])[0];
  const inline = [...cssTexts, ...[...String(html).matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)].map(x => x[1])];
  const css = inline.join('\n') + `\nbody{${attr(bodyTag, 'style')}}\nhtml{${attr(htmlTag, 'style')}}`;
  const b = declsFor(css, 'body');
  const h = declsFor(css, 'html');
  const cls = ` ${attr(bodyTag, 'class')} `.toLowerCase();
  const hcls = ` ${attr(htmlTag, 'class')} `.toLowerCase();
  const display = b.display || '';
  if (/\b(inline-)?grid\b/.test(display) || /\s(grid|inline-grid)\s/.test(cls)) return 'grid';
  const col = /column/.test(b['flex-direction'] || '') || /^column/.test(b['flex-flow'] || '') || /\sflex-col(-reverse)?\s/.test(cls);
  if ((/\b(inline-)?flex\b/.test(display) || /\s(flex|inline-flex)\s/.test(cls)) && !col) return 'flex';
  const hidden = v => /\b(hidden|clip)\b/.test(v || '');
  if (hidden(b.overflow) || hidden(b['overflow-y']) || hidden(h.overflow) || hidden(h['overflow-y'])) return 'overflow';
  if (/\soverflow(-y)?-(hidden|clip)\s/.test(cls) || /\soverflow(-y)?-(hidden|clip)\s/.test(hcls)) return 'overflow';
  return null;
}

// 페이지가 부르는 로컬 CSS 파일 글(링크 rel=stylesheet). 루트 기준 주소는 배포 접두어를 떼고 찾는다.
export function linkedCss(html, file, buildFull, readText) {
  const out = [];
  for (const m of String(html).matchAll(/<link\b[^>]*>/gi)) {
    const tag = m[0];
    if (!/rel\s*=\s*["']?stylesheet/i.test(tag)) continue;
    const href = attr(tag, 'href');
    const abs = resolveLocalRef(href, file, buildFull);
    if (!abs) continue;
    const txt = readText(abs);
    if (txt) out.push(txt);
  }
  return out;
}

function inBuild(buildFull, abs) {
  const b = path.resolve(buildFull);
  return abs === b || abs.startsWith(b + path.sep);
}
export function resolveLocalRef(ref, file, buildFull) {
  if (!ref || /^(https?:|data:|mailto:|tel:|javascript:|#|\/\/)/i.test(ref)) return null;
  const clean = ref.split('?')[0].split('#')[0];
  if (!clean) return null;
  if (clean.startsWith('/')) {
    const segs = clean.split('/').filter(Boolean);
    for (let i = 0; i < segs.length; i++) {
      const abs = path.resolve(buildFull, ...segs.slice(i));
      if (inBuild(buildFull, abs) && fs.existsSync(abs)) return abs;
    }
    return null;
  }
  const abs = path.resolve(path.dirname(file), clean);
  return inBuild(buildFull, abs) && fs.existsSync(abs) ? abs : null;
}

// 이용 안내 링크 주소. 페이지가 자산을 루트 기준(/assets/..., /myapp/assets/...)으로 부르면 SPA 의 깊은 주소
// (/lesson/3)에서도 열리게 같은 접두어의 루트 기준 주소(/usage.html, /myapp/usage.html)를 쓴다.
// 상대 주소로 부르는 페이지(./assets)는 파일 기준 상대 주소를 쓴다. <base href> 가 있으면 그것을 따른다.
export function usageHref(html, file, buildFull, usageFile) {
  const usageRel = path.relative(buildFull, usageFile).split(path.sep).join('/');
  const base = /<base\b[^>]*>/i.exec(html);
  if (base) {
    const bh = attr(base[0], 'href');
    if (bh && bh.startsWith('/') && !bh.startsWith('//')) return bh.replace(/\/?$/, '/') + usageRel;
  }
  for (const m of String(html).matchAll(/<(?:script|link)\b[^>]*>/gi)) {
    const ref = attr(m[0], 'src') || attr(m[0], 'href');
    if (!ref || !ref.startsWith('/') || ref.startsWith('//')) continue;
    const abs = resolveLocalRef(ref, file, buildFull);
    if (!abs) continue;
    const rel = path.relative(buildFull, abs).split(path.sep).join('/');
    const clean = ref.split('?')[0].split('#')[0];
    if (!clean.endsWith(rel)) continue;
    const prefix = clean.slice(0, clean.length - rel.length);
    return (prefix.endsWith('/') ? prefix : prefix + '/') + usageRel;
  }
  const r = path.relative(path.dirname(file), usageFile).split(path.sep).join('/');
  return r || path.basename(usageFile);
}

// 복제 의심 주소 대조 (ai-clone-shield 의 watermark-check 를 대신한다. 제로폭 워터마크는 쓰지 않는다).
// 의심 주소의 공개 HTML·같은 출처 JS/CSS·llms.txt·dorms.json 을 받아, 내 앱의 출처 표식(번호·주석·주소·이름)과
// 빌드 파일 지문(sha256)이 보이는지 사실만 기록한다. 결과는 .dorms-check/protect/evidence/ 에 날짜별로 남긴다.
// 정직한 한계: 표식이 없다고 복제가 아니라는 뜻이 아니고(새로 다시 만든 복제엔 남지 않는다),
// 표식이 있다고 침해가 확정되는 것도 아니다. 법률 자문이 아니다.
import path from 'node:path';
import net from 'node:net';
import { request } from '../core/http.js';
import { walk, readTextSafe, readJsonSafe, writeText, sha256, exists } from '../core/util.js';
import { t } from '../core/copy.js';
import { provenanceFacts } from '../core/usage-policy.js';
import { JS_HEADER_PREFIX, stripJsHeader } from './provenance-text.js';

const MAX_ASSETS = 25;

export function isLocalHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h === '0.0.0.0') return true;
  if (net.isIPv4(h)) {
    const [a, b] = h.split('.').map(Number);
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0;
  }
  if (net.isIPv6(h)) return h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80');
  return false;
}

export function parseSuspectUrl(input, { allowLocal = false } = {}) {
  let u;
  try { u = new URL(String(input || '').trim()); } catch { return { ok: false, reason: t('cli.compareBadUrl') }; }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) return { ok: false, reason: t('cli.compareBadUrl') };
  if (!allowLocal && isLocalHost(u.hostname)) return { ok: false, reason: t('cli.compareLocalBlocked') };
  return { ok: true, url: u };
}

// HTML 에서 같은 출처 스크립트·스타일 주소만 뽑는다.
export function assetUrls(html, base) {
  const out = new Set();
  const re = /<(?:script|link)\b[^>]*?(?:src|href)\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = re.exec(html))) {
    const tag = m[0];
    if (/^<link/i.test(tag) && !/rel\s*=\s*["']?(?:stylesheet|modulepreload|preload)/i.test(tag)) continue;
    try {
      const u = new URL(m[1], base);
      if (u.origin !== base.origin) continue;
      if (!/\.(m?js|cjs|css)$/i.test(u.pathname)) continue;
      out.add(u.href);
    } catch { /* ignore */ }
    if (out.size >= MAX_ASSETS) break;
  }
  return [...out];
}

// 내 빌드 파일 지문: 그대로의 지문 + 머리 주석을 뗀 지문.
export function localFingerprints(root, buildFull) {
  const raw = new Map();
  const stripped = new Map();
  if (buildFull && exists(buildFull)) {
    for (const f of walk(buildFull, { exts: ['.js', '.mjs', '.cjs', '.css'] })) {
      const c = readTextSafe(f);
      if (c === null || c.length < 200) continue; // 아주 작은 파일은 우연히 같을 수 있어 뺀다
      const rel = path.relative(buildFull, f);
      raw.set(sha256(c), rel);
      stripped.set(sha256(stripJsHeader(c)), rel);
    }
  }
  const integ = readJsonSafe(path.join(root, '.dorms-check', 'protect', 'integrity.json'));
  if (integ && integ.files) for (const [rel, h] of Object.entries(integ.files)) if (/\.(m?js|cjs|css)$/.test(rel) && !raw.has(h)) raw.set(h, rel);
  return { raw, stripped };
}

// 넘겨주기(redirect)를 한 번씩 직접 따라가며, 매번 내부망 주소가 아닌지 다시 확인한다.
async function fetchChecked(href, { allowLocal, opts }) {
  let cur = href;
  for (let i = 0; i < 5; i++) {
    const r = await request(cur, { ...opts, redirect: 'manual' });
    if (!r.ok) return r;
    const loc = r.headers && r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc) {
      const next = parseSuspectUrl(new URL(loc, cur).href, { allowLocal });
      if (!next.ok) return { ok: false, error: next.reason };
      cur = next.url.href;
      continue;
    }
    return { ...r, finalUrl: cur };
  }
  return { ok: false, error: 'too many redirects' };
}

export async function compareSuspect(root, { url, buildFull, rightsProfile, allowLocal = false, fetchImpl, now = new Date() } = {}) {
  const parsed = parseSuspectUrl(url, { allowLocal });
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const base = parsed.url;
  const f = provenanceFacts(rightsProfile);
  const opts = fetchImpl ? { fetchImpl } : {};

  const get = h => fetchChecked(h, { allowLocal, opts });
  const page = await get(base.href);
  if (!page.ok) return { ok: false, reason: `주소를 열지 못했어요: ${page.error || 'network'}` };
  const finalBase = (() => { try { return new URL(page.finalUrl || base.href); } catch { return base; } })();
  if (!allowLocal && isLocalHost(finalBase.hostname)) return { ok: false, reason: t('cli.compareLocalBlocked') };

  const texts = [{ where: 'html', url: finalBase.href, body: page.body || '' }];
  for (const extra of ['/llms.txt', '/dorms.json']) {
    const r = await get(new URL(extra, finalBase).href);
    if (r.ok && r.status === 200 && r.body) texts.push({ where: extra.slice(1), url: new URL(extra, finalBase).href, body: r.body });
  }
  const assets = [];
  for (const a of assetUrls(page.body || '', finalBase)) {
    const r = await get(a);
    if (r.ok && r.status === 200 && r.body) { assets.push({ url: a, body: r.body }); texts.push({ where: 'asset', url: a, body: r.body }); }
  }

  const fp = localFingerprints(root, buildFull);
  const signals = [];
  const add = (id, where) => { if (!signals.some(s => s.id === id && s.where === where)) signals.push({ id, label: t('compare.signals.' + id), where }); };
  for (const x of texts) {
    if (f.provenanceId && x.body.includes(f.provenanceId)) add('provenanceId', x.url);
    if (x.where === 'html' && (x.body.includes('dorms-check:notice') || x.body.includes('data-dorms-check-'))) add('markerHtml', x.url);
    if (x.where === 'asset' && x.body.includes(JS_HEADER_PREFIX)) add('markerJs', x.url);
    if (f.dormsUrl && x.body.toLowerCase().includes(f.dormsUrl)) add('dormsUrl', x.url);
    if (f.creator && f.creator.length >= 2 && x.body.includes(f.creator)) add('creator', x.url);
    if (x.where === 'dorms.json') {
      const j = (() => { try { return JSON.parse(x.body); } catch { return null; } })();
      if (j && (j.provenanceId === f.provenanceId || (f.dormsUrl && j.app && j.app.dormsUrl === f.dormsUrl))) add('dormsJson', x.url);
    }
  }
  for (const a of assets) {
    const h = sha256(a.body);
    if (fp.raw.has(h)) add('bundleExact', `${a.url} = ${fp.raw.get(h)}`);
    else {
      const hs = sha256(stripJsHeader(a.body));
      if (fp.stripped.has(hs)) add('bundleStripped', `${a.url} = ${fp.stripped.get(hs)}`);
    }
  }

  const allIds = Object.keys({ provenanceId: 1, markerHtml: 1, markerJs: 1, dormsUrl: 1, creator: 1, bundleExact: 1, bundleStripped: 1, dormsJson: 1 });
  const foundIds = new Set(signals.map(s => s.id));
  const record = {
    at: now.toISOString(),
    url: base.href,
    finalUrl: finalBase.href,
    status: page.status,
    provenanceId: f.provenanceId,
    fetched: texts.map(x => ({ where: x.where, url: x.url, sha256: sha256(x.body), bytes: x.body.length })),
    signals,
    notFound: allIds.filter(id => !foundIds.has(id)).map(id => ({ id, label: t('compare.signals.' + id) })),
  };

  const stamp = now.toISOString().replace(/[:.]/g, '-');
  const host = finalBase.hostname.replace(/[^a-z0-9.-]/gi, '_').slice(0, 60);
  const outDir = path.join(root, '.dorms-check', 'protect', 'evidence');
  const base_ = path.join(outDir, `compare-${stamp}-${host}`);
  writeText(base_ + '.json', JSON.stringify(record, null, 2) + '\n');
  writeText(base_ + '.md', [
    `# ${t('compare.title')}`,
    '',
    `- ${t('compare.when')}: ${record.at}`,
    `- ${t('compare.url')}: ${record.url}`,
    `- ${t('compare.finalUrl')}: ${record.finalUrl} (HTTP ${record.status})`,
    '',
    `## ${t('compare.found')} (${signals.length})`,
    ...(signals.length ? signals.map(s => `- ${s.label}: ${s.where}`) : ['- 0']),
    '',
    `## ${t('compare.notFound')}`,
    ...record.notFound.map(s => `- ${s.label}`),
    '',
    '## sha256',
    ...record.fetched.map(x => `- ${x.where} ${x.url} ${x.sha256}`),
    '',
    t('compare.honest'),
    '',
  ].join('\n'));
  return { ok: true, record, file: base_ + '.md' };
}

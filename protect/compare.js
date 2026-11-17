// 복제 의심 주소 대조 (ai-clone-shield 의 watermark-check 를 대신한다. 제로폭 워터마크는 쓰지 않는다).
// 의심 주소의 공개 HTML·같은 출처 JS/CSS·llms.txt·dorms.json 을 받아, 내 앱의 출처 표식(번호·주석·주소·이름)과
// 빌드 파일 지문(sha256)이 보이는지 사실만 기록한다. 결과는 .dorms-check/protect/evidence/ 에 날짜별로 남긴다.
// 정직한 한계: 표식이 없다고 복제가 아니라는 뜻이 아니고(새로 다시 만든 복제엔 남지 않는다),
// 표식이 있다고 침해가 확정되는 것도 아니다. 법률 자문이 아니다.
import path from 'node:path';
import { readdirSync as fsReaddir } from 'node:fs';
import net from 'node:net';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import { walk, readTextSafe, readJsonSafe, safeWrite, assertStateDirSafe, sha256, exists } from '../core/util.js';
import { t } from '../core/copy.js';
import { provenanceFacts } from '../core/usage-policy.js';
import { JS_HEADER_PREFIX, stripJsHeader } from './provenance-text.js';
import { isVendorFile } from './steps/provenance.js';

const MAX_ASSETS = 25;
const MAX_REDIRECTS = 5;
// 0.5.2: 큰 번들도 통째로 대조하도록 2MB → 8MB. 넘으면 '일부만 받음'으로 적고 통째 지문은 비교하지 않는다.
const MAX_BODY = 8 * 1024 * 1024;
// 0.5.2: 이름을 밝히는 요청 머리를 쓰면 그 요청에만 빈 화면을 주는 식으로 속일 수 있어 보통 브라우저처럼 요청한다.
export const BROWSER_HEADERS = {
  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'accept-language': 'ko-KR,ko;q=0.9,en;q=0.8',
};
const SIMILAR_MIN = 0.5; // 내 파일 조각의 절반 이상이 그 파일에 있으면 '많이 겹침'으로 적는다
const HISTORY_DIR = path.join('.dorms-check', 'protect', 'integrity-history');
const MAX_HISTORY = 60;
const TIMEOUT_MS = 15000;        // 요청 하나(이어받는 시간 포함 전체)
const TOTAL_TIMEOUT_MS = 90000;  // 대조 한 번 전체

// 이름 정리: 소문자, 대괄호·끝 점 제거("localhost." 우회 막기).
export function normalizeHost(hostname) {
  return String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
}

function v4ToInt(ip) { return ip.split('.').reduce((n, o) => (n * 256) + Number(o), 0) >>> 0; }
const V4_BLOCKS = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([b, m]) => [v4ToInt(b), m]);
function blockedV4(ip) {
  const n = v4ToInt(ip);
  return V4_BLOCKS.some(([b, m]) => ((n >>> (32 - m)) === (b >>> (32 - m))));
}

// IPv6 를 16바이트로 펼친다(::ffff:1.2.3.4 같은 끝 IPv4 표기 포함).
function v6Bytes(ip) {
  let s = ip;
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  let tail = [];
  if (v4) {
    tail = v4[1].split('.').map(Number);
    s = s.slice(0, -v4[1].length) + '0:0';
  }
  const [head, rest] = s.split('::');
  const h = head ? head.split(':') : [];
  const r = rest !== undefined && rest !== '' ? rest.split(':') : [];
  const fill = s.includes('::') ? 8 - h.length - r.length : 0;
  const groups = [...h, ...Array(Math.max(0, fill)).fill('0'), ...r].map(g => parseInt(g || '0', 16));
  const bytes = [];
  for (const g of groups) bytes.push((g >> 8) & 255, g & 255);
  if (v4) bytes.splice(12, 4, ...tail);
  return bytes;
}
function blockedV6(ip) {
  const b = v6Bytes(ip);
  if (b.length !== 16) return true;
  const allZero = n => b.slice(0, n).every(x => x === 0);
  if (allZero(16)) return true;                                   // ::
  if (allZero(15) && b[15] === 1) return true;                    // ::1
  if (allZero(10) && b[10] === 255 && b[11] === 255) return blockedV4(b.slice(12).join('.')); // ::ffff:a.b.c.d
  if (allZero(8) && b[8] === 255 && b[9] === 255 && b[10] === 0 && b[11] === 0) return blockedV4(b.slice(12).join('.')); // ::ffff:0:a.b.c.d (SIIT)
  if (allZero(12)) return blockedV4(b.slice(12).join('.'));      // ::a.b.c.d (옛 표기)
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return blockedV4(b.slice(12).join('.')); // 64:ff9b::/96
  if ((b[0] & 0xfe) === 0xfc) return true;                        // fc00::/7
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;       // fe80::/10
  if (b[0] === 0xff) return true;                                 // 멀티캐스트
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true; // 문서용
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return true;       // fec0::/10 (옛 사이트 로컬)
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00) return true; // 2001::/32 Teredo(안에 IPv4 를 숨김)
  if (b[0] === 0x20 && b[1] === 0x02) return blockedV4(b.slice(2, 6).join('.')); // 2002::/16 6to4: 안의 IPv4 로 판정
  if (b[0] === 0x01 && b.slice(1, 8).every(x => x === 0)) return true; // 100::/64 버리는 주소
  return false;
}

// 주소(IP) 하나가 내 컴퓨터·내부망·특수 용도면 true.
export function isBlockedAddress(ip) {
  const h = normalizeHost(ip);
  if (net.isIPv4(h)) return blockedV4(h);
  if (net.isIPv6(h)) return blockedV6(h);
  return true; // IP 가 아니면 막는다(이 함수는 IP 만 받는다)
}

// 이름만으로 막을 수 있는 경우(IP 글자이거나 localhost 계열).
export function isLocalHost(hostname) {
  const h = normalizeHost(hostname);
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (net.isIP(h)) return isBlockedAddress(h);
  return false;
}

export function parseSuspectUrl(input, { allowLocal = false } = {}) {
  let u;
  try { u = new URL(String(input || '').trim()); } catch { return { ok: false, reason: t('cli.compareBadUrl') }; }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) return { ok: false, reason: t('cli.compareBadUrl') };
  if (!allowLocal && isLocalHost(u.hostname)) return { ok: false, reason: t('cli.compareLocalBlocked') };
  return { ok: true, url: u };
}

// 이름을 풀어 나온 주소가 하나라도 막힌 주소면 거부한다. 통과한 주소 하나를 돌려준다.
export async function resolveSafe(hostname, { allowLocal = false, lookupImpl = dns.promises.lookup } = {}) {
  const h = normalizeHost(hostname);
  if (net.isIP(h)) {
    if (!allowLocal && isBlockedAddress(h)) return { ok: false, reason: t('cli.compareLocalBlocked') };
    return { ok: true, address: h, family: net.isIP(h) };
  }
  if (!allowLocal && isLocalHost(h)) return { ok: false, reason: t('cli.compareLocalBlocked') };
  let addrs;
  try { addrs = await lookupImpl(h, { all: true, verbatim: true }); }
  catch (e) { return { ok: false, reason: `주소를 찾지 못했어요: ${e.code || e.message}` }; }
  if (!Array.isArray(addrs) || !addrs.length) return { ok: false, reason: '주소를 찾지 못했어요' };
  if (!allowLocal && addrs.some(a => isBlockedAddress(a.address))) return { ok: false, reason: t('cli.compareLocalBlocked') };
  return { ok: true, address: addrs[0].address, family: addrs[0].family || net.isIP(addrs[0].address) };
}

// 확인한 IP 로만 접속한다(확인과 접속 사이에 DNS 가 바뀌어도 그 IP 로 간다). 크기·시간 상한.
function pinnedGet(u, pinned, timeoutMs = TIMEOUT_MS) {
  return new Promise(resolve => {
    let settled = false;
    const finish = v => { if (!settled) { settled = true; clearTimeout(timer); resolve(v); } };
    // 요청 하나의 전체 시간 한도. 서버가 몇 초마다 한 글자씩 흘려도 여기서 끊는다(소켓 쉬는 시간 한도만으로는 못 끊는다).
    const timer = setTimeout(() => { try { req.destroy(new Error('timeout')); } catch { /* 이미 닫힘 */ } finish({ ok: false, error: 'timeout' }); }, Math.max(1, timeoutMs));
    const mod = u.protocol === 'https:' ? https : http;
    const lookup = (_host, opts, cb) => {
      if (typeof opts === 'function') cb = opts;
      if (opts && opts.all) cb(null, [{ address: pinned.address, family: pinned.family }]);
      else cb(null, pinned.address, pinned.family);
    };
    const req = mod.request({
      protocol: u.protocol, hostname: normalizeHost(u.hostname), port: u.port || undefined,
      path: u.pathname + u.search, method: 'GET', lookup, servername: net.isIP(normalizeHost(u.hostname)) ? undefined : normalizeHost(u.hostname),
      headers: { ...BROWSER_HEADERS, host: u.host },
      timeout: Math.max(1, timeoutMs), agent: false,
    }, res => {
      const chunks = []; let total = 0; let truncated = false;
      res.on('data', c => {
        if (truncated) return;
        total += c.length;
        if (total > MAX_BODY) { truncated = true; chunks.push(c.subarray(0, c.length - (total - MAX_BODY))); res.destroy(); return; }
        chunks.push(c);
      });
      const done = () => finish({ ok: true, status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), truncated });
      res.on('end', done);
      res.on('close', done);
      res.on('error', () => done());
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', e => finish({ ok: false, error: e.code || e.message }));
    req.end();
  });
}

// 테스트용 fetchImpl 이 있으면 그것으로 받되, 주소 검사(이름 풀기 포함)는 똑같이 한다.
async function fetchOnce(u, pinned, fetchImpl, timeoutMs) {
  if (!fetchImpl) return pinnedGet(u, pinned, timeoutMs);
  try {
    const res = await fetchImpl(u.href, { redirect: 'manual', headers: BROWSER_HEADERS });
    const full = await res.text();
    const truncated = full.length > MAX_BODY;
    return { ok: true, status: res.status, headers: { location: res.headers.get('location') || undefined }, body: truncated ? full.slice(0, MAX_BODY) : full, truncated };
  } catch (e) { return { ok: false, error: e.message }; }
}

// 넘겨주기(redirect)를 한 번씩 직접 따라가며, 매번 주소 글자와 풀린 IP 를 다시 검사한다.
export async function fetchChecked(href, { allowLocal, fetchImpl, lookupImpl, deadline, requestTimeoutMs = TIMEOUT_MS }) {
  let cur = href;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const left = deadline ? deadline - Date.now() : requestTimeoutMs;
    if (left <= 0) return { ok: false, error: 'timeout' };
    const p = parseSuspectUrl(cur, { allowLocal });
    if (!p.ok) return { ok: false, error: p.reason };
    const pinned = await resolveSafe(p.url.hostname, { allowLocal, lookupImpl });
    if (!pinned.ok) return { ok: false, error: pinned.reason };
    const r = await fetchOnce(p.url, pinned, fetchImpl, Math.min(requestTimeoutMs, left));
    if (!r.ok) return r;
    const loc = r.headers && r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc) {
      try { cur = new URL(loc, p.url).href; } catch { return { ok: false, error: 'bad redirect' }; }
      continue;
    }
    return { ...r, finalUrl: p.url.href };
  }
  return { ok: false, error: 'too many redirects' };
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

// 프레임워크가 모든 앱에 똑같이 넣는 작은 공통 조각(Vite modulepreload polyfill·preload helper·웹팩 실행 조각 등).
// 이런 파일이 같다고 내 앱의 복제본이라고 볼 수 없으니 지문 대조에서 뺀다(0.5.2, 회원 검토 허점 5).
const COMMON_NAME_RE = /(modulepreload-polyfill|preload-helper|__vite|vite[-_]?(?:browser|env|client)|webpack-runtime|webpack\b|runtime[.~-]|polyfills?[.-]|framework[.-]|main-app[.-]|_buildManifest|_ssgManifest|react-refresh|turbopack)/i;
const COMMON_BODY_RE = [
  /\.supports\(["']modulepreload["']\)/,           // Vite modulepreload polyfill
  /__vitePreload|"modulepreload"\s*,\s*\w+\s*=\s*function/, // Vite preload helper
  /webpackChunk[\w$]*\s*=\s*self\.webpackChunk/,
];
export function isCommonChunk(rel, body) {
  const name = String(rel || '').split(/[\\/]/).pop();
  if (isVendorFile(String(rel || '')) || COMMON_NAME_RE.test(name)) return true;
  const b = String(body || '');
  return b.length < 6000 && COMMON_BODY_RE.some(re => re.test(b));
}

// 부분 일치용 조각 지문: 머리 주석을 떼고 문장 단위(; { } 줄바꿈)로 자른 뒤, 이웃한 조각 4개씩 묶어 해시한다.
// 압축된 코드는 조각 하나가 짧아서 묶어야 우연한 일치가 줄어든다. 한 글자를 바꾸면 그 근처 묶음 몇 개만 달라지므로,
// 통째 지문이 어긋나도 얼마나 같은지 비율로 말할 수 있다.
const SHINGLE = 4;
export function chunkPrints(body) {
  const out = new Set();
  const text = stripJsHeader(String(body || '')).replace(/\s+/g, ' ');
  const pieces = [];
  for (const piece of text.split(/[;{}\n]/)) {
    const p = piece.trim();
    if (p) pieces.push(p);
    if (pieces.length >= 200000) break;
  }
  for (let i = 0; i + SHINGLE <= pieces.length; i++) {
    const w = pieces.slice(i, i + SHINGLE).join(';');
    if (w.length >= 40) out.add(sha256(w).slice(0, 16));
    if (out.size >= 50000) break;
  }
  return out;
}

// 판마다 지문을 쌓는다: protect apply 마다 integrity-history/<시각>.json 이 하나씩 남는다(지우지 않는다).
export function loadIntegrityHistory(root) {
  const dir = path.join(root, HISTORY_DIR);
  if (!exists(dir)) return [];
  let names = [];
  try { names = fsReaddir(dir).filter(n => /^[\w.-]+\.json$/.test(n)).sort(); } catch { return []; }
  return names.slice(-MAX_HISTORY).map(n => readJsonSafe(path.join(dir, n))).filter(x => x && x.files && typeof x.files === 'object');
}

// 내 빌드 파일 지문: 그대로의 지문 + 머리 주석을 뗀 지문 + 지난 판 지문 + 부분 일치용 조각 지문.
export function localFingerprints(root, buildFull) {
  const raw = new Map();
  const stripped = new Map();
  const old = new Map();     // 지난 판에만 있던 지문 → { rel, at }
  const chunks = [];         // [{ rel, prints:Set }]
  if (buildFull && exists(buildFull)) {
    for (const f of walk(buildFull, { exts: ['.js', '.mjs', '.cjs', '.css'] })) {
      const c = readTextSafe(f);
      if (c === null || c.length < 200) continue; // 아주 작은 파일은 우연히 같을 수 있어 뺀다
      const rel = path.relative(buildFull, f);
      if (isCommonChunk(rel, c)) continue;
      raw.set(sha256(c), rel);
      stripped.set(sha256(stripJsHeader(c)), rel);
      const prints = chunkPrints(c);
      if (prints.size >= 5) chunks.push({ rel, prints });
    }
  }
  const integ = readJsonSafe(path.join(root, '.dorms-check', 'protect', 'integrity.json'));
  const histories = [...loadIntegrityHistory(root), ...(integ && integ.files ? [integ] : [])];
  for (const h of histories) {
    for (const [rel, hash] of Object.entries(h.files)) {
      if (!/\.(m?js|cjs|css)$/.test(rel) || isCommonChunk(rel, '')) continue;
      if (h.common && h.common.includes(rel)) continue;
      if (!raw.has(hash) && !old.has(hash)) old.set(hash, { rel, at: h.at || '' });
    }
  }
  return { raw, stripped, old, chunks };
}

export async function compareSuspect(root, { url, buildFull, rightsProfile, allowLocal = false, fetchImpl, lookupImpl, now = new Date(), requestTimeoutMs = TIMEOUT_MS, totalTimeoutMs = TOTAL_TIMEOUT_MS } = {}) {
  const parsed = parseSuspectUrl(url, { allowLocal });
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const base = parsed.url;
  const f = provenanceFacts(rightsProfile);
  const deadline = Date.now() + totalTimeoutMs;
  const get = h => fetchChecked(h, { allowLocal, fetchImpl, lookupImpl, deadline, requestTimeoutMs });
  const page = await get(base.href);
  if (!page.ok && page.error === 'timeout') return { ok: false, reason: t('cli.compareTimeout', { seconds: Math.round(Math.min(requestTimeoutMs, totalTimeoutMs) / 1000) }) };
  if (!page.ok) return { ok: false, reason: page.error === t('cli.compareLocalBlocked') ? page.error : `주소를 열지 못했어요: ${page.error || 'network'}` };
  const finalBase = (() => { try { return new URL(page.finalUrl || base.href); } catch { return base; } })();

  const texts = [{ where: 'html', url: finalBase.href, body: page.body || '' }];
  for (const extra of ['/llms.txt', '/dorms.json']) {
    const r = await get(new URL(extra, finalBase).href);
    if (r.ok && r.status === 200 && r.body) texts.push({ where: extra.slice(1), url: new URL(extra, finalBase).href, body: r.body });
  }
  const assets = [];
  for (const a of assetUrls(page.body || '', finalBase)) {
    const r = await get(a);
    if (r.ok && r.status === 200 && r.body) { assets.push({ url: a, body: r.body, truncated: Boolean(r.truncated) }); texts.push({ where: 'asset', url: a, body: r.body, truncated: Boolean(r.truncated) }); }
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
  const skippedCommon = [];
  for (const a of assets) {
    // 프레임워크 공통 조각은 어느 앱에나 똑같이 있으니 대조하지 않는다.
    if (isCommonChunk(new URL(a.url).pathname, a.body)) { skippedCommon.push(a.url); continue; }
    if (!a.truncated) {
      const h = sha256(a.body);
      if (fp.raw.has(h)) { add('bundleExact', `${a.url} = ${fp.raw.get(h)}`); continue; }
      const hs = sha256(stripJsHeader(a.body));
      if (fp.stripped.has(hs)) { add('bundleStripped', `${a.url} = ${fp.stripped.get(hs)}`); continue; }
      const o = fp.old.get(h) || fp.old.get(hs);
      if (o) { add('bundleOld', `${a.url} = ${o.rel} (${o.at.slice(0, 10)})`); continue; }
    }
    // 통째로 같지 않으면 조각이 얼마나 겹치는지 본다(일부만 받은 큰 파일도 받은 만큼으로 본다).
    const theirs = chunkPrints(a.body);
    if (theirs.size < 5) continue;
    let best = null;
    for (const mine of fp.chunks) {
      let same = 0;
      for (const x of mine.prints) if (theirs.has(x)) same++;
      const ratio = same / mine.prints.size;
      if (!best || ratio > best.ratio) best = { rel: mine.rel, ratio };
    }
    if (best && best.ratio >= SIMILAR_MIN) add('bundleSimilar', `${a.url} ≈ ${best.rel} (${Math.round(best.ratio * 100)}%)`);
  }

  const allIds = Object.keys({ provenanceId: 1, markerHtml: 1, markerJs: 1, dormsUrl: 1, creator: 1, bundleExact: 1, bundleStripped: 1, bundleOld: 1, bundleSimilar: 1, dormsJson: 1 });
  const foundIds = new Set(signals.map(s => s.id));
  const record = {
    at: now.toISOString(),
    url: base.href,
    finalUrl: finalBase.href,
    status: page.status,
    provenanceId: f.provenanceId,
    fetched: texts.map(x => ({ where: x.where, url: x.url, sha256: sha256(x.body), bytes: x.body.length, ...(x.truncated ? { truncated: true } : {}) })),
    signals,
    skippedCommon,
    notFound: allIds.filter(id => !foundIds.has(id)).map(id => ({ id, label: t('compare.signals.' + id) })),
  };

  const stamp = now.toISOString().replace(/[:.]/g, '-');
  const host = finalBase.hostname.replace(/[^a-z0-9.-]/gi, '_').slice(0, 60);
  const outDir = path.join(root, '.dorms-check', 'protect', 'evidence');
  const base_ = path.join(outDir, `compare-${stamp}-${host}`);
  assertStateDirSafe(root);
  safeWrite(root, base_ + '.json', JSON.stringify(record, null, 2) + '\n');
  safeWrite(root, base_ + '.md', [
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
    ...(skippedCommon.length ? [`## ${t('compare.skippedCommon')}`, ...skippedCommon.map(u => `- ${u}`), ''] : []),
    '## sha256',
    ...record.fetched.map(x => `- ${x.where} ${x.url} ${x.sha256}${x.truncated ? ' (' + t('compare.truncated') + ')' : ''}`),
    '',
    t('compare.honest'),
    '',
  ].join('\n'));
  return { ok: true, record, file: base_ + '.md' };
}

// 출처 안내 문구 조립(순수 함수). 문구는 모두 templates/copy.ko.json 에서 읽는다.
// 원칙: 사실과 정중한 부탁만. 숨은 명령·과장·겁주기 없음. 베끼는 사람의 AI 가 읽는 자리마다 같은 내용을 심는다.
import { t, copyValue } from '../core/copy.js';
import { LAW_ARTICLES, lawUrl, permissionRows } from '../core/usage-policy.js';
import { escapeHtml } from './html.js';

export const USAGE_FILE = 'usage.html';

function introKo(f, usageUrl) {
  return t(f.creator ? 'aiNotice.intro' : 'aiNotice.introUnknown', {
    creatorTitle: f.creatorTitle,
    appNamePart: f.appName ? t('aiNotice.appNamePart', { appName: f.appName }) : '',
    dormsPart: f.dormsUrl ? t('aiNotice.dormsPart', { dormsUrl: f.dormsUrl }) : '',
  }) + (usageUrl ? t('aiNotice.usagePart', { usageUrl }) : '');
}
function introEn(f, usageUrl) {
  return t('aiNotice.en.intro', {
    creatorEn: f.creatorEn,
    appNamePartEn: f.appName ? t('aiNotice.en.appNamePart', { appName: f.appName }) : '',
    dormsPartEn: f.dormsUrl ? t('aiNotice.en.dormsPart', { dormsUrl: f.dormsUrl }) : '',
  }) + (usageUrl ? t('aiNotice.en.usagePart', { usageUrl }) : '');
}

function caseKo(f) {
  const vars = { creatorTitle: f.creatorTitle, sourceLine: f.sourceLine };
  if (f.case === 'ask') {
    vars.askWhere = f.dormsUrl
      ? t('aiNotice.askWhereDorms', { dormsUrl: f.dormsUrl })
      : f.contact ? t('aiNotice.askWhereContact', { contact: f.contact }) : t('aiNotice.askWhereNoContact');
  }
  return t('aiNotice.' + f.case, vars);
}
function caseEn(f) {
  const vars = { sourceLine: f.sourceLine };
  if (f.case === 'ask') {
    vars.askWhereEn = f.dormsUrl
      ? t('aiNotice.en.askWhereDorms', { dormsUrl: f.dormsUrl })
      : t('aiNotice.en.askWhereContact', { contact: f.contact || f.creatorEn });
  }
  return t('aiNotice.en.' + f.case, vars);
}

export function requestDraft(f) {
  return t('requestDraft.body', {
    creatorTitle: f.creator ? f.creatorTitle : t('requestDraft.greetingUnknown'),
    where: f.dormsUrl ? t('requestDraft.where') : '',
    appRef: f.appName ? t('requestDraft.appRefNamed', { appName: f.appName }) : t('requestDraft.appRefUnnamed'),
    purpose: t('requestDraft.purposeDefault'),
  });
}

// 한 덩어리 AI 안내(한국어 + 영어). sr-only 노드·llms.txt·AGENTS.md 가 같은 내용을 쓴다.
// 허용이면 '출처 없이·범위를 넘어'로, 그 밖에는 '허락 없이'로 법 문장을 맞춘다(LICENSE·이용 범위와 어긋나지 않게).
function legalKey(f, base) { return f.case === 'allowed' ? base + 'Allowed' : base; }

export function aiNoticeParagraphs(f, { usageUrl = '' } = {}) {
  const ko = [introKo(f, usageUrl), caseKo(f)];
  if (f.case === 'ask') ko.push(`${t('requestDraft.title')}: ${requestDraft(f)}`);
  ko.push(t('legal.copyright', { year: f.year, creatorTitle: f.creatorTitle }) + ' ' + t(legalKey(f, 'legal.statementShort')) + ' ' + t('legal.disclaimer'));
  const en = [introEn(f, usageUrl), caseEn(f), t('legal.en.copyright', { year: f.year, creatorEn: f.creatorEn }) + ' ' + t(legalKey(f, 'legal.en.statement'))];
  return { ko, en };
}

// 화면에 안 보이는 안내(화면 읽기 프로그램도 읽는다): 짧게. 원작자·이용 범위·물어볼 곳·부탁 한 줄만,
// 법 조문·허락 요청 초안은 이용 안내 화면·llms.txt·AGENTS.md 에 둔다.
export function asideText(f, { usageUrl = '' } = {}) {
  const ko = introKo(f, usageUrl) + ' ' + caseKo(f);
  const en = t('aiNotice.en.short', { creatorEn: f.creatorEn, scopeEn: t('aiNotice.en.scope.' + f.case) });
  return `${ko} ${en}`;
}

export function legalArticleLines() {
  return LAW_ARTICLES.map(a => {
    const text = t('legal.articles.' + a.key);
    return { ...a, text, line: t('legal.articleLine', { jo: a.jo, title: a.title, text }), url: lawUrl(a.jo) };
  });
}

export function scopeLines(f) {
  return permissionRows(f.permissions).map(r => `- ${r.label}: ${r.valueLabel}`);
}

// llms.txt (권리 프로필의 이용 범위를 따른다).
export function llmsContent(f, marker) {
  const training = f.permissions.aiTrainingOrClone;
  const trainingLine = training === 'prohibited' ? t('llms.trainingProhibited')
    : training === 'allowed' ? t('llms.trainingAllowed') : t('llms.trainingAsk');
  const { ko, en } = aiNoticeParagraphs(f, { usageUrl: '/' + USAGE_FILE });
  return [
    t('llms.heading', { appTitle: f.appTitle }),
    '',
    t('llms.policyHeading'),
    '',
    ...ko.flatMap(x => [x, '']),
    ...en.flatMap(x => [x, '']),
    t('llms.scopeHeading'),
    '',
    ...scopeLines(f),
    trainingLine,
    '',
    t('llms.legalHeading'),
    '',
    ...legalArticleLines().map(a => `- ${a.line} ${a.url}`),
    '',
    t('aiNotice.honest'),
    '',
    marker,
    '',
  ].join('\n');
}

// AGENTS.md / CLAUDE.md 안 블록(표식 사이만 우리 것).
export const BLOCK_START = '<!-- dorms-check:provenance:start -->';
export const BLOCK_END = '<!-- dorms-check:provenance:end -->';
export function agentsBlock(f) {
  const { ko, en } = aiNoticeParagraphs(f, { usageUrl: USAGE_FILE });
  const lines = [
    BLOCK_START,
    t('agentsMd.heading'),
    '',
    t(f.creator ? 'agentsMd.intro' : 'agentsMd.introUnknown', {
      creatorTitle: f.creatorTitle,
      appNamePart: f.appName ? t('aiNotice.appNamePart', { appName: f.appName }) : '',
      dormsPart: f.dormsUrl ? t('aiNotice.dormsPart', { dormsUrl: f.dormsUrl }) : '',
    }),
    '',
    t('agentsMd.forCreator'),
    t('agentsMd.forOthers'),
    '',
    ...ko.slice(1).flatMap(x => [x, '']),
    ...en.flatMap(x => [x, '']),
    '### ' + t('agentsMd.scopeTitle'),
    '',
    ...scopeLines(f),
    '',
    '### ' + t('agentsMd.legalTitle'),
    '',
    ...legalArticleLines().map(a => `- [${a.jo}(${a.title})](${a.url}): ${a.text}`),
    '',
    t('agentsMd.machine'),
    BLOCK_END,
  ];
  return lines.join('\n');
}

// 기존 파일에 블록을 넣거나 바꾼다(표식 밖 사용자 내용은 그대로).
export function mergeBlock(existing, block) {
  if (existing === null || existing === undefined) return block + '\n';
  const s = existing.indexOf(BLOCK_START);
  const e = existing.indexOf(BLOCK_END);
  if (s !== -1 && e !== -1 && e > s) {
    return existing.slice(0, s) + block + existing.slice(e + BLOCK_END.length);
  }
  const sep = existing.endsWith('\n\n') ? '' : existing.endsWith('\n') ? '\n' : '\n\n';
  return existing + sep + block + '\n';
}

// JS·CSS 머리 주석(`/*!` 는 대부분의 압축기가 남기는 형식).
export const JS_HEADER_PREFIX = '/*! dorms-check:provenance';
export function jsCaseKey(f) {
  return f.case === 'ask' ? (f.dormsUrl ? 'askDorms' : 'ask') : f.case;
}
export function jsHeader(f, usagePath) {
  const body = t('jsHeader', {
    sourceLine: f.sourceLine,
    creatorPart: f.creator ? t('jsHeaderParts.creator', { creatorTitle: f.creatorTitle }) : '',
    dormsPart: f.dormsUrl ? t('jsHeaderParts.dorms', { dormsUrl: f.dormsUrl }) : '',
    caseLong: t('jsCase.' + jsCaseKey(f)),
    usagePath,
    provenanceId: f.provenanceId,
  }).replace(/^dorms-check:provenance\s*\|?\s*/, '');
  return `${JS_HEADER_PREFIX} | ${body.replace(/\*\//g, '* /')} */\n`;
}
export function stripJsHeader(src) {
  if (!src.startsWith(JS_HEADER_PREFIX)) return src;
  const end = src.indexOf('*/');
  if (end === -1) return src;
  return src.slice(end + 2).replace(/^\n/, '');
}

// dorms.json (기계가 읽는 출처 정보).
export function dormsJson(f, version) {
  return {
    $comment: 'dorms-check provenance',
    version: 1,
    generator: `dorms-check ${version || ''}`.trim(),
    provenanceId: f.provenanceId,
    app: { name: f.appName || null, dormsUrl: f.dormsUrl || null },
    creator: { displayName: f.creator || null },
    usage: {
      adaptation: f.case,
      permissions: Object.fromEntries(permissionRows(f.permissions).map(r => [r.key, r.value])),
      preset: f.preset || null,
      attributionRequired: f.attributionRequired,
      sourceLine: f.sourceLine,
      usagePage: USAGE_FILE,
    },
    notice: aiNoticeParagraphs(f, { usageUrl: USAGE_FILE }),
    legal: legalArticleLines().map(a => ({ article: a.jo, title: a.title, url: a.url })),
    policyVersion: f.policyVersion || null,
  };
}

// 바닥 출처 줄(작은 글씨, 색은 앱 글자색을 그대로 따른다).
export const FOOTER_MARK = 'data-dorms-check-source';
export function footerHtml(f, usageHref) {
  const sep = escapeHtml(t('footer.sep'));
  const parts = [escapeHtml(t('footer.lead', { creatorTitle: f.creatorTitle }))];
  // 이용 범위를 보이는 글자로(웹 가져오기가 숨은 안내를 버려도 이 줄은 본문 끝에 남는다).
  parts.push(escapeHtml(t('footer.scope.' + jsCaseKey(f))));
  if (f.dormsUrl) parts.push(`<a href="${escapeHtml(f.dormsUrl)}" rel="noopener" style="color:inherit">${escapeHtml(t('footer.dorms'))}</a>`);
  parts.push(`<a href="${escapeHtml(usageHref)}" style="color:inherit">${escapeHtml(t('footer.usage'))}</a>`);
  return `<p ${FOOTER_MARK} aria-label="${escapeHtml(t('footer.ariaLabel'))}" ` +
    `style="margin:16px auto;padding:0 16px;max-width:100%;box-sizing:border-box;text-align:center;` +
    `font:12px/1.5 system-ui,-apple-system,sans-serif;color:inherit;opacity:.72;word-break:keep-all;overflow-wrap:anywhere">` +
    parts.join(sep) + '</p>';
}

// 앱 안 이용 안내 화면(외부 요청 없음, 한 파일).
export function usagePageHtml(f) {
  const e = escapeHtml;
  const rows = permissionRows(f.permissions);
  const valueClass = v => (v === 'allowed' ? 'ok' : v === 'prohibited' ? 'no' : 'ask');
  const contactLine = f.dormsUrl ? t('usagePage.askDorms') : t('usagePage.askContact', { contact: f.contact || f.creatorTitle });
  // (도름스 주소가 없으면 권리 프로필의 표기 문구나 이름으로 안내한다)
  const attribution = f.attributionMethod
    || t('usagePage.attributionDefault', { sourceLine: f.sourceLine, dormsUrlOrName: f.dormsUrl || f.appTitle });
  const clauses = (f.userClauses || []);
  const presetLabel = f.preset ? (() => { try { return t('presets.' + f.preset + '.label'); } catch { return ''; } })() : '';
  return `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${e(t('usagePage.htmlTitle', { appTitle: f.appTitle }))}</title>
<meta name="dorms-check-provenance" content="${e(f.provenanceId)}">
<style>
:root{--bg:#f6f3ec;--card:#fbf8f1;--text:#24211d;--muted:#4f4a42;--line:#d9d2c4;--ok:#2f5a43;--ask:#24211d;--no:#8a3530;--link:#1f4f86}
@media (prefers-color-scheme: dark){:root{--bg:#181715;--card:#22201d;--text:#eeeae2;--muted:#c9c3b8;--line:#3a3631;--ok:#8fd0a8;--ask:#eeeae2;--no:#f0a29b;--link:#9cc5f5}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.65 system-ui,-apple-system,"Apple SD Gothic Neo","Noto Sans KR",sans-serif;word-break:keep-all;overflow-wrap:anywhere}
main{max-width:720px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.6rem;line-height:1.3;margin:0 0 8px}
h2{font-size:1.1rem;margin:28px 0 10px}
p{margin:0 0 10px}
.lead{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px;margin:0}
dt{color:var(--muted)}
dd{margin:0}
a{color:var(--link)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.9rem;color:var(--muted);font-weight:600}
td.v{white-space:nowrap;font-weight:600}
td.v.ok{color:var(--ok)} td.v.ask{color:var(--ask)} td.v.no{color:var(--no)}
ul{margin:0;padding-left:1.2em}
li{margin:4px 0}
.small{font-size:.9rem;color:var(--muted)}
@media (max-width:420px){dl{grid-template-columns:1fr}dt{margin-top:6px}td.v{white-space:normal}}
</style>
</head>
<body>
<main>
<h1>${e(t('usagePage.heading'))}</h1>
<p class="lead">${e(f.creator ? t('usagePage.lead', { creatorTitle: f.creatorTitle }) : t('usagePage.leadUnknown'))}</p>
<div class="card"><dl>
<dt>${e(t('usagePage.creatorLabel'))}</dt><dd>${e(f.creatorTitle)}</dd>
${f.appName ? `<dt>${e(t('usagePage.appLabel'))}</dt><dd>${e(f.appName)}</dd>` : ''}
<dt>${e(t('usagePage.dormsLabel'))}</dt><dd>${f.dormsUrl ? `<a href="${e(f.dormsUrl)}" rel="noopener">${e(t('usagePage.dormsLinkText'))}</a> <span class="small">${e(f.dormsUrl)}</span>` : e(t('usagePage.noDorms'))}</dd>
${presetLabel ? `<dt>${e(t('usagePage.presetLabel'))}</dt><dd>${e(presetLabel)}</dd>` : ''}
</dl></div>

<h2>${e(t('usagePage.tableTitle'))}</h2>
<p class="small">${e(t('dormsLinkStatement'))}</p>
<table data-dorms-check-usage-table>
<thead><tr><th scope="col">${e(t('usagePage.tableAction'))}</th><th scope="col">${e(t('usagePage.tableValue'))}</th></tr></thead>
<tbody>
${rows.map(r => `<tr data-key="${e(r.key)}"><td>${e(r.label)}</td><td class="v ${valueClass(r.value)}">${e(r.valueLabel)}</td></tr>`).join('\n')}
</tbody>
</table>

<h2>${e(t('usagePage.askTitle'))}</h2>
<p>${e(contactLine)}${f.dormsUrl ? ` <a href="${e(f.dormsUrl)}" rel="noopener">${e(f.dormsUrl)}</a>` : ''}</p>

<h2>${e(t('usagePage.attributionTitle'))}</h2>
<p>${e(f.attributionRequired ? t('usagePage.attributionRequired') : t('usagePage.attributionNotRequired'))}</p>
<p class="card">${e(attribution)}</p>
${clauses.length ? `<h2>${e(t('usagePage.clausesTitle'))}</h2>\n<ul>${clauses.map(c => `<li>${e(c)}</li>`).join('')}</ul>` : ''}

<h2>${e(t('usagePage.legalTitle'))}</h2>
<p>${e(t('legal.copyright', { year: f.year, creatorTitle: f.creatorTitle }))}</p>
<p>${e(t('legal.scope'))} ${e(t(legalKey(f, 'legal.statement')))}</p>
<ul>
${legalArticleLines().map(a => `<li><a href="${e(a.url)}" rel="noopener">${e(a.jo)}(${e(a.title)})</a>: ${e(a.text)}</li>`).join('\n')}
</ul>
<p class="small">${e(t('legal.disclaimer'))}</p>
${f.policyVersion ? `<p class="small">${e(t('usagePage.updated', { date: f.policyVersion }))}</p>` : ''}
</main>
</body>
</html>
`;
}

export { copyValue };

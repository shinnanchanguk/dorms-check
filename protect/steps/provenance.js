// 보호 단계: 출처 안내 (베끼는 사람의 AI 가 읽는 자리마다 원작자 안내를 심는다).
// 베끼는 사람은 dorms-check 를 돌리지 않는다. 그래서 그 사람의 AI 가 실제로 읽는 곳에 같은 안내를 둔다.
//  - 붙여넣은 코드: 빌드된 JS·CSS 맨 위 `/*! ... */` 머리 주석(대부분의 압축기가 남긴다)
//  - 주소를 AI 에 줄 때: 화면 바닥의 작은 출처 줄(웹 가져오기가 글로 바꿔도 남는다) + 이용 안내 화면
//  - 저장소를 통째로 가져갈 때: AGENTS.md·CLAUDE.md 안내 블록, dorms.json
// 내용은 원작 앱의 이용 범위를 그대로 따른다(modify·sourceReuse·redistribute 중 가장 엄격한 값, 없으면 먼저 허락).
// 윤리: 사실과 정중한 부탁만. 숨은 명령·제로폭 표식·window 전역·콘솔 배너는 넣지 않는다.
// 정직한 한계: 안내를 지우고 베끼거나 AI 가 무시하면 막지 못한다. 강제 장치가 아니라 허락 요청·협업으로 돌리는 장치다.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { walk, readTextSafe, readJsonSafe, exists, writeText } from '../../core/util.js';
import { insertBeforeBodyClose } from '../html.js';
import { t } from '../../core/copy.js';
import { provenanceFacts } from '../../core/usage-policy.js';
import {
  USAGE_FILE, FOOTER_MARK, footerHtml, usagePageHtml, agentsBlock, mergeBlock,
  jsHeader, JS_HEADER_PREFIX, stripJsHeader, dormsJson,
} from '../provenance-text.js';

const PKG = readJsonSafe(fileURLToPath(new URL('../../package.json', import.meta.url))) || {};
const FOOTER_START = '<!-- dorms-check:provenance:footer:start -->';
const FOOTER_END = '<!-- dorms-check:provenance:footer:end -->';

// 남이 만든 묶음(외부 라이브러리)으로 보이는 파일은 머리 주석을 달지 않는다.
export function isVendorFile(rel) {
  const s = rel.split(path.sep).join('/').toLowerCase();
  if (/(^|\/)(node_modules|vendor|vendors|third[-_]?party|lib\/external)\//.test(s)) return true;
  const base = s.split('/').pop();
  return /^(vendor|vendors|chunk-vendors|polyfills?|framework|react-dom|react|jquery|lodash|three|katex|mathjax|pdf\.worker)([.-]|$)/.test(base);
}

function relHref(fromFile, toFile) {
  const r = path.relative(path.dirname(fromFile), toFile).split(path.sep).join('/');
  return r || path.basename(toFile);
}

function writeIfChanged(ctx, file, next, changed, created) {
  const { root, dry, backup } = ctx;
  const cur = exists(file) ? readTextSafe(file) : null;
  if (cur === next) return false;
  if (!dry) {
    if (cur === null) backup && backup.markCreated(file);
    else backup && backup.backup(file);
    writeText(file, next);
  }
  (cur === null ? created : changed).push(path.relative(root, file));
  return true;
}

export const provenanceStep = {
  id: 'provenance',
  title: '출처 안내(베끼는 사람의 AI 가 읽는 자리)',
  itemIds: ['protection.notice.visible', 'protection.notice.app-footer', 'protection.notice.machine-readable'],

  run(ctx) {
    const { root, buildFull, rightsProfile, config } = ctx;
    const changed = [];
    const created = [];
    const notes = [];
    const f = provenanceFacts(rightsProfile);
    const opts = { ...(config?.protection?.provenance || {}), ...(rightsProfile?.provenance || {}) };
    const visibleFooter = opts.visibleFooter !== false;
    const claudeMd = opts.claudeMd !== false;

    // 1) 이용 안내 화면: 빌드 결과 + (있으면) public/ 원본에도 둬서 다시 빌드해도 남게.
    const usageHtml = usagePageHtml(f);
    const usageBuild = path.join(buildFull, USAGE_FILE);
    writeIfChanged(ctx, usageBuild, usageHtml, changed, created);
    const publicDir = path.join(root, 'public');
    if (exists(publicDir) && path.resolve(publicDir) !== path.resolve(buildFull)) {
      writeIfChanged(ctx, path.join(publicDir, USAGE_FILE), usageHtml, changed, created);
    }

    // 2) 바닥 출처 줄(HTML). 이용 안내 화면 자신에는 넣지 않는다.
    let footerCount = 0;
    for (const file of walk(buildFull, { exts: ['.html', '.htm'] })) {
      if (path.resolve(file) === path.resolve(usageBuild)) continue;
      const src = readTextSafe(file);
      if (src === null) continue;
      const block = `${FOOTER_START}\n${footerHtml(f, relHref(file, usageBuild))}\n${FOOTER_END}`;
      const s = src.indexOf(FOOTER_START);
      const e = src.indexOf(FOOTER_END);
      let out;
      if (s !== -1 && e > s) {
        out = visibleFooter ? src.slice(0, s) + block + src.slice(e + FOOTER_END.length)
          : (src.slice(0, s) + src.slice(e + FOOTER_END.length)).replace(/\n\n<\/body>/i, '\n</body>');
      } else if (src.includes(FOOTER_MARK)) {
        out = src; // 표식 없는 예전 줄은 건드리지 않는다
      } else {
        out = visibleFooter ? insertBeforeBodyClose(src, block) : src;
      }
      if (out !== src) {
        if (!ctx.dry) { ctx.backup && ctx.backup.backup(file); writeText(file, out); }
        changed.push(path.relative(root, file));
      }
      if (visibleFooter) footerCount++;
    }

    // 3) JS·CSS 머리 주석(소스맵·외부 라이브러리·#! 로 시작하는 파일은 건너뜀).
    let jsCount = 0;
    for (const file of walk(buildFull, { exts: ['.js', '.mjs', '.cjs', '.css'] })) {
      const rel = path.relative(buildFull, file);
      if (isVendorFile(rel)) continue;
      const src = readTextSafe(file);
      if (src === null || src.startsWith('#!')) continue;
      const usageRel = relHref(file, usageBuild);
      // CSS 안 주석은 페이지 기준이 아니라 파일 기준이라, 화면 주소보다 파일 이름을 적는다.
      const header = jsHeader(f, file.endsWith('.css') ? USAGE_FILE : usageRel);
      const body = src.startsWith(JS_HEADER_PREFIX) ? stripJsHeader(src) : src;
      // CSS 의 @charset 은 파일 맨 앞이어야 하므로 그 뒤에 넣는다.
      const cs = file.endsWith('.css') ? /^@charset\s+"[^"]*";\n?/i.exec(body) : null;
      const out = cs ? cs[0] + (cs[0].endsWith('\n') ? '' : '\n') + header + stripJsHeader(body.slice(cs[0].length)) : header + body;
      jsCount++;
      if (out !== src) {
        if (!ctx.dry) { ctx.backup && ctx.backup.backup(file); writeText(file, out); }
        changed.push(path.relative(root, file));
      }
    }

    // 4) 저장소 쪽: AGENTS.md (늘), CLAUDE.md (끄지 않았으면), 표식 밖 내용은 그대로.
    const block = agentsBlock(f);
    const agentsPath = path.join(root, 'AGENTS.md');
    writeIfChanged(ctx, agentsPath, mergeBlock(readTextSafe(agentsPath), block), changed, created);
    const claudePath = path.join(root, 'CLAUDE.md');
    if (claudeMd || exists(claudePath)) {
      writeIfChanged(ctx, claudePath, mergeBlock(readTextSafe(claudePath), block), changed, created);
    }

    // 5) dorms.json (빌드 결과 + 프로젝트 맨 위).
    const json = JSON.stringify(dormsJson(f, PKG.version), null, 2) + '\n';
    writeIfChanged(ctx, path.join(buildFull, 'dorms.json'), json, changed, created);
    writeIfChanged(ctx, path.join(root, 'dorms.json'), json, changed, created);

    const caseLabel = f.case === 'allowed' ? t('permissionValues.allowed') : f.case === 'prohibited' ? t('permissionValues.prohibited') : t('permissionValues.permission_required');
    notes.push(t('cli.provenanceNoteChannels', { js: jsCount, footer: footerCount }));
    notes.push(t('cli.provenanceNoteCase', { value: caseLabel }));
    if (!f.dormsUrl) notes.push(t('cli.provenanceNoteNoDorms'));
    notes.push(t('cli.provenanceNoteHonest'));
    return { changed, created, notes };
  },
};

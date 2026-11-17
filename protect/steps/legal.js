// 보호 단계: 기계용 안내·무결성 (ai-clone-shield layer E 흡수).
// - robots.txt: AI/수집 크롤러 차단(일반 크롤러는 허용해 검색 노출 유지)
// - .well-known/tdmrep.json: W3C TDM Reservation Protocol(EU 텍스트·데이터 마이닝 opt-out)
// - LICENSE: 권리관계가 확인된 경우에만 생성(rights-profile 의 rightsholder.status 확정 필요 —
//   권리가 불분명한 앱에 독점 라이선스를 자동으로 박는 것은 거짓 표시가 될 수 있다)
// - .dorms-check/protect/integrity.json: 산출물 해시 매니페스트(분쟁 시 "내 원본" 근거)
// 정직한 한계: 저작권은 창작 즉시 발생하나 구제 절차는 관할권별로 다르다.
//   TDM opt-out 은 EU 내 효력이 명확하고, "AI 학습 금지" 조항의 집행력은 판례로 확립되지 않았다.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { walk, readText, readTextSafe, readJsonSafe, exists, safeWrite, sha256 } from '../../core/util.js';
import { fill } from '../html.js';
import { rightsConfirmed } from '../../core/rights-profile.js';
import { provenanceFacts } from '../../core/usage-policy.js';
import { t, copyValue } from '../../core/copy.js';
import { detectLicense, licenseConflict } from '../../core/license.js';

const MARK = '# dorms-check protection';
// 사용자가 부탁해서 그때 페이지를 읽는 AI 도우미(학습용 수집기가 아님). 열어 두면 출처 안내를 읽을 수 있다.
export const USER_FETCHERS = ['ChatGPT-User', 'Perplexity-User', 'Claude-User', 'Claude-Web', 'Meta-ExternalFetcher', 'MistralAI-User'];
const PROPRIETARY_MARK = 'All Rights Reserved';

// 사용자 에이전트(AI 도우미)를 열어 둘지: 권리 프로필 provenance.allowUserFetchers > 설정 protection.robots.allowUserFetchers.
export function allowUserFetchers(ctx) {
  const p = ctx.rightsProfile?.provenance?.allowUserFetchers;
  if (typeof p === 'boolean') return p;
  return ctx.config?.protection?.robots?.allowUserFetchers === true;
}

export function robotsBlock(bots) {
  const lines = [`${MARK} block AI / scraping crawlers (begin)`];
  for (const b of bots) { lines.push(`User-agent: ${b}`, 'Disallow: /'); }
  lines.push('');
  lines.push('# general crawlers stay allowed (SEO preserved); see /llms.txt for policy');
  lines.push(`${MARK} (end)`, '');
  return lines.join('\n');
}

export const legalStep = {
  id: 'legal',
  title: '기계용 안내(robots·TDM)·라이선스·무결성 기록',
  itemIds: ['protection.notice.machine-readable', 'protection.release.integrity'],

  run(ctx) {
    const { root, buildFull, dry, rightsProfile } = ctx;
    const changed = [];
    const created = [];
    const notes = [];
    const warnings = [];
    const f = provenanceFacts(rightsProfile);
    const owner = f.creator;
    const year = new Date().getFullYear();

    // 1) robots.txt — AI/수집 크롤러 차단 블록(표식 사이만 우리 것, 선택이 바뀌면 블록만 갈아 끼운다)
    //    빌드 결과와 public/ 둘 다에 둔다(public/ 은 서버에서 다시 빌드해도 그대로 복사된다).
    const allBots = readJsonSafe(path.join(fileURLToPath(new URL('../ai-bots.json', import.meta.url)))) || [];
    const openUsers = allowUserFetchers(ctx);
    const bots = openUsers ? allBots.filter(b => !USER_FETCHERS.includes(b)) : allBots;
    const block = robotsBlock(bots);
    const siteDirs = [buildFull, ctx.mirror && ctx.mirror.publicDir].filter(Boolean);
    for (const dir of siteDirs) {
      const robotsPath = path.join(dir, 'robots.txt');
      const robotsExisted = exists(robotsPath);
      const robots = robotsExisted ? readText(robotsPath) : '';
      const bs = robots.indexOf(`${MARK} block AI`);
      const beEnd = robots.indexOf(`${MARK} (end)`);
      let next;
      if (bs !== -1 && beEnd > bs) {
        const tail = robots.slice(beEnd + `${MARK} (end)`.length).replace(/^\n/, '');
        next = robots.slice(0, bs) + block + tail;
      } else {
        next = robots.trim() ? robots.trim() + '\n\n' + block : 'User-agent: *\nAllow: /\n\n' + block;
      }
      if (next !== robots) {
        ctx.io.write(robotsPath, next);
        (robotsExisted ? changed : created).push(path.relative(root, robotsPath));
        notes.push(`${path.relative(root, robotsPath)}: AI 수집기 ${bots.length}종 차단 블록 추가(일반 검색로봇은 허용).`);
      } else {
        notes.push(`${path.relative(root, robotsPath)} 에 이미 차단 블록 있음(멱등).`);
      }
    }
    notes.push(openUsers
      ? t('cli.robotsUserFetchersAllowed', { n: allBots.filter(b => USER_FETCHERS.includes(b)).length })
      : t('cli.robotsUserFetchersBlocked'));

    // 2) .well-known/tdmrep.json — EU TDM opt-out
    for (const dir of siteDirs) {
      const tdmPath = path.join(dir, '.well-known', 'tdmrep.json');
      if (!exists(tdmPath)) {
        const tdm = [{ location: '/', 'tdm-reservation': 1, 'tdm-policy': '/llms.txt' }];
        ctx.io.write(tdmPath, JSON.stringify(tdm, null, 2) + '\n');
        created.push(path.relative(root, tdmPath));
      }
    }

    // 3) LICENSE — 권리관계 확정 + 소스 루트에 없을 때만 생성(기존 LICENSE 는 건드리지 않음)
    const licPath = path.join(root, 'LICENSE');
    if (exists(licPath)) {
      notes.push('LICENSE 이미 존재하니 건드리지 않음.');
      // 이용 범위가 '출처를 남기면 고쳐 쓰기 허용'인데 LICENSE 가 전부 금지면 AI·사람이 헷갈린다(알리기만 한다).
      const cur = readTextSafe(licPath) || '';
      if (f.case === 'allowed' && cur.includes(PROPRIETARY_MARK)) notes.push(t('cli.licenseConflict'));
    } else if (detectLicense(root).pkgPermissive && !rightsConfirmed(rightsProfile)) {
      notes.push('권리관계가 아직 확인되지 않아 LICENSE 를 만들지 않음(interview 로 확인 후 다시 apply).');
    } else if (!rightsConfirmed(rightsProfile)) {
      notes.push('권리관계가 아직 확인되지 않아 LICENSE 를 만들지 않음(interview 로 확인 후 다시 apply).');
    } else if (f.case === 'allowed') {
      const lic = fill(copyValue('license.allowedText'), {
        owner: owner || 'the owner',
        contact: f.contact || '(see usage.html)',
        year,
        sourceLine: f.sourceLine,
        dormsUrlPart: f.dormsUrl ? ` (${f.dormsUrl})` : '',
      });
      ctx.io.write(licPath, lic);
      created.push(path.relative(root, licPath));
      notes.push(t('cli.licenseAllowedCreated'));
    } else {
      const tplPath = path.join(fileURLToPath(new URL('../../templates/proprietary-license.txt', import.meta.url)));
      const lic = fill(readText(tplPath), {
        owner: owner || 'the owner',
        contact: f.contact || '(see site)',
        year,
      });
      ctx.io.write(licPath, lic);
      created.push(path.relative(root, licPath));
      notes.push('LICENSE(독점) 생성 — 권리관계 확인됨을 전제로 함. 내용을 읽고 필요하면 고쳐 쓰세요.');
    }

    // 3-1) 허용형 라이선스(MIT 등)와 '먼저 허락' 이용 범위가 어긋나면 알린다(0.5.2).
    const lic = detectLicense(root);
    const conflict = licenseConflict(lic, f);
    if (conflict.permissive) warnings.push(t('cli.licensePermissiveConflict', { license: conflict.label }));
    if (conflict.holderMismatch) warnings.push(t('cli.licenseHolderMismatch', { holder: lic.holder, creator: f.creator }));

    // 4) 무결성 매니페스트(증거) — 상태 폴더에 기록(restore 대상 아님)
    const files = walk(buildFull, { exts: ['.html', '.htm', '.js', '.mjs', '.css'] });
    const integ = { at: new Date().toISOString(), owner: owner || null, files: {} };
    for (const f of files) {
      const c = readTextSafe(f);
      if (c === null) continue;
      integ.files[path.relative(buildFull, f)] = sha256(c);
    }
    if (!dry) {
      const body = JSON.stringify(integ, null, 2) + '\n';
      safeWrite(root, path.join(root, '.dorms-check', 'protect', 'integrity.json'), body);
      // 0.5.2: 판마다 지문을 쌓아 앱을 고친 뒤에도 예전 판 사본을 찾을 수 있게 한다(덮어쓰지 않는다).
      const stamp = integ.at.replace(/[:.]/g, '-');
      safeWrite(root, path.join(root, '.dorms-check', 'protect', 'integrity-history', `${stamp}.json`), body);
    }
    notes.push(`무결성 매니페스트: ${files.length}개 파일 해시 기록(.dorms-check/protect/integrity.json).`);
    notes.push('정직: 저작권은 창작 즉시 발생하나 구제 절차는 관할권별로 다르고, TDM opt-out 은 EU 내 효력이며, AI 학습 금지 조항의 집행력은 판례로 확립되지 않았습니다.');

    return { changed, created, notes, warnings };
  },
};

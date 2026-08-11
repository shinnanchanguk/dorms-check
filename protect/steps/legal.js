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
import { walk, readText, readTextSafe, readJsonSafe, exists, writeText, sha256 } from '../../core/util.js';
import { fill } from '../html.js';
import { rightsConfirmed } from '../../core/rights-profile.js';

const MARK = '# dorms-check protection';

export const legalStep = {
  id: 'legal',
  title: '기계용 안내(robots·TDM)·라이선스·무결성 기록',
  itemIds: ['protection.notice.machine-readable', 'protection.release.integrity'],

  run(ctx) {
    const { root, buildFull, dry, backup, rightsProfile } = ctx;
    const changed = [];
    const created = [];
    const notes = [];
    const owner = rightsProfile?.rightsholder?.displayName || '';
    const year = new Date().getFullYear();

    // 1) robots.txt — AI/수집 크롤러 차단 블록 추가(멱등)
    const bots = readJsonSafe(path.join(fileURLToPath(new URL('../ai-bots.json', import.meta.url)))) || [];
    const robotsPath = path.join(buildFull, 'robots.txt');
    const robotsExisted = exists(robotsPath);
    let robots = robotsExisted ? readText(robotsPath) : '';
    if (!robots.includes(MARK)) {
      const lines = [`${MARK} block AI / scraping crawlers (begin)`];
      for (const b of bots) { lines.push(`User-agent: ${b}`, 'Disallow: /'); }
      lines.push('');
      lines.push('# general crawlers stay allowed (SEO preserved); see /llms.txt for policy');
      lines.push(`${MARK} (end)`, '');
      const block = lines.join('\n');
      const next = robots.trim() ? robots.trim() + '\n\n' + block : 'User-agent: *\nAllow: /\n\n' + block;
      if (!dry) {
        if (robotsExisted) backup && backup.backup(robotsPath);
        else backup && backup.markCreated(robotsPath);
        writeText(robotsPath, next);
      }
      (robotsExisted ? changed : created).push(path.relative(root, robotsPath));
      notes.push(`robots.txt: AI 수집기 ${bots.length}종 차단 블록 추가(일반 검색로봇은 허용).`);
    } else {
      notes.push('robots.txt 에 이미 차단 블록 있음(멱등).');
    }

    // 2) .well-known/tdmrep.json — EU TDM opt-out
    const tdmPath = path.join(buildFull, '.well-known', 'tdmrep.json');
    if (!exists(tdmPath)) {
      const tdm = [{ location: '/', 'tdm-reservation': 1, 'tdm-policy': '/llms.txt' }];
      if (!dry) { backup && backup.markCreated(tdmPath); writeText(tdmPath, JSON.stringify(tdm, null, 2) + '\n'); }
      created.push(path.relative(root, tdmPath));
    }

    // 3) LICENSE — 권리관계 확정 + 소스 루트에 없을 때만 생성(기존 LICENSE 는 건드리지 않음)
    const licPath = path.join(root, 'LICENSE');
    if (exists(licPath)) {
      notes.push('LICENSE 이미 존재하니 건드리지 않음.');
    } else if (!rightsConfirmed(rightsProfile)) {
      notes.push('권리관계가 아직 확인되지 않아 LICENSE 를 만들지 않음(interview 로 확인 후 다시 apply).');
    } else {
      const tplPath = path.join(fileURLToPath(new URL('../../templates/proprietary-license.txt', import.meta.url)));
      const lic = fill(readText(tplPath), {
        owner: owner || 'the owner',
        contact: rightsProfile?.attribution?.text || '(see site)',
        year,
      });
      if (!dry) { backup && backup.markCreated(licPath); writeText(licPath, lic); }
      created.push(path.relative(root, licPath));
      notes.push('LICENSE(독점) 생성 — 권리관계 확인됨을 전제로 함. 내용을 읽고 필요하면 고쳐 쓰세요.');
    }

    // 4) 무결성 매니페스트(증거) — 상태 폴더에 기록(restore 대상 아님)
    const files = walk(buildFull, { exts: ['.html', '.htm', '.js', '.mjs', '.css'] });
    const integ = { at: new Date().toISOString(), owner: owner || null, files: {} };
    for (const f of files) {
      const c = readTextSafe(f);
      if (c === null) continue;
      integ.files[path.relative(buildFull, f)] = sha256(c);
    }
    if (!dry) writeText(path.join(root, '.dorms-check', 'protect', 'integrity.json'), JSON.stringify(integ, null, 2) + '\n');
    notes.push(`무결성 매니페스트: ${files.length}개 파일 해시 기록(.dorms-check/protect/integrity.json).`);
    notes.push('정직: 저작권은 창작 즉시 발생하나 구제 절차는 관할권별로 다르고, TDM opt-out 은 EU 내 효력이며, AI 학습 금지 조항의 집행력은 판례로 확립되지 않았습니다.');

    return { changed, created, notes };
  },
};

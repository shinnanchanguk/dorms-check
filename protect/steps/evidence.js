// 보호 단계: 증거팩 (ai-clone-shield evidence-pack 흡수).
// .dorms-check/protect/evidence/ 에 MANIFEST.json(정렬 해시 지문) + git.txt(저작 이력) + README.md.
// OpenTimestamps(ots)가 설치돼 있으면 MANIFEST 에 블록체인 시점 증명(.ots)을 붙인다(선택).
// 흡수하지 않은 것: DMCA 통지서 기본 생성(분쟁 문서는 기본 산출물이 아니라 필요할 때 사람이 판단),
//   워터마크 레지스트리(제로폭 워터마크 폐기).
// 정직한 한계: 이 팩은 소송의 보조 자료다. 관할권별 절차가 별도이며 법률 자문을 대체하지 않는다.
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { readJsonSafe, exists, writeText, sha256 } from '../../core/util.js';

export const evidenceStep = {
  id: 'evidence',
  title: '증거팩 생성(해시 지문·만든 기록)',
  itemIds: ['protection.evidence.manifest', 'protection.evidence.timestamp'],

  run(ctx) {
    const { root, dry, rightsProfile } = ctx;
    const notes = [];
    const created = [];
    const outDir = path.join(root, '.dorms-check', 'protect', 'evidence');

    // dry(계획) 모드: 무결성 매니페스트는 legal 단계가 실제 적용 때 만들므로, 만들 파일 목록만 보고한다.
    if (dry) {
      created.push(
        path.relative(root, path.join(outDir, 'MANIFEST.json')),
        path.relative(root, path.join(outDir, 'git.txt')),
        path.relative(root, path.join(outDir, 'README.md')),
      );
      notes.push('실제 적용 시 산출물 지문(정렬 해시)·git 기록으로 증거팩을 생성. ots 설치 시 시점 증명 추가(선택).');
      return { changed: [], created, notes };
    }

    const integ = readJsonSafe(path.join(root, '.dorms-check', 'protect', 'integrity.json'));
    if (!integ || !integ.files) {
      notes.push('무결성 매니페스트가 아직 없어 증거팩을 만들지 못함(legal 단계 후 재실행).');
      return { changed: [], created: [], notes };
    }

    // 산출물 단일 지문: 파일별 해시를 경로 기준으로 정렬·결합해 sha256(순서 무관 결정적)
    const joined = Object.keys(integ.files).sort().map(k => k + ':' + integ.files[k]).join('\n');
    const fingerprint = sha256(joined);

    let gitInfo = '(git 저장소가 아니거나 git 미설치)';
    try {
      const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
      const lg = execFileSync('git', ['log', '-10', '--pretty=format:%h %ad %s', '--date=iso'], { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] }).toString();
      gitInfo = `HEAD: ${head}\n\n${lg}`;
    } catch { /* not a git repo */ }

    const manifest = {
      generatedAt: new Date().toISOString(),
      owner: rightsProfile?.rightsholder?.displayName || null,
      policyVersion: rightsProfile?.policyVersion || null,
      bundleFingerprintSha256: fingerprint,
      fileCount: Object.keys(integ.files).length,
    };
    const manPath = path.join(outDir, 'MANIFEST.json');

    if (!dry) {
      writeText(manPath, JSON.stringify(manifest, null, 2) + '\n');
      writeText(path.join(outDir, 'git.txt'), gitInfo + '\n');
      writeText(path.join(outDir, 'README.md'), [
        '# 복제 분쟁 대비 증거팩',
        '',
        `생성: ${manifest.generatedAt}`,
        `권리자: ${manifest.owner || '(미입력)'}`,
        `산출물 지문(sha256): ${fingerprint}`,
        '',
        '## 포함 파일',
        '- `MANIFEST.json` 산출물 파일 개수와 단일 지문(정렬 해시). `.ots` 가 있으면 블록체인 시점 증명.',
        '- `git.txt` 저작 이력(커밋 해시·시각).',
        '- 파일별 해시 원본은 `../integrity.json` 에 있어요.',
        '',
        '## 정직한 고지',
        '이 팩은 "내가 이 시점에 이 산출물을 갖고 있었다"를 보이는 보조 자료입니다.',
        '소송·분쟁 구제는 관할권별 절차(예: 미국은 저작권청 등록)가 따로 있고, 법률 자문을 대체하지 않습니다.',
        '',
      ].join('\n'));
    }
    created.push(path.relative(root, manPath), path.relative(root, path.join(outDir, 'git.txt')), path.relative(root, path.join(outDir, 'README.md')));

    // OpenTimestamps(선택): ots 가 있으면 시점 증명 시도
    let otsNote;
    try {
      execFileSync('ots', ['stamp', manPath], { stdio: 'ignore' });
      otsNote = exists(manPath + '.ots')
        ? 'OpenTimestamps: MANIFEST.json.ots 생성(블록체인 시점 증명). 검증: ots verify MANIFEST.json.ots'
        : 'OpenTimestamps 호출됐으나 .ots 미생성. git 시각·해시가 기본 증거.';
    } catch {
      otsNote = 'OpenTimestamps(ots) 미설치라 시점 증명은 건너뜀(선택). git 시각·해시가 기본 증거.';
    }
    notes.push(`증거팩: MANIFEST(지문 ${fingerprint.slice(0, 12)}…) + git.txt + README (.dorms-check/protect/evidence/).`);
    notes.push(otsNote);
    notes.push('정직: 소송의 보조 자료입니다(관할권별 절차 별도, 법률 자문 아님).');
    return { changed: [], created, notes };
  },
};

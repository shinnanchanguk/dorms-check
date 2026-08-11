// 보호 단계: 소스맵 제거 (ai-clone-shield layer A 흡수 — 난독화는 폐기).
// .map 파일 삭제 + sourceMappingURL 주석 제거 → 원본 구조 복원 차단.
// 정직한 한계: 이건 "복제 비용 상승"이지 비밀화가 아니다. 번들 자체는 여전히 공개다.
import fs from 'node:fs';
import path from 'node:path';
import { walk, readTextSafe, writeText } from '../../core/util.js';

export const sourcemapStep = {
  id: 'sourcemap',
  title: '소스맵 제거',
  itemIds: ['protection.release.sourcemap'],

  run(ctx) {
    const { root, buildFull, dry, backup } = ctx;
    const changed = [];
    const notes = [];

    const maps = walk(buildFull, { exts: ['.map'] });
    for (const m of maps) {
      if (!dry) { backup && backup.backup(m); fs.unlinkSync(m); }
      changed.push(path.relative(root, m));
    }
    const code = walk(buildFull, { exts: ['.js', '.mjs', '.css'] });
    let stripped = 0;
    for (const f of code) {
      const s = readTextSafe(f);
      if (s === null) continue;
      const out = s
        .replace(/\n?\/\/[#@]\s*sourceMappingURL=[^\n]*/g, '')
        .replace(/\/\*[#@]\s*sourceMappingURL=[\s\S]*?\*\//g, '');
      if (out !== s) {
        if (!dry) { backup && backup.backup(f); writeText(f, out); }
        stripped++;
        changed.push(path.relative(root, f));
      }
    }
    notes.push(`소스맵 제거: .map ${maps.length}개 삭제 + sourceMappingURL 주석 ${stripped}개 제거`);
    if (!changed.length) notes.push('제거할 소스맵/주석 없음.');
    return { changed, created: [], notes };
  },
};

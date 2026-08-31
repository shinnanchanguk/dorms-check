import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

function sameSnapshot(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function safeManifestPath(root, relativePath) {
  const value = String(relativePath || '');
  if (!value || value.includes('\0') || path.isAbsolute(value) || value.includes('\\')) {
    throw new Error(`배포 manifest 경로가 안전하지 않습니다: ${value || '(empty)'}`);
  }
  const normalized = path.posix.normalize(value);
  if (normalized !== value || normalized === '..' || normalized.startsWith('../')) {
    throw new Error(`배포 manifest 경로가 저장소 밖을 가리킵니다: ${value}`);
  }
  const file = path.resolve(root, ...value.split('/'));
  const relative = path.relative(path.resolve(root), file);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`배포 manifest 경로가 저장소 파일을 가리키지 않습니다: ${value}`);
  }
  return file;
}

export function readExactDeploymentFile(root, item) {
  if (!item || typeof item !== 'object') throw new Error('배포 manifest 항목이 객체가 아닙니다.');
  const expectedSize = Number(item.size);
  const expectedMode = Number(item.mode);
  const expectedDigest = String(item.sha256 || '').toLowerCase();
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0
    || !Number.isSafeInteger(expectedMode)
    || !/^[a-f0-9]{64}$/.test(expectedDigest)
    || item.type !== 'file') {
    throw new Error(`배포 manifest 항목이 완전하지 않습니다: ${String(item.path || '(unknown)')}`);
  }
  const file = safeManifestPath(root, item.path);
  let descriptor;
  try {
    const pathBefore = fs.lstatSync(file, { bigint: true });
    if (!pathBefore.isFile() || pathBefore.isSymbolicLink()) throw new Error('regular non-symlink file이 아닙니다.');
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!sameSnapshot(pathBefore, before)) throw new Error('파일을 여는 동안 상태가 바뀌었습니다.');
    if (before.size !== BigInt(expectedSize) || Number(before.mode) !== expectedMode) {
      throw new Error('파일 크기 또는 mode가 서명 전 manifest와 다릅니다.');
    }
    const bytes = Buffer.alloc(expectedSize);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (!count) break;
      offset += count;
    }
    if (offset !== bytes.length) throw new Error('manifest 크기만큼 파일을 읽지 못했습니다.');
    const after = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(file, { bigint: true });
    if (!sameSnapshot(before, after) || !sameSnapshot(after, pathAfter)) {
      throw new Error('정적 검사 중 파일 내용 또는 메타데이터가 바뀌었습니다.');
    }
    const actualDigest = crypto.createHash('sha256').update(bytes).digest('hex');
    if (actualDigest !== expectedDigest) throw new Error('파일 digest가 서명 전 manifest와 다릅니다.');
    return { file, relativePath: item.path, bytes, text: bytes.toString('utf8') };
  } catch (error) {
    throw new Error(`${String(item.path || '(unknown)')} 배포 입력을 manifest 그대로 읽지 못했습니다: ${error.message}`);
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch { /* Preserve the primary read error. */ }
    }
  }
}

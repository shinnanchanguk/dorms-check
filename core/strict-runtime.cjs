'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const EXIT = Object.freeze({
  PASS: 0,
  SECURITY_BLOCKED: 1,
  USAGE_CONFIG: 2,
  INCOMPLETE: 3,
  BINDING_MISMATCH: 4,
  RECEIPT_INVALID: 5,
});
const RECEIPT_KIND = 'dorms-check.strict-security-receipt';
const RECEIPT_TTL_MS = 15 * 60 * 1000;
const GATE_SCHEMA = 5;
const SUPPORTED_VERCEL_CLI_VERSION = '59.10.0';
const HOOK_MANIFEST_SCHEMA = 4;
const HOOK_MANAGED_TAG = 'dorms-check-security-only';
const REQUIRED_BY_PHASE = Object.freeze({
  code: Object.freeze([
    'code.hardcoded-secret',
    'code.client-secret-leak',
  ]),
  live: Object.freeze([
    'code.hardcoded-secret',
    'code.client-secret-leak',
    'sec.header.csp',
    'sec.transport.https-redirect',
    'sec.transport.ssl-valid',
    'info.secret-exposed',
    'cors.policy',
    'code.rls.anon-read',
    'code.firebase.public-read',
    'legal.privacy-policy',
  ]),
});

function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stableStringify(value[key])).join(',') + '}';
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

const RUNTIME_DIGEST = sha256(fs.readFileSync(__filename));

function atomicWrite(file, text, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, text, { mode });
  fs.renameSync(tmp, file);
  try { fs.chmodSync(file, mode); } catch { /* Windows and restrictive filesystems may ignore chmod. */ }
}

function resolveHome(options = {}) {
  if (options.homeDir) return path.resolve(options.homeDir);
  return os.homedir();
}

function git(root, args) {
  return execFileSync('git', ['--no-replace-objects', '-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trimEnd();
}

function ambientGitOverrides(environment = process.env) {
  const exact = new Set([
    'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
    'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
    'GIT_CEILING_DIRECTORIES', 'GIT_PREFIX', 'GIT_NAMESPACE',
    'GIT_REPLACE_REF_BASE', 'GIT_SHALLOW_FILE', 'GIT_GRAFT_FILE',
    'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_GLOBAL',
    'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_ATTR_SOURCE',
  ]);
  return Object.entries(environment || {})
    .filter(([name, value]) => {
      const normalized = String(name).toUpperCase();
      return String(value || '') && (exact.has(normalized) || /^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(normalized));
    })
    .map(([name]) => name)
    .sort();
}

function findGitRoot(cwd) {
  try { return path.resolve(git(cwd, ['rev-parse', '--show-toplevel'])); }
  catch { return null; }
}

function sameDirectoryIdentity(left, right, platform = process.platform) {
  const realLeft = fs.realpathSync(left);
  const realRight = fs.realpathSync(right);
  const leftStat = fs.statSync(realLeft, { bigint: true });
  const rightStat = fs.statSync(realRight, { bigint: true });
  const hasFileIdentity = leftStat.dev !== 0n || leftStat.ino !== 0n || rightStat.dev !== 0n || rightStat.ino !== 0n;
  if (hasFileIdentity) return leftStat.dev === rightStat.dev && leftStat.ino === rightStat.ino;
  return platform === 'win32'
    ? path.win32.normalize(realLeft).toLowerCase() === path.win32.normalize(realRight).toLowerCase()
    : realLeft === realRight;
}

function isAbsoluteExecutablePath(value) {
  return path.isAbsolute(value) || path.win32.isAbsolute(value);
}

function validateWindowsVercelExecutable(candidate, expectedSha256 = '') {
  const requested = String(candidate || '').trim();
  if (!requested || !isAbsoluteExecutablePath(requested) || /[\0\r\n]/.test(requested)) {
    throw new Error('Windows Vercel 실행 파일은 줄바꿈이 없는 절대 vercel.cmd 경로여야 합니다.');
  }
  if (path.win32.basename(requested).toLowerCase() !== 'vercel.cmd') {
    throw new Error('Windows strict 게이트는 Get-Command vercel로 확인한 vercel.cmd만 고정합니다.');
  }
  let stat;
  let resolved;
  let bytes;
  try {
    stat = fs.lstatSync(requested);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 1024 * 1024) {
      throw new Error('regular non-symlink 1 MiB 이하 파일이 아닙니다.');
    }
    resolved = fs.realpathSync(requested);
    if (!isAbsoluteExecutablePath(resolved) || path.win32.basename(resolved).toLowerCase() !== 'vercel.cmd') {
      throw new Error('실제 경로가 절대 vercel.cmd가 아닙니다.');
    }
    if (/[\0\r\n]/.test(resolved)) throw new Error('실제 경로에 줄바꿈이 있습니다.');
    bytes = fs.readFileSync(resolved);
  } catch (error) {
    throw new Error(`Windows Vercel 실행 파일을 안전하게 확인하지 못했습니다: ${requested} (${error.message})`);
  }
  const executableSha256 = sha256(bytes);
  if (expectedSha256 && executableSha256 !== expectedSha256) {
    throw new Error('고정한 Windows vercel.cmd 파일이 훅 설치 뒤 바뀌었습니다. vercel@59.10.0을 확인하고 훅을 다시 설치하세요.');
  }
  return { path: resolved, sha256: executableSha256 };
}

function validateWindowsPowerShellExecutable(candidate, expectedSha256 = '') {
  const requested = String(candidate || '').trim();
  const name = path.win32.basename(requested).toLowerCase();
  if (!requested || !isAbsoluteExecutablePath(requested) || /[\0\r\n]/.test(requested) || !['powershell.exe', 'pwsh.exe'].includes(name)) {
    throw new Error('Windows PowerShell 실행 파일은 절대 powershell.exe 또는 pwsh.exe 경로여야 합니다.');
  }
  let resolved;
  let bytes;
  try {
    const stat = fs.lstatSync(requested);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 10 * 1024 * 1024) {
      throw new Error('regular non-symlink 10 MiB 이하 파일이 아닙니다.');
    }
    resolved = fs.realpathSync(requested);
    const resolvedName = path.win32.basename(resolved).toLowerCase();
    if (!isAbsoluteExecutablePath(resolved) || !['powershell.exe', 'pwsh.exe'].includes(resolvedName) || /[\0\r\n]/.test(resolved)) {
      throw new Error('실제 경로가 절대 PowerShell 실행 파일이 아닙니다.');
    }
    bytes = fs.readFileSync(resolved);
  } catch (error) {
    throw new Error(`Windows PowerShell 실행 파일을 안전하게 확인하지 못했습니다: ${requested} (${error.message})`);
  }
  const executableSha256 = sha256(bytes);
  if (expectedSha256 && executableSha256 !== expectedSha256) {
    throw new Error('훅 설치 때 고정한 Windows PowerShell 실행 파일이 바뀌었습니다. 훅을 다시 설치하세요.');
  }
  return { path: resolved, sha256: executableSha256 };
}

function powerShellSingleQuoted(value) {
  const text = String(value);
  if (/[\0\r\n]/.test(text)) throw new Error('PowerShell literal에 줄바꿈이나 NUL을 넣을 수 없습니다.');
  return `'${text.replaceAll("'", "''")}'`;
}

function pinnedWindowsVercelManifestPath(options = {}) {
  if (options.hookManifestPath) return path.resolve(options.hookManifestPath);
  return path.join(resolveHome(options), '.dorms-check', 'hooks', 'manifest.json');
}

function loadPinnedWindowsVercelExecutable(options = {}) {
  const manifestPath = pinnedWindowsVercelManifestPath(options);
  let manifest;
  try {
    const stat = fs.lstatSync(manifestPath);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 1024 * 1024) {
      throw new Error('regular non-symlink 1 MiB 이하 파일이 아닙니다.');
    }
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    throw new Error(`Windows strict 훅 manifest를 읽지 못했습니다: ${manifestPath} (${error.message})`);
  }
  if (manifest?.schemaVersion !== HOOK_MANIFEST_SCHEMA || manifest?.tag !== HOOK_MANAGED_TAG) {
    throw new Error('Windows strict 훅 manifest 버전 또는 관리 태그가 현재 runtime과 다릅니다. 훅을 다시 설치하세요.');
  }
  const record = manifest?.windowsVercelExecutable;
  if (!record
    || record.version !== SUPPORTED_VERCEL_CLI_VERSION
    || !/^[a-f0-9]{64}$/.test(String(record.sha256 || ''))
    || !/^[a-f0-9]{64}$/.test(String(record.backingSha256 || ''))
    || !/^[a-f0-9]{64}$/.test(String(record.powerShellSha256 || ''))) {
    throw new Error(`Windows strict 훅에 고정 Vercel CLI ${SUPPORTED_VERCEL_CLI_VERSION} 실행 파일 정보가 없습니다.`);
  }
  for (const name of ['strict-runtime.cjs', 'vercel-proxy.cjs']) {
    const file = path.join(path.dirname(manifestPath), name);
    let digest = '';
    try {
      const stat = fs.lstatSync(file);
      if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 10 * 1024 * 1024) throw new Error('regular non-symlink 10 MiB 이하 파일이 아닙니다.');
      digest = sha256(fs.readFileSync(file));
    } catch (error) {
      throw new Error(`Windows strict 관리 파일 ${name}을 확인하지 못했습니다: ${error.message}`);
    }
    if (manifest?.files?.[name] !== digest) throw new Error(`Windows strict 관리 파일 ${name}이 설치 뒤 바뀌었습니다. 훅을 다시 설치하세요.`);
  }
  if (manifest?.files?.['vercel.cmd'] !== record.sha256) {
    throw new Error('Windows strict 관리 proxy manifest 해시가 일치하지 않습니다.');
  }
  const executable = validateWindowsVercelExecutable(record.path, record.sha256);
  const backing = validateWindowsVercelExecutable(record.backingPath, record.backingSha256);
  const powerShell = validateWindowsPowerShellExecutable(record.powerShellPath, record.powerShellSha256);
  return {
    path: executable.path,
    sha256: executable.sha256,
    version: record.version,
    backingPath: backing.path,
    backingSha256: backing.sha256,
    powerShellPath: powerShell.path,
    powerShellSha256: powerShell.sha256,
    discoveredBy: record.discoveredBy || '',
    manifestPath,
  };
}

function resolveVercelExecutable(options = {}) {
  if (options.vercelBackingExecutable) {
    const executable = validateWindowsVercelExecutable(options.vercelBackingExecutable, options.vercelBackingExecutableSha256 || '');
    const powerShell = validateWindowsPowerShellExecutable(options.powerShellExecutable, options.powerShellExecutableSha256 || '');
    return {
      ...executable,
      version: options.vercelExecutableVersion || '',
      powerShellPath: powerShell.path,
      powerShellSha256: powerShell.sha256,
    };
  }
  if (options.vercelExecutable) {
    const executable = validateWindowsVercelExecutable(options.vercelExecutable, options.vercelExecutableSha256 || '');
    const powerShell = validateWindowsPowerShellExecutable(options.powerShellExecutable, options.powerShellExecutableSha256 || '');
    return {
      ...executable,
      version: options.vercelExecutableVersion || '',
      powerShellPath: powerShell.path,
      powerShellSha256: powerShell.sha256,
    };
  }
  const pinned = loadPinnedWindowsVercelExecutable(options);
  return {
    path: pinned.backingPath,
    sha256: pinned.backingSha256,
    version: pinned.version,
    powerShellPath: pinned.powerShellPath,
    powerShellSha256: pinned.powerShellSha256,
  };
}

function runVercelCli(args, spawnOptions = {}, options = {}) {
  const runner = options.execFileSync || execFileSync;
  const platform = options.platform || process.platform;
  const pinned = options.vercelExecutable || options.vercelBackingExecutable || platform === 'win32'
    ? resolveVercelExecutable(options)
    : null;
  if (platform !== 'win32') return runner(pinned?.path || 'vercel', args, spawnOptions);

  const safeArgs = args.map(value => String(value));
  if (safeArgs.some(value => !value || /[\s%&|<>^!"'()`]/.test(value))) {
    throw new Error('Windows PowerShell Vercel 내부 명령에 안전하게 전달할 수 없는 문자가 있습니다.');
  }
  const command = ['&', powerShellSingleQuoted(pinned.path), ...safeArgs.map(powerShellSingleQuoted)].join(' ');
  return runner(pinned.powerShellPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command], spawnOptions);
}

function verifyVercelCliVersion({ cwd = process.cwd() } = {}, options = {}) {
  let stdout;
  try {
    if (typeof options.vercelVersion === 'string') {
      stdout = options.vercelVersion;
    } else {
      stdout = runVercelCli(['--version'], {
        cwd,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: options.env || process.env,
        timeout: 60000,
      }, options);
    }
  } catch (error) {
    return {
      ok: false,
      exitCode: EXIT.INCOMPLETE,
      reason: `Vercel CLI 버전을 확인하지 못했습니다. npm install --global vercel@${SUPPORTED_VERCEL_CLI_VERSION}로 고정 설치하세요.`,
    };
  }
  const match = /(?:^|\D)(\d+\.\d+\.\d+)(?:\D|$)/.exec(String(stdout || ''));
  const version = match?.[1] || '';
  if (version !== SUPPORTED_VERCEL_CLI_VERSION) {
    return {
      ok: false,
      exitCode: EXIT.USAGE_CONFIG,
      version,
      expectedVersion: SUPPORTED_VERCEL_CLI_VERSION,
      reason: `strict source binding은 Vercel CLI ${SUPPORTED_VERCEL_CLI_VERSION}만 검증했습니다. npm install --global vercel@${SUPPORTED_VERCEL_CLI_VERSION}로 고정 설치하세요.`,
    };
  }
  return {
    ok: true,
    exitCode: EXIT.PASS,
    version,
    expectedVersion: SUPPORTED_VERCEL_CLI_VERSION,
    executable: options.vercelBackingExecutable || options.vercelExecutable || '',
  };
}

function readVercelLinkIdentity(root) {
  const directory = path.join(root, '.vercel');
  const file = path.join(root, '.vercel', 'project.json');
  let stat;
  let raw;
  let linked;
  try {
    const directoryStat = fs.lstatSync(directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw new Error('unsafe linked project directory');
    stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64 * 1024) throw new Error('unsafe linked project file');
    raw = fs.readFileSync(file);
    linked = JSON.parse(raw.toString('utf8'));
  } catch {
    return {
      ok: false,
      exitCode: EXIT.INCOMPLETE,
      reason: '.vercel/project.json을 안전하게 읽지 못했습니다. strict 검사 전에 현재 앱을 vercel link로 연결하세요.',
    };
  }
  const projectId = String(linked?.projectId || '').trim();
  const orgId = String(linked?.orgId || '').trim();
  const projectName = String(linked?.projectName || '').trim();
  if (!/^[A-Za-z0-9_-]+$/.test(projectId) || !/^[A-Za-z0-9_-]+$/.test(orgId) || projectId.length > 256 || orgId.length > 256 || projectName.length > 256) {
    return {
      ok: false,
      exitCode: EXIT.INCOMPLETE,
      reason: '.vercel/project.json에 유효한 projectId와 orgId가 모두 있어야 합니다.',
    };
  }
  return {
    ok: true,
    file,
    projectId,
    orgId,
    projectName,
    linkedConfigSha256: sha256(raw),
  };
}

const ALLOWED_PROJECT_STATE_FILES = new Set([
  '.dorms-check/REPORT.md',
  '.dorms-check/review.json',
  '.dorms-check/scan.json',
  '.dorms-check/state.json',
  '.dorms-check/strict-code.json',
  '.dorms-check/strict-live.json',
]);
const MAX_DEPLOYMENT_INPUT_FILE_BYTES = 100 * 1024 * 1024;
const MAX_DEPLOYMENT_INPUT_TOTAL_BYTES = 1024 * 1024 * 1024;

function isAllowedProjectStateLine(line) {
  const filePart = line.length > 3 ? line.slice(3).replace(/^"|"$/g, '') : '';
  const paths = filePart.split(' -> ');
  return paths.length > 0 && paths.every(item => ALLOWED_PROJECT_STATE_FILES.has(item));
}

function isVercelDefaultExcluded(relativePath, isDirectory) {
  const rel = relativePath.replaceAll('\\', '/');
  const parts = rel.split('/');
  const name = parts.at(-1) || '';
  if (rel === '.vercel' && isDirectory) return false;
  if (rel === '.vercel/routes.json' && !isDirectory) return false;
  const directoryNames = new Set([
    '.hg', '.git', '.svn', '.cache', '.next', '.now', '.vercel', '.venv',
    'node_modules', '__pycache__', 'venv', 'CVS',
  ]);
  if (parts.some(part => directoryNames.has(part))) return true;
  if (rel === '.yarn/cache' || rel.startsWith('.yarn/cache/')) return true;
  if (isDirectory) return false;
  if (['.gitmodules', '.npmignore', '.dockerignore', '.gitignore', '.DS_Store', '.lock-wscript', 'npm-debug.log', 'config.gypi'].includes(name)) return true;
  if (/^\..+\.swp$/.test(name) || /^\.wafpicke-/.test(name)) return true;
  if (/^\.pnp/.test(name)) return true;
  if (name === '.env.local' || /^\.env\..+\.local$/.test(name)) return true;
  return false;
}

function sameFileSnapshot(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function hashStableRegularFile(file, relativePath) {
  let descriptor;
  try {
    const pathBefore = fs.lstatSync(file, { bigint: true });
    if (!pathBefore.isFile() || pathBefore.isSymbolicLink()) throw new Error('regular non-symlink file이 아닙니다.');
    if (pathBefore.size > BigInt(MAX_DEPLOYMENT_INPUT_FILE_BYTES)) {
      throw new Error(`${MAX_DEPLOYMENT_INPUT_FILE_BYTES / (1024 * 1024)} MiB 파일 상한을 넘었습니다.`);
    }
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFileSnapshot(pathBefore, before)) throw new Error('파일을 여는 동안 상태가 바뀌었습니다.');
    const digest = crypto.createHash('sha256');
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    for (;;) {
      const count = fs.readSync(descriptor, chunk, 0, chunk.length, null);
      if (!count) break;
      bytes += count;
      if (bytes > MAX_DEPLOYMENT_INPUT_FILE_BYTES) throw new Error('파일을 읽는 동안 크기 상한을 넘었습니다.');
      digest.update(chunk.subarray(0, count));
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(file, { bigint: true });
    if (!sameFileSnapshot(before, after) || !sameFileSnapshot(after, pathAfter) || BigInt(bytes) !== after.size) {
      throw new Error('파일을 해시하는 동안 내용 또는 메타데이터가 바뀌었습니다.');
    }
    return { path: relativePath, sha256: digest.digest('hex'), size: bytes, mode: Number(before.mode), type: 'file' };
  } catch (error) {
    throw new Error(`${relativePath} 원본 바이트를 안정적으로 해시하지 못했습니다: ${error.message}`);
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch { /* Preserve the primary hashing error. */ }
    }
  }
}

function customVercelIgnoreStatus(root) {
  const present = [];
  for (const name of ['.vercelignore', '.nowignore']) {
    const file = path.join(root, name);
    if (!fs.existsSync(file)) continue;
    let stat;
    let text;
    try {
      stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) {
        throw new Error('regular non-symlink file이 아니거나 1 MiB 상한을 넘었습니다.');
      }
      text = fs.readFileSync(file, 'utf8');
    } catch (error) {
      return { ok: false, reason: `${name}을 안전하게 읽지 못했습니다: ${error.message}` };
    }
    if (text.trim()) present.push(name);
    if (text.split(/\r?\n/).some(line => /^\s*!/.test(line))) {
      return {
        ok: false,
        reason: `${name}의 negation 규칙은 Vercel 기본 제외 파일을 다시 업로드할 수 있어 strict source binding에서 허용하지 않습니다.`,
      };
    }
  }
  if (present.length > 1) {
    return { ok: false, reason: '.vercelignore와 .nowignore를 함께 사용할 수 없습니다.' };
  }
  return { ok: true };
}

function activeGitFilters(root, relativePaths) {
  if (!relativePaths.length) return [];
  const output = execFileSync('git', ['--no-replace-objects', '-C', root, 'check-attr', '-z', '--stdin', 'filter'], {
    input: `${relativePaths.join('\0')}\0`,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
  });
  const values = output.split('\0');
  const active = [];
  for (let index = 0; index + 2 < values.length; index += 3) {
    const [file, attribute, value] = values.slice(index, index + 3);
    if (attribute === 'filter' && value !== 'unspecified' && value !== 'unset') active.push(`${file}=${value}`);
  }
  return active;
}

function headTreeEntries(root) {
  const output = execFileSync('git', ['--no-replace-objects', '-C', root, 'ls-tree', '-rz', '--full-tree', 'HEAD'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
  });
  const entries = new Map();
  for (const record of output.split('\0').filter(Boolean)) {
    const tab = record.indexOf('\t');
    const header = tab >= 0 ? record.slice(0, tab).split(' ') : [];
    const relativePath = tab >= 0 ? record.slice(tab + 1) : '';
    if (header.length === 3 && relativePath) entries.set(relativePath, { mode: header[0], type: header[1], oid: header[2] });
  }
  return entries;
}

function canonicalWorktreeObjectIds(root, relativePaths) {
  const ids = new Map();
  for (let start = 0; start < relativePaths.length; start += 1000) {
    const chunk = relativePaths.slice(start, start + 1000);
    const output = execFileSync('git', ['--no-replace-objects', '-C', root, 'hash-object', '--filters', '--stdin-paths'], {
      input: `${chunk.join('\n')}\n`,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024,
    });
    const hashes = output.trim().split(/\r?\n/).filter(Boolean);
    if (hashes.length !== chunk.length) throw new Error('Git raw worktree object hash 개수가 입력 파일과 다릅니다.');
    chunk.forEach((file, index) => ids.set(file, hashes[index]));
  }
  return ids;
}

function indexEntries(root) {
  const output = execFileSync('git', ['--no-replace-objects', '-C', root, 'ls-files', '--stage', '-z'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
  });
  const entries = new Map();
  for (const record of output.split('\0').filter(Boolean)) {
    const match = /^(\d+) ([a-f0-9]+) (\d+)\t([\s\S]+)$/.exec(record);
    if (match && match[3] === '0') entries.set(match[4], { mode: match[1], oid: match[2] });
  }
  return entries;
}

function verifyTrackedDeploymentInputsMatchHead(root, manifest, tracked) {
  const trackedItems = manifest.filter(item => tracked.has(item.path) && !ALLOWED_PROJECT_STATE_FILES.has(item.path));
  const paths = trackedItems.map(item => item.path);
  const filters = activeGitFilters(root, paths);
  if (filters.length) {
    return { ok: false, reason: `배포 입력에 active Git clean/smudge filter가 있어 HEAD와 실제 업로드 바이트의 일치를 증명할 수 없습니다: ${filters.slice(0, 10).join(', ')}` };
  }
  const head = headTreeEntries(root);
  const index = indexEntries(root);
  const worktreeIds = canonicalWorktreeObjectIds(root, paths);
  const mismatches = [];
  for (const item of trackedItems) {
    const expected = head.get(item.path);
    const staged = index.get(item.path);
    if (!expected || expected.type !== 'blob'
      || !staged || staged.oid !== expected.oid || staged.mode !== expected.mode
      || expected.oid !== worktreeIds.get(item.path)) {
      mismatches.push(item.path);
    }
  }
  return mismatches.length
    ? { ok: false, reason: `tracked 배포 입력의 원본 바이트 또는 실행 mode가 HEAD와 다릅니다: ${mismatches.slice(0, 10).join(', ')}` }
    : { ok: true };
}

function deploymentInputStatus(root) {
  const customIgnore = customVercelIgnoreStatus(root);
  if (!customIgnore.ok) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: customIgnore.reason };
  }
  let trackedOutput;
  let flagOutput;
  try {
    trackedOutput = git(root, ['ls-files', '-z']);
    flagOutput = git(root, ['ls-files', '-v', '-z']);
  } catch (error) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: `Git 배포 입력 목록을 확인하지 못했습니다: ${error.message}` };
  }
  const tracked = new Set(trackedOutput.split('\0').filter(Boolean));
  const riskyFlags = flagOutput.split('\0').filter(Boolean).filter(entry => {
    const tag = entry[0] || '';
    return tag === 'S' || tag === 's' || (tag && tag === tag.toLowerCase());
  });
  if (riskyFlags.length) {
    return {
      ok: false,
      exitCode: EXIT.BINDING_MISMATCH,
      reason: `assume-unchanged/skip-worktree Git 플래그가 있어 source binding을 보장할 수 없습니다: ${riskyFlags.slice(0, 10).map(item => item.slice(2)).join(', ')}`,
    };
  }

  const unbound = [];
  const symlinks = [];
  const projectState = [];
  const manifest = [];
  let totalBytes = 0;
  let visited = 0;
  const walk = (directory, prefix = '') => {
    let entries;
    try { entries = fs.readdirSync(directory, { withFileTypes: true }); }
    catch (error) { throw new Error(`${prefix || '.'}을 읽지 못했습니다: ${error.message}`); }
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (/[\0\r\n]/.test(rel)) throw new Error(`제어 문자가 포함된 배포 입력 경로는 strict manifest에서 허용하지 않습니다: ${JSON.stringify(rel)}`);
      if (entry.isSymbolicLink()) {
        if (rel === '.vercel' || !isVercelDefaultExcluded(rel, false)) symlinks.push(rel);
        continue;
      }
      if (isVercelDefaultExcluded(rel, entry.isDirectory())) continue;
      visited++;
      if (visited > 20000) throw new Error('배포 입력이 20,000개를 넘어 strict source binding 상한을 초과했습니다.');
      if (rel === '.vercel/routes.json' && entry.isDirectory()) {
        unbound.push(rel);
        continue;
      }
      if (entry.isDirectory()) {
        walk(path.join(directory, entry.name), rel);
      } else if (rel === '.vercel/routes.json') {
        const item = hashStableRegularFile(path.join(directory, entry.name), rel);
        manifest.push(item);
        totalBytes += item.size;
      } else if (rel.startsWith('.dorms-check/')) {
        if (!ALLOWED_PROJECT_STATE_FILES.has(rel)) {
          unbound.push(rel);
        } else {
          const item = hashStableRegularFile(path.join(directory, entry.name), rel);
          if (item.size > 10 * 1024 * 1024) throw new Error(`${rel} 상태 파일이 10 MiB 상한을 넘었습니다.`);
          projectState.push(item);
          manifest.push(item);
          totalBytes += item.size;
        }
      } else if (!tracked.has(rel)) {
        unbound.push(rel);
      } else {
        const item = hashStableRegularFile(path.join(directory, entry.name), rel);
        manifest.push(item);
        totalBytes += item.size;
      }
      if (totalBytes > MAX_DEPLOYMENT_INPUT_TOTAL_BYTES) throw new Error('배포 입력 원본 바이트가 1 GiB 상한을 넘었습니다.');
      if (unbound.length >= 20 || symlinks.length >= 20) return;
    }
  };
  try { walk(root); }
  catch (error) { return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: `Vercel 배포 입력을 열거하지 못했습니다: ${error.message}` }; }
  if (symlinks.length) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: `strict direct-source 배포는 symlink 입력을 허용하지 않습니다: ${symlinks.join(', ')}` };
  }
  if (unbound.length) {
    return {
      ok: false,
      exitCode: EXIT.BINDING_MISMATCH,
      reason: `Vercel CLI가 업로드할 수 있지만 Git HEAD 또는 허용된 dorms-check 상태 digest에 묶이지 않은 파일이 있습니다: ${unbound.join(', ')}`,
    };
  }
  projectState.sort((left, right) => left.path.localeCompare(right.path));
  manifest.sort((left, right) => left.path.localeCompare(right.path));
  let headBinding;
  try { headBinding = verifyTrackedDeploymentInputsMatchHead(root, manifest, tracked); }
  catch (error) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: `tracked 배포 입력과 HEAD를 비교하지 못했습니다: ${error.message}` };
  }
  if (!headBinding.ok) return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: headBinding.reason };
  return {
    ok: true,
    trackedFiles: tracked.size,
    inspectedInputs: visited,
    deploymentInputFiles: manifest.length,
    deploymentInputBytes: totalBytes,
    deploymentInputSha256: sha256(stableStringify(manifest)),
    projectStateFiles: projectState.length,
    projectStateSha256: sha256(stableStringify(projectState)),
    manifest,
  };
}

function projectIdentity(cwd) {
  const gitOverrides = ambientGitOverrides();
  if (gitOverrides.length) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: `Git 저장소·index·object/config identity를 바꾸는 ambient 환경변수는 strict 흐름에서 허용하지 않습니다: ${gitOverrides.join(', ')}` };
  }
  const root = findGitRoot(cwd);
  if (!root) return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: '현재 폴더가 Git 저장소가 아닙니다.' };
  const vercel = readVercelLinkIdentity(root);
  if (!vercel.ok) return { ...vercel, root };
  try {
    const gitSha = git(root, ['rev-parse', 'HEAD']);
    const treeSha = git(root, ['rev-parse', 'HEAD^{tree}']);
    const dirtyLines = git(root, ['status', '--porcelain=v1', '--untracked-files=all'])
      .split(/\r?\n/)
      .filter(Boolean)
      .filter(line => !isAllowedProjectStateLine(line));
    const deploymentInputs = deploymentInputStatus(root);
    if (!deploymentInputs.ok) return { ...deploymentInputs, root };
    const deploymentInputSummary = {
      trackedFiles: deploymentInputs.trackedFiles,
      inspectedInputs: deploymentInputs.inspectedInputs,
      deploymentInputFiles: deploymentInputs.deploymentInputFiles,
      deploymentInputBytes: deploymentInputs.deploymentInputBytes,
      deploymentInputSha256: deploymentInputs.deploymentInputSha256,
      projectStateFiles: deploymentInputs.projectStateFiles,
      projectStateSha256: deploymentInputs.projectStateSha256,
    };
    Object.defineProperty(deploymentInputSummary, 'manifest', {
      value: deploymentInputs.manifest,
      enumerable: false,
      writable: false,
    });
    return {
      ok: true,
      root,
      rootHash: sha256(fs.realpathSync(root)),
      gitSha,
      treeSha,
      vercel: {
        projectId: vercel.projectId,
        orgId: vercel.orgId,
        projectName: vercel.projectName,
        linkedConfigSha256: vercel.linkedConfigSha256,
      },
      deploymentInputs: deploymentInputSummary,
      clean: dirtyLines.length === 0,
      dirty: dirtyLines.slice(0, 50),
    };
  } catch (error) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: `Git 상태를 확인하지 못했습니다: ${error.message}` };
  }
}

function normalizeDeploymentUrl(value) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('배포 URL이 필요합니다.');
  const raw = /^https?:\/\//i.test(value.trim()) ? value.trim() : `https://${value.trim()}`;
  const parsed = new URL(raw);
  if (parsed.protocol !== 'https:') throw new Error('배포 URL은 https여야 합니다.');
  if (parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error('배포 URL에는 사용자정보, 쿼리, 해시를 넣을 수 없습니다.');
  parsed.hostname = parsed.hostname.toLowerCase();
  parsed.pathname = parsed.pathname.replace(/\/+$/, '') || '/';
  return parsed.toString();
}

function receiptBase(homeDir, rootHash) {
  return path.join(homeDir, '.dorms-check', 'receipts', rootHash);
}

function receiptFile(homeDir, rootHash, phase) {
  return path.join(receiptBase(homeDir, rootHash), `${phase}.json`);
}

function keyFile(homeDir) {
  return path.join(homeDir, '.dorms-check', 'receipt.key');
}

function loadOrCreateKey(homeDir, { create = false } = {}) {
  const file = keyFile(homeDir);
  if (fs.existsSync(file)) {
    const key = fs.readFileSync(file, 'utf8').trim();
    if (!/^[A-Za-z0-9+/]{43}=$/.test(key)) throw new Error('receipt key is malformed');
    const decoded = Buffer.from(key, 'base64');
    if (decoded.length !== 32) throw new Error('receipt key is malformed');
    return decoded;
  }
  if (!create) throw new Error('receipt key is missing');
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const value = crypto.randomBytes(32).toString('base64');
  try {
    fs.writeFileSync(file, value + '\n', { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    return loadOrCreateKey(homeDir, { create: false });
  }
  return Buffer.from(value, 'base64');
}

function unsignedReceipt(receipt) {
  const copy = JSON.parse(JSON.stringify(receipt));
  delete copy.integrity;
  return copy;
}

function signReceipt(receipt, key) {
  return crypto.createHmac('sha256', key).update(stableStringify(unsignedReceipt(receipt))).digest('hex');
}

function safeEqualHex(left, right) {
  if (!/^[a-f0-9]{64}$/.test(String(left || '')) || !/^[a-f0-9]{64}$/.test(String(right || ''))) return false;
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function createReceipt({
  phase,
  project,
  deploymentUrl = '',
  deploymentId = '',
  deploymentGitSha = '',
  vercelProjectId = '',
  vercelOrgId = '',
  strict,
  results,
  tool = {},
  now = new Date(),
}) {
  if (!['code', 'live'].includes(phase)) throw new Error('receipt phase must be code or live');
  if (!project?.ok || !project.clean) throw new Error('receipt requires a clean Git project');
  if (
    !project.vercel?.projectId
    || !project.vercel?.orgId
    || !/^[a-f0-9]{64}$/i.test(String(project.vercel?.linkedConfigSha256 || ''))
  ) {
    throw new Error('receipt requires an exact linked Vercel project binding');
  }
  const checkedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + RECEIPT_TTL_MS).toISOString();
  const deployment = phase === 'live'
    ? {
        provider: 'vercel',
        url: normalizeDeploymentUrl(deploymentUrl),
        id: String(deploymentId || ''),
        sourceGitSha: String(deploymentGitSha || ''),
        projectId: String(vercelProjectId || ''),
        orgId: String(vercelOrgId || ''),
        target: 'production',
        readyState: 'READY',
      }
    : null;
  if (phase === 'live' && !/^dpl_[A-Za-z0-9]+$/.test(deployment.id)) {
    throw new Error('live receipt requires a verified Vercel deployment ID');
  }
  if (phase === 'live' && (
    deployment.sourceGitSha !== project.gitSha
    || !/^[a-f0-9]{40}$/i.test(deployment.sourceGitSha)
    || deployment.projectId !== project.vercel.projectId
    || deployment.orgId !== project.vercel.orgId
  )) {
    throw new Error('live receipt requires exact Git artifact and Vercel project bindings');
  }
  return {
    schemaVersion: 1,
    kind: RECEIPT_KIND,
    phase,
    checkedAt,
    expiresAt,
    tool: { version: String(tool.version || 'unknown'), commit: String(tool.commit || '') },
    gate: { schema: GATE_SCHEMA, runtimeSha256: RUNTIME_DIGEST },
    project: {
      rootHash: project.rootHash,
      gitSha: project.gitSha,
      treeSha: project.treeSha,
      clean: true,
      vercel: {
        projectId: project.vercel.projectId,
        orgId: project.vercel.orgId,
        projectName: project.vercel.projectName || '',
        linkedConfigSha256: project.vercel.linkedConfigSha256,
      },
      deploymentInputs: {
        deploymentInputFiles: project.deploymentInputs?.deploymentInputFiles || 0,
        deploymentInputBytes: project.deploymentInputs?.deploymentInputBytes || 0,
        deploymentInputSha256: project.deploymentInputs?.deploymentInputSha256 || '',
        projectStateFiles: project.deploymentInputs?.projectStateFiles || 0,
        projectStateSha256: project.deploymentInputs?.projectStateSha256 || '',
      },
    },
    deployment,
    strict: {
      status: strict.status,
      expected: [...strict.expected],
      observed: [...strict.observed],
      blockers: [...strict.blockers],
      incomplete: [...strict.incomplete],
    },
    resultsSha256: sha256(stableStringify(results || [])),
  };
}

function storeReceipt(receipt, projectRoot, options = {}) {
  const homeDir = resolveHome(options);
  const key = loadOrCreateKey(homeDir, { create: true });
  const signed = {
    ...receipt,
    integrity: { algorithm: 'hmac-sha256', digest: signReceipt(receipt, key) },
  };
  const trustedFile = receiptFile(homeDir, receipt.project.rootHash, receipt.phase);
  atomicWrite(trustedFile, JSON.stringify(signed, null, 2) + '\n');
  return { receipt: signed, trustedFile, projectFile: null };
}

function invalidateReceipt(phase, project, projectRoot, options = {}) {
  if (!['code', 'live'].includes(phase) || !project?.rootHash) return;
  const homeDir = resolveHome(options);
  const files = [
    receiptFile(homeDir, project.rootHash, phase),
  ];
  for (const file of files) {
    try { fs.unlinkSync(file); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function readAndVerifyReceipt(file, key, expectedPhase, now) {
  if (!fs.existsSync(file)) return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: `${expectedPhase} strict 영수증이 없습니다.` };
  let receipt;
  try { receipt = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: `${expectedPhase} strict 영수증 JSON이 손상됐습니다.` }; }
  if (receipt.kind !== RECEIPT_KIND || receipt.schemaVersion !== 1 || receipt.phase !== expectedPhase) {
    return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: `${expectedPhase} strict 영수증 형식이 맞지 않습니다.` };
  }
  if (receipt.gate?.schema !== GATE_SCHEMA || receipt.gate?.runtimeSha256 !== RUNTIME_DIGEST) {
    return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: `${expectedPhase} strict 영수증이 현재 보안 게이트 런타임과 다릅니다. 현재 고정 버전으로 다시 검사하세요.` };
  }
  const expectedDigest = signReceipt(receipt, key);
  if (receipt.integrity?.algorithm !== 'hmac-sha256' || !safeEqualHex(receipt.integrity?.digest, expectedDigest)) {
    return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: `${expectedPhase} strict 영수증 무결성 검증에 실패했습니다.` };
  }
  const checkedAt = Date.parse(receipt.checkedAt);
  const expiresAt = Date.parse(receipt.expiresAt);
  if (!Number.isFinite(checkedAt) || !Number.isFinite(expiresAt) || expiresAt - checkedAt !== RECEIPT_TTL_MS || now.getTime() > expiresAt || checkedAt > now.getTime() + 60 * 1000) {
    return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: `${expectedPhase} strict 영수증이 만료됐습니다. 다시 검사하세요.` };
  }
  if (receipt.strict?.status !== 'PASS' || receipt.strict.blockers?.length || receipt.strict.incomplete?.length) {
    return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: `${expectedPhase} strict 영수증이 PASS 상태가 아닙니다.` };
  }
  const required = REQUIRED_BY_PHASE[expectedPhase];
  const expected = Array.isArray(receipt.strict?.expected) ? [...new Set(receipt.strict.expected)].sort() : [];
  const observed = new Set(Array.isArray(receipt.strict?.observed) ? receipt.strict.observed : []);
  if (expected.join('\n') !== [...required].sort().join('\n') || required.some(id => !observed.has(id))) {
    return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: `${expectedPhase} strict 영수증의 필수 검사 목록이 완전하지 않습니다.` };
  }
  if (
    typeof receipt.project?.vercel?.projectId !== 'string'
    || !receipt.project.vercel.projectId
    || typeof receipt.project?.vercel?.orgId !== 'string'
    || !receipt.project.vercel.orgId
    || !/^[a-f0-9]{64}$/i.test(String(receipt.project?.vercel?.linkedConfigSha256 || ''))
    || !Number.isInteger(receipt.project?.deploymentInputs?.deploymentInputFiles)
    || receipt.project.deploymentInputs.deploymentInputFiles < 0
    || !Number.isInteger(receipt.project?.deploymentInputs?.deploymentInputBytes)
    || receipt.project.deploymentInputs.deploymentInputBytes < 0
    || !/^[a-f0-9]{64}$/i.test(String(receipt.project?.deploymentInputs?.deploymentInputSha256 || ''))
    || !Number.isInteger(receipt.project?.deploymentInputs?.projectStateFiles)
    || receipt.project.deploymentInputs.projectStateFiles < 0
    || !/^[a-f0-9]{64}$/i.test(String(receipt.project?.deploymentInputs?.projectStateSha256 || ''))
  ) {
    return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: `${expectedPhase} strict 영수증의 프로젝트 입력 바인딩이 완전하지 않습니다.` };
  }
  if (expectedPhase === 'live' && (
    receipt.deployment?.provider !== 'vercel'
    || !/^dpl_[A-Za-z0-9]+$/.test(String(receipt.deployment?.id || ''))
    || !/^[a-f0-9]{40}$/i.test(String(receipt.deployment?.sourceGitSha || ''))
    || receipt.deployment?.sourceGitSha !== receipt.project?.gitSha
    || typeof receipt.deployment?.projectId !== 'string'
    || !receipt.deployment.projectId
    || typeof receipt.deployment?.orgId !== 'string'
    || !receipt.deployment.orgId
    || receipt.deployment.projectId !== receipt.project.vercel.projectId
    || receipt.deployment.orgId !== receipt.project.vercel.orgId
    || receipt.deployment?.target !== 'production'
    || receipt.deployment?.readyState !== 'READY'
  )) {
    return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: 'live strict 영수증의 Vercel 배포 바인딩이 완전하지 않습니다.' };
  }
  return { ok: true, receipt };
}

function comparableTarget(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  try { return normalizeDeploymentUrl(text); }
  catch { return text; }
}

function verifiedCodeContext({ cwd, gitSha = '', now = new Date() }, options = {}) {
  const project = projectIdentity(cwd);
  if (!project.ok) return project;
  const environment = options.env || process.env;
  const identityOverrides = [
    ['VERCEL_PROJECT_ID', project.vercel.projectId],
    ['NOW_PROJECT_ID', project.vercel.projectId],
    ['VERCEL_ORG_ID', project.vercel.orgId],
    ['NOW_ORG_ID', project.vercel.orgId],
    ['VERCEL_TEAM_ID', project.vercel.orgId],
  ];
  const environmentEntries = Object.entries(environment || {}).map(([name, value]) => ({
    name,
    normalizedName: String(name).toUpperCase(),
    value: String(value || '').trim(),
  }));
  const mismatchedIdentity = identityOverrides.find(([name, expected]) => environmentEntries
    .some(entry => entry.normalizedName === name && entry.value && entry.value !== expected));
  if (mismatchedIdentity) {
    return {
      ok: false,
      exitCode: EXIT.BINDING_MISMATCH,
      reason: `${mismatchedIdentity[0]}가 서명된 로컬 Vercel project/org 링크와 정확히 일치하지 않습니다.`,
    };
  }
  const allowedIdentityNames = new Set(identityOverrides.map(([name]) => name));
  const forbiddenOverrides = environmentEntries
    .filter(entry => /^(?:VERCEL|NOW)(?:_|$)/.test(entry.normalizedName)
      && !allowedIdentityNames.has(entry.normalizedName)
      && entry.value)
    .map(entry => entry.name)
    .sort();
  if (forbiddenOverrides.length) {
    return {
      ok: false,
      exitCode: EXIT.BINDING_MISMATCH,
      reason: `strict Vercel 명령은 project/org identity 외 ambient Vercel/NOW override를 허용하지 않습니다: ${forbiddenOverrides.join(', ')}`,
    };
  }
  if (!project.clean) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: 'Git 작업트리에 커밋되지 않은 변경이 있어 strict 영수증과 일치하지 않습니다.', dirty: project.dirty };
  }
  if (gitSha && gitSha !== project.gitSha) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: `요청한 Git SHA(${gitSha})와 현재 HEAD(${project.gitSha})가 다릅니다.` };
  }
  const homeDir = resolveHome(options);
  let key;
  try { key = loadOrCreateKey(homeDir, { create: false }); }
  catch (error) { return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: `strict 영수증 키를 읽지 못했습니다: ${error.message}` }; }

  const code = readAndVerifyReceipt(receiptFile(homeDir, project.rootHash, 'code'), key, 'code', now);
  if (!code.ok) return code;
  const item = code.receipt;
  if (
    item.project.rootHash !== project.rootHash
    || item.project.gitSha !== project.gitSha
    || item.project.treeSha !== project.treeSha
    || item.project.clean !== true
    || item.project.deploymentInputs?.deploymentInputFiles !== project.deploymentInputs.deploymentInputFiles
    || item.project.deploymentInputs?.deploymentInputBytes !== project.deploymentInputs.deploymentInputBytes
    || item.project.deploymentInputs?.deploymentInputSha256 !== project.deploymentInputs.deploymentInputSha256
    || item.project.deploymentInputs?.projectStateFiles !== project.deploymentInputs.projectStateFiles
    || item.project.deploymentInputs?.projectStateSha256 !== project.deploymentInputs.projectStateSha256
  ) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: 'code strict 영수증의 Git 바인딩이 현재 소스와 다릅니다.' };
  }
  if (
    item.project.vercel?.projectId !== project.vercel.projectId
    || item.project.vercel?.orgId !== project.vercel.orgId
    || item.project.vercel?.projectName !== project.vercel.projectName
    || item.project.vercel?.linkedConfigSha256 !== project.vercel.linkedConfigSha256
  ) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: 'code strict 영수증의 Vercel project/org 또는 linked config digest가 현재 링크와 다릅니다.' };
  }
  return { ok: true, project, key, code: code.receipt, homeDir, now };
}

function verifyCodeGate({ cwd, gitSha = '', now = new Date() }, options = {}) {
  const context = verifiedCodeContext({ cwd, gitSha, now }, options);
  if (!context.ok) return context;
  return {
    ok: true,
    exitCode: EXIT.PASS,
    status: 'PASS',
    gate: { schema: GATE_SCHEMA, runtimeSha256: RUNTIME_DIGEST },
    project: {
      gitSha: context.project.gitSha,
      treeSha: context.project.treeSha,
      vercel: context.project.vercel,
      deploymentInputs: context.project.deploymentInputs,
    },
    checkedAt: context.code.checkedAt,
    expiresAt: context.code.expiresAt,
  };
}

function verifyGate({ cwd, gitSha = '', deployment = '', url = '', now = new Date() }, options = {}) {
  const context = verifiedCodeContext({ cwd, gitSha, now }, options);
  if (!context.ok) return context;
  const { project, key, homeDir } = context;
  const live = readAndVerifyReceipt(receiptFile(homeDir, project.rootHash, 'live'), key, 'live', now);
  if (!live.ok) return live;
  if (
    live.receipt.project.rootHash !== project.rootHash
    || live.receipt.project.gitSha !== project.gitSha
    || live.receipt.project.treeSha !== project.treeSha
    || live.receipt.project.clean !== true
    || live.receipt.project.vercel?.projectId !== project.vercel.projectId
    || live.receipt.project.vercel?.orgId !== project.vercel.orgId
    || live.receipt.project.vercel?.projectName !== project.vercel.projectName
    || live.receipt.project.vercel?.linkedConfigSha256 !== project.vercel.linkedConfigSha256
    || live.receipt.project.deploymentInputs?.deploymentInputFiles !== project.deploymentInputs.deploymentInputFiles
    || live.receipt.project.deploymentInputs?.deploymentInputBytes !== project.deploymentInputs.deploymentInputBytes
    || live.receipt.project.deploymentInputs?.deploymentInputSha256 !== project.deploymentInputs.deploymentInputSha256
    || live.receipt.project.deploymentInputs?.projectStateFiles !== project.deploymentInputs.projectStateFiles
    || live.receipt.project.deploymentInputs?.projectStateSha256 !== project.deploymentInputs.projectStateSha256
  ) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: 'live strict 영수증의 Git 바인딩이 현재 소스와 다릅니다.' };
  }

  const expectedTargets = new Set([
    comparableTarget(live.receipt.deployment?.url),
    comparableTarget(live.receipt.deployment?.id),
  ].filter(Boolean));
  if (!expectedTargets.size) return { ok: false, exitCode: EXIT.RECEIPT_INVALID, reason: 'live strict 영수증에 배포 식별자가 없습니다.' };
  if (deployment && !expectedTargets.has(comparableTarget(deployment))) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: '프로덕션 전환 대상이 strict 검사한 Vercel 배포와 다릅니다.' };
  }
  if (url && comparableTarget(url) !== comparableTarget(live.receipt.deployment.url)) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: '요청한 URL이 strict 검사한 Vercel 배포 URL과 다릅니다.' };
  }
  return {
    ok: true,
    exitCode: EXIT.PASS,
    status: 'PASS',
    gate: { schema: GATE_SCHEMA, runtimeSha256: RUNTIME_DIGEST },
    project: { gitSha: project.gitSha, treeSha: project.treeSha, vercel: project.vercel, deploymentInputs: project.deploymentInputs },
    deployment: live.receipt.deployment,
    checkedAt: live.receipt.checkedAt,
    expiresAt: live.receipt.expiresAt,
  };
}

function tokenizeShell(command) {
  const segments = [];
  let tokens = [];
  let token = '';
  let quote = '';
  let escaped = false;
  const pushToken = () => { if (token) { tokens.push(token); token = ''; } };
  const pushSegment = () => { pushToken(); if (tokens.length) segments.push(tokens); tokens = []; };
  for (let index = 0; index < command.length; index++) {
    const char = command[index];
    if (escaped) { token += char; escaped = false; continue; }
    if (char === '\\' && quote !== "'" && process.platform !== 'win32') { escaped = true; continue; }
    if (quote) {
      if (char === quote) quote = '';
      else token += char;
      continue;
    }
    if (char === "'" || char === '"') { quote = char; continue; }
    if (/\s/.test(char)) {
      if (char === '\n' || char === '\r') pushSegment();
      else pushToken();
      continue;
    }
    if (char === ';' || char === '&') {
      pushSegment();
      if ((char === '|' || char === '&') && command[index + 1] === char) index++;
      continue;
    }
    if (char === '|') {
      pushSegment();
      if (command[index + 1] === '|') index++;
      continue;
    }
    token += char;
  }
  pushSegment();
  return { segments, unterminatedQuote: Boolean(quote || escaped) };
}

function basename(token) {
  return path.basename(String(token || '').replace(/\\/g, '/')).toLowerCase();
}

function isAssignment(token) {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

function isVercelToken(token) {
  const base = basename(token);
  return /^(?:vercel|vc)(?:\.exe|\.cmd)?(?:@[^/]+)?$/i.test(base);
}

const PRODUCTION_MUTATOR_RE = /--prod(?:\b|=)|--target(?:=|\s+)production\b|\bpromote\b|\brollback\b|\bredeploy\b|\brolling-release\b|\brr\b|\balias\b|\bapi\b/i;
const VERCEL_ADMIN_MUTATOR_RE = /\b(?:domains?|dns|env|project|git|flags?|webhooks?|deploy-hooks|routes?|redirects?|firewall|certs?|teams?|cache|telemetry|integrations?|integration-resource)\s+(?:add|set|rm|remove|delete|create|update|enable|disable|connect|disconnect|invite|issue|buy|move|transfer-in|import|pull|run|publish|restore|purge|invalidate|dangerously-delete|unlink)\b/i;
const PRODUCTION_SCRIPT_HINT_RE = /(?:^|[._/-])(?:deploy|deployment|prod|production|promote|rollback|redeploy|release|vercel|alias)(?:$|[._/-])/i;

function skipPrefix(tokens, start = 0) {
  let index = start;
  while (index < tokens.length && isAssignment(tokens[index])) index++;
  while (['env', 'command', 'sudo'].includes(basename(tokens[index]))) {
    index++;
    while (index < tokens.length && (tokens[index].startsWith('-') || isAssignment(tokens[index]))) index++;
  }
  return index;
}

function findPackageToken(tokens, start) {
  const optionsWithValue = new Set(['--package', '-p', '--cache', '--prefix', '--userconfig', '--registry']);
  let index = start;
  for (; index < tokens.length; index++) {
    const token = tokens[index];
    if (token === '--') continue;
    if (optionsWithValue.has(token)) { index++; continue; }
    if (token.startsWith('-')) continue;
    return index;
  }
  return -1;
}

function unwrapVercel(tokens) {
  let index = skipPrefix(tokens);
  const executable = basename(tokens[index]);
  if (isVercelToken(tokens[index])) return { args: tokens.slice(index + 1) };

  if (/^npx(?:\.cmd|\.exe)?$/.test(executable) || (executable === 'npm' && tokens[index + 1] === 'exec')) {
    if (executable === 'npm') index++;
    const packageIndex = findPackageToken(tokens, index + 1);
    if (packageIndex >= 0 && isVercelToken(tokens[packageIndex])) return { args: tokens.slice(packageIndex + 1) };
  }
  if (/^pnpm(?:\.cmd|\.exe)?$/.test(executable) && ['dlx', 'exec'].includes(tokens[index + 1])) {
    const packageIndex = findPackageToken(tokens, index + 2);
    if (packageIndex >= 0 && isVercelToken(tokens[packageIndex])) return { args: tokens.slice(packageIndex + 1) };
  }
  if (/^bunx(?:\.cmd|\.exe)?$/.test(executable)) {
    const packageIndex = findPackageToken(tokens, index + 1);
    if (packageIndex >= 0 && isVercelToken(tokens[packageIndex])) return { args: tokens.slice(packageIndex + 1) };
  }
  return null;
}

function nestedShellCommand(tokens) {
  const index = skipPrefix(tokens);
  const executable = basename(tokens[index]);
  if (!['sh', 'bash', 'zsh', 'dash', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'].includes(executable)) return '';
  const commandFlag = tokens.findIndex((token, itemIndex) => itemIndex > index && ['-c', '/c', '-command'].includes(token.toLowerCase()));
  return commandFlag >= 0 ? tokens[commandFlag + 1] || '' : '';
}

function assignedVercelVariables(segments) {
  const names = new Set();
  for (const tokens of segments) {
    for (const token of tokens) {
      const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/.exec(token);
      if (match && isVercelToken(match[2])) names.add(match[1]);
    }
  }
  return names;
}

function dynamicExecutableName(token) {
  const value = String(token || '');
  const match = /^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$/.exec(value)
    || /^%([A-Za-z_][A-Za-z0-9_]*)%$/.exec(value);
  if (match) return match[1] || match[2] || 'dynamic';
  return /\$(?:\{|[A-Za-z_])|%[A-Za-z_][A-Za-z0-9_]*%/.test(value) ? 'dynamic' : '';
}

function hasDynamicExecutable(segments) {
  return segments.some(tokens => dynamicExecutableName(tokens[skipPrefix(tokens)]));
}

function hasCommandSubstitutionExecutable(rawCommand) {
  return /(?:^|[;&|\r\n])\s*(?:(?:[A-Za-z_][A-Za-z0-9_]*=\S+|env|command|sudo)\s+)*(?:["']?\$\(|`)/.test(rawCommand);
}

function hasFlag(args, name) {
  return args.some(item => item === name || item === `${name}=true` || item === `${name}=1`);
}

function hasOption(args, name) {
  return args.some(item => item === name || item.startsWith(`${name}=`));
}

function optionValues(args, names) {
  const wanted = new Set(names);
  const values = [];
  for (let index = 0; index < args.length; index++) {
    const token = args[index];
    if (wanted.has(token)) {
      values.push(args[index + 1] || '');
      index++;
      continue;
    }
    for (const name of wanted) {
      if (token.startsWith(`${name}=`)) values.push(token.slice(name.length + 1));
    }
  }
  return values;
}

function stagedGitSha(args) {
  const values = optionValues(args, ['--meta', '-m'])
    .filter(value => value.startsWith('githubCommitSha='))
    .map(value => value.slice('githubCommitSha='.length));
  return values.length === 1 ? values[0] : '';
}

function validateStagedInvocation(args, cwd, expectedSha, platform = process.platform) {
  let gitRoot;
  try {
    gitRoot = findGitRoot(cwd);
    if (!gitRoot || !sameDirectoryIdentity(cwd, gitRoot, platform)) {
      return { ok: false, reason: 'strict staged production은 현재 clean Git 저장소 루트에서 직접 실행해야 합니다.' };
    }
  } catch {
    return { ok: false, reason: 'strict staged production의 Git 저장소 루트를 확인하지 못했습니다.' };
  }

  const deployIndexes = args.reduce((indexes, token, index) => token === 'deploy' ? [...indexes, index] : indexes, []);
  if (deployIndexes.length > 1 || (deployIndexes.length === 1 && deployIndexes[0] !== 0)) {
    return { ok: false, reason: 'deploy는 선택적 첫 번째 subcommand로만 정확히 한 번 사용할 수 있으며 source path로 사용할 수 없습니다.' };
  }
  if (args.filter(token => token === '--prod').length !== 1 || args.filter(token => token === '--skip-domain').length !== 1) {
    return { ok: false, reason: 'staged production에는 --prod와 --skip-domain을 각각 정확히 한 번 넣어야 합니다.' };
  }
  if (args.filter(token => token === '--yes').length > 1) {
    return { ok: false, reason: '--yes는 선택적으로 한 번만 사용할 수 있습니다.' };
  }
  const allowedFlags = new Set(['--prod', '--skip-domain', '--yes']);
  const allowedOptions = new Set(['--meta', '-m']);
  for (let index = 0; index < args.length; index++) {
    const token = args[index];
    if (token === 'deploy' && index === 0) continue;
    if (allowedFlags.has(token)) continue;
    if (allowedOptions.has(token)) {
      if (!args[index + 1]) return { ok: false, reason: `${token} 값이 없어 staged 명령을 안전하게 확인할 수 없습니다.` };
      index++;
      continue;
    }
    if ([...allowedOptions].some(option => token.startsWith(`${option}=`))) continue;
    return { ok: false, reason: `strict staged production에서 허용하지 않는 인자 형식입니다: ${token.startsWith('-') ? token.split('=')[0] : 'source path'}` };
  }
  const metadata = optionValues(args, ['--meta', '-m']);
  const expectedMetadata = [`githubCommitSha=${expectedSha}`, 'githubDeployment=1'].sort();
  if (metadata.length !== 2 || metadata.slice().sort().join('\n') !== expectedMetadata.join('\n') || stagedGitSha(args) !== expectedSha) {
    return { ok: false, reason: `staged production에는 --meta githubDeployment=1과 --meta githubCommitSha=${expectedSha}를 각각 정확히 한 번 넣어야 합니다.` };
  }
  return { ok: true };
}

function isExplicitReadOnlyVercelInvocation(invocation) {
  if (!invocation) return false;
  const args = invocation.args.map(value => String(value).toLowerCase());
  if (!args.length || targetsProduction(args)) return false;
  if (args.length === 1 && ['--help', '-h', '--version', '-v', 'version'].includes(args[0])) return true;
  const command = args[0];
  if (command === 'help') return true;
  if (['whoami', 'list', 'ls', 'inspect', 'logs', 'open'].includes(command)) return true;
  const allowedActions = {
    alias: new Set(['ls', 'list']),
    certs: new Set(['ls', 'list']),
    dns: new Set(['ls', 'list']),
    domains: new Set(['ls', 'list', 'inspect']),
    env: new Set(['ls', 'list']),
    flags: new Set(['ls', 'list', 'inspect']),
    git: new Set(['ls', 'list']),
    integrations: new Set(['ls', 'list', 'inspect', 'get']),
    'integration-resource': new Set(['ls', 'list', 'inspect', 'get']),
    project: new Set(['ls', 'list', 'inspect']),
    promote: new Set(['status']),
    rollback: new Set(['status']),
    target: new Set(['ls', 'list']),
    targets: new Set(['ls', 'list']),
    teams: new Set(['ls', 'list']),
    telemetry: new Set(['status']),
    webhooks: new Set(['ls', 'list', 'get']),
    'deploy-hooks': new Set(['ls', 'list', 'get']),
    routes: new Set(['ls', 'list', 'inspect', 'get', 'status']),
    redirects: new Set(['ls', 'list', 'inspect', 'get', 'status']),
    firewall: new Set(['ls', 'list', 'inspect', 'get', 'status']),
  };
  return Boolean(allowedActions[command]?.has(args[1] || ''));
}

function isLiteralDirectVercelCommand(rawCommand, parsed) {
  if (parsed.unterminatedQuote || parsed.segments.length !== 1) return false;
  if (/[;&|<>`$\\\r\n]/.test(rawCommand)) return false;
  const tokens = parsed.segments[0];
  // Production writes use only the canonical shell token `vercel`. On native
  // Windows the shell resolves that token to vercel.cmd; accepting a literal
  // vc/vercel.cmd path here could make the version probe inspect another file.
  return String(tokens[0] || '') === 'vercel';
}

function isWindowsPowerShellContext(options = {}) {
  return options.shellTool === 'PowerShell' || (options.platform || process.platform) === 'win32';
}

function parsePinnedPowerShellVercelCommand(rawCommand, expectedExecutable) {
  const expected = String(expectedExecutable || '').trim();
  if (!expected) return { ok: false, reason: 'Windows strict 훅에 고정된 vercel.cmd 절대 경로가 없습니다.' };
  const match = /^& '((?:[^'\r\n]|'')+)'(?: ([^\r\n]+))?$/.exec(String(rawCommand || ''));
  if (!match) {
    return { ok: false, reason: "PowerShell Vercel 명령은 & '<고정된 절대 vercel.cmd>' <인자> 단일 literal 형식이어야 합니다." };
  }
  const executable = match[1].replaceAll("''", "'");
  // The command must copy the exact spelling reported by hook status. NTFS can
  // enable case-sensitive directories, so case-folding here could select a
  // different file even though ordinary Windows paths are case-insensitive.
  const expectedNormalized = path.win32.normalize(expected);
  const actualNormalized = path.win32.normalize(executable);
  if (actualNormalized !== expectedNormalized) {
    return { ok: false, reason: 'PowerShell Vercel 실행 파일이 훅 설치 때 고정한 절대 vercel.cmd 경로와 다릅니다.' };
  }
  const rawArgs = match[2] || '';
  const args = rawArgs ? rawArgs.split(' ') : [];
  if (args.some(token => !token || !/^[A-Za-z0-9_:/.=+-]+$/.test(token))) {
    return { ok: false, reason: 'PowerShell Vercel 인자는 변수, 따옴표, wildcard, 셸 연산자 없는 literal 토큰이어야 합니다.' };
  }
  return { ok: true, executable: expected, args };
}

function targetsProduction(args) {
  if (hasFlag(args, '--prod')) return true;
  return args.some((item, index) => item === '--target' && args[index + 1] === 'production')
    || args.some(item => item === '--target=production');
}

function deploymentTarget(args, commandIndex) {
  const optionsWithValue = new Set(['--scope', '--token', '--timeout', '--cwd', '--local-config', '--global-config']);
  for (let index = commandIndex + 1; index < args.length; index++) {
    const token = args[index];
    if (optionsWithValue.has(token)) { index++; continue; }
    if (token.startsWith('-')) continue;
    return token;
  }
  return '';
}

function shellDirectoryChange(tokens, currentCwd) {
  const index = skipPrefix(tokens);
  const executable = basename(tokens[index]);
  if (executable === 'popd') return { ok: false, reason: 'popd 이후 작업 폴더를 결정할 수 없습니다.' };
  if (!['cd', 'chdir', 'pushd', 'set-location', 'sl'].includes(executable)) return null;
  let targetIndex = index + 1;
  if (['/d', '-path', '-literalpath'].includes(String(tokens[targetIndex] || '').toLowerCase())) targetIndex++;
  if (tokens[targetIndex] === '--') targetIndex++;
  const target = tokens[targetIndex];
  if (!target) return { ok: true, cwd: os.homedir() };
  if (target === '-' || /\$|%[^%]+%/.test(target)) {
    return { ok: false, reason: '셸 디렉터리 변경 경로를 결정할 수 없습니다.' };
  }
  return { ok: true, cwd: path.resolve(currentCwd, target) };
}

function optionValue(args, name) {
  for (let index = 0; index < args.length; index++) {
    if (args[index] === name) return args[index + 1] || '';
    if (args[index].startsWith(`${name}=`)) return args[index].slice(name.length + 1);
  }
  return '';
}

function vercelWorkingDirectory(args, currentCwd) {
  const explicit = optionValue(args, '--cwd');
  if (args.some(item => item === '--cwd' || item.startsWith('--cwd='))) {
    if (!explicit || /\$|%[^%]+%/.test(explicit)) return { ok: false, reason: 'Vercel --cwd 경로를 결정할 수 없습니다.' };
    return { ok: true, cwd: path.resolve(currentCwd, explicit) };
  }

  if (!targetsProduction(args)) return { ok: true, cwd: currentCwd };

  // `vercel [path] --prod` and `vercel deploy [path] --prod` both deploy the
  // named directory. Detect an existing path-like positional argument so the
  // receipt is checked against that project rather than the caller's project.
  const optionsWithValue = new Set([
    '--scope', '--token', '--target', '--local-config', '--global-config',
    '--name', '--meta', '--build-env', '--env', '--regions', '--archive',
  ]);
  for (let index = 0; index < args.length; index++) {
    const token = args[index];
    if (optionsWithValue.has(token)) { index++; continue; }
    if (token.startsWith('-') || ['deploy'].includes(token)) continue;
    const candidate = path.resolve(currentCwd, token);
    if (token === '.' || token === '..' || /[\\/]/.test(token) || fs.existsSync(candidate)) {
      return { ok: true, cwd: candidate };
    }
  }
  return { ok: true, cwd: currentCwd };
}

function runtimeScriptCommand(tokens, currentCwd) {
  const index = skipPrefix(tokens);
  const executable = basename(tokens[index]).replace(/\.(?:cmd|exe)$/, '');
  let scriptToken = '';

  if (['.', 'source'].includes(executable)) {
    scriptToken = tokens[index + 1] || '';
  } else if (['sh', 'bash', 'zsh', 'dash'].includes(executable)) {
    for (let itemIndex = index + 1; itemIndex < tokens.length; itemIndex++) {
      const token = tokens[itemIndex];
      if (['-c', '--command'].includes(token)) return null;
      if (token === '--') { scriptToken = tokens[itemIndex + 1] || ''; break; }
      if (token.startsWith('-')) continue;
      scriptToken = token;
      break;
    }
  } else if (['node', 'nodejs', 'deno', 'python', 'python3', 'ruby', 'perl', 'php'].includes(executable)) {
    for (let itemIndex = index + 1; itemIndex < tokens.length; itemIndex++) {
      const token = tokens[itemIndex];
      if (['-e', '--eval', '-p', '--print'].includes(token)) {
        return { command: tokens[itemIndex + 1] || '', cwd: currentCwd, inline: true };
      }
      if (token === '--') { scriptToken = tokens[itemIndex + 1] || ''; break; }
      if (token.startsWith('-')) continue;
      scriptToken = token;
      break;
    }
  } else if (['powershell', 'pwsh'].includes(executable)) {
    const fileIndex = tokens.findIndex((token, itemIndex) => itemIndex > index && ['-file', '-f'].includes(token.toLowerCase()));
    if (fileIndex >= 0) scriptToken = tokens[fileIndex + 1] || '';
  } else if (/^(?:\.\.?[\\/]|[A-Za-z]:[\\/])/.test(tokens[index] || '')) {
    scriptToken = tokens[index];
  }

  if (!scriptToken) return null;
  const hinted = PRODUCTION_SCRIPT_HINT_RE.test(scriptToken);
  if (/\$|%[^%]+%/.test(scriptToken)) {
    return hinted ? { unresolved: true, script: scriptToken, reason: '동적 스크립트 경로를 결정할 수 없습니다.' } : null;
  }
  const file = path.resolve(currentCwd, scriptToken);
  let stat;
  try { stat = fs.statSync(file); }
  catch {
    return hinted ? { unresolved: true, script: scriptToken, reason: `스크립트 ${scriptToken}을 읽지 못했습니다.` } : null;
  }
  if (!stat.isFile() || stat.size > 1024 * 1024) {
    return hinted ? { unresolved: true, script: scriptToken, reason: `스크립트 ${scriptToken}을 안전하게 분석할 수 없습니다.` } : null;
  }
  try { return { command: fs.readFileSync(file, 'utf8'), cwd: currentCwd, script: scriptToken }; }
  catch { return hinted ? { unresolved: true, script: scriptToken, reason: `스크립트 ${scriptToken}을 읽지 못했습니다.` } : null; }
}

function packageOrTaskLauncher(tokens) {
  const index = skipPrefix(tokens);
  const executable = basename(tokens[index]).replace(/\.(?:cmd|exe)$/, '');
  if (['npm', 'npx', 'pnpm', 'yarn', 'bun', 'bunx', 'corepack'].includes(executable)) {
    return `${executable} package manager or executable`;
  }
  if (['make', 'gmake', 'just', 'task', 'turbo', 'nx', 'lage', 'moon', 'rush', 'lerna'].includes(executable)) {
    return `${executable} task runner`;
  }
  return '';
}

function runtimeOrScriptLauncher(tokens) {
  const envIndex = tokens.findIndex(token => basename(token).replace(/\.(?:cmd|exe)$/, '') === 'env');
  if (envIndex >= 0 && tokens.slice(envIndex + 1).some(token => token === '-S' || token.startsWith('-S') || token === '--split-string' || token.startsWith('--split-string='))) {
    return 'env split-string process launcher';
  }
  const index = skipPrefix(tokens);
  const rawExecutable = String(tokens[index] || '');
  const executable = basename(rawExecutable).replace(/\.(?:cmd|exe)$/, '');
  if (['.', 'source', 'sh', 'bash', 'zsh', 'dash', 'fish', 'cmd', 'powershell', 'pwsh'].includes(executable)) {
    return `${executable} shell or script`;
  }
  if ([
    'node', 'nodejs', 'deno', 'bun', 'python', 'python2', 'python3', 'ruby', 'perl', 'php',
    'java', 'jshell', 'dotnet', 'go', 'cargo', 'rust-script', 'tsx', 'ts-node', 'uv', 'pipx',
    'awk', 'gawk', 'mawk', 'nawk', 'lua', 'luajit', 'r', 'rscript', 'tclsh', 'wish',
    'groovy', 'scala', 'kotlin', 'swift', 'elixir', 'erl', 'escript',
  ].includes(executable)) {
    return `${executable} runtime`;
  }
  if ([
    'xargs', 'busybox', 'toybox', 'time', 'nice', 'nohup', 'timeout', 'stdbuf', 'setsid',
    'chrt', 'ionice', 'watch', 'parallel', 'script', 'rlwrap', 'winpty', 'wsl', 'ssh', 'mosh',
    'docker', 'podman', 'nerdctl', 'kubectl', 'osascript', 'expect', 'find', 'vim', 'nvim', 'emacs',
    'wmic', 'schtasks', 'mshta', 'rundll32', 'regsvr32', 'cscript', 'wscript',
    'exec', 'runuser', 'su', 'doas',
  ].includes(executable)) {
    return `${executable} process launcher`;
  }
  if (/^(?:\.\.?[\\/]|[A-Za-z]:[\\/]|[\\/])/.test(rawExecutable)) {
    return 'path-based executable';
  }
  return '';
}

function packageScriptCommand(tokens, currentCwd) {
  const index = skipPrefix(tokens);
  const executable = basename(tokens[index]).replace(/\.(?:cmd|exe)$/, '');
  if (!['npm', 'pnpm', 'yarn', 'bun'].includes(executable)) return null;
  const cwdOptions = executable === 'npm'
    ? ['--prefix']
    : executable === 'pnpm'
      ? ['--dir', '--prefix', '-C']
      : executable === 'yarn'
        ? ['--cwd']
        : ['--cwd'];
  let scriptCwd = currentCwd;
  for (let itemIndex = index + 1; itemIndex < tokens.length; itemIndex++) {
    const token = tokens[itemIndex];
    const exact = cwdOptions.find(option => token === option);
    const equal = cwdOptions.find(option => token.startsWith(`${option}=`));
    if (!exact && !equal) continue;
    const value = exact ? tokens[itemIndex + 1] : token.slice(equal.length + 1);
    if (!value || /\$|%[^%]+%/.test(value)) {
      return { unresolved: true, script: tokens.find(item => /deploy|prod|promote|rollback|release/i.test(item)) || 'deploy', reason: 'package manager 작업 폴더를 결정할 수 없습니다.' };
    }
    scriptCwd = path.resolve(currentCwd, value);
    if (exact) itemIndex++;
  }
  let scriptIndex = -1;
  const runIndex = tokens.findIndex((token, itemIndex) => itemIndex > index && ['run', 'run-script'].includes(token));
  if (runIndex >= 0) scriptIndex = runIndex + 1;
  else if (executable === 'yarn') {
    let itemIndex = index + 1;
    while (itemIndex < tokens.length) {
      const token = tokens[itemIndex];
      const exact = cwdOptions.includes(token);
      if (exact) { itemIndex += 2; continue; }
      if (cwdOptions.some(option => token.startsWith(`${option}=`)) || token.startsWith('-')) { itemIndex++; continue; }
      scriptIndex = itemIndex;
      break;
    }
  }
  if (scriptIndex < 0 || !tokens[scriptIndex]) return null;
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(path.join(scriptCwd, 'package.json'), 'utf8')); }
  catch { return { unresolved: true, script: tokens[scriptIndex], reason: `package.json을 ${scriptCwd}에서 읽지 못했습니다.` }; }
  const script = manifest?.scripts?.[tokens[scriptIndex]];
  if (typeof script !== 'string' || !script.trim()) return null;
  const separator = tokens.indexOf('--', scriptIndex + 1);
  const extra = separator >= 0 ? tokens.slice(separator + 1) : [];
  return { command: `${script}${extra.length ? ` ${extra.join(' ')}` : ''}`, script: tokens[scriptIndex], cwd: scriptCwd };
}

function evaluateVercelCommand(command, cwd, options = {}) {
  const rawCommand = String(command || '');
  if (!options._pinnedPowerShellCanonical && isWindowsPowerShellContext(options)) {
    const exact = parsePinnedPowerShellVercelCommand(rawCommand, options.vercelExecutable);
    if (exact.ok) {
      const canonical = ['vercel', ...exact.args].join(' ');
      return evaluateVercelCommand(canonical, cwd, {
        ...options,
        _pinnedPowerShellCanonical: true,
        shellTool: 'PinnedWindowsPowerShell',
      });
    }
    const generic = evaluateVercelCommand(rawCommand, cwd, {
      ...options,
      _pinnedPowerShellCanonical: true,
      shellTool: 'PinnedWindowsPolicyProbe',
    });
    if (generic.relevant) {
      return { relevant: true, allowed: false, reason: exact.reason };
    }
    return generic;
  }
  // These shell features can construct or rewrite an executable after the hook
  // has inspected the source text. The strict hook deliberately accepts a
  // smaller command language instead of claiming it can prove every shell AST.
  if (/\$\(|\$'|`|\beval\b/i.test(rawCommand)) {
    return { relevant: true, allowed: false, reason: '명령 치환, PowerShell backtick, eval 실행은 실제 하위 프로그램을 증명할 수 없어 strict 훅에서 차단했습니다.' };
  }
  if (/\^/.test(rawCommand)) {
    return { relevant: true, allowed: false, reason: 'Windows cmd caret escape는 실행 파일이나 인자를 다시 조합할 수 있어 strict 훅에서 차단했습니다.' };
  }
  if (/&/.test(rawCommand)) {
    return { relevant: true, allowed: false, reason: 'PowerShell call operator 또는 셸 compound ampersand는 간접 실행을 만들 수 있어 strict 훅에서 차단했습니다.' };
  }
  if (/%[^%\r\n]+%|![A-Za-z_][A-Za-z0-9_]*!/.test(rawCommand)
    || /(?:^|[;|\r\n]\s*)(?:call|for)\b/i.test(rawCommand)) {
    return { relevant: true, allowed: false, reason: 'Windows cmd 변수 확장, call, for 동적 실행은 실제 하위 프로그램을 증명할 수 없어 strict 훅에서 차단했습니다.' };
  }
  const powerShellDynamic = /(?:^|[\s;(])(?:iex|saps|icm|new-object)\b/i.test(rawCommand)
    || /\b(?:invoke-(?:expression|command|script|cimmethod|wmiMethod)|start-(?:process|job|threadjob)|set-alias|new-alias)\b/i.test(rawCommand)
    || /\bforeach-object\b[^\r\n|;]*\b-process\b/i.test(rawCommand)
    || /\[[^\]\r\n]{1,200}\]\s*::/.test(rawCommand)
    || /\.(?:invoke|start)\s*\(/i.test(rawCommand)
    || /(?:['"][^'"\r\n]*['"])\s*\+\s*(?:['"($]|\[[^\]]+\])/i.test(rawCommand)
    || /\s-join\s/i.test(rawCommand);
  if (powerShellDynamic) {
    return { relevant: true, allowed: false, reason: 'PowerShell 동적 실행 또는 문자열 조합은 실제 하위 프로그램을 증명할 수 없어 strict 훅에서 차단했습니다.' };
  }
  const parsed = tokenizeShell(rawCommand);
  if (parsed.unterminatedQuote && /vercel/i.test(command)) {
    return { relevant: true, allowed: false, reason: 'Vercel 명령의 따옴표를 해석할 수 없어 안전하게 차단했습니다.' };
  }
  // Shell substitution and eval can hide the executable from the token parser.
  // Fail closed when such a construct can hide a Vercel state change. Only a
  // directly parsed explicit read-only invocation can avoid that conservative block.
  const concealedExecution = /\$\(|`|\beval\b/i.test(rawCommand);
  const dynamicExecution = concealedExecution
    || /\$(?:\{|[A-Za-z_])|%[A-Za-z_][A-Za-z0-9_]*%/.test(rawCommand)
    || /\b(?:sh|bash|zsh|dash|cmd|powershell|pwsh)(?:\.exe)?\b[^\r\n;&|]*(?:-c|\/c|-command)\b/i.test(rawCommand);
  const namesVercel = /(?:^|[\\/\s"'`($;&|])(?:vercel|vc)(?:\.exe|\.cmd)?(?:@[^\s"'`);&|]+)?(?=$|[\s"'`);&|])/i.test(rawCommand);
  const referencesVercel = namesVercel || /\b(?:vercel|vc)(?:\.exe|\.cmd)?\b/i.test(rawCommand);
  const parsedCommandText = parsed.segments.map(segment => segment.join(' ')).join(' ; ');
  const productionChange = PRODUCTION_MUTATOR_RE.test(rawCommand) || PRODUCTION_MUTATOR_RE.test(parsedCommandText);
  const administrativeChange = VERCEL_ADMIN_MUTATOR_RE.test(rawCommand) || VERCEL_ADMIN_MUTATOR_RE.test(parsedCommandText);
  const stateChange = productionChange || administrativeChange;
  const singleInvocation = parsed.segments.length === 1 ? unwrapVercel(parsed.segments[0]) : null;
  const singleReadOnly = isExplicitReadOnlyVercelInvocation(singleInvocation);
  if (stateChange && !singleReadOnly && Number(options._wrapperDepth || 0) > 0) {
    return { relevant: true, allowed: false, reason: 'package script, 셸·런타임 스크립트, 중첩 명령을 통한 프로덕션 조작은 허용하지 않습니다.' };
  }
  if (stateChange && !singleReadOnly && !isLiteralDirectVercelCommand(rawCommand, parsed)) {
    return { relevant: true, allowed: false, reason: 'Vercel 상태 변경은 셸 래퍼·복합 명령 없이 게이트가 허용한 단일 literal vercel 명령으로만 실행할 수 있습니다.' };
  }
  if (dynamicExecution && (stateChange || (referencesVercel && !singleReadOnly))) {
    return { relevant: true, allowed: false, reason: '동적 실행이 포함된 Vercel 상태 변경은 실제 명령을 결정할 수 없어 차단했습니다.' };
  }
  if (concealedExecution && referencesVercel && stateChange) {
    return { relevant: true, allowed: false, reason: '명령 치환 또는 eval 안의 Vercel 상태 변경은 안전하게 검증할 수 없어 차단했습니다.' };
  }
  const assignedVariables = assignedVercelVariables(parsed.segments);
  if (/\beval\b/i.test(rawCommand) || hasCommandSubstitutionExecutable(rawCommand)) {
    return { relevant: true, allowed: false, reason: 'eval 또는 command-substitution 실행 파일은 실제 프로그램을 결정할 수 없어 strict 훅에서 차단했습니다.' };
  }
  if (hasDynamicExecutable(parsed.segments)) {
    const detail = assignedVariables.size ? 'Vercel 실행 파일을 변수로 간접 호출했습니다.' : '실행 파일 변수를 결정할 수 없습니다.';
    return { relevant: true, allowed: false, reason: `${detail} 동적 Vercel 명령은 안전하게 차단했습니다.` };
  }
  let sawRelevant = false;
  let lastGate = null;
  let effectiveCwd = path.resolve(cwd || process.cwd());
  let uncertainCwd = '';
  for (const segment of parsed.segments) {
    const directoryChange = shellDirectoryChange(segment, effectiveCwd);
    if (directoryChange) {
      if (directoryChange.ok) effectiveCwd = directoryChange.cwd;
      else uncertainCwd = directoryChange.reason;
      continue;
    }
    const runtimeLauncher = runtimeOrScriptLauncher(segment);
    if (runtimeLauncher) {
      return { relevant: true, allowed: false, reason: `${runtimeLauncher}를 통한 간접 실행은 실제 하위 프로그램을 증명할 수 없어 strict 훅에서 차단했습니다. 필요한 도구를 literal 직접 명령으로 실행하세요.` };
    }
    const launcher = packageOrTaskLauncher(segment);
    if (launcher) {
      return { relevant: true, allowed: false, reason: `${launcher}를 통한 간접 실행은 Vercel 상태 변경을 숨길 수 있어 strict 훅에서 차단했습니다. 필요한 도구를 literal 직접 명령으로 실행하세요.` };
    }
    const packageScript = packageScriptCommand(segment, effectiveCwd);
    if (packageScript?.unresolved && /deploy|prod|promote|rollback|redeploy|release|vercel|alias/i.test(packageScript.script)) {
      return { relevant: true, allowed: false, reason: packageScript.reason || `package.json에서 ${packageScript.script} 스크립트를 확인할 수 없어 안전하게 차단했습니다.` };
    }
    if (packageScript?.command) {
      const depth = Number(options._scriptDepth || 0);
      if (depth >= 5) return { relevant: true, allowed: false, reason: '중첩된 package script를 끝까지 확인할 수 없어 안전하게 차단했습니다.' };
      const scriptResult = evaluateVercelCommand(packageScript.command, packageScript.cwd || effectiveCwd, { ...options, _scriptDepth: depth + 1, _wrapperDepth: Number(options._wrapperDepth || 0) + 1 });
      if (scriptResult.relevant && !scriptResult.allowed) return scriptResult;
      if (scriptResult.relevant) { sawRelevant = true; lastGate = scriptResult.gate || lastGate; continue; }
    }
    const nested = nestedShellCommand(segment);
    if (nested) {
      return { relevant: true, allowed: false, reason: 'sh/bash/cmd/PowerShell command-string 중첩 실행은 실제 프로그램을 보장할 수 없어 strict 훅에서 차단했습니다.' };
    }
    const runtimeScript = runtimeScriptCommand(segment, effectiveCwd);
    if (runtimeScript?.unresolved) {
      return { relevant: true, allowed: false, reason: runtimeScript.reason || '프로덕션 관련 스크립트를 안전하게 분석할 수 없어 차단했습니다.' };
    }
    if (runtimeScript?.command) {
      const depth = Number(options._scriptDepth || 0);
      if (depth >= 5) return { relevant: true, allowed: false, reason: '중첩된 실행 스크립트를 끝까지 확인할 수 없어 안전하게 차단했습니다.' };
      const scriptResult = evaluateVercelCommand(runtimeScript.command, runtimeScript.cwd || effectiveCwd, { ...options, _scriptDepth: depth + 1, _wrapperDepth: Number(options._wrapperDepth || 0) + 1 });
      if (scriptResult.relevant && !scriptResult.allowed) return scriptResult;
      if (scriptResult.relevant) { sawRelevant = true; lastGate = scriptResult.gate || lastGate; continue; }
    }
    const invocation = unwrapVercel(segment);
    if (!invocation) continue;
    sawRelevant = true;
    const args = invocation.args;
    if (uncertainCwd) return { relevant: true, allowed: false, reason: `${uncertainCwd} Vercel 프로덕션 조작을 안전하게 차단했습니다.` };
    const workingDirectory = vercelWorkingDirectory(args, effectiveCwd);
    if (!workingDirectory.ok) return { relevant: true, allowed: false, reason: workingDirectory.reason };
    const invocationCwd = workingDirectory.cwd;
    if (args.includes('api')) {
      return { relevant: true, allowed: false, reason: 'vercel api는 임의의 쓰기 API를 호출할 수 있어 strict 훅에서 차단했습니다.' };
    }
    if (args.includes('redeploy')) {
      return { relevant: true, allowed: false, reason: 'vercel redeploy는 새 배포를 만들어 기존 영수증과 같은 아티팩트임을 보장할 수 없어 차단했습니다.' };
    }
    if (args.includes('rolling-release')) {
      return { relevant: true, allowed: false, reason: 'vercel rolling-release는 프로덕션 트래픽을 바꾸므로 strict 훅에서 차단했습니다.' };
    }
    const aliasIndex = args.indexOf('alias');
    if (aliasIndex >= 0) {
      const aliasAction = deploymentTarget(args, aliasIndex).toLowerCase();
      if (aliasAction && !['ls', 'list'].includes(aliasAction)) {
        return { relevant: true, allowed: false, reason: 'Vercel alias 변경은 strict promote 게이트를 우회할 수 있어 차단했습니다.' };
      }
    }
    const promoteIndex = args.indexOf('promote');
    if (promoteIndex >= 0) {
      const target = deploymentTarget(args, promoteIndex);
      if (!target) return { relevant: true, allowed: false, reason: 'vercel promote 대상 URL 또는 ID가 없습니다.' };
      if (target.toLowerCase() === 'status') continue;
      if (promoteIndex !== 0 || args.length !== 2) {
        return { relevant: true, allowed: false, reason: 'strict promote는 vercel promote <literal URL 또는 ID> 단일 형식만 허용합니다.' };
      }
      const cliVersion = verifyVercelCliVersion({ cwd: invocationCwd }, options);
      if (!cliVersion.ok) return { relevant: true, allowed: false, reason: cliVersion.reason, gate: cliVersion };
      const gate = verifyGate({ cwd: invocationCwd, deployment: target, url: /^https?:\/\//i.test(target) ? target : '' }, options);
      if (!gate.ok) return { relevant: true, allowed: false, reason: gate.reason, gate };
      lastGate = gate;
      continue;
    }
    const rollbackIndex = args.indexOf('rollback');
    if (rollbackIndex >= 0) {
      const target = deploymentTarget(args, rollbackIndex);
      if (target.toLowerCase() === 'status') continue;
      return { relevant: true, allowed: false, reason: 'vercel rollback은 프로덕션 트래픽을 바꾸므로 strict 훅에서 자동 실행을 차단했습니다. 복구 절차만 제시하세요.' };
    }
    if (targetsProduction(args) && !hasFlag(args, '--skip-domain')) {
      return { relevant: true, allowed: false, reason: '프로덕션 배포는 먼저 vercel --prod --skip-domain으로 격리해야 합니다.' };
    }
    if (targetsProduction(args) && hasFlag(args, '--skip-domain')) {
      const cliVersion = verifyVercelCliVersion({ cwd: invocationCwd }, options);
      if (!cliVersion.ok) return { relevant: true, allowed: false, reason: cliVersion.reason, gate: cliVersion };
      const gate = verifyCodeGate({ cwd: invocationCwd }, options);
      if (!gate.ok) return { relevant: true, allowed: false, reason: gate.reason, gate };
      const staged = validateStagedInvocation(args, invocationCwd, gate.project.gitSha, options.platform || process.platform);
      if (!staged.ok) return { relevant: true, allowed: false, reason: staged.reason, gate };
      lastGate = gate;
      continue;
    }
    if (isExplicitReadOnlyVercelInvocation(invocation)) continue;
    return {
      relevant: true,
      allowed: false,
      reason: 'strict 훅은 검증된 staged deploy, 영수증과 일치하는 promote, 명시적 read-only Vercel 명령만 허용합니다.',
    };
  }
  if (!sawRelevant && namesVercel && stateChange) {
    return { relevant: true, allowed: false, reason: 'Vercel 상태 변경 명령 형식을 안전하게 해석할 수 없어 차단했습니다.' };
  }
  return { relevant: sawRelevant, allowed: true, reason: sawRelevant ? '현재 Git과 strict 영수증이 일치합니다.' : '', gate: lastGate };
}

module.exports = {
  EXIT,
  RECEIPT_KIND,
  RECEIPT_TTL_MS,
  GATE_SCHEMA,
  SUPPORTED_VERCEL_CLI_VERSION,
  HOOK_MANIFEST_SCHEMA,
  RUNTIME_DIGEST,
  REQUIRED_BY_PHASE,
  stableStringify,
  sha256,
  atomicWrite,
  resolveHome,
  findGitRoot,
  validateWindowsVercelExecutable,
  validateWindowsPowerShellExecutable,
  loadPinnedWindowsVercelExecutable,
  runVercelCli,
  verifyVercelCliVersion,
  projectIdentity,
  normalizeDeploymentUrl,
  createReceipt,
  storeReceipt,
  invalidateReceipt,
  verifyCodeGate,
  verifyGate,
  tokenizeShell,
  parsePinnedPowerShellVercelCommand,
  evaluateVercelCommand,
};

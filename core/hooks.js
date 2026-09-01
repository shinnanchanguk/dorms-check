import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import TOML from '@iarna/toml';
import runtime from './strict-runtime.cjs';

const MANAGED_TAG = 'dorms-check-security-only';
const CODEX_START = `# >>> ${MANAGED_TAG} >>>`;
const CODEX_END = `# <<< ${MANAGED_TAG} <<<`;
const ALL_AGENTS = Object.freeze(['codex', 'claude', 'gemini', 'antigravity']);
const ANTIGRAVITY_HOOK_NAME = 'dorms-check-security-gate';

function homeDir(options = {}) {
  return runtime.resolveHome(options);
}

function sha256Buffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function atomicWrite(file, text, mode = 0o600) {
  runtime.atomicWrite(file, text, mode);
}

function readText(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch { return ''; }
}

function configError(file, message) {
  const error = new Error(`${file} 설정 파일을 안전하게 읽지 못했습니다: ${message}`);
  error.exitCode = runtime.EXIT.USAGE_CONFIG;
  return error;
}

function configFileState(file) {
  try {
    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink()) throw configError(file, 'symlink 설정 파일은 자동 교체하지 않습니다. 실제 파일을 직접 확인하세요.');
    if (!stat.isFile()) throw configError(file, 'regular file이 아닙니다.');
    return { exists: true, stat };
  } catch (error) {
    if (error?.code === 'ENOENT') return { exists: false, stat: null };
    if (error?.exitCode) throw error;
    throw configError(file, error.message);
  }
}

function readConfigText(file) {
  const state = configFileState(file);
  if (!state.exists) return '';
  try { return fs.readFileSync(file, 'utf8'); }
  catch (error) { throw configError(file, error.message); }
}

function statusConfigText(file) {
  try { return { text: readConfigText(file), error: '', present: fs.existsSync(file) }; }
  catch (error) { return { text: '', error: error.message, present: true }; }
}

function readJson(file) {
  if (!fs.existsSync(file)) return {};
  try {
    const value = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('root must be an object');
    return value;
  } catch (error) {
    const wrapped = new Error(`${file} JSON을 읽지 못했습니다: ${error.message}`);
    wrapped.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw wrapped;
  }
}

function validateCodexToml(text, file) {
  if (!text.trim()) return {};
  try { return TOML.parse(text); }
  catch (error) {
    const wrapped = new Error(`${file} TOML을 읽지 못했습니다: ${error.message}`);
    wrapped.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw wrapped;
  }
}

function configEnvironment(options = {}) {
  if (options.environment) return options.environment;
  // An explicit fixture home must never inherit a real custom config root.
  if (options.homeDir) return {};
  return process.env;
}

function validatedConfigOverride(environment, name) {
  const value = String(environment?.[name] || '').trim();
  if (!value) return '';
  if (value.includes('\0') || !path.isAbsolute(value)) {
    const error = new Error(`${name}은 절대 경로여야 합니다: ${value || '(empty)'}`);
    error.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw error;
  }
  return path.normalize(value);
}

function agentConfigLocation(agent, base, environment) {
  if (agent === 'codex') {
    const override = validatedConfigOverride(environment, 'CODEX_HOME');
    const configRoot = override || path.join(base, '.codex');
    return { file: path.join(configRoot, 'config.toml'), configRoot, configRootSource: override ? 'CODEX_HOME' : 'home-default' };
  }
  if (agent === 'claude') {
    const override = validatedConfigOverride(environment, 'CLAUDE_CONFIG_DIR');
    const configRoot = override || path.join(base, '.claude');
    return { file: path.join(configRoot, 'settings.json'), configRoot, configRootSource: override ? 'CLAUDE_CONFIG_DIR' : 'home-default' };
  }
  if (agent === 'antigravity') {
    // Antigravity CLI(agy)는 settings.json이 아니라 별도 hooks.json(이름 → 이벤트 맵)을 읽는다.
    // 공식 문서: 전역 ~/.gemini/antigravity-cli/hooks.json, 작업 공간 .agents/hooks.json.
    const configRoot = path.join(base, '.gemini', 'antigravity-cli');
    return { file: path.join(configRoot, 'hooks.json'), configRoot, configRootSource: 'home-default' };
  }
  const override = validatedConfigOverride(environment, 'GEMINI_CLI_HOME');
  const configRoot = override ? path.join(override, '.gemini') : path.join(base, '.gemini');
  return { file: path.join(configRoot, 'settings.json'), configRoot, configRootSource: override ? 'GEMINI_CLI_HOME' : 'home-default' };
}

function guardFiles(base) {
  const dir = path.join(base, '.dorms-check', 'hooks');
  return {
    dir,
    guard: path.join(dir, 'vercel-guard.cjs'),
    runtime: path.join(dir, 'strict-runtime.cjs'),
    proxy: path.join(dir, 'vercel-proxy.cjs'),
    proxyCmd: path.join(dir, 'vercel.cmd'),
    manifest: path.join(dir, 'manifest.json'),
  };
}

function assertManagedGuardTargetsSafe(base) {
  const files = guardFiles(base);
  for (const directory of [path.join(base, '.dorms-check'), files.dir]) {
    try {
      const stat = fs.lstatSync(directory);
      if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('regular directory가 아닙니다.');
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      const wrapped = new Error(`${directory} 관리 훅 디렉터리를 안전하게 사용할 수 없습니다: ${error.message}`);
      wrapped.exitCode = runtime.EXIT.USAGE_CONFIG;
      throw wrapped;
    }
  }
  for (const file of [files.guard, files.runtime, files.proxy, files.proxyCmd, files.manifest]) {
    try {
      const stat = fs.lstatSync(file);
      if (stat.isSymbolicLink() || !stat.isFile()) throw new Error('regular non-symlink file이 아닙니다.');
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      const wrapped = new Error(`${file} 관리 훅 파일을 안전하게 교체할 수 없습니다: ${error.message}`);
      wrapped.exitCode = runtime.EXIT.USAGE_CONFIG;
      throw wrapped;
    }
  }
}

function sourceFiles() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return {
    guard: path.resolve(here, '..', 'hooks', 'vercel-guard.cjs'),
    proxy: path.resolve(here, '..', 'hooks', 'vercel-proxy.cjs'),
    runtime: path.resolve(here, 'strict-runtime.cjs'),
  };
}

function installGuardFiles(base, nodeExecutable, windowsVercelExecutable = null) {
  const destination = guardFiles(base);
  const source = sourceFiles();
  const guard = fs.readFileSync(source.guard);
  const proxy = fs.readFileSync(source.proxy);
  const strictRuntime = fs.readFileSync(source.runtime);
  atomicWrite(destination.guard, guard, 0o700);
  atomicWrite(destination.runtime, strictRuntime, 0o600);
  let installedWindowsVercelExecutable = null;
  let proxyCmd = null;
  if (windowsVercelExecutable) {
    const node = assertHookPathSafe(nodeExecutable, 'Node 실행 파일');
    const proxyPath = assertHookPathSafe(destination.proxy, 'Windows Vercel proxy');
    proxyCmd = Buffer.from(`@echo off\r\n"${node}" "${proxyPath}" %*\r\n`);
    atomicWrite(destination.proxy, proxy, 0o700);
    atomicWrite(destination.proxyCmd, proxyCmd, 0o700);
    installedWindowsVercelExecutable = {
      path: destination.proxyCmd,
      sha256: sha256Buffer(proxyCmd),
      version: windowsVercelExecutable.version,
      backingPath: windowsVercelExecutable.path,
      backingSha256: windowsVercelExecutable.sha256,
      powerShellPath: windowsVercelExecutable.powerShellPath,
      powerShellSha256: windowsVercelExecutable.powerShellSha256,
      discoveredBy: windowsVercelExecutable.discoveredBy,
    };
  } else {
    for (const file of [destination.proxy, destination.proxyCmd]) {
      try { fs.unlinkSync(file); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  }
  const manifest = {
    schemaVersion: runtime.HOOK_MANIFEST_SCHEMA,
    tag: MANAGED_TAG,
    nodeExecutable,
    windowsVercelExecutable: installedWindowsVercelExecutable,
    files: {
      'vercel-guard.cjs': sha256Buffer(guard),
      'strict-runtime.cjs': sha256Buffer(strictRuntime),
      ...(installedWindowsVercelExecutable ? {
        'vercel-proxy.cjs': sha256Buffer(proxy),
        'vercel.cmd': sha256Buffer(proxyCmd),
      } : {}),
    },
  };
  atomicWrite(destination.manifest, JSON.stringify(manifest, null, 2) + '\n');
  return destination;
}

function snapshotGuardFiles(base) {
  const files = guardFiles(base);
  return Object.values(files)
    .filter(file => file !== files.dir)
    .map(file => {
      if (!fs.existsSync(file)) return { file, existed: false, bytes: null, mode: 0o600 };
      const stat = fs.statSync(file);
      return { file, existed: true, bytes: fs.readFileSync(file), mode: stat.mode & 0o777 };
    });
}

function restoreGuardFiles(snapshot) {
  for (const item of snapshot) {
    if (item.existed) atomicWrite(item.file, item.bytes, item.mode);
    else {
      try { fs.unlinkSync(item.file); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  }
}

function quoteShellPath(value) {
  return `"${String(value)}"`;
}

function quotePowerShellPath(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function assertHookPathSafe(value, label) {
  const text = String(value || '');
  if (!path.isAbsolute(text) || /[\0\r\n"`$%!&|<>^]/.test(text)) {
    const error = new Error(`${label} 경로에 공통 Bash/PowerShell/cmd 훅 명령으로 안전하게 인용할 수 없는 문자가 있습니다: ${text || '(empty)'}`);
    error.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw error;
  }
  return text;
}

function validateExecutableFile(candidate) {
  if (!candidate || String(candidate).includes('\0') || !path.isAbsolute(candidate)) {
    throw new Error('절대 실행 파일 경로가 아닙니다.');
  }
  const resolved = fs.realpathSync(candidate);
  if (!fs.statSync(resolved).isFile()) throw new Error('regular file이 아닙니다.');
  fs.accessSync(resolved, fs.constants.X_OK);
  return assertHookPathSafe(resolved, 'Node 실행 파일');
}

function resolveNodeExecutable(options = {}) {
  const candidate = String(options.nodeExecutable || process.execPath || '').trim();
  if (!candidate || candidate.includes('\0') || !path.isAbsolute(candidate)) {
    const error = new Error('훅에 사용할 Node 실행 파일의 절대 경로를 확인하지 못했습니다.');
    error.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw error;
  }
  let resolved;
  try {
    resolved = validateExecutableFile(candidate);
    const version = String(execFileSync(resolved, ['--version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 5000,
      env: { ...process.env, PATH: '' },
    })).trim();
    if (!/^v\d+\.\d+\.\d+(?:[-+].*)?$/.test(version)) throw new Error(`Node 버전 출력을 확인하지 못했습니다: ${version || '(empty)'}`);
  } catch (error) {
    const wrapped = new Error(`훅에 사용할 Node 실행 파일을 실행 가능 상태로 확인하지 못했습니다: ${candidate} (${error.message})`);
    wrapped.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw wrapped;
  }
  return resolved;
}

function resolveWindowsPowerShellExecutable(options = {}) {
  const environment = options.environment || process.env;
  const candidates = [];
  if (options.powerShellExecutable) candidates.push(String(options.powerShellExecutable));
  const systemRoot = String(environment.SystemRoot || environment.SYSTEMROOT || '').trim();
  if (systemRoot) candidates.push(path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'));
  let lastError = null;
  for (const candidate of candidates) {
    try {
      const validated = runtime.validateWindowsPowerShellExecutable(candidate);
      if (path.win32.basename(validated.path).toLowerCase() !== 'powershell.exe') {
        throw new Error('Codex CMD 호환 훅 런처에는 Windows PowerShell 5.1 powershell.exe가 필요합니다.');
      }
      return validated;
    }
    catch (error) { lastError = error; }
  }
  const error = new Error(`Windows PowerShell 절대 실행 파일을 확인하지 못했습니다${lastError ? `: ${lastError.message}` : '.'}`);
  error.exitCode = runtime.EXIT.USAGE_CONFIG;
  throw error;
}

function resolveWindowsVercelExecutable(options = {}) {
  const platform = options.platform || process.platform;
  if (platform !== 'win32') return null;
  const runner = options.execFileSync || execFileSync;
  const environment = options.environment || process.env;
  const powerShell = resolveWindowsPowerShellExecutable(options);
  let candidate = String(options.vercelExecutable || '').trim();
  let discoveredBy = 'explicit-install-option';
  if (!candidate) {
    const excluded = String(options.managedProxyPath || '').trim();
    const pathFilter = excluded
      ? ` | Where-Object { $_.Path -ine ${quotePowerShellPath(excluded)} }`
      : '';
    const script = [
      `$matches = @(Get-Command vercel -All -CommandType Application -ErrorAction Stop | Where-Object { $_.Name -ieq 'vercel.cmd' }${pathFilter})`,
      "if ($matches.Count -lt 1) { throw 'vercel.cmd not found' }",
      '[Console]::Out.Write($matches[0].Path)',
    ].join('; ');
    try {
      candidate = String(runner(powerShell.path, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], {
        cwd: options.cwd || process.cwd(),
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: environment,
        timeout: 60000,
      })).trim();
    } catch (error) {
      const wrapped = new Error(`Get-Command vercel로 Windows vercel.cmd 절대 경로를 확인하지 못했습니다: ${error.message}`);
      wrapped.exitCode = runtime.EXIT.USAGE_CONFIG;
      throw wrapped;
    }
    discoveredBy = 'PowerShell Get-Command vercel -All -CommandType Application (Name=vercel.cmd)';
  }
  let executable;
  try { executable = runtime.validateWindowsVercelExecutable(candidate); }
  catch (error) {
    const wrapped = new Error(error.message);
    wrapped.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw wrapped;
  }
  if (options.managedProxyPath
    && path.win32.normalize(executable.path).toLowerCase() === path.win32.normalize(options.managedProxyPath).toLowerCase()) {
    const error = new Error('Windows backing Vercel CLI로 dorms-check 관리 proxy 자체를 고정할 수 없습니다. npm 전역 vercel.cmd를 확인하세요.');
    error.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw error;
  }
  const version = runtime.verifyVercelCliVersion({ cwd: options.cwd || process.cwd() }, {
    ...options,
    platform,
    vercelExecutable: executable.path,
    vercelExecutableSha256: executable.sha256,
    powerShellExecutable: powerShell.path,
    powerShellExecutableSha256: powerShell.sha256,
    env: environment,
  });
  if (!version.ok) {
    const error = new Error(version.reason);
    error.exitCode = version.exitCode || runtime.EXIT.USAGE_CONFIG;
    throw error;
  }
  return {
    path: executable.path,
    sha256: executable.sha256,
    version: version.version,
    powerShellPath: powerShell.path,
    powerShellSha256: powerShell.sha256,
    discoveredBy,
  };
}

function hookCommand(guardPath, nodeExecutable = resolveNodeExecutable(), platform = process.platform) {
  const node = assertHookPathSafe(nodeExecutable, 'Node 실행 파일');
  const guard = assertHookPathSafe(guardPath, 'guard');
  return platform === 'win32'
    ? `& ${quotePowerShellPath(node)} ${quotePowerShellPath(guard)}`
    : `${quoteShellPath(node)} ${quoteShellPath(guard)}`;
}

function codexWindowsHookCommand(guardPath, nodeExecutable, powerShellExecutable = 'powershell.exe') {
  const node = assertHookPathSafe(nodeExecutable, 'Node 실행 파일');
  const guard = assertHookPathSafe(guardPath, 'guard');
  const launcher = String(powerShellExecutable || 'powershell.exe');
  if (!/^(?:powershell\.exe|(?:[A-Za-z]:\\|\/)[^\s\0\r\n"'`$%!&|<>^]*powershell\.exe)$/i.test(launcher)) {
    const error = new Error(`Codex Windows 훅은 공백·셸 메타문자가 없는 절대 powershell.exe 경로가 필요합니다: ${launcher}`);
    error.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw error;
  }
  const script = `& ${quotePowerShellPath(node)} ${quotePowerShellPath(guard)}`;
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return `${launcher} -NoLogo -NoProfile -NonInteractive -EncodedCommand ${encoded}`;
}

function hookCommands(guardPath, nodeExecutable, windowsPowerShellExecutable = '') {
  return {
    posix: hookCommand(guardPath, nodeExecutable, 'posix'),
    windowsPowerShell: hookCommand(guardPath, nodeExecutable, 'win32'),
    codexWindows: codexWindowsHookCommand(guardPath, nodeExecutable, windowsPowerShellExecutable || 'powershell.exe'),
    windowsPowerShellExecutable: windowsPowerShellExecutable || 'powershell.exe',
    nodeExecutable,
    guardPath,
  };
}

function tomlString(value) {
  return JSON.stringify(String(value));
}

function removeCodexBlock(text) {
  const start = text.indexOf(CODEX_START);
  if (start < 0) return text;
  const endStart = text.indexOf(CODEX_END, start);
  if (endStart < 0) {
    const error = new Error('Codex 설정의 dorms-check 관리 블록 끝 표식이 없습니다. 자동 덮어쓰기를 중단합니다.');
    error.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw error;
  }
  let end = endStart + CODEX_END.length;
  if (text[end] === '\r') end++;
  if (text[end] === '\n') end++;
  return text.slice(0, start) + text.slice(end);
}

function codexBlock(commands) {
  return `${CODEX_START}\n[[hooks.PreToolUse]]\nmatcher = "^Bash$"\n\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = ${tomlString(commands.posix)}\ncommand_windows = ${tomlString(commands.codexWindows)}\ntimeout = 120\nstatusMessage = "Checking Vercel security gate"\n${CODEX_END}\n`;
}

function installCodexConfig(text, commands) {
  const clean = removeCodexBlock(text).replace(/\s+$/, '');
  return `${clean}${clean ? '\n\n' : ''}${codexBlock(commands)}`;
}

function isManagedHandler(handler) {
  return (typeof handler?.command === 'string'
      && /[\\/]\.dorms-check[\\/]hooks[\\/]vercel-guard\.cjs/.test(handler.command))
    || (Array.isArray(handler?.args)
      && handler.args.some(value => typeof value === 'string' && /[\\/]\.dorms-check[\\/]hooks[\\/]vercel-guard\.cjs/.test(value)));
}

function managedJsonHandlerPresent(handler) {
  return isManagedHandler(handler)
    || handler?.name === 'dorms-check security gate'
    || handler?.description === 'Blocks unscanned Vercel production promotion.';
}

function managedTextPresent(text) {
  const value = String(text || '');
  return value.includes(CODEX_START)
    || /[\\/]\.dorms-check[\\/]hooks[\\/]vercel-guard\.cjs/.test(value)
    || value.includes('dorms-check security gate')
    || value.includes('Blocks unscanned Vercel production promotion.');
}

function removeJsonHooks(settings) {
  if (!settings.hooks || typeof settings.hooks !== 'object' || Array.isArray(settings.hooks)) return settings;
  for (const event of Object.keys(settings.hooks)) {
    if (!Array.isArray(settings.hooks[event])) continue;
    settings.hooks[event] = settings.hooks[event]
      .map(group => ({ ...group, hooks: Array.isArray(group.hooks) ? group.hooks.filter(handler => !managedJsonHandlerPresent(handler)) : group.hooks }))
      .filter(group => !Array.isArray(group.hooks) || group.hooks.length > 0);
    if (settings.hooks[event].length === 0) delete settings.hooks[event];
  }
  if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  return settings;
}

function installJsonHook(settings, agent, commands, platform) {
  const event = agent === 'claude' ? 'PreToolUse' : 'BeforeTool';
  const matcher = agent === 'claude' ? 'Bash|PowerShell' : '^run_shell_command$';
  removeJsonHooks(settings);
  settings.hooks ||= {};
  settings.hooks[event] ||= [];
  settings.hooks[event].push({
    matcher,
    hooks: [agent === 'claude'
      ? {
          type: 'command',
          command: commands.nodeExecutable,
          args: [commands.guardPath],
          timeout: 120,
        }
      : {
          type: 'command',
          command: platform === 'win32' ? commands.windowsPowerShell : commands.posix,
          name: 'dorms-check security gate',
          timeout: 120000,
          description: 'Blocks unscanned Vercel production promotion.',
        }],
  });
  return settings;
}

function isManagedAntigravityEntry(name, entry) {
  if (name === ANTIGRAVITY_HOOK_NAME) return true;
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  return Object.values(entry).some(groups => Array.isArray(groups)
    && groups.some(group => Array.isArray(group?.hooks) && group.hooks.some(managedJsonHandlerPresent)));
}

function removeAntigravityHooks(settings) {
  for (const [name, entry] of Object.entries(settings)) {
    if (isManagedAntigravityEntry(name, entry)) delete settings[name];
  }
  return settings;
}

/**
 * Antigravity CLI hooks.json 형식. 이벤트 PreToolUse, 셸 도구 이름은 run_command.
 * Windows는 어느 셸이 훅을 실행하는지 공식 문서가 밝히지 않으므로 cmd·PowerShell 양쪽에서
 * 같은 뜻인 고정 PowerShell EncodedCommand 런처(Codex Windows와 동일)를 기록한다.
 */
function installAntigravityHook(settings, commands, platform) {
  removeAntigravityHooks(settings);
  settings[ANTIGRAVITY_HOOK_NAME] = {
    enabled: true,
    PreToolUse: [{
      matcher: 'run_command',
      hooks: [{
        type: 'command',
        command: platform === 'win32' ? commands.codexWindows : commands.posix,
        timeout: 120,
      }],
    }],
  };
  return settings;
}

function serializeJson(value) {
  return JSON.stringify(value, null, 2) + '\n';
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function backupConfig(file, base, stamp) {
  if (!fs.existsSync(file)) return null;
  const relative = path.relative(base, file);
  const rel = relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)
    ? path.join('outside', sha256Buffer(Buffer.from(file)).slice(0, 16), path.basename(file))
    : relative;
  const backup = path.join(base, '.dorms-check', 'backups', stamp, rel);
  fs.mkdirSync(path.dirname(backup), { recursive: true, mode: 0o700 });
  fs.copyFileSync(file, backup);
  return backup;
}

function parseAgents(agents) {
  const selected = typeof agents === 'string' ? agents.split(',') : (agents || ALL_AGENTS);
  const normalized = [...new Set(selected.map(item => String(item).trim().toLowerCase()).filter(Boolean))];
  const unknown = normalized.filter(item => !ALL_AGENTS.includes(item));
  if (!normalized.length || unknown.length) {
    const error = new Error(`--agents는 ${ALL_AGENTS.join(',')} 중에서 골라야 합니다${unknown.length ? `: ${unknown.join(',')}` : ''}.`);
    error.exitCode = runtime.EXIT.USAGE_CONFIG;
    throw error;
  }
  return normalized;
}

function writeIfChanged(file, before, after, base, stamp) {
  if (before === after) return { changed: false, backup: null };
  const backup = backupConfig(file, base, stamp);
  atomicWrite(file, after);
  return { changed: true, backup };
}

function prepareConfigChanges(selected, base, commands, action, environment, platform) {
  return selected.map(agent => {
    const { file } = agentConfigLocation(agent, base, environment);
    const before = readConfigText(file);
    const existed = configFileState(file).exists;
    let after = before;
    if (agent === 'codex') {
      validateCodexToml(before, file);
      after = action === 'install'
        ? installCodexConfig(before, commands)
        : removeCodexBlock(before).replace(/\n{3,}/g, '\n\n');
      validateCodexToml(after, file);
    } else if (agent === 'antigravity') {
      if (action === 'install' || before) {
        // agy가 아직 실행된 적 없으면 ~/.gemini/antigravity-cli 가 없을 수 있다. 훅 파일만 두는 디렉터리라 만들어도 안전하다.
        if (action === 'install') fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
        const settings = readJson(file);
        if (action === 'install') installAntigravityHook(settings, commands, platform);
        else removeAntigravityHooks(settings);
        after = serializeJson(settings);
      }
    } else if (action === 'install' || before) {
      const settings = readJson(file);
      if (action === 'install') installJsonHook(settings, agent, commands, platform);
      else removeJsonHooks(settings);
      after = serializeJson(settings);
    }
    return { agent, file, existed, before, after };
  });
}

function applyConfigChanges(prepared, base, stamp) {
  const changes = {};
  const touched = [];
  try {
    for (const item of prepared) {
      changes[item.agent] = { file: item.file, ...writeIfChanged(item.file, item.before, item.after, base, stamp) };
      if (changes[item.agent].changed) touched.push(item);
    }
    return changes;
  } catch (error) {
    for (const item of touched.reverse()) {
      try {
        if (item.existed) atomicWrite(item.file, item.before);
        else fs.unlinkSync(item.file);
      } catch { /* Preserve the original error. */ }
    }
    error.partial = touched.length > 0;
    throw error;
  }
}

function isWslHost() {
  if (process.platform !== 'linux') return false;
  return Boolean(process.env.WSL_DISTRO_NAME || /microsoft/i.test(`${os.release()} ${readText('/proc/version')}`));
}

function validateManagedCommand(command, expectedGuardPath, expectedNodeExecutable, platform = 'posix') {
  const text = String(command || '');
  const match = platform === 'win32'
    ? /^& '((?:[^'\r\n]|'')+)' '((?:[^'\r\n]|'')+)'$/.exec(text)
    : /^"([^"\r\n]+)" "([^"\r\n]+)"$/.exec(text);
  if (!match) return { valid: false, error: '관리 훅 명령 형식이 정확하지 않습니다.' };
  const recordedNode = platform === 'win32' ? match[1].replaceAll("''", "'") : match[1];
  const recordedGuard = platform === 'win32' ? match[2].replaceAll("''", "'") : match[2];
  if (!path.isAbsolute(recordedGuard) || path.normalize(recordedGuard) !== path.normalize(expectedGuardPath)) {
    return { valid: false, error: '관리 훅 guard 경로가 현재 설치 범위와 일치하지 않습니다.' };
  }
  try {
    assertHookPathSafe(recordedNode, '기록된 Node 실행 파일');
    assertHookPathSafe(recordedGuard, '기록된 guard');
    const resolvedNode = validateExecutableFile(recordedNode);
    if (!expectedNodeExecutable || resolvedNode !== expectedNodeExecutable) {
      return { valid: false, nodeExecutable: resolvedNode, error: '관리 훅 Node 경로가 설치 manifest와 일치하지 않습니다.' };
    }
    return { valid: true, nodeExecutable: resolvedNode, command: hookCommand(expectedGuardPath, resolvedNode, platform) };
  } catch (error) {
    return { valid: false, nodeExecutable: recordedNode, error: error.message };
  }
}

function validateCodexWindowsCommand(command, expectedGuardPath, expectedNodeExecutable, expectedPowerShellExecutable = '') {
  const text = String(command || '');
  const match = /^((?:(?:[A-Za-z]:\\|\/)[^\s\0\r\n"'`$%!&|<>^]*powershell\.exe)|powershell\.exe) -NoLogo -NoProfile -NonInteractive -EncodedCommand ([A-Za-z0-9+/]+={0,2})$/i.exec(text);
  if (!match) return { valid: false, error: 'Codex Windows 관리 훅이 CMD 호환 PowerShell EncodedCommand 형식이 아닙니다.' };
  const recordedPowerShell = match[1];
  const expectedPowerShell = expectedPowerShellExecutable || 'powershell.exe';
  const sameLauncher = expectedPowerShell === 'powershell.exe'
    ? recordedPowerShell.toLowerCase() === 'powershell.exe'
    : path.win32.normalize(recordedPowerShell).toLowerCase() === path.win32.normalize(expectedPowerShell).toLowerCase();
  if (!sameLauncher) return { valid: false, error: 'Codex Windows PowerShell 런처가 설치 manifest와 일치하지 않습니다.' };
  let script = '';
  try {
    script = Buffer.from(match[2], 'base64').toString('utf16le');
  } catch {
    return { valid: false, error: 'Codex Windows EncodedCommand를 해석할 수 없습니다.' };
  }
  const decoded = validateManagedCommand(script, expectedGuardPath, expectedNodeExecutable, 'win32');
  if (!decoded.valid) return decoded;
  return {
    ...decoded,
    command: codexWindowsHookCommand(expectedGuardPath, decoded.nodeExecutable, expectedPowerShell),
    powerShellExecutable: recordedPowerShell,
  };
}

function validateManagedExecHandler(handler, expectedGuardPath, expectedNodeExecutable) {
  const recordedNode = String(handler?.command || '');
  const recordedGuard = Array.isArray(handler?.args) && handler.args.length === 1 ? String(handler.args[0] || '') : '';
  if (!recordedNode || !recordedGuard || !path.isAbsolute(recordedGuard) || path.normalize(recordedGuard) !== path.normalize(expectedGuardPath)) {
    return { valid: false, error: 'Claude 관리 훅 exec-form 경로가 현재 설치 범위와 일치하지 않습니다.' };
  }
  try {
    assertHookPathSafe(recordedNode, '기록된 Node 실행 파일');
    assertHookPathSafe(recordedGuard, '기록된 guard');
    const resolvedNode = validateExecutableFile(recordedNode);
    if (!expectedNodeExecutable || resolvedNode !== expectedNodeExecutable) {
      return { valid: false, nodeExecutable: resolvedNode, error: 'Claude 관리 훅 Node 경로가 설치 manifest와 일치하지 않습니다.' };
    }
    return { valid: true, nodeExecutable: resolvedNode, command: recordedNode, args: [recordedGuard] };
  } catch (error) {
    return { valid: false, nodeExecutable: recordedNode, error: error.message };
  }
}

function codexManagedStatus(text, parsed, expectedGuardPath, expectedNodeExecutable, expectedPowerShellExecutable = '') {
  const groups = Array.isArray(parsed?.hooks?.PreToolUse) ? parsed.hooks.PreToolUse : [];
  const managedPresent = managedTextPresent(text)
    || groups.some(group => Array.isArray(group?.hooks) && group.hooks.some(isManagedHandler));
  for (const group of groups) {
    if (group?.matcher !== '^Bash$' || !Array.isArray(group.hooks)) continue;
    for (const handler of group.hooks) {
      if (!isManagedHandler(handler)) continue;
      const posix = validateManagedCommand(handler.command, expectedGuardPath, expectedNodeExecutable, 'posix');
      const windows = validateCodexWindowsCommand(handler.command_windows, expectedGuardPath, expectedNodeExecutable, expectedPowerShellExecutable);
      const installed = posix.valid
        && windows.valid
        && posix.nodeExecutable === windows.nodeExecutable
        && handler.type === 'command'
        && handler.timeout === 120
        && handler.statusMessage === 'Checking Vercel security gate';
      if (installed) return { managedPresent: true, installed: true, ...posix, commandWindows: windows.command };
      return { managedPresent: true, installed: false, ...posix, error: posix.error || windows.error || 'Codex 관리 훅 스키마가 정확하지 않습니다.' };
    }
  }
  return { managedPresent, installed: false, valid: false, error: managedPresent ? 'Codex 관리 훅 스키마가 정확하지 않습니다.' : '' };
}

function jsonManagedStatus(settings, agent, event, matcher, expectedGuardPath, expectedNodeExecutable, platform) {
  const groups = Array.isArray(settings.hooks?.[event]) ? settings.hooks[event] : [];
  const managedPresent = Object.values(settings.hooks || {}).some(eventGroups => (
    Array.isArray(eventGroups)
      && eventGroups.some(group => Array.isArray(group?.hooks) && group.hooks.some(managedJsonHandlerPresent))
  ));
  for (const group of groups) {
    if (group?.matcher !== matcher || !Array.isArray(group.hooks)) continue;
    for (const handler of group.hooks) {
      if (!managedJsonHandlerPresent(handler)) continue;
      const command = agent === 'claude'
        ? validateManagedExecHandler(handler, expectedGuardPath, expectedNodeExecutable)
        : validateManagedCommand(handler.command, expectedGuardPath, expectedNodeExecutable, platform === 'win32' ? 'win32' : 'posix');
      const installed = command.valid
        && handler.type === 'command'
        && (agent === 'claude'
          ? handler.timeout === 120 && handler.async !== true && handler.shell === undefined
          : handler.timeout === 120000
            && handler.name === 'dorms-check security gate'
            && handler.description === 'Blocks unscanned Vercel production promotion.');
      if (installed) return { managedPresent: true, installed: true, ...command };
      return { managedPresent: true, installed: false, ...command, error: command.error || `${agent} 관리 훅 스키마가 정확하지 않습니다.` };
    }
  }
  return { managedPresent, installed: false, valid: false, error: managedPresent ? `${agent} 관리 훅 스키마가 정확하지 않습니다.` : '' };
}

function antigravityManagedStatus(settings, expectedGuardPath, expectedNodeExecutable, platform, expectedPowerShellExecutable = '') {
  const managedPresent = Object.entries(settings).some(([name, entry]) => isManagedAntigravityEntry(name, entry));
  for (const [name, entry] of Object.entries(settings)) {
    if (!isManagedAntigravityEntry(name, entry)) continue;
    const groups = Array.isArray(entry?.PreToolUse) ? entry.PreToolUse : [];
    for (const group of groups) {
      if (group?.matcher !== 'run_command' || !Array.isArray(group.hooks)) continue;
      for (const handler of group.hooks) {
        if (!managedJsonHandlerPresent(handler)) continue;
        const command = platform === 'win32'
          ? validateCodexWindowsCommand(handler.command, expectedGuardPath, expectedNodeExecutable, expectedPowerShellExecutable)
          : validateManagedCommand(handler.command, expectedGuardPath, expectedNodeExecutable, 'posix');
        const installed = command.valid
          && name === ANTIGRAVITY_HOOK_NAME
          && entry.enabled !== false
          && handler.type === 'command'
          && handler.timeout === 120;
        if (installed) return { managedPresent: true, installed: true, ...command };
        return { managedPresent: true, installed: false, ...command, error: command.error || 'Antigravity 관리 훅 스키마가 정확하지 않습니다.' };
      }
    }
  }
  return { managedPresent, installed: false, valid: false, error: managedPresent ? 'Antigravity 관리 훅 스키마가 정확하지 않습니다.' : '' };
}

function sourceStatus(base, options = {}) {
  const files = guardFiles(base);
  let manifest;
  let manifestError = '';
  try {
    const stat = fs.lstatSync(files.manifest);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 1024 * 1024) throw new Error('manifest가 regular non-symlink 1 MiB 이하 파일이 아닙니다.');
    manifest = JSON.parse(fs.readFileSync(files.manifest, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') manifestError = error.message;
    manifest = null;
  }
  const entries = {};
  const managedFiles = [
    ['vercel-guard.cjs', files.guard],
    ['strict-runtime.cjs', files.runtime],
    ...((manifest?.files?.['vercel-proxy.cjs'] || fs.existsSync(files.proxy)) ? [['vercel-proxy.cjs', files.proxy]] : []),
    ...((manifest?.files?.['vercel.cmd'] || fs.existsSync(files.proxyCmd)) ? [['vercel.cmd', files.proxyCmd]] : []),
  ];
  for (const [name, file] of managedFiles) {
    let present = false;
    let digest = '';
    let error = '';
    try {
      const stat = fs.lstatSync(file);
      present = true;
      if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 10 * 1024 * 1024) throw new Error('regular non-symlink 10 MiB 이하 파일이 아닙니다.');
      digest = sha256Buffer(fs.readFileSync(file));
    } catch (caught) {
      if (caught.code !== 'ENOENT') error = caught.message;
    }
    entries[name] = { present, valid: present && !error && manifest?.files?.[name] === digest, sha256: digest, error };
  }
  let nodeExecutable = '';
  let nodeExecutableError = '';
  try { nodeExecutable = validateExecutableFile(String(manifest?.nodeExecutable || '')); }
  catch (error) { nodeExecutableError = error.message; }
  let windowsVercelExecutable = null;
  let windowsVercelExecutableError = '';
  const record = manifest?.windowsVercelExecutable;
  if (record) {
    try {
      const executable = runtime.validateWindowsVercelExecutable(record.path, record.sha256);
      const backing = runtime.validateWindowsVercelExecutable(record.backingPath, record.backingSha256);
      const powerShell = runtime.validateWindowsPowerShellExecutable(record.powerShellPath, record.powerShellSha256);
      if (record.version !== runtime.SUPPORTED_VERCEL_CLI_VERSION) {
        throw new Error(`고정 Vercel CLI 버전이 ${runtime.SUPPORTED_VERCEL_CLI_VERSION}이 아닙니다.`);
      }
      if ((options.platform || process.platform) === 'win32') {
        const version = runtime.verifyVercelCliVersion({}, {
          platform: 'win32',
          vercelBackingExecutable: backing.path,
          vercelBackingExecutableSha256: backing.sha256,
          vercelExecutableVersion: record.version,
          powerShellExecutable: powerShell.path,
          powerShellExecutableSha256: powerShell.sha256,
        });
        if (!version.ok) throw new Error(version.reason);
      }
      windowsVercelExecutable = {
        path: executable.path,
        sha256: executable.sha256,
        version: record.version,
        backingPath: backing.path,
        backingSha256: backing.sha256,
        powerShellPath: powerShell.path,
        powerShellSha256: powerShell.sha256,
        discoveredBy: record.discoveredBy || '',
      };
    } catch (error) {
      windowsVercelExecutableError = error.message;
    }
  }
  const platform = options.platform || process.platform;
  const windowsRecordRequired = platform === 'win32';
  const windowsRecordValid = !record ? !windowsRecordRequired : Boolean(windowsVercelExecutable) && !windowsVercelExecutableError;
  const manifestValid = manifest?.schemaVersion === runtime.HOOK_MANIFEST_SCHEMA
    && manifest?.tag === MANAGED_TAG
    && Boolean(nodeExecutable)
    && !nodeExecutableError
    && windowsRecordValid;
  return {
    files,
    valid: manifestValid && !manifestError && Object.values(entries).every(entry => entry.valid),
    entries,
    manifestError,
    nodeExecutable,
    nodeExecutableVerified: manifestValid,
    nodeExecutableError,
    windowsVercelExecutable,
    windowsVercelExecutableVerified: Boolean(windowsVercelExecutable) && !windowsVercelExecutableError,
    windowsVercelExecutableError,
  };
}

export function hookStatus(options = {}) {
  const base = homeDir(options);
  const environment = configEnvironment(options);
  const platform = options.platform || process.platform;
  const source = sourceStatus(base, { platform });
  let nodeExecutable = '';
  let nodeExecutableError = '';
  try { nodeExecutable = resolveNodeExecutable(options); }
  catch (error) { nodeExecutableError = error.message; }
  const expectedGuardPath = guardFiles(base).guard;
  let guardPathError = '';
  try { assertHookPathSafe(expectedGuardPath, 'guard'); }
  catch (error) { guardPathError = error.message; }
  const sourceManagedPresent = Object.values(source.entries).some(entry => entry.present);
  const agents = {};
  for (const agent of ALL_AGENTS) {
    let location;
    try { location = agentConfigLocation(agent, base, environment); }
    catch (error) {
      agents[agent] = {
        file: '',
        configRoot: '',
        configRootSource: 'invalid-environment-override',
        managedPresent: sourceManagedPresent,
        installed: false,
        configured: false,
        activation: 'not-configured',
        disabled: false,
        parseError: error.message,
        hostActivationNotObservable: true,
      };
      continue;
    }
    const { file, configRoot, configRootSource } = location;
    if (agent === 'codex') {
      const config = statusConfigText(file);
      const text = config.text;
      let parseError = config.error || guardPathError;
      let parsed = {};
      if (!parseError) {
        try { parsed = validateCodexToml(text, file); } catch (error) { parseError = error.message; }
      }
      const disabled = parsed?.features?.hooks === false
        || parsed?.features?.codex_hooks === false
        || parsed?.allow_managed_hooks_only === true;
      const managed = parseError
        ? { managedPresent: config.present || managedTextPresent(text), installed: false, valid: false, error: parseError }
        : codexManagedStatus(
            text,
            parsed,
            expectedGuardPath,
            source.nodeExecutable,
            platform === 'win32' ? source.windowsVercelExecutable?.powerShellPath || '' : '',
          );
      const configured = managed.installed && managed.valid && source.valid && !disabled;
      agents[agent] = {
        file,
        configRoot,
        configRootSource,
        managedPresent: managed.managedPresent,
        installed: managed.installed,
        configured,
        activation: configured ? 'unknown' : 'not-configured',
        disabled,
        parseError,
        managedNodeExecutable: managed.nodeExecutable || '',
        managedNodeExecutableVerified: Boolean(managed.valid),
        managedCommandError: managed.error || '',
        hostActivationNotObservable: true,
      };
    } else if (agent === 'antigravity') {
      const config = statusConfigText(file);
      const text = config.text;
      let settings = {};
      let parseError = config.error || guardPathError;
      if (!parseError && text) {
        try {
          settings = JSON.parse(text);
          if (!settings || Array.isArray(settings) || typeof settings !== 'object') throw new Error('root must be an object');
        } catch (error) { parseError = `${file} JSON을 읽지 못했습니다: ${error.message}`; }
      }
      const managed = parseError
        ? { managedPresent: config.present || managedTextPresent(text), installed: false, valid: false, error: parseError }
        : antigravityManagedStatus(
            settings,
            expectedGuardPath,
            source.nodeExecutable,
            platform,
            platform === 'win32' ? source.windowsVercelExecutable?.powerShellPath || '' : '',
          );
      const disabled = settings?.[ANTIGRAVITY_HOOK_NAME]?.enabled === false;
      const configured = managed.installed && managed.valid && source.valid && !disabled;
      agents[agent] = {
        file,
        configRoot,
        configRootSource,
        managedPresent: managed.managedPresent,
        installed: managed.installed,
        configured,
        activation: configured ? 'unknown' : 'not-configured',
        disabled,
        parseError,
        managedNodeExecutable: managed.nodeExecutable || '',
        managedNodeExecutableVerified: Boolean(managed.valid),
        managedCommandError: managed.error || '',
        hostActivationNotObservable: true,
      };
    } else {
      const config = statusConfigText(file);
      const text = config.text;
      let settings = {};
      let parseError = config.error || guardPathError;
      if (!parseError && text) {
        try {
          settings = JSON.parse(text);
          if (!settings || Array.isArray(settings) || typeof settings !== 'object') throw new Error('root must be an object');
        } catch (error) { parseError = `${file} JSON을 읽지 못했습니다: ${error.message}`; }
      }
      const event = agent === 'claude' ? 'PreToolUse' : 'BeforeTool';
      const matcher = agent === 'claude' ? 'Bash|PowerShell' : '^run_shell_command$';
      const managed = parseError
        ? { managedPresent: config.present || managedTextPresent(text), installed: false, valid: false, error: parseError }
        : jsonManagedStatus(settings, agent, event, matcher, expectedGuardPath, source.nodeExecutable, platform);
      const geminiDisabledNames = Array.isArray(settings.hooksConfig?.disabled)
        ? settings.hooksConfig.disabled.map(value => String(value).toLowerCase())
        : [];
      const disabled = Boolean(settings.disableAllHooks)
        || (agent === 'gemini' && (
          settings.hooksConfig?.enabled === false
          || geminiDisabledNames.some(name => name === 'dorms-check security gate' || name === MANAGED_TAG)
        ));
      const configured = managed.installed && managed.valid && source.valid && !disabled;
      agents[agent] = {
        file,
        configRoot,
        configRootSource,
        managedPresent: managed.managedPresent,
        installed: managed.installed,
        configured,
        activation: configured ? 'unknown' : 'not-configured',
        disabled,
        parseError,
        managedNodeExecutable: managed.nodeExecutable || '',
        managedNodeExecutableVerified: Boolean(managed.valid),
        managedCommandError: managed.error || '',
        hostActivationNotObservable: true,
      };
    }
  }
  return {
    hostPlatform: platform,
    home: base,
    isWSL: isWslHost(),
    installationScope: 'current-host-only',
    hostScopeWarning: 'Windows와 WSL 등 다른 네이티브 호스트의 CLI는 해당 호스트에서 별도로 설치·확인해야 합니다.',
    timeoutSeconds: 120,
    hostTimeoutMayFailOpen: true,
    nodeExecutable,
    nodeExecutableVerified: Boolean(nodeExecutable) && !nodeExecutableError,
    nodeExecutableError,
    windowsPowerShellSupported: platform === 'win32' && source.windowsVercelExecutableVerified,
    windowsVercelExecutable: source.windowsVercelExecutable?.path || '',
    windowsVercelExecutableSha256: source.windowsVercelExecutable?.sha256 || '',
    windowsVercelVersion: source.windowsVercelExecutable?.version || '',
    windowsVercelBackingExecutable: source.windowsVercelExecutable?.backingPath || '',
    windowsVercelBackingExecutableSha256: source.windowsVercelExecutable?.backingSha256 || '',
    windowsPowerShellExecutable: source.windowsVercelExecutable?.powerShellPath || '',
    windowsPowerShellExecutableSha256: source.windowsVercelExecutable?.powerShellSha256 || '',
    windowsVercelExecutableVerified: source.windowsVercelExecutableVerified,
    windowsVercelExecutableError: source.windowsVercelExecutableError,
    activation: 'unknown',
    ready: false,
    securityOnly: true,
    provider: 'vercel',
    source: {
      valid: source.valid,
      entries: source.entries,
      manifestError: source.manifestError,
      nodeExecutable: source.nodeExecutable,
      nodeExecutableVerified: source.nodeExecutableVerified,
      nodeExecutableError: source.nodeExecutableError,
      windowsVercelExecutable: source.windowsVercelExecutable,
      windowsVercelExecutableVerified: source.windowsVercelExecutableVerified,
      windowsVercelExecutableError: source.windowsVercelExecutableError,
    },
    enforcementBoundary: {
      covers: ['Codex/Claude/Gemini/Antigravity shell-tool Vercel CLI commands'],
      excludes: ['Vercel dashboard actions', 'Git-push automatic production deployments', 'external CI and other users'],
      hostActivationNotObservable: true,
      timeoutSeconds: 120,
      hostTimeoutMayFailOpen: true,
    },
    agents,
  };
}

export function installHooks({
  agents,
  homeDir: requestedHome,
  environment: requestedEnvironment,
  nodeExecutable: requestedNodeExecutable,
  platform: requestedPlatform,
  vercelExecutable: requestedVercelExecutable,
  powerShellExecutable: requestedPowerShellExecutable,
  execFileSync: requestedExecFileSync,
  vercelVersion: requestedVercelVersion,
  cwd: requestedCwd,
} = {}) {
  const selected = parseAgents(agents);
  const base = homeDir({ homeDir: requestedHome });
  const environment = requestedEnvironment || (requestedHome ? {} : process.env);
  const platform = requestedPlatform || process.platform;
  const destination = guardFiles(base);
  const nodeExecutable = resolveNodeExecutable({ nodeExecutable: requestedNodeExecutable });
  const windowsVercelExecutable = resolveWindowsVercelExecutable({
    platform,
    environment,
    vercelExecutable: requestedVercelExecutable,
    powerShellExecutable: requestedPowerShellExecutable,
    execFileSync: requestedExecFileSync,
    vercelVersion: requestedVercelVersion,
    cwd: requestedCwd,
    managedProxyPath: destination.proxyCmd,
  });
  assertHookPathSafe(destination.guard, 'guard');
  assertManagedGuardTargetsSafe(base);
  const commands = hookCommands(destination.guard, nodeExecutable, windowsVercelExecutable?.powerShellPath || '');
  const prepared = prepareConfigChanges(selected, base, commands, 'install', environment, platform);
  const guardSnapshot = snapshotGuardFiles(base);
  try {
    installGuardFiles(base, nodeExecutable, windowsVercelExecutable);
    const stamp = timestamp();
    const changes = applyConfigChanges(prepared, base, stamp);
    return { action: 'install', agents: selected, changes, status: hookStatus({ homeDir: base, environment, platform }) };
  } catch (error) {
    try { restoreGuardFiles(guardSnapshot); }
    catch (restoreError) {
      error.partial = true;
      error.restoreError = restoreError.message;
    }
    throw error;
  }
}

export function uninstallHooks({ agents, homeDir: requestedHome, environment: requestedEnvironment, nodeExecutable: requestedNodeExecutable } = {}) {
  const selected = parseAgents(agents);
  const base = homeDir({ homeDir: requestedHome });
  const environment = requestedEnvironment || (requestedHome ? {} : process.env);
  const stamp = timestamp();
  const nodeExecutable = resolveNodeExecutable({ nodeExecutable: requestedNodeExecutable });
  const prepared = prepareConfigChanges(selected, base, hookCommands(guardFiles(base).guard, nodeExecutable), 'uninstall', environment, process.platform);
  const changes = applyConfigChanges(prepared, base, stamp);
  const remaining = hookStatus({ homeDir: base, environment });
  if (!Object.values(remaining.agents).some(agent => agent.managedPresent)) {
    const files = guardFiles(base);
    for (const file of [files.guard, files.runtime, files.proxy, files.proxyCmd, files.manifest]) {
      try { fs.unlinkSync(file); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    try { fs.rmdirSync(files.dir); } catch { /* Keep a non-empty user directory. */ }
  }
  return { action: 'uninstall', agents: selected, changes, status: hookStatus({ homeDir: base, environment }) };
}

export { ALL_AGENTS, ANTIGRAVITY_HOOK_NAME };

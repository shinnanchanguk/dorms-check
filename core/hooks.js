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
const ALL_AGENTS = Object.freeze(['codex', 'claude', 'gemini']);

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
  for (const file of [files.guard, files.runtime, files.manifest]) {
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
    runtime: path.resolve(here, 'strict-runtime.cjs'),
  };
}

function installGuardFiles(base, nodeExecutable) {
  const destination = guardFiles(base);
  const source = sourceFiles();
  const guard = fs.readFileSync(source.guard);
  const strictRuntime = fs.readFileSync(source.runtime);
  atomicWrite(destination.guard, guard, 0o700);
  atomicWrite(destination.runtime, strictRuntime, 0o600);
  const manifest = {
    schemaVersion: 2,
    tag: MANAGED_TAG,
    nodeExecutable,
    files: {
      'vercel-guard.cjs': sha256Buffer(guard),
      'strict-runtime.cjs': sha256Buffer(strictRuntime),
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

function hookCommand(guardPath, nodeExecutable = resolveNodeExecutable()) {
  return `${quoteShellPath(assertHookPathSafe(nodeExecutable, 'Node 실행 파일'))} ${quoteShellPath(assertHookPathSafe(guardPath, 'guard'))}`;
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

function codexBlock(command) {
  return `${CODEX_START}\n[[hooks.PreToolUse]]\nmatcher = "^Bash$"\n\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = ${tomlString(command)}\ncommand_windows = ${tomlString(command)}\ntimeout = 120\nstatusMessage = "Checking Vercel security gate"\n${CODEX_END}\n`;
}

function installCodexConfig(text, command) {
  const clean = removeCodexBlock(text).replace(/\s+$/, '');
  return `${clean}${clean ? '\n\n' : ''}${codexBlock(command)}`;
}

function isManagedHandler(handler) {
  return typeof handler?.command === 'string'
    && /[\\/]\.dorms-check[\\/]hooks[\\/]vercel-guard\.cjs/.test(handler.command);
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

function installJsonHook(settings, agent, command) {
  const event = agent === 'claude' ? 'PreToolUse' : 'BeforeTool';
  const matcher = agent === 'claude' ? 'Bash|PowerShell' : '^run_shell_command$';
  removeJsonHooks(settings);
  settings.hooks ||= {};
  settings.hooks[event] ||= [];
  settings.hooks[event].push({
    matcher,
    hooks: [{
      type: 'command',
      command,
      ...(agent === 'gemini'
        ? { name: 'dorms-check security gate', timeout: 120000, description: 'Blocks unscanned Vercel production promotion.' }
        : { timeout: 120 }),
    }],
  });
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

function prepareConfigChanges(selected, base, command, action, environment) {
  return selected.map(agent => {
    const { file } = agentConfigLocation(agent, base, environment);
    const before = readConfigText(file);
    const existed = configFileState(file).exists;
    let after = before;
    if (agent === 'codex') {
      validateCodexToml(before, file);
      after = action === 'install'
        ? installCodexConfig(before, command)
        : removeCodexBlock(before).replace(/\n{3,}/g, '\n\n');
      validateCodexToml(after, file);
    } else if (action === 'install' || before) {
      const settings = readJson(file);
      if (action === 'install') installJsonHook(settings, agent, command);
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

function validateManagedCommand(command, expectedGuardPath, expectedNodeExecutable) {
  const match = /^"([^"\r\n]+)" "([^"\r\n]+)"$/.exec(String(command || ''));
  if (!match) return { valid: false, error: '관리 훅 명령 형식이 정확하지 않습니다.' };
  const [, recordedNode, recordedGuard] = match;
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
    return { valid: true, nodeExecutable: resolvedNode, command: hookCommand(expectedGuardPath, resolvedNode) };
  } catch (error) {
    return { valid: false, nodeExecutable: recordedNode, error: error.message };
  }
}

function codexManagedStatus(text, parsed, expectedGuardPath, expectedNodeExecutable) {
  const groups = Array.isArray(parsed?.hooks?.PreToolUse) ? parsed.hooks.PreToolUse : [];
  const managedPresent = managedTextPresent(text)
    || groups.some(group => Array.isArray(group?.hooks) && group.hooks.some(isManagedHandler));
  for (const group of groups) {
    if (group?.matcher !== '^Bash$' || !Array.isArray(group.hooks)) continue;
    for (const handler of group.hooks) {
      if (!isManagedHandler(handler)) continue;
      const command = validateManagedCommand(handler.command, expectedGuardPath, expectedNodeExecutable);
      const installed = command.valid
        && handler.type === 'command'
        && handler.command_windows === handler.command
        && handler.timeout === 120
        && handler.statusMessage === 'Checking Vercel security gate';
      if (installed) return { managedPresent: true, installed: true, ...command };
      return { managedPresent: true, installed: false, ...command, error: command.error || 'Codex 관리 훅 스키마가 정확하지 않습니다.' };
    }
  }
  return { managedPresent, installed: false, valid: false, error: managedPresent ? 'Codex 관리 훅 스키마가 정확하지 않습니다.' : '' };
}

function jsonManagedStatus(settings, agent, event, matcher, expectedGuardPath, expectedNodeExecutable) {
  const groups = Array.isArray(settings.hooks?.[event]) ? settings.hooks[event] : [];
  const managedPresent = Object.values(settings.hooks || {}).some(eventGroups => (
    Array.isArray(eventGroups)
      && eventGroups.some(group => Array.isArray(group?.hooks) && group.hooks.some(managedJsonHandlerPresent))
  ));
  for (const group of groups) {
    if (group?.matcher !== matcher || !Array.isArray(group.hooks)) continue;
    for (const handler of group.hooks) {
      if (!managedJsonHandlerPresent(handler)) continue;
      const command = validateManagedCommand(handler.command, expectedGuardPath, expectedNodeExecutable);
      const installed = command.valid
        && handler.type === 'command'
        && (agent === 'claude'
          ? handler.timeout === 120 && handler.async !== true
          : handler.timeout === 120000
            && handler.name === 'dorms-check security gate'
            && handler.description === 'Blocks unscanned Vercel production promotion.');
      if (installed) return { managedPresent: true, installed: true, ...command };
      return { managedPresent: true, installed: false, ...command, error: command.error || `${agent} 관리 훅 스키마가 정확하지 않습니다.` };
    }
  }
  return { managedPresent, installed: false, valid: false, error: managedPresent ? `${agent} 관리 훅 스키마가 정확하지 않습니다.` : '' };
}

function sourceStatus(base) {
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
  for (const [name, file] of [['vercel-guard.cjs', files.guard], ['strict-runtime.cjs', files.runtime]]) {
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
  const manifestValid = manifest?.schemaVersion === 2 && manifest?.tag === MANAGED_TAG && Boolean(nodeExecutable) && !nodeExecutableError;
  return { files, valid: manifestValid && !manifestError && Object.values(entries).every(entry => entry.valid), entries, manifestError, nodeExecutable, nodeExecutableVerified: manifestValid, nodeExecutableError };
}

export function hookStatus(options = {}) {
  const base = homeDir(options);
  const environment = configEnvironment(options);
  const source = sourceStatus(base);
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
        : codexManagedStatus(text, parsed, expectedGuardPath, source.nodeExecutable);
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
        : jsonManagedStatus(settings, agent, event, matcher, expectedGuardPath, source.nodeExecutable);
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
    hostPlatform: process.platform,
    home: base,
    isWSL: isWslHost(),
    installationScope: 'current-host-only',
    hostScopeWarning: 'Windows와 WSL 등 다른 네이티브 호스트의 CLI는 해당 호스트에서 별도로 설치·확인해야 합니다.',
    timeoutSeconds: 120,
    hostTimeoutMayFailOpen: true,
    nodeExecutable,
    nodeExecutableVerified: Boolean(nodeExecutable) && !nodeExecutableError,
    nodeExecutableError,
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
    },
    enforcementBoundary: {
      covers: ['Codex/Claude/Gemini shell-tool Vercel CLI commands'],
      excludes: ['Vercel dashboard actions', 'Git-push automatic production deployments', 'external CI and other users'],
      hostActivationNotObservable: true,
      timeoutSeconds: 120,
      hostTimeoutMayFailOpen: true,
    },
    agents,
  };
}

export function installHooks({ agents, homeDir: requestedHome, environment: requestedEnvironment, nodeExecutable: requestedNodeExecutable } = {}) {
  const selected = parseAgents(agents);
  const base = homeDir({ homeDir: requestedHome });
  const environment = requestedEnvironment || (requestedHome ? {} : process.env);
  const destination = guardFiles(base);
  const nodeExecutable = resolveNodeExecutable({ nodeExecutable: requestedNodeExecutable });
  assertHookPathSafe(destination.guard, 'guard');
  assertManagedGuardTargetsSafe(base);
  const command = hookCommand(destination.guard, nodeExecutable);
  const prepared = prepareConfigChanges(selected, base, command, 'install', environment);
  const guardSnapshot = snapshotGuardFiles(base);
  try {
    installGuardFiles(base, nodeExecutable);
    const stamp = timestamp();
    const changes = applyConfigChanges(prepared, base, stamp);
    return { action: 'install', agents: selected, changes, status: hookStatus({ homeDir: base, environment }) };
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
  const prepared = prepareConfigChanges(selected, base, hookCommand(guardFiles(base).guard, resolveNodeExecutable({ nodeExecutable: requestedNodeExecutable })), 'uninstall', environment);
  const changes = applyConfigChanges(prepared, base, stamp);
  const remaining = hookStatus({ homeDir: base, environment });
  if (!Object.values(remaining.agents).some(agent => agent.managedPresent)) {
    const files = guardFiles(base);
    for (const file of [files.guard, files.runtime, files.manifest]) {
      try { fs.unlinkSync(file); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    try { fs.rmdirSync(files.dir); } catch { /* Keep a non-empty user directory. */ }
  }
  return { action: 'uninstall', agents: selected, changes, status: hookStatus({ homeDir: base, environment }) };
}

export { ALL_AGENTS };

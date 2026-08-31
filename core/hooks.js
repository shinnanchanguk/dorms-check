import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
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

function agentConfigFile(agent, base) {
  if (agent === 'codex') return path.join(base, '.codex', 'config.toml');
  if (agent === 'claude') return path.join(base, '.claude', 'settings.json');
  return path.join(base, '.gemini', 'settings.json');
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

function sourceFiles() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return {
    guard: path.resolve(here, '..', 'hooks', 'vercel-guard.cjs'),
    runtime: path.resolve(here, 'strict-runtime.cjs'),
  };
}

function installGuardFiles(base) {
  const destination = guardFiles(base);
  const source = sourceFiles();
  const guard = fs.readFileSync(source.guard);
  const strictRuntime = fs.readFileSync(source.runtime);
  atomicWrite(destination.guard, guard, 0o700);
  atomicWrite(destination.runtime, strictRuntime, 0o600);
  const manifest = {
    schemaVersion: 1,
    tag: MANAGED_TAG,
    files: {
      'vercel-guard.cjs': sha256Buffer(guard),
      'strict-runtime.cjs': sha256Buffer(strictRuntime),
    },
  };
  atomicWrite(destination.manifest, JSON.stringify(manifest, null, 2) + '\n');
  return destination;
}

function quoteShellPath(value) {
  return `"${String(value).replaceAll('"', '\\"')}"`;
}

function hookCommand(guardPath) {
  return `node ${quoteShellPath(guardPath)}`;
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
  return `${CODEX_START}\n[[hooks.PreToolUse]]\nmatcher = "^Bash$"\n\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = ${tomlString(command)}\ncommand_windows = ${tomlString(command)}\ntimeout = 10\nstatusMessage = "Checking Vercel security gate"\n${CODEX_END}\n`;
}

function installCodexConfig(text, command) {
  const clean = removeCodexBlock(text).replace(/\s+$/, '');
  return `${clean}${clean ? '\n\n' : ''}${codexBlock(command)}`;
}

function isManagedHandler(handler) {
  return handler?.type === 'command'
    && typeof handler.command === 'string'
    && /[\\/]\.dorms-check[\\/]hooks[\\/]vercel-guard\.cjs(?:"|$)/.test(handler.command);
}

function removeJsonHook(settings, event) {
  if (!settings.hooks || !Array.isArray(settings.hooks[event])) return settings;
  settings.hooks[event] = settings.hooks[event]
    .map(group => ({ ...group, hooks: Array.isArray(group.hooks) ? group.hooks.filter(handler => !isManagedHandler(handler)) : group.hooks }))
    .filter(group => !Array.isArray(group.hooks) || group.hooks.length > 0);
  if (settings.hooks[event].length === 0) delete settings.hooks[event];
  if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  return settings;
}

function installJsonHook(settings, agent, command) {
  const event = agent === 'claude' ? 'PreToolUse' : 'BeforeTool';
  const matcher = agent === 'claude' ? 'Bash' : '^run_shell_command$';
  removeJsonHook(settings, event);
  settings.hooks ||= {};
  settings.hooks[event] ||= [];
  settings.hooks[event].push({
    matcher,
    hooks: [{
      type: 'command',
      command,
      ...(agent === 'gemini'
        ? { name: 'dorms-check security gate', timeout: 10000, description: 'Blocks unscanned Vercel production promotion.' }
        : { timeout: 10 }),
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
  const rel = path.relative(base, file).replace(/^\.\.[\\/]/, 'outside/');
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

function codexInstalled(text, command) {
  return text.includes(codexBlock(command));
}

function jsonInstalled(settings, event, matcher, command) {
  return Boolean(settings.hooks?.[event]?.some(group => group.matcher === matcher && group.hooks?.some(handler => (
    handler?.type === 'command' && handler.command === command
  ))));
}

function sourceStatus(base) {
  const files = guardFiles(base);
  let manifest;
  try { manifest = JSON.parse(readText(files.manifest)); } catch { manifest = null; }
  const entries = {};
  for (const [name, file] of [['vercel-guard.cjs', files.guard], ['strict-runtime.cjs', files.runtime]]) {
    const present = fs.existsSync(file);
    const digest = present ? sha256Buffer(fs.readFileSync(file)) : '';
    entries[name] = { present, valid: present && manifest?.files?.[name] === digest, sha256: digest };
  }
  return { files, valid: Object.values(entries).every(entry => entry.valid), entries };
}

export function hookStatus(options = {}) {
  const base = homeDir(options);
  const source = sourceStatus(base);
  const expectedCommand = hookCommand(guardFiles(base).guard);
  const agents = {};
  for (const agent of ALL_AGENTS) {
    const file = agentConfigFile(agent, base);
    if (agent === 'codex') {
      const text = readText(file);
      const disabled = /\[features\][\s\S]*?^\s*hooks\s*=\s*false\s*$/m.test(text)
        || /^\s*allow_managed_hooks_only\s*=\s*true\s*$/m.test(text);
      const installed = codexInstalled(text, expectedCommand);
      agents[agent] = { file, installed, effective: installed && source.valid && !disabled, disabled, hostActivationNotObservable: true };
    } else {
      let settings = {};
      let parseError = '';
      try { settings = readJson(file); } catch (error) { parseError = error.message; }
      const event = agent === 'claude' ? 'PreToolUse' : 'BeforeTool';
      const matcher = agent === 'claude' ? 'Bash' : '^run_shell_command$';
      const installed = !parseError && jsonInstalled(settings, event, matcher, expectedCommand);
      const disabled = Boolean(settings.disableAllHooks);
      agents[agent] = { file, installed, effective: installed && source.valid && !disabled, disabled, parseError, hostActivationNotObservable: true };
    }
  }
  return {
    home: base,
    securityOnly: true,
    provider: 'vercel',
    source: { valid: source.valid, entries: source.entries },
    enforcementBoundary: {
      covers: ['Codex/Claude/Gemini shell-tool Vercel CLI commands'],
      excludes: ['Vercel dashboard actions', 'Git-push automatic production deployments', 'external CI and other users'],
      hostActivationNotObservable: true,
    },
    agents,
  };
}

export function installHooks({ agents, homeDir: requestedHome } = {}) {
  const selected = parseAgents(agents);
  const base = homeDir({ homeDir: requestedHome });
  const files = installGuardFiles(base);
  const command = hookCommand(files.guard);
  const stamp = timestamp();
  const changes = {};
  for (const agent of selected) {
    const file = agentConfigFile(agent, base);
    if (agent === 'codex') {
      const before = readText(file);
      changes[agent] = { file, ...writeIfChanged(file, before, installCodexConfig(before, command), base, stamp) };
    } else {
      const before = readText(file);
      const settings = readJson(file);
      const after = serializeJson(installJsonHook(settings, agent, command));
      changes[agent] = { file, ...writeIfChanged(file, before, after, base, stamp) };
    }
  }
  return { action: 'install', agents: selected, changes, status: hookStatus({ homeDir: base }) };
}

export function uninstallHooks({ agents, homeDir: requestedHome } = {}) {
  const selected = parseAgents(agents);
  const base = homeDir({ homeDir: requestedHome });
  const stamp = timestamp();
  const changes = {};
  for (const agent of selected) {
    const file = agentConfigFile(agent, base);
    const before = readText(file);
    let after = before;
    if (agent === 'codex') after = removeCodexBlock(before).replace(/\n{3,}/g, '\n\n');
    else if (before) {
      const settings = readJson(file);
      removeJsonHook(settings, agent === 'claude' ? 'PreToolUse' : 'BeforeTool');
      after = serializeJson(settings);
    }
    changes[agent] = { file, ...writeIfChanged(file, before, after, base, stamp) };
  }
  const remaining = hookStatus({ homeDir: base });
  if (!Object.values(remaining.agents).some(agent => agent.installed)) {
    const files = guardFiles(base);
    for (const file of [files.guard, files.runtime, files.manifest]) {
      try { fs.unlinkSync(file); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    try { fs.rmdirSync(files.dir); } catch { /* Keep a non-empty user directory. */ }
  }
  return { action: 'uninstall', agents: selected, changes, status: hookStatus({ homeDir: base }) };
}

export { ALL_AGENTS };

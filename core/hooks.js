// Compatibility cleanup for global hooks installed by dorms-check before 0.3.
// This module only reads configuration or removes managed entries. It never launches commands.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import TOML from '@iarna/toml';

const MANAGED_TAG = 'dorms-check-security-only';
const CODEX_START = '# >>> ' + MANAGED_TAG + ' >>>';
const CODEX_END = '# <<< ' + MANAGED_TAG + ' <<<';
const ALL_AGENTS = Object.freeze(['codex', 'claude', 'gemini', 'antigravity']);
const ANTIGRAVITY_HOOK_NAME = 'dorms-check-security-gate';
const LEGACY_FILES = ['vercel-guard.cjs', 'strict-runtime.cjs', 'vercel-proxy.cjs', 'vercel.cmd', 'manifest.json'];

function failure(message) {
  const error = new Error(message);
  error.exitCode = 2;
  return error;
}

function selectedAgents(value) {
  const names = typeof value === 'string' ? value.split(',') : (value || ALL_AGENTS);
  const selected = [...new Set(names.map(name => String(name).trim().toLowerCase()).filter(Boolean))];
  if (!selected.length || selected.some(name => !ALL_AGENTS.includes(name))) throw failure('--agents는 ' + ALL_AGENTS.join(',') + ' 중에서 고르세요.');
  return selected;
}

function context(options) {
  const base = path.resolve(options.homeDir || os.homedir());
  return { base, environment: options.environment || (options.homeDir ? {} : process.env) };
}

function configLocations(agent, base, environment) {
  const defaults = {
    codex: path.join(base, '.codex', 'config.toml'),
    claude: path.join(base, '.claude', 'settings.json'),
    gemini: path.join(base, '.gemini', 'settings.json'),
    antigravity: path.join(base, '.gemini', 'antigravity-cli', 'hooks.json'),
  };
  const variable = { codex: 'CODEX_HOME', claude: 'CLAUDE_CONFIG_DIR', gemini: 'GEMINI_CLI_HOME' }[agent];
  const custom = variable ? String(environment[variable] || '').trim() : '';
  if (custom && (!path.isAbsolute(custom) || custom.includes('\0'))) throw failure(variable + '에는 절대 경로가 필요합니다.');
  const current = !custom ? defaults[agent] : path.join(custom, ...(agent === 'gemini' ? ['.gemini'] : []), path.basename(defaults[agent]));
  return [...new Set([current, defaults[agent]])];
}

// Refuse symlinked files and parent directories rather than replacing an unknown target.
function assertPlainPath(file) {
  const absolute = path.resolve(file);
  const root = path.parse(absolute).root;
  let current = root;
  for (const part of absolute.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink()) throw failure(current + ': 연결된 경로는 자동으로 바꾸지 않습니다.');
      if (current !== absolute && !stat.isDirectory()) throw failure(current + ': 폴더가 아닙니다.');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function readConfig(file) {
  assertPlainPath(file);
  let stat;
  try { stat = fs.lstatSync(file); }
  catch (error) { if (error.code === 'ENOENT') return { file, exists: false, text: '', mode: 0o600 }; throw error; }
  if (!stat.isFile() || stat.size > 4 * 1024 * 1024) throw failure(file + ': 설정 파일 형식이나 크기를 확인해 주세요.');
  return { file, exists: true, text: fs.readFileSync(file, 'utf8'), mode: stat.mode & 0o777 };
}

function parseConfig(agent, text) {
  if (!text.trim()) return {};
  const value = agent === 'codex' ? TOML.parse(text) : JSON.parse(text);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw failure('설정의 최상위 값은 객체여야 합니다.');
  return value;
}

function decodedCommands(text) {
  const values = [String(text || '')];
  // Earlier native Windows installers recorded a UTF-16LE PowerShell launcher.
  // Decoding is sufficient to locate the old path; no interpreter is needed.
  for (const match of values[0].matchAll(/-(?:EncodedCommand|enc|e)\s+["']?([A-Za-z0-9+/=]{12,})/gi)) {
    if (match[1].length <= 32768) values.push(Buffer.from(match[1], 'base64').toString('utf16le'));
  }
  return values;
}

function managedCommand(value) {
  return decodedCommands(value).some(text => /[\\/]?\.dorms-check[\\/]hooks[\\/]vercel-guard\.cjs(?:["'\s;]|$)/i.test(text));
}

function managedHandler(handler) {
  if (!handler || typeof handler !== 'object') return false;
  return managedCommand(handler.command)
    || managedCommand(handler.command_windows)
    || (Array.isArray(handler.args) && handler.args.some(managedCommand))
    || (handler.name === 'dorms-check security gate' && handler.description === 'Blocks unscanned Vercel production promotion.');
}

function hasReference(value) {
  if (typeof value === 'string') return decodedCommands(value).some(text => text.includes(MANAGED_TAG)
    || text.includes(ANTIGRAVITY_HOOK_NAME)
    || text.includes('dorms-check security gate')
    || /[\\/]?\.dorms-check[\\/]hooks[\\/](?:vercel-guard\.cjs|strict-runtime\.cjs|vercel-proxy\.cjs|vercel\.cmd)/i.test(text));
  if (!value || typeof value !== 'object') return false;
  return Object.values(value).some(hasReference);
}

function removeEventHooks(events) {
  if (!events || typeof events !== 'object' || Array.isArray(events)) return false;
  let changed = false;
  for (const [event, groups] of Object.entries(events)) {
    if (!Array.isArray(groups)) continue;
    const next = [];
    for (const group of groups) {
      if (!Array.isArray(group?.hooks)) { next.push(group); continue; }
      const kept = group.hooks.filter(handler => !managedHandler(handler));
      if (kept.length === group.hooks.length) next.push(group);
      else {
        changed = true;
        if (kept.length) next.push({ ...group, hooks: kept });
      }
    }
    if (!next.length && groups.length && changed) delete events[event];
    else events[event] = next;
  }
  return changed;
}

function removeCodexBlocks(text) {
  let rest = text;
  while (rest.includes(CODEX_START)) {
    const start = rest.indexOf(CODEX_START);
    const endStart = rest.indexOf(CODEX_END, start + CODEX_START.length);
    if (endStart < 0 || rest.indexOf(CODEX_START, start + CODEX_START.length) >= 0 && rest.indexOf(CODEX_START, start + CODEX_START.length) < endStart) {
      throw failure('Codex의 도름스 관리 블록 표식이 맞지 않아 원본을 보존했습니다.');
    }
    const block = parseConfig('codex', rest.slice(start + CODEX_START.length, endStart));
    if (Object.keys(block).some(key => key !== 'hooks')
      || Object.values(block.hooks || {}).some(groups => !Array.isArray(groups)
        || groups.some(group => !Array.isArray(group?.hooks) || group.hooks.some(handler => !managedHandler(handler))))) {
      throw failure('Codex의 도름스 관리 블록 안에 다른 설정이 있어 원본을 보존했습니다.');
    }
    let end = endStart + CODEX_END.length;
    if (rest[end] === '\r') end++;
    if (rest[end] === '\n') end++;
    rest = rest.slice(0, start) + rest.slice(end);
  }
  if (rest.includes(CODEX_END)) throw failure('Codex의 도름스 관리 블록 시작 표식이 없습니다.');
  return rest;
}

function cleanedText(agent, before) {
  const settings = parseConfig(agent, before);
  if (agent === 'codex') {
    const after = removeCodexBlocks(before);
    parseConfig(agent, after);
    return after;
  }
  let changed = false;
  if (agent === 'antigravity') {
    for (const [name, entry] of Object.entries(settings)) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      if (!removeEventHooks(entry)) continue;
      changed = true;
      // A named entry can contain a user's extra hooks. Keep them.
      if (Object.keys(entry).every(key => ['enabled', 'description'].includes(key))) delete settings[name];
    }
  } else {
    changed = removeEventHooks(settings.hooks);
    if (changed && !Object.keys(settings.hooks).length) delete settings.hooks;
  }
  return changed ? JSON.stringify(settings, null, 2) + '\n' : before;
}

function inspectAgent(agent, base, environment) {
  try {
    const locations = configLocations(agent, base, environment).map(file => {
      try {
        const { text, exists } = readConfig(file);
        const parsed = parseConfig(agent, text);
        return { file, exists, managedPresent: hasReference(parsed) || text.includes(CODEX_START), error: '' };
      } catch (error) { return { file, exists: true, managedPresent: true, error: error.message }; }
    });
    return { file: locations[0].file, locations, managedPresent: locations.some(item => item.managedPresent), error: locations.map(item => item.error).filter(Boolean).join(' | ') };
  } catch (error) { return { file: '', locations: [], managedPresent: true, error: error.message }; }
}

export function hookStatus(options = {}) {
  const { base, environment } = context(options);
  const selected = selectedAgents(options.agents);
  const agents = Object.fromEntries(selected.map(agent => [agent, inspectAgent(agent, base, environment)]));
  const errors = Object.values(agents).map(agent => agent.error).filter(Boolean);
  return { ok: errors.length === 0, action: 'status', cleanupOnly: true, home: base, agents, reason: errors.join(' | ') };
}

function atomicWrite(file, text, mode) {
  assertPlainPath(file);
  const temp = file + '.dorms-cleanup-' + crypto.randomUUID();
  try {
    fs.writeFileSync(temp, text, { flag: 'wx', mode });
    fs.renameSync(temp, file);
  } finally {
    try { fs.unlinkSync(temp); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function backupFactory(base) {
  let directory;
  return file => {
    const backupRoot = path.join(base, '.dorms-check', 'backups');
    assertPlainPath(backupRoot);
    fs.mkdirSync(backupRoot, { recursive: true, mode: 0o700 });
    directory ||= fs.mkdtempSync(path.join(backupRoot, 'legacy-hooks-'));
    const digest = crypto.createHash('sha256').update(file).digest('hex').slice(0, 16);
    const target = path.join(directory, digest + '-' + path.basename(file));
    fs.writeFileSync(target, fs.readFileSync(file), { flag: 'wx', mode: 0o600 });
    return target;
  };
}

function cleanupSharedFiles(base, environment, backup) {
  const directory = path.join(base, '.dorms-check', 'hooks');
  const candidates = LEGACY_FILES.map(name => path.join(directory, name)).filter(file => {
    try { fs.lstatSync(file); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  });
  const remaining = Object.values(hookStatus({ homeDir: base, environment }).agents).some(agent => agent.managedPresent || agent.error);
  if (remaining) return { removedFiles: [], retainedFiles: candidates };
  let manifest;
  try { manifest = JSON.parse(readConfig(path.join(directory, 'manifest.json')).text); }
  catch { return { removedFiles: [], retainedFiles: candidates }; }
  if (manifest?.tag !== MANAGED_TAG) return { removedFiles: [], retainedFiles: candidates };

  const removable = [], retainedFiles = [];
  for (const file of candidates) {
    if (path.basename(file) === 'manifest.json') continue;
    try {
      readConfig(file);
      const digest = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
      if (manifest.files?.[path.basename(file)] === digest) removable.push(file);
      else retainedFiles.push(file);
    } catch { retainedFiles.push(file); }
  }
  const manifestFile = path.join(directory, 'manifest.json');
  if (!retainedFiles.length) removable.push(manifestFile);
  else retainedFiles.push(manifestFile);
  const saved = removable.map(file => ({ file, backup: backup(file) }));
  for (const item of saved) { assertPlainPath(item.file); fs.unlinkSync(item.file); }
  try { fs.rmdirSync(directory); } catch (error) { if (!['ENOTEMPTY', 'ENOENT', 'EEXIST'].includes(error.code)) throw error; }
  return { removedFiles: saved, retainedFiles };
}

export function uninstallHooks(options = {}) {
  const { base, environment } = context(options);
  const selected = selectedAgents(options.agents);
  const prepared = [];
  for (const agent of selected) {
    for (const file of configLocations(agent, base, environment)) {
      if (prepared.some(item => item.file === file)) continue;
      const current = readConfig(file);
      const after = cleanedText(agent, current.text);
      if (after !== current.text) prepared.push({ agent, ...current, after });
    }
  }
  const backup = backupFactory(base);
  // Parse every selected file before writing any of them.
  const changes = prepared.map(item => ({ agent: item.agent, file: item.file, backup: backup(item.file), changed: true }));
  const touched = [];
  try {
    for (const item of prepared) {
      if (readConfig(item.file).text !== item.text) throw failure(item.file + ': 정리 중 설정이 바뀌어 중단했습니다.');
      atomicWrite(item.file, item.after, item.mode);
      touched.push(item);
    }
  } catch (error) {
    for (const item of touched.reverse()) {
      try {
        if (readConfig(item.file).text === item.after) atomicWrite(item.file, item.text, item.mode);
      } catch { /* Exact backups remain available without overwriting concurrent user changes. */ }
    }
    throw error;
  }
  const shared = cleanupSharedFiles(base, environment, backup);
  const status = hookStatus({ homeDir: base, environment, agents: selected });
  const ok = status.ok && Object.values(status.agents).every(agent => !agent.managedPresent);
  return { ok, action: 'uninstall', cleanupOnly: true, agents: selected, changes, ...shared, status, reason: ok ? '' : '자동으로 구분할 수 없는 참조를 보존했습니다. status에서 남은 위치를 확인하세요.' };
}

export { ALL_AGENTS, ANTIGRAVITY_HOOK_NAME };

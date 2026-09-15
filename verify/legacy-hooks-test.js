import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { ALL_AGENTS, hookStatus, uninstallHooks } from '../core/hooks.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dcheck-cleanup-')));
let passed = 0;
const json = value => JSON.stringify(value, null, 2) + '\n';
const digest = text => crypto.createHash('sha256').update(text).digest('hex');
function write(file, text) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, text); }
function test(name, run) { run(); passed++; console.log('ok ' + passed + ' - ' + name); }
function fixture(name) { const directory = path.join(temp, name); fs.mkdirSync(directory); return directory; }
function legacyFiles(base) {
  const directory = path.join(base, '.dorms-check', 'hooks');
  const contents = {
    'vercel-guard.cjs': 'legacy guard fixture; do not execute',
    'strict-runtime.cjs': 'legacy runtime fixture; do not execute',
    'vercel-proxy.cjs': 'legacy proxy fixture; do not execute',
    'vercel.cmd': '@echo off\r\nmissing-node missing-proxy\r\n',
  };
  for (const [name, text] of Object.entries(contents)) write(path.join(directory, name), text);
  write(path.join(directory, 'manifest.json'), json({
    tag: 'dorms-check-security-only',
    nodeExecutable: '/removed/node',
    windowsVercelExecutable: { backingPath: 'C:\\Removed\\vercel.cmd', powerShellPath: 'C:\\Removed\\powershell.exe' },
    files: Object.fromEntries(Object.entries(contents).map(([name, text]) => [name, digest(text)])),
  }));
  return directory;
}
const guard = 'C:\\Users\\Teacher\\.dorms-check\\hooks\\vercel-guard.cjs';
const launcher = '"C:\\Removed\\powershell.exe" -NoProfile -EncodedCommand ' + Buffer.from('& "C:\\Removed\\node.exe" "' + guard + '"', 'utf16le').toString('base64');
const managed = { type: 'command', command: '/removed/node', args: [guard], timeout: 120 };
const userHook = { type: 'command', command: 'echo user command', timeout: 5 };
const markers = ['# >>> dorms-check-security-only >>>', '# <<< dorms-check-security-only <<<'];
function codexBlock(extra = '') {
  return markers[0] + '\n[[hooks.PreToolUse]]\nmatcher = "^Bash$"\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = ' + JSON.stringify('/removed/node "/tmp/.dorms-check/hooks/vercel-guard.cjs"') + '\ncommand_windows = ' + JSON.stringify(launcher) + '\ntimeout = 120\n' + extra + markers[1] + '\n';
}

try {
  test('status is read-only and a fresh home needs no cleanup writes', () => {
    const base = fixture('empty');
    assert.equal(hookStatus({ homeDir: base }).ok, true);
    assert.deepEqual(fs.readdirSync(base), []);
    const result = uninstallHooks({ homeDir: base });
    assert.equal(result.ok, true);
    assert.deepEqual(result.changes, []);
    assert.deepEqual(fs.readdirSync(base), []);
  });

  test('all historical agent formats preserve user settings and backed-up bytes', () => {
    const base = fixture('all');
    const directory = legacyFiles(base);
    const configs = {
      codex: path.join(base, '.codex', 'config.toml'),
      claude: path.join(base, '.claude', 'settings.json'),
      gemini: path.join(base, '.gemini', 'settings.json'),
      antigravity: path.join(base, '.gemini', 'antigravity-cli', 'hooks.json'),
    };
    const codexBefore = '# user formatting stays\nmodel = "user-model"\n\n' + codexBlock() + '\n[features]\nhooks = false\n';
    write(configs.codex, codexBefore);
    write(configs.claude, json({ theme: 'user', hooks: { PreToolUse: [{ matcher: 'Bash|PowerShell', hooks: [managed, userHook] }] } }));
    write(configs.gemini, json({ security: { auth: { selectedType: 'user' } }, hooks: { BeforeTool: [{ matcher: '^run_shell_command$', hooks: [{ type: 'command', command: launcher }, userHook] }] } }));
    write(configs.antigravity, json({ 'dorms-check-security-gate': { enabled: true, PreToolUse: [{ matcher: 'run_command', hooks: [{ type: 'command', command: launcher }, userHook] }] }, custom: { enabled: false } }));
    const before = Object.fromEntries(Object.values(configs).map(file => [file, fs.readFileSync(file, 'utf8')]));
    const inspected = hookStatus({ homeDir: base });
    assert.equal(inspected.ok, true);
    assert(ALL_AGENTS.every(agent => inspected.agents[agent].managedPresent));
    assert.deepEqual(before, Object.fromEntries(Object.values(configs).map(file => [file, fs.readFileSync(file, 'utf8')])));

    const first = uninstallHooks({ homeDir: base, agents: 'codex' });
    assert.equal(first.ok, true);
    assert(fs.existsSync(path.join(directory, 'vercel-guard.cjs')));
    assert.equal(first.removedFiles.length, 0);
    assert.equal(fs.readFileSync(configs.codex, 'utf8'), codexBefore.replace(codexBlock(), ''));
    const result = uninstallHooks({ homeDir: base });
    assert.equal(result.ok, true);
    assert.equal(JSON.parse(fs.readFileSync(configs.claude)).theme, 'user');
    assert.deepEqual(JSON.parse(fs.readFileSync(configs.claude)).hooks.PreToolUse[0].hooks, [userHook]);
    assert.deepEqual(JSON.parse(fs.readFileSync(configs.gemini)).hooks.BeforeTool[0].hooks, [userHook]);
    assert.deepEqual(JSON.parse(fs.readFileSync(configs.antigravity))['dorms-check-security-gate'].PreToolUse[0].hooks, [userHook]);
    assert.equal(result.retainedFiles.length, 0);
    assert.equal(result.removedFiles.length, 5);
    for (const change of [...first.changes, ...result.changes]) assert.equal(fs.readFileSync(change.backup, 'utf8'), before[change.file]);
    const second = uninstallHooks({ homeDir: base });
    assert.equal(second.changes.length, 0);
    assert.equal(fs.readFileSync(configs.codex, 'utf8'), codexBefore.replace(codexBlock(), ''));
  });

  test('unreferenced shared files are backed up and deleted only with matching manifest', () => {
    const base = fixture('shared');
    const directory = legacyFiles(base);
    write(path.join(base, '.claude', 'settings.json'), json({ hooks: { PreToolUse: [{ hooks: [managed] }] }, user: 1 }));
    const before = fs.readFileSync(path.join(directory, 'vercel-guard.cjs'), 'utf8');
    const result = uninstallHooks({ homeDir: base });
    assert.equal(result.ok, true);
    assert.equal(result.removedFiles.length, 5);
    assert.equal(fs.existsSync(directory), false);
    assert.equal(fs.readFileSync(result.removedFiles.find(item => item.file.endsWith('vercel-guard.cjs')).backup, 'utf8'), before);
    assert.equal(uninstallHooks({ homeDir: base }).changes.length, 0);
  });

  test('current custom roots and previous default roots are both cleaned', () => {
    const base = fixture('custom');
    const environment = { CODEX_HOME: path.join(base, 'custom-codex'), CLAUDE_CONFIG_DIR: path.join(base, 'custom-claude'), GEMINI_CLI_HOME: path.join(base, 'custom-gemini') };
    const files = [path.join(base, '.claude', 'settings.json'), path.join(environment.CLAUDE_CONFIG_DIR, 'settings.json'), path.join(environment.GEMINI_CLI_HOME, '.gemini', 'settings.json')];
    for (const file of files) write(file, json({ user: true, hooks: { BeforeTool: [{ hooks: [managed] }] } }));
    const result = uninstallHooks({ homeDir: base, environment });
    assert.equal(result.ok, true);
    assert.equal(result.changes.length, 3);
    for (const file of files) assert.deepEqual(JSON.parse(fs.readFileSync(file)), { user: true });
  });

  test('malformed selected config stops before any selected config changes', () => {
    const base = fixture('malformed');
    const codex = path.join(base, '.codex', 'config.toml');
    write(codex, codexBlock());
    write(path.join(base, '.claude', 'settings.json'), '{invalid');
    assert.throws(() => uninstallHooks({ homeDir: base }));
    assert.equal(fs.readFileSync(codex, 'utf8'), codexBlock());
    assert.equal(fs.existsSync(path.join(base, '.dorms-check', 'backups')), false);
    assert.equal(hookStatus({ homeDir: base }).ok, false);
  });

  test('incomplete or mixed Codex blocks are preserved', () => {
    for (const [name, text] of [
      ['incomplete', codexBlock().replace(markers[1], '')],
      ['mixed', codexBlock('[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "echo user"\n')],
    ]) {
      const base = fixture(name);
      const file = path.join(base, '.codex', 'config.toml');
      write(file, text);
      assert.throws(() => uninstallHooks({ homeDir: base, agents: 'codex' }));
      assert.equal(fs.readFileSync(file, 'utf8'), text);
    }
  });

  test('unmarked references retain shared files and surface incomplete cleanup', () => {
    const base = fixture('unmarked');
    const directory = legacyFiles(base);
    const file = path.join(base, '.codex', 'config.toml');
    const text = codexBlock().replace(markers[0], '').replace(markers[1], '');
    write(file, text);
    const result = uninstallHooks({ homeDir: base, agents: 'codex' });
    assert.equal(result.ok, false);
    assert.equal(result.removedFiles.length, 0);
    assert(fs.existsSync(directory));
    assert.equal(fs.readFileSync(file, 'utf8'), text);
  });

  test('a modified shared file is preserved with its manifest', () => {
    const base = fixture('modified');
    const directory = legacyFiles(base);
    const file = path.join(directory, 'vercel-proxy.cjs');
    fs.writeFileSync(file, 'user modification');
    const result = uninstallHooks({ homeDir: base });
    assert.equal(result.ok, true);
    assert.equal(fs.readFileSync(file, 'utf8'), 'user modification');
    assert(result.retainedFiles.includes(path.join(directory, 'manifest.json')));
  });

  test('a symlinked config is never replaced', () => {
    const base = fixture('symlink');
    const target = path.join(base, 'user.json');
    write(target, json({ hooks: { PreToolUse: [{ hooks: [managed] }] } }));
    const file = path.join(base, '.claude', 'settings.json');
    fs.mkdirSync(path.dirname(file));
    try { fs.symlinkSync(target, file); }
    catch (error) { if (process.platform === 'win32' && error.code === 'EPERM') { console.log('Windows symlink privilege unavailable; regular-file fixtures still run.'); return; } throw error; }
    assert.throws(() => uninstallHooks({ homeDir: base, agents: 'claude' }));
    assert(fs.lstatSync(file).isSymbolicLink());
    assert.equal(hookStatus({ homeDir: base, agents: 'claude' }).ok, false);
  });

  test('retired commands return FEATURE_REMOVED before scanning or writing', () => {
    const base = fixture('retired-cli');
    write(path.join(base, 'dorms-check.config.json'), '{invalid');
    for (const args of [
      ['scan', '--strict', '--json'],
      ['scan', '--strict=true', '--json'],
      ['scan', '--git-sha', 'invalid', '--json'],
      ['scan', '--vercel-deployment=https://invalid.example', '--json'],
      ['gate', 'verify', '--json'],
      ['hooks', 'install', '--global', '--agents', 'claude', '--json'],
    ]) {
      const child = spawnSync(process.execPath, [path.join(root, 'bin/dcheck.js'), ...args], { cwd: base, encoding: 'utf8' });
      assert.equal(child.status, 2, child.stderr);
      assert.equal(JSON.parse(child.stdout).code, 'FEATURE_REMOVED');
      assert.deepEqual(fs.readdirSync(base), ['dorms-check.config.json']);
    }
  });

  test('ordinary code-only scan completes with explicit unavailable coverage', () => {
    const base = fixture('scan-cli');
    const invoke = args => spawnSync(process.execPath, [path.join(root, 'bin/dcheck.js'), ...args], { cwd: base, encoding: 'utf8' });
    assert.equal(invoke(['init', '--name', 'Fixture', '--track', 'security', '--confirm-ownership']).status, 0);
    const scanned = invoke(['scan', '--code-only', '--json']);
    assert.equal(scanned.status, 0, scanned.stderr);
    const result = JSON.parse(scanned.stdout);
    assert.equal(result.trackResults.security.outcome, 'unavailable');
    assert.equal(result.trackResults.security.eligible, false);
    assert.equal(result.trackResults.security.score, null);
    assert.equal(fs.existsSync(path.join(base, '.dorms-check', 'scan.json')), true);
    assert.equal(invoke(['status']).status, 0);
    assert.equal(invoke(['report']).status, 0);
    assert.equal(invoke(['submit']).status, 0);
  });

  test('cleanup implementation has no subprocess or removed runtime dependency', () => {
    const source = fs.readFileSync(path.join(root, 'core/hooks.js'), 'utf8');
    assert(!source.includes('node:child_process'));
    assert(!/from ['"].*strict/.test(source));
    assert(!/export function installHooks\(/.test(source));
    for (const file of ['core/strict.js', 'core/strict-runtime.cjs', 'hooks/vercel-guard.cjs', 'hooks/vercel-proxy.cjs']) assert.equal(fs.existsSync(path.join(root, file)), false);
  });

  console.log('legacy-hooks: ' + passed + ' tests passed');
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}

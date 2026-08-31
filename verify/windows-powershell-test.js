import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import TOML from '@iarna/toml';
import { hookStatus, installHooks, uninstallHooks } from '../core/hooks.js';
import {
  createReceipt,
  projectIdentity,
  storeReceipt,
  strictRequiredIds,
} from '../core/strict.js';

if (process.platform !== 'win32') {
  console.log('windows PowerShell result: 0 pass, 0 fail (non-Windows skip)');
  process.exit(0);
}

let passed = 0;
let failed = 0;
const cleanup = [];

function ok(name, condition, detail = '') {
  if (condition) {
    passed++;
    console.log('  v', name);
  } else {
    failed++;
    console.error('  x', name, detail);
  }
}

function tempDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(dir);
  return dir;
}

function git(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim();
}

function quotePowerShell(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function cleanEnvironment(home) {
  const environment = Object.fromEntries(Object.entries(process.env)
    .filter(([name]) => !/^(?:VERCEL|NOW)(?:_|$)/i.test(name)
      && !/^(?:CODEX_HOME|CLAUDE_CONFIG_DIR|GEMINI_CLI_HOME)$/i.test(name)));
  environment.HOME = home;
  environment.USERPROFILE = home;
  return environment;
}

function strictPass(phase) {
  const expected = strictRequiredIds(phase);
  return { status: 'PASS', expected, observed: [...expected], blockers: [], incomplete: [], exitCode: 0 };
}

function resultsFor(phase) {
  return strictRequiredIds(phase).map(id => ({ id, status: 'pass', observed: 'pass', evidence: {} }));
}

function writeReceipts(root, home) {
  const project = projectIdentity(root);
  storeReceipt(createReceipt({
    phase: 'code',
    project,
    strict: strictPass('code'),
    results: resultsFor('code'),
    tool: { version: 'windows-ci' },
  }), root, { homeDir: home });
  storeReceipt(createReceipt({
    phase: 'live',
    project,
    deploymentUrl: 'https://strict-fixture.vercel.app/',
    deploymentId: 'dpl_fixture123',
    deploymentGitSha: project.gitSha,
    vercelProjectId: 'prj_fixture123',
    vercelOrgId: 'team_fixture123',
    strict: strictPass('live'),
    results: resultsFor('live'),
    tool: { version: 'windows-ci' },
  }), root, { homeDir: home });
  return project.gitSha;
}

function createRepo() {
  const root = tempDir('dcheck-windows-repo-');
  git(root, ['init', '-q']);
  git(root, ['config', 'user.name', 'dorms-check Windows CI']);
  git(root, ['config', 'user.email', 'dcheck-windows@example.invalid']);
  fs.writeFileSync(path.join(root, 'app.js'), 'export const app = true;\n');
  fs.writeFileSync(path.join(root, '.gitignore'), '.vercel/\n');
  fs.writeFileSync(path.join(root, '.vercelignore'), '.dorms-check/\n');
  fs.mkdirSync(path.join(root, '.vercel'), { recursive: true });
  fs.writeFileSync(path.join(root, '.vercel', 'project.json'), JSON.stringify({
    projectId: 'prj_fixture123',
    orgId: 'team_fixture123',
    projectName: 'fixture',
  }, null, 2));
  git(root, ['add', '.']);
  git(root, ['commit', '-qm', 'fixture']);
  return root;
}

function runPowerShell(executable, command, cwd, environment, input = '') {
  const propagateNativeExit = `${command}; exit $LASTEXITCODE`;
  return spawnSync(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', propagateNativeExit], {
    cwd,
    env: environment,
    input,
    encoding: 'utf8',
  });
}

function availablePowerShellExecutables(primary) {
  const candidates = [primary];
  try {
    const pwsh = execFileSync('where.exe', ['pwsh.exe'], { encoding: 'utf8' }).split(/\r?\n/).find(Boolean);
    if (pwsh) candidates.push(pwsh.trim());
  } catch { /* PowerShell 7 is optional on a custom runner. */ }
  return [...new Set(candidates.map(file => fs.realpathSync(file)))];
}

try {
  console.log('\n[Windows 1] real Vercel discovery and host-hook-independent challenge');
  const actualHome = tempDir('dcheck-windows-actual-home-');
  const actualEnvironment = cleanEnvironment(actualHome);
  const actual = installHooks({ homeDir: actualHome, environment: actualEnvironment, platform: 'win32' });
  ok('Get-Command discovers installed vercel@59.10.0 and exposes a separate managed proxy', actual.status.windowsVercelVersion === '59.10.0'
    && actual.status.windowsVercelExecutableVerified
    && path.win32.basename(actual.status.windowsVercelBackingExecutable).toLowerCase() === 'vercel.cmd'
    && actual.status.windowsVercelExecutable !== actual.status.windowsVercelBackingExecutable);
  for (const shell of availablePowerShellExecutables(actual.status.windowsPowerShellExecutable)) {
    const challenge = runPowerShell(
      shell,
      `& ${quotePowerShell(actual.status.windowsVercelExecutable)} promote https://dcheck-hook-challenge.invalid`,
      actualHome,
      actualEnvironment,
    );
    ok(`${path.win32.basename(shell)} managed proxy blocks invalid promote without a host hook event`, challenge.status === 2, challenge.stderr);
  }
  uninstallHooks({ homeDir: actualHome, environment: actualEnvironment });

  console.log('\n[Windows 2] exact staged/promote proxy and three installed handlers');
  const root = createRepo();
  const home = tempDir('dcheck-windows-fixture-home-');
  const fakeBin = tempDir('dcheck-windows-fake-bin-');
  const fakeVercel = path.join(fakeBin, 'vercel.cmd');
  const marker = path.join(fakeBin, 'calls.txt');
  const environment = cleanEnvironment(home);
  fs.writeFileSync(fakeVercel, [
    '@echo off',
    'if "%~1"=="--version" (',
    '  echo Vercel CLI 59.10.0',
    '  exit /b 0',
    ')',
    `echo %*>>"${marker}"`,
    'exit /b 0',
    '',
  ].join('\r\n'));
  const installed = installHooks({
    homeDir: home,
    environment,
    platform: 'win32',
    vercelExecutable: fakeVercel,
    powerShellExecutable: actual.status.windowsPowerShellExecutable,
  });
  const sha = writeReceipts(root, home);
  const proxy = quotePowerShell(installed.status.windowsVercelExecutable);
  const staged = `& ${proxy} --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${sha} --yes`;
  const promote = `& ${proxy} promote https://strict-fixture.vercel.app/`;
  const stagedResult = runPowerShell(installed.status.windowsPowerShellExecutable, staged, root, environment);
  ok('native PowerShell exact literal staged deploy reaches only the pinned fake backing CLI', stagedResult.status === 0
    && fs.readFileSync(marker, 'utf8').includes(`githubCommitSha=${sha}`), stagedResult.stderr);
  const promoteResult = runPowerShell(installed.status.windowsPowerShellExecutable, promote, root, environment);
  ok('native PowerShell exact literal receipt-bound promote reaches only the pinned fake backing CLI', promoteResult.status === 0
    && fs.readFileSync(marker, 'utf8').includes('promote https://strict-fixture.vercel.app/'), promoteResult.stderr);
  const markerBeforeBlock = fs.readFileSync(marker, 'utf8');
  const blocked = runPowerShell(installed.status.windowsPowerShellExecutable, `& ${proxy} promote https://dcheck-hook-challenge.invalid`, root, environment);
  ok('native PowerShell proxy blocks wrong promote before the backing CLI', blocked.status === 2
    && fs.readFileSync(marker, 'utf8') === markerBeforeBlock, blocked.stderr);

  const claude = JSON.parse(fs.readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8'));
  const claudeHandler = claude.hooks.PreToolUse.find(group => group.matcher === 'Bash|PowerShell').hooks[0];
  const hookInput = JSON.stringify({ cwd: root, tool_name: 'PowerShell', tool_input: { command: staged } });
  const claudeResult = spawnSync(claudeHandler.command, claudeHandler.args, { cwd: root, env: environment, input: hookInput, encoding: 'utf8' });
  ok('Claude PowerShell PreToolUse direct exec handler permits the exact staged command', claudeResult.status === 0, claudeResult.stderr);

  const gemini = JSON.parse(fs.readFileSync(path.join(home, '.gemini', 'settings.json'), 'utf8'));
  const geminiHandler = gemini.hooks.BeforeTool.find(group => group.matcher === '^run_shell_command$').hooks[0];
  const geminiResult = runPowerShell(
    installed.status.windowsPowerShellExecutable,
    geminiHandler.command,
    root,
    environment,
    JSON.stringify({ cwd: root, tool_name: 'run_shell_command', tool_input: { command: staged } }),
  );
  ok('Gemini BeforeTool PowerShell handler permits the exact staged command', geminiResult.status === 0, geminiResult.stderr);

  const codex = TOML.parse(fs.readFileSync(path.join(home, '.codex', 'config.toml'), 'utf8'));
  const codexHandler = codex.hooks.PreToolUse[0].hooks[0];
  const codexLauncher = path.join(home, 'run-codex-hook.cmd');
  fs.writeFileSync(codexLauncher, `@echo off\r\n${codexHandler.command_windows}\r\n`);
  const codexResult = spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', codexLauncher], {
    cwd: root,
    env: environment,
    input: hookInput,
    encoding: 'utf8',
  });
  ok('Codex command_windows CMD-compatible EncodedCommand launches the guard', codexResult.status === 0, codexResult.stderr);
  const status = hookStatus({ homeDir: home, environment, platform: 'win32' });
  ok('Windows status validates all three configured handlers and proxy/backing hashes', Object.values(status.agents).every(agent => agent.configured)
    && status.windowsVercelExecutableVerified
    && status.windowsVercelBackingExecutableSha256.length === 64);
  uninstallHooks({ homeDir: home, environment });
} finally {
  for (const dir of cleanup.reverse()) fs.rmSync(dir, { recursive: true, force: true });
}

console.log(`\nwindows PowerShell result: ${passed} pass, ${failed} fail`);
if (failed) process.exitCode = 1;

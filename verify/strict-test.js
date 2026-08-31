import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hookStatus, installHooks, uninstallHooks } from '../core/hooks.js';
import {
  STRICT_EXIT,
  createReceipt,
  evaluateStrictSecurity,
  inspectVercelDeployment,
  invalidateReceipt,
  projectIdentity,
  storeReceipt,
  strictRequiredIds,
  verifyCodeGate,
  verifyGate,
} from '../core/strict.js';

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

function initRepo(prefix = 'dcheck-strict-repo-') {
  const root = tempDir(prefix);
  git(root, ['init', '-q']);
  git(root, ['config', 'user.name', 'dorms-check test']);
  git(root, ['config', 'user.email', 'dcheck-test@example.invalid']);
  fs.writeFileSync(path.join(root, 'app.js'), 'export const app = true;\n');
  git(root, ['add', 'app.js']);
  git(root, ['commit', '-qm', 'fixture']);
  return root;
}

function strictPass(phase) {
  const expected = strictRequiredIds(phase);
  return { status: 'PASS', expected, observed: [...expected], blockers: [], incomplete: [], exitCode: STRICT_EXIT.PASS };
}

function resultsFor(phase, status = 'pass') {
  return strictRequiredIds(phase).map(id => ({ id, status, observed: status, evidence: {} }));
}

function writeReceipts(root, home, { now = new Date(), url = 'https://strict-fixture.vercel.app/', deploymentId = 'dpl_fixture123' } = {}) {
  const project = projectIdentity(root);
  const codeResults = resultsFor('code');
  const code = createReceipt({ phase: 'code', project, strict: strictPass('code'), results: codeResults, tool: { version: 'test' }, now });
  const storedCode = storeReceipt(code, root, { homeDir: home });
  const liveResults = resultsFor('live');
  const live = createReceipt({
    phase: 'live',
    project,
    deploymentUrl: url,
    deploymentId,
    strict: strictPass('live'),
    results: liveResults,
    tool: { version: 'test' },
    now,
  });
  const storedLive = storeReceipt(live, root, { homeDir: home });
  return { project, storedCode, storedLive, url };
}

function runGuard(guard, cwd, home, command, agent = 'codex') {
  const toolName = agent === 'gemini' ? 'run_shell_command' : 'Bash';
  return spawnSync(process.execPath, [guard], {
    cwd,
    env: { ...process.env, NODE_ENV: 'test', DCHECK_TEST_HOME: home },
    input: JSON.stringify({ cwd, hook_event_name: agent === 'gemini' ? 'BeforeTool' : 'PreToolUse', tool_name: toolName, tool_input: { command } }),
    encoding: 'utf8',
  });
}

function runCli(cwd, home, args) {
  const cli = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'dcheck.js');
  return spawnSync(process.execPath, [cli, ...args], {
    cwd,
    env: { ...process.env, NODE_ENV: 'test', DCHECK_TEST_HOME: home, NO_COLOR: '1' },
    encoding: 'utf8',
  });
}

async function run() {
  console.log('\n[1] strict completeness and exit contract');
  const codePass = evaluateStrictSecurity(resultsFor('code'), 'code');
  ok('code required items pass -> exit 0', codePass.status === 'PASS' && codePass.exitCode === STRICT_EXIT.PASS);
  const codeBlocked = evaluateStrictSecurity(resultsFor('code').map((item, index) => index === 0 ? { ...item, status: 'fail' } : item), 'code');
  ok('deterministic code failure -> exit 1', codeBlocked.status === 'SECURITY_BLOCKED' && codeBlocked.exitCode === STRICT_EXIT.SECURITY_BLOCKED);
  const codeIncomplete = evaluateStrictSecurity([], 'code');
  ok('missing deterministic results -> exit 3', codeIncomplete.status === 'INCOMPLETE' && codeIncomplete.exitCode === STRICT_EXIT.INCOMPLETE);
  const liveNa = resultsFor('live').map(item => ['code.rls.anon-read', 'code.firebase.public-read'].includes(item.id)
    ? { ...item, status: 'na', observed: `${item.id} provider not found`, evidence: { providerDetected: false } }
    : item);
  ok('explicit non-provider RLS/Firebase na is allowed', evaluateStrictSecurity(liveNa, 'live').status === 'PASS');
  const probeError = liveNa.map(item => item.id === 'code.rls.anon-read' ? { ...item, observed: 'RLS probe failed: timeout', evidence: { probeError: true } } : item);
  ok('probe failure disguised as na -> incomplete', evaluateStrictSecurity(probeError, 'live').status === 'INCOMPLETE');

  const inspectFixture = (fields = {}) => () => JSON.stringify({
    id: 'dpl_fixture123',
    url: 'strict-fixture.vercel.app',
    readyState: 'READY',
    target: 'production',
    ...fields,
  });
  ok('Vercel inspect binds exact READY production URL and ID', inspectVercelDeployment({ cwd: process.cwd(), deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/' }, { execFileSync: inspectFixture() }).ok);
  const inspectMismatch = inspectVercelDeployment({ cwd: process.cwd(), deployment: 'dpl_fixture123', url: 'https://other.vercel.app/' }, { execFileSync: inspectFixture() });
  ok('Vercel inspect URL mismatch -> exit 4', !inspectMismatch.ok && inspectMismatch.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const inspectPreview = inspectVercelDeployment({ cwd: process.cwd(), deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/' }, { execFileSync: inspectFixture({ target: 'preview' }) });
  ok('Vercel preview is not accepted as staged production', !inspectPreview.ok && inspectPreview.exitCode === STRICT_EXIT.BINDING_MISMATCH);

  console.log('\n[2] signed receipts, Git/deployment binding, expiry and tamper detection');
  const repo = initRepo();
  const receiptHome = tempDir('dcheck-strict-home-');
  const stored = writeReceipts(repo, receiptHome);
  const sha = stored.project.gitSha;
  ok('code receipt verifies current clean Git', verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome }).ok);
  ok('code+live receipts verify exact deployment', verifyGate({ cwd: repo, gitSha: sha, deployment: stored.url, url: stored.url }, { homeDir: receiptHome }).ok);
  const wrongDeployment = verifyGate({ cwd: repo, gitSha: sha, deployment: 'https://other.vercel.app/' }, { homeDir: receiptHome });
  ok('different deployment -> exit 4', !wrongDeployment.ok && wrongDeployment.exitCode === STRICT_EXIT.BINDING_MISMATCH);

  const liveFile = stored.storedLive.trustedFile;
  const tampered = JSON.parse(fs.readFileSync(liveFile, 'utf8'));
  tampered.deployment.url = 'https://tampered.vercel.app/';
  fs.writeFileSync(liveFile, JSON.stringify(tampered, null, 2));
  const tamperResult = verifyGate({ cwd: repo, gitSha: sha, deployment: stored.url }, { homeDir: receiptHome });
  ok('tampered receipt -> exit 5', !tamperResult.ok && tamperResult.exitCode === STRICT_EXIT.RECEIPT_INVALID);
  writeReceipts(repo, receiptHome);

  const weakHome = tempDir('dcheck-weak-home-');
  const weakProject = projectIdentity(repo);
  const weakReceipt = createReceipt({
    phase: 'code',
    project: weakProject,
    strict: { status: 'PASS', expected: [], observed: [], blockers: [], incomplete: [] },
    results: [],
    tool: { version: 'test' },
  });
  storeReceipt(weakReceipt, repo, { homeDir: weakHome });
  const weak = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: weakHome });
  ok('signed but incomplete required list -> exit 5', !weak.ok && weak.exitCode === STRICT_EXIT.RECEIPT_INVALID);

  const revokedHome = tempDir('dcheck-revoked-home-');
  writeReceipts(repo, revokedHome);
  invalidateReceipt('live', projectIdentity(repo), repo, { homeDir: revokedHome });
  const revoked = verifyGate({ cwd: repo, gitSha: sha, deployment: stored.url }, { homeDir: revokedHome });
  ok('starting a new live scan can revoke an older live receipt', !revoked.ok && revoked.exitCode === STRICT_EXIT.RECEIPT_INVALID);

  const expiredHome = tempDir('dcheck-expired-home-');
  writeReceipts(repo, expiredHome, { now: new Date(Date.now() - 16 * 60 * 1000) });
  const expired = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: expiredHome });
  ok('receipt older than 15 minutes -> exit 5', !expired.ok && expired.exitCode === STRICT_EXIT.RECEIPT_INVALID);

  fs.writeFileSync(path.join(repo, 'app.js'), 'export const app = false;\n');
  const dirty = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('dirty worktree -> exit 4', !dirty.ok && dirty.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  fs.writeFileSync(path.join(repo, 'app.js'), 'export const app = true;\n');
  fs.writeFileSync(path.join(repo, 'next.js'), 'export const next = true;\n');
  git(repo, ['add', 'next.js']);
  git(repo, ['commit', '-qm', 'next']);
  const changedSha = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('new commit invalidates old receipt -> exit 4', !changedSha.ok && changedSha.exitCode === STRICT_EXIT.BINDING_MISMATCH);

  console.log('\n[3] global hook install/status/uninstall in an isolated home fixture');
  const hookHome = tempDir('dcheck-hooks-home-');
  fs.mkdirSync(path.join(hookHome, '.codex'), { recursive: true });
  fs.mkdirSync(path.join(hookHome, '.claude'), { recursive: true });
  fs.mkdirSync(path.join(hookHome, '.gemini'), { recursive: true });
  fs.writeFileSync(path.join(hookHome, '.codex', 'config.toml'), 'model = "fixture"\n');
  fs.writeFileSync(path.join(hookHome, '.claude', 'settings.json'), JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: 'command', command: 'echo keep' }] }] } }, null, 2));
  fs.writeFileSync(path.join(hookHome, '.gemini', 'settings.json'), JSON.stringify({ theme: 'fixture' }, null, 2));
  const installed = installHooks({ homeDir: hookHome });
  ok('all three hook configs effective', Object.values(installed.status.agents).every(agent => agent.effective));
  ok('status names dashboard/Git/CI enforcement exclusions', installed.status.enforcementBoundary.excludes.length === 3 && installed.status.enforcementBoundary.hostActivationNotObservable === true);
  const codexText = fs.readFileSync(path.join(hookHome, '.codex', 'config.toml'), 'utf8');
  ok('Codex uses inline PreToolUse Bash hook', codexText.includes('[[hooks.PreToolUse]]') && codexText.includes('matcher = "^Bash$"'));
  const claudeSettings = JSON.parse(fs.readFileSync(path.join(hookHome, '.claude', 'settings.json'), 'utf8'));
  ok('Claude uses PreToolUse Bash hook', claudeSettings.hooks.PreToolUse.some(group => group.matcher === 'Bash'));
  ok('pre-existing Claude hook is preserved', claudeSettings.hooks.Stop[0].hooks[0].command === 'echo keep');
  const geminiSettings = JSON.parse(fs.readFileSync(path.join(hookHome, '.gemini', 'settings.json'), 'utf8'));
  ok('Gemini uses BeforeTool run_shell_command hook', geminiSettings.hooks.BeforeTool.some(group => group.matcher === '^run_shell_command$'));
  const installedAgain = installHooks({ homeDir: hookHome });
  ok('second install is idempotent', Object.values(installedAgain.changes).every(change => change.changed === false));
  ok('config backups were created outside agent config dirs', fs.existsSync(path.join(hookHome, '.dorms-check', 'backups')));
  const installedGuard = path.join(hookHome, '.dorms-check', 'hooks', 'vercel-guard.cjs');
  fs.appendFileSync(installedGuard, '\n// tampered\n');
  ok('tampered common guard makes all configured hooks ineffective', Object.values(hookStatus({ homeDir: hookHome }).agents).every(agent => !agent.effective));
  installHooks({ homeDir: hookHome });
  ok('reinstall repairs common guard integrity', hookStatus({ homeDir: hookHome }).source.valid);
  fs.writeFileSync(path.join(hookHome, '.codex', 'config.toml'), fs.readFileSync(path.join(hookHome, '.codex', 'config.toml'), 'utf8').replace('matcher = "^Bash$"', 'matcher = "^Other$"'));
  ok('tampered Codex matcher is not reported effective', hookStatus({ homeDir: hookHome }).agents.codex.effective === false);
  installHooks({ agents: 'codex', homeDir: hookHome });
  ok('reinstall repairs exact Codex hook configuration', hookStatus({ homeDir: hookHome }).agents.codex.effective === true);

  console.log('\n[4] common guard positive and negative Vercel command cases');
  const guardRepo = initRepo('dcheck-hook-repo-');
  fs.writeFileSync(path.join(guardRepo, 'package.json'), JSON.stringify({ scripts: {
    'prod-direct': 'vercel --prod',
    'prod-staged': 'vercel --prod --skip-domain',
  } }, null, 2));
  git(guardRepo, ['add', 'package.json']);
  git(guardRepo, ['commit', '-qm', 'package scripts fixture']);
  writeReceipts(guardRepo, hookHome);
  const guardPath = installed.status.source.entries['vercel-guard.cjs'].present
    ? path.join(hookHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')
    : '';
  for (const agent of ['codex', 'claude', 'gemini']) {
    const direct = runGuard(guardPath, guardRepo, hookHome, 'vercel --prod', agent);
    ok(`${agent}: direct production deploy is blocked`, direct.status === 2, direct.stderr);
  }
  ok('npx direct production form is blocked', runGuard(guardPath, guardRepo, hookHome, 'npx -y vercel@latest --prod', 'codex').status === 2);
  ok('vc alias direct production form is blocked', runGuard(guardPath, guardRepo, hookHome, 'vc --prod', 'codex').status === 2);
  ok('absolute-path compound production form is blocked', runGuard(guardPath, guardRepo, hookHome, 'echo ready && /usr/local/bin/vercel --prod', 'claude').status === 2);
  ok('command-substitution production form fails closed', runGuard(guardPath, guardRepo, hookHome, 'echo $(vercel --prod)', 'claude').status === 2);
  ok('--skip-domain=false does not bypass direct production block', runGuard(guardPath, guardRepo, hookHome, 'vercel --prod --skip-domain=false', 'codex').status === 2);
  ok('npm script that hides direct production is blocked', runGuard(guardPath, guardRepo, hookHome, 'npm run prod-direct', 'codex').status === 2);
  ok('code receipt permits isolated staged production', runGuard(guardPath, guardRepo, hookHome, 'vercel --prod --skip-domain', 'codex').status === 0);
  ok('npm script that stages production requires and accepts code receipt', runGuard(guardPath, guardRepo, hookHome, 'npm run prod-staged', 'claude').status === 0);
  ok('pnpm wrapper permits isolated staged production', runGuard(guardPath, guardRepo, hookHome, 'pnpm dlx vercel --prod --skip-domain', 'gemini').status === 0);
  ok('exact live receipt permits promote', runGuard(guardPath, guardRepo, hookHome, 'bunx vercel promote https://strict-fixture.vercel.app/', 'claude').status === 0);
  writeReceipts(guardRepo, hookHome, { deploymentId: 'dpl_fixture123' });
  ok('verified deployment ID receipt permits exact ID promote', runGuard(guardPath, guardRepo, hookHome, 'vercel promote dpl_fixture123', 'codex').status === 0);
  ok('different promote target is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel promote https://other.vercel.app/', 'codex').status === 2);
  ok('a later mismatched promote in one compound command is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel promote dpl_fixture123 && vercel promote https://other.vercel.app/', 'codex').status === 2);
  ok('alias-set bypass is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel alias set https://strict-fixture.vercel.app production.example', 'gemini').status === 2);

  fs.writeFileSync(path.join(guardRepo, 'app.js'), 'export const app = false;\n');
  ok('dirty source blocks staged production', runGuard(guardPath, guardRepo, hookHome, 'vercel --prod --skip-domain', 'codex').status === 2);
  fs.writeFileSync(path.join(guardRepo, 'app.js'), 'export const app = true;\n');
  const noReceiptRepo = initRepo('dcheck-no-receipt-repo-');
  ok('missing code receipt blocks staged production', runGuard(guardPath, noReceiptRepo, hookHome, 'vercel --prod --skip-domain', 'codex').status === 2);
  ok('compound cd uses target project receipt instead of caller receipt', runGuard(guardPath, guardRepo, hookHome, `cd ${noReceiptRepo} && vercel --prod --skip-domain`, 'claude').status === 2);
  writeReceipts(noReceiptRepo, hookHome);
  ok('compound cd permits target project with its own receipt', runGuard(guardPath, guardRepo, hookHome, `cd ${noReceiptRepo} && vercel --prod --skip-domain`, 'claude').status === 0);
  ok('Vercel --cwd permits target project with its own receipt', runGuard(guardPath, guardRepo, hookHome, `vercel --cwd ${noReceiptRepo} --prod --skip-domain`, 'gemini').status === 0);

  const uninstalled = uninstallHooks({ homeDir: hookHome });
  ok('all managed config entries are removed', Object.values(uninstalled.status.agents).every(agent => !agent.installed));
  ok('pre-existing Codex config remains', fs.readFileSync(path.join(hookHome, '.codex', 'config.toml'), 'utf8').includes('model = "fixture"'));
  ok('pre-existing Claude Stop hook remains after uninstall', JSON.parse(fs.readFileSync(path.join(hookHome, '.claude', 'settings.json'), 'utf8')).hooks.Stop[0].hooks[0].command === 'echo keep');
  const uninstalledAgain = uninstallHooks({ homeDir: hookHome });
  ok('second uninstall is idempotent', Object.values(uninstalledAgain.changes).every(change => change.changed === false));
  ok('status reports source absent after full uninstall', hookStatus({ homeDir: hookHome }).source.valid === false);

  console.log('\n[5] CLI strict JSON and deterministic judge non-override');
  const cliRepo = tempDir('dcheck-cli-repo-');
  git(cliRepo, ['init', '-q']);
  git(cliRepo, ['config', 'user.name', 'dorms-check test']);
  git(cliRepo, ['config', 'user.email', 'dcheck-test@example.invalid']);
  fs.writeFileSync(path.join(cliRepo, 'app.js'), 'export const app = true;\n');
  fs.writeFileSync(path.join(cliRepo, 'dorms-check.config.json'), JSON.stringify({
    app: { name: 'fixture', url: '', stack: 'static' },
    tracks: ['security'],
    teacher: { dormsHandle: '' },
    ownershipConfirmed: true,
  }, null, 2));
  git(cliRepo, ['add', '.']);
  git(cliRepo, ['commit', '-qm', 'fixture']);
  const cliSha = git(cliRepo, ['rev-parse', 'HEAD']);
  const cliHome = tempDir('dcheck-cli-home-');
  const cliPass = runCli(cliRepo, cliHome, ['scan', '--track', 'security', '--strict', '--json', '--code-only', '--git-sha', cliSha]);
  let cliPassJson = null;
  try { cliPassJson = JSON.parse(cliPass.stdout); } catch { /* asserted below */ }
  ok('CLI code-only strict emits JSON and exit 0', cliPass.status === 0 && cliPassJson?.status === 'PASS', cliPass.stderr || cliPass.stdout);
  const cliUsage = runCli(cliRepo, cliHome, ['scan', '--track', 'security', '--strict', '--json', '--code-only']);
  ok('CLI missing git-sha -> exit 2', cliUsage.status === STRICT_EXIT.USAGE_CONFIG);
  const cliMismatch = runCli(cliRepo, cliHome, ['scan', '--track', 'security', '--strict', '--json', '--code-only', '--git-sha', '0000000000000000000000000000000000000000']);
  ok('CLI wrong git-sha -> exit 4', cliMismatch.status === STRICT_EXIT.BINDING_MISMATCH);
  const cliBadDeployment = runCli(cliRepo, cliHome, ['scan', '--track', 'security', '--strict', '--json', '--url', 'https://strict-fixture.vercel.app/', '--git-sha', cliSha, '--vercel-deployment', 'not-a-deployment-id']);
  ok('CLI malformed Vercel deployment ID -> exit 2', cliBadDeployment.status === STRICT_EXIT.USAGE_CONFIG);

  const secret = 'sk-' + 'A'.repeat(32);
  fs.writeFileSync(path.join(cliRepo, 'secret.js'), `export const leaked = "${secret}";\n`);
  git(cliRepo, ['add', 'secret.js']);
  git(cliRepo, ['commit', '-qm', 'vulnerable fixture']);
  const vulnerableSha = git(cliRepo, ['rev-parse', 'HEAD']);
  fs.mkdirSync(path.join(cliRepo, '.dorms-check'), { recursive: true });
  fs.writeFileSync(path.join(cliRepo, '.dorms-check', 'review.json'), JSON.stringify({
    'code.hardcoded-secret': { status: 'pass', evidence: 'AI says it is safe' },
  }));
  const cliBlocked = runCli(cliRepo, cliHome, ['scan', '--track', 'security', '--strict', '--json', '--code-only', '--git-sha', vulnerableSha]);
  let blockedJson = null;
  try { blockedJson = JSON.parse(cliBlocked.stdout); } catch { /* asserted below */ }
  ok('committed hardcoded secret -> exit 1 despite judge pass', cliBlocked.status === STRICT_EXIT.SECURITY_BLOCKED && blockedJson?.strict?.blockers?.includes('code.hardcoded-secret'), cliBlocked.stderr || cliBlocked.stdout);

  const cliHookHome = tempDir('dcheck-cli-hooks-home-');
  const cliHookInstall = runCli(cliRepo, cliHookHome, ['hooks', 'install', '--global', '--agents', 'codex,claude,gemini', '--provider', 'vercel', '--security-only', '--json']);
  ok('CLI installs all hooks only in temp HOME', cliHookInstall.status === STRICT_EXIT.PASS, cliHookInstall.stderr || cliHookInstall.stdout);
  const cliHookStatus = runCli(cliRepo, cliHookHome, ['hooks', 'status', '--agents', 'codex,claude,gemini', '--json']);
  ok('CLI reports all temp HOME hooks effective', cliHookStatus.status === STRICT_EXIT.PASS, cliHookStatus.stderr || cliHookStatus.stdout);
  const cliUnknownAgent = runCli(cliRepo, cliHookHome, ['hooks', 'status', '--agents', 'unknown', '--json']);
  ok('CLI unknown hook agent -> exit 2', cliUnknownAgent.status === STRICT_EXIT.USAGE_CONFIG);
  const cliHookUninstall = runCli(cliRepo, cliHookHome, ['hooks', 'uninstall', '--agents', 'codex,claude,gemini', '--json']);
  ok('CLI uninstalls all hooks only in temp HOME', cliHookUninstall.status === STRICT_EXIT.PASS, cliHookUninstall.stderr || cliHookUninstall.stdout);

  console.log('\n[6] published package contains the common hook runtime');
  const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const pack = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: packageRoot, encoding: 'utf8' }));
  const packedFiles = new Set((pack[0]?.files || []).map(item => item.path));
  ok('npm package includes hooks/vercel-guard.cjs', packedFiles.has('hooks/vercel-guard.cjs'));
  ok('npm package includes core/strict-runtime.cjs', packedFiles.has('core/strict-runtime.cjs'));
  ok('npm package includes strict security gate documentation', packedFiles.has('docs/STRICT-SECURITY-GATE.ko.md'));

  console.log(`\nstrict 결과: ${passed} pass, ${failed} fail`);
  if (failed) process.exitCode = 1;
}

try {
  await run();
} finally {
  for (const dir of cleanup.reverse()) fs.rmSync(dir, { recursive: true, force: true });
}

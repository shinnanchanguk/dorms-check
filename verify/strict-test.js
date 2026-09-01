import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import runtime from '../core/strict-runtime.cjs';
import { fileURLToPath } from 'node:url';
import { hookStatus, installHooks, uninstallHooks } from '../core/hooks.js';
import { validateFinalOrigin } from '../checks/external/index.js';
import { readExactDeploymentFile } from '../checks/static/exact-file.js';
import {
  STRICT_EXIT,
  createReceipt,
  evaluateStrictSecurity,
  inspectVercelDeployment,
  invalidateReceipt,
  projectIdentity,
  storeReceipt,
  strictRequiredIds,
  evaluateVercelCommand,
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
  fs.writeFileSync(path.join(root, '.gitignore'), '.vercel/\n');
  fs.writeFileSync(path.join(root, '.vercelignore'), '.dorms-check/\n');
  fs.mkdirSync(path.join(root, '.vercel'), { recursive: true });
  fs.writeFileSync(path.join(root, '.vercel', 'project.json'), JSON.stringify({
    projectId: 'prj_fixture123',
    orgId: 'team_fixture123',
    projectName: 'fixture',
  }, null, 2));
  git(root, ['add', 'app.js', '.gitignore', '.vercelignore']);
  git(root, ['commit', '-qm', 'fixture']);
  return root;
}

function initStrictCliRepo(prefix, { excludeDcheck = true } = {}) {
  const root = tempDir(prefix);
  git(root, ['init', '-q']);
  git(root, ['config', 'user.name', 'dorms-check test']);
  git(root, ['config', 'user.email', 'dcheck-test@example.invalid']);
  fs.writeFileSync(path.join(root, 'app.js'), 'export const app = true;\n');
  fs.writeFileSync(path.join(root, '.gitignore'), '.vercel/\n');
  fs.writeFileSync(path.join(root, '.vercelignore'), excludeDcheck ? '.dorms-check/\n' : 'node_modules/\n');
  fs.mkdirSync(path.join(root, '.vercel'), { recursive: true });
  fs.writeFileSync(path.join(root, '.vercel', 'project.json'), JSON.stringify({
    projectId: 'prj_fixture123',
    orgId: 'team_fixture123',
    projectName: 'fixture',
  }, null, 2));
  fs.writeFileSync(path.join(root, 'dorms-check.config.json'), JSON.stringify({
    app: { name: 'fixture', url: '', stack: 'static' },
    tracks: ['security'],
    teacher: { dormsHandle: '' },
    ownershipConfirmed: true,
  }, null, 2));
  git(root, ['add', '.']);
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
    deploymentGitSha: project.gitSha,
    vercelProjectId: 'prj_fixture123',
    vercelOrgId: 'team_fixture123',
    strict: strictPass('live'),
    results: liveResults,
    tool: { version: 'test' },
    now,
  });
  const storedLive = storeReceipt(live, root, { homeDir: home });
  return { project, storedCode, storedLive, url };
}

const fakeVercelBins = new Map();

function fakeWindowsToolchain(version = '59.10.0') {
  const bin = tempDir(`dcheck-fake-windows-${version.replace(/\W/g, '-')}-`);
  const vercel = path.join(bin, 'vercel.cmd');
  const powerShell = path.join(bin, 'powershell.exe');
  fs.writeFileSync(vercel, `#!/bin/sh\nprintf '%s\\n' 'Vercel CLI ${version}'\n`);
  fs.writeFileSync(powerShell, `#!/bin/sh\ncase "$*" in *--version*) printf '%s\\n' 'Vercel CLI ${version}';; esac\nexit 0\n`);
  fs.chmodSync(vercel, 0o700);
  fs.chmodSync(powerShell, 0o700);
  return {
    vercel,
    vercelSha256: runtime.sha256(fs.readFileSync(vercel)),
    powerShell,
    powerShellSha256: runtime.sha256(fs.readFileSync(powerShell)),
    version,
  };
}

function managedHandler(group) {
  return group?.hooks?.find(handler => String(handler?.command || '').includes('vercel-guard.cjs')
    || handler?.args?.some(value => String(value).includes('vercel-guard.cjs')));
}

function fakeVercelBin(version = '59.10.0') {
  if (fakeVercelBins.has(version)) return fakeVercelBins.get(version);
  const bin = tempDir(`dcheck-fake-vercel-${version.replace(/\W/g, '-')}-`);
  const shell = path.join(bin, 'vercel');
  fs.writeFileSync(shell, `#!/bin/sh\nprintf '%s\\n' 'Vercel CLI ${version}'\n`);
  fs.chmodSync(shell, 0o700);
  fs.writeFileSync(path.join(bin, 'vercel.cmd'), `@echo off\r\necho Vercel CLI ${version}\r\n`);
  fakeVercelBins.set(version, bin);
  return bin;
}

function runGuardInput(guard, cwd, home, input, extraEnv = {}) {
  const requestedVersion = extraEnv.DCHECK_TEST_VERCEL_VERSION || '59.10.0';
  const childExtraEnv = { ...extraEnv };
  delete childExtraEnv.DCHECK_TEST_VERCEL_VERSION;
  const fakePath = `${fakeVercelBin(requestedVersion)}${path.delimiter}${childExtraEnv.PATH || process.env.PATH || ''}`;
  delete childExtraEnv.PATH;
  return spawnSync(process.execPath, [guard], {
    cwd,
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      PATH: fakePath,
      VERCEL_PROJECT_ID: '',
      VERCEL_ORG_ID: '',
      NOW_PROJECT_ID: '',
      NOW_ORG_ID: '',
      VERCEL_TEAM_ID: '',
      VERCEL_TOKEN: '',
      NOW_TOKEN: '',
      VERCEL_SCOPE: '',
      VERCEL_TEAM: '',
      VERCEL_PROJECT: '',
      VERCEL_CWD: '',
      VERCEL_CONFIG: '',
      VERCEL_GLOBAL_CONFIG: '',
      VERCEL_LOCAL_CONFIG: '',
      ...childExtraEnv,
      NODE_ENV: 'test',
    },
    input: JSON.stringify(input),
    encoding: 'utf8',
  });
}

function runGuard(guard, cwd, home, command, agent = 'codex', toolNameOverride = '', extraEnv = {}) {
  const toolName = toolNameOverride || (agent === 'gemini' ? 'run_shell_command' : 'Bash');
  return runGuardInput(guard, cwd, home, {
    cwd,
    hook_event_name: agent === 'gemini' ? 'BeforeTool' : 'PreToolUse',
    tool_name: toolName,
    tool_input: { command },
  }, extraEnv);
}

function runCli(cwd, home, args, extraEnv = {}) {
  const cli = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'dcheck.js');
  return spawnSync(process.execPath, [cli, ...args], {
    cwd,
    env: {
      ...process.env,
      VERCEL_PROJECT_ID: '',
      VERCEL_ORG_ID: '',
      NOW_PROJECT_ID: '',
      NOW_ORG_ID: '',
      VERCEL_TEAM_ID: '',
      VERCEL_TOKEN: '',
      NOW_TOKEN: '',
      VERCEL_SCOPE: '',
      VERCEL_TEAM: '',
      VERCEL_PROJECT: '',
      VERCEL_CWD: '',
      VERCEL_CONFIG: '',
      VERCEL_GLOBAL_CONFIG: '',
      VERCEL_LOCAL_CONFIG: '',
      CODEX_HOME: '',
      CLAUDE_CONFIG_DIR: '',
      GEMINI_CLI_HOME: '',
      HOME: home,
      USERPROFILE: home,
      NODE_ENV: 'test',
      NO_COLOR: '1',
      ...extraEnv,
    },
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

  const inspectRoot = tempDir('dcheck-inspect-project-');
  fs.mkdirSync(path.join(inspectRoot, '.vercel'), { recursive: true });
  fs.writeFileSync(path.join(inspectRoot, '.vercel', 'project.json'), JSON.stringify({
    projectId: 'prj_fixture123',
    orgId: 'team_fixture123',
    projectName: 'strict-fixture',
  }));
  const inspectSha = 'a'.repeat(40);
  const inspectFixture = (rawFields = {}, { inspectFields = {}, version = '59.10.0' } = {}) => {
    const calls = [];
    const execute = (_file, args) => {
      calls.push([...args]);
      if (args[0] === '--version') return `${version}\n`;
      if (args[0] === 'inspect') return JSON.stringify({
        id: 'dpl_fixture123',
        name: 'strict-fixture',
        url: 'strict-fixture.vercel.app',
        readyState: 'READY',
        target: 'production',
        createdAt: 1,
        ...inspectFields,
      });
      if (args[0] === 'api') return JSON.stringify({
        id: 'dpl_fixture123',
        name: 'strict-fixture',
        url: 'strict-fixture.vercel.app',
        readyState: 'READY',
        target: 'production',
        meta: { githubDeployment: '1', githubCommitSha: inspectSha },
        gitSource: { type: 'github', sha: inspectSha },
        projectId: 'prj_fixture123',
        ownerId: 'team_fixture123',
        ...rawFields,
      });
      throw new Error(`unexpected Vercel CLI call: ${args.join(' ')}`);
    };
    execute.calls = calls;
    return execute;
  };
  ok('Vercel inspect binds READY URL, ID, Git SHA, project and team', inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture() }).ok);
  const inspectCalls = inspectFixture();
  inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectCalls });
  const inspectCliArgs = inspectCalls.calls.find(args => args[0] === 'inspect') || [];
  const rawApiArgs = inspectCalls.calls.find(args => args[0] === 'api') || [];
  ok('Vercel inspection uses canonical inspect JSON plus read-only deployment GET', inspectCliArgs.includes('--format=json')
    && !inspectCliArgs.includes('--json')
    && rawApiArgs[1] === '/v13/deployments/dpl_fixture123?teamId=team_fixture123'
    && rawApiArgs.includes('--non-interactive')
    && !rawApiArgs.includes('--raw'));
  ok('real Vercel inspect projection without hidden metadata is completed by deployment API binding', inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture() }).ok);
  ok('real-shaped gitSource.sha also binds the exact Git artifact', inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({ gitSource: { type: 'github', sha: inspectSha } }) }).ok);
  const inspectMissingProviderMarker = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({ meta: { githubCommitSha: inspectSha } }) });
  ok('Vercel deployment without githubDeployment=1 -> exit 3', !inspectMissingProviderMarker.ok && inspectMissingProviderMarker.exitCode === STRICT_EXIT.INCOMPLETE);
  const inspectWrongProviderMarker = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({ meta: { githubDeployment: '0', githubCommitSha: inspectSha } }) });
  ok('Vercel deployment with wrong githubDeployment marker -> exit 4', !inspectWrongProviderMarker.ok && inspectWrongProviderMarker.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const inspectMismatch = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://other.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture() });
  ok('Vercel inspect URL mismatch -> exit 4', !inspectMismatch.ok && inspectMismatch.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const inspectReferenceMismatch = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'https://other.vercel.app/', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture() });
  ok('deployment URL argument cannot be ignored in favor of a different --url', !inspectReferenceMismatch.ok && inspectReferenceMismatch.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const inspectPreview = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({}, { inspectFields: { target: 'preview' } }) });
  ok('Vercel preview is not accepted as staged production', !inspectPreview.ok && inspectPreview.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const inspectMissingMetadata = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({ meta: undefined }) });
  ok('Vercel deployment without canonical metadata -> exit 3', !inspectMissingMetadata.ok && inspectMissingMetadata.exitCode === STRICT_EXIT.INCOMPLETE);
  const inspectMissingGitSource = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, {
    execFileSync: inspectFixture({ gitSource: undefined, gitMetadata: { commitSha: inspectSha } }),
  });
  ok('gitMetadata cannot substitute for required canonical gitSource.sha', !inspectMissingGitSource.ok && inspectMissingGitSource.exitCode === STRICT_EXIT.INCOMPLETE);
  const inspectWrongSha = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({ meta: { githubDeployment: '1', githubCommitSha: 'b'.repeat(40) } }) });
  ok('Vercel deployment from another Git SHA -> exit 4', !inspectWrongSha.ok && inspectWrongSha.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const inspectConflictingSourceSha = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({ gitSource: { type: 'github', sha: 'b'.repeat(40) } }) });
  ok('extra conflicting Git source metadata -> exit 4', !inspectConflictingSourceSha.ok && inspectConflictingSourceSha.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const inspectForeignProject = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({ projectId: 'prj_foreign', name: 'foreign' }) });
  ok('foreign Vercel project -> exit 4', !inspectForeignProject.ok && inspectForeignProject.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const inspectMissingProject = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({ projectId: undefined, ownerId: undefined }) });
  ok('Vercel response without project/team identity -> exit 3', !inspectMissingProject.ok && inspectMissingProject.exitCode === STRICT_EXIT.INCOMPLETE);
  const inspectApiMismatch = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({ id: 'dpl_other123' }) });
  ok('deployment GET must match the exact inspect ID and URL', !inspectApiMismatch.ok && inspectApiMismatch.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const inspectWrongCliVersion = inspectVercelDeployment({ cwd: inspectRoot, deployment: 'dpl_fixture123', url: 'https://strict-fixture.vercel.app/', gitSha: inspectSha }, { execFileSync: inspectFixture({}, { version: '40.1.0' }) });
  ok('unreviewed Vercel CLI version fails closed before live binding', !inspectWrongCliVersion.ok && inspectWrongCliVersion.exitCode === STRICT_EXIT.USAGE_CONFIG);
  const windowsToolchain = fakeWindowsToolchain();
  const windowsVercelCalls = [];
  const windowsVercelOutput = runtime.runVercelCli(['inspect', 'dpl_fixture123', '--format=json', '--non-interactive'], { encoding: 'utf8' }, {
    platform: 'win32',
    vercelExecutable: windowsToolchain.vercel,
    vercelExecutableSha256: windowsToolchain.vercelSha256,
    vercelExecutableVersion: windowsToolchain.version,
    powerShellExecutable: windowsToolchain.powerShell,
    powerShellExecutableSha256: windowsToolchain.powerShellSha256,
    execFileSync(file, args) {
      windowsVercelCalls.push({ file, args });
      return 'fixture';
    },
  });
  ok('Windows internal Vercel execution uses the pinned PowerShell and absolute vercel.cmd', windowsVercelOutput === 'fixture'
    && windowsVercelCalls[0]?.file === fs.realpathSync(windowsToolchain.powerShell)
    && windowsVercelCalls[0]?.args?.slice(0, 4).join('\n') === ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command'].join('\n')
    && windowsVercelCalls[0]?.args?.[4]?.includes(`'${fs.realpathSync(windowsToolchain.vercel)}'`));
  let windowsUnsafeArgumentBlocked = false;
  try {
    runtime.runVercelCli(['inspect', 'unsafe target'], {}, {
      platform: 'win32',
      vercelExecutable: windowsToolchain.vercel,
      vercelExecutableSha256: windowsToolchain.vercelSha256,
      powerShellExecutable: windowsToolchain.powerShell,
      powerShellExecutableSha256: windowsToolchain.powerShellSha256,
      execFileSync() {},
    });
  } catch { windowsUnsafeArgumentBlocked = true; }
  ok('Windows internal Vercel runner rejects arguments requiring PowerShell re-parsing', windowsUnsafeArgumentBlocked);
  const ambientHome = tempDir('dcheck-ambient-home-');
  const ignoredHome = tempDir('dcheck-ignored-test-home-');
  const resolveHomeProbe = spawnSync(process.execPath, ['-e', `const r=require(${JSON.stringify(path.resolve('core/strict-runtime.cjs'))});process.stdout.write(r.resolveHome({}));`], {
    cwd: path.resolve('.'),
    env: { ...process.env, HOME: ambientHome, USERPROFILE: ambientHome, NODE_ENV: 'test', DCHECK_TEST_HOME: ignoredHome },
    encoding: 'utf8',
  });
  ok('NODE_ENV=test cannot redirect the trusted receipt home through DCHECK_TEST_HOME', resolveHomeProbe.status === 0 && path.resolve(resolveHomeProbe.stdout) === path.resolve(ambientHome));
  const versionProbe = spawnSync(process.execPath, ['-e', `const r=require(${JSON.stringify(path.resolve('core/strict-runtime.cjs'))});const v=r.verifyVercelCliVersion({cwd:process.cwd()});process.stdout.write(JSON.stringify(v));process.exit(v.ok?0:1);`], {
    cwd: path.resolve('.'),
    env: { ...process.env, PATH: `${fakeVercelBin('59.10.0')}${path.delimiter}${process.env.PATH || ''}`, NODE_ENV: 'test', DCHECK_TEST_VERCEL_VERSION: '40.1.0' },
    encoding: 'utf8',
  });
  ok('NODE_ENV=test cannot forge the probed Vercel CLI version through DCHECK_TEST_VERCEL_VERSION', versionProbe.status === 0 && JSON.parse(versionProbe.stdout).version === '59.10.0');
  const redirectBinding = validateFinalOrigin('https://strict-fixture.vercel.app/', 'https://evil.example/login');
  ok('cross-origin live redirect is rejected before strict scanning', !redirectBinding.ok && redirectBinding.finalOrigin === 'https://evil.example');

  console.log('\n[2] signed receipts, Git/deployment binding, expiry and tamper detection');
  const repo = initRepo();
  const receiptHome = tempDir('dcheck-strict-home-');
  const stored = writeReceipts(repo, receiptHome);
  const sha = stored.project.gitSha;
  ok('code receipt verifies current clean Git', verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome }).ok);
  ok('code+live receipts verify exact deployment', verifyGate({ cwd: repo, gitSha: sha, deployment: stored.url, url: stored.url }, { homeDir: receiptHome }).ok);
  ok('strict receipts are stored only outside the project', stored.storedCode.projectFile === null
    && stored.storedLive.projectFile === null
    && !fs.existsSync(path.join(repo, '.dorms-check', 'strict-code.json'))
    && !fs.existsSync(path.join(repo, '.dorms-check', 'strict-live.json')));
  const wrongDeployment = verifyGate({ cwd: repo, gitSha: sha, deployment: 'https://other.vercel.app/' }, { homeDir: receiptHome });
  ok('different deployment -> exit 4', !wrongDeployment.ok && wrongDeployment.exitCode === STRICT_EXIT.BINDING_MISMATCH);

  const linkedProjectFile = path.join(repo, '.vercel', 'project.json');
  const linkedProjectBefore = fs.readFileSync(linkedProjectFile, 'utf8');
  fs.writeFileSync(linkedProjectFile, JSON.stringify({ projectId: 'prj_foreign', orgId: 'team_foreign', projectName: 'foreign' }, null, 2));
  const relinked = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('changing ignored Vercel project link invalidates code receipt', !relinked.ok && relinked.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  fs.writeFileSync(linkedProjectFile, JSON.stringify({ projectId: 'prj_fixture123', orgId: 'team_fixture123', projectName: 'fixture' }));
  const linkDigestChanged = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('changing linked project file digest invalidates code receipt even with the same IDs', !linkDigestChanged.ok && linkDigestChanged.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  fs.writeFileSync(linkedProjectFile, linkedProjectBefore);
  const foreignAmbient = verifyCodeGate({ cwd: repo, gitSha: sha }, {
    homeDir: receiptHome,
    env: { VERCEL_PROJECT_ID: 'prj_foreign', VERCEL_ORG_ID: 'team_foreign' },
  });
  ok('foreign ambient Vercel project precedence invalidates code gate', !foreignAmbient.ok && foreignAmbient.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  ok('matching ambient Vercel project and org remain bound', verifyCodeGate({ cwd: repo, gitSha: sha }, {
    homeDir: receiptHome,
    env: { VERCEL_PROJECT_ID: 'prj_fixture123', VERCEL_ORG_ID: 'team_fixture123', VERCEL_TEAM_ID: 'team_fixture123' },
  }).ok);
  const foreignAmbientTeam = verifyCodeGate({ cwd: repo, gitSha: sha }, {
    homeDir: receiptHome,
    env: { VERCEL_TEAM_ID: 'team_foreign' },
  });
  ok('foreign ambient VERCEL_TEAM_ID invalidates code gate', !foreignAmbientTeam.ok && foreignAmbientTeam.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const ambientToken = verifyCodeGate({ cwd: repo, gitSha: sha }, {
    homeDir: receiptHome,
    env: { VERCEL_TOKEN: 'fixture-token' },
  });
  ok('ambient Vercel token/scope/config overrides fail closed', !ambientToken.ok && ambientToken.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  const unknownAmbientVercel = verifyCodeGate({ cwd: repo, gitSha: sha }, {
    homeDir: receiptHome,
    env: { VERCEL_TARGET_ENV: 'foreign-production' },
  });
  ok('unknown ambient Vercel artifact or target override fails closed', !unknownAmbientVercel.ok
    && unknownAmbientVercel.exitCode === STRICT_EXIT.BINDING_MISMATCH);

  git(repo, ['update-index', '--assume-unchanged', 'app.js']);
  fs.writeFileSync(path.join(repo, 'app.js'), 'export const hidden = "assume-unchanged";\n');
  const assumeUnchanged = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('assume-unchanged tracked source cannot fake a clean code receipt', !assumeUnchanged.ok && assumeUnchanged.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  git(repo, ['update-index', '--no-assume-unchanged', 'app.js']);
  fs.writeFileSync(path.join(repo, 'app.js'), 'export const app = true;\n');

  git(repo, ['update-index', '--skip-worktree', 'app.js']);
  fs.writeFileSync(path.join(repo, 'app.js'), 'export const hidden = "skip-worktree";\n');
  const skipWorktree = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('skip-worktree tracked source cannot fake a clean code receipt', !skipWorktree.ok && skipWorktree.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  git(repo, ['update-index', '--no-skip-worktree', 'app.js']);
  fs.writeFileSync(path.join(repo, 'app.js'), 'export const app = true;\n');

  const filteredRepo = initRepo('dcheck-clean-filter-repo-');
  fs.writeFileSync(path.join(filteredRepo, '.gitattributes'), 'app.js filter=dropbad\n');
  git(filteredRepo, ['config', 'filter.dropbad.clean', "sed '/^MALICIOUS/d'"]);
  git(filteredRepo, ['config', 'filter.dropbad.smudge', 'cat']);
  git(filteredRepo, ['add', '.gitattributes', 'app.js']);
  git(filteredRepo, ['commit', '-qm', 'bind clean filter']);
  const filteredInitialIdentity = projectIdentity(filteredRepo);
  ok('an active Git clean filter blocks the initial source binding', !filteredInitialIdentity.ok
    && filteredInitialIdentity.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  fs.appendFileSync(path.join(filteredRepo, 'app.js'), 'MALICIOUS=run_unscanned_payload()\n');
  git(filteredRepo, ['add', 'app.js']);
  const filteredStatus = git(filteredRepo, ['status', '--porcelain=v1', '--untracked-files=all']);
  const filteredBypass = projectIdentity(filteredRepo);
  ok('active filter stays blocked when Git hides different upload bytes as clean', filteredStatus === ''
    && fs.readFileSync(path.join(filteredRepo, 'app.js'), 'utf8').includes('MALICIOUS=')
    && !filteredBypass.ok
    && filteredBypass.exitCode === STRICT_EXIT.BINDING_MISMATCH);

  const crlfRepo = initRepo('dcheck-crlf-repo-');
  git(crlfRepo, ['config', 'core.autocrlf', 'true']);
  fs.unlinkSync(path.join(crlfRepo, 'app.js'));
  git(crlfRepo, ['checkout', '--', 'app.js']);
  const crlfStatus = git(crlfRepo, ['status', '--porcelain=v1', '--untracked-files=all']);
  const crlfIdentity = projectIdentity(crlfRepo);
  ok('standard autocrlf checkout remains bound through Git canonical hashing and raw manifest digest', crlfStatus === '' && crlfIdentity.ok, crlfIdentity.reason);

  const replacementRepo = initRepo('dcheck-replace-ref-repo-');
  const replacementOriginal = git(replacementRepo, ['rev-parse', 'HEAD']);
  fs.writeFileSync(path.join(replacementRepo, 'app.js'), 'export const replacementPayload = true;\n');
  git(replacementRepo, ['add', 'app.js']);
  git(replacementRepo, ['commit', '-qm', 'replacement payload']);
  const replacementCommit = git(replacementRepo, ['rev-parse', 'HEAD']);
  git(replacementRepo, ['replace', replacementOriginal, replacementCommit]);
  git(replacementRepo, ['update-ref', 'HEAD', replacementOriginal]);
  const replaceAwareStatus = git(replacementRepo, ['status', '--porcelain=v1', '--untracked-files=all']);
  const replacementIdentity = projectIdentity(replacementRepo);
  ok('replace refs cannot bind replacement bytes under the original 40-character commit', replaceAwareStatus === ''
    && !replacementIdentity.ok
    && replacementIdentity.exitCode === STRICT_EXIT.BINDING_MISMATCH);

  const previousGitIndex = process.env.GIT_INDEX_FILE;
  process.env.GIT_INDEX_FILE = path.join(tempDir('dcheck-foreign-index-'), 'index');
  let ambientGitIdentity;
  try { ambientGitIdentity = projectIdentity(repo); }
  finally {
    if (previousGitIndex === undefined) delete process.env.GIT_INDEX_FILE;
    else process.env.GIT_INDEX_FILE = previousGitIndex;
  }
  ok('ambient Git identity override fails closed before source binding', !ambientGitIdentity.ok
    && ambientGitIdentity.exitCode === STRICT_EXIT.BINDING_MISMATCH
    && ambientGitIdentity.reason.includes('GIT_INDEX_FILE'));

  const trackedStateRepo = initRepo('dcheck-tracked-state-repo-');
  fs.mkdirSync(path.join(trackedStateRepo, '.dorms-check'), { recursive: true });
  fs.writeFileSync(path.join(trackedStateRepo, '.dorms-check', 'scan.json'), '{"status":"initial"}\n');
  git(trackedStateRepo, ['add', '-f', '.dorms-check/scan.json']);
  git(trackedStateRepo, ['commit', '-qm', 'tracked legacy state']);
  fs.writeFileSync(path.join(trackedStateRepo, '.dorms-check', 'scan.json'), '{"status":"updated"}\n');
  const trackedStateIdentity = projectIdentity(trackedStateRepo);
  ok('allowlisted tracked legacy state may change only by entering the bound project-state digest', trackedStateIdentity.ok
    && trackedStateIdentity.deploymentInputs.projectStateFiles === 1,
  trackedStateIdentity.reason);

  const exactReadRepo = initRepo('dcheck-exact-static-repo-');
  const exactIdentity = projectIdentity(exactReadRepo);
  const exactItem = exactIdentity.deploymentInputs.manifest.find(item => item.path === 'app.js');
  fs.writeFileSync(path.join(exactReadRepo, 'app.js'), 'export const raced = true;\n');
  let exactReadBlocked = false;
  try { readExactDeploymentFile(exactReadRepo, exactItem); } catch { exactReadBlocked = true; }
  ok('strict static readers reject bytes changed after the deployment manifest snapshot', exactReadBlocked);

  const routesRepo = initRepo('dcheck-vercel-routes-repo-');
  const routesHome = tempDir('dcheck-vercel-routes-home-');
  const routesStored = writeReceipts(routesRepo, routesHome);
  const routesFile = path.join(routesRepo, '.vercel', 'routes.json');
  fs.writeFileSync(routesFile, JSON.stringify([{ src: '/safe', dest: '/index' }]));
  const addedRoutes = verifyCodeGate({ cwd: routesRepo, gitSha: routesStored.project.gitSha }, { homeDir: routesHome });
  ok('untracked .vercel/routes.json added after receipt invalidates raw upload binding', !addedRoutes.ok && addedRoutes.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  writeReceipts(routesRepo, routesHome);
  fs.writeFileSync(routesFile, JSON.stringify([{ src: '/(.*)', dest: 'https://evil.example/$1' }]));
  const changedRoutes = verifyCodeGate({ cwd: routesRepo, gitSha: routesStored.project.gitSha }, { homeDir: routesHome });
  ok('mutated .vercel/routes.json invalidates raw upload binding', !changedRoutes.ok && changedRoutes.exitCode === STRICT_EXIT.BINDING_MISMATCH);

  if (process.platform !== 'win32') {
    const modeRepo = initRepo('dcheck-file-mode-repo-');
    git(modeRepo, ['config', 'core.fileMode', 'false']);
    const modeHome = tempDir('dcheck-file-mode-home-');
    const modeStored = writeReceipts(modeRepo, modeHome);
    fs.chmodSync(path.join(modeRepo, 'app.js'), 0o755);
    const modeStatus = git(modeRepo, ['status', '--porcelain=v1', '--untracked-files=all']);
    const changedMode = verifyCodeGate({ cwd: modeRepo, gitSha: modeStored.project.gitSha }, { homeDir: modeHome });
    ok('raw upload manifest catches a Git-clean executable mode mutation', modeStatus === ''
      && !changedMode.ok
      && changedMode.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  }

  if (process.platform !== 'win32') {
    const symlinkRepo = initRepo('dcheck-vercel-symlink-repo-');
    const externalVercel = tempDir('dcheck-external-vercel-');
    fs.writeFileSync(path.join(externalVercel, 'project.json'), JSON.stringify({ projectId: 'prj_fixture123', orgId: 'team_fixture123', projectName: 'fixture' }));
    fs.writeFileSync(path.join(externalVercel, 'routes.json'), JSON.stringify([{ src: '/(.*)', dest: 'https://evil.example/$1' }]));
    fs.rmSync(path.join(symlinkRepo, '.vercel'), { recursive: true, force: true });
    fs.symlinkSync(externalVercel, path.join(symlinkRepo, '.vercel'), 'dir');
    const symlinkIdentity = projectIdentity(symlinkRepo);
    ok('symlinked .vercel ancestor is rejected before linked project or routes can escape binding', !symlinkIdentity.ok
      && [STRICT_EXIT.INCOMPLETE, STRICT_EXIT.BINDING_MISMATCH].includes(symlinkIdentity.exitCode));
  }

  fs.appendFileSync(path.join(repo, '.git', 'info', 'exclude'), '\nvercel.json\nignored-source.js\n.wafpickle-upload.js\n.pnp.cjs\n');
  fs.writeFileSync(path.join(repo, 'vercel.json'), JSON.stringify({ builds: [{ src: 'ignored-source.js', use: '@vercel/node' }] }));
  const ignoredVercelConfig = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('ignored untracked vercel.json cannot alter the deployment artifact', !ignoredVercelConfig.ok && ignoredVercelConfig.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  fs.unlinkSync(path.join(repo, 'vercel.json'));
  fs.writeFileSync(path.join(repo, 'ignored-source.js'), 'export const ignored = true;\n');
  const ignoredSource = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('ignored untracked source cannot enter the Vercel upload', !ignoredSource.ok && ignoredSource.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  fs.unlinkSync(path.join(repo, 'ignored-source.js'));
  fs.writeFileSync(path.join(repo, '.wafpickle-upload.js'), 'export const uploaded = true;\n');
  const nearMissDefaultIgnore = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('near-miss Vercel ignore filename remains bound instead of being incorrectly excluded', !nearMissDefaultIgnore.ok && nearMissDefaultIgnore.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  fs.unlinkSync(path.join(repo, '.wafpickle-upload.js'));
  fs.writeFileSync(path.join(repo, '.pnp.cjs'), 'module.exports = {};\n');
  const exactDefaultIgnore = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('current Vercel default .pnp* exclusion does not create a false unbound input', exactDefaultIgnore.ok, exactDefaultIgnore.reason);
  fs.unlinkSync(path.join(repo, '.pnp.cjs'));

  const negatedIgnoreRepo = initRepo('dcheck-negated-vercelignore-repo-');
  fs.writeFileSync(path.join(negatedIgnoreRepo, '.vercelignore'), '!.env.local\n');
  git(negatedIgnoreRepo, ['add', '.vercelignore']);
  git(negatedIgnoreRepo, ['commit', '-qm', 'add negated Vercel ignore']);
  fs.appendFileSync(path.join(negatedIgnoreRepo, '.git', 'info', 'exclude'), '\n.env.local\n');
  fs.writeFileSync(path.join(negatedIgnoreRepo, '.env.local'), 'REINCLUDED_BUILD_INPUT=true\n');
  const negatedIgnoreIdentity = projectIdentity(negatedIgnoreRepo);
  ok('Vercel ignore negation cannot re-include a default-excluded unbound file', !negatedIgnoreIdentity.ok
    && negatedIgnoreIdentity.exitCode === STRICT_EXIT.BINDING_MISMATCH);

  const conflictingIgnoreRepo = initRepo('dcheck-conflicting-vercelignore-repo-');
  fs.writeFileSync(path.join(conflictingIgnoreRepo, '.vercelignore'), 'cache/\n');
  fs.writeFileSync(path.join(conflictingIgnoreRepo, '.nowignore'), 'tmp/\n');
  git(conflictingIgnoreRepo, ['add', '.vercelignore', '.nowignore']);
  git(conflictingIgnoreRepo, ['commit', '-qm', 'add conflicting Vercel ignores']);
  const conflictingIgnoreIdentity = projectIdentity(conflictingIgnoreRepo);
  ok('conflicting Vercel ignore files fail closed like the Vercel CLI', !conflictingIgnoreIdentity.ok
    && conflictingIgnoreIdentity.exitCode === STRICT_EXIT.BINDING_MISMATCH);

  fs.mkdirSync(path.join(repo, '.dorms-check'), { recursive: true });
  fs.writeFileSync(path.join(repo, '.dorms-check', 'scan.json'), '{"status":"legacy"}\n');
  const addedAllowedState = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('adding an allowlisted legacy state file still invalidates the prior digest', !addedAllowedState.ok && addedAllowedState.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  writeReceipts(repo, receiptHome);
  fs.writeFileSync(path.join(repo, '.dorms-check', 'scan.json'), '{"status":"changed"}\n');
  const changedAllowedState = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('changing an allowlisted legacy state file invalidates the bound receipt', !changedAllowedState.ok && changedAllowedState.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  fs.writeFileSync(path.join(repo, '.dorms-check', 'scan.json'), '{"status":"legacy"}\n');
  writeReceipts(repo, receiptHome);
  fs.writeFileSync(path.join(repo, '.dorms-check', 'build.js'), 'require("node:child_process").execSync("vercel rr complete")\n');
  const hiddenDcheckBuild = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: receiptHome });
  ok('arbitrary .dorms-check build input is blocked instead of globally ignored', !hiddenDcheckBuild.ok && hiddenDcheckBuild.exitCode === STRICT_EXIT.BINDING_MISMATCH);
  fs.unlinkSync(path.join(repo, '.dorms-check', 'build.js'));

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

  const wrongTtlHome = tempDir('dcheck-wrong-ttl-home-');
  const wrongTtlReceipt = createReceipt({
    phase: 'code',
    project: projectIdentity(repo),
    strict: strictPass('code'),
    results: resultsFor('code'),
    tool: { version: 'test' },
  });
  wrongTtlReceipt.expiresAt = new Date(Date.parse(wrongTtlReceipt.checkedAt) + 16 * 60 * 1000).toISOString();
  storeReceipt(wrongTtlReceipt, repo, { homeDir: wrongTtlHome });
  const wrongTtl = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: wrongTtlHome });
  ok('even a signed receipt must use the exact 15-minute TTL -> exit 5', !wrongTtl.ok && wrongTtl.exitCode === STRICT_EXIT.RECEIPT_INVALID);

  const staleRuntimeHome = tempDir('dcheck-stale-runtime-home-');
  const staleRuntimeReceipt = createReceipt({
    phase: 'code',
    project: projectIdentity(repo),
    strict: strictPass('code'),
    results: resultsFor('code'),
    tool: { version: 'stale-test' },
  });
  staleRuntimeReceipt.gate.runtimeSha256 = '0'.repeat(64);
  storeReceipt(staleRuntimeReceipt, repo, { homeDir: staleRuntimeHome });
  const staleRuntime = verifyCodeGate({ cwd: repo, gitSha: sha }, { homeDir: staleRuntimeHome });
  ok('signed receipt from a different strict runtime -> exit 5', !staleRuntime.ok && staleRuntime.exitCode === STRICT_EXIT.RECEIPT_INVALID);

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
  ok('all four hook configs are configured but activation remains unknown', Object.values(installed.status.agents).every(agent => agent.configured && agent.activation === 'unknown') && installed.status.ready === false);
  ok('status names dashboard/Git/CI enforcement exclusions', installed.status.enforcementBoundary.excludes.length === 3 && installed.status.enforcementBoundary.hostActivationNotObservable === true);
  ok('status reports current-host-only Windows/WSL boundary', installed.status.installationScope === 'current-host-only' && typeof installed.status.hostPlatform === 'string' && typeof installed.status.isWSL === 'boolean');
  ok('status reports 120-second host timeout may fail open', installed.status.timeoutSeconds === 120 && installed.status.hostTimeoutMayFailOpen === true);
  ok('status reports a verified absolute Node executable instead of relying on PATH', installed.status.nodeExecutableVerified === true
    && path.isAbsolute(installed.status.nodeExecutable)
    && installed.status.nodeExecutable === fs.realpathSync(process.execPath));
  const codexText = fs.readFileSync(path.join(hookHome, '.codex', 'config.toml'), 'utf8');
  ok('Codex uses inline PreToolUse Bash hook with Windows command, absolute Node, and 120s timeout', codexText.includes('[[hooks.PreToolUse]]')
    && codexText.includes('matcher = "^Bash$"')
    && codexText.includes('command_windows')
    && codexText.includes(fs.realpathSync(process.execPath).replaceAll('\\', '\\\\'))
    && codexText.includes('timeout = 120'));
  const claudeSettings = JSON.parse(fs.readFileSync(path.join(hookHome, '.claude', 'settings.json'), 'utf8'));
  ok('Claude covers Bash and native PowerShell with 120s timeout', claudeSettings.hooks.PreToolUse.some(group => group.matcher === 'Bash|PowerShell' && group.hooks.some(handler => handler.timeout === 120)));
  const claudeManagedHandler = managedHandler(claudeSettings.hooks.PreToolUse.find(group => group.matcher === 'Bash|PowerShell'));
  const poisonedPathHook = spawnSync(claudeManagedHandler.command, claudeManagedHandler.args, {
    cwd: process.cwd(),
    env: { ...process.env, HOME: hookHome, USERPROFILE: hookHome, PATH: '/dcheck/path-does-not-exist' },
    input: JSON.stringify({ cwd: process.cwd(), hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git status' } }),
    encoding: 'utf8',
  });
  ok('managed hook runs with a poisoned PATH because Node is absolute', poisonedPathHook.status === 0);
  ok('pre-existing Claude hook is preserved', claudeSettings.hooks.Stop[0].hooks[0].command === 'echo keep');
  const geminiSettings = JSON.parse(fs.readFileSync(path.join(hookHome, '.gemini', 'settings.json'), 'utf8'));
  ok('Gemini uses BeforeTool run_shell_command hook with 120s timeout', geminiSettings.hooks.BeforeTool.some(group => group.matcher === '^run_shell_command$' && group.hooks.some(handler => handler.timeout === 120000)));
  const antigravityFile = path.join(hookHome, '.gemini', 'antigravity-cli', 'hooks.json');
  const antigravityHooks = JSON.parse(fs.readFileSync(antigravityFile, 'utf8'));
  const antigravityEntry = antigravityHooks['dorms-check-security-gate'];
  ok('Antigravity writes a named hooks.json PreToolUse run_command hook with 120s timeout and a created config dir', antigravityEntry?.enabled === true
    && antigravityEntry.PreToolUse.some(group => group.matcher === 'run_command'
      && group.hooks.some(handler => handler.type === 'command' && handler.timeout === 120 && String(handler.command).includes('vercel-guard.cjs'))));
  const antigravityGuard = path.join(hookHome, '.dorms-check', 'hooks', 'vercel-guard.cjs');
  const antigravityAllow = runGuardInput(antigravityGuard, process.cwd(), hookHome, {
    toolCall: { name: 'run_command', args: { CommandLine: 'git status', Cwd: process.cwd(), WaitMsBeforeAsync: 5000 } },
    stepIdx: 1,
  });
  ok('Antigravity-shaped input allows a non-Vercel command with a JSON allow decision', antigravityAllow.status === 0
    && /"decision":"allow"/.test(antigravityAllow.stdout), antigravityAllow.stderr);
  const antigravityDeny = runGuardInput(antigravityGuard, process.cwd(), hookHome, {
    toolCall: { name: 'run_command', args: { CommandLine: 'vercel promote https://dcheck-hook-challenge.invalid', Cwd: process.cwd() } },
  });
  ok('Antigravity-shaped input denies an unscanned promote with a JSON deny decision and exit 2', antigravityDeny.status === 2
    && /"decision":"deny"/.test(antigravityDeny.stdout), antigravityDeny.stdout + antigravityDeny.stderr);
  const antigravityWrongTool = runGuardInput(antigravityGuard, process.cwd(), hookHome, {
    toolCall: { name: 'view_file', args: { CommandLine: 'vercel promote https://dcheck-hook-challenge.invalid' } },
  });
  ok('Antigravity input with an unexpected tool name is denied fail-closed', antigravityWrongTool.status === 2 && /"decision":"deny"/.test(antigravityWrongTool.stdout));
  const installedAgain = installHooks({ homeDir: hookHome });
  ok('second install is idempotent', Object.values(installedAgain.changes).every(change => change.changed === false));
  ok('config backups were created outside agent config dirs', fs.existsSync(path.join(hookHome, '.dorms-check', 'backups')));
  const installedGuard = path.join(hookHome, '.dorms-check', 'hooks', 'vercel-guard.cjs');
  fs.appendFileSync(installedGuard, '\n// tampered\n');
  ok('tampered common guard makes all hooks unconfigured', Object.values(hookStatus({ homeDir: hookHome }).agents).every(agent => !agent.configured));
  installHooks({ homeDir: hookHome });
  ok('reinstall repairs common guard integrity', hookStatus({ homeDir: hookHome }).source.valid);
  if (process.platform !== 'win32') {
    const symlinkGuardHome = tempDir('dcheck-hooks-symlink-guard-');
    installHooks({ agents: 'codex', homeDir: symlinkGuardHome });
    const symlinkGuard = path.join(symlinkGuardHome, '.dorms-check', 'hooks', 'vercel-guard.cjs');
    const symlinkGuardTarget = path.join(symlinkGuardHome, 'external-guard.cjs');
    fs.writeFileSync(symlinkGuardTarget, 'module.exports = {};\n');
    fs.unlinkSync(symlinkGuard);
    fs.symlinkSync(symlinkGuardTarget, symlinkGuard);
    const symlinkSourceStatus = hookStatus({ homeDir: symlinkGuardHome });
    let symlinkGuardInstallError = null;
    try { installHooks({ agents: 'codex', homeDir: symlinkGuardHome }); } catch (error) { symlinkGuardInstallError = error; }
    ok('symlinked managed guard is unconfigured and never silently replaced', symlinkSourceStatus.source.valid === false
      && symlinkSourceStatus.source.entries['vercel-guard.cjs'].present === true
      && Boolean(symlinkSourceStatus.source.entries['vercel-guard.cjs'].error)
      && symlinkGuardInstallError?.exitCode === STRICT_EXIT.USAGE_CONFIG
      && fs.lstatSync(symlinkGuard).isSymbolicLink());
  }
  fs.writeFileSync(path.join(hookHome, '.codex', 'config.toml'), fs.readFileSync(path.join(hookHome, '.codex', 'config.toml'), 'utf8').replace('matcher = "^Bash$"', 'matcher = "^Other$"'));
  ok('tampered Codex matcher is not reported configured', hookStatus({ homeDir: hookHome }).agents.codex.configured === false);
  installHooks({ agents: 'codex', homeDir: hookHome });
  ok('reinstall repairs exact Codex hook configuration without claiming activation', hookStatus({ homeDir: hookHome }).agents.codex.configured === true && hookStatus({ homeDir: hookHome }).agents.codex.activation === 'unknown');

  const schemaClaudeFile = path.join(hookHome, '.claude', 'settings.json');
  const schemaGeminiFile = path.join(hookHome, '.gemini', 'settings.json');
  const schemaClaude = JSON.parse(fs.readFileSync(schemaClaudeFile, 'utf8'));
  const schemaGemini = JSON.parse(fs.readFileSync(schemaGeminiFile, 'utf8'));
  const managedClaude = managedHandler(schemaClaude.hooks.PreToolUse.find(group => group.matcher === 'Bash|PowerShell'));
  const managedGemini = managedHandler(schemaGemini.hooks.BeforeTool.find(group => group.matcher === '^run_shell_command$'));
  managedClaude.timeout = 10;
  managedClaude.async = true;
  managedGemini.timeout = 10;
  managedGemini.name = 'tampered';
  fs.writeFileSync(schemaClaudeFile, JSON.stringify(schemaClaude, null, 2));
  fs.writeFileSync(schemaGeminiFile, JSON.stringify(schemaGemini, null, 2));
  const tamperedSchemaStatus = hookStatus({ homeDir: hookHome });
  ok('tampered Claude async/timeout is never reported configured', tamperedSchemaStatus.agents.claude.installed === false && tamperedSchemaStatus.agents.claude.configured === false);
  ok('tampered Gemini timeout/name is never reported configured', tamperedSchemaStatus.agents.gemini.installed === false && tamperedSchemaStatus.agents.gemini.configured === false);
  installHooks({ agents: 'claude,gemini', homeDir: hookHome });
  ok('reinstall repairs exact Claude and Gemini managed handler schemas', hookStatus({ homeDir: hookHome }).agents.claude.configured && hookStatus({ homeDir: hookHome }).agents.gemini.configured);
  const tamperedAntigravity = JSON.parse(fs.readFileSync(antigravityFile, 'utf8'));
  tamperedAntigravity['dorms-check-security-gate'].PreToolUse[0].matcher = 'view_file';
  fs.writeFileSync(antigravityFile, JSON.stringify(tamperedAntigravity, null, 2));
  ok('tampered Antigravity matcher is never reported configured', hookStatus({ homeDir: hookHome }).agents.antigravity.configured === false);
  const disabledAntigravity = JSON.parse(fs.readFileSync(antigravityFile, 'utf8'));
  disabledAntigravity['dorms-check-security-gate'].PreToolUse[0].matcher = 'run_command';
  disabledAntigravity['dorms-check-security-gate'].enabled = false;
  disabledAntigravity['keep-me'] = { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'echo keep' }] }] };
  fs.writeFileSync(antigravityFile, JSON.stringify(disabledAntigravity, null, 2));
  ok('disabled Antigravity entry is reported disabled and not configured', hookStatus({ homeDir: hookHome }).agents.antigravity.disabled === true && hookStatus({ homeDir: hookHome }).agents.antigravity.configured === false);
  installHooks({ agents: 'antigravity', homeDir: hookHome });
  const repairedAntigravity = JSON.parse(fs.readFileSync(antigravityFile, 'utf8'));
  ok('reinstall repairs Antigravity hooks.json and preserves unrelated named hooks', hookStatus({ homeDir: hookHome }).agents.antigravity.configured === true
    && repairedAntigravity['keep-me']?.PreToolUse?.[0]?.hooks?.[0]?.command === 'echo keep');
  uninstallHooks({ agents: 'antigravity', homeDir: hookHome });
  const uninstalledAntigravity = JSON.parse(fs.readFileSync(antigravityFile, 'utf8'));
  ok('Antigravity uninstall removes only the managed entry', uninstalledAntigravity['dorms-check-security-gate'] === undefined
    && uninstalledAntigravity['keep-me']?.PreToolUse?.[0]?.hooks?.[0]?.command === 'echo keep'
    && hookStatus({ homeDir: hookHome }).agents.antigravity.managedPresent === false);
  installHooks({ agents: 'antigravity', homeDir: hookHome });

  const switchedNodeHome = tempDir('dcheck-hooks-node-switch-');
  installHooks({ homeDir: switchedNodeHome });
  const alternateNode = path.join(switchedNodeHome, 'alternate-node');
  fs.linkSync(fs.realpathSync(process.execPath), alternateNode);
  const switchedStatus = hookStatus({ homeDir: switchedNodeHome, nodeExecutable: alternateNode });
  ok('status validates each recorded absolute Node independently of the current Node path', Object.values(switchedStatus.agents).every(agent => agent.configured
    && agent.managedNodeExecutableVerified
    && agent.managedNodeExecutable === fs.realpathSync(process.execPath))
    && switchedStatus.nodeExecutable === fs.realpathSync(alternateNode));
  const switchedUninstall = uninstallHooks({ agents: 'codex', homeDir: switchedNodeHome, nodeExecutable: alternateNode });
  ok('partial uninstall after a Node switch preserves other configured hooks and shared guard files', switchedUninstall.status.agents.codex.managedPresent === false
    && switchedUninstall.status.agents.claude.configured
    && switchedUninstall.status.agents.gemini.configured
    && switchedUninstall.status.agents.antigravity.configured
    && fs.existsSync(path.join(switchedNodeHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));
  const switchedClaudeFile = path.join(switchedNodeHome, '.claude', 'settings.json');
  const switchedClaude = JSON.parse(fs.readFileSync(switchedClaudeFile, 'utf8'));
  managedHandler(switchedClaude.hooks.PreToolUse.find(group => group.matcher === 'Bash|PowerShell')).timeout = 1;
  fs.writeFileSync(switchedClaudeFile, JSON.stringify(switchedClaude, null, 2));
  const switchedGeminiUninstall = uninstallHooks({ agents: 'gemini', homeDir: switchedNodeHome, nodeExecutable: alternateNode });
  ok('a tampered remaining managed handler still preserves shared guard files', switchedGeminiUninstall.status.agents.claude.managedPresent === true
    && switchedGeminiUninstall.status.agents.claude.configured === false
    && fs.existsSync(path.join(switchedNodeHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));
  const switchedClaudeUninstall = uninstallHooks({ agents: 'claude', homeDir: switchedNodeHome, nodeExecutable: alternateNode });
  ok('a remaining Antigravity managed handler still preserves shared guard files', switchedClaudeUninstall.status.agents.claude.managedPresent === false
    && switchedClaudeUninstall.status.agents.antigravity.configured === true
    && fs.existsSync(path.join(switchedNodeHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));
  const switchedAntigravityUninstall = uninstallHooks({ agents: 'antigravity', homeDir: switchedNodeHome, nodeExecutable: alternateNode });
  ok('shared guard files are removed only after the final managed handler is removed', switchedAntigravityUninstall.status.agents.antigravity.managedPresent === false
    && !fs.existsSync(path.join(switchedNodeHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));

  const malformedRemainingHome = tempDir('dcheck-hooks-malformed-remaining-');
  installHooks({ homeDir: malformedRemainingHome });
  const malformedRemainingClaudeFile = path.join(malformedRemainingHome, '.claude', 'settings.json');
  fs.appendFileSync(malformedRemainingClaudeFile, '{ malformed');
  const malformedRemainingUninstall = uninstallHooks({ agents: 'codex,gemini', homeDir: malformedRemainingHome });
  ok('an unselected malformed config containing a managed hook preserves shared guard files', malformedRemainingUninstall.status.agents.claude.managedPresent === true
    && Boolean(malformedRemainingUninstall.status.agents.claude.parseError)
    && fs.existsSync(path.join(malformedRemainingHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));

  const markerOnlyHome = tempDir('dcheck-hooks-marker-only-');
  installHooks({ agents: 'gemini', homeDir: markerOnlyHome });
  const markerOnlyFile = path.join(markerOnlyHome, '.gemini', 'settings.json');
  const markerOnlySettings = JSON.parse(fs.readFileSync(markerOnlyFile, 'utf8'));
  markerOnlySettings.hooks.BeforeTool[0].hooks[0].command = 'echo tampered';
  fs.writeFileSync(markerOnlyFile, JSON.stringify(markerOnlySettings, null, 2));
  const markerOnlyUninstall = uninstallHooks({ agents: 'gemini', homeDir: markerOnlyHome });
  ok('uninstall removes a tampered Gemini handler identified by its managed name and description', markerOnlyUninstall.status.agents.gemini.managedPresent === false
    && !fs.existsSync(path.join(markerOnlyHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));

  const movedEventHome = tempDir('dcheck-hooks-moved-event-');
  installHooks({ agents: 'claude', homeDir: movedEventHome });
  const movedEventFile = path.join(movedEventHome, '.claude', 'settings.json');
  const movedEventSettings = JSON.parse(fs.readFileSync(movedEventFile, 'utf8'));
  movedEventSettings.hooks.AfterTool = movedEventSettings.hooks.PreToolUse;
  delete movedEventSettings.hooks.PreToolUse;
  fs.writeFileSync(movedEventFile, JSON.stringify(movedEventSettings, null, 2));
  const movedEventUninstall = uninstallHooks({ agents: 'claude', homeDir: movedEventHome });
  ok('uninstall removes managed JSON handlers even when tampered into another event', movedEventUninstall.status.agents.claude.managedPresent === false
    && !fs.existsSync(path.join(movedEventHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));

  const markerlessCodexHome = tempDir('dcheck-hooks-markerless-codex-');
  installHooks({ agents: 'codex', homeDir: markerlessCodexHome });
  const markerlessCodexFile = path.join(markerlessCodexHome, '.codex', 'config.toml');
  fs.writeFileSync(markerlessCodexFile, fs.readFileSync(markerlessCodexFile, 'utf8')
    .replace(/^# >>> dorms-check-security-only >>>\n/m, '')
    .replace(/^# <<< dorms-check-security-only <<<\n?/m, ''));
  const markerlessCodexUninstall = uninstallHooks({ agents: 'codex', homeDir: markerlessCodexHome });
  ok('markerless Codex residue is not falsely reported removed and preserves shared guard files', markerlessCodexUninstall.status.agents.codex.managedPresent === true
    && markerlessCodexUninstall.status.agents.codex.installed === true
    && fs.existsSync(path.join(markerlessCodexHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));

  const overrideHome = tempDir('dcheck-hooks-override-home-');
  const codexRoot = path.join(tempDir('dcheck-codex-config-'), 'root');
  const claudeRoot = path.join(tempDir('dcheck-claude-config-'), 'root');
  const geminiHome = path.join(tempDir('dcheck-gemini-home-'), 'root');
  const overrideEnvironment = { CODEX_HOME: codexRoot, CLAUDE_CONFIG_DIR: claudeRoot, GEMINI_CLI_HOME: geminiHome };
  const overrideInstall = installHooks({ homeDir: overrideHome, environment: overrideEnvironment });
  ok('custom agent homes receive configs at each official path', fs.existsSync(path.join(codexRoot, 'config.toml'))
    && fs.existsSync(path.join(claudeRoot, 'settings.json'))
    && fs.existsSync(path.join(geminiHome, '.gemini', 'settings.json'))
    && !fs.existsSync(path.join(overrideHome, '.codex', 'config.toml')));
  ok('status exposes each resolved custom config root and source', overrideInstall.status.agents.codex.configRoot === codexRoot
    && overrideInstall.status.agents.codex.configRootSource === 'CODEX_HOME'
    && overrideInstall.status.agents.claude.configRoot === claudeRoot
    && overrideInstall.status.agents.claude.configRootSource === 'CLAUDE_CONFIG_DIR'
    && overrideInstall.status.agents.gemini.configRoot === path.join(geminiHome, '.gemini')
    && overrideInstall.status.agents.gemini.configRootSource === 'GEMINI_CLI_HOME');
  const overrideUninstall = uninstallHooks({ homeDir: overrideHome, environment: overrideEnvironment });
  ok('custom-root uninstall removes all managed entries through the same resolved paths', Object.values(overrideUninstall.status.agents).every(agent => !agent.installed));
  let invalidOverrideError = null;
  const invalidOverrideHome = tempDir('dcheck-hooks-invalid-override-');
  try { installHooks({ agents: 'codex', homeDir: invalidOverrideHome, environment: { CODEX_HOME: 'relative/config' } }); }
  catch (error) { invalidOverrideError = error; }
  ok('relative custom config root fails before guard or config writes', invalidOverrideError?.exitCode === STRICT_EXIT.USAGE_CONFIG
    && !fs.existsSync(path.join(invalidOverrideHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));

  if (process.platform !== 'win32') {
    const symlinkConfigHome = tempDir('dcheck-hooks-symlink-config-');
    const symlinkTarget = path.join(symlinkConfigHome, 'real-codex.toml');
    fs.writeFileSync(symlinkTarget, 'model = "preserve"\n');
    fs.mkdirSync(path.join(symlinkConfigHome, '.codex'), { recursive: true });
    const symlinkConfig = path.join(symlinkConfigHome, '.codex', 'config.toml');
    fs.symlinkSync(symlinkTarget, symlinkConfig);
    let symlinkConfigError = null;
    try { installHooks({ agents: 'codex', homeDir: symlinkConfigHome }); } catch (error) { symlinkConfigError = error; }
    const symlinkStatus = hookStatus({ homeDir: symlinkConfigHome }).agents.codex;
    ok('symlinked agent config fails before writes without replacing the link target', symlinkConfigError?.exitCode === STRICT_EXIT.USAGE_CONFIG
      && fs.lstatSync(symlinkConfig).isSymbolicLink()
      && fs.readFileSync(symlinkTarget, 'utf8') === 'model = "preserve"\n'
      && Boolean(symlinkStatus.parseError)
      && symlinkStatus.managedPresent === true
      && !fs.existsSync(path.join(symlinkConfigHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));
  }

  const unsafePathHome = tempDir('dcheck-hooks-safe-parent-');
  const unsafeHome = path.join(unsafePathHome, 'home$expanded');
  let unsafePathError = null;
  try { installHooks({ agents: 'codex', homeDir: unsafeHome }); } catch (error) { unsafePathError = error; }
  ok('hook paths with cross-shell expansion metacharacters fail before writes', unsafePathError?.exitCode === STRICT_EXIT.USAGE_CONFIG
    && !fs.existsSync(path.join(unsafeHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));

  const missingNodeHome = tempDir('dcheck-hooks-missing-node-');
  let missingNodeError = null;
  try { installHooks({ agents: 'codex', homeDir: missingNodeHome, nodeExecutable: path.join(missingNodeHome, 'missing-node') }); }
  catch (error) { missingNodeError = error; }
  ok('missing absolute Node executable aborts before guard or config writes', missingNodeError?.exitCode === STRICT_EXIT.USAGE_CONFIG
    && !fs.existsSync(path.join(missingNodeHome, '.dorms-check', 'hooks', 'vercel-guard.cjs'))
    && hookStatus({ homeDir: missingNodeHome, nodeExecutable: path.join(missingNodeHome, 'missing-node') }).nodeExecutableVerified === false);
  if (process.platform !== 'win32') {
    const nonNodeHome = tempDir('dcheck-hooks-non-node-');
    let nonNodeError = null;
    try { installHooks({ agents: 'codex', homeDir: nonNodeHome, nodeExecutable: '/bin/sh' }); }
    catch (error) { nonNodeError = error; }
    ok('an executable that is not Node is rejected before hook installation', nonNodeError?.exitCode === STRICT_EXIT.USAGE_CONFIG
      && !fs.existsSync(path.join(nonNodeHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));
  }

  const malformedCodexHome = tempDir('dcheck-hooks-malformed-codex-');
  fs.mkdirSync(path.join(malformedCodexHome, '.codex'), { recursive: true });
  const malformedCodexFile = path.join(malformedCodexHome, '.codex', 'config.toml');
  fs.writeFileSync(malformedCodexFile, 'model = [\n');
  const malformedCodexStatus = hookStatus({ homeDir: malformedCodexHome }).agents.codex;
  ok('malformed Codex TOML reports parseError and never configured', Boolean(malformedCodexStatus.parseError) && malformedCodexStatus.configured === false);
  let malformedCodexInstallError = null;
  try { installHooks({ agents: 'codex', homeDir: malformedCodexHome }); } catch (error) { malformedCodexInstallError = error; }
  ok('malformed Codex TOML aborts install before config or guard writes', malformedCodexInstallError?.exitCode === STRICT_EXIT.USAGE_CONFIG
    && fs.readFileSync(malformedCodexFile, 'utf8') === 'model = [\n'
    && !fs.existsSync(path.join(malformedCodexHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')));

  for (const featureName of ['hooks', 'codex_hooks']) {
    const disabledCodexHome = tempDir(`dcheck-hooks-disabled-codex-${featureName}-`);
    fs.mkdirSync(path.join(disabledCodexHome, '.codex'), { recursive: true });
    fs.writeFileSync(path.join(disabledCodexHome, '.codex', 'config.toml'), `[features]\n${featureName} = false\n`);
    installHooks({ agents: 'codex', homeDir: disabledCodexHome });
    const disabledCodexStatus = hookStatus({ homeDir: disabledCodexHome }).agents.codex;
    ok(`Codex ${featureName}=false is resolved as disabled`, disabledCodexStatus.disabled === true && disabledCodexStatus.configured === false);
  }
  for (const [name, text] of [
    ['dotted hooks', 'features.hooks = false\n'],
    ['dotted legacy alias', 'features.codex_hooks = false\n'],
    ['inline hooks', 'features = { hooks = false }\n'],
    ['inline legacy alias', 'features = { codex_hooks = false }\n'],
  ]) {
    const disabledCodexHome = tempDir(`dcheck-hooks-disabled-codex-${name.replace(/\W/g, '-')}-`);
    fs.mkdirSync(path.join(disabledCodexHome, '.codex'), { recursive: true });
    fs.writeFileSync(path.join(disabledCodexHome, '.codex', 'config.toml'), text);
    installHooks({ agents: 'codex', homeDir: disabledCodexHome });
    const disabledCodexStatus = hookStatus({ homeDir: disabledCodexHome }).agents.codex;
    ok(`Codex ${name} feature disable is resolved by the TOML parser`, disabledCodexStatus.disabled === true && disabledCodexStatus.configured === false);
  }

  for (const [name, hooksConfig] of [
    ['enabled=false', { enabled: false }],
    ['disabled hook name', { disabled: ['dorms-check security gate'] }],
  ]) {
    const disabledGeminiHome = tempDir(`dcheck-hooks-disabled-gemini-${name.replace(/\W/g, '-')}-`);
    fs.mkdirSync(path.join(disabledGeminiHome, '.gemini'), { recursive: true });
    fs.writeFileSync(path.join(disabledGeminiHome, '.gemini', 'settings.json'), JSON.stringify({ hooksConfig }, null, 2));
    installHooks({ agents: 'gemini', homeDir: disabledGeminiHome });
    const disabledGeminiStatus = hookStatus({ homeDir: disabledGeminiHome }).agents.gemini;
    ok(`Gemini hooksConfig ${name} is resolved as disabled`, disabledGeminiStatus.disabled === true && disabledGeminiStatus.configured === false);
  }

  const atomicInstallHome = tempDir('dcheck-hooks-atomic-install-');
  fs.mkdirSync(path.join(atomicInstallHome, '.codex'), { recursive: true });
  fs.mkdirSync(path.join(atomicInstallHome, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(atomicInstallHome, '.codex', 'config.toml'), 'model = "unchanged"\n');
  fs.writeFileSync(path.join(atomicInstallHome, '.claude', 'settings.json'), '{ malformed');
  let malformedInstallBlocked = false;
  try { installHooks({ homeDir: atomicInstallHome }); } catch { malformedInstallBlocked = true; }
  ok('malformed later config aborts install before earlier config writes', malformedInstallBlocked && fs.readFileSync(path.join(atomicInstallHome, '.codex', 'config.toml'), 'utf8') === 'model = "unchanged"\n');

  const failedWriteHome = tempDir('dcheck-hooks-failed-write-');
  fs.mkdirSync(path.join(failedWriteHome, '.codex', 'config.toml'), { recursive: true });
  let failedWriteBlocked = false;
  try { installHooks({ agents: 'codex', homeDir: failedWriteHome }); } catch { failedWriteBlocked = true; }
  ok('a config write failure restores shared guard files to their pre-install state', failedWriteBlocked
    && !fs.existsSync(path.join(failedWriteHome, '.dorms-check', 'hooks', 'vercel-guard.cjs'))
    && fs.statSync(path.join(failedWriteHome, '.codex', 'config.toml')).isDirectory());

  const atomicUninstallHome = tempDir('dcheck-hooks-atomic-uninstall-');
  fs.mkdirSync(path.join(atomicUninstallHome, '.codex'), { recursive: true });
  fs.mkdirSync(path.join(atomicUninstallHome, '.claude'), { recursive: true });
  fs.mkdirSync(path.join(atomicUninstallHome, '.gemini'), { recursive: true });
  installHooks({ homeDir: atomicUninstallHome });
  const atomicCodexBefore = fs.readFileSync(path.join(atomicUninstallHome, '.codex', 'config.toml'), 'utf8');
  fs.writeFileSync(path.join(atomicUninstallHome, '.gemini', 'settings.json'), '{ malformed');
  let malformedUninstallBlocked = false;
  try { uninstallHooks({ homeDir: atomicUninstallHome }); } catch { malformedUninstallBlocked = true; }
  ok('malformed later config aborts uninstall before earlier config writes', malformedUninstallBlocked && fs.readFileSync(path.join(atomicUninstallHome, '.codex', 'config.toml'), 'utf8') === atomicCodexBefore);

  console.log('\n[4] common guard positive and negative Vercel command cases');
  const guardRepo = initRepo('dcheck-hook-repo-');
  fs.writeFileSync(path.join(guardRepo, 'package.json'), JSON.stringify({ scripts: {
    'prod-direct': 'vercel --prod',
    'prod-staged': 'vercel --prod --skip-domain',
    'rollback-direct': 'vercel rollback dpl_ABCDEFGHIJ',
  } }, null, 2));
  for (const manager of ['npm-child', 'pnpm-child', 'yarn-child']) {
    fs.mkdirSync(path.join(guardRepo, manager), { recursive: true });
    fs.writeFileSync(path.join(guardRepo, manager, 'package.json'), JSON.stringify({ scripts: { deploy: 'vercel --prod' } }, null, 2));
  }
  fs.writeFileSync(path.join(guardRepo, 'deploy-production.sh'), 'vercel --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=0000000000000000000000000000000000000000\n');
  fs.writeFileSync(path.join(guardRepo, 'deploy.js'), 'require("node:child_process").execSync("vercel --prod")\n');
  fs.writeFileSync(path.join(guardRepo, 'ship-production'), '#!/bin/sh\nvercel rr complete\n');
  fs.chmodSync(path.join(guardRepo, 'ship-production'), 0o700);
  git(guardRepo, ['add', '.']);
  git(guardRepo, ['commit', '-qm', 'script and package fixtures']);
  const guardSha = git(guardRepo, ['rev-parse', 'HEAD']);
  const stagedCommand = `vercel --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${guardSha}`;
  writeReceipts(guardRepo, hookHome);
  const guardPath = installed.status.source.entries['vercel-guard.cjs'].present
    ? path.join(hookHome, '.dorms-check', 'hooks', 'vercel-guard.cjs')
    : '';
  const windowsHookHome = tempDir('dcheck-windows-hooks-home-');
  const windowsInstalled = installHooks({
    homeDir: windowsHookHome,
    platform: 'win32',
    vercelExecutable: windowsToolchain.vercel,
    powerShellExecutable: windowsToolchain.powerShell,
    vercelVersion: windowsToolchain.version,
  });
  writeReceipts(guardRepo, windowsHookHome);
  const windowsGuardPath = path.join(windowsHookHome, '.dorms-check', 'hooks', 'vercel-guard.cjs');
  const pinnedWindowsVercel = windowsInstalled.status.windowsVercelExecutable;
  const quotedPinnedWindowsVercel = `'${pinnedWindowsVercel.replaceAll("'", "''")}'`;
  const windowsStagedCommand = `& ${quotedPinnedWindowsVercel} --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${guardSha}`;
  ok('Windows install pins vercel.cmd, version, hash, and PowerShell in the managed manifest', windowsInstalled.status.windowsPowerShellSupported === true
    && windowsInstalled.status.windowsVercelVersion === '59.10.0'
    && windowsInstalled.status.windowsVercelExecutableVerified === true
    && path.basename(windowsInstalled.status.windowsVercelExecutable).toLowerCase() === 'vercel.cmd'
    && windowsInstalled.status.windowsVercelBackingExecutable === fs.realpathSync(windowsToolchain.vercel)
    && windowsInstalled.status.windowsVercelBackingExecutableSha256 === windowsToolchain.vercelSha256
    && windowsInstalled.status.windowsPowerShellExecutableSha256 === windowsToolchain.powerShellSha256);
  const windowsCodexText = fs.readFileSync(path.join(windowsHookHome, '.codex', 'config.toml'), 'utf8');
  ok('Codex Windows hook uses a quote-free CMD-compatible PowerShell EncodedCommand launcher', windowsCodexText.includes('-EncodedCommand ')
    && !windowsCodexText.includes(`command_windows = "&`));
  const windowsClaudeSettings = JSON.parse(fs.readFileSync(path.join(windowsHookHome, '.claude', 'settings.json'), 'utf8'));
  const windowsClaudeHandler = managedHandler(windowsClaudeSettings.hooks.PreToolUse.find(group => group.matcher === 'Bash|PowerShell'));
  ok('Claude Windows hook uses direct absolute Node exec form', windowsClaudeHandler.command === fs.realpathSync(process.execPath)
    && windowsClaudeHandler.args?.[0] === windowsGuardPath);
  const windowsGeminiSettings = JSON.parse(fs.readFileSync(path.join(windowsHookHome, '.gemini', 'settings.json'), 'utf8'));
  const windowsGeminiHandler = managedHandler(windowsGeminiSettings.hooks.BeforeTool.find(group => group.matcher === '^run_shell_command$'));
  ok('Gemini Windows hook uses the PowerShell call operator form', windowsGeminiHandler.command.startsWith("& '")
    && windowsGeminiHandler.command.includes('vercel-guard.cjs'));
  const windowsProxy = path.join(windowsHookHome, '.dorms-check', 'hooks', 'vercel-proxy.cjs');
  const runWindowsProxy = args => spawnSync(process.execPath, [windowsProxy, ...args], {
    cwd: guardRepo,
    env: {
      ...process.env,
      HOME: windowsHookHome,
      USERPROFILE: windowsHookHome,
      VERCEL_PROJECT_ID: '',
      VERCEL_ORG_ID: '',
      VERCEL_TEAM_ID: '',
      VERCEL_TOKEN: '',
    },
    encoding: 'utf8',
  });
  const proxyStaged = runWindowsProxy([
    '--prod', '--skip-domain', '--meta', 'githubDeployment=1', '--meta', `githubCommitSha=${guardSha}`, '--yes',
  ]);
  ok('managed Windows Vercel proxy permits receipt-bound staged deploy without relying on a host hook event', proxyStaged.status === 0, proxyStaged.stderr);
  ok('managed Windows Vercel proxy blocks a fake promote even when a host hook event does not fire', runWindowsProxy([
    'promote', 'https://dcheck-hook-challenge.invalid',
  ]).status === 2);
  const proxyPromote = runWindowsProxy([
    'promote', 'https://strict-fixture.vercel.app/',
  ]);
  ok('managed Windows Vercel proxy permits the exact receipt-bound promote without relying on a host hook event', proxyPromote.status === 0, proxyPromote.stderr);
  const discoveryHome = tempDir('dcheck-windows-discovery-home-');
  let discoveryScript = '';
  const discovered = installHooks({
    agents: 'codex',
    homeDir: discoveryHome,
    platform: 'win32',
    powerShellExecutable: windowsToolchain.powerShell,
    vercelVersion: windowsToolchain.version,
    execFileSync(file, args) {
      discoveryScript = String(args?.[4] || '');
      return windowsToolchain.vercel;
    },
  });
  ok('Windows install discovers the exact vercel.cmd application through Get-Command', discoveryScript.includes('Get-Command vercel -All -CommandType Application')
    && discoveryScript.includes("Name -ieq 'vercel.cmd'")
    && discovered.status.windowsVercelBackingExecutable === fs.realpathSync(windowsToolchain.vercel));
  for (const [name, payload] of [
    ['missing tool_input command', { cwd: guardRepo, tool_name: 'Bash', tool_input: {} }],
    ['object command', { cwd: guardRepo, tool_name: 'Bash', tool_input: { command: { text: 'git status' } } }],
    ['empty command', { cwd: guardRepo, tool_name: 'Bash', tool_input: { command: '   ' } }],
    ['missing tool name', { cwd: guardRepo, tool_input: { command: 'git status' } }],
  ]) {
    ok(`${name} hook payload fails closed`, runGuardInput(guardPath, guardRepo, hookHome, payload).status === 2);
  }
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
  ok('exact code receipt and two literal Git metadata values permit staged production', runGuard(guardPath, guardRepo, hookHome, stagedCommand, 'codex').status === 0);
  ok('unreviewed Vercel CLI version blocks an otherwise exact staged command', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    stagedCommand,
    'codex',
    '',
    { DCHECK_TEST_VERCEL_VERSION: '40.1.0' },
  ).status === 2);
  ok('vc shorthand is blocked so the probed and executed CLI cannot diverge', runGuard(guardPath, guardRepo, hookHome, `vc deploy --prod --skip-domain --meta githubCommitSha=${guardSha} --meta githubDeployment=1`, 'gemini').status === 2);
  ok('staged --yes is the only optional non-routing flag', runGuard(guardPath, guardRepo, hookHome, `${stagedCommand} --yes`, 'claude').status === 0);
  ok('native PowerShell permits the exact pinned absolute vercel.cmd staged command', runGuard(
    windowsGuardPath,
    guardRepo,
    windowsHookHome,
    windowsStagedCommand,
    'claude',
    'PowerShell',
  ).status === 0);
  ok('native PowerShell permits the exact pinned absolute vercel.cmd staged command with --yes', runGuard(
    windowsGuardPath,
    guardRepo,
    windowsHookHome,
    `${windowsStagedCommand} --yes`,
    'claude',
    'PowerShell',
  ).status === 0);
  const caseChangedWindowsVercel = pinnedWindowsVercel.replace(/vercel\.cmd$/, 'VERCEL.cmd');
  ok('native PowerShell rejects even a case-variant of the status-pinned vercel.cmd path', runGuard(
    windowsGuardPath,
    guardRepo,
    windowsHookHome,
    `& '${caseChangedWindowsVercel.replaceAll("'", "''")}' --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${guardSha}`,
    'claude',
    'PowerShell',
  ).status === 2);
  ok('native PowerShell rejects a bare vercel staged command even with a valid receipt', runGuard(
    windowsGuardPath,
    guardRepo,
    windowsHookHome,
    stagedCommand,
    'claude',
    'PowerShell',
  ).status === 2);
  ok('PowerShell does not block dorms-check provider arguments that merely name Vercel', runGuard(
    windowsGuardPath,
    guardRepo,
    windowsHookHome,
    'dcheck hooks status --provider vercel --json',
    'claude',
    'PowerShell',
  ).status === 0);
  ok('PowerShell does not block non-executing Git text searches for Vercel', runGuard(
    windowsGuardPath,
    guardRepo,
    windowsHookHome,
    'git log --grep vercel',
    'claude',
    'PowerShell',
  ).status === 0);
  ok('duplicate staged flags are rejected', runGuard(guardPath, guardRepo, hookHome, `${stagedCommand} --yes --yes`, 'claude').status === 2
    && runGuard(guardPath, guardRepo, hookHome, `${stagedCommand} --prod`, 'codex').status === 2);
  fs.mkdirSync(path.join(guardRepo, 'deploy'), { recursive: true });
  ok('deploy directory cannot be smuggled as a duplicate deploy source token', runGuard(guardPath, guardRepo, hookHome, `vercel deploy deploy --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${guardSha}`, 'codex').status === 2);
  ok('foreign ambient Vercel project precedence blocks exact staged command', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    stagedCommand,
    'codex',
    '',
    { VERCEL_PROJECT_ID: 'prj_foreign', VERCEL_ORG_ID: 'team_foreign' },
  ).status === 2);
  ok('Windows-style case-insensitive lowercase Vercel overrides also block exact staged command', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    stagedCommand,
    'codex',
    '',
    { vercel_project_id: 'prj_foreign', vercel_org_id: 'team_foreign' },
  ).status === 2);
  ok('foreign ambient Vercel team precedence blocks exact staged command', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    stagedCommand,
    'codex',
    '',
    { VERCEL_TEAM_ID: 'team_foreign' },
  ).status === 2);
  ok('ambient Vercel token override blocks exact staged command', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    stagedCommand,
    'codex',
    '',
    { VERCEL_TOKEN: 'fixture-token' },
  ).status === 2);
  const guardLinkFile = path.join(guardRepo, '.vercel', 'project.json');
  const guardLinkBefore = fs.readFileSync(guardLinkFile, 'utf8');
  fs.writeFileSync(guardLinkFile, JSON.stringify({ projectId: 'prj_foreign', orgId: 'team_foreign', projectName: 'foreign' }, null, 2));
  ok('ignored Vercel relink after code receipt blocks exact staged command', runGuard(guardPath, guardRepo, hookHome, stagedCommand, 'codex').status === 2);
  fs.writeFileSync(guardLinkFile, guardLinkBefore);
  ok('missing Git metadata blocks staged production', runGuard(guardPath, guardRepo, hookHome, 'vercel --prod --skip-domain', 'codex').status === 2);
  ok('fake Git SHA metadata blocks staged production', runGuard(guardPath, guardRepo, hookHome, 'vercel --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=0000000000000000000000000000000000000000', 'codex').status === 2);
  ok('missing githubDeployment metadata blocks staged production', runGuard(guardPath, guardRepo, hookHome, `vercel --prod --skip-domain --meta githubCommitSha=${guardSha}`, 'codex').status === 2);
  ok('extra metadata blocks staged production', runGuard(guardPath, guardRepo, hookHome, `${stagedCommand} --meta extra=value`, 'codex').status === 2);
  for (const [name, command] of [
    ['prebuilt', `${stagedCommand} --prebuilt`],
    ['archive', `${stagedCommand} --archive=tgz`],
    ['local-config', `${stagedCommand} --local-config /tmp/evil-vercel.json`],
    ['cwd', `${stagedCommand} --cwd .`],
    ['project', `${stagedCommand} --project foreign`],
    ['scope', `${stagedCommand} --scope foreign`],
    ['runtime env', `${stagedCommand} --env SECRET=x`],
    ['build env', `${stagedCommand} --build-env SECRET=x`],
  ]) {
    ok(`${name} source/artifact override is blocked`, runGuard(guardPath, guardRepo, hookHome, command, 'codex').status === 2);
  }
  ok('npx staged wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, `npx -y vercel@latest --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${guardSha}`, 'codex').status === 2);
  ok('pnpm staged wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, `pnpm dlx vercel --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${guardSha}`, 'gemini').status === 2);
  ok('bunx promote wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, 'bunx vercel promote https://strict-fixture.vercel.app/', 'claude').status === 2);
  ok('npm staged package script is blocked even when recursively visible', runGuard(guardPath, guardRepo, hookHome, 'npm run prod-staged', 'claude').status === 2);
  writeReceipts(guardRepo, hookHome, { deploymentId: 'dpl_fixture123' });
  ok('exact live receipt permits direct literal URL promote', runGuard(guardPath, guardRepo, hookHome, 'vercel promote "https://strict-fixture.vercel.app/"', 'claude').status === 0);
  ok('native PowerShell exact pinned vercel.cmd permits receipt-bound promote', runGuard(
    windowsGuardPath,
    guardRepo,
    windowsHookHome,
    `& ${quotedPinnedWindowsVercel} promote https://strict-fixture.vercel.app/`,
    'claude',
    'PowerShell',
  ).status === 0);
  ok('native PowerShell blocks promote through a different absolute vercel.cmd', runGuard(
    windowsGuardPath,
    guardRepo,
    windowsHookHome,
    `& 'C:\\foreign\\vercel.cmd' promote https://strict-fixture.vercel.app/`,
    'claude',
    'PowerShell',
  ).status === 2);
  ok('verified deployment ID receipt permits exact ID promote', runGuard(guardPath, guardRepo, hookHome, 'vercel promote dpl_fixture123', 'codex').status === 0);
  ok('shell-variable promote target is blocked before expansion', runGuard(guardPath, guardRepo, hookHome, 'vercel promote "$DEPLOYMENT_URL"', 'codex').status === 2);
  ok('promote project/config override flags are blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel promote dpl_fixture123 --scope foreign', 'codex').status === 2);
  ok('different promote target is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel promote https://other.vercel.app/', 'codex').status === 2);
  ok('a later mismatched promote in one compound command is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel promote dpl_fixture123 && vercel promote https://other.vercel.app/', 'codex').status === 2);
  ok('alias-set bypass is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel alias set https://strict-fixture.vercel.app production.example', 'gemini').status === 2);
  ok('legacy alias mutation is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel alias https://strict-fixture.vercel.app production.example', 'codex').status === 2);
  ok('alias remove mutation is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel alias remove production.example', 'claude').status === 2);
  ok('literal alias list remains read-only', runGuard(guardPath, guardRepo, hookHome, 'vercel alias list', 'gemini').status === 0);
  for (const [name, command] of [
    ['domains add', 'vercel domains add example.com my-project'],
    ['domains force add', 'vercel domains add example.com my-project --force'],
    ['mutator with help-like value', 'vercel domains add example.com --help'],
    ['domains remove', 'vercel domains rm example.com'],
    ['DNS add', 'vercel dns add example.com www CNAME cname.example.com'],
    ['environment add', 'vercel env add SECRET production'],
    ['project remove', 'vercel project rm my-project'],
    ['project relink', 'vercel link --yes --project prj_foreign'],
    ['team switch', 'vercel switch other-team'],
    ['Git connect', 'vercel git connect --yes'],
    ['feature flag enable', 'vercel flags enable launch --environment production'],
    ['webhook create', 'vercel webhooks create https://evil.example/hook --event deployment.created'],
    ['routes publish', 'vercel routes publish'],
    ['routes restore', 'vercel routes restore snapshot'],
    ['rolling-release alias start', 'vercel rr start --dpl dpl_fixture123'],
    ['rolling-release alias approve', 'vercel rr approve'],
    ['rolling-release alias complete', 'vercel rr complete'],
    ['firewall publish', 'vercel firewall publish'],
    ['firewall bypass add', 'vercel firewall system-bypass add 203.0.113.1'],
    ['redirect restore', 'vercel redirects restore snapshot'],
    ['deploy hook create', 'vercel deploy-hooks create main'],
    ['preview deploy', 'vercel deploy'],
    ['implicit preview deploy', 'vercel'],
  ]) {
    ok(`${name} mutation outside the strict flow is blocked`, runGuard(guardPath, guardRepo, hookHome, command, 'codex').status === 2);
  }
  for (const [name, command] of [
    ['domains list', 'vercel domains ls'],
    ['domain inspect', 'vercel domains inspect example.com'],
    ['DNS list', 'vercel dns ls example.com'],
    ['environment list', 'vercel env ls'],
    ['project inspect', 'vercel project inspect my-project'],
    ['Git list', 'vercel git ls'],
    ['webhook get', 'vercel webhooks get hook_fixture'],
    ['whoami', 'vercel whoami'],
    ['version', 'vercel --version'],
  ]) {
    ok(`${name} is an explicit read-only command`, runGuard(guardPath, guardRepo, hookHome, command, 'gemini').status === 0);
  }
  const rollbackRegression = evaluateVercelCommand('vercel rollback dpl_ABCDEFGHIJ', guardRepo, { homeDir: hookHome });
  ok('direct evaluator blocks every non-readonly rollback', rollbackRegression.relevant && !rollbackRegression.allowed);
  ok('bare rollback that auto-selects a previous deployment is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel rollback', 'codex').status === 2);
  ok('direct rollback to an unverified deployment is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel rollback dpl_ABCDEFGHIJ', 'codex').status === 2);
  ok('npx rollback wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, 'npx -y vercel@latest rollback dpl_ABCDEFGHIJ', 'claude').status === 2);
  ok('nested-shell rollback is blocked', runGuard(guardPath, guardRepo, hookHome, 'bash -c "vercel rollback dpl_ABCDEFGHIJ"', 'gemini').status === 2);
  ok('package script rollback is blocked', runGuard(guardPath, guardRepo, hookHome, 'npm run rollback-direct', 'codex').status === 2);
  ok('compound rollback is blocked', runGuard(guardPath, guardRepo, hookHome, 'echo ready && /usr/local/bin/vercel rollback dpl_ABCDEFGHIJ', 'claude').status === 2);
  ok('even an exact receipt cannot auto-authorize rollback', runGuard(guardPath, guardRepo, hookHome, 'vercel rollback https://strict-fixture.vercel.app/', 'codex').status === 2);
  ok('wrapped exact-ID rollback is blocked', runGuard(guardPath, guardRepo, hookHome, 'pnpm exec vercel rollback dpl_fixture123', 'gemini').status === 2);
  ok('rollback status remains read-only and permitted', runGuard(guardPath, guardRepo, hookHome, 'vercel rollback status', 'claude').status === 0);
  ok('a later mismatched rollback in one compound command is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel rollback dpl_fixture123 && vercel rollback dpl_ABCDEFGHIJ', 'codex').status === 2);
  ok('redeploy is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel redeploy dpl_fixture123', 'codex').status === 2);
  ok('rolling release is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel rolling-release start --dpl dpl_fixture123', 'claude').status === 2);
  ok('arbitrary Vercel API is blocked', runGuard(guardPath, guardRepo, hookHome, 'vercel api /v2/aliases -X POST', 'gemini').status === 2);
  ok('variable-assigned Vercel staged command is blocked', runGuard(guardPath, guardRepo, hookHome, `V=vercel; $V --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${guardSha}`, 'codex').status === 2);
  ok('braced variable promote is blocked', runGuard(guardPath, guardRepo, hookHome, 'V=vercel; ${V} promote dpl_fixture123', 'claude').status === 2);
  ok('env variable rollback is blocked', runGuard(guardPath, guardRepo, hookHome, 'env V=vercel $V rollback dpl_ABCDEFGHIJ', 'gemini').status === 2);
  ok('command-generated Vercel rollback is blocked', runGuard(guardPath, guardRepo, hookHome, '$(printf vercel) rollback dpl_ABCDEFGHIJ', 'codex').status === 2);
  ok('command-generated unknown Vercel write is blocked', runGuard(guardPath, guardRepo, hookHome, '$(printf vercel) storage create production-store', 'codex').status === 2);
  ok('octal-obfuscated command-substitution rr executable is blocked', runGuard(guardPath, guardRepo, hookHome, "$(printf '\\166\\145\\162\\143\\145\\154') rr complete", 'codex').status === 2);
  ok('command-substitution variable executable for domains is blocked', runGuard(guardPath, guardRepo, hookHome, "V=$(printf '\\166\\145\\162\\143\\145\\154'); \"$V\" domains add example.com my-project", 'claude').status === 2);
  ok('command-substitution variable executable for flags is blocked', runGuard(guardPath, guardRepo, hookHome, "V=$(printf '\\166\\145\\162\\143\\145\\154'); \"$V\" flags enable launch --environment production", 'gemini').status === 2);
  ok('unknown dynamic executable is blocked even without a recognized Vercel verb', runGuard(guardPath, guardRepo, hookHome, '$TOOL storage create production-store', 'codex').status === 2);
  ok('embedded variable executable and verb obfuscation is blocked', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    'X=erce; P=romot; v${X}l p${P}e https://evil.example',
    'codex',
  ).status === 2);
  ok('nested variable command string is blocked', runGuard(guardPath, guardRepo, hookHome, "export C=vercel; CMD='$C rollback dpl_ABCDEFGHIJ'; sh -c \"$CMD\"", 'claude').status === 2);
  for (const [name, body] of [
    ['rollback', '$C rollback dpl_ABCDEFGHIJ'],
    ['redeploy', '$C redeploy dpl_fixture123'],
    ['legacy alias', '$C alias dpl_fixture123 production.example'],
    ['api', '$C api /v2/aliases -X POST'],
    ['staged', `$C --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${guardSha}`],
  ]) {
    const generated = `export C=vercel; printf '%s\\n' '${body}' > /tmp/dcheck-generated.sh && bash /tmp/dcheck-generated.sh`;
    ok(`generated-script ${name} is blocked`, runGuard(guardPath, guardRepo, hookHome, generated, 'codex').status === 2);
  }
  ok('bash script wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, 'bash ./deploy-production.sh', 'codex').status === 2);
  ok('source script wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, '. ./deploy-production.sh', 'claude').status === 2);
  ok('node runtime script wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, 'node ./deploy.js', 'gemini').status === 2);
  ok('npm --prefix deploy script is resolved and blocked', runGuard(guardPath, guardRepo, hookHome, 'npm --prefix npm-child run deploy', 'codex').status === 2);
  ok('pnpm --dir deploy script is resolved and blocked', runGuard(guardPath, guardRepo, hookHome, 'pnpm --dir pnpm-child run deploy', 'claude').status === 2);
  ok('yarn --cwd deploy script is resolved and blocked', runGuard(guardPath, guardRepo, hookHome, 'yarn --cwd yarn-child deploy', 'gemini').status === 2);
  for (const [name, command] of [
    ['npm install lifecycle', 'npm install'],
    ['pnpm audit lifecycle', 'pnpm audit'],
    ['yarn install lifecycle', 'yarn install'],
    ['corepack package manager', 'corepack pnpm install'],
    ['npm workspace', 'npm --workspace npm-child run deploy'],
    ['npm short workspace', 'npm -w npm-child run deploy'],
    ['npm all workspaces', 'npm --workspaces run deploy'],
    ['pnpm filter run', 'pnpm --filter pnpm-child run deploy'],
    ['pnpm implicit filtered script', 'pnpm --filter pnpm-child deploy'],
    ['yarn workspace', 'yarn workspace yarn-child deploy'],
    ['bun filter', 'bun --filter ./npm-child run deploy'],
    ['make task', 'make deploy'],
    ['turbo task', 'turbo run deploy'],
  ]) {
    ok(`${name} launcher is blocked without attempting workspace grammar`, runGuard(guardPath, guardRepo, hookHome, command, 'codex').status === 2);
  }
  ok('extensionless local script containing Vercel mutation is blocked', runGuard(guardPath, guardRepo, hookHome, './ship-production', 'codex').status === 2);
  ok('shell-launched extensionless script containing Vercel mutation is blocked', runGuard(guardPath, guardRepo, hookHome, 'sh ./ship-production', 'claude').status === 2);
  ok('fully string-obfuscated Node child process is blocked at the runtime boundary', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    `node -e 'require("node:child_process").spawnSync(["ve","rcel"].join(""), ["--"+"prod"])'`,
    'codex',
  ).status === 2);
  ok('fully string-obfuscated Python child process is blocked at the runtime boundary', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    `python3 -c 'import subprocess; subprocess.run(["ve"+"rcel", "--"+"prod"])'`,
    'claude',
  ).status === 2);
  ok('fully string-obfuscated Perl child process is blocked at the runtime boundary', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    `perl -e 'system(join("", "ve", "rcel"), join("", "--", "prod"))'`,
    'gemini',
  ).status === 2);
  ok('xargs NUL-stream process launcher is blocked at the runtime boundary', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    "printf '\\166\\145\\162\\143\\145\\154\\0\\160\\162\\157\\155\\157\\164\\145\\0https://evil.example\\0' | xargs -0",
    'codex',
  ).status === 2);
  ok('awk system process launcher is blocked at the runtime boundary', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    "awk 'BEGIN { system(sprintf(\"%c%c%c%c%c%c\",118,101,114,99,101,108)) }'",
    'claude',
  ).status === 2);
  ok('busybox shell launcher is blocked at the runtime boundary', runGuard(guardPath, guardRepo, hookHome, "busybox sh -c 'echo hidden'", 'gemini').status === 2);
  ok('shell exec launcher is blocked at the runtime boundary', runGuard(guardPath, guardRepo, hookHome, 'exec ./ship-production', 'codex').status === 2);
  ok('privilege-switch launcher is blocked at the runtime boundary', runGuard(guardPath, guardRepo, hookHome, 'doas ./ship-production', 'claude').status === 2);
  ok('env split-string encoded launcher is blocked at the runtime boundary', runGuard(guardPath, guardRepo, hookHome, "env -S $'\\x76\\x65\\x72\\x63\\x65\\x6c --prod'", 'codex').status === 2);
  ok('Bash ANSI-C hex-quoted executable and verb are blocked', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    "$'\\x76\\x65\\x72\\x63\\x65\\x6c' $'\\x70\\x72\\x6f\\x6d\\x6f\\x74\\x65' https://evil.example",
    'codex',
  ).status === 2);
  ok('Bash ANSI-C octal-quoted executable and verb are blocked', runGuard(
    guardPath,
    guardRepo,
    hookHome,
    "$'\\166\\145\\162\\143\\145\\154' $'\\160\\162\\157\\155\\157\\164\\145' https://evil.example",
    'claude',
  ).status === 2);
  ok('renamed extensionless deploy wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, `./deploy --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${guardSha}`, 'codex').status === 2);
  ok('unknown absolute promote wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, '/tmp/ship promote dpl_fixture123', 'claude').status === 2);
  ok('renamed rollback wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, 'myvercel rollback dpl_fixture123', 'gemini').status === 2);
  ok('renamed rolling-release alias wrapper is blocked', runGuard(guardPath, guardRepo, hookHome, 'myvercel rr start --dpl dpl_fixture123', 'gemini').status === 2);
  ok('backslash-escaped executable is not treated as a literal Vercel command', runGuard(guardPath, guardRepo, hookHome, 'v\\e\\r\\c\\e\\l promote dpl_fixture123', 'codex').status === 2);
  ok('backslash-escaped mutator is not treated as a literal Vercel command', runGuard(guardPath, guardRepo, hookHome, 'vercel pro\\mote dpl_fixture123', 'claude').status === 2);
  ok('Windows caret-obfuscated Vercel executable and flag are blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, 'v^e^r^c^e^l --^prod', 'claude', 'PowerShell').status === 2);
  ok('cmd wrapper with caret-obfuscated Vercel is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, 'cmd /c v^e^r^c^e^l --^prod', 'claude', 'PowerShell').status === 2);
  ok('Windows caret-obfuscated rollback is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, 'v^e^r^c^e^l r^o^l^l^b^a^c^k dpl_fixture123', 'claude', 'PowerShell').status === 2);
  ok('Windows cmd percent-variable call is blocked', runGuard(
    windowsGuardPath,
    guardRepo,
    windowsHookHome,
    'call %A% %B% https://evil.example',
    'claude',
    'PowerShell',
    { A: 'vercel', B: 'promote' },
  ).status === 2);
  ok('Windows cmd delayed-variable call is blocked', runGuard(
    windowsGuardPath,
    guardRepo,
    windowsHookHome,
    'call !A! !B! https://evil.example',
    'claude',
    'PowerShell',
    { A: 'vercel', B: 'promote' },
  ).status === 2);
  ok('PowerShell backtick-obfuscated Vercel is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, 'v`ercel --prod', 'claude', 'PowerShell').status === 2);
  ok('PowerShell call-operator string-built promote is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, "& ('ver'+'cel') ('pro'+'mote') 'https://evil.example'", 'claude', 'PowerShell').status === 2);
  ok('PowerShell iex string-built promote is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, "iex ('ver'+'cel pro'+'mote https://evil.example')", 'claude', 'PowerShell').status === 2);
  ok('PowerShell Invoke-Expression string-built promote is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, "Invoke-Expression ('ver'+'cel pro'+'mote https://evil.example')", 'claude', 'PowerShell').status === 2);
  ok('PowerShell Start-Process string-built promote is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, "Start-Process ('ver'+'cel') -ArgumentList ('pro'+'mote'), 'https://evil.example'", 'claude', 'PowerShell').status === 2);
  ok('PowerShell type Concat dynamic executable is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, "& ([string]::Concat('ver','cel')) --prod", 'claude', 'PowerShell').status === 2);
  ok('PowerShell argument splatting is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, `& ${quotedPinnedWindowsVercel} @deployArgs`, 'claude', 'PowerShell').status === 2);
  ok('PowerShell stop-parsing token is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, `& ${quotedPinnedWindowsVercel} --% --prod`, 'claude', 'PowerShell').status === 2);
  ok('PowerShell compound command is blocked', runGuard(windowsGuardPath, guardRepo, windowsHookHome, `${windowsStagedCommand}; Write-Output done`, 'claude', 'PowerShell').status === 2);
  const pinnedVercelBytes = fs.readFileSync(windowsToolchain.vercel);
  fs.appendFileSync(windowsToolchain.vercel, '\nrem tampered\n');
  ok('changed pinned vercel.cmd hash blocks the actual PowerShell hook', runGuard(windowsGuardPath, guardRepo, windowsHookHome, windowsStagedCommand, 'claude', 'PowerShell').status === 2);
  fs.writeFileSync(windowsToolchain.vercel, pinnedVercelBytes);
  const installedProxyBytes = fs.readFileSync(windowsProxy);
  fs.appendFileSync(windowsProxy, '\n// tampered\n');
  ok('changed managed Windows proxy source blocks its own fallback execution', runWindowsProxy([
    'promote', 'https://strict-fixture.vercel.app/',
  ]).status === 2);
  fs.writeFileSync(windowsProxy, installedProxyBytes);
  const missingWindowsToolchain = fakeWindowsToolchain();
  const missingWindowsHome = tempDir('dcheck-windows-missing-cli-home-');
  installHooks({
    homeDir: missingWindowsHome,
    platform: 'win32',
    vercelExecutable: missingWindowsToolchain.vercel,
    powerShellExecutable: missingWindowsToolchain.powerShell,
    vercelVersion: missingWindowsToolchain.version,
  });
  fs.unlinkSync(missingWindowsToolchain.vercel);
  const missingWindowsUninstall = uninstallHooks({ homeDir: missingWindowsHome });
  ok('Windows uninstall remains available after the pinned Vercel CLI disappears', Object.values(missingWindowsUninstall.status.agents).every(agent => !agent.managedPresent)
    && !fs.existsSync(path.join(missingWindowsHome, '.dorms-check', 'hooks', 'manifest.json')));
  ok('command substitution is rejected at the conservative shell boundary', runGuard(guardPath, guardRepo, hookHome, 'echo $(date)', 'codex').status === 2);
  ok('Claude PowerShell-shaped production command is gated', runGuard(windowsGuardPath, guardRepo, windowsHookHome, 'vercel.cmd --prod', 'claude', 'PowerShell').status === 2);
  ok('explicit vercel.cmd token is blocked so Windows also uses canonical vercel resolution', runGuard(guardPath, guardRepo, hookHome, `vercel.cmd --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${guardSha}`, 'codex').status === 2);

  fs.writeFileSync(path.join(guardRepo, 'app.js'), 'export const app = false;\n');
  ok('dirty source blocks staged production', runGuard(guardPath, guardRepo, hookHome, stagedCommand, 'codex').status === 2);
  fs.writeFileSync(path.join(guardRepo, 'app.js'), 'export const app = true;\n');
  const noReceiptRepo = initRepo('dcheck-no-receipt-repo-');
  const noReceiptSha = git(noReceiptRepo, ['rev-parse', 'HEAD']);
  const noReceiptStage = `vercel --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${noReceiptSha}`;
  ok('missing code receipt blocks staged production', runGuard(guardPath, noReceiptRepo, hookHome, noReceiptStage, 'codex').status === 2);
  ok('rollback remains blocked independently of receipts', runGuard(guardPath, noReceiptRepo, hookHome, 'vercel rollback https://strict-fixture.vercel.app/', 'gemini').status === 2);
  ok('compound cd staged production is denied by the literal-only policy', runGuard(guardPath, guardRepo, hookHome, `cd ${noReceiptRepo} && ${noReceiptStage}`, 'claude').status === 2);
  writeReceipts(noReceiptRepo, hookHome);
  ok('compound cd stays blocked even when target has a receipt', runGuard(guardPath, guardRepo, hookHome, `cd ${noReceiptRepo} && ${noReceiptStage}`, 'claude').status === 2);
  ok('Vercel --cwd stays blocked even when target has a receipt', runGuard(guardPath, noReceiptRepo, hookHome, `vercel --cwd . --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=${noReceiptSha}`, 'gemini').status === 2);

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
  fs.writeFileSync(path.join(cliRepo, '.gitignore'), '.vercel/\n');
  fs.writeFileSync(path.join(cliRepo, '.vercelignore'), '.dorms-check/\n');
  fs.mkdirSync(path.join(cliRepo, '.vercel'), { recursive: true });
  fs.writeFileSync(path.join(cliRepo, '.vercel', 'project.json'), JSON.stringify({
    projectId: 'prj_fixture123',
    orgId: 'team_fixture123',
    projectName: 'fixture',
  }, null, 2));
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
  ok('CLI strict JSON reports gate runtime digest', /^[a-f0-9]{64}$/.test(cliPassJson?.gate?.runtimeSha256 || ''));
  ok('CLI strict scan leaves no mutable report or receipt inside the project', !fs.existsSync(path.join(cliRepo, '.dorms-check')));
  const cliUsage = runCli(cliRepo, cliHome, ['scan', '--track', 'security', '--strict', '--json', '--code-only']);
  ok('CLI missing git-sha -> exit 2', cliUsage.status === STRICT_EXIT.USAGE_CONFIG);
  const cliMismatch = runCli(cliRepo, cliHome, ['scan', '--track', 'security', '--strict', '--json', '--code-only', '--git-sha', '0000000000000000000000000000000000000000']);
  ok('CLI wrong git-sha -> exit 4', cliMismatch.status === STRICT_EXIT.BINDING_MISMATCH);
  const cliBadDeployment = runCli(cliRepo, cliHome, ['scan', '--track', 'security', '--strict', '--json', '--url', 'https://strict-fixture.vercel.app/', '--git-sha', cliSha, '--vercel-deployment', 'not-a-deployment-id']);
  ok('CLI malformed Vercel deployment ID -> exit 2', cliBadDeployment.status === STRICT_EXIT.USAGE_CONFIG, cliBadDeployment.stderr || cliBadDeployment.stdout);

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

  const hiddenStateRepo = initStrictCliRepo('dcheck-cli-hidden-state-', { excludeDcheck: false });
  const hiddenStateHome = tempDir('dcheck-cli-hidden-state-home-');
  fs.mkdirSync(path.join(hiddenStateRepo, '.dorms-check'), { recursive: true });
  fs.writeFileSync(path.join(hiddenStateRepo, '.dorms-check', 'scan.json'), JSON.stringify({ leaked: secret }));
  const hiddenStateSha = git(hiddenStateRepo, ['rev-parse', 'HEAD']);
  const hiddenStateBlocked = runCli(hiddenStateRepo, hiddenStateHome, ['scan', '--track', 'security', '--strict', '--json', '--code-only', '--git-sha', hiddenStateSha]);
  ok('strict static scan covers allowlisted uploaded .dorms-check state files', hiddenStateBlocked.status === STRICT_EXIT.SECURITY_BLOCKED, hiddenStateBlocked.stderr || hiddenStateBlocked.stdout);

  fs.rmSync(path.join(hiddenStateRepo, '.dorms-check'), { recursive: true, force: true });
  fs.mkdirSync(path.join(hiddenStateRepo, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(hiddenStateRepo, 'dist', 'late.js'), `export const leaked = "${secret}";\n`);
  git(hiddenStateRepo, ['add', 'dist/late.js']);
  git(hiddenStateRepo, ['commit', '-qm', 'tracked dist input']);
  const distSecretSha = git(hiddenStateRepo, ['rev-parse', 'HEAD']);
  const distSecretBlocked = runCli(hiddenStateRepo, hiddenStateHome, ['scan', '--track', 'security', '--strict', '--json', '--code-only', '--git-sha', distSecretSha]);
  ok('strict static scan covers tracked dist files excluded by the legacy walker', distSecretBlocked.status === STRICT_EXIT.SECURITY_BLOCKED, distSecretBlocked.stderr || distSecretBlocked.stdout);

  const manyInputRepo = initStrictCliRepo('dcheck-cli-many-inputs-');
  const manyInputHome = tempDir('dcheck-cli-many-inputs-home-');
  fs.mkdirSync(path.join(manyInputRepo, 'bulk'), { recursive: true });
  for (let index = 0; index < 5001; index++) {
    fs.writeFileSync(path.join(manyInputRepo, 'bulk', `${String(index).padStart(4, '0')}.txt`), index === 5000 ? secret : 'safe');
  }
  git(manyInputRepo, ['add', 'bulk']);
  git(manyInputRepo, ['commit', '-qm', 'many deployment inputs']);
  const manyInputSha = git(manyInputRepo, ['rev-parse', 'HEAD']);
  const manyInputBlocked = runCli(manyInputRepo, manyInputHome, ['scan', '--track', 'security', '--strict', '--json', '--code-only', '--git-sha', manyInputSha]);
  ok('strict static scan has no legacy 5,000-file blind spot', manyInputBlocked.status === STRICT_EXIT.SECURITY_BLOCKED, manyInputBlocked.stderr || manyInputBlocked.stdout);

  const cliHookHome = tempDir('dcheck-cli-hooks-home-');
  const cliHookInstall = runCli(cliRepo, cliHookHome, ['hooks', 'install', '--global', '--agents', 'codex,claude,gemini', '--provider', 'vercel', '--security-only', '--json']);
  let cliHookInstallJson = null;
  try { cliHookInstallJson = JSON.parse(cliHookInstall.stdout); } catch { /* asserted below */ }
  ok('CLI configures all hooks in temp HOME but does not claim host activation', cliHookInstall.status === STRICT_EXIT.INCOMPLETE && cliHookInstallJson?.configured === true && cliHookInstallJson?.activation === 'unknown', cliHookInstall.stderr || cliHookInstall.stdout);
  const cliHookStatus = runCli(cliRepo, cliHookHome, ['hooks', 'status', '--agents', 'codex,claude,gemini', '--json']);
  let cliHookStatusJson = null;
  try { cliHookStatusJson = JSON.parse(cliHookStatus.stdout); } catch { /* asserted below */ }
  ok('CLI status remains NOT READY while host activation is unobservable', cliHookStatus.status === STRICT_EXIT.INCOMPLETE && cliHookStatusJson?.configured === true && cliHookStatusJson?.ready === false && Object.values(cliHookStatusJson?.agents || {}).every(agent => !Object.hasOwn(agent, 'effective')), cliHookStatus.stderr || cliHookStatus.stdout);
  ok('CLI hook status exposes current-host and timeout boundaries', cliHookStatusJson?.installationScope === 'current-host-only' && cliHookStatusJson?.timeoutSeconds === 120 && cliHookStatusJson?.hostTimeoutMayFailOpen === true);
  const cliClaudeFile = path.join(cliHookHome, '.claude', 'settings.json');
  const cliGeminiFile = path.join(cliHookHome, '.gemini', 'settings.json');
  const cliClaudeSettings = JSON.parse(fs.readFileSync(cliClaudeFile, 'utf8'));
  const cliGeminiSettings = JSON.parse(fs.readFileSync(cliGeminiFile, 'utf8'));
  managedHandler(cliClaudeSettings.hooks.PreToolUse.find(group => group.matcher === 'Bash|PowerShell')).timeout = 1;
  managedHandler(cliGeminiSettings.hooks.BeforeTool.find(group => group.matcher === '^run_shell_command$')).timeout = 1;
  fs.writeFileSync(cliClaudeFile, JSON.stringify(cliClaudeSettings, null, 2));
  fs.writeFileSync(cliGeminiFile, JSON.stringify(cliGeminiSettings, null, 2));
  const cliTamperedHookStatus = runCli(cliRepo, cliHookHome, ['hooks', 'status', '--agents', 'claude,gemini', '--json']);
  let cliTamperedHookStatusJson = null;
  try { cliTamperedHookStatusJson = JSON.parse(cliTamperedHookStatus.stdout); } catch { /* asserted below */ }
  ok('CLI tampered Claude/Gemini schemas never return ok or exit 0', cliTamperedHookStatus.status === STRICT_EXIT.INCOMPLETE
    && cliTamperedHookStatusJson?.ok === false
    && cliTamperedHookStatusJson?.configured === false
    && cliTamperedHookStatusJson?.agents?.claude?.configured === false
    && cliTamperedHookStatusJson?.agents?.gemini?.configured === false,
  cliTamperedHookStatus.stderr || cliTamperedHookStatus.stdout);
  const cliMalformedHookHome = tempDir('dcheck-cli-malformed-hook-home-');
  fs.mkdirSync(path.join(cliMalformedHookHome, '.codex'), { recursive: true });
  fs.writeFileSync(path.join(cliMalformedHookHome, '.codex', 'config.toml'), 'model = [\n');
  const cliMalformedHookStatus = runCli(cliRepo, cliMalformedHookHome, ['hooks', 'status', '--agents', 'codex', '--json']);
  let cliMalformedHookStatusJson = null;
  try { cliMalformedHookStatusJson = JSON.parse(cliMalformedHookStatus.stdout); } catch { /* asserted below */ }
  ok('CLI malformed Codex status exits 2 with parseError', cliMalformedHookStatus.status === STRICT_EXIT.USAGE_CONFIG && Boolean(cliMalformedHookStatusJson?.agents?.codex?.parseError));
  const cliOverrideHome = tempDir('dcheck-cli-override-home-');
  const cliOverrideCodex = path.join(tempDir('dcheck-cli-codex-root-'), 'config');
  const cliOverrideClaude = path.join(tempDir('dcheck-cli-claude-root-'), 'config');
  const cliOverrideGemini = path.join(tempDir('dcheck-cli-gemini-home-'), 'config');
  const cliOverrideEnvironment = { CODEX_HOME: cliOverrideCodex, CLAUDE_CONFIG_DIR: cliOverrideClaude, GEMINI_CLI_HOME: cliOverrideGemini };
  const cliOverrideInstall = runCli(cliRepo, cliOverrideHome, ['hooks', 'install', '--global', '--agents', 'codex,claude,gemini', '--provider', 'vercel', '--security-only', '--json'], cliOverrideEnvironment);
  ok('CLI honors CODEX_HOME, CLAUDE_CONFIG_DIR, and GEMINI_CLI_HOME instead of HOME defaults', cliOverrideInstall.status === STRICT_EXIT.INCOMPLETE
    && fs.existsSync(path.join(cliOverrideCodex, 'config.toml'))
    && fs.existsSync(path.join(cliOverrideClaude, 'settings.json'))
    && fs.existsSync(path.join(cliOverrideGemini, '.gemini', 'settings.json'))
    && !fs.existsSync(path.join(cliOverrideHome, '.codex', 'config.toml')),
  cliOverrideInstall.stderr || cliOverrideInstall.stdout);
  const cliOverrideStatus = runCli(cliRepo, cliOverrideHome, ['hooks', 'status', '--agents', 'codex,claude,gemini', '--json'], cliOverrideEnvironment);
  let cliOverrideStatusJson = null;
  try { cliOverrideStatusJson = JSON.parse(cliOverrideStatus.stdout); } catch { /* asserted below */ }
  ok('CLI custom-root status reports the resolved runtime roots', cliOverrideStatus.status === STRICT_EXIT.INCOMPLETE
    && cliOverrideStatusJson?.agents?.codex?.configRoot === cliOverrideCodex
    && cliOverrideStatusJson?.agents?.claude?.configRoot === cliOverrideClaude
    && cliOverrideStatusJson?.agents?.gemini?.configRoot === path.join(cliOverrideGemini, '.gemini'));
  const cliOverrideUninstall = runCli(cliRepo, cliOverrideHome, ['hooks', 'uninstall', '--agents', 'codex,claude,gemini', '--json'], cliOverrideEnvironment);
  ok('CLI custom-root uninstall uses the same resolved paths', cliOverrideUninstall.status === STRICT_EXIT.PASS, cliOverrideUninstall.stderr || cliOverrideUninstall.stdout);
  const cliUnknownAgent = runCli(cliRepo, cliHookHome, ['hooks', 'status', '--agents', 'unknown', '--json']);
  ok('CLI unknown hook agent -> exit 2', cliUnknownAgent.status === STRICT_EXIT.USAGE_CONFIG);
  const cliMarkerlessHome = tempDir('dcheck-cli-markerless-home-');
  runCli(cliRepo, cliMarkerlessHome, ['hooks', 'install', '--global', '--agents', 'codex', '--provider', 'vercel', '--security-only', '--json']);
  const cliMarkerlessFile = path.join(cliMarkerlessHome, '.codex', 'config.toml');
  fs.writeFileSync(cliMarkerlessFile, fs.readFileSync(cliMarkerlessFile, 'utf8')
    .replace(/^# >>> dorms-check-security-only >>>\n/m, '')
    .replace(/^# <<< dorms-check-security-only <<<\n?/m, ''));
  const cliMarkerlessUninstall = runCli(cliRepo, cliMarkerlessHome, ['hooks', 'uninstall', '--agents', 'codex', '--json']);
  let cliMarkerlessJson = null;
  try { cliMarkerlessJson = JSON.parse(cliMarkerlessUninstall.stdout); } catch { /* asserted below */ }
  ok('CLI uninstall never reports PASS while markerless managed residue remains', cliMarkerlessUninstall.status === STRICT_EXIT.INCOMPLETE
    && cliMarkerlessJson?.ok === false
    && cliMarkerlessJson?.status?.agents?.codex?.managedPresent === true,
  cliMarkerlessUninstall.stderr || cliMarkerlessUninstall.stdout);
  const cliHookUninstall = runCli(cliRepo, cliHookHome, ['hooks', 'uninstall', '--agents', 'codex,claude,gemini', '--json']);
  ok('CLI uninstalls all hooks only in temp HOME', cliHookUninstall.status === STRICT_EXIT.PASS, cliHookUninstall.stderr || cliHookUninstall.stdout);

  console.log('\n[6] published package contains the common hook runtime');
  const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const pack = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: packageRoot, encoding: 'utf8' }));
  const packedFiles = new Set((pack[0]?.files || []).map(item => item.path));
  ok('npm package includes hooks/vercel-guard.cjs', packedFiles.has('hooks/vercel-guard.cjs'));
  ok('npm package includes hooks/vercel-proxy.cjs', packedFiles.has('hooks/vercel-proxy.cjs'));
  ok('npm package includes core/strict-runtime.cjs', packedFiles.has('core/strict-runtime.cjs'));
  ok('npm package includes exact manifest-bound static reader', packedFiles.has('checks/static/exact-file.js'));
  ok('npm package includes strict security gate documentation', packedFiles.has('docs/STRICT-SECURITY-GATE.ko.md'));

  console.log(`\nstrict 결과: ${passed} pass, ${failed} fail`);
  if (failed) process.exitCode = 1;
}

try {
  await run();
} finally {
  for (const dir of cleanup.reverse()) fs.rmSync(dir, { recursive: true, force: true });
}

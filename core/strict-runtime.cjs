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
const GATE_SCHEMA = 2;
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
  if (process.env.NODE_ENV === 'test' && process.env.DCHECK_TEST_HOME) {
    return path.resolve(process.env.DCHECK_TEST_HOME);
  }
  return os.homedir();
}

function git(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function findGitRoot(cwd) {
  try { return path.resolve(git(cwd, ['rev-parse', '--show-toplevel'])); }
  catch { return null; }
}

function isDcheckStateLine(line) {
  const filePart = line.length > 3 ? line.slice(3).replace(/^"|"$/g, '') : '';
  const paths = filePart.split(' -> ');
  return paths.every(item => item === '.dorms-check' || item.startsWith('.dorms-check/'));
}

function projectIdentity(cwd) {
  const root = findGitRoot(cwd);
  if (!root) return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: '현재 폴더가 Git 저장소가 아닙니다.' };
  try {
    const gitSha = git(root, ['rev-parse', 'HEAD']);
    const treeSha = git(root, ['rev-parse', 'HEAD^{tree}']);
    const dirtyLines = git(root, ['status', '--porcelain=v1', '--untracked-files=all'])
      .split(/\r?\n/)
      .filter(Boolean)
      .filter(line => !isDcheckStateLine(line));
    return {
      ok: true,
      root,
      rootHash: sha256(fs.realpathSync(root)),
      gitSha,
      treeSha,
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
    || !deployment.projectId
    || !deployment.orgId
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
  const projectFile = path.join(projectRoot, '.dorms-check', `strict-${receipt.phase}.json`);
  atomicWrite(projectFile, JSON.stringify(signed, null, 2) + '\n');
  return { receipt: signed, trustedFile, projectFile };
}

function invalidateReceipt(phase, project, projectRoot, options = {}) {
  if (!['code', 'live'].includes(phase) || !project?.rootHash) return;
  const homeDir = resolveHome(options);
  const files = [
    receiptFile(homeDir, project.rootHash, phase),
    path.join(projectRoot, '.dorms-check', `strict-${phase}.json`),
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
  const expiresAt = Date.parse(receipt.expiresAt);
  if (!Number.isFinite(expiresAt) || now.getTime() > expiresAt) {
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
  if (expectedPhase === 'live' && (
    receipt.deployment?.provider !== 'vercel'
    || !/^dpl_[A-Za-z0-9]+$/.test(String(receipt.deployment?.id || ''))
    || !/^[a-f0-9]{40}$/i.test(String(receipt.deployment?.sourceGitSha || ''))
    || receipt.deployment?.sourceGitSha !== receipt.project?.gitSha
    || typeof receipt.deployment?.projectId !== 'string'
    || !receipt.deployment.projectId
    || typeof receipt.deployment?.orgId !== 'string'
    || !receipt.deployment.orgId
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
  if (item.project.rootHash !== project.rootHash || item.project.gitSha !== project.gitSha || item.project.treeSha !== project.treeSha || item.project.clean !== true) {
    return { ok: false, exitCode: EXIT.BINDING_MISMATCH, reason: 'code strict 영수증의 Git 바인딩이 현재 소스와 다릅니다.' };
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
    project: { gitSha: context.project.gitSha, treeSha: context.project.treeSha },
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
  if (live.receipt.project.rootHash !== project.rootHash || live.receipt.project.gitSha !== project.gitSha || live.receipt.project.treeSha !== project.treeSha || live.receipt.project.clean !== true) {
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
    project: { gitSha: project.gitSha, treeSha: project.treeSha },
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

const PRODUCTION_MUTATOR_RE = /--prod(?:\b|=)|--target(?:=|\s+)production\b|\bpromote\b|\brollback\b|\bredeploy\b|\brolling-release\b|\balias\b|\bapi\b/i;
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
  const match = /^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$/.exec(String(token || ''))
    || /^%([A-Za-z_][A-Za-z0-9_]*)%$/.exec(String(token || ''));
  return match ? (match[1] || match[2] || '') : '';
}

function hasDynamicExecutable(segments) {
  return segments.some(tokens => dynamicExecutableName(tokens[skipPrefix(tokens)]));
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

function validateStagedInvocation(args, cwd, expectedSha) {
  let gitRoot;
  try {
    gitRoot = findGitRoot(cwd);
    if (!gitRoot || fs.realpathSync(cwd) !== fs.realpathSync(gitRoot)) {
      return { ok: false, reason: 'strict staged production은 현재 clean Git 저장소 루트에서 직접 실행해야 합니다.' };
    }
  } catch {
    return { ok: false, reason: 'strict staged production의 Git 저장소 루트를 확인하지 못했습니다.' };
  }

  const allowedFlags = new Set([
    'deploy', '--prod', '--skip-domain', '--yes',
  ]);
  const allowedOptions = new Set(['--meta', '-m']);
  for (let index = 0; index < args.length; index++) {
    const token = args[index];
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

function isReadOnlyRoutingInvocation(invocation) {
  if (!invocation) return false;
  const args = invocation.args;
  if (targetsProduction(args) || args.includes('redeploy') || args.includes('rolling-release') || args.includes('api')) return false;
  for (const name of ['promote', 'rollback']) {
    const index = args.indexOf(name);
    if (index >= 0) return deploymentTarget(args, index).toLowerCase() === 'status';
  }
  const aliasIndex = args.indexOf('alias');
  if (aliasIndex >= 0) {
    const action = deploymentTarget(args, aliasIndex).toLowerCase();
    return !action || ['ls', 'list'].includes(action);
  }
  return false;
}

function isLiteralDirectVercelCommand(rawCommand, parsed) {
  if (parsed.unterminatedQuote || parsed.segments.length !== 1) return false;
  if (/[;&|<>`$\\\r\n]/.test(rawCommand)) return false;
  const tokens = parsed.segments[0];
  return /^(?:vercel|vc)(?:\.cmd|\.exe)?$/i.test(String(tokens[0] || ''));
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
  } else if (['node', 'nodejs', 'deno'].includes(executable)) {
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
  } else if (/^(?:\.\.?[\\/]|[A-Za-z]:[\\/])/.test(tokens[index] || '') && /\.(?:sh|bash|zsh|js|cjs|mjs|ps1|cmd|bat)$/i.test(tokens[index])) {
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
  const parsed = tokenizeShell(rawCommand);
  if (parsed.unterminatedQuote && /vercel/i.test(command)) {
    return { relevant: true, allowed: false, reason: 'Vercel 명령의 따옴표를 해석할 수 없어 안전하게 차단했습니다.' };
  }
  // Shell substitution and eval can hide the executable from the token parser.
  // Fail closed only when such a construct also contains a production-changing
  // Vercel command. Ordinary substitutions and read-only Vercel commands pass.
  const concealedExecution = /\$\(|`|\beval\b/i.test(rawCommand);
  const dynamicExecution = concealedExecution
    || /\$(?:\{|[A-Za-z_])|%[A-Za-z_][A-Za-z0-9_]*%/.test(rawCommand)
    || /\b(?:sh|bash|zsh|dash|cmd|powershell|pwsh)(?:\.exe)?\b[^\r\n;&|]*(?:-c|\/c|-command)\b/i.test(rawCommand);
  const namesVercel = /(?:^|[\\/\s"'`($;&|])(?:vercel|vc)(?:\.exe|\.cmd)?(?:@[^\s"'`);&|]+)?(?=$|[\s"'`);&|])/i.test(rawCommand);
  const referencesVercel = namesVercel || /\b(?:vercel|vc)(?:\.exe|\.cmd)?\b/i.test(rawCommand);
  const parsedCommandText = parsed.segments.map(segment => segment.join(' ')).join(' ; ');
  const productionChange = PRODUCTION_MUTATOR_RE.test(rawCommand) || PRODUCTION_MUTATOR_RE.test(parsedCommandText);
  const singleInvocation = parsed.segments.length === 1 ? unwrapVercel(parsed.segments[0]) : null;
  if (productionChange && !isReadOnlyRoutingInvocation(singleInvocation) && Number(options._wrapperDepth || 0) > 0) {
    return { relevant: true, allowed: false, reason: 'package script, 셸·런타임 스크립트, 중첩 명령을 통한 프로덕션 조작은 허용하지 않습니다.' };
  }
  if (productionChange && !isReadOnlyRoutingInvocation(singleInvocation) && !isLiteralDirectVercelCommand(rawCommand, parsed)) {
    return { relevant: true, allowed: false, reason: '프로덕션 조작은 셸 래퍼·복합 명령 없이 단일 literal vercel 또는 vc 명령으로만 실행할 수 있습니다.' };
  }
  if (dynamicExecution && productionChange) {
    return { relevant: true, allowed: false, reason: '동적 실행이 포함된 프로덕션 조작은 실제 명령을 결정할 수 없어 차단했습니다.' };
  }
  if (concealedExecution && referencesVercel && productionChange) {
    return { relevant: true, allowed: false, reason: '명령 치환 또는 eval 안의 Vercel 프로덕션 조작은 안전하게 검증할 수 없어 차단했습니다.' };
  }
  const assignedVariables = assignedVercelVariables(parsed.segments);
  if (productionChange && hasDynamicExecutable(parsed.segments)) {
    const detail = assignedVariables.size ? 'Vercel 실행 파일을 변수로 간접 호출했습니다.' : '실행 파일 변수를 결정할 수 없습니다.';
    return { relevant: true, allowed: false, reason: `${detail} 동적 프로덕션 조작은 안전하게 차단했습니다.` };
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
      const nestedResult = evaluateVercelCommand(nested, effectiveCwd, { ...options, _wrapperDepth: Number(options._wrapperDepth || 0) + 1 });
      if (nestedResult.relevant && !nestedResult.allowed) return nestedResult;
      if (nestedResult.relevant) { sawRelevant = true; lastGate = nestedResult.gate || lastGate; continue; }
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
      const gate = verifyCodeGate({ cwd: invocationCwd }, options);
      if (!gate.ok) return { relevant: true, allowed: false, reason: gate.reason, gate };
      const staged = validateStagedInvocation(args, invocationCwd, gate.project.gitSha);
      if (!staged.ok) return { relevant: true, allowed: false, reason: staged.reason, gate };
      lastGate = gate;
    }
  }
  if (!sawRelevant && namesVercel && productionChange) {
    return { relevant: true, allowed: false, reason: 'Vercel 프로덕션 명령 형식을 안전하게 해석할 수 없어 차단했습니다.' };
  }
  return { relevant: sawRelevant, allowed: true, reason: sawRelevant ? '현재 Git과 strict 영수증이 일치합니다.' : '', gate: lastGate };
}

module.exports = {
  EXIT,
  RECEIPT_KIND,
  RECEIPT_TTL_MS,
  GATE_SCHEMA,
  RUNTIME_DIGEST,
  REQUIRED_BY_PHASE,
  stableStringify,
  sha256,
  atomicWrite,
  resolveHome,
  findGitRoot,
  projectIdentity,
  normalizeDeploymentUrl,
  createReceipt,
  storeReceipt,
  invalidateReceipt,
  verifyCodeGate,
  verifyGate,
  tokenizeShell,
  evaluateVercelCommand,
};

#!/usr/bin/env node
'use strict';

const path = require('node:path');
const runtime = require('./strict-runtime.cjs');

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function isAntigravityInput(input) {
  return Boolean(input && typeof input === 'object' && input.toolCall && typeof input.toolCall === 'object');
}

function extractCommand(input) {
  // Antigravity CLI(agy): { toolCall: { name: 'run_command', args: { CommandLine, Cwd } } }
  if (isAntigravityInput(input) && input.toolCall.args && Object.prototype.hasOwnProperty.call(input.toolCall.args, 'CommandLine')) {
    return input.toolCall.args.CommandLine;
  }
  if (input?.tool_input && Object.prototype.hasOwnProperty.call(input.tool_input, 'command')) {
    return input.tool_input.command;
  }
  if (input?.toolInput && Object.prototype.hasOwnProperty.call(input.toolInput, 'command')) {
    return input.toolInput.command;
  }
  if (input && Object.prototype.hasOwnProperty.call(input, 'command')) return input.command;
  return null;
}

// Antigravity는 stdout JSON의 decision으로 판정한다. 다른 에이전트는 exit 2가 차단이다.
// 두 계약을 모두 만족하도록 Antigravity 입력이면 JSON을 함께 쓰고 종료 코드는 그대로 둔다.
function deny(input, reason) {
  if (isAntigravityInput(input)) process.stdout.write(JSON.stringify({ decision: 'deny', reason }) + '\n');
  process.stderr.write(`dorms-check: ${reason}\n`);
  process.exit(2);
}

async function main() {
  let input = {};
  try {
    const raw = await readStdin();
    input = raw.trim() ? JSON.parse(raw) : {};
  } catch {
    deny({}, '훅 입력 JSON을 읽지 못해 Vercel 명령을 안전하게 차단했습니다.');
  }
  const command = extractCommand(input);
  if (typeof command !== 'string' || !command.trim()) {
    deny(input, '셸 훅 입력에 비어 있지 않은 command 문자열이 없어 안전하게 차단했습니다.');
  }
  const antigravity = isAntigravityInput(input);
  const cwd = (antigravity && typeof input.toolCall.args?.Cwd === 'string' && input.toolCall.args.Cwd)
    || input.cwd
    || process.cwd();
  const toolName = antigravity
    ? String(input.toolCall.name || '')
    : (typeof input.tool_name === 'string'
      ? input.tool_name
      : (typeof input.toolName === 'string' ? input.toolName : ''));
  if (!['Bash', 'PowerShell', 'run_shell_command', 'run_command'].includes(toolName)) {
    deny(input, '지원하는 셸 tool_name을 훅 입력에서 확인하지 못해 안전하게 차단했습니다.');
  }
  const runtimeOptions = { shellTool: toolName, platform: process.platform };
  if (process.platform === 'win32' || toolName === 'PowerShell') {
    try {
      const pinned = runtime.loadPinnedWindowsVercelExecutable({ hookManifestPath: path.join(__dirname, 'manifest.json') });
      Object.assign(runtimeOptions, {
        vercelExecutable: pinned.path,
        vercelExecutableSha256: pinned.sha256,
        vercelExecutableVersion: pinned.version,
        vercelBackingExecutable: pinned.backingPath,
        vercelBackingExecutableSha256: pinned.backingSha256,
        powerShellExecutable: pinned.powerShellPath,
        powerShellExecutableSha256: pinned.powerShellSha256,
      });
    } catch (error) {
      deny(input, `Windows strict 실행 파일 고정을 확인하지 못해 안전하게 차단했습니다: ${error.message}`);
    }
  }
  const verdict = runtime.evaluateVercelCommand(command, cwd, runtimeOptions);
  if (verdict.relevant && !verdict.allowed) {
    deny(input, verdict.reason);
  }
  if (antigravity) process.stdout.write(JSON.stringify({ decision: 'allow' }) + '\n');
  process.exit(0);
}

if (require.main === module) {
  main().catch(error => {
    deny({}, `배포 훅 오류로 안전하게 차단했습니다: ${error.message}`);
  });
}

module.exports = { extractCommand, isAntigravityInput };

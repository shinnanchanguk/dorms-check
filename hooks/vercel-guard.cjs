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

function extractCommand(input) {
  if (input?.tool_input && Object.prototype.hasOwnProperty.call(input.tool_input, 'command')) {
    return input.tool_input.command;
  }
  if (input?.toolInput && Object.prototype.hasOwnProperty.call(input.toolInput, 'command')) {
    return input.toolInput.command;
  }
  if (input && Object.prototype.hasOwnProperty.call(input, 'command')) return input.command;
  return null;
}

async function main() {
  let input = {};
  try {
    const raw = await readStdin();
    input = raw.trim() ? JSON.parse(raw) : {};
  } catch {
    process.stderr.write('dorms-check: 훅 입력 JSON을 읽지 못해 Vercel 명령을 안전하게 차단했습니다.\n');
    process.exit(2);
  }
  const command = extractCommand(input);
  if (typeof command !== 'string' || !command.trim()) {
    process.stderr.write('dorms-check: 셸 훅 입력에 비어 있지 않은 command 문자열이 없어 안전하게 차단했습니다.\n');
    process.exit(2);
  }
  const cwd = input.cwd || process.cwd();
  const toolName = typeof input.tool_name === 'string'
    ? input.tool_name
    : (typeof input.toolName === 'string' ? input.toolName : '');
  if (!['Bash', 'PowerShell', 'run_shell_command'].includes(toolName)) {
    process.stderr.write('dorms-check: 지원하는 셸 tool_name을 훅 입력에서 확인하지 못해 안전하게 차단했습니다.\n');
    process.exit(2);
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
      process.stderr.write(`dorms-check: Windows strict 실행 파일 고정을 확인하지 못해 안전하게 차단했습니다: ${error.message}\n`);
      process.exit(2);
    }
  }
  const verdict = runtime.evaluateVercelCommand(command, cwd, runtimeOptions);
  if (verdict.relevant && !verdict.allowed) {
    process.stderr.write(`dorms-check: ${verdict.reason}\n`);
    process.exit(2);
  }
  process.exit(0);
}

if (require.main === module) {
  main().catch(error => {
    process.stderr.write(`dorms-check: 배포 훅 오류로 안전하게 차단했습니다: ${error.message}\n`);
    process.exit(2);
  });
}

module.exports = { extractCommand };

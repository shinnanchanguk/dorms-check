#!/usr/bin/env node
'use strict';

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
  const verdict = runtime.evaluateVercelCommand(command, cwd, { shellTool: toolName });
  if ((process.platform === 'win32' || toolName === 'PowerShell') && verdict.relevant) {
    process.stderr.write('dorms-check: native Windows 또는 PowerShell에서는 Vercel 실행 파일 해석을 결정적으로 증명할 수 없어 strict Vercel 명령을 차단했습니다. Bash 환경 또는 WSL의 literal vercel 명령을 사용하세요.\n');
    process.exit(2);
  }
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

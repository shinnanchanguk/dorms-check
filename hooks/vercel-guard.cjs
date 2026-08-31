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
  return input?.tool_input?.command
    || input?.toolInput?.command
    || input?.command
    || '';
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
  if (!command) process.exit(0);
  const cwd = input.cwd || process.cwd();
  const verdict = runtime.evaluateVercelCommand(command, cwd);
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

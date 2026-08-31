#!/usr/bin/env node
'use strict';

const path = require('node:path');
const runtime = require('./strict-runtime.cjs');

function fail(message) {
  process.stderr.write(`dorms-check: ${message}\n`);
  process.exit(2);
}

function main() {
  let pinned;
  try {
    pinned = runtime.loadPinnedWindowsVercelExecutable({ hookManifestPath: path.join(__dirname, 'manifest.json') });
  } catch (error) {
    fail(`Windows Vercel proxy 고정 정보를 확인하지 못했습니다: ${error.message}`);
  }

  const args = process.argv.slice(2);
  if (!args.length || args.some(value => !/^[A-Za-z0-9_:/.=+-]+$/.test(String(value)))) {
    fail('Windows Vercel proxy는 변수·셸 연산자 없는 literal 인자만 허용합니다.');
  }

  const verdict = runtime.evaluateVercelCommand(['vercel', ...args].join(' '), process.cwd(), {
    platform: 'win32',
    shellTool: 'PinnedWindowsProxy',
    _pinnedPowerShellCanonical: true,
    vercelExecutable: pinned.path,
    vercelExecutableSha256: pinned.sha256,
    vercelExecutableVersion: pinned.version,
    vercelBackingExecutable: pinned.backingPath,
    vercelBackingExecutableSha256: pinned.backingSha256,
    powerShellExecutable: pinned.powerShellPath,
    powerShellExecutableSha256: pinned.powerShellSha256,
  });
  if (verdict.relevant && !verdict.allowed) fail(verdict.reason);

  try {
    runtime.runVercelCli(args, {
      cwd: process.cwd(),
      env: process.env,
      stdio: 'inherit',
    }, {
      platform: 'win32',
      vercelBackingExecutable: pinned.backingPath,
      vercelBackingExecutableSha256: pinned.backingSha256,
      vercelExecutableVersion: pinned.version,
      powerShellExecutable: pinned.powerShellPath,
      powerShellExecutableSha256: pinned.powerShellSha256,
    });
  } catch (error) {
    process.exit(Number.isInteger(error?.status) ? error.status : 2);
  }
}

if (require.main === module) main();

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';

// Independent regression fixture: no network access or application source writes.
// Each untrusted input runs in an isolated process so a synchronous regex hang
// is terminated without hanging the test runner. No input/key bytes are printed.
const thisFile = fileURLToPath(import.meta.url);
const engineRoot = path.resolve(path.dirname(thisFile), '..');
const begin = '-----BEGIN PRIVATE KEY-----';
const end = '-----END PRIVATE KEY-----';
const body = Buffer.from('ephemeral independent regression fixture '.repeat(8)).toString('base64');
const cases = [
  { name: 'unfinished-begin-2048-newlines', confirmed: false, make: () => begin + '\n'.repeat(2048) },
  { name: 'unfinished-begin-1MiB-newlines', confirmed: false, make: () => begin + '\n'.repeat(1024 * 1024) },
  { name: 'ten-thousand-unfinished-begins', confirmed: false, make: () => (begin + '\n' + body + '\n').repeat(10000) },
  { name: 'ten-thousand-invalid-start-markers', confirmed: false, make: () => ('-----START PRIVATE KEY-----\n' + body + '\n').repeat(10000) },
  { name: 'begin-with-body-without-end', confirmed: false, make: () => begin + '\n' + body + '\n' },
  { name: 'base64-without-pem-markers', confirmed: false, make: () => body },
  { name: 'start-marker-is-not-begin-marker', confirmed: false, make: () => '-----START PRIVATE KEY-----\n' + body + '\n' + end },
  { name: 'empty-pem-body', confirmed: false, make: () => begin + '\n' + end },
  { name: 'whitespace-only-pem-body', confirmed: false, make: () => begin + '\n'.repeat(2048) + end },
  { name: 'simple-base64-pem-body', confirmed: true, make: () => begin + '\n' + body + '\n' + end },
  { name: 'ephemeral-real-pkcs8-pem', confirmed: true, make: () => generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
  { name: 'ephemeral-real-pkcs1-pem', confirmed: true, make: () => generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey.export({ type: 'pkcs1', format: 'pem' }).toString() },
  { name: 'ephemeral-real-ec-pem', confirmed: true, make: () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'sec1', format: 'pem' }).toString() },
  { name: 'valid-pem-after-unfinished-begins', confirmed: true, make: () => (begin + '\ninvalid!\n').repeat(10000) + begin + '\n' + body + '\n' + end },
];

if (process.argv[2] === '--child') {
  const selected = cases.find(test => test.name === process.argv[3]);
  assert.ok(selected, 'Known regression case required');
  const { classifySensitiveExposure } = await import(pathToFileURL(path.join(engineRoot, 'core/minimum-policy.js')).href);
  const input = selected.make();
  const started = performance.now();
  const result = classifySensitiveExposure(input);
  const elapsedMs = performance.now() - started;
  console.log(JSON.stringify({ name: selected.name, inputBytes: Buffer.byteLength(input), elapsedMs: Math.round(elapsedMs * 100) / 100, ...result }));
} else {
  const results = [];
  for (const test of cases) {
    const child = spawnSync(process.execPath, [thisFile, '--child', test.name], { encoding: 'utf8', timeout: 2000, maxBuffer: 64 * 1024, env: process.env });
    let observed;
    let failure;
    try {
      assert.equal(child.error?.code, undefined, `Process error: ${child.error?.code}`);
      assert.equal(child.status, 0, `Child exited ${child.status}: ${child.stderr}`);
      observed = JSON.parse(child.stdout.trim());
      assert.equal(observed.confirmed, test.confirmed, 'Exposure classification changed');
      if (test.confirmed) assert.equal(observed.kind, 'private-key');
      assert.ok(observed.elapsedMs < 1000, `Classification took ${observed.elapsedMs} ms (limit 1000 ms)`);
    } catch (error) {
      failure = error.message;
    }
    const entry = { name: test.name, pass: !failure, ...(observed || {}), ...(failure ? { failure } : {}) };
    results.push(entry);
    console.log(JSON.stringify(entry));
  }
  console.log(JSON.stringify({ summary: { passed: results.filter(test => test.pass).length, total: results.length }, engineRoot }));
  process.exitCode = results.every(test => test.pass) ? 0 : 1;
}

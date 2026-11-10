import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

test('one-command startup bootstraps once and preserves existing setup', t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-start-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const name of ['bin', 'project_back', 'project_front']) mkdirSync(join(dir, name));
  const back = join(dir, 'project_back');
  copyFileSync(resolve('start.sh'), join(back, 'start.sh'));
  writeFileSync(join(dir, 'project_front/package.json'), '{}');
  writeFileSync(join(dir, 'bin/docker'), `#!/bin/sh
printf '%s\\n' "$*" >> calls.txt
case "$*" in
  *'run --rm'*) printf 'LAN_IP=192.168.1.10\\nREGISTRATION_TOKEN=not-printed\\n' > .env ;;
esac
`, { mode: 0o755 });
  const run = (...args: string[]) => spawnSync('sh', ['start.sh', ...args], { cwd: back,
    env: { ...process.env, PATH: `${join(dir, 'bin')}:/usr/bin:/bin` }, encoding: 'utf8' });
  const first = run('192.168.1.10');
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, /https:\/\/192\.168\.1\.10:8443/);
  assert.equal(first.stdout.includes('not-printed'), false);
  const content = readFileSync(join(back, '.env'), 'utf8');
  assert.equal(run().status, 0);
  assert.equal(readFileSync(join(back, '.env'), 'utf8'), content);
  const calls = readFileSync(join(back, 'calls.txt'), 'utf8');
  assert.equal(calls.split('\n').filter(line => line.includes('run --rm')).length, 1);
  assert.equal(calls.split('\n').filter(line => line.includes('up --build -d --wait')).length, 2);
  assert.equal(run('192.168.1.11').status, 1);
  assert.equal(readFileSync(join(back, '.env'), 'utf8'), content);
});

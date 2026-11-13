import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

test('offline startup loads images once and prohibits builds and pulls', t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-offline-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, 'bin'));
  copyFileSync(resolve('scripts/start-offline.sh'), join(dir, 'start.sh'));
  writeFileSync(join(dir, 'images.tar'), 'test archive');
  writeFileSync(join(dir, 'images.tar.sha256'), 'test checksum');
  writeFileSync(join(dir, 'bin/sha256sum'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  writeFileSync(join(dir, 'bin/docker'), `#!/bin/sh
printf '%s\\n' "$*" >> calls.txt
case "$*" in
  *'run --rm'*) printf 'LAN_IP=192.168.1.10\\n' > .env ;;
esac
`, { mode: 0o755 });
  const run = (...args: string[]) => spawnSync('sh', ['start.sh', ...args], { cwd: dir,
    env: { ...process.env, SUDO_UID: '1001', SUDO_GID: '1001', PATH: `${join(dir, 'bin')}:/usr/bin:/bin` }, encoding: 'utf8' });
  assert.equal(run('192.168.1.10').status, 0);
  assert.equal(run().status, 0);
  assert.equal(run('192.168.1.20').status, 1);
  const calls = readFileSync(join(dir, 'calls.txt'), 'utf8').trim().split('\n');
  assert.equal(calls.filter(line => line === 'load -i images.tar').length, 1);
  assert.ok(calls.filter(line => line.includes('compose')).every(line => line.includes('--pull never')));
  assert.ok(calls.filter(line => line.includes(' up ')).every(line => line.includes('--no-build')));
  assert.ok(calls.some(line => line.startsWith('image inspect ')));
  assert.ok(!calls.some(line => line.includes(' run ') && line.includes('--no-build')));
  assert.ok(calls.some(line => line.includes('--user 1001:1001')));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

test('changing LAN IP preserves trust and custom origins and rolls back a failed recreation', t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-address-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = (name: string) => join(dir, name);
  const previous = '192.168.2.10', next = '192.168.2.20';
  execFileSync(process.execPath, [resolve('scripts/setup.mjs'), '--ip', previous], { cwd: dir });
  copyFileSync(resolve('change-ip.py'), path('change-ip.py'));
  mkdirSync(path('bin'));
  const mock = (name: string, body: string) => writeFileSync(path('bin/' + name), '#!/bin/sh\n' + body, { mode: 0o700 });
  mock('ip', `echo '2: eth0 inet ${next}/24'; echo '2: eth0 inet ${previous}/24'`);
  mock('ifconfig', `echo '  inet ${next} netmask'; echo '  inet ${previous} netmask'`);
  mock('docker', `case "$2" in
    ps) if [ -f fail-once ]; then echo api; fi ;;
    up) echo up >> applied; if [ -f fail-once ]; then rm fail-once; exit 1; fi ;;
    *) exit 2 ;;
  esac`);
  const run = (ip: string) => spawnSync('python3', [path('change-ip.py'), '--compose', ip], {
    cwd: dir, encoding: 'utf8', env: { ...process.env, PATH: path('bin') + ':' + process.env.PATH },
  });
  const hash = (name: string) => createHash('sha256').update(readFileSync(path(name))).digest('hex');
  const cert = 'runtime/tls/server.crt', ca = 'runtime/tls/ca.crt', key = 'runtime/tls/server.key';
  const original = readFileSync(path('.env'), 'utf8').replace('ALLOWED_ORIGINS=',
    'ALLOWED_ORIGINS=https://192.168.2.100:8443,https://localhost:4000,');
  writeFileSync(path('.env'), original);
  const unchanged = [hash('.env'), hash(cert), hash(ca), hash(key)];
  for (const bad of ['300.1.1.1', '8.8.8.8', '192.168.2.99']) assert.notEqual(run(bad).status, 0);
  // The first recreation fails. The second one re-applies the original configuration.
  writeFileSync(path('fail-once'), '');
  assert.notEqual(run(next).status, 0);
  assert.equal(readFileSync(path('applied'), 'utf8'), 'up\nup\n');
  assert.deepEqual([hash('.env'), hash(cert), hash(ca), hash(key)], unchanged);

  // Simulate termination just after publishing the new .env, before replacing the certificate.
  const pending = 'runtime/ip-change.pending/';
  mkdirSync(path(pending + 'runtime/tls'), { recursive: true });
  copyFileSync(path('.env'), path(pending + '.env'));
  copyFileSync(path(cert), path(pending + cert));
  writeFileSync(path('.env'), original.replace('LAN_IP=' + previous, 'LAN_IP=' + next));
  const result = run(next);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(path('applied'), 'utf8'), 'up\nup\n', 'a stopped project stays stopped');
  assert.equal(readFileSync(path('.env'), 'utf8'), original.replace('LAN_IP=' + previous, 'LAN_IP=' + next)
    .replaceAll('https://' + previous + ':', 'https://' + next + ':'));
  const verify = (...args: string[]) => spawnSync('openssl', ['verify', '-CAfile', path(ca), ...args, path(cert)]);
  assert.equal(verify('-verify_ip', next).status, 0);
  assert.equal(verify('-verify_hostname', 'localhost').status, 0);
  assert.notEqual(verify('-verify_ip', previous).status, 0);
  assert.deepEqual([hash(ca), hash(key)], unchanged.slice(2));
  const issued = hash(cert);
  assert.equal(run(next).status, 0);
  assert.equal(hash(cert), issued);
  assert.equal(existsSync(path('runtime/ip-change.pending')), false);
});

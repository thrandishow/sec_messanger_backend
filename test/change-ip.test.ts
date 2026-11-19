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
  mkdirSync(path('bin'));
  const mock = (name: string, body: string) => writeFileSync(path('bin/' + name), '#!/bin/sh\n' + body, { mode: 0o700 });
  mock('ip', `echo '2: eth0 inet ${next}/24'; echo '2: eth0 inet ${previous}/24'`);
  mock('ifconfig', `echo '  inet ${next} netmask'; echo '  inet ${previous} netmask'`);
  mock('docker', `case "$2" in
    ps) if [ -f fail-once ]; then echo api; fi ;;
    up) echo up >> applied; if [ -f fail-once ]; then rm fail-once; exit 1; fi ;;
    *) exit 2 ;;
  esac`);
  const cli = (...args: string[]) => spawnSync(resolve('shifrctl'), [...args, '--compose', '--root', dir], {
    cwd: dir, encoding: 'utf8', env: { ...process.env, PATH: path('bin') + ':' + process.env.PATH },
  });
  const run = (ip: string) => cli('set-ip', ip);
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

  const unchangedAfterMove = ['.env', ca, key, 'runtime/ca/ca.key'].map(hash);
  const renewed = cli('renew-cert');
  assert.equal(renewed.status, 0, renewed.stderr);
  assert.notEqual(hash(cert), issued);
  assert.equal(verify('-verify_ip', next).status, 0);
  assert.deepEqual(['.env', ca, key, 'runtime/ca/ca.key'].map(hash), unchangedAfterMove);
});

test('native maintenance preserves extra SANs and reloads services only after nginx accepts the configuration', t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-native-cert-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = (name: string) => join(dir, name);
  const read = (name: string) => readFileSync(path(name), 'utf8');
  const old = '10.1.1.10', next = '10.1.1.11';
  mkdirSync(path('bin'));
  const mock = (name: string, script: string) => writeFileSync(path(name), '#!/bin/sh\n' + script, { mode: 0o700 });
  mock('bin/ip', `echo '1: eth0 inet ${next}/24'`);
  mock('bin/ifconfig', `echo '  inet ${next} netmask'`);
  mock('bin/systemctl', 'case "$2" in show-environment|is-active) exit 0;; restart) echo restart >> restarted;; *) exit 1;; esac');
  mock('bin/curl', 'for last do :; done; echo "$last" >> checked; printf \'{"status":"ok"}\\n200\'');
  mock('nginx', '[ "$1" = "-t" ] && [ ! -f reject ]');
  const cli = (...args: string[]) => spawnSync(resolve('shifrctl'), [...args, '--native', '--root', dir], {
    encoding: 'utf8', env: { ...process.env, PATH: path('bin') + ':' + process.env.PATH },
  });
  assert.equal(cli('init', old).status, 0);
  // A prepared native installation also supports renewal before its first deployment.
  assert.equal(cli('renew-cert').status, 0);
  writeFileSync(path('native.env'), `ALLOWED_ORIGINS=https://${old}:8443,https://chat.lan\n`);
  writeFileSync(path('nginx.conf'), `  listen ${old}:8443 ssl;\n`);
  const crt = 'runtime/tls/server.crt', ca = 'runtime/tls/ca.crt';
  const openssl = (...args: string[]) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  // Simulate a pre-existing server certificate with a custom DNS name and IPv4 SAN.
  openssl('req', '-new', '-key', 'runtime/tls/server.key', '-subj', '/CN=chat.lan', '-out', 'custom.csr');
  writeFileSync(path('custom.ext'), `subjectAltName=IP:${old},DNS:chat.lan,IP:10.1.2.3,DNS:localhost`);
  openssl('x509', '-req', '-in', 'custom.csr', '-CA', ca, '-CAkey', 'runtime/ca/ca.key', '-set_serial', '123',
    '-days', '0', '-extfile', 'custom.ext', '-out', crt);
  const files = ['.env', 'native.env', 'nginx.conf', crt];
  const baseline = files.map(read);
  writeFileSync(path('reject'), '');
  assert.notEqual(cli('set-ip', next).status, 0);
  assert.deepEqual(files.map(read), baseline);
  rmSync(path('reject'));
  const moved = cli('set-ip', next);
  assert.equal(moved.status, 0, moved.stderr);
  assert.equal(read('nginx.conf'), `  listen ${next}:8443 ssl;\n`);
  assert.equal(read('native.env'), `ALLOWED_ORIGINS=https://${next}:8443,https://chat.lan\n`);
  openssl('verify', '-CAfile', ca, '-verify_hostname', 'chat.lan', crt);
  openssl('verify', '-CAfile', ca, '-verify_ip', '10.1.2.3', crt);
  assert.equal(read('checked'), `https://${next}:8443/health/frontend\nhttps://${next}:8443/health/ready\n`);
  const movedConfig = files.slice(0, 3).map(read);
  const renewed = cli('renew-cert');
  assert.equal(renewed.status, 0, renewed.stderr);
  assert.deepEqual(files.slice(0, 3).map(read), movedConfig);
  assert.equal(read('restarted'), 'restart\nrestart\nrestart\n');
  openssl('verify', '-CAfile', ca, '-verify_hostname', 'chat.lan', crt);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';

test('LAN setup creates a trusted certificate chain and refuses to overwrite secrets', t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-setup-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const script = resolve('scripts/setup.mjs');
  const run = (ip: string) => spawnSync(process.execPath, [script, '--ip', ip], { cwd: dir, encoding: 'utf8' });
  assert.equal(run('8.8.8.8').status, 1);
  const generated = run('192.168.1.10');
  assert.equal(generated.status, 0, generated.stderr);
  const env = readFileSync(join(dir, '.env'), 'utf8');
  const token = env.match(/^BROKER_TOKEN=(.*)$/m)![1]!;
  assert.equal(token.length, 64);
  assert.equal(generated.stdout.includes(token), false);
  assert.equal(statSync(join(dir, '.env')).mode & 0o777, 0o600);
  const cert = new X509Certificate(readFileSync(join(dir, 'runtime/tls/server.crt')));
  const ca = new X509Certificate(readFileSync(join(dir, 'runtime/tls/ca.crt')));
  assert.equal(ca.ca, true);
  assert.equal(cert.ca, false);
  assert.equal(cert.verify(ca.publicKey), true);
  assert.equal(cert.checkIP('192.168.1.10'), '192.168.1.10');
  assert.equal(cert.checkHost('localhost'), 'localhost');
  assert.equal(run('192.168.1.20').status, 1);
  assert.equal(readFileSync(join(dir, '.env'), 'utf8'), env);
});

test('init preserves existing data and recovers an interrupted publication without replacing keys', t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-init-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = (name: string) => join(dir, name);
  const run = (ip: string, env = process.env) => spawnSync(resolve('shifrctl'), ['init', '--compose', '--root', dir, ip],
    { encoding: 'utf8', env });
  mkdirSync(path('data'));
  writeFileSync(path('data/sentinel'), 'existing installation data');
  mkdirSync(path('bin'));
  writeFileSync(path('bin/openssl'), '#!/bin/sh\nexit 1\n', { mode: 0o700 });
  assert.notEqual(run('10.1.2.3', { ...process.env, PATH: path('bin') + ':' + process.env.PATH }).status, 0);
  assert.equal(existsSync(path('runtime')), false);
  assert.equal(existsSync(path('.env')), false);
  assert.equal(run('10.1.2.3').status, 0);
  const fingerprint = new X509Certificate(readFileSync(path('runtime/tls/ca.crt'))).fingerprint256;
  const env = readFileSync(path('.env'));
  renameSync(path('.env'), path('runtime/.init.env'));
  assert.notEqual(run('10.1.2.4').status, 0);
  assert.equal(run('10.1.2.3').status, 0);
  assert.equal(new X509Certificate(readFileSync(path('runtime/tls/ca.crt'))).fingerprint256, fingerprint);
  assert.ok(readFileSync(path('.env')).equals(env));
  assert.equal(readFileSync(path('data/sentinel'), 'utf8'), 'existing installation data');
  for (const key of ['runtime/ca/ca.key', 'runtime/tls/server.key']) {
    assert.equal(statSync(path(key)).mode & 0o777, 0o600);
  }
});

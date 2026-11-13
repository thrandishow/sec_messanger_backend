import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { Store } from '../src/store.js';

test('local bootstrap creates the first admin and refuses further bootstrap', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-admin-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'db.sqlite');
  const password = 'bootstrap-test-password';
  const run = (args: string[], input = '') => spawnSync(process.execPath, ['--import', 'tsx', resolve('src/admin.ts'), ...args], {
    env: { ...process.env, DATABASE_PATH: path }, input, encoding: 'utf8',
  });
  assert.equal(run(['--nickname', 'admin'], 'short').status, 1);
  const result = run(['--nickname', 'admin'], `${password}\n`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.includes(password), false);
  assert.equal(run(['--nickname', 'another'], password).status, 1);
  const store = new Store(path); t.after(() => store.close());
  assert.equal((await store.login('admin', password))?.role, 'admin');
  assert.equal(store.auditLog()[0]!.action, 'admin.bootstrap');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

import { apiBinary, testDatabase, sql } from './helpers.ts';

test('local bootstrap creates the first admin and refuses further bootstrap', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-admin-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'db.sqlite');
  const password = 'bootstrap-test-password';
  const database=testDatabase(path);
  const run = (args: string[], input = '') => spawnSync(apiBinary, ['admin', ...args], {
    env: { ...process.env, ...database }, input, encoding: 'utf8',
  });
  assert.equal(run(['--nickname', 'admin'], 'short').status, 1);
  const result = run(['--nickname', 'admin'], `${password}\n`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.includes(password), false);
  assert.equal(run(['--nickname', 'another'], password).status, 1);
  assert.equal(sql(database.PGDATABASE,'SELECT role FROM users'),'admin');
  assert.equal(sql(database.PGDATABASE,'SELECT action FROM audit'),'admin.bootstrap');
});

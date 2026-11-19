import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { apiBinary, legacyDatabase, testDatabase, sql } from './helpers.ts';

test('legacy import rolls back, retries once, preserves identity sequences and refuses a merge', t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-import-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'legacy.sqlite');
  const source = legacyDatabase(path);
  // Simulate a broken reference from an older installation.
  source.db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=OFF');
  const id = source.account('alice', 'legacy-test-password');
  source.db.exec(`
    CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,time TEXT,actor TEXT,action TEXT,subject TEXT,ip TEXT);
    INSERT INTO audit(id,time,action,ip) VALUES (91,'old','old','local');
    DELETE FROM audit;
  `);
  source.db.prepare('INSERT INTO sessions VALUES(?,?,?)').run('bad', 'missing', Date.now() + 60000);
  source.db.close();

  const target = testDatabase(path);
  function migrate(legacy: string, database = target) {
    return spawnSync(apiBinary, ['migrate'], {
      env: { ...process.env, ...database, LEGACY_SQLITE_PATH: legacy }, encoding: 'utf8',
    });
  }
  assert.equal(migrate('').status, 0);
  assert.equal(migrate(path).status, 1);
  assert.equal(sql(target.PGDATABASE, 'SELECT count(*) FROM users'), '0');
  assert.equal(sql(target.PGDATABASE, 'SELECT count(*) FROM storage_migrations'), '0');

  const repair = new DatabaseSync(path);
  repair.prepare('UPDATE sessions SET user_id=?').run(id);
  repair.close();
  assert.equal(migrate(path).status, 0);
  assert.equal(migrate(path).status, 0);
  assert.equal(sql(target.PGDATABASE, 'SELECT count(*) FROM users'), '1');
  assert.equal(sql(target.PGDATABASE,
    "INSERT INTO audit(time,action,ip) VALUES('new','test','local') RETURNING id"), '92');

  const other = testDatabase();
  const setup = spawnSync(apiBinary, ['admin', '--nickname', 'other'], {
    env: { ...process.env, ...other }, input: 'another-test-password',
  });
  assert.equal(setup.status, 0);
  const conflict = migrate(path, other);
  assert.equal(conflict.status, 1);
  assert.match(conflict.stderr, /MIGRATION_TARGET_NOT_EMPTY/);
  assert.equal(sql(other.PGDATABASE, 'SELECT nickname FROM users'), 'other');
});

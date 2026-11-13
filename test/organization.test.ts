import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Store } from '../src/store.js';
import { buildApp } from '../src/app.js';
import { testConfig } from './helpers.js';

const password = 'strong-test-password-123';
test('closed accounts, roles, departments, audit, file authorization and persistence', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-organization-'));
  const path = join(dir, 'db.sqlite');
  let store = new Store(path);
  const admin = (await store.register('admin', password, 'admin'))!;
  store.addDepartment('#finance', 'Финансы'); store.addDepartment('#engineering', 'Разработка');
  const alice = (await store.register('alice', password, 'member', '#finance'))!;
  const bob = (await store.register('bob', password, 'member', '#engineering'))!;
  const moderator = (await store.register('moderator', password, 'moderator', '#finance'))!;
  store.recordMessage(alice, '#finance', 'Private finance', new Date().toISOString());
  const secret = store.upload(alice, 'chat', 'bob', 'contract.pdf', Buffer.from('private document'), 10000)!;
  store.recordMessage(alice, 'bob', 'Document', new Date().toISOString(), secret.id);
  const config = testConfig({ databasePath: path });
  const app = await buildApp(config);
  t.after(async () => { await app.close(); store.close(); rmSync(dir, { recursive: true, force: true }); });
  const login = async (nickname: string) => {
    const r = await app.inject({ method: 'POST', url: '/api/auth/login', headers: { origin: config.origins[0]! }, payload: { nickname, password } });
    assert.equal(r.statusCode, 200); return String(r.headers['set-cookie']).split(';')[0]!;
  };
  const adminCookie = await login('admin'), aliceCookie = await login('alice'), bobCookie = await login('bob'), modCookie = await login('moderator');
  const req = (url: string, cookie: string, payload?: unknown) => app.inject({ url, method: payload === undefined ? 'GET' : 'POST',
    headers: { cookie, origin: config.origins[0]! }, ...(payload === undefined ? {} : { payload: payload as any }) });
  assert.equal((await req('/api/auth/register', '', { nickname: 'intruder', password, invitation: config.registrationToken })).statusCode, 403);
  assert.equal((await req('/api/admin/users', aliceCookie)).statusCode, 403);
  assert.equal((await req('/api/admin/audit', modCookie)).statusCode, 403);
  assert.equal((await req('/api/admin/users', modCookie, { nickname: 'intruder', password, role: 'admin', department: null })).statusCode, 403);
  assert.equal((await req('/api/admin/users', adminCookie, { nickname: 'created', password, role: 'member', department: '#finance' })).statusCode, 201);
  assert.equal((await req('/api/admin/users', adminCookie, { nickname: 'invalid', password, role: 'member', department: '#missing' })).statusCode, 400);
  assert.equal((await req(`/api/admin/users/${admin.id}`, adminCookie, { role: 'member', department: null, active: true })).statusCode, 409);
  assert.equal((await req('/api/history?target=%23finance', aliceCookie)).json().messages.length, 1);
  assert.equal((await req('/api/history?target=%23finance', bobCookie)).statusCode, 403);
  assert.equal((await req('/api/history?target=%23missing', adminCookie)).statusCode, 403);
  assert.equal((await req('/api/directory', bobCookie)).json().channels.some((c: any) => c.channel === '#finance'), false);
  assert.equal((await req('/api/history?target=bob', modCookie)).json().messages.length, 0);
  assert.equal((await req(`/api/files/${secret.id}`, modCookie)).statusCode, 404);
  assert.equal((await req(`/api/files/${secret.id}`, adminCookie)).statusCode, 404); // Admin cannot read other people's DMs.
  const downloaded = await req(`/api/files/${secret.id}`, bobCookie);
  assert.equal(downloaded.body, 'private document');
  assert.match(String(downloaded.headers['content-disposition']), /^attachment;/);
  assert.equal(downloaded.headers['content-type'], 'application/octet-stream');
  assert.match(String(downloaded.headers['content-security-policy']), /sandbox/);
  const upload = (cookie: string, scope: string, target: string, name = 'Template.html', size = 16) => app.inject({ method: 'POST',
    url: `/api/files?scope=${scope}&target=${encodeURIComponent(target)}&name=${encodeURIComponent(name)}`,
    headers: { cookie, origin: config.origins[0]!, 'content-type': 'application/octet-stream' }, payload: Buffer.alloc(size, 65) });
  assert.equal((await upload('', 'resource', '#general')).statusCode, 401);
  assert.equal((await upload(aliceCookie, 'resource', '#general')).statusCode, 403);
  assert.equal((await upload(aliceCookie, 'chat', '#announcements')).statusCode, 403);
  assert.equal((await upload(aliceCookie, 'chat', '#engineering')).statusCode, 403);
  assert.equal((await upload(aliceCookie, 'chat', '#general', '../unsafe')).statusCode, 400);
  assert.equal((await upload(aliceCookie, 'chat', '#general', 'large', 10 * 1024 * 1024 + 1)).statusCode, 413);
  const resource = await upload(modCookie, 'resource', '#general'); assert.equal(resource.statusCode, 201);
  const resourceId = resource.json().file.id;
  assert.equal((await req('/api/resources', aliceCookie)).json().files.length, 1);
  assert.equal((await req(`/api/files/${resourceId}`, aliceCookie)).statusCode, 200);
  assert.equal((await req(`/api/resources/${resourceId}/delete`, aliceCookie, {})).statusCode, 403);
  assert.equal((await req(`/api/resources/${resourceId}/delete`, modCookie, {})).statusCode, 204);
  assert.equal((await req(`/api/files/${resourceId}`, aliceCookie)).statusCode, 404);
  // Changing department immediately revokes sessions and access to department history/files.
  assert.equal((await req(`/api/admin/users/${alice.id}`, adminCookie, { role: 'member', department: '#engineering', active: true })).statusCode, 200);
  assert.equal((await req('/api/auth/me', aliceCookie)).statusCode, 401);
  const newCookie = await login('alice');
  assert.equal((await req('/api/history?target=%23finance', newCookie)).statusCode, 403);
  const audit = (await req('/api/admin/audit', adminCookie)).json().entries;
  assert.ok(audit.some((e: any) => e.action === 'auth.login'));
  assert.ok(audit.some((e: any) => e.action === 'file.upload'));
  assert.ok(audit.some((e: any) => e.action === 'user.update'));
  assert.ok(!JSON.stringify(audit).includes(password));
  store.close(); store = new Store(path);
  assert.equal(store.history(bob, 'alice').length, 1);
  assert.equal(Buffer.from(store.fileContent(secret.id)).toString(), 'private document');
  assert.ok(store.auditLog().length > 0);
  assert.equal(store.upload(bob, 'resource', '', 'over-quota', Buffer.alloc(100), 1), null);
});

test('migrates old databases without granting admin or dropping sessions', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-migrate-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'db.sqlite');
  const db = new DatabaseSync(path);
  db.exec(`CREATE TABLE users(id TEXT PRIMARY KEY, nickname TEXT NOT NULL UNIQUE COLLATE NOCASE,
    salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
    INSERT INTO users VALUES ('legacy', 'legacy', 'salt', 'hash', 1);`);
  db.close();
  const store = new Store(path); t.after(() => store.close());
  assert.equal(store.user('legacy')!.role, 'member');
  assert.equal(store.hasAdmin(), false);
  assert.equal(store.users().length, 1);
});

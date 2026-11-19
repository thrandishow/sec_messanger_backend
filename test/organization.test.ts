import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { legacyDatabase, buildApp, testConfig } from './helpers.ts';

const password = 'strong-test-password-123';
test('closed accounts, roles, departments, audit, file authorization and persistence', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'shifr-organization-'));
  const path = join(dir, 'db.sqlite');
  const seed = legacyDatabase(path);
  const admin={id:seed.account('admin',password)},alice={id:seed.account('alice',password)},bob={id:seed.account('bob',password)};
  seed.account('moderator',password);const oldCookie=seed.session(alice.id,60000);seed.db.close();
  const db=new DatabaseSync(path);
  db.exec(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'member'; ALTER TABLE users ADD COLUMN department TEXT;
    CREATE TABLE departments(channel TEXT PRIMARY KEY,name TEXT);
    CREATE TABLE files(id TEXT PRIMARY KEY,owner TEXT,scope TEXT,target TEXT,name TEXT,size INTEGER,content BLOB,created_at INTEGER);
    CREATE TABLE messages(id INTEGER PRIMARY KEY AUTOINCREMENT,sender TEXT,recipient TEXT,target TEXT,text TEXT,time TEXT,file_id TEXT);
    CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,time TEXT,actor TEXT,action TEXT,subject TEXT,ip TEXT);
    INSERT INTO audit(id,time,action,ip) VALUES(43,'2026-01-01T00:00:00.000Z','legacy.test','local');`);
  db.exec("INSERT INTO departments VALUES('#finance','Финансы'),('#engineering','Разработка'); UPDATE users SET role='admin' WHERE nickname='admin'; UPDATE users SET role='moderator' WHERE nickname='moderator'; UPDATE users SET department='#finance' WHERE nickname IN ('alice','moderator'); UPDATE users SET department='#engineering' WHERE nickname='bob'");
  const secret={id:'550e8400-e29b-41d4-a716-446655440000'};
  db.prepare("INSERT INTO files VALUES(?,?,'chat','bob','contract.pdf',16,?,?)").run(secret.id,alice.id,Buffer.from('private document'),Date.now());
  const insert=db.prepare('INSERT INTO messages(sender,recipient,target,text,time,file_id) VALUES(?,?,?,?,?,?)');
  insert.run(alice.id,null,'#finance','Private finance',new Date().toISOString(),null);
  insert.run(alice.id,bob.id,'bob','Document',new Date().toISOString(),secret.id);db.close();
  const config = testConfig({databasePath:path});const app=await buildApp(config);
  t.after(async()=>{await app.close();rmSync(dir,{recursive:true,force:true});});
  const migrated=await app.inject({url:'/api/auth/me',headers:{cookie:oldCookie}});
  assert.equal(migrated.statusCode,200);assert.equal(migrated.json().user.role,'member');
  const login = async (nickname: string) => {
    const r = await app.inject({ method: 'POST', url: '/api/auth/login', headers: { origin: config.origins[0]! }, payload: { nickname, password } });
    assert.equal(r.statusCode, 200); return String(r.headers['set-cookie']).split(';')[0]!;
  };
  const adminCookie = await login('admin'), aliceCookie = await login('alice'), bobCookie = await login('bob'), modCookie = await login('moderator');
  const req = (url: string, cookie: string, payload?: unknown) => app.inject({ url, method: payload === undefined ? 'GET' : 'POST',
    headers: { cookie, origin: config.origins[0]! }, ...(payload === undefined ? {} : { payload: payload as any }) });
  assert.equal((await req('/api/auth/register', '', { nickname: 'intruder', password, invitation: 'closed' })).statusCode, 403);
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
  assert.ok(audit.some((e: any) => e.action === 'legacy.test' && e.id===43));
  assert.ok(audit.some((e: any) => e.action === 'auth.login' && e.id>43));
  assert.ok(audit.some((e: any) => e.action === 'file.upload'));
  assert.ok(audit.some((e: any) => e.action === 'user.update'));
  assert.ok(!JSON.stringify(audit).includes(password));
});

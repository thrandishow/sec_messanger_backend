import test from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from '../src/app.js';
import { testConfig } from './helpers.js';

test('registration, login, cookie session, and logout work without exposing secrets', async t => {
  const config = testConfig();
  const app = await buildApp(config);
  t.after(() => app.close());
  const headers = { origin: config.origins[0]! };
  const credentials = { nickname: 'Alice', password: 'a-strong-password-123' };
  const denied = await app.inject({ method: 'POST', url: '/api/auth/register', headers,
    payload: { ...credentials, invitation: 'wrong' } });
  assert.equal(denied.statusCode, 403);
  const register = await app.inject({ method: 'POST', url: '/api/auth/register', headers,
    payload: { ...credentials, invitation: config.registrationToken } });
  assert.equal(register.statusCode, 201);
  assert.equal(register.json().user.nickname, 'alice');
  assert.ok(!register.body.includes(credentials.password));
  assert.ok(!register.body.includes(config.registrationToken));
  const cookie = String(register.headers['set-cookie']).split(';')[0]!;
  assert.match(String(register.headers['set-cookie']), /HttpOnly/);
  assert.match(String(register.headers['set-cookie']), /SameSite=Strict/);
  const me = await app.inject({ url: '/api/auth/me', headers: { cookie } });
  assert.equal(me.statusCode, 200);
  assert.deepEqual((await app.inject({ url: '/api/chat/status', headers: { cookie } })).json(), { connected: false });
  assert.equal((await app.inject({ url: '/api/chat/status' })).statusCode, 401);
  const duplicate = await app.inject({ method: 'POST', url: '/api/auth/register', headers,
    payload: { ...credentials, invitation: config.registrationToken } });
  assert.equal(duplicate.statusCode, 409);
  const badLogin = await app.inject({ method: 'POST', url: '/api/auth/login', headers,
    payload: { ...credentials, password: 'wrong-password-123' } });
  assert.equal(badLogin.statusCode, 401);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', headers, payload: credentials });
  assert.equal(login.statusCode, 200);
  assert.notEqual(String(login.headers['set-cookie']).split(';')[0], cookie);
  assert.equal((await app.inject({ method: 'POST', url: '/api/auth/logout', headers: { ...headers, cookie } })).statusCode, 204);
  assert.equal((await app.inject({ url: '/api/auth/me', headers: { cookie } })).statusCode, 401);
  assert.equal((await app.inject({ url: '/api/auth/me' })).statusCode, 401);
});

test('private single-hop proxy preserves client IP checks and separates rate limits', async t => {
  const config = testConfig({ trustProxy: true });
  const app = await buildApp(config);
  t.after(() => app.close());
  assert.equal((await app.inject({ url: '/health/live', remoteAddress: '172.20.0.2',
    headers: { 'x-forwarded-for': '8.8.8.8' } })).statusCode, 403);
  for (let i = 0; i < 11; i++) await app.inject({ method: 'POST', url: '/api/auth/login',
    remoteAddress: '172.20.0.2', headers: { origin: config.origins[0]!, 'x-forwarded-for': '192.168.1.10' }, payload: {} });
  assert.equal((await app.inject({ method: 'POST', url: '/api/auth/login', remoteAddress: '172.20.0.2',
    headers: { origin: config.origins[0]!, 'x-forwarded-for': '192.168.1.11' }, payload: {} })).statusCode, 400);
});

test('CSRF, origin allowlist, public IPs, and request size are enforced', async t => {
  const config = testConfig();
  const app = await buildApp(config);
  t.after(() => app.close());
  for (const origin of [undefined, 'http://evil.example', 'null']) {
    const result = await app.inject({ method: 'POST', url: '/api/auth/login',
      headers: origin ? { origin } : {}, payload: {} });
    assert.equal(result.statusCode, 403);
  }
  assert.equal((await app.inject({ url: '/health/live', remoteAddress: '8.8.8.8',
    headers: { 'x-forwarded-for': '127.0.0.1' } })).statusCode, 403);
  const tooBig = await app.inject({ method: 'POST', url: '/api/auth/login',
    headers: { origin: config.origins[0]! }, payload: { data: 'x'.repeat(5000) } });
  assert.equal(tooBig.statusCode, 413);
  const preflight = await app.inject({ method: 'OPTIONS', url: '/api/auth/login',
    headers: { origin: config.origins[0]!, 'access-control-request-method': 'POST' } });
  assert.equal(preflight.statusCode, 204);
  assert.equal(preflight.headers['access-control-allow-origin'], config.origins[0]);
});

test('login attempts are rate limited', async t => {
  const config = testConfig();
  const app = await buildApp(config);
  t.after(() => app.close());
  for (let i = 0; i < 10; i++) {
    assert.equal((await app.inject({ method: 'POST', url: '/api/auth/login',
      headers: { origin: config.origins[0]! }, payload: {} })).statusCode, 400);
  }
  assert.equal((await app.inject({ method: 'POST', url: '/api/auth/login',
    headers: { origin: config.origins[0]! }, payload: {} })).statusCode, 429);
});

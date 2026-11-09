import test from 'node:test';
import assert from 'node:assert/strict';
import { clientCommandSchema, parseIrcLine } from '../src/protocol.js';
import { isLocalAddress, loadConfig } from '../src/config.js';

test('IRCv3 tags, prefixes, and trailing text are preserved', () => {
  const m = parseIrcLine('@time=2026-11-09T12:00:00.000Z;label=hello\\sworld :alice!u@host PRIVMSG #general :Привет, мир');
  assert.equal(m?.tags.time, '2026-11-09T12:00:00.000Z');
  assert.equal(m?.tags.label, 'hello world');
  assert.deepEqual(m?.params, ['#general', 'Привет, мир']);
  assert.equal(parseIrcLine('PING :abc')?.params[0], 'abc');
  assert.equal(parseIrcLine(':broken'), null);
});

test('JSON protocol rejects IRC injection, multiple targets, and UTF-8 overflow', () => {
  for (const text of ['hello\r\nOPER root', 'hello\0', '\x01ACTION test\x01', 'я'.repeat(176)]) {
    assert.equal(clientCommandSchema.safeParse({ type: 'message', target: '#general', text }).success, false);
  }
  for (const target of ['#one,#two', 'alice bob', '#one\nJOIN #two']) {
    assert.equal(clientCommandSchema.safeParse({ type: 'message', target, text: 'hi' }).success, false);
  }
  assert.equal(clientCommandSchema.safeParse({ type: 'raw', command: 'OPER root' }).success, false);
  assert.equal(clientCommandSchema.safeParse({ type: 'message', target: '#general', text: 'я'.repeat(175) }).success, true);
});

test('only local addresses are accepted, including Docker and IPv4-mapped IPv6', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.1.1', '192.168.1.1', '::ffff:192.168.1.1', '::1', 'fd00::1']) {
    assert.equal(isLocalAddress(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '172.32.0.1', '172.15.0.1', '192.169.1.1', 'example.com', 'fcwhatever', '2001:4860:4860::8888']) {
    assert.equal(isLocalAddress(ip), false, ip);
  }
});

test('configuration refuses LAN plaintext, wildcard origins, and missing secrets', () => {
  const env = { IRC_PASSWORD: 'a'.repeat(64), REGISTRATION_TOKEN: 'b'.repeat(64), ALLOWED_ORIGINS: 'http://127.0.0.1:3000' };
  assert.equal(loadConfig(env).host, '127.0.0.1');
  assert.throws(() => loadConfig({ ...env, HOST: '0.0.0.0' }), /TLS/);
  assert.throws(() => loadConfig({ ...env, ALLOWED_ORIGINS: '*' }), /ORIGINS/);
  assert.throws(() => loadConfig({ ...env, ALLOWED_ORIGINS: 'http://evil.example' }), /ORIGINS/);
  assert.throws(() => loadConfig({ ...env, IRC_PASSWORD: undefined }), /IRC_PASSWORD/);
  assert.throws(() => loadConfig({ ...env, TLS_CERT_PATH: 'x' }), /both TLS/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { parseEnv } from 'node:util';
import { createServer, createConnection } from 'node:net';
import { request } from 'node:https';
import { WebSocket } from 'ws';
import { buildApp } from '../../src/app.js';
import { loadConfig } from '../../src/config.js';
import type { ServerEvent } from '../../src/protocol.js';

async function freePort() {
  const server = createServer();
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = (server.address() as { port: number }).port;
  await new Promise<void>(resolve => server.close(() => resolve()));
  return port;
}

async function portReady(port: number) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const ok = await new Promise<boolean>(resolve => {
      const socket = createConnection({ host: '127.0.0.1', port });
      socket.once('connect', () => { socket.destroy(); resolve(true); });
      socket.once('error', () => { socket.destroy(); resolve(false); });
    });
    if (ok) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('Test listener did not start with the project configuration');
}

function inbox(ws: WebSocket) {
  const events: ServerEvent[] = [];
  let notify = () => {};
  ws.on('message', data => { events.push(JSON.parse(data.toString()) as ServerEvent); notify(); });
  return {
    send: (command: unknown) => ws.send(JSON.stringify(command)),
    wait: (predicate: (event: ServerEvent) => boolean) => new Promise<ServerEvent>((resolve, reject) => {
      const timeout = setTimeout(() => {
        notify = () => {};
        reject(new Error(`Missing ${predicate.toString()}; received ${events.map(e => e.type === 'error' ? e.code : e.type).join(', ')}`));
      }, 5000);
      notify = () => {
        const index = events.findIndex(predicate);
        if (index === -1) return;
        clearTimeout(timeout);
        const event = events.splice(index, 1)[0]!;
        notify = () => {};
        resolve(event);
      };
      notify();
    }),
  };
}

test('real InspIRCd: HTTPS auth, WSS rooms, direct messages, logout, expiry, and outage', { timeout: 30_000 }, async t => {
  assert.ok(process.env.INSPIRCD_BINARY, 'Set INSPIRCD_BINARY to a built InspIRCd 4.12.1 executable');
  const dir = mkdtempSync(join(tmpdir(), 'shifr-integration-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const ircPort = await freePort();
  const proxied = process.env.SHIFR_TEST_PROXY === '1';
  if (proxied) assert.ok(process.env.NGINX_BINARY, 'Set NGINX_BINARY to a local Nginx executable');
  const proxyPort = proxied ? await freePort() : 3000;
  assert.equal(spawnSync(process.execPath, [resolve('scripts/setup.mjs'), '--ip', '192.168.1.10'],
    { cwd: dir, stdio: 'ignore' }).status, 0);
  const ca = readFileSync(join(dir, 'runtime/tls/ca.crt'));
  const config = loadConfig({ ...parseEnv(readFileSync(join(dir, '.env'), 'utf8')),
    HOST: '127.0.0.1', IRC_PORT: String(ircPort), ALLOWED_ORIGINS: `https://127.0.0.1:${proxyPort}`,
    TRUST_PROXY: proxied ? '1' : '0',
    TLS_CERT_PATH: join(dir, 'runtime/tls/server.crt'), TLS_KEY_PATH: join(dir, 'runtime/tls/server.key'),
    DATABASE_PATH: join(dir, 'db.sqlite') });
  const connectFile = join(dir, 'runtime/irc-connect.conf');
  const ircConfig = readFileSync(resolve('docker/inspircd/inspircd.conf'), 'utf8')
    .replace('address="0.0.0.0" port="6667"', `address="127.0.0.1" port="${ircPort}"`)
    .replace('/run/shifr/irc-connect.conf', connectFile);
  const configFile = join(dir, 'inspircd.conf');
  writeFileSync(configFile, ircConfig);
  const ircd = spawn(process.env.INSPIRCD_BINARY, ['--nofork', '--nopid', '--nolog', '--config', configFile], { stdio: 'ignore' });
  t.after(async () => {
    if (ircd.exitCode === null && ircd.signalCode === null) {
      const exited = once(ircd, 'exit'); ircd.kill('SIGTERM'); await exited;
    }
  });
  await portReady(ircPort);
  const app = await buildApp(config);
  t.after(() => app.close());
  await app.listen({ host: '127.0.0.1', port: 0 });
  const apiPort = (app.server.address() as { port: number }).port;
  const port = proxied ? proxyPort : apiPort;
  if (proxied) {
    const frontDir = resolve(process.env.SHIFR_FRONT_DIR ?? '../project_front');
    const nginxConfig = readFileSync(join(frontDir, 'nginx.conf'), 'utf8')
      .replace('worker_processes auto;', 'worker_processes 1;')
      .replace('include /etc/nginx/mime.types;', 'types { text/html html; application/javascript js; text/css css; image/svg+xml svg; }')
      .replace('listen 8443 ssl;', `listen 127.0.0.1:${port} ssl;`)
      .replaceAll('/tmp/', `${dir}/`)
      .replaceAll('/tls/', `${dir}/runtime/tls/`)
      .replace('/usr/share/nginx/html', `${frontDir}/out`)
      .replace('https://api:8443', `https://127.0.0.1:${apiPort}`);
    mkdirSync(join(dir, 'logs'));
    const nginxFile = join(dir, 'nginx.conf');
    writeFileSync(nginxFile, nginxConfig);
    const syntax = spawnSync(process.env.NGINX_BINARY!, ['-t', '-p', dir, '-c', nginxFile], { encoding: 'utf8' });
    assert.equal(syntax.status, 0, syntax.stderr);
    const nginx = spawn(process.env.NGINX_BINARY!, ['-p', dir, '-c', nginxFile, '-g', 'daemon off;'], { stdio: 'ignore' });
    t.after(async () => {
      if (nginx.exitCode === null && nginx.signalCode === null) {
        const exited = once(nginx, 'exit'); nginx.kill('SIGTERM'); await exited;
      }
    });
    await portReady(port);
  }
  const origin = config.origins[0]!;
  const http = (path: string, payload?: unknown, cookie?: string, trusted = true) => new Promise<{
    status: number; body: string; cookie: string; setCookie: string;
  }>((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method: payload === undefined ? 'GET' : 'POST',
      ...(trusted ? { ca } : {}), headers: { origin, 'content-type': 'application/json', ...(cookie ? { cookie } : {}) } }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode!, body,
        cookie: res.headers['set-cookie']?.[0]?.split(';')[0] ?? '', setCookie: res.headers['set-cookie']?.[0] ?? '' }));
    });
    req.on('error', reject);
    req.end(payload === undefined ? undefined : JSON.stringify(payload));
  });
  assert.equal((await http('/health/ready')).status, 200);
  if (proxied) {
    const page = await http('/');
    assert.equal(page.status, 200);
    assert.match(page.body, /Шифр-связь/);
    const scripts = [...page.body.matchAll(/src="([^"\s]+\.js[^"\s]*)"/g)].map(match => match[1]!);
    assert.ok(scripts.length > 0, 'Next.js JavaScript bundles are present');
    for (const path of scripts) {
      assert.ok(path.startsWith('/_next/static/'), 'JavaScript is served locally');
      assert.equal((await http(path)).status, 200);
    }
    assert.equal((await http('/health/frontend')).status, 200);
  }
  await assert.rejects(http('/health/live', undefined, undefined, false), /certificate|self.signed/i);
  const register = async (nickname: string) => {
    const result = await http('/api/auth/register', { nickname, password: 'test-password-123', invitation: config.registrationToken });
    assert.equal(result.status, 201);
    assert.match(result.setCookie, /Secure/);
    return result.cookie;
  };
  const aliceCookie = await register('alice');
  const bobCookie = await register('bob');
  assert.equal(JSON.parse((await http('/api/chat/status', undefined, aliceCookie)).body).connected, false);
  const rejectedWs = (cookie: string, requestOrigin: string | undefined, status: number) => new Promise<void>((resolve, reject) => {
    const ws = new WebSocket(`wss://127.0.0.1:${port}/ws`, { ca, headers: { cookie }, origin: requestOrigin });
    ws.on('error', () => {});
    ws.on('unexpected-response', (_req, res) => {
      res.resume(); ws.terminate();
      try { assert.equal(res.statusCode, status); resolve(); } catch (error) { reject(error); }
    });
    ws.on('open', () => { ws.terminate(); reject(new Error('Unauthorized WebSocket was accepted')); });
  });
  await rejectedWs('', origin, 401);
  await rejectedWs(aliceCookie, 'https://evil.example', 403);
  await rejectedWs(aliceCookie, undefined, 403);
  const alice = new WebSocket(`wss://127.0.0.1:${port}/ws`, { ca, origin, headers: { cookie: aliceCookie } });
  const aliceEvents = inbox(alice);
  t.after(() => alice.terminate());
  assert.equal((await aliceEvents.wait(e => e.type === 'ready')).type, 'ready');
  assert.equal(JSON.parse((await http('/api/chat/status', undefined, aliceCookie)).body).connected, true);
  const bob = new WebSocket(`wss://127.0.0.1:${port}/ws`, { ca, origin, headers: { cookie: bobCookie } });
  const bobEvents = inbox(bob);
  t.after(() => bob.terminate());
  await bobEvents.wait(e => e.type === 'ready');
  await rejectedWs(aliceCookie, origin, 409);
  aliceEvents.send({ type: 'join', channel: '#general' });
  await aliceEvents.wait(e => e.type === 'join' && e.nickname === 'alice');
  bobEvents.send({ type: 'join', channel: '#general' });
  await bobEvents.wait(e => e.type === 'join' && e.nickname === 'bob');
  await aliceEvents.wait(e => e.type === 'join' && e.nickname === 'bob');
  aliceEvents.send({ type: 'names', channel: '#general' });
  const names = await aliceEvents.wait(e => e.type === 'names' && e.members.some(m => m.nickname === 'bob'));
  assert.equal(names.type === 'names' && names.members.length, 2);
  aliceEvents.send({ type: 'message', target: '#general', text: 'Привет из LAN 🔐' });
  const received = await bobEvents.wait(e => e.type === 'message');
  assert.equal(received.type === 'message' && received.text, 'Привет из LAN 🔐');
  assert.equal(received.type === 'message' && received.from, 'alice');
  assert.ok(received.type === 'message' && !Number.isNaN(Date.parse(received.time)));
  await aliceEvents.wait(e => e.type === 'message' && e.text === 'Привет из LAN 🔐'); // server echo
  bobEvents.send({ type: 'message', target: 'alice', text: 'Личное сообщение' });
  await aliceEvents.wait(e => e.type === 'message' && e.target === 'alice' && e.text === 'Личное сообщение');
  aliceEvents.send({ type: 'message', target: '#general', text: 'test\r\nJOIN #injected' });
  await aliceEvents.wait(e => e.type === 'error' && e.code === 'INVALID_COMMAND');
  aliceEvents.send({ type: 'message', target: 'nobody', text: 'Offline?' });
  await aliceEvents.wait(e => e.type === 'error' && e.code === 'IRC_401');
  bobEvents.send({ type: 'part', channel: '#general' });
  await aliceEvents.wait(e => e.type === 'part' && e.nickname === 'bob');
  const aliceClosed = once(alice, 'close');
  assert.equal((await http('/api/auth/logout', {}, aliceCookie)).status, 204);
  await aliceClosed;
  await rejectedWs(aliceCookie, origin, 401);

  await t.test('session expiry disconnects a live WebSocket', async sub => {
    const shortApp = await buildApp({ ...config, databasePath: ':memory:', sessionTtlSeconds: 3 });
    sub.after(() => shortApp.close());
    const result = await shortApp.inject({ method: 'POST', url: '/api/auth/register', headers: { origin },
      payload: { nickname: 'expires', password: 'test-password-123', invitation: config.registrationToken } });
    assert.equal(result.statusCode, 201);
    await shortApp.listen({ host: '127.0.0.1', port: 0 });
    const shortPort = (shortApp.server.address() as { port: number }).port;
    const ws = new WebSocket(`wss://127.0.0.1:${shortPort}/ws`, { ca, origin,
      headers: { cookie: String(result.headers['set-cookie']).split(';')[0]! } });
    const events = inbox(ws);
    sub.after(() => ws.terminate());
    await events.wait(e => e.type === 'ready');
    await once(ws, 'close');
  });

  const bobClosed = once(bob, 'close');
  const ircExited = once(ircd, 'exit');
  ircd.kill('SIGTERM');
  await ircExited;
  await bobClosed;
  assert.equal((await http('/health/ready')).status, 503);
  assert.equal((await http('/health/live')).status, 200);
});

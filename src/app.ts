import Fastify, { LogController } from 'fastify';
import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import websocket from '@fastify/websocket';
import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { WebSocket } from 'ws';
import { isLocalAddress, type Config } from './config.js';
import { Store, equalSecret } from './store.js';
import { IrcBridge, probeIrc } from './irc.js';
import { clientCommandSchema, nicknameSchema, type ServerEvent } from './protocol.js';

export const COOKIE_NAME = 'shifr_session';
const credentialsSchema = z.object({ nickname: nicknameSchema, password: z.string().min(12).max(128) }).strict();
const registerSchema = credentialsSchema.extend({ invitation: z.string().max(128) });

export async function buildApp(config: Config, options: { logger?: boolean } = {}) {
  const app = Fastify({
    logger: options.logger ? { redact: ['req.headers.cookie', 'req.headers.authorization', 'req.body', 'res.headers["set-cookie"]'] } : false,
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: false,
    bodyLimit: 4096,
    requestTimeout: 10_000,
    ...(config.tlsCert && config.tlsKey ? { https: { cert: readFileSync(config.tlsCert), key: readFileSync(config.tlsKey) } } : {}),
  });
  const store = new Store(config.databasePath);
  const active = new Map<string, { socket: WebSocket; tokenHash: string; close: () => void }>();

  app.addHook('onRequest', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    reply.header('X-Content-Type-Options', 'nosniff');
    if (!isLocalAddress(request.ip)) return reply.code(403).send({ error: 'LAN_ONLY' });
    const origin = request.headers.origin;
    if ((origin && !config.origins.includes(origin))
      || (!['GET', 'HEAD'].includes(request.method) && !origin)) {
      return reply.code(403).send({ error: 'ORIGIN_DENIED' });
    }
  });
  await app.register(cookie);
  await app.register(cors, { origin: config.origins, credentials: true, methods: ['GET', 'POST'], maxAge: 600 });
  await app.register(rateLimit, { max: 120, timeWindow: '1 minute' });
  await app.register(websocket, { options: { maxPayload: 4096, perMessageDeflate: false },
    preClose(done) {
      for (const connection of active.values()) connection.close();
      this.websocketServer.close(done);
    },
  });
  app.addHook('onClose', async () => store.close());
  app.setErrorHandler((error, _request, reply) => {
    const status = error && typeof error === 'object' && 'statusCode' in error
      && typeof error.statusCode === 'number' ? error.statusCode : 500;
    // Do not serialize exception messages, payloads, passwords, or SQL.
    reply.code(status).send({ error: status >= 500 ? 'INTERNAL_ERROR' : 'INVALID_REQUEST' });
  });

  const cookieOptions = { httpOnly: true, secure: config.secureCookies, sameSite: 'strict' as const, path: '/' };
  const sessionFrom = (token?: string) => store.getSession(token);

  app.get('/health/live', async () => ({ status: 'ok' }));
  app.get('/health/ready', async (_request, reply) => {
    const irc = await probeIrc(config);
    return reply.code(irc ? 200 : 503).send({ status: irc ? 'ok' : 'unavailable', irc });
  });
  app.get('/api/config', async () => ({ name: 'Шифр-связь', protocolVersion: 1,
    registration: 'invitation', messageMaxBytes: 350, history: false, endToEndEncryption: false }));

  app.post('/api/auth/register', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (request, reply) => {
    const body = registerSchema.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: 'INVALID_INPUT' });
    if (!equalSecret(body.data.invitation, config.registrationToken)) return reply.code(403).send({ error: 'INVALID_INVITATION' });
    const user = await store.register(body.data.nickname, body.data.password);
    if (!user) return reply.code(409).send({ error: 'NICKNAME_TAKEN' });
    const session = store.createSession(user, config.sessionTtlSeconds);
    reply.setCookie(COOKIE_NAME, session.token, { ...cookieOptions, maxAge: config.sessionTtlSeconds });
    return reply.code(201).send({ user, expiresAt: session.expiresAt });
  });
  app.post('/api/auth/login', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (request, reply) => {
    const body = credentialsSchema.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: 'INVALID_INPUT' });
    const user = await store.login(body.data.nickname, body.data.password);
    if (!user) return reply.code(401).send({ error: 'INVALID_CREDENTIALS' });
    const session = store.createSession(user, config.sessionTtlSeconds);
    reply.setCookie(COOKIE_NAME, session.token, { ...cookieOptions, maxAge: config.sessionTtlSeconds });
    return { user, expiresAt: session.expiresAt };
  });
  app.get('/api/auth/me', async (request, reply) => {
    const session = sessionFrom(request.cookies[COOKIE_NAME]);
    return session ? { user: session.user, expiresAt: session.expiresAt } : reply.code(401).send({ error: 'UNAUTHORIZED' });
  });
  app.post('/api/auth/logout', async (request, reply) => {
    const token = request.cookies[COOKIE_NAME];
    const session = sessionFrom(token);
    if (token) store.revoke(token);
    if (session) {
      const connection = active.get(session.user.id);
      if (connection?.tokenHash === session.tokenHash) connection.close();
    }
    reply.clearCookie(COOKIE_NAME, cookieOptions);
    return reply.code(204).send();
  });

  app.get('/ws', { websocket: true, preValidation: async (request, reply) => {
    if (!request.headers.origin || !config.origins.includes(request.headers.origin)) {
      return reply.code(403).send({ error: 'ORIGIN_DENIED' });
    }
    const session = sessionFrom(request.cookies[COOKIE_NAME]);
    if (!session) return reply.code(401).send({ error: 'UNAUTHORIZED' });
    if (active.has(session.user.id)) return reply.code(409).send({ error: 'ALREADY_CONNECTED' });
  } }, (socket, request) => {
    const session = sessionFrom(request.cookies[COOKIE_NAME]);
    if (!session) return socket.close(1008, 'Session expired');
    // Check again after upgrade to cover simultaneous handshakes.
    if (active.has(session.user.id)) return socket.close(1008, 'Already connected');
    const emit = (event: ServerEvent) => {
      if (socket.readyState !== WebSocket.OPEN) return;
      if (socket.bufferedAmount > 64 * 1024) { socket.terminate(); return; }
      socket.send(JSON.stringify(event));
    };
    const bridge = new IrcBridge(config, session.user.nickname, emit, () => socket.close(1011, 'IRC unavailable'));
    let cleaned = false;
    let alive = true;
    let tokens = 20;
    let lastRefill = Date.now();
    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      clearInterval(heartbeat);
      clearTimeout(expiry);
      bridge.close();
      active.delete(session.user.id);
    };
    const close = () => { cleanup(); socket.terminate(); };
    const expiry = setTimeout(close, Math.max(1, session.expiresAt - Date.now()));
    const heartbeat = setInterval(() => {
      if (!alive || !sessionFrom(request.cookies[COOKIE_NAME])) return close();
      alive = false;
      socket.ping();
    }, 30_000);
    active.set(session.user.id, { socket, tokenHash: session.tokenHash, close });
    socket.on('pong', () => { alive = true; });
    socket.on('error', close);
    socket.on('close', cleanup);
    socket.on('message', (data, binary) => {
      if (!sessionFrom(request.cookies[COOKIE_NAME])) return close();
      const now = Date.now();
      tokens = Math.min(20, tokens + (now - lastRefill) / 1000 * 5);
      lastRefill = now;
      if (tokens < 1) return socket.close(1008, 'Rate limit exceeded');
      tokens--;
      if (binary) return socket.close(1003, 'Text JSON required');
      let value: unknown;
      try { value = JSON.parse(data.toString()); } catch {
        emit({ type: 'error', code: 'INVALID_JSON', message: 'Expected JSON' });
        return;
      }
      const parsed = clientCommandSchema.safeParse(value);
      if (!parsed.success) {
        emit({ type: 'error', code: 'INVALID_COMMAND', message: 'Invalid command or message exceeds 350 UTF-8 bytes' });
        return;
      }
      bridge.command(parsed.data);
    });
  });

  return app;
}

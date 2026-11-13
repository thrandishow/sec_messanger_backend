import Fastify, { LogController } from 'fastify';
import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import websocket from '@fastify/websocket';
import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { WebSocket } from 'ws';
import { isLocalAddress, type Config } from './config.js';
import { Store } from './store.js';
import { IrcBridge, probeIrc } from './irc.js';
import { organizationRoutes, FILE_LIMIT } from './organization.js';
import { clientCommandSchema, nicknameSchema, type ServerEvent } from './protocol.js';

export const COOKIE_NAME = 'shifr_session';
const credentialsSchema = z.object({ nickname: nicknameSchema, password: z.string().min(12).max(128) }).strict();

export async function buildApp(config: Config, options: { logger?: boolean } = {}) {
  const app = Fastify({
    logger: options.logger ? { redact: ['req.headers.cookie', 'req.headers.authorization', 'req.body', 'res.headers["set-cookie"]'] } : false,
    logController: new LogController({ disableRequestLogging: true }),
    // Enabled only behind our unexposed, single-hop Nginx proxy, which overwrites X-Forwarded-For.
    trustProxy: config.trustProxy ? (address, hop) => hop === 0 && isLocalAddress(address) : false,
    bodyLimit: 4096,
    requestTimeout: 10_000,
    ...(config.tlsCert && config.tlsKey ? { https: { cert: readFileSync(config.tlsCert), key: readFileSync(config.tlsKey) } } : {}),
  });
  const store = new Store(config.databasePath);
  const active = new Map<string, { socket: WebSocket; tokenHash: string; close: () => void; emit: (event: ServerEvent) => void; joined: Set<string> }>();

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
  organizationRoutes(app, store, id => active.get(id)?.close());
  app.get('/api/config', async () => ({ name: 'Шифр-связь', protocolVersion: 2,
    registration: 'admin', messageMaxBytes: 350, history: true, fileMaxBytes: FILE_LIMIT, endToEndEncryption: false }));
  app.post('/api/auth/register', async (_request, reply) => reply.code(403).send({ error: 'REGISTRATION_CLOSED' }));

  app.post('/api/auth/login', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (request, reply) => {
    const body = credentialsSchema.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: 'INVALID_INPUT' });
    const user = await store.login(body.data.nickname, body.data.password);
    if (!user) { store.audit(null, 'auth.login_failed', body.data.nickname.toLowerCase(), request.ip); return reply.code(401).send({ error: 'INVALID_CREDENTIALS' }); }
    store.audit(user.id, 'auth.login', user.id, request.ip);
    const session = store.createSession(user, config.sessionTtlSeconds);
    reply.setCookie(COOKIE_NAME, session.token, { ...cookieOptions, maxAge: config.sessionTtlSeconds });
    return { user, expiresAt: session.expiresAt };
  });
  app.get('/api/auth/me', async (request, reply) => {
    const session = sessionFrom(request.cookies[COOKIE_NAME]);
    return session ? { user: session.user, expiresAt: session.expiresAt } : reply.code(401).send({ error: 'UNAUTHORIZED' });
  });
  app.get('/api/chat/status', async (request, reply) => {
    const session = sessionFrom(request.cookies[COOKIE_NAME]);
    if (!session) return reply.code(401).send({ error: 'UNAUTHORIZED' });
    return { connected: active.has(session.user.id) };
  });
  app.post('/api/auth/logout', async (request, reply) => {
    const token = request.cookies[COOKIE_NAME];
    const session = sessionFrom(token);
    if (token) store.revoke(token);
    if (session) {
      store.audit(session.user.id, 'auth.logout', session.user.id, request.ip);
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
    const deliver = (event: ServerEvent) => {
      if (socket.readyState !== WebSocket.OPEN) return;
      if (socket.bufferedAmount > 64 * 1024) { socket.terminate(); return; }
      socket.send(JSON.stringify(event));
    };
    const joined = new Set<string>();
    let pending: { target: string; text: string; attachmentId?: string } | null = null;
    let pendingTimer: NodeJS.Timeout | undefined;
    const emit = (event: ServerEvent) => {
      if (event.type === 'join' && event.nickname === session.user.nickname) joined.add(event.channel);
      if (event.type === 'part' && event.nickname === session.user.nickname) joined.delete(event.channel);
      if (event.type === 'error') { pending = null; clearTimeout(pendingTimer); }
      if (event.type !== 'message') { deliver(event); return; }
      // A single persistence point: only the sender's IRC echo confirms delivery.
      // Other IRC connections receive the same message; ignoring those avoids duplicate rows.
      if (event.from !== session.user.nickname || !pending || event.target !== pending.target || event.text !== pending.text) return;
      const outgoing = pending;
      pending = null; clearTimeout(pendingTimer);
      const currentSession = sessionFrom(request.cookies[COOKIE_NAME]);
      if (!currentSession || !store.canWrite(currentSession.user, event.target)) return;
      try {
        const saved = store.recordMessage(currentSession.user, event.target, event.text, event.time, outgoing.attachmentId);
        for (const [id, connection] of active) {
          const viewer = store.user(id);
          if (!viewer?.active) continue;
          const allowed = event.target.startsWith('#')
            ? connection.joined.has(event.target) && store.canRead(viewer, event.target)
            : id === currentSession.user.id || viewer.nickname === event.target;
          if (allowed) connection.emit({ type: 'message', ...saved });
        }
      } catch {
        deliver({ type: 'error', code: 'STORAGE_ERROR', message: 'Message was not saved. Try again.' });
      }
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
      clearTimeout(pendingTimer);
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
    active.set(session.user.id, { socket, tokenHash: session.tokenHash, close, emit: deliver, joined });
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
      const command = parsed.data;
      const currentUser = sessionFrom(request.cookies[COOKIE_NAME])?.user;
      if (!currentUser) return close();
      if (command.type !== 'ping') {
        const target = command.type === 'message' ? command.target.toLowerCase() : command.channel;
        if (command.type === 'message') command.target = target;
        if (!(command.type === 'message' ? store.canWrite(currentUser, target) : store.canRead(currentUser, target))) {
          deliver({ type: 'error', code: 'FORBIDDEN', message: 'Access denied' }); return;
        }
        if (command.type === 'message') {
          if (pending) { deliver({ type: 'error', code: 'MESSAGE_PENDING', message: 'Wait for confirmation' }); return; }
          if (target.startsWith('#') && !joined.has(target)) { deliver({ type: 'error', code: 'NOT_JOINED', message: 'Join first' }); return; }
          if (command.attachmentId && !store.attachmentAllowed(currentUser, command.attachmentId, target)) {
            deliver({ type: 'error', code: 'FORBIDDEN', message: 'Attachment unavailable' }); return;
          }
          pending = command;
          pendingTimer = setTimeout(() => {
            pending = null;
            deliver({ type: 'error', code: 'MESSAGE_TIMEOUT', message: 'No server confirmation' });
          }, 10_000);
        }
      }
      bridge.command(command);
    });
  });

  return app;
}

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { Store, User } from './store.js';
import { nicknameSchema, channelSchema } from './protocol.js';

export const FILE_LIMIT = 10 * 1024 * 1024;
const role = z.enum(['admin', 'moderator', 'member']);
const password = z.string().min(12).max(128);
const account = z.object({ nickname: nicknameSchema, password, role, department: channelSchema.nullable() }).strict();
const userUpdate = z.object({ role, department: channelSchema.nullable(), active: z.boolean(), password: password.optional() }).strict();
const target = z.union([channelSchema, nicknameSchema]).transform(s => s.toLowerCase());
const cursor = z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional();

export function organizationRoutes(app: FastifyInstance, store: Store, closeUser: (id: string) => void) {
  const auth = (req: FastifyRequest, reply: FastifyReply, admin = false): User | null => {
    const user = store.getSession(req.cookies.shifr_session)?.user;
    if (!user) { reply.code(401).send({ error: 'UNAUTHORIZED' }); return null; }
    if (admin && user.role !== 'admin') { reply.code(403).send({ error: 'FORBIDDEN' }); return null; }
    return user;
  };
  app.get('/api/directory', async (req, reply) => {
    const user = auth(req, reply); if (!user) return;
    return { channels: [
      { channel: '#general', name: 'Общий чат' }, { channel: '#announcements', name: 'Объявления' },
      ...store.departments().filter(d => store.canRead(user, d.channel)),
    ], users: store.users().filter(u => u.active).map(u => ({ nickname: u.nickname })), conversations: store.conversations(user) };
  });
  app.get('/api/history', async (req, reply) => {
    const user = auth(req, reply); if (!user) return;
    const q = z.object({ target, before: cursor }).safeParse(req.query);
    if (!q.success) return reply.code(400).send({ error: 'INVALID_INPUT' });
    if (!store.canRead(user, q.data.target)) return reply.code(403).send({ error: 'FORBIDDEN' });
    const messages = store.history(user, q.data.target, q.data.before);
    return { messages, nextBefore: messages.length === 50 ? messages[0]!.id : null };
  });
  app.get('/api/admin/users', async (req, reply) => {
    if (!auth(req, reply, true)) return;
    return { users: store.users(), departments: store.departments() };
  });
  app.post('/api/admin/users', async (req, reply) => {
    const actor = auth(req, reply, true); if (!actor) return;
    const b = account.safeParse(req.body);
    if (!b.success || (b.data.department && !store.departments().some(d => d.channel === b.data.department))) {
      return reply.code(400).send({ error: 'INVALID_INPUT' });
    }
    const user = await store.register(b.data.nickname, b.data.password, b.data.role, b.data.department);
    if (!user) return reply.code(409).send({ error: 'NICKNAME_TAKEN' });
    store.audit(actor.id, 'user.create', user.id, req.ip);
    return reply.code(201).send({ user });
  });
  app.post<{ Params: { id: string } }>('/api/admin/users/:id', async (req, reply) => {
    const actor = auth(req, reply, true); if (!actor) return;
    const b = userUpdate.safeParse(req.body);
    if (!b.success || (b.data.department && !store.departments().some(d => d.channel === b.data.department))) {
      return reply.code(400).send({ error: 'INVALID_INPUT' });
    }
    const previous = store.user(req.params.id);
    if (!previous) return reply.code(404).send({ error: 'NOT_FOUND' });
    if (!await store.updateUser(req.params.id, b.data)) return reply.code(409).send({ error: 'LAST_ADMIN' });
    closeUser(req.params.id);
    store.audit(actor.id, 'user.update', JSON.stringify({ id: previous.id,
      before: { role: previous.role, department: previous.department, active: Boolean(previous.active) },
      after: { role: b.data.role, department: b.data.department, active: b.data.active }, passwordReset: Boolean(b.data.password) }), req.ip);
    return { user: store.user(req.params.id) };
  });
  app.post('/api/admin/departments', async (req, reply) => {
    const actor = auth(req, reply, true); if (!actor) return;
    const b = z.object({ channel: channelSchema, name: z.string().trim().min(1).max(80) }).strict().safeParse(req.body);
    if (!b.success || ['#general', '#announcements'].includes(b.data.channel)) return reply.code(400).send({ error: 'INVALID_INPUT' });
    if (!store.addDepartment(b.data.channel, b.data.name)) return reply.code(409).send({ error: 'ALREADY_EXISTS' });
    store.audit(actor.id, 'department.create', b.data.channel, req.ip);
    return reply.code(201).send(b.data);
  });
  app.get('/api/admin/audit', async (req, reply) => {
    if (!auth(req, reply, true)) return;
    const q = z.object({ before: cursor }).safeParse(req.query);
    if (!q.success) return reply.code(400).send({ error: 'INVALID_INPUT' });
    const entries = store.auditLog(q.data.before);
    return { entries, nextBefore: entries.length === 100 ? entries.at(-1)!.id : null };
  });
  app.get('/api/resources', async (req, reply) => {
    if (!auth(req, reply)) return;
    return { files: store.resources() };
  });
  // Raw binary body avoids base64 overhead; filename and destination are validated separately.
  app.addContentTypeParser('application/octet-stream', { parseAs: 'buffer', bodyLimit: FILE_LIMIT }, (_req, body, done) => done(null, body));
  app.post('/api/files', { bodyLimit: FILE_LIMIT, config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
    onRequest: async (req, reply) => { auth(req, reply); } }, async (req, reply) => {
    const user = auth(req, reply); if (!user) return;
    const q = z.object({ scope: z.enum(['chat', 'resource']), target: target.optional(),
      name: z.string().min(1).max(180).refine(s => !/[\x00-\x1f\x7f/\\]/.test(s)) }).safeParse(req.query);
    if (!q.success || !Buffer.isBuffer(req.body) || req.body.length === 0) return reply.code(400).send({ error: 'INVALID_INPUT' });
    if ((q.data.scope === 'resource' && user.role === 'member') || (q.data.scope === 'chat' && (!q.data.target || !store.canWrite(user, q.data.target)))) {
      return reply.code(403).send({ error: 'FORBIDDEN' });
    }
    // A shared 1 GiB quota bounds the prototype's file storage, independent of filename or MIME.
    const file = store.upload(user, q.data.scope, q.data.target ?? '', q.data.name, req.body, 1024 * 1024 * 1024);
    if (!file) return reply.code(507).send({ error: 'STORAGE_FULL' });
    store.audit(user.id, 'file.upload', file.id, req.ip);
    return reply.code(201).send({ file });
  });
  app.get<{ Params: { id: string } }>('/api/files/:id', async (req, reply) => {
    const user = auth(req, reply); if (!user) return;
    if (!store.canDownload(user, req.params.id)) return reply.code(404).send({ error: 'NOT_FOUND' });
    const file = store.file(req.params.id)!;
    store.audit(user.id, 'file.download', file.id, req.ip);
    // Always download; uploaded HTML/SVG must never execute on the application's origin.
    reply.type('application/octet-stream').header('Content-Disposition', `attachment; filename="document"; filename*=UTF-8''${encodeURIComponent(file.name).replace(/'/g, '%27')}`);
    reply.header('Content-Security-Policy', "sandbox; default-src 'none'");
    return Buffer.from(store.fileContent(file.id));
  });
  app.post<{ Params: { id: string } }>('/api/resources/:id/delete', async (req, reply) => {
    const user = auth(req, reply); if (!user) return;
    if (user.role === 'member') return reply.code(403).send({ error: 'FORBIDDEN' });
    if (!store.deleteResource(req.params.id)) return reply.code(404).send({ error: 'NOT_FOUND' });
    store.audit(user.id, 'resource.delete', req.params.id, req.ip);
    return reply.code(204).send();
  });
}

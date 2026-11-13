import { randomBytes, randomUUID, createHash, scrypt, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export type Role = 'admin' | 'moderator' | 'member';
export type User = { id: string; nickname: string; role: Role; department: string | null; active: number };
export type Department = { channel: string; name: string };
export type Attachment = { id: string; name: string; size: number };
export type SavedMessage = { id: number; from: string; target: string; text: string; time: string; attachment?: Attachment };
type FileRecord = Attachment & { owner: string; scope: string; target: string; created_at: number };
export type Session = { user: User; expiresAt: number; tokenHash: string };
type Account = User & { salt: string; password_hash: string };
const tokenHash = (token: string) => createHash('sha256').update(token).digest('hex');

function derive(password: string, salt: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (error, key) => {
      if (error) reject(error); else resolve(key);
    });
  });
}

export function equalSecret(a: string, b: string): boolean {
  return timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest());
}

export class Store {
  private db: DatabaseSync;

  constructor(path: string) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        nickname TEXT NOT NULL UNIQUE COLLATE NOCASE,
        salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
    `);
    // Additive migration: existing accounts stay members, with no implicit administrator.
    const columns = this.db.prepare('PRAGMA table_info(users)').all().map(row => row.name);
    if (!columns.includes('role')) this.db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'");
    if (!columns.includes('department')) this.db.exec('ALTER TABLE users ADD COLUMN department TEXT');
    if (!columns.includes('active')) this.db.exec('ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS departments (channel TEXT PRIMARY KEY, name TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES users(id), scope TEXT NOT NULL,
        target TEXT NOT NULL, name TEXT NOT NULL, size INTEGER NOT NULL, content BLOB NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES users(id),
        recipient TEXT REFERENCES users(id), target TEXT NOT NULL, text TEXT NOT NULL,
        time TEXT NOT NULL, file_id TEXT UNIQUE REFERENCES files(id)
      );
      CREATE INDEX IF NOT EXISTS messages_channel ON messages(target, id);
      CREATE INDEX IF NOT EXISTS messages_direct ON messages(sender, recipient, id);
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, actor TEXT,
        action TEXT NOT NULL, subject TEXT, ip TEXT NOT NULL
      );
    `);
    this.prune();
  }

  async register(nickname: string, password: string, role: Role = 'member', department: string | null = null): Promise<User | null> {
    const user: User = { id: randomUUID(), nickname: nickname.toLowerCase(), role, department, active: 1 };
    const salt = randomBytes(16).toString('hex');
    const hash = await derive(password, salt);
    const result = this.db.prepare(`INSERT INTO users (id, nickname, salt, password_hash, created_at, role, department)
      VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(nickname) DO NOTHING`)
      .run(user.id, user.nickname, salt, hash.toString('hex'), Date.now(), role, department);
    return result.changes ? user : null;
  }

  async login(nickname: string, password: string): Promise<User | null> {
    const account = this.db.prepare('SELECT id, nickname, role, department, active, salt, password_hash FROM users WHERE nickname = ?')
      .get(nickname) as Account | undefined;
    // Spend the same scrypt work even if the account does not exist.
    const key = await derive(password, account?.salt ?? '0'.repeat(32));
    const expected = account ? Buffer.from(account.password_hash, 'hex') : Buffer.alloc(64);
    return timingSafeEqual(key, expected) && account?.active ? this.user(account.id) ?? null : null;
  }

  createSession(user: User, ttlSeconds: number) {
    this.prune();
    // Keep at most five browser sessions per account.
    this.db.prepare(`DELETE FROM sessions WHERE token_hash IN (
      SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY expires_at DESC LIMIT -1 OFFSET 4
    )`).run(user.id);
    const token = randomBytes(32).toString('hex');
    const expiresAt = Date.now() + ttlSeconds * 1000;
    this.db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(tokenHash(token), user.id, expiresAt);
    return { token, expiresAt };
  }

  getSession(token: string | undefined): Session | null {
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
    const row = this.db.prepare(`SELECT u.id, u.nickname, u.role, u.department, u.active, s.expires_at FROM sessions s
      JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1`)
      .get(tokenHash(token), Date.now()) as (User & { expires_at: number }) | undefined;
    return row ? { user: { id: row.id, nickname: row.nickname, role: row.role, department: row.department, active: row.active }, expiresAt: row.expires_at, tokenHash: tokenHash(token) } : null;
  }

  user(id: string) {
    const row = this.db.prepare('SELECT id, nickname, role, department, active FROM users WHERE id = ?').get(id) as User | undefined;
    return row ? { ...row } : undefined;
  }
  byNickname(nickname: string) { return this.db.prepare('SELECT id, nickname, role, department, active FROM users WHERE nickname = ?').get(nickname) as User | undefined; }
  users() { return this.db.prepare('SELECT id, nickname, role, department, active FROM users ORDER BY nickname').all() as User[]; }
  hasAdmin() { return Boolean(this.db.prepare("SELECT 1 FROM users WHERE role = 'admin' AND active = 1").get()); }
  async updateUser(id: string, fields: { role: Role; department: string | null; active: boolean; password?: string }) {
    const user = this.user(id);
    if (!user) return false;
    const salt = fields.password ? randomBytes(16).toString('hex') : null;
    const hash = fields.password ? (await derive(fields.password, salt!)).toString('hex') : null;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      // Re-read after async password derivation; preserve at least one active administrator.
      const current = this.user(id)!;
      const admins = this.db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1").get()!.n as number;
      if (current.role === 'admin' && current.active && (fields.role !== 'admin' || !fields.active) && admins <= 1) {
        this.db.exec('ROLLBACK'); return false;
      }
      this.db.prepare('UPDATE users SET role = ?, department = ?, active = ? WHERE id = ?')
        .run(fields.role, fields.department, Number(fields.active), id);
      if (hash) this.db.prepare('UPDATE users SET salt = ?, password_hash = ? WHERE id = ?').run(salt, hash, id);
      this.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
      this.db.exec('COMMIT'); return true;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  departments() { return this.db.prepare('SELECT channel, name FROM departments ORDER BY name').all() as Department[]; }
  addDepartment(channel: string, name: string) {
    return Boolean(this.db.prepare('INSERT INTO departments VALUES (?, ?) ON CONFLICT DO NOTHING').run(channel, name).changes);
  }
  canRead(user: User, target: string) {
    if (!user.active) return false;
    if (target === '#general' || target === '#announcements') return true;
    if (target.startsWith('#')) return this.departments().some(d => d.channel === target)
      && (user.role === 'admin' || user.department === target);
    const peer = this.byNickname(target);
    return Boolean(peer && peer.id !== user.id);
  }
  canWrite(user: User, target: string) {
    return this.canRead(user, target) && (target !== '#announcements' || user.role !== 'member')
      && (target.startsWith('#') || Boolean(this.byNickname(target)?.active));
  }
  recordMessage(user: User, target: string, text: string, time: string, fileId?: string): SavedMessage {
    const recipient = target.startsWith('#') ? null : this.byNickname(target)!.id;
    const result = this.db.prepare('INSERT INTO messages(sender, recipient, target, text, time, file_id) VALUES (?, ?, ?, ?, ?, ?)')
      .run(user.id, recipient, target, text, time, fileId ?? null);
    const file = fileId ? this.file(fileId) : undefined;
    return { id: Number(result.lastInsertRowid), from: user.nickname, target, text, time,
      ...(file ? { attachment: { id: file.id, name: file.name, size: file.size } } : {}) };
  }
  history(user: User, target: string, before = Number.MAX_SAFE_INTEGER, limit = 50): SavedMessage[] {
    const peer = target.startsWith('#') ? null : this.byNickname(target)?.id;
    const rows = this.db.prepare(`SELECT m.id, u.nickname AS sender_name, m.target, m.text, m.time,
      f.id AS file_id, f.name AS file_name, f.size AS file_size FROM messages m
      JOIN users u ON u.id = m.sender LEFT JOIN files f ON f.id = m.file_id
      WHERE m.id < ? AND ${peer ? '((m.sender = ? AND m.recipient = ?) OR (m.sender = ? AND m.recipient = ?))' : 'm.target = ? AND m.recipient IS NULL'}
      ORDER BY m.id DESC LIMIT ?`).all(before, ...(peer ? [user.id, peer, peer, user.id] : [target]), limit);
    return rows.reverse().map(row => ({ id: row.id as number, from: row.sender_name as string,
      target: row.target as string, text: row.text as string, time: row.time as string,
      ...(row.file_id ? { attachment: { id: row.file_id as string, name: row.file_name as string, size: row.file_size as number } } : {}) }));
  }
  conversations(user: User) {
    return this.db.prepare(`SELECT DISTINCT u.nickname FROM messages m JOIN users u
      ON u.id = CASE WHEN m.sender = ? THEN m.recipient ELSE m.sender END
      WHERE m.recipient IS NOT NULL AND (m.sender = ? OR m.recipient = ?) LIMIT 200`)
      .all(user.id, user.id, user.id).map(r => r.nickname as string);
  }
  upload(user: User, scope: 'chat' | 'resource', target: string, name: string, content: Buffer, quota: number) {
    this.pruneFiles();
    const size = this.db.prepare('SELECT COALESCE(SUM(size), 0) AS size FROM files').get()!.size as number;
    if (size + content.length > quota) return null;
    const id = randomUUID();
    this.db.prepare('INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, user.id, scope, target, name, content.length, content, Date.now());
    return { id, name, size: content.length };
  }
  file(id: string) { return this.db.prepare('SELECT id, owner, scope, target, name, size, created_at FROM files WHERE id = ?').get(id) as FileRecord | undefined; }
  attachmentAllowed(user: User, id: string, target: string) {
    const file = this.file(id);
    return Boolean(file && file.owner === user.id && file.scope === 'chat' && file.target === target
      && !this.db.prepare('SELECT 1 FROM messages WHERE file_id = ?').get(id));
  }
  canDownload(user: User, id: string) {
    const file = this.file(id);
    if (!file) return false;
    if (file.scope === 'resource') return true;
    const message = this.db.prepare('SELECT sender, recipient, target FROM messages WHERE file_id = ?').get(id);
    if (!message) return file.owner === user.id && this.canRead(user, file.target);
    return message.recipient ? message.sender === user.id || message.recipient === user.id : this.canRead(user, message.target as string);
  }
  fileContent(id: string) { return this.db.prepare('SELECT content FROM files WHERE id = ?').get(id)!.content as Uint8Array; }
  resources() { return this.db.prepare("SELECT id, name, size, created_at FROM files WHERE scope = 'resource' ORDER BY created_at DESC").all(); }
  deleteResource(id: string) { return Boolean(this.db.prepare("DELETE FROM files WHERE id = ? AND scope = 'resource'").run(id).changes); }
  private pruneFiles() {
    this.db.prepare("DELETE FROM files WHERE scope = 'chat' AND created_at < ? AND NOT EXISTS (SELECT 1 FROM messages WHERE file_id = files.id)").run(Date.now() - 86400_000);
  }
  audit(actor: string | null, action: string, subject: string | null, ip: string) {
    this.db.prepare('INSERT INTO audit(time, actor, action, subject, ip) VALUES (?, ?, ?, ?, ?)')
      .run(new Date().toISOString(), actor, action, subject, ip);
  }
  auditLog(before = Number.MAX_SAFE_INTEGER) {
    return this.db.prepare(`SELECT a.*, u.nickname FROM audit a LEFT JOIN users u ON u.id = a.actor
      WHERE a.id < ? ORDER BY a.id DESC LIMIT 100`).all(before);
  }

  revoke(token: string) { this.db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash(token)); }
  prune() { this.db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now()); }
  close() { this.db.close(); }
}

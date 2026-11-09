import { randomBytes, randomUUID, createHash, scrypt, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export type User = { id: string; nickname: string };
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
    this.prune();
  }

  async register(nickname: string, password: string): Promise<User | null> {
    const user = { id: randomUUID(), nickname: nickname.toLowerCase() };
    const salt = randomBytes(16).toString('hex');
    const hash = await derive(password, salt);
    const result = this.db.prepare(`INSERT INTO users (id, nickname, salt, password_hash, created_at)
      VALUES (?, ?, ?, ?, ?) ON CONFLICT(nickname) DO NOTHING`)
      .run(user.id, user.nickname, salt, hash.toString('hex'), Date.now());
    return result.changes ? user : null;
  }

  async login(nickname: string, password: string): Promise<User | null> {
    const account = this.db.prepare('SELECT id, nickname, salt, password_hash FROM users WHERE nickname = ?')
      .get(nickname) as Account | undefined;
    // Spend the same scrypt work even if the account does not exist.
    const key = await derive(password, account?.salt ?? '0'.repeat(32));
    const expected = account ? Buffer.from(account.password_hash, 'hex') : Buffer.alloc(64);
    return timingSafeEqual(key, expected) && account ? { id: account.id, nickname: account.nickname } : null;
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
    const row = this.db.prepare(`SELECT u.id, u.nickname, s.expires_at FROM sessions s
      JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?`)
      .get(tokenHash(token), Date.now()) as (User & { expires_at: number }) | undefined;
    return row ? { user: { id: row.id, nickname: row.nickname }, expiresAt: row.expires_at, tokenHash: tokenHash(token) } : null;
  }

  revoke(token: string) { this.db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash(token)); }
  prune() { this.db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now()); }
  close() { this.db.close(); }
}

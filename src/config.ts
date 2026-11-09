import { isIP } from 'node:net';
import { z } from 'zod';

export function isLocalAddress(address: string): boolean {
  const ip = address.replace(/^::ffff:/, '');
  if (ip === '::1') return true;
  if (isIP(ip) === 6) return /^(fc|fd|fe[89ab])/i.test(ip);
  if (isIP(ip) !== 4) return false;
  const [a, b] = ip.split('.').map(Number);
  return a === 127 || a === 10 || (a === 172 && b! >= 16 && b! <= 31)
    || (a === 192 && b === 168) || (a === 169 && b === 254);
}

const envSchema = z.object({
  HOST: z.string().default('127.0.0.1'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8443),
  ALLOWED_ORIGINS: z.string().min(1),
  DATABASE_PATH: z.string().default('./data/shifr.sqlite'),
  TLS_CERT_PATH: z.string().optional(),
  TLS_KEY_PATH: z.string().optional(),
  IRC_HOST: z.string().default('127.0.0.1'),
  IRC_PORT: z.coerce.number().int().min(1).max(65535).default(6667),
  IRC_PASSWORD: z.string().regex(/^[a-f0-9]{64}$/),
  REGISTRATION_TOKEN: z.string().regex(/^[a-f0-9]{64}$/),
  SESSION_TTL_SECONDS: z.coerce.number().int().min(60).max(604800).default(86400),
});

export type Config = ReturnType<typeof loadConfig>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env) {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    // Validation diagnostics must never include env values or secrets.
    throw new Error(`Invalid configuration: ${parsed.error.issues.map(i => i.path.join('.')).join(', ')}`);
  }
  const e = parsed.data;
  const tls = Boolean(e.TLS_CERT_PATH && e.TLS_KEY_PATH);
  if (Boolean(e.TLS_CERT_PATH) !== Boolean(e.TLS_KEY_PATH)) throw new Error('Set both TLS paths');
  if (e.HOST !== '0.0.0.0' && !isLocalAddress(e.HOST)) throw new Error('HOST must be a local IP');
  if (!tls && !['127.0.0.1', '::1'].includes(e.HOST)) throw new Error('LAN access requires TLS');
  const origins = e.ALLOWED_ORIGINS.split(',').map(s => s.trim());
  for (const origin of origins) {
    let url: URL;
    try { url = new URL(origin); } catch { throw new Error('Invalid ALLOWED_ORIGINS'); }
    if (url.origin !== origin || !['https:', 'http:'].includes(url.protocol)
      || (url.hostname !== 'localhost' && !isLocalAddress(url.hostname.replace(/^\[|\]$/g, '')))
      || (tls && url.protocol !== 'https:')
      || (!tls && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) {
      throw new Error('ALLOWED_ORIGINS must contain exact local origins; HTTPS is required for LAN');
    }
  }
  return {
    host: e.HOST, port: e.PORT, origins, databasePath: e.DATABASE_PATH,
    tlsCert: e.TLS_CERT_PATH, tlsKey: e.TLS_KEY_PATH, secureCookies: tls,
    ircHost: e.IRC_HOST, ircPort: e.IRC_PORT, ircPassword: e.IRC_PASSWORD,
    registrationToken: e.REGISTRATION_TOKEN, sessionTtlSeconds: e.SESSION_TTL_SECONDS,
  };
}

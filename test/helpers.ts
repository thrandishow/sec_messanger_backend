import { randomBytes } from 'node:crypto';
import type { Config } from '../src/config.js';

export function testConfig(overrides: Partial<Config> = {}): Config {
  return { host: '127.0.0.1', port: 8443, origins: ['http://127.0.0.1:3000'],
    databasePath: ':memory:', tlsCert: undefined, tlsKey: undefined, secureCookies: false,
    ircHost: '127.0.0.1', ircPort: 1, ircPassword: randomBytes(32).toString('hex'),
    registrationToken: randomBytes(32).toString('hex'), sessionTtlSeconds: 86400, ...overrides };
}

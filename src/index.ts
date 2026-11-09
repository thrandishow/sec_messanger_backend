import { buildApp } from './app.js';
import { loadConfig } from './config.js';

process.umask(0o077);
try {
  const config = loadConfig();
  const app = await buildApp(config, { logger: true });
  const stop = async () => { await app.close(); };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  await app.listen({ host: config.host, port: config.port });
} catch {
  // Never dump env, key paths, or secret-bearing exception payloads.
  console.error('Backend startup failed. Check configuration, TLS files, database permissions, and port availability.');
  process.exitCode = 1;
}

// Local console bootstrap only. Password arrives on stdin, never via argv or logs.
import { Store } from './store.js';
import { nicknameSchema } from './protocol.js';

const [mode, nickname] = process.argv.slice(2);
if (!['--nickname', '--promote'].includes(mode ?? '') || !nicknameSchema.safeParse(nickname).success) {
  console.error('Usage: node dist/admin.js --nickname <new-admin> < password-on-stdin; or --promote <existing-user>');
  process.exit(1);
}
const store = new Store(process.env.DATABASE_PATH ?? './data/shifr.sqlite');
try {
  if (store.hasAdmin()) throw new Error('An active administrator already exists. Use the admin panel.');
  if (mode === '--promote') {
    const user = store.byNickname(nickname!);
    if (!user) throw new Error('Account not found.');
    await store.updateUser(user.id, { role: 'admin', department: user.department, active: true });
    store.audit(user.id, 'admin.bootstrap', user.id, 'local-console');
  } else {
    const parts: Buffer[] = [];
    let size = 0;
    for await (const part of process.stdin) {
      size += part.length;
      if (size > 1024) throw new Error('Password input too large.');
      parts.push(Buffer.from(part));
    }
    const password = Buffer.concat(parts).toString('utf8').replace(/\r?\n$/, '');
    if (password.length < 12 || password.length > 128) throw new Error('Use a password of 12–128 characters.');
    if (store.hasAdmin()) throw new Error('An administrator was created concurrently.');
    const user = await store.register(nickname!, password, 'admin');
    if (!user) throw new Error('Nickname exists. Use --promote for an existing account.');
    store.audit(user.id, 'admin.bootstrap', user.id, 'local-console');
  }
  console.log('Administrator configured. Sign in through the web interface.');
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Bootstrap failed');
  process.exitCode = 1;
} finally { store.close(); }

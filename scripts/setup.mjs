// Compatibility with npm run setup -- --ip LAN-IP and existing development tools.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const [flag, ip, ...extra] = process.argv.slice(2);
if (flag !== '--ip' || !ip || extra.length) {
  console.error('Usage: npm run setup -- --ip <LAN-IP>');
  process.exit(1);
}
const cli = fileURLToPath(new URL('../shifrctl', import.meta.url));
const result = spawnSync(cli, ['init', '--compose', '--root', process.cwd(), ip], { stdio: 'inherit' });
if (result.error) console.error(result.error.message);
process.exit(result.status ?? 1);

// Adapt the frontend's actual TLS, LAN ACL and WebSocket configuration for a native nginx prefix.
import { readFileSync, writeFileSync, renameSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { isIPv4 } from 'node:net';

const [frontendConfig] = process.argv.slice(2);
const settings = parseEnv(readFileSync('.env', 'utf8'));
const ip = settings.LAN_IP;
const token = settings.BROKER_TOKEN || settings.IRC_PASSWORD;
if (!isIPv4(ip) || !/^[a-f0-9]{64}$/i.test(token ?? '')) {
  throw new Error('Проверьте LAN_IP и секрет брокера в конфигурации установки.');
}

function save(name, value) {
  writeFileSync(name + '.new', value, { mode: 0o600 });
  renameSync(name + '.new', name);
}

let config = readFileSync(frontendConfig, 'utf8');
for (const [from, to] of [
  ['error_log /dev/stderr warn;', 'error_log stderr warn;'],
  ['listen 8443 ssl;', `listen ${ip}:8443 ssl;`],
  ['    resolver 127.0.0.11 valid=10s ipv6=off;\n', ''],
  ['https://api:8443', 'https://127.0.0.1:9443'],
  ['/usr/share/nginx/html', 'current/html'],
  ['/tls/', 'runtime/tls/'],
  ['/tmp/', 'tmp/'],
]) {
  if (!config.includes(from)) throw new Error(`Неизвестный формат nginx.conf (${from})`);
  config = config.replaceAll(from, to);
}
save('nginx.candidate.conf', config);
save('broker.env', `BROKER_TOKEN=${token}\n`);
save('native.env', `ALLOWED_ORIGINS=https://${ip}:8443\nSESSION_TTL_SECONDS=${Number(settings.SESSION_TTL_SECONDS || 86400)}\n`);

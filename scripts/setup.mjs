import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync, unlinkSync } from 'node:fs';
import { isIP } from 'node:net';
import { spawnSync } from 'node:child_process';

// No dependencies: this also runs before npm ci.
process.umask(0o077);
const args = process.argv.slice(2);
const ip = args[0] === '--ip' && args.length === 2 ? args[1] : undefined;
const parts = ip?.split('.').map(Number) ?? [];
const [a, b] = parts;
const privateIp = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
if (!ip || isIP(ip) !== 4 || !privateIp) {
  console.error('Usage: node scripts/setup.mjs --ip <private LAN IPv4, e.g. 192.168.1.10>');
  process.exit(1);
}
if (existsSync('.env') || existsSync('runtime')) {
  console.error('Setup refused to overwrite .env or runtime/. Existing secrets and certificates were preserved.');
  process.exit(1);
}
const openssl = spawnSync('openssl', ['version'], { stdio: 'ignore' });
if (openssl.status !== 0) {
  console.error('OpenSSL is required to generate the local TLS certificate.');
  process.exit(1);
}
mkdirSync('runtime/tls', { recursive: true, mode: 0o700 });
mkdirSync('runtime/ca', { recursive: true, mode: 0o700 });
mkdirSync('data', { recursive: true, mode: 0o700 });
function runOpenSSL(args) {
  if (spawnSync('openssl', args, { stdio: 'ignore' }).status !== 0) {
    console.error('Certificate generation failed. Use OpenSSL 3, then inspect the partial runtime/ directory.');
    process.exit(1);
  }
}
runOpenSSL(['req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-days', '3650', '-noenc',
  '-keyout', 'runtime/ca/ca.key', '-out', 'runtime/tls/ca.crt', '-subj', '/CN=Shifr Svyaz Local CA',
  '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
runOpenSSL(['req', '-new', '-newkey', 'rsa:3072', '-noenc', '-keyout', 'runtime/tls/server.key',
  '-out', 'runtime/tls/server.csr', '-subj', '/CN=Shifr Svyaz Local']);
writeFileSync('runtime/tls/server.ext', `subjectAltName=IP:${ip},IP:127.0.0.1,DNS:localhost
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
`);
runOpenSSL(['x509', '-req', '-in', 'runtime/tls/server.csr', '-CA', 'runtime/tls/ca.crt',
  '-CAkey', 'runtime/ca/ca.key', '-set_serial', `0x${randomBytes(16).toString('hex')}`,
  '-days', '365', '-sha256', '-extfile', 'runtime/tls/server.ext', '-out', 'runtime/tls/server.crt']);
unlinkSync('runtime/tls/server.csr');
unlinkSync('runtime/tls/server.ext');
const ircPassword = randomBytes(32).toString('hex');
writeFileSync('runtime/irc-connect.conf', `<connect name="gateway" allow="*" password="${ircPassword}"
  hash="plaintext" resolvehostnames="no" localmax="1000" globalmax="1000"
  maxchans="20" limit="1000" timeout="10s" pingfreq="60s" commandrate="10000" threshold="40">
`, { mode: 0o600, flag: 'wx' });
writeFileSync('.env', `HOST=0.0.0.0
PORT=8443
LAN_IP=${ip}
LOCAL_UID=${process.getuid?.() || 1000}
LOCAL_GID=${process.getgid?.() || 1000}
ALLOWED_ORIGINS=https://${ip}:3000,https://${ip}:8443,https://localhost:3000,https://127.0.0.1:3000,https://localhost:8443,https://127.0.0.1:8443
DATABASE_PATH=./data/shifr.sqlite
TLS_CERT_PATH=./runtime/tls/server.crt
TLS_KEY_PATH=./runtime/tls/server.key
IRC_HOST=127.0.0.1
IRC_PORT=6667
IRC_PASSWORD=${ircPassword}
SESSION_TTL_SECONDS=86400
TRUST_PROXY=0
`, { mode: 0o600, flag: 'wx' });
console.log(`Configuration created for https://${ip}:8443. Secrets are in .env (not printed).
Trust runtime/tls/ca.crt on LAN clients. Keep all .key files on the server only.
Start: docker compose up --build -d`);

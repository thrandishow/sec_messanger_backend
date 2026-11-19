// Disposable test cluster. The published port is random and bound only to loopback.
import { spawnSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
const name = 'shifr-pg-test-' + randomUUID();
const env = { ...process.env, POSTGRES_PASSWORD: randomBytes(32).toString('hex') };
function docker(args) {
  const r = spawnSync('docker',args,{env,encoding:'utf8'});
  if (r.status !== 0) throw new Error('Docker failed: ' + (r.error?.message ?? r.stderr));
  return r.stdout.trim();
}
docker(['run','--detach','--rm','--name',name,'--tmpfs','/var/lib/postgresql/data',
  '-e','POSTGRES_PASSWORD','-p','127.0.0.1::5432','postgres:17-bookworm']);
try {
  const port = docker(['port',name,'5432/tcp']).split(':').at(-1);
  for(let attempt=0;;attempt++){
    const ready=spawnSync('docker',['exec',name,'pg_isready','-h','127.0.0.1','-U','postgres'],{stdio:'ignore'});
    if(ready.status===0)break;
    if(attempt===100)throw new Error('PostgreSQL did not start');
    await setTimeout(200);
  }
  const testEnv={...env,PGUSER:'postgres',PGHOST:'127.0.0.1',PGPORT:port,PGPASSWORD:env.POSTGRES_PASSWORD,SHIFR_TEST_PG:name};
  delete testEnv.DATABASE_URL;
  process.exitCode=spawnSync(process.execPath,['--test',...process.argv.slice(2)],{env:testEnv,stdio:'inherit'}).status ?? 1;
} finally { docker(['stop',name]); }

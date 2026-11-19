// Black-box helpers: all HTTP requests go to a separate Rust process.
import { createHash, randomBytes, randomUUID, scryptSync } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { createServer, connect } from 'node:net';
import { once } from 'node:events';
import { resolve } from 'node:path';
export const apiBinary = resolve(process.env.API_BINARY ?? 'api/target/debug/shifr-api');
export const brokerBinary = resolve(process.env.BROKER_BINARY ?? 'broker/target/debug/shifr-broker');
const databases = new Map<string,string>();
export function testDatabase(legacy?:string){
  const key=legacy && legacy!==':memory:' ? legacy : randomUUID();
  let name=databases.get(key);
  if(!name){
    name='test_'+randomBytes(12).toString('hex');
    sql('postgres','CREATE DATABASE '+name);
    databases.set(key,name);
  }
  return {PGDATABASE:name,PGPORT:process.env.PGPORT,PGHOST:'127.0.0.1',PGUSER:'postgres',PGPASSWORD:process.env.PGPASSWORD,LEGACY_SQLITE_PATH:legacy===':memory:'?'':legacy??''};
}
export function sql(database:string,query:string){
  const container=process.env.SHIFR_TEST_PG;
  if(!container?.startsWith('shifr-pg-test-'))throw new Error('Run tests with npm test (isolated PostgreSQL required)');
  return execFileSync('docker',['exec','-i',container,'psql','-XAtq','-v','ON_ERROR_STOP=1','-U','postgres','-d',database],{input:query,encoding:'utf8'}).trim();
}
export async function freePort() {
  const s = createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening');
  const port = (s.address() as {port:number}).port; await new Promise<void>(r=>s.close(()=>r())); return port;
}
export async function stop(child:ChildProcess) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const done = once(child,'exit'); child.kill('SIGTERM'); await done;
}
export function testConfig(opts:{databasePath?:string,trustProxy?:boolean}={}) {
  return {databasePath:opts.databasePath ?? ':memory:',origins:['http://127.0.0.1:3000'],trustProxy:opts.trustProxy ?? false};
}
export async function startApi(overrides:NodeJS.ProcessEnv) {
  const port=await freePort();
  const database=testDatabase(overrides.DATABASE_PATH);
  const env={...process.env,HOST:'127.0.0.1',ALLOWED_ORIGINS:'http://127.0.0.1:3000',
    BROKER_HOST:'127.0.0.1',BROKER_PORT:'1',BROKER_TOKEN:randomBytes(32).toString('hex'),
    TLS_CERT_PATH:'',TLS_KEY_PATH:'',DATABASE_PATH:':memory:',TRUST_PROXY:'0',...overrides,...database,PORT:String(port)};
  const child=spawn(apiBinary,[],{env,stdio:['ignore','ignore','inherit']});
  await new Promise<void>((resolve,reject)=>{
    child.once('error',reject);child.once('exit',()=>reject(new Error('Rust API exited before listen')));
    const poll=(n:number)=>{const s=connect(port,'127.0.0.1');s.on('connect',()=>{s.destroy();resolve()});
      s.on('error',()=>{s.destroy();if(child.exitCode!==null||child.signalCode!==null||n>=200){child.kill();reject(new Error('API did not start'))}
        else setTimeout(()=>poll(n+1),20);});};poll(0);
  });
  return {port,close:()=>stop(child)};
}
export async function buildApp(config:ReturnType<typeof testConfig>) {
  const api=await startApi({DATABASE_PATH:config.databasePath,TRUST_PROXY:config.trustProxy?'1':'0'});
  return {...api,inject:async(q:{method?:string,url:string,headers?:Record<string,string>,payload?:unknown})=>{
    const binary=Buffer.isBuffer(q.payload);
    const r=await fetch(`http://127.0.0.1:${api.port}${q.url}`,{method:q.method??'GET',headers:{...(q.payload!==undefined?{'content-type':binary?'application/octet-stream':'application/json'}:{}),...q.headers},
      body:q.payload===undefined?undefined:binary?q.payload as Buffer<ArrayBuffer>:JSON.stringify(q.payload)});
    const body=await r.text();return {statusCode:r.status,body,json:()=>JSON.parse(body),headers:Object.fromEntries(r.headers)};
  }};
}
// Earliest Node database layout: salt is ASCII hex and sessions store SHA-256(token).
export function legacyDatabase(path:string) {
  const db=new DatabaseSync(path);
  db.exec(`CREATE TABLE users(id TEXT PRIMARY KEY,nickname TEXT NOT NULL UNIQUE COLLATE NOCASE,salt TEXT NOT NULL,password_hash TEXT NOT NULL,created_at INTEGER NOT NULL);
    CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);`);
  return { db, account(nickname:string,password:string) {
    const id=randomUUID(),salt=randomBytes(16).toString('hex');
    const key=scryptSync(password,salt,64,{N:32768,r:8,p:1,maxmem:64*1024*1024}).toString('hex');
    db.prepare('INSERT INTO users VALUES(?,?,?,?,?)').run(id,nickname,salt,key,Date.now());return id;
  }, session(id:string,ttl:number){
    const token=randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(createHash('sha256').update(token).digest('hex'),id,Date.now()+ttl);
    return 'shifr_session='+token;
  }};
}

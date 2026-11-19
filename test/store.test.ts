import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildApp, testConfig, legacyDatabase, testDatabase, sql } from './helpers.ts';

test('Rust reads Node hashes and sessions and preserves accounts across restart',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'shifr-upgrade-'));
  const config=testConfig({databasePath:join(dir,'db.sqlite')});
  const seed=legacyDatabase(config.databasePath);
  const password='correct-password-123';
  const id=seed.account('alice',password);
  const legacy=seed.session(id,60000);
  const expired=seed.session(id,-1);
  seed.db.close();
  let app=await buildApp(config);
  t.after(async()=>{await app.close();rmSync(dir,{recursive:true,force:true});});
  const me=(cookie:string)=>app.inject({url:'/api/auth/me',headers:{cookie}});
  assert.equal((await me(legacy)).json().user.role,'member');
  assert.equal((await me(expired)).statusCode,401);
  const login=()=>app.inject({url:'/api/auth/login',method:'POST',headers:{origin:config.origins[0]!},payload:{nickname:'ALICE',password}});
  let latest='';
  for(let i=0;i<6;i++){const result=await login();assert.equal(result.statusCode,200);latest=result.headers['set-cookie']!.split(';')[0]!;}
  const database=testDatabase(config.databasePath).PGDATABASE;
  assert.equal(sql(database,'SELECT count(*) FROM sessions'),'5');
  assert.ok(!sql(database,'SELECT token_hash FROM sessions').includes(latest.split('=')[1]!));
  await app.close();app=await buildApp(config);
  assert.equal((await me(latest)).json().user.id,id);
  assert.equal((await me(legacy)).statusCode,401);
});

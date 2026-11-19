import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {apiBinary} from './helpers.ts';

test('Rust refuses public origins, LAN plaintext, incomplete TLS and missing broker secret',()=>{
  const base={ALLOWED_ORIGINS:'http://127.0.0.1:3000',DATABASE_PATH:':memory:',BROKER_TOKEN:randomBytes(32).toString('hex')};
  for(const change of [{HOST:'0.0.0.0'},{ALLOWED_ORIGINS:'*'},{ALLOWED_ORIGINS:'http://example.com'},{ALLOWED_ORIGINS:'http://user@localhost:3000'},{BROKER_TOKEN:''},{TLS_CERT_PATH:'cert'}]){
    const result=spawnSync(apiBinary,[],{env:{...base,...change},timeout:1000});
    assert.equal(result.status,1);assert.ok(!result.stderr.toString().includes(base.BROKER_TOKEN));
  }
});

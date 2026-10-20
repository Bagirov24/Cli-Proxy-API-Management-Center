import test from 'node:test';
import assert from 'node:assert/strict';
import {enforceNativeBunCi,verifyNativeBunArchive,NATIVE_BUN_CI_PIN}
  from '../scripts/saas-staging/install-backend16-native-bun-ci.mjs';

test('upstream native SQL fix is an immutable CI-only binary, never a floating canary',()=>{
  const e={GITHUB_ACTIONS:'true',CI:'true',GITHUB_ENV:'/tmp/synthetic-github-env'};
  assert.doesNotThrow(()=>enforceNativeBunCi(e,24,'linux','x64'));
  for(const key of Object.keys(e))assert.throws(()=>enforceNativeBunCi({...e,[key]:''},24,'linux','x64'));
  for(const [key,value] of Object.entries({NODE_ENV:'production',
    NODE_TLS_REJECT_UNAUTHORIZED:'0',RAILWAY_SERVICE_ID:'x'}))
    assert.throws(()=>enforceNativeBunCi({...e,[key]:value},24,'linux','x64'));
  assert.throws(()=>enforceNativeBunCi(e,22,'linux','x64'));
  assert.throws(()=>enforceNativeBunCi(e,24,'win32','x64'));
  assert.match(NATIVE_BUN_CI_PIN.url,/1\.4\.3-canary\.20261019\.1\.tgz$/);
  assert.equal(Buffer.from(NATIVE_BUN_CI_PIN.sha512,'base64').length,64);
});
test('missing, truncated or tampered native runtime cannot reach extraction',()=>{
  for(const bytes of [undefined,new Uint8Array(),new Uint8Array(1_000_001)])
    assert.throws(()=>verifyNativeBunArchive(bytes));
});

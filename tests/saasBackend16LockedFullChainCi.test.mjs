import test from 'node:test';
import assert from 'node:assert/strict';
import {FULL_CHAIN_MARKERS,enforceLockedFullChainEnvironment,verifyFullChainResult}
  from '../scripts/saas-staging/backend16-locked-full-chain-ci.mjs';

const env={GITHUB_ACTIONS:'true',CI:'true',SAAS_B16_LOCKED_FULL_CHAIN_CI:'true',
  SAAS_B16_EPHEMERAL_CI:'true',SAAS_B16_NODEPG_PHYSICAL_CI:'true',
  SAAS_B16_BROKER_MTLS_CI:'true',PGHOST:'127.0.0.1',PGPORT:'5432',PGUSER:'postgres',
  PGDATABASE:'saas_ephemeral_test',PGPASSWORD:'ci_ephemeral_test_only',
  SAAS_B16_CI_PG_CONTAINER:'a'.repeat(64)};
test('full chain requires every disposable-service opt-in and refuses production',()=>{
  assert.doesNotThrow(()=>enforceLockedFullChainEnvironment(env,24));
  for(const key of Object.keys(env))assert.throws(()=>
    enforceLockedFullChainEnvironment({...env,[key]:undefined},24));
  for(const [key,value] of Object.entries({NODE_ENV:'production',
    NODE_TLS_REJECT_UNAUTHORIZED:'0',RAILWAY_PROJECT_ID:'x',PGHOST:'remote',
    SAAS_B16_LOCKED_FULL_CHAIN_CI:'false'}))assert.throws(()=>
      enforceLockedFullChainEnvironment({...env,[key]:value},24));
  assert.throws(()=>enforceLockedFullChainEnvironment(env,22));
});
test('every complete child proof is required, including all denial and PID tests',()=>{
  const result={status:0,stdout:FULL_CHAIN_MARKERS.join('\n')};
  assert.deepEqual(verifyFullChainResult(result),FULL_CHAIN_MARKERS);
  for(const marker of FULL_CHAIN_MARKERS){
    assert.throws(()=>verifyFullChainResult({...result,
      stdout:result.stdout.replace(marker,'')}));
    assert.throws(()=>verifyFullChainResult({...result,
      stdout:result.stdout+'\n'+marker}));
  }
  for(const failure of [{status:1},{signal:'SIGTERM'},{error:Error('timeout')}])
    assert.throws(()=>verifyFullChainResult({...result,...failure}));
});

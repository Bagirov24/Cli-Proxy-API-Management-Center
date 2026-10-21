import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  REQUIRED_LOCKED_NODEPG_PEER_MARKERS,
  enforceLockedNodePgPeerCiEnvironment,
  verifyLockedNodePgPeerResult,
} from '../scripts/saas-staging/backend16-locked-nodepg-peer-ci.mjs';

const GOOD={
  GITHUB_ACTIONS:'true',CI:'true',
  SAAS_B16_NODEPG_PEER_CI:'true',
  SAAS_B16_LOCKED_NODEPG_PEER_CI:'true',
  SAAS_B16_CI_PG_CONTAINER:'a'.repeat(64),
  PGHOST:'127.0.0.1',PGPORT:'5432',
  PGUSER:'postgres',PGDATABASE:'saas_ephemeral_test',
  PGPASSWORD:'ci_ephemeral_test_only',
};
const refused=fn=>assert.throws(fn,/dual-locked NodePG peer TLS CI refused|genuine NodePG CI lock refused/);
const successful=()=>({
  status:0,signal:null,stdout:REQUIRED_LOCKED_NODEPG_PEER_MARKERS.join('\n')+'\n',
});

test('peer fixture is GitHub disposable Node24 only, never a live server',()=>{
  assert.doesNotThrow(()=>enforceLockedNodePgPeerCiEnvironment(GOOD,24));
  for(const bad of [
    {GITHUB_ACTIONS:'false'}, {CI:'false'},
    {SAAS_B16_NODEPG_PEER_CI:'false'},
    {SAAS_B16_LOCKED_NODEPG_PEER_CI:'false'},
    {SAAS_B16_CI_PG_CONTAINER:'production'},
    {SAAS_B16_VERIFIED_NODEPG_DIR:'/tmp/forged-install'},
    {SAAS_B16_LOCKED_FULL_CHAIN_CI:'true'},
    {SAAS_B16_LOCKED_PG16_CI:'true'},
    {PGHOST:'prod.db'}, {PGPORT:'5433'},
    {PGUSER:'application'}, {PGDATABASE:'postgres'},
    {PGPASSWORD:'x'}, {NODE_ENV:'production'},
    {NODE_TLS_REJECT_UNAUTHORIZED:'0'},
    {RAILWAY_SERVICE_ID:'production'},
  ])refused(()=>enforceLockedNodePgPeerCiEnvironment(
    {...GOOD,...bad},24));
  for(const n of [18,20,22,23,25])refused(()=>
    enforceLockedNodePgPeerCiEnvironment(GOOD,n));
});

test('peer results need every unchanged positive and TLS-negative marker exactly once',()=>{
  assert.equal(REQUIRED_LOCKED_NODEPG_PEER_MARKERS.length,8);
  assert.equal(new Set(REQUIRED_LOCKED_NODEPG_PEER_MARKERS).size,8);
  assert.equal(Object.isFrozen(REQUIRED_LOCKED_NODEPG_PEER_MARKERS),true);
  assert.deepEqual(verifyLockedNodePgPeerResult(successful()),
    REQUIRED_LOCKED_NODEPG_PEER_MARKERS);
  for(const missing of REQUIRED_LOCKED_NODEPG_PEER_MARKERS){
    const lines=successful().stdout.split('\n').filter(line=>line!==missing);
    refused(()=>verifyLockedNodePgPeerResult({
      status:0,stdout:lines.join('\n'),
    }));
  }
  const duplicated=successful().stdout+
    REQUIRED_LOCKED_NODEPG_PEER_MARKERS[1]+'\n';
  refused(()=>verifyLockedNodePgPeerResult({status:0,stdout:duplicated}));
  refused(()=>verifyLockedNodePgPeerResult({
    status:1,stdout:successful().stdout,
  }));
  refused(()=>verifyLockedNodePgPeerResult({
    status:0,signal:'SIGTERM',stdout:successful().stdout,
  }));
  refused(()=>verifyLockedNodePgPeerResult({
    status:0,error:new Error('private evidence'),stdout:successful().stdout,
  }));
});

test('all peer TLS cases reuse the two independently verified frozen installs',()=>{
  const gate=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs',
    import.meta.url),'utf8');
  const runner=readFileSync(new URL(
    '../scripts/saas-staging/backend16-locked-nodepg-peer-ci.mjs',
    import.meta.url),'utf8');
  const peer=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-nodepg-peer-ci.ts',
    import.meta.url),'utf8');
  const workflow=readFileSync(new URL(
    '../.github/workflows/saas-backend16-nodepg-peer-ci.yml',
    import.meta.url),'utf8');
  assert.ok(gate.includes('SAAS_B16_LOCKED_NODEPG_PEER_CI'));
  assert.ok(gate.includes('runLockedNodePgPeerCi(receipts.map(r=>r.dir))'));
  assert.ok(gate.includes('assertObservedBackend16NodePgGraph('));
  assert.ok(gate.includes('B16_REAL_LOCK_CI_FROZEN_INSTALL_PASS'));
  assert.ok(gate.indexOf('B16_REAL_LOCK_CI_FROZEN_INSTALL_PASS')<
    gate.indexOf('runLockedNodePgPeerCi(receipts.map(r=>r.dir))'));
  assert.ok(runner.includes("a[2]!=='a'||b[2]!=='b'"));
  assert.ok(runner.includes("env:{...process.env,SAAS_B16_VERIFIED_NODEPG_DIR:dir}"));
  assert.ok(peer.includes("join(packageDir,'node_modules')"));
  assert.ok(peer.includes('SAAS_B16_VERIFIED_NODEPG_DIR'));
  assert.ok(peer.includes('SAAS_B16_LOCKED_NODEPG_PEER_CI'));
  assert.doesNotMatch(peer,/\/tmp\/b16-nodepg-peer\/node_modules/);
  assert.doesNotMatch(workflow,/npm install|--no-save|--package-lock=false/);
  assert.ok(workflow.includes(
    'node scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs'));
  assert.ok(workflow.includes('SAAS_B16_LOCKED_NODEPG_PEER_CI'));
  assert.ok(workflow.includes("image: postgres:16.6"));
  assert.ok(workflow.includes("contents: read"));
  for(const path of [
    'scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs',
    'scripts/saas-staging/verify-backend16-nodepg-peer-ci.ts',
    'scripts/saas-staging/backend16-locked-nodepg-peer-ci.mjs',
    'tests/saasBackend16LockedNodePgPeerCi.test.mjs',
    'src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts',
  ])assert.ok(workflow.includes("      - '"+path+"'"),
    'missing independent peer CI trigger: '+path);
  assert.doesNotMatch(runner,/startSyntheticBackend16MtlsBroker|createBackend16ExactSqlReadPort/);
});

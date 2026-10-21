import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {OBSERVED_NODEPG_GRAPH}
  from '../scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs';
import {
  parseBackend16NodePgIndependentGateOutput,
  enforceBackend16NodePgCrossRunnerEnvironment,
  assertMatchingBackend16NodePgCrossRunnerProofs,
} from '../scripts/saas-staging/verify-backend16-nodepg-cross-runner-ci.mjs';

const TREE='f'.repeat(64);
const HEAD='a'.repeat(40);
const CHECKOUT='b'.repeat(40);
const GRAPH=OBSERVED_NODEPG_GRAPH.sha256;
const MARKERS=[
  'B16_REAL_LOCK_CI_RESOLUTION_START',
  'B16_REAL_LOCK_CI_OBSERVED_GRAPH_MATCH_PASS',
  'B16_REAL_LOCK_CI_INDEPENDENT_RESOLUTIONS_MATCH_PASS',
  'B16_NODEPG_FROZEN_TREE_INDEPENDENT_MATCH_PASS',
  'B16_NODEPG_FROZEN_TREE_SHA256='+TREE,
  'B16_REAL_LOCK_CI_FROZEN_INSTALL_PASS',
  'PASS Backend16 Node24 independently resolved pg lock twice: '+
    '14 packages; canonical_sha256='+GRAPH+
    '; two frozen installs; NO RELEASE AUTHORIZATION',
];
const text=()=>MARKERS.join('\n')+'\n';
const refuse=fn=>assert.throws(
  fn,/Backend16 NodePG cross-runner CI refused|Backend16 genuine NodePG CI lock refused/);
const a=()=>({slot:'A',head:HEAD,checkout:CHECKOUT,graph:GRAPH,tree:TREE});
const b=()=>({...a(),slot:'B'});
const ENV={
  CI:'true',GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'pull_request',
  RUNNER_OS:'Linux',RUNNER_ARCH:'X64',
  GITHUB_SHA:CHECKOUT,B16_PR_HEAD_SHA:HEAD,
  RUNNER_TEMP:'/tmp/b16-cross-runner-test',
  GITHUB_OUTPUT:'/tmp/b16-cross-runner-test/_runner_file_commands/set_output_123',
  B16_CROSS_RUNNER_SLOT:'A',
};

test('real dual-lock stdout gives a single minimal immutable digest receipt',()=>{
  const parsed=parseBackend16NodePgIndependentGateOutput(text());
  assert.equal(parsed.tree,TREE);
  assert.equal(parsed.graph,GRAPH);
  assert.equal(Object.isFrozen(parsed),true);
  assert.equal(Object.keys(parsed).sort().join(','),'graph,tree');
});

test('forged, repeated or out-of-order npm markers fail before output',()=>{
  for(const marker of MARKERS){
    refuse(()=>parseBackend16NodePgIndependentGateOutput(
      MARKERS.filter(x=>x!==marker).join('\n')));
    refuse(()=>parseBackend16NodePgIndependentGateOutput(
      text()+marker+'\n'));
  }
  const swapped=[...MARKERS];
  [swapped[2],swapped[3]]=[swapped[3],swapped[2]];
  refuse(()=>parseBackend16NodePgIndependentGateOutput(swapped.join('\n')));
  const wrongTree=text().replace(TREE,'g'.repeat(64));
  refuse(()=>parseBackend16NodePgIndependentGateOutput(wrongTree));
  refuse(()=>parseBackend16NodePgIndependentGateOutput(
    text().replace(GRAPH,'0'.repeat(64))));
  refuse(()=>parseBackend16NodePgIndependentGateOutput(''));
  refuse(()=>parseBackend16NodePgIndependentGateOutput(text()+'a'.repeat(65_000)));
  refuse(()=>parseBackend16NodePgIndependentGateOutput(null));
});

test('two distinct jobs must match PR head, checked-out commit, graph AND file bytes',()=>{
  assert.equal(assertMatchingBackend16NodePgCrossRunnerProofs(
    a(),b(),HEAD,CHECKOUT),'B16_NODEPG_CROSS_RUNNER_FROZEN_BYTES_MATCH_PASS');
  for(const mutation of [
    {slot:'A'}, {head:'0'.repeat(40)}, {head:'invalid'},
    {checkout:'0'.repeat(40)}, {graph:'0'.repeat(64)},
    {tree:'e'.repeat(64)}, {tree:'0'.repeat(63)},
    {extra:'unreviewed field'},
  ])refuse(()=>assertMatchingBackend16NodePgCrossRunnerProofs(
    a(),{...b(),...mutation},HEAD,CHECKOUT));
  refuse(()=>assertMatchingBackend16NodePgCrossRunnerProofs(a(),a(),HEAD,CHECKOUT));
  refuse(()=>assertMatchingBackend16NodePgCrossRunnerProofs(a(),b(),'0'.repeat(40),CHECKOUT));
  refuse(()=>assertMatchingBackend16NodePgCrossRunnerProofs(a(),b(),HEAD,'0'.repeat(40)));
  refuse(()=>assertMatchingBackend16NodePgCrossRunnerProofs(null,b(),HEAD,CHECKOUT));
});

test('cross-job proof is GH PR + Linux X64 Node24 only, no release context',()=>{
  assert.doesNotThrow(()=>enforceBackend16NodePgCrossRunnerEnvironment(
    ENV,24,'record'));
  const compare={...ENV};
  delete compare.B16_CROSS_RUNNER_SLOT;
  assert.doesNotThrow(()=>enforceBackend16NodePgCrossRunnerEnvironment(
    compare,24,'compare'));
  for(const bad of [
    {GITHUB_ACTIONS:'false'}, {CI:'false'}, {GITHUB_EVENT_NAME:'push'},
    {RUNNER_OS:'Windows'}, {RUNNER_ARCH:'ARM64'},
    {GITHUB_SHA:'invalid'}, {B16_PR_HEAD_SHA:'invalid'},
    {B16_CROSS_RUNNER_SLOT:'A/B'}, {GITHUB_OUTPUT:'/tmp/other/evil'},
    {NODE_ENV:'production'}, {NODE_TLS_REJECT_UNAUTHORIZED:'0'},
    {RAILWAY_PROJECT_ID:'production'},
    {SAAS_B16_LOCKED_NODEPG_PEER_CI:'true'},
    {SAAS_B16_LOCKED_PG16_CI:'true'},
    {SAAS_B16_LOCKED_FULL_CHAIN_CI:'true'},
    {SAAS_B16_VERIFIED_NODEPG_DIR:'/tmp/injected'},
  ])refuse(()=>enforceBackend16NodePgCrossRunnerEnvironment(
    {...ENV,...bad},24,'record'));
  for(const major of [18,20,22,23,25])
    refuse(()=>enforceBackend16NodePgCrossRunnerEnvironment(ENV,major,'record'));
  refuse(()=>enforceBackend16NodePgCrossRunnerEnvironment(
    ENV,24,'compare'));
});

test('two separate hosted jobs and a dependent comparer gate enforce real source',()=>{
  const workflow=readFileSync(new URL(
    '../.github/workflows/saas-backend16-nodepg-cross-runner-ci.yml',
    import.meta.url),'utf8');
  const runner=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-nodepg-cross-runner-ci.mjs',
    import.meta.url),'utf8');
  assert.ok(workflow.includes('  proof_a:'));
  assert.ok(workflow.includes('  proof_b:'));
  assert.ok(workflow.includes('  compare:'));
  assert.ok(workflow.includes('needs: [proof_a, proof_b]'));
  assert.equal((workflow.match(/runs-on: ubuntu-24\.04/g)||[]).length,3);
  assert.equal((workflow.match(/node-version: '24'/g)||[]).length,3);
  assert.equal((workflow.match(/verify-backend16-nodepg-cross-runner-ci\.mjs record/g)||[]).length,2);
  assert.equal((workflow.match(/verify-backend16-nodepg-cross-runner-ci\.mjs compare/g)||[]).length,1);
  assert.ok(workflow.includes('permissions:\n  contents: read'));
  assert.ok(workflow.includes('B16_PR_HEAD_SHA:'));
  assert.ok(workflow.includes('github.event.pull_request.head.sha'));
  assert.ok(workflow.includes('needs.proof_a.outputs.tree'));
  assert.ok(workflow.includes('needs.proof_b.outputs.tree'));
  assert.doesNotMatch(workflow,/continue-on-error:|workflow_dispatch:|npm install --no-save/);
  for(const path of [
    '.github/workflows/saas-backend16-nodepg-cross-runner-ci.yml',
    'scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs',
    'scripts/saas-staging/verify-backend16-nodepg-runtime-lock.mjs',
    'scripts/saas-staging/verify-backend16-nodepg-installed-tree-ci.mjs',
    'scripts/saas-staging/verify-backend16-nodepg-cross-runner-ci.mjs',
    'tests/saasBackend16NodePgCrossRunnerCi.test.mjs',
    'package.json',
    'bun.lock',
  ])assert.ok(workflow.includes("      - '"+path+"'"),
    'missing cross-runner trigger '+path);
  assert.ok(runner.includes('if(actual!==e.GITHUB_SHA)refuse()'));
  assert.ok(runner.includes("env:{\n      PATH:process.env.PATH"));
  assert.ok(runner.includes('GITHUB_ACTIONS:\'true\',CI:\'true\',LANG:\'C\''));
  assert.ok(runner.includes('appendFileSync(e.GITHUB_OUTPUT'));
  assert.ok(runner.includes('NO RELEASE AUTHORIZATION'));
  assert.doesNotMatch(runner,/createBackend16ExactSqlReadPort|startSyntheticBackend16MtlsBroker|NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=true/);
});

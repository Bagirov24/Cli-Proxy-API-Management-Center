import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  BUNDLE_SHA256,BUNDLE_BYTES,RUNTIME_SHA256,INPUT_SHA256,CHILD_BLOB,
  ORIGINAL_SUPERVISOR_BLOB,BUILD,BUNDLE_MARKERS,SUPERVISOR_ADDITION,
  assertBundleEnvironment,bundleChildEnvironment,emittedHarness,
  assertBuiltBundle,assertRuntimeBytes,makeBundleReceipt,assertBundleReceipt,
} from '../scripts/saas-staging/backend16-native-bundle-physical-contract.mjs';
import {gitBlob,sha256} from '../scripts/saas-staging/backend16-native-package-contract.mjs';
import {COMBINED_STEPS,parseCombinedCommand,assertCombinedBrokerReceipt}
  from '../scripts/saas-staging/backend16-stable-144-combined-contract.mjs';
import {runBundledPhysicalCi} from '../scripts/saas-staging/verify-backend16-native-bundle-physical-ci.mjs';
const read=p=>readFileSync(new URL('../'+p,import.meta.url));
const original=read('scripts/saas-staging/backend16-stable-144-combined-child.ts');
const runner=read('scripts/saas-staging/verify-backend16-native-bundle-physical-ci.mjs').toString();
const head='a'.repeat(40);
const expected={headSha:head,runId:'12345',runAttempt:'1'};
function env(){
  const e={CI:'true',GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'pull_request',
    GITHUB_REPOSITORY:'Bagirov24/Cli-Proxy-API-Management-Center',RUNNER_OS:'Linux',RUNNER_ARCH:'X64',
    B16_PR_HEAD_SHA:head,GITHUB_SHA:'b'.repeat(40),GITHUB_RUN_ID:'12345',GITHUB_RUN_ATTEMPT:'1',
    RUNNER_TEMP:'/tmp/ci-work',SAAS_B16_EPHEMERAL_CI:'true',SAAS_B16_STABLE_144_FULL_PG16_CI:'true',
    SAAS_B16_STABLE_144_COMBINED_CI:'true',PGHOST:'127.0.0.1',PGPORT:'5432',PGUSER:'postgres',
    PGDATABASE:'saas_ephemeral_test',PGPASSWORD:'ci_ephemeral_test_only',
    SAAS_B16_STABLE_144_BIN:'/tmp/b16-official-stable-144-ci-Ab12cd/bun',
    SAAS_B16_CI_PG_CONTAINER:'c'.repeat(64)};
  for(const k of ['A','B']){
    e['SAAS_B16_CI_'+k+'_PASSWORD']='d'.repeat(64);
    e['SAAS_B16_CI_'+k+'_SUBJECT_SHA']='e'.repeat(64);
    for(const f of ['TENANT','SESSION','BINDING'])
      e['SAAS_B16_CI_'+k+'_'+f]='11111111-1111-4111-8111-111111111111';
  }
  return e;
}
const receipt=()=>makeBundleReceipt(head,'12345','1','c'.repeat(64),'d'.repeat(64));
const denied=f=>assert.throws(f,/refused/);

test('bundle physical pins reference observed PR107 bytes, never a release approval',()=>{
  assert.equal(BUNDLE_SHA256,'21ae8f82c05ff2b8a3ae2e096f7d1262107fd5e924bf3212ad3c354ebea9cd56');
  assert.equal(BUNDLE_BYTES,59771);assert.match(RUNTIME_SHA256,/^[a-f0-9]{64}$/);
  assert.match(INPUT_SHA256,/^[a-f0-9]{64}$/);assert.equal(gitBlob(original),CHILD_BLOB);
  assert.deepEqual(BUILD,['build','./index.ts','--target=bun','--format=esm',
    '--packages=bundle','--outfile=./dist/transport.js']);assert.ok(Object.isFrozen(BUILD));
});
test('emitted harness preserves the entire original physical assertion body byte-for-byte',()=>{
  const transformed=emittedHarness(original).toString();
  const source=original.toString(),start="let phase='ENVIRONMENT';";
  assert.equal(transformed.slice(transformed.indexOf(start)),source.slice(source.indexOf(start)));
  assert.ok(transformed.includes("import {transport} from './transport.js';"));
  assert.doesNotMatch(transformed,/\.\.\/\.\.\/src\/|from ['"].*\.ts['"]|combined-contract\.mjs/);
  assert.equal((transformed.match(/\bfrom ['"]/g)||[]).length,9);
});
test('all five production execution bindings come from the emitted transport namespaces',()=>{
  const h=emittedHarness(original).toString();
  for(const space of ['secretReader','vault','physicalPool','tlsTrust','exactRead'])
    assert.ok(h.includes('}=transport.'+space+';'),space);
  for(const phrase of ["assert.equal(released,9)","assert.equal(await rpc('stats'),12)",
    "assert.deepEqual(await read(a,tb,fresh()),{kind:'denied'})",
    "await rpc('wait');e.SAAS_B16_BROKER_MTLS_CI='false'",
    "wait_event_type='Lock'","await gone(A)","trust(other)"])
    assert.ok(h.includes(phrase),phrase);
});
test('changed harness assertions, import targets, missing bytes and appended fallback refuse',()=>{
  for(const text of [original.toString().replace('assert.equal(released,9)','assert.equal(released,8)'),
    original.toString().replace("from 'bun'","from 'pg'"),
    original.toString()+'\nimport evil from "./src/fallback.ts";\n',
    original.subarray(0,original.length-1)])
    denied(()=>emittedHarness(Buffer.from(text)));
  denied(()=>emittedHarness(original.toString()));denied(()=>emittedHarness(Buffer.alloc(0)));
});
test('supervisor addition leaves ALL existing source-scenario bytes unchanged',()=>{
  const text=read('scripts/saas-staging/verify-backend16-stable-144-combined-ci.ts').toString();
  assert.equal(text.split(SUPERVISOR_ADDITION).length,2);
  assert.equal(gitBlob(Buffer.from(text.replace(SUPERVISOR_ADDITION,''))),ORIGINAL_SUPERVISOR_BLOB);
  assert.ok(text.indexOf(SUPERVISOR_ADDITION)>text.indexOf('await new Promise<void>'));
  assert.ok(text.indexOf(SUPERVISOR_ADDITION)<text.indexOf('for(const marker of COMBINED_MARKERS)'));
});
test('exact-head bundle environment accepts only the explicit disposable Node24 context',()=>{
  assert.equal(assertBundleEnvironment(env(),24,'linux','x64',head),true);
  for(const args of [[22,'linux','x64',head],[24,'darwin','x64',head],
    [24,'linux','arm64',head],[24,'linux','x64','f'.repeat(40)]])
    denied(()=>assertBundleEnvironment(env(),...args));
});
test('production, Railway, external DB, missing CI and stale coordinates refuse',()=>{
  for(const [k,v] of Object.entries({NODE_ENV:'production',RAILWAY_TOKEN:'x',
    DATABASE_URL:'postgres://live',PGHOST:'external',PGPORT:'6432',PGUSER:'live',
    PGPASSWORD:'live',PGDATABASE:'live',CI:'false',GITHUB_ACTIONS:'false',GITHUB_EVENT_NAME:'push',
    GITHUB_REPOSITORY:'foreign/repo',GITHUB_RUN_ID:'0',GITHUB_RUN_ATTEMPT:'0',
    RUNNER_TEMP:'relative',SAAS_B16_STABLE_144_COMBINED_CI:'false',
    SAAS_B16_CI_A_PASSWORD:'bad',SAAS_B16_STABLE_144_BIN:'/usr/bin/bun'}))
    denied(()=>assertBundleEnvironment({...env(),[k]:v},24,'linux','x64',head));
});
test('loaders and trust injection are rejected before subprocess creation',()=>{
  for(const k of ['NODE_OPTIONS','NODE_PATH','BUN_OPTIONS','BUN_PRELOAD','LD_PRELOAD',
    'LD_LIBRARY_PATH','NODE_EXTRA_CA_CERTS','SSL_CERT_FILE','SSL_CERT_DIR'])
    denied(()=>assertBundleEnvironment({...env(),[k]:'injection'},24,'linux','x64',head));
});
test('child environment contains no principal passwords, token, proxy or inherited HOME',()=>{
  const child=bundleChildEnvironment({...env(),HOME:'/secret',HTTP_PROXY:'https://proxy',
    GITHUB_TOKEN:'secret',OTHER_SECRET:'secret',NODE_OPTIONS:'--require bad'},'/tmp/probe');
  for(const k of ['SAAS_B16_CI_A_PASSWORD','SAAS_B16_CI_B_PASSWORD','HTTP_PROXY','GITHUB_TOKEN',
    'OTHER_SECRET','NODE_OPTIONS','DATABASE_URL'])assert.equal(Object.hasOwn(child,k),false);
  assert.equal(child.HOME,'/tmp/probe/home');assert.equal(child.TMPDIR,'/tmp/probe/tmp');
  assert.equal(child.PGPASSWORD,'ci_ephemeral_test_only'); // fixture observer, NOT app secret
  assert.equal(child.BUN_RUNTIME_TRANSPILER_CACHE_PATH,'0');assert.ok(Object.isFrozen(child));
});
test('counterfeit library bytes and a version-looking nonbinary cannot satisfy byte pins',()=>{
  for(const bytes of [Buffer.alloc(0),Buffer.alloc(BUNDLE_BYTES),Buffer.from(BUNDLE_SHA256)])
    denied(()=>assertBuiltBundle(bytes));
  for(const bytes of [Buffer.from('1.4.4+38afee6c8'),Buffer.alloc(20_000_000)])
    denied(()=>assertRuntimeBytes(bytes));
});
test('receipt binds current head and run while explicitly denying package/server/release approval',()=>{
  const r=receipt();assert.equal(assertBundleReceipt(r,expected),true);
  assert.equal(r.physicalBundleIntegrationPassed,true);assert.equal(r.sourceRemovedBeforeExecution,true);
  for(const k of ['packageManagerLockVerified','serverEntrypointBuilt','stableRuntimeApproved','productionAuthorized'])
    assert.equal(r[k],false);
  assert.equal(r.releaseState,'BLOCKED_RELEASE');assert.ok(Object.isFrozen(r));
});
test('stale head, run and attempt receipts refuse',()=>{
  for(const [k,v] of Object.entries({headSha:'f'.repeat(40),runId:'12346',runAttempt:'2'}))
    denied(()=>assertBundleReceipt({...receipt(),[k]:v},expected));
});
test('receipt refuses byte drift, missing physical results and changed independent broker counts',()=>{
  for(const [k,v] of Object.entries({bundleSha256:'f'.repeat(64),bundleBytes:BUNDLE_BYTES+1,
    runtimeSha256:'f'.repeat(64),inputSha256:'f'.repeat(64),harnessSourceGitBlob:'f'.repeat(40),
    brokerRequests:11,brokerRequestsA:7,brokerRequestsB:5,credentialReleases:10,
    sourceRemovedBeforeExecution:false,physicalBundleIntegrationPassed:false}))
    denied(()=>assertBundleReceipt({...receipt(),[k]:v},expected));
});
test('receipt rejects every forged approval, extra field and removed field',()=>{
  for(const k of ['packageManagerLockVerified','serverEntrypointBuilt','stableRuntimeApproved','productionAuthorized'])
    denied(()=>assertBundleReceipt({...receipt(),[k]:true},expected));
  denied(()=>assertBundleReceipt({...receipt(),releaseState:'APPROVED'},expected));
  denied(()=>assertBundleReceipt({...receipt(),extra:true},expected));
  for(const k of Object.keys(receipt())){const r={...receipt()};delete r[k];denied(()=>assertBundleReceipt(r,expected));}
});
test('receipt rejects getters, symbols and nonplain prototypes without evaluating code',()=>{
  let called=false;const r={...receipt()};Object.defineProperty(r,'headSha',{get(){called=true;return head;}});
  denied(()=>assertBundleReceipt(r,expected));assert.equal(called,false);
  denied(()=>assertBundleReceipt({...receipt(),[Symbol('extra')]:true},expected));
  denied(()=>assertBundleReceipt(Object.assign(Object.create(null),receipt()),expected));
});
test('strict original control sequence rejects skipped, duplicate and reordered commands',()=>{
  COMBINED_STEPS.forEach((op,i)=>assert.deepEqual(parseCombinedCommand(JSON.stringify({id:i+1,op}),i),{id:i+1,op}));
  for(const [line,i] of [['{"id":1,"id":1,"op":"stats"}',0],
    ['{"id":1,"op":"done"}',0],['{"id":14,"op":"done"}',13],
    ['{"id":1,"op":"stats","pass":true}',0]])denied(()=>parseCombinedCommand(line,i));
});
test('independent broker receipt requires exactly eight A and four B versioned reads',()=>{
  const records=Array.from({length:12},(_,i)=>{const a=i<8,letter=a?'a':'b';return {
    pgLogin:a?'saas_b14_person':'saas_b16_person_b',secretId:'b16-stg-pg-'+letter.repeat(20),version:letter.repeat(32)};});
  assert.equal(assertCombinedBrokerReceipt(12,records),true);
  denied(()=>assertCombinedBrokerReceipt(11,records));
  denied(()=>assertCombinedBrokerReceipt(12,records.slice(1)));
  denied(()=>assertCombinedBrokerReceipt(12,records.map(x=>({...x,version:'c'.repeat(32)}))));
});
test('runner deletes copied build inputs BEFORE broker startup and accepts only emitted files',()=>{
  const erased=runner.indexOf('rmSync(build,{recursive:true,force:true})');
  const start=runner.indexOf('broker=await startSyntheticBackend16MtlsBroker');
  assert.ok(erased>0&&start>erased);
  assert.ok(runner.includes("filesAt(stage).join(',')!=='probe.ts,transport.js'"));
  assert.ok(runner.includes("['--no-install','--no-env-file','./probe.ts']"));
  assert.ok(runner.includes('cwd:stage,env:bundleChildEnvironment(e,stage)'));
  assert.ok(runner.includes('assertBuiltBundle(readInput(stage,\'transport.js\'))'));
  assert.ok(runner.includes('assertCombinedBrokerReceipt(broker.calls(),broker.received)'));
});
test('new guards run unconditionally in BOTH existing package lanes without weakening old gates',()=>{
  const workflow=read('.github/workflows/saas-backend16-native-package-ci.yml').toString();
  assert.ok(workflow.includes('lane: [A, B]'));
  for(const name of ['saasBackend16NativeBundlePhysicalCi.test.mjs','saasBackend16NativePackageCi.test.mjs',
    'verify-backend16-native-server-artifact-evidence-contract-ci.mjs','verify-backend16-official-stable-144-tls-ci.ts'])
    assert.ok(workflow.includes(name),name);
  assert.doesNotMatch(workflow,/continue-on-error:|expected-failure:/);
  assert.equal(BUNDLE_MARKERS.length,8);assert.ok(Object.isFrozen(BUNDLE_MARKERS));
  assert.match(sha256(emittedHarness(original)),/^[a-f0-9]{64}$/);
});
test('untrusted exported invocation refuses before checkout, subprocesses or native imports',async()=>{
  await assert.rejects(runBundledPhysicalCi('/does-not-exist',{}),/refused/);
});

import {parseBundleLog} from '../scripts/saas-staging/backend16-native-bundle-physical-contract.mjs';
const logText=()=>BUNDLE_MARKERS.join('\n')+'\nB16_EMITTED_BUNDLE_RECEIPT='+JSON.stringify(receipt())+'\n';
test('bounded log readback selects one canonical current-run receipt and exact-once markers',()=>{
  assert.deepEqual(parseBundleLog(logText(),expected),receipt());
  assert.ok(Object.isFrozen(parseBundleLog(logText(),expected)));
  for(const text of [logText()+logText(),logText().replace(BUNDLE_MARKERS[0],'missing'),
    BUNDLE_MARKERS[0]+'\n'+logText(),logText().replace('"runId":"12345"','"runId":"999"'),
    logText().replace('"runId":"12345"','"runId":"12345","runId":"12345"'),
    logText().replace('B16_EMITTED_BUNDLE_RECEIPT={','B16_EMITTED_BUNDLE_RECEIPT={ '),
    logText()+'x'.repeat(65536)])denied(()=>parseBundleLog(text,expected));
});
test('bounded receipt readback is the ONLY physical shell addition; every old byte remains',()=>{
  const shell=read('scripts/saas-staging/verify-backend16-exact-session-pg16.sh').toString();
  const begin='# BEGIN emitted-only bounded log readback.\n';
  const end='# END emitted-only bounded log readback.\n';
  assert.equal(shell.split(begin).length,2);assert.equal(shell.split(end).length,2);
  const start=shell.indexOf(begin),finish=shell.indexOf(end)+end.length;
  const restored=shell.slice(0,start)+shell.slice(finish);
  assert.equal(gitBlob(Buffer.from(restored)),'838e0279200947a206230f593aa44a7a7f0ae782');
  const block=shell.slice(start,finish);
  assert.ok(block.includes('constants.O_NOFOLLOW'));
  assert.ok(block.includes('before.size>65536'));
  assert.ok(block.includes('parseBundleLog'));
  assert.ok(block.includes('headSha:process.env.B16_PR_HEAD_SHA'));
  assert.ok(start<shell.indexOf('# END stable combined;'));
});

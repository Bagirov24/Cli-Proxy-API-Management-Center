import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const read=p=>readFileSync(new URL(p,import.meta.url),'utf8');
const workflow=read('../.github/workflows/saas-staging-rls-ci.yml');
const stableWorkflow=read('../.github/workflows/saas-backend16-stable-144-tls-ci.yml');
const canary=read('../scripts/saas-staging/verify-backend16-native-pg-tls-ci.ts');
const stable=read('../scripts/saas-staging/verify-backend16-official-stable-144-physical-pg16-ci.ts');
const mtls=read('../scripts/saas-staging/verify-backend16-official-stable-144-mtls-ci.ts');
const originalMtls=read('../scripts/saas-staging/verify-backend16-mtls-secret-broker-ci.ts');
const shell=read('../scripts/saas-staging/verify-backend16-exact-session-pg16.sh');
const stableRev='38afee6c84fcf48c0edb2466aa4b27d287a59c30';
const canaryRev='6bb5dc1956505dd1113455f58d4757c924f3ad54';
const paths=[
  'scripts/saas-staging/verify-backend16-official-stable-144-physical-pg16-ci.ts',
  'scripts/saas-staging/verify-backend16-official-stable-144-mtls-ci.ts',
  'tests/saasBackend16Stable144FullPhysicalCi.test.mjs',
  'docs/saas/BACKEND_16_P1_STABLE_144_FULL_PHYSICAL_CI.md',
];
const count=(s,needle)=>s.split(needle).length-1;
const noBypass=src=>assert.doesNotMatch(src,
  /continue-on-error:|expected-failure:|NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=true/);

test('stable full native TLS is byte-identical to original canary negative assertions',()=>{
  const guard="   env.SAAS_B16_STABLE_144_FULL_PG16_CI!=='true'||\n";
  assert.equal(count(stable,stableRev),1);
  assert.equal(count(stable,guard),1);
  assert.equal(stable.replace(stableRev,canaryRev).replace(guard,''),canary);
  for(const m of ['B16_NATIVE_SQL_TLS_REAL_PID_VERIFIED',
    'B16_NATIVE_SQL_TLS_TWO_TENANT_RLS_PASS',
    'B16_NATIVE_SQL_TLS_ALWAYS_DENY_CALLBACK_',
    'B16_NATIVE_SQL_TLS_WRONG_ROOT_',
    'B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_',
    'BACKEND16_EXACT_READ_SQL.identity',
    'createBackend16StagingVersionedPrincipalVault',
  ])assert.ok(stable.includes(m),m);
  noBypass(stable);
});

test('stable broker retains EVERY original Node24 mTLS negative and immutable vault test',()=>{
  const guard=[
    "if(process.env.SAAS_B16_STABLE_144_FULL_PG16_CI!=='true'||",
    "   !/^\\/tmp\\/b16-official-stable-144-ci-[A-Za-z0-9]{6}\\/bun$/.test(",
    "     process.env.SAAS_B16_STABLE_144_BIN??'')||",
    "   process.env.NODE_ENV==='production'||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')",
    "  throw Error('B16 official stable 1.4.4 mTLS client refused environment');",
  ].join('\n')+'\n';
  assert.equal(count(mtls,guard),1);
  const child='spawn(process.env.SAAS_B16_STABLE_144_BIN!,args,{';
  assert.equal(count(mtls,child),1);
  assert.equal(mtls.replace(guard,'').replace(child,"spawn('bun',args,{"),originalMtls);
  for(const marker of [
    'B16_MTLS_BROKER_CI_BUN_CLIENT_PASS',
    'B16_MTLS_BROKER_CI_WRONG_SERVER_SAN_DENY',
    'B16_MTLS_BROKER_CI_WILDCARD_SERVER_SAN_DENY',
    'B16_MTLS_BROKER_CI_UNTRUSTED_IDENTITY_DENY',
    'PASS Backend16.15 actual mutual TLS immutable-version reader',
  ])assert.ok(mtls.includes(marker),marker);
  noBypass(mtls);
});

test('physical PG16 job pins exact PR head and installs stable BEFORE old canary',()=>{
  assert.ok(workflow.includes('ref: $'+'{{ github.event.pull_request.head.sha }}'));
  assert.ok(workflow.includes('persist-credentials: false'));
  assert.ok(workflow.includes('image: postgres:16.6'));
  assert.ok(workflow.includes("node-version: '24'"));
  assert.ok(workflow.includes("bun-version: 1.3.14"));
  const stableAt=workflow.indexOf('Pin OFFICIAL stable Bun144 for additional full physical PG16 only');
  const canaryAt=workflow.indexOf('Install integrity-pinned upstream native SQL TLS fix (CI only)');
  const physicalAt=workflow.indexOf('Backend08/09 isolated PG16 migrator role, ledger and dump-restore (CI only)');
  assert.ok(stableAt>0&&stableAt<canaryAt&&canaryAt<physicalAt);
  assert.ok(workflow.includes('node scripts/saas-staging/install-backend16-official-stable-144-ci.mjs'));
  assert.ok(workflow.includes('B16_PR_HEAD_SHA: $'+'{{ github.event.pull_request.head.sha }}'));
  assert.ok(workflow.includes("SAAS_B16_STABLE_144_FULL_PG16_CI: 'true'"));
  assert.ok(workflow.includes('bash scripts/saas-staging/verify-backend16-exact-session-pg16.sh'));
  noBypass(workflow);
});

test('original Node pg, root Bun, canary TLS and all SQL0008 adversarial gates remain',()=>{
  for(const m of [
    'bun scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts',
    'node scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs',
    'B16_LOCKED_FULL_CHAIN_INDEPENDENT_A_PASS',
    'B16_LOCKED_FULL_CHAIN_INDEPENDENT_B_PASS',
    'B16_LOCKED_DUAL_INSTALL_MTLS_VAULT_PG16_EXACT_RLS_PASS',
    'verify-backend16-native-pg-tls-ci.ts',
    'B16_NATIVE_SQL_TLS_ALWAYS_DENY_CALLBACK_ENFORCED',
    'B16_NATIVE_SQL_TLS_WRONG_ROOT_DENIED',
    'B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_DENIED',
    'eq wrong_session f','eq wrong_binding f','eq wrong_digest f',
    'eq missing_gate f','eq fake_set_role f','eq revoke_after_reader 2',
    'eq revoked_denied f','eq old_session_stale f','eq eight_receipts 8',
  ])assert.ok(shell.includes(m),m);
  const pid=shell.indexOf('B16_STABLE_144_PHYSICAL_VAULT_FOR_SHARE_REVOKE_PID_PASS');
  const node=shell.indexOf('B16_LOCKED_DUAL_INSTALL_MTLS_VAULT_PG16_EXACT_RLS_PASS');
  const tls=shell.indexOf('B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_DENIED');
  const stableTls=shell.indexOf('B16_STABLE_144_TLS_TWO_TENANT_VAULT_RLS_PID_NEGATIVES_PASS');
  const revoke=shell.indexOf('eq wrong_session f');
  assert.ok(pid>0&&pid<node&&node<tls&&tls<stableTls&&stableTls<revoke);
  noBypass(shell);
});

test('full stable extra requires two physical logins, broker mTLS, vault and negative TLS',()=>{
  for(const m of [
    'B16_STABLE_144_PHYSICAL_VAULT_FOR_SHARE_REVOKE_PID_PASS',
    'B16_STABLE_144_MTLS_BROKER_VERSIONED_VAULT_PASS',
    'B16_STABLE_144_TLS_TWO_TENANT_VAULT_RLS_PID_NEGATIVES_PASS',
    'B16_STABLE_144_FULL_DISPOSABLE_PG16_CANDIDATE_PASS_NOT_RELEASE_APPROVAL',
  ])assert.equal(count(shell,"echo '"+m+"'"),1);
  assert.ok(shell.includes('git rev-parse HEAD'));
  assert.ok(shell.includes('1.4.4+38afee6c8'));
  assert.ok(shell.includes('"$SAAS_B16_STABLE_144_BIN" --revision'));
  assert.ok(shell.includes("ALTER SYSTEM SET ssl='off'"));
  assert.ok(shell.includes('pg_reload_conf()'));
  assert.ok(shell.includes("-c 'SHOW ssl')"));
  assert.ok(shell.includes('verify-backend16-official-stable-144-physical-pg16-ci.ts'));
  assert.ok(shell.includes('verify-backend16-official-stable-144-mtls-ci.ts'));
  assert.ok(shell.includes('NO RELEASE AUTHORIZATION'));
  noBypass(shell);
});

test('stable changes trigger all four security workflows and mTLS regression',()=>{
  for(const file of [
    '.github/workflows/saas-backend16-native-tls-experiment.yml',
    '.github/workflows/saas-backend16-native-source-repro-ci.yml',
    '.github/workflows/saas-backend16-stable-144-tls-ci.yml',
    '.github/workflows/saas-staging-rls-ci.yml',
  ]){
    const flow=read('../'+file);
    for(const p of paths)assert.ok(flow.includes("      - '"+p+"'"),file+' missing '+p);
    noBypass(flow);
  }
  for(const path of [
    'scripts/saas-staging/verify-backend16-exact-session-pg16.sh',
    'scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts',
    'scripts/saas-staging/verify-backend16-mtls-secret-broker-ci.ts',
    'scripts/saas-staging/verify-backend16-native-pg-tls-ci.ts',
    '.github/workflows/saas-staging-rls-ci.yml',
  ])assert.ok(stableWorkflow.includes("      - '"+path+"'"),path);
  assert.ok(stableWorkflow.includes(
    'node --experimental-strip-types scripts/saas-staging/verify-backend16-official-stable-144-mtls-ci.ts'));
});

test('stable binary can never become approved runtime via CI receipt',()=>{
  const installer=read('../scripts/saas-staging/install-backend16-official-stable-144-ci.mjs');
  assert.ok(installer.includes('38afee6c84fcf48c0edb2466aa4b27d287a59c30'));
  assert.ok(installer.includes('verifyBackend16OfficialStable144Archive(bytes);'));
  assert.ok(installer.includes('B16_OFFICIAL_STABLE_144_NOT_APPROVED_FOR_RELEASE'));
  assert.equal(JSON.parse(read('../package.json')).packageManager,'bun@1.3.14');
  assert.ok(read('../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts')
    .includes('const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
});

test('CI-only shell and real mTLS fixture fail closed on untrusted local invocation',()=>{
  const sh=fileURLToPath(new URL('../scripts/saas-staging/verify-backend16-exact-session-pg16.sh',import.meta.url));
  const a=spawnSync('bash',[sh],{encoding:'utf8',timeout:5000,
    env:{...process.env,GITHUB_ACTIONS:'false',SAAS_B16_EPHEMERAL_CI:'false'}});
  assert.equal(a.status,1);
  assert.match(a.stderr,/Backend16 SQL0008 disposable PG16 acceptance STOP/);
  const ts=fileURLToPath(new URL('../scripts/saas-staging/verify-backend16-official-stable-144-mtls-ci.ts',import.meta.url));
  const b=spawnSync(process.execPath,['--experimental-strip-types',ts],{
    encoding:'utf8',timeout:8000,env:{
      ...process.env,GITHUB_ACTIONS:'false',SAAS_B16_STABLE_144_FULL_PG16_CI:'false',
    }});
  assert.notEqual(b.status,0);
  assert.equal(b.stdout,'');
});

// Additional composition regressions: the original eight tests above are unchanged.
import {createHash as combinedHash} from 'node:crypto';
import {
  COMBINED_STEPS,COMBINED_MARKERS,assertCombinedEnvironment,
  combinedChildEnvironment,parseCombinedCommand,assertCombinedBrokerReceipt,
} from '../scripts/saas-staging/backend16-stable-144-combined-contract.mjs';
const combinedHead='a'.repeat(40);
function combinedEnv(){
  const e={CI:'true',GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'pull_request',
    GITHUB_REPOSITORY:'Bagirov24/Cli-Proxy-API-Management-Center',
    RUNNER_OS:'Linux',RUNNER_ARCH:'X64',B16_PR_HEAD_SHA:combinedHead,GITHUB_SHA:'b'.repeat(40),
    SAAS_B16_EPHEMERAL_CI:'true',SAAS_B16_STABLE_144_FULL_PG16_CI:'true',
    SAAS_B16_STABLE_144_COMBINED_CI:'true',PGHOST:'127.0.0.1',PGPORT:'5432',PGUSER:'postgres',
    PGDATABASE:'saas_ephemeral_test',PGPASSWORD:'ci_ephemeral_test_only',
    SAAS_B16_STABLE_144_BIN:'/tmp/b16-official-stable-144-ci-Ab12cd/bun',
    SAAS_B16_CI_PG_CONTAINER:'c'.repeat(64),PATH:'/usr/bin:/bin'};
  for(const k of ['A','B']){
    e['SAAS_B16_CI_'+k+'_PASSWORD']='d'.repeat(64);
    e['SAAS_B16_CI_'+k+'_SUBJECT_SHA']='e'.repeat(64);
    for(const f of ['TENANT','SESSION','BINDING'])
      e['SAAS_B16_CI_'+k+'_'+f]='11111111-1111-4111-8111-111111111111';
  }
  return e;
}
const combinedDenied=fn=>assert.throws(fn,/Backend16 stable combined CI refused/);

test('combined exact-head environment denies production, external DB, wrong runner and candidate',()=>{
  const e=combinedEnv();assert.equal(assertCombinedEnvironment(e,24,combinedHead),true);
  for(const [key,value] of Object.entries({
    CI:'false',GITHUB_ACTIONS:'false',GITHUB_EVENT_NAME:'push',GITHUB_REPOSITORY:'other/repo',
    RUNNER_OS:'Windows',RUNNER_ARCH:'ARM64',B16_PR_HEAD_SHA:'bad',GITHUB_SHA:'bad',
    SAAS_B16_EPHEMERAL_CI:'false',SAAS_B16_STABLE_144_FULL_PG16_CI:'false',
    SAAS_B16_STABLE_144_COMBINED_CI:'false',PGHOST:'live.private',PGPORT:'6432',PGUSER:'runtime',
    PGDATABASE:'live',PGPASSWORD:'live',NODE_ENV:'production',NODE_TLS_REJECT_UNAUTHORIZED:'0',
    DATABASE_URL:'postgres://live',RAILWAY_SERVICE_ID:'live',SAAS_B16_STABLE_144_BIN:'/bin/bun',
    SAAS_B16_CI_PG_CONTAINER:'bad',SAAS_B16_CI_A_PASSWORD:'short',SAAS_B16_CI_B_SESSION:'bad',
  }))combinedDenied(()=>assertCombinedEnvironment({...e,[key]:value},24,combinedHead));
  combinedDenied(()=>assertCombinedEnvironment(e,22,combinedHead));
  combinedDenied(()=>assertCombinedEnvironment(e,24,'f'.repeat(40)));
  combinedDenied(()=>assertCombinedEnvironment(null,24,combinedHead));
});

test('combined child cannot inherit principal passwords or arbitrary process injection',()=>{
  const e={...combinedEnv(),NODE_OPTIONS:'--require evil',GITHUB_TOKEN:'private',OTHER_SECRET:'hidden'};
  const child=combinedChildEnvironment(e);
  for(const key of ['SAAS_B16_CI_A_PASSWORD','SAAS_B16_CI_B_PASSWORD',
    'NODE_OPTIONS','GITHUB_TOKEN','OTHER_SECRET'])assert.equal(Object.hasOwn(child,key),false);
  assert.equal(child.PGPASSWORD,'ci_ephemeral_test_only');
  assert.equal(child.SAAS_B16_BROKER_MTLS_CI,'true');
  assert.equal(child.SAAS_B16_CI_A_SUBJECT_SHA,e.SAAS_B16_CI_A_SUBJECT_SHA);
  assert.ok(Object.isFrozen(child));
});

test('combined control protocol rejects skips, duplicate keys, extra data and reordered commands',()=>{
  for(const [i,op] of COMBINED_STEPS.entries()){
    const line=JSON.stringify({id:i+1,op});
    assert.equal(parseCombinedCommand(line,i).op,op);
    for(const bad of [line+'\n',line.replace('"id":','"extra":0,"id":'),
      JSON.stringify({op,id:i+1}),JSON.stringify({id:99,op}),
      JSON.stringify({id:i+1,op:'approve'}),line.replace('"id":','"id":0,"id":')])
      combinedDenied(()=>parseCombinedCommand(bad,i));
  }
  for(const bad of ['',null,'[]','{"id":1}', 'x'.repeat(161)])
    combinedDenied(()=>parseCombinedCommand(bad,0));
  combinedDenied(()=>parseCombinedCommand('{"id":1,"op":"stats"}',13));
});

function combinedReceipts(){
  return [...Array(8).fill('a'),...Array(4).fill('b')].map(k=>({
    pgLogin:k==='a'?'saas_b14_person':'saas_b16_person_b',
    secretId:'b16-stg-pg-'+k.repeat(20),version:k.repeat(32),
  }));
}
test('combined receipt requires twelve actual exact-version requests across both LOGINs',()=>{
  assert.equal(assertCombinedBrokerReceipt(12,combinedReceipts()),true);
  for(const n of [0,11,13])combinedDenied(()=>assertCombinedBrokerReceipt(n,combinedReceipts()));
  for(const update of [{pgLogin:'postgres'},{secretId:'unreviewed'},{version:'latest'},
    {password:'should-never-be-in-receipt'}]){
    const rows=combinedReceipts();rows[0]={...rows[0],...update};
    combinedDenied(()=>assertCombinedBrokerReceipt(12,rows));
  }
  const rows=combinedReceipts();rows[0]=rows[11];
  combinedDenied(()=>assertCombinedBrokerReceipt(12,rows));
  combinedDenied(()=>assertCombinedBrokerReceipt(12,combinedReceipts().slice(1)));
});

test('combined runner composes real mTLS, real native SQL and counted credential release',()=>{
  const child=read('../scripts/saas-staging/backend16-stable-144-combined-child.ts');
  const parent=read('../scripts/saas-staging/verify-backend16-stable-144-combined-ci.ts');
  for(const s of ['createBackend16DisposableCiMtlsSecretReader(setup.trust,setup.port)',
    'source:reader,manifest:','const secret=await vault.readPrincipal(login,signal)',
    'createBackend16StagingDisposableCiTlsPhysicalPgPool(observed,trust(ca))',
    'assert.equal(e.SAAS_B16_CI_A_PASSWORD,undefined)',
    "e.SAAS_B16_BROKER_MTLS_CI='false'",'wait_event_type=\'Lock\'',
    'assert.equal(released,9)',"assert.equal(await rpc('stats'),12)"])
    assert.ok(child.includes(s),s);
  assert.ok(parent.includes('env:combinedChildEnvironment(e)'));
  assert.ok(parent.includes('code===0&&!signal&&!failed&&index===COMBINED_STEPS.length'));
  assert.ok(parent.includes('assertCombinedBrokerReceipt(broker.calls(),broker.received)'));
  assert.ok(parent.includes("proc.kill('SIGKILL')"));
  noBypass(child);noBypass(parent);
});

test('combined shell addition leaves every previous physical assertion byte-identical',()=>{
  const start=shell.indexOf('# BEGIN stable combined mTLS');
  const endMarker='# END stable combined; SSL reset to off has been independently read back.\n\n';
  const end=shell.indexOf(endMarker,start);
  assert.ok(start>0&&end>start);
  const original=Buffer.from(shell.slice(0,start)+shell.slice(end+endMarker.length));
  assert.equal(combinedHash('sha1').update('blob '+original.length+'\0').update(original).digest('hex'),
    '09ae6983e3f87df3edd20d957a08f0b2706edb46');
  assert.ok(shell.includes('SAAS_B16_STABLE_144_COMBINED_CI=true'));
  assert.ok(shell.includes('grep -Fxc "$marker" /tmp/b16-stable144-combined-ci.log'));
  for(const marker of COMBINED_MARKERS)assert.ok(shell.includes(marker),marker);
  assert.ok(start<shell.indexOf('# Newly isolated native verify-full'));
});

test('combined source and docs rerun physical, canary, stable and source-repro checks',()=>{
  const inputs=['scripts/saas-staging/backend16-stable-144-combined-contract.mjs',
    'scripts/saas-staging/verify-backend16-stable-144-combined-ci.ts',
    'scripts/saas-staging/backend16-stable-144-combined-child.ts',
    'docs/saas/BACKEND_16_P1_STABLE_144_COMBINED_MTLS_PG16.md'];
  for(const file of ['saas-backend16-native-tls-experiment.yml',
    'saas-backend16-native-source-repro-ci.yml','saas-backend16-stable-144-tls-ci.yml']){
    const flow=read('../.github/workflows/'+file);
    for(const p of inputs)assert.ok(flow.includes("      - '"+p+"'"),p);
  }
  for(const p of ['scripts/saas-staging/**','docs/saas/**',
    'tests/saasBackend16Stable144FullPhysicalCi.test.mjs'])
    assert.ok(workflow.includes("      - '"+p+"'"),p);
});

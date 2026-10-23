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
    'pg_backend_pid()',
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

import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {
  B16_OFFICIAL_STABLE_144,
  assertBackend16OfficialStable144CandidatePin,
  verifyBackend16OfficialStable144Archive,
  enforceBackend16OfficialStable144CiEnvironment,
  assertBackend16OfficialStable144Redirect,
} from '../scripts/saas-staging/install-backend16-official-stable-144-ci.mjs';

const read=path=>readFileSync(new URL(path,import.meta.url),'utf8');
const refuse=fn=>assert.throws(fn,/Backend16 official stable Bun144 disposable CI refused/);
const HEAD='a'.repeat(40),EVENT='b'.repeat(40);
const E={
  CI:'true',GITHUB_ACTIONS:'true',SAAS_B16_STABLE_144_CI:'true',
  GITHUB_EVENT_NAME:'pull_request',
  GITHUB_REPOSITORY:'Bagirov24/Cli-Proxy-API-Management-Center',
  GITHUB_REF:'refs/pull/103/merge',GITHUB_SHA:EVENT,
  B16_PR_HEAD_SHA:HEAD,RUNNER_OS:'Linux',RUNNER_ARCH:'X64',
  RUNNER_TEMP:'/home/runner/work/_temp',
  GITHUB_ENV:'/home/runner/work/_temp/_runner_file_commands/set_env_01234567-aaaa-bbbb-cccc-123456789abc',
  PGHOST:'127.0.0.1',PGPORT:'5432',
  PGUSER:'postgres',PGDATABASE:'saas_ephemeral_test',
  PGPASSWORD:'ci_ephemeral_test_only',
};
const scriptPath='../scripts/saas-staging/install-backend16-official-stable-144-ci.mjs';
const stableTlsPath='../scripts/saas-staging/verify-backend16-official-stable-144-tls-ci.ts';
const nativePath='../scripts/saas-staging/verify-backend16-native-tls-version-probe-ci.ts';

test('published stable Bun v1.4.4 GitHub release/tag/asset pins are immutable but not approvals',()=>{
  const pin=B16_OFFICIAL_STABLE_144;
  assert.ok(Object.isFrozen(pin));
  assert.equal(pin.tag,'bun-v1.4.4');
  assert.equal(pin.version,'1.4.4');
  assert.equal(pin.fullRevision,'38afee6c84fcf48c0edb2466aa4b27d287a59c30');
  assert.equal(pin.cliRevision,'1.4.4+38afee6c8');
  assert.equal(pin.filename,'bun-linux-x64.zip');
  assert.equal(pin.archiveSize,51794595);
  assert.equal(pin.archiveSha256,
    'bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c');
  assert.equal(pin.url,
    'https://github.com/oven-sh/bun/releases/download/bun-v1.4.4/bun-linux-x64.zip');
  assert.equal(assertBackend16OfficialStable144CandidatePin({...pin}),true);
  assert.equal(Object.hasOwn(pin,'stableRuntimeApproved'),false);
});

test('reject unreviewed versions, canary, floating release URLs and mismatched pins',()=>{
  for(const update of [
    {tag:'bun-v1.4.3'},{tag:'canary'},{tag:'bun-v1.4.5'},
    {version:'1.4.4-canary.1'},{version:'1.4.3'},
    {fullRevision:'6bb5dc1956505dd1113455f58d4757c924f3ad54'},
    {fullRevision:'0'.repeat(40)},
    {cliRevision:'1.4.4+6bb5dc195'},
    {archiveSha256:'a'.repeat(64)},
    {archiveSize:51794594},{archiveSize:0},{archiveSize:NaN},
    {filename:'bun-linux-x64-baseline.zip'},
    {url:B16_OFFICIAL_STABLE_144.url+'?download=1'},
    {url:'http://github.com/oven-sh/bun/releases/download/bun-v1.4.4/bun-linux-x64.zip'},
    {url:'https://github.com.evil.test/oven-sh/bun/releases/download/bun-v1.4.4/bun-linux-x64.zip'},
    {productionAuthorized:true},
  ])refuse(()=>assertBackend16OfficialStable144CandidatePin(
    {...B16_OFFICIAL_STABLE_144,...update}));
  refuse(()=>assertBackend16OfficialStable144CandidatePin(null));
  refuse(()=>assertBackend16OfficialStable144CandidatePin([]));
  refuse(()=>assertBackend16OfficialStable144CandidatePin(
    Object.create(B16_OFFICIAL_STABLE_144)));
});

test('archive SHA256 is checked on actual bytes, not a version string',()=>{
  refuse(()=>verifyBackend16OfficialStable144Archive(new Uint8Array(0)));
  refuse(()=>verifyBackend16OfficialStable144Archive(undefined));
  refuse(()=>verifyBackend16OfficialStable144Archive(new ArrayBuffer(4)));
  const forged=Buffer.alloc(B16_OFFICIAL_STABLE_144.archiveSize,0x55);
  refuse(()=>verifyBackend16OfficialStable144Archive(forged));
  refuse(()=>verifyBackend16OfficialStable144Archive(forged.subarray(1)));
  forged[0]^=1;
  refuse(()=>verifyBackend16OfficialStable144Archive(forged));
});

test('CI context refuses local, production, platform drift and secret-bearing environments',()=>{
  assert.equal(enforceBackend16OfficialStable144CiEnvironment(E,24,'linux','x64'),true);
  for(const [key,value] of Object.entries({
    CI:'false',GITHUB_ACTIONS:'false',SAAS_B16_STABLE_144_CI:'false',
    GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'another/repo',
    GITHUB_REF:'refs/heads/main',GITHUB_SHA:'bad',B16_PR_HEAD_SHA:'bad',
    RUNNER_OS:'Windows',RUNNER_ARCH:'ARM64',
    NODE_ENV:'production',NODE_TLS_REJECT_UNAUTHORIZED:'0',
    PGHOST:'production.private',PGPORT:'5433',PGUSER:'prod',
    PGDATABASE:'real',PGPASSWORD:'secret',
    DATABASE_URL:'postgres://live/db',RAILWAY_PROJECT_ID:'live',
    SAAS_B16_NATIVE_BUN_BIN:'/usr/bin/bun',SAAS_B16_LOCKED_FULL_CHAIN_CI:'true',
    GITHUB_ENV:'/tmp/unsafe',RUNNER_TEMP:'relative',
  }))refuse(()=>enforceBackend16OfficialStable144CiEnvironment(
    {...E,[key]:value},24,'linux','x64'));
  for(const [major,os,arch] of [
    [23,'linux','x64'],[24,'darwin','x64'],
    [24,'linux','arm64'],[25,'linux','x64'],
  ])refuse(()=>enforceBackend16OfficialStable144CiEnvironment(E,major,os,arch));
});

test('HTTP redirects must use explicit GitHub-owned HTTPS release CDN hosts',()=>{
  const start=B16_OFFICIAL_STABLE_144.url;
  assert.equal(assertBackend16OfficialStable144Redirect(
    start,'https://release-assets.githubusercontent.com/asset?token=a'),
    'https://release-assets.githubusercontent.com/asset?token=a');
  for(const url of [
    'http://release-assets.githubusercontent.com/asset',
    'https://release-assets.githubusercontent.com.evil.example/asset',
    'https://registry.npmjs.org/evil','https://github.com:444/asset',
    'https://evil@github.com/asset','https://github.com/asset#fragment',
    '//evil.example/redirect','javascript:alert(1)','ftp://github.com/file',
  ])refuse(()=>assertBackend16OfficialStable144Redirect(start,url));
});

test('stable same-socket TLS probe is byte-identical to canary negatives',()=>{
  const stable=read(stableTlsPath),canary=read(nativePath);
  const normalized=stable.replace(
    '38afee6c84fcf48c0edb2466aa4b27d287a59c30',
    '6bb5dc1956505dd1113455f58d4757c924f3ad54'
  ).replace('SAAS_B16_STABLE_144_PROBE_CI','SAAS_B16_EXPERIMENTAL_TLS_CI');
  assert.equal(normalized,canary,
    'physical TLS negative tests must not be deleted, skipped or weakened');
  for(const marker of [
    'B16_PINNED_NATIVE_ONE_ARG_ALWAYS_DENY_',
    'B16_PINNED_NATIVE_TWO_ARG_URL_ALWAYS_DENY_',
    'B16_PINNED_NATIVE_TLS_WRONG_ROOT_',
    'B16_PINNED_NATIVE_TLS_WILDCARD_',
    'B16_PINNED_NATIVE_EXPLICIT_TLS_DISABLE_',
    'B16_PINNED_NATIVE_TLS_AUTHENTICATED_POSITIVE',
    'pg_backend_pid()','Bun.revision',
  ])assert.ok(stable.includes(marker),marker);
});

test('stable workflow checks out exact PR head and exercises real PG16 TLS',()=>{
  const yml=read('../.github/workflows/saas-backend16-stable-144-tls-ci.yml');
  for(const expected of [
    'on:\n  pull_request:\n    paths:',
    'permissions:\n  contents: read',
    'runs-on: ubuntu-24.04','image: postgres:16.6',
    "node-version: '24'",'persist-credentials: false',
    'ref: $'+'{{ github.event.pull_request.head.sha }}',
    'B16_PR_HEAD_SHA: $'+'{{ github.event.pull_request.head.sha }}',
    'node --test tests/saasBackend16OfficialStable144Ci.test.mjs',
    'node scripts/saas-staging/install-backend16-official-stable-144-ci.mjs',
    '"$'+'{SAAS_B16_STABLE_144_BIN:?stable candidate binary required}" scripts/saas-staging/verify-backend16-official-stable-144-tls-ci.ts',
    'SAAS_B16_CI_PG_CONTAINER: $'+'{{ job.services.postgres.id }}',
    "SAAS_B16_STABLE_144_CI: 'true'",
    "SAAS_B16_STABLE_144_PROBE_CI: 'true'",
  ])assert.ok(yml.includes(expected),expected);
  assert.doesNotMatch(yml,/continue-on-error:|expected-failure:|productionAuthorized:\s*true/);
});

test('stable changes trigger existing canary, full PG16, and source cross-runner',()=>{
  const paths=[
    '.github/workflows/saas-backend16-stable-144-tls-ci.yml',
    'scripts/saas-staging/install-backend16-official-stable-144-ci.mjs',
    'scripts/saas-staging/verify-backend16-official-stable-144-tls-ci.ts',
    'tests/saasBackend16OfficialStable144Ci.test.mjs',
    'docs/saas/BACKEND_16_P1_STABLE_144_TLS_CANDIDATE.md',
  ];
  for(const flow of [
    read('../.github/workflows/saas-backend16-stable-144-tls-ci.yml'),
    read('../.github/workflows/saas-backend16-native-tls-experiment.yml'),
    read('../.github/workflows/saas-staging-rls-ci.yml'),
    read('../.github/workflows/saas-backend16-native-source-repro-ci.yml'),
  ]){
    for(const path of paths)assert.ok(
      flow.includes("      - '"+path+"'"),'missing trigger '+path);
    assert.doesNotMatch(flow,/continue-on-error:|expected-failure:/);
  }
  assert.equal(JSON.parse(read('../package.json')).packageManager,'bun@1.3.14');
  assert.ok(read(
    '../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts'
  ).includes('const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
});

test('untrusted direct installer invocation fails before any network or binary execution',()=>{
  const file=fileURLToPath(new URL(scriptPath,import.meta.url));
  const result=spawnSync(process.execPath,[file],{
    encoding:'utf8',timeout:5_000,
    env:{...process.env,CI:'false',GITHUB_ACTIONS:'false',
      SAAS_B16_STABLE_144_CI:'false'},
  });
  assert.equal(result.status,1);
  assert.equal(result.stdout,'');
  assert.match(result.stderr,/STOP Backend16 official stable Bun144 disposable CI refused/);
  const src=read(scriptPath);
  const checksum=src.indexOf('verifyBackend16OfficialStable144Archive(bytes);');
  const unpack=src.indexOf('extractPinnedBinary(archive,dir);');
  const execution=src.indexOf('verifyRuntime(binary);');
  assert.ok(checksum>0&&unpack>checksum&&execution>unpack);
  assert.ok(src.includes("redirect:'manual'"));
  assert.ok(src.includes('B16_OFFICIAL_STABLE_144_NOT_APPROVED_FOR_RELEASE'));
  assert.doesNotMatch(src,/NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0|NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=true/);
});

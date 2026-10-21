import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const read=(path:string)=>readFileSync(new URL(path,import.meta.url),'utf8');
const adr=read('../docs/saas/BACKEND_16_P1_NATIVE_BUN_SQL_ADR.ru.md');
const roadmap=read('../docs/saas/BACKEND_16_DELIVERY_ROADMAP.ru.md');
const nativeDoc=read('../docs/saas/BACKEND_16_NATIVE_BUN_SQL_TLS_E2E.md');
const nativePool=read(
  '../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts');
const nodeComparator=read(
  '../src/features/saasBlueprint/controlApi/server/backend16DisposableNodePgPhysicalPool.ts');
const nativeInstaller=read(
  '../scripts/saas-staging/install-backend16-native-bun-ci.mjs');
const nativePhysical=read(
  '../scripts/saas-staging/verify-backend16-native-pg-tls-ci.ts');
const nativeProbe=read(
  '../scripts/saas-staging/verify-backend16-native-tls-version-probe-ci.ts');
const packageJson=JSON.parse(read('../package.json'));

test('P1 target is Native Bun.SQL, never a runtime release approval',()=>{
  const from='<!-- BEGIN BACKEND16 P1 RUNTIME DECISION -->';
  const to='<!-- END BACKEND16 P1 RUNTIME DECISION -->';
  assert.equal(adr.split(from).length,2);
  assert.equal(adr.split(to).length,2);
  const tick=String.fromCharCode(96);
  const rows=adr.split(from)[1].split(to)[0].split('\n')
    .filter(line=>line.startsWith('| '))
    .slice(2)
    .map(line=>{
      const parts=line.split('|').slice(1,-1).map(cell=>
        cell.trim().replaceAll(tick,''));
      assert.equal(parts.length,2);
      return parts;
    });
  assert.deepEqual(rows,[
    ['Целевой physical PostgreSQL transport','Native Bun.SQL'],
    ['Статус архитектуры','ARCHITECTURE_SELECTED_RELEASE_BLOCKED'],
    ['Роль Node24 pg','CI_ONLY_COMPARATOR_NOT_PRODUCTION_FALLBACK'],
    ['Одобренный stable runtime','NONE'],
    ['Проверенный live operator trust','LIVE_UNVERIFIED'],
    ['Release hard stop','NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false'],
  ]);
  assert.ok(roadmap.includes(
    '### P1. Native Bun.SQL выбран — ARCHITECTURE_SELECTED_RELEASE_BLOCKED'));
  assert.ok(roadmap.includes('BACKEND_16_P1_NATIVE_BUN_SQL_ADR.ru.md'));
  assert.ok(nativeDoc.includes('BACKEND_16_P1_NATIVE_BUN_SQL_ADR.ru.md'));
  assert.ok(roadmap.includes('P0 → P1 → P2'));
});

test('Native Bun remains blocked; no CI canary-to-stable promotion',()=>{
  assert.equal(packageJson.packageManager,'bun@1.3.14');
  assert.ok(nativePool.includes(
    'const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
  assert.ok(nativeInstaller.includes("version:'1.4.3-canary.20261019.1'"));
  assert.ok(nativeInstaller.includes(
    "revision:'6bb5dc1956505dd1113455f58d4757c924f3ad54'"));
  assert.ok(nativeInstaller.includes(
    "console.info('B16_NATIVE_BUN_ARCHIVE_SHA512_VERIFIED')"));
  for(const doc of [adr,roadmap,nativeDoc]){
    assert.ok(doc.includes('NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false'));
    assert.ok(doc.toLowerCase().includes('ci-only'));
  }
  assert.ok(adr.includes('BLOCKED_RELEASE'));
  assert.ok(adr.includes('1.4.4-canary.1+6bb5dc195'));
  assert.ok(roadmap.includes('bun@1.3.14'));
});

test('the chosen native transport keeps genuine physical TLS negatives',()=>{
  for(const fragment of [
    'B16_NATIVE_SQL_TLS_ALWAYS_DENY_CALLBACK_',
    'B16_NATIVE_SQL_TLS_WRONG_ROOT_',
    'B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_',
    'B16_NATIVE_SQL_TLS_REAL_PID_VERIFIED',
    'B16_NATIVE_SQL_TLS_TWO_TENANT_RLS_PASS',
    'PASS Backend16 native Bun.SQL TLS to real disposable PG16',
  ])assert.ok(nativePhysical.includes(fragment),'missing physical TLS: '+fragment);
  for(const fragment of [
    'B16_PINNED_NATIVE_ONE_ARG_ALWAYS_DENY_',
    'B16_PINNED_NATIVE_TWO_ARG_URL_ALWAYS_DENY_',
    'B16_PINNED_NATIVE_TLS_WRONG_ROOT_',
    'B16_PINNED_NATIVE_TLS_WILDCARD_',
  ])assert.ok(nativeProbe.includes(fragment),'missing independent TLS: '+fragment);
  for(const phrase of ['always-deny','wrong-root','wildcard','same-socket'])
    assert.ok(adr.includes(phrase),'missing Native gate: '+phrase);
});

test('Node pg remains separate CI comparator, not automatic runtime fallback',()=>{
  assert.ok(nodeComparator.includes('CI-ONLY node-postgres'));
  assert.ok(adr.includes('CI_ONLY_COMPARATOR_NOT_PRODUCTION_FALLBACK'));
  assert.ok(roadmap.includes('CI-only security comparator'));
  assert.ok(roadmap.includes('production fallback'));
  assert.ok(adr.includes('не является production fallback'));
  for(const forbiddenOperation of ['GitHub Releases','SQL0008','Core/Gateway'])
    assert.ok(adr.includes(forbiddenOperation));
});

test('P1 decision updates trigger independent physical Native TLS CI',()=>{
  const workflow=read(
    '../.github/workflows/saas-backend16-native-tls-experiment.yml');
  for(const path of [
    'docs/saas/BACKEND_16_P1_NATIVE_BUN_SQL_ADR.ru.md',
    'docs/saas/BACKEND_16_DELIVERY_ROADMAP.ru.md',
    'docs/saas/BACKEND_16_NATIVE_BUN_SQL_TLS_E2E.md',
    'tests/saasBackend16NativeBunSqlDecision.test.ts',
    'src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts',
  ])assert.ok(workflow.includes("      - '"+path+"'"),
    'missing independent Native TLS trigger: '+path);
  assert.ok(workflow.includes('runs-on: ubuntu-24.04'));
  assert.ok(workflow.includes(
    'node --experimental-strip-types --test tests/saasBackend16NativeBunSqlDecision.test.ts'));
  assert.ok(workflow.includes(
    'scripts/saas-staging/verify-backend16-native-tls-version-probe-ci.ts'));
  assert.ok(workflow.includes('contents: read'));
  assert.doesNotMatch(workflow,/continue-on-error:|expected-failure:/);
});

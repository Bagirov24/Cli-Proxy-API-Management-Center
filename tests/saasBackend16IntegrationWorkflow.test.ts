import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {parse} from 'yaml';

test('combined Backend16 workflow preserves independent security test coverage',()=>{
  const workflow=parse(readFileSync(new URL(
    '../.github/workflows/saas-backend16-private-read-contract.yml',import.meta.url),
  'utf8'),{uniqueKeys:true});
  const steps=workflow.jobs['private-read-contract'].steps as Array<{run?:string}>;
  const commands=steps.map(step=>step.run??'').join('\n');
  for(const file of [
    'saasBackend16PrivateTenantProjectRead',
    'saasBackend16PinnedSessionAuthenticator',
    'saasBackend16PhysicalPgAdmission',
    'saasBackend16ExactSessionGate',
    'saasBackend16ExactSessionSqlRead',
    'saasBackend16CiBunPhysicalPgPool',
    'saasBackend16StagingBunPhysicalPgPool',
    'saasBackend16StagingPgTlsTrust',
    'saasBackend16TlsPeerProbe',
    'saasBackend16ReleaseEvidenceGate',
    'saasBackend16StagingVersionedPrincipalVault',
    'saasBackend16PrivateMtlsVersionedSecretReader',
    'saasBackend16Sql0008ReadOnlyReconcile',
  ])assert.ok(commands.includes(`tests/${file}.test.ts`),file);
  for(const runner of [
    'verify-backend16-mtls-secret-broker-ci.ts',
    'verify-backend16-verified-private-pg-tls-ci.ts',
    'verify-backend16-bun-tls-client-ci.ts',
  ])assert.ok(commands.includes(runner),runner);
  assert.equal(workflow.permissions.contents,'read');
});

test('full physical Backend16 PG16 acceptance reruns for transport and trust changes',()=>{
  const workflow=parse(readFileSync(new URL(
    '../.github/workflows/saas-staging-rls-ci.yml',import.meta.url),
  'utf8'),{uniqueKeys:true});
  const paths=workflow.on.pull_request.paths as string[];
  assert.ok(Array.isArray(paths),'pull_request.paths must be present');
  const server='src/features/saasBlueprint/controlApi/server/';
  for(const path of [
    'package.json','bun.lock',
    ...[
      'backend16StagingBunPhysicalPgPool.ts',
      'backend16StagingPgTlsTrust.ts',
      'backend16DisposableNodePgPhysicalPool.ts',
      'backend16StagingVersionedPrincipalVault.ts',
      'backend16PrivateMtlsVersionedSecretReader.ts',
      'backend16PinnedSessionAuthenticator.ts',
      'backend16PrivateTenantProjectRead.ts',
      'backend16VerifiedPrivatePgTls.ts',
    ].map(file=>server+file),
    'tests/saasBackend16StagingBunPhysicalPgPool.test.ts',
    'tests/saasBackend16DisposableNodePgPhysicalPool.test.ts',
    'tests/saasBackend16StagingPgTlsTrust.test.ts',
    'scripts/saas-staging/**',
    '.github/workflows/saas-staging-rls-ci.yml',
  ]){
    assert.ok(paths.includes(path),'missing physical PG16 PR trigger: '+path);
  }
  assert.equal(workflow.permissions.contents,'read');
  assert.ok(Object.hasOwn(workflow.on,'workflow_dispatch'));
});

test('disposable physical PG16 and Playwright jobs use compatible explicit runner tools',()=>{
  const pg=parse(readFileSync(new URL(
    '../.github/workflows/saas-staging-rls-ci.yml',import.meta.url),
  'utf8'),{uniqueKeys:true});
  assert.equal(pg.jobs['tenant-rls']['runs-on'],'ubuntu-24.04');
  assert.equal(pg.jobs['tenant-rls'].services.postgres.image,'postgres:16.6');
  const steps=pg.jobs['tenant-rls'].steps as Array<{name?:string;run?:string}>;
  const setup=steps.find(s=>s.name==='Pin PostgreSQL 16 client for real PG16 backup and restore');
  assert.ok(setup?.run,'PostgreSQL 16 client setup must run before any PG commands');
  const pg16=setup.run;
  for(const invariant of [
    'postgresql-client-16',
    '/usr/lib/postgresql/16/bin',
    'for tool in psql pg_dump pg_restore createdb dropdb',
    'grep -Eq',
    'echo "$bin" >> "$GITHUB_PATH"',
    'export PATH="$bin:$PATH"',
    'test "$(command -v pg_dump)" = "$bin/pg_dump"',
    'test "$(command -v pg_restore)" = "$bin/pg_restore"',
  ])assert.ok(pg16.includes(invariant),'missing PG16 toolchain guard: '+invariant);
  assert.ok(steps.indexOf(setup)<steps.findIndex(s=>s.name?.includes('legacy tenant RLS')),
    'PG16 client version proof must precede PG16 acceptance');
  const browser=parse(readFileSync(new URL(
    '../.github/workflows/saas-blueprint-browser-ci.yml',import.meta.url),
  'utf8'),{uniqueKeys:true});
  assert.equal(browser.jobs.browser['runs-on'],'ubuntu-24.04');
  const browserCommands=(browser.jobs.browser.steps as Array<{run?:string}>)
    .map(step=>step.run??'').join('\n');
  assert.ok(browserCommands.includes('playwright==1.55.0'));
  assert.ok(browserCommands.includes('playwright install --with-deps chromium'));
  assert.equal(browser.permissions.contents,'read');
});

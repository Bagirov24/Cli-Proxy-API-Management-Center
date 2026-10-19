import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';

const source=readFileSync(new URL(
  '../scripts/saas-staging/backend16-railway-readonly-preflight.ts',
  import.meta.url),'utf8');
const reconcile=readFileSync(new URL(
  '../scripts/saas-staging/backend16-0008-readonly-reconcile.sql',
  import.meta.url),'utf8');

test('Railway read-only function embeds exactly the immutable verified SQL DO block',()=>{
  const m=source.match(/^const RECONCILE_DO_SQL=(.+);$/m);
  assert.ok(m,'single JSON-escaped constant');
  const expected=reconcile.match(/DO \$b16_readonly\$[\s\S]*?\$b16_readonly\$;/);
  assert.ok(expected,'authoritative PostgreSQL16 reconcile body');
  assert.equal(JSON.parse(m[1]),expected[0],
    'any change to SQL checks must be independently reviewed');
  assert.match(expected[0],/saas_bootstrap\.schema_migrations/);
  assert.match(expected[0],/pg_catalog\.pg_authid/);
  assert.match(expected[0],/B16_READONLY_STOP_FORCE_RLS/);
  assert.match(expected[0],/B16_READONLY_STOP_SQL0008_FUNCTION_DRIFT/);
});
test('read-only PostgreSQL transaction, exact INSTALLED operator expectation and no retry',()=>{
  const index=(s:string)=>source.indexOf(s);
  assert.ok(index("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")>=0);
  assert.ok(index('RECONCILE_DO_SQL,[]')>
            index("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"));
  assert.ok(index("connection.unsafe('COMMIT',[])")>index('RECONCILE_DO_SQL,[]'));
  assert.ok(index('console.info(MARKER)')>index("connection.unsafe('COMMIT',[])"));
  assert.ok(index('if(failed||!closed||EXPECTED')>index("connection.unsafe('COMMIT',[])"));
  assert.match(source,/commitSent=true/);
  assert.match(source,/if\(transaction&&!commitSent&&connection\)/);
  assert.match(source,/const EXPECTED='installed'/);
  assert.match(source,/saas\.b16\.reconcile_expected','installed',true/);
  assert.match(source,/set_config\('saas\.staging_only','true',true\)/);
  assert.ok(index("set_config('saas.staging_only','true',true)")>
            index("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"));
  assert.ok(index("set_config('saas.staging_only','true',true)")<
            index('RECONCILE_DO_SQL,[]'));

  assert.match(source,/READONLY_INSTALLED_SEALED/);
  assert.match(source,/failurePhase=phase/);
  assert.match(source,/failurePhase='CLOSE'/);
  assert.match(source,/B16_READONLY_PREFLIGHT_STOP_PHASE_/);
  assert.match(source,/catalogStopCode=candidate/);
  assert.match(source,/catalogStopCode\?\?'UNSPECIFIED'/);
  assert.doesNotMatch(source,/console\.(?:error|log|warn)\(error\)/);

  assert.match(source,/if\(failed\|\|!closed\|\|EXPECTED!=='installed'\)/);
  assert.doesNotMatch(source,/throw Error\('B16_READONLY_PREFLIGHT_FAILED/);

  assert.doesNotMatch(source,/retry\s*\(/);
  assert.doesNotMatch(source,/Bun\.serve|createServer|listen\(/);
});
test('context pins private PostgreSQL16 with no public proxy, credentials or logs',()=>{
  for(const v of [
    'RAILWAY_PROJECT_ID','RAILWAY_ENVIRONMENT_ID',
    'RAILWAY_ENVIRONMENT_NAME','RAILWAY_SERVICE_NAME','RAILWAY_SERVICE_ID',
    'SAAS_B16_READONLY_PREFLIGHT_EXPLICIT_ENABLE',
    "uri.hostname!=='postgres.railway.internal'",
    "uri.pathname!=='/saas_staging'",
    "decodeURIComponent(uri.username)!=='postgres'",
    "uri.port!=='5432'","uri.search||uri.hash",
    "tls:'require'","max:1,connectionTimeout:4",
    "connection?.release()","pool.close({timeout:0})",
  ])assert.ok(source.includes(v),v);
  assert.doesNotMatch(source,/DATABASE_PUBLIC_URL|RAILWAY_TCP_PROXY|setInterval|cronSchedule/);
  const withoutDo=source.replace(/^const RECONCILE_DO_SQL=.+;$/m,'');
  assert.doesNotMatch(withoutDo,/\b(?:ALTER\s+ROLE|CREATE\s+ROLE|DROP\s+ROLE|CREATE\s+TABLE|INSERT\s+INTO|DELETE\s+FROM)\b/i);
  assert.doesNotMatch(source,/console\.(?:log|info|error)\s*\(\s*(?:password|uri|e\.)/);
});

// Real Bun process: an unenabled Railway Function must exit cleanly without
// probing the private database, leaking credentials, or emitting PASS.
test('disabled Railway staging read-only Function exits without DB or retries',()=>{
  const file=new URL('../scripts/saas-staging/backend16-railway-readonly-preflight.ts',
    import.meta.url);
  const env={
    RAILWAY_PROJECT_ID:'a9703851-6eb1-406c-bb15-7d3a89359fb7',
    RAILWAY_ENVIRONMENT_ID:'b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b',
    RAILWAY_ENVIRONMENT_NAME:'staging',
    RAILWAY_SERVICE_NAME:'saas-b16-0008-readonly-preflight',
    RAILWAY_SERVICE_ID:'ff2df1d3-3bca-483c-bc2a-0edea01dd3f1',
    SAAS_B16_READONLY_PREFLIGHT_EXPLICIT_ENABLE:'false',
    GITHUB_ACTIONS:'false',
  };
  const child=spawnSync(process.execPath,[file.pathname],{
    encoding:'utf8',timeout:8000,env,
  });
  assert.equal(child.status,0,String(child.stderr).slice(-500));
  assert.match(child.stdout,/B16_READONLY_PREFLIGHT_DISABLED_NO_DATABASE/);
  assert.doesNotMatch(child.stdout,/PASS_BACKEND16/);
  assert.doesNotMatch(child.stdout+child.stderr,/password|DATABASE_URL|PGPASSWORD/i);
});


test('post-install staging runner cannot revert to a seven-receipt ABSENT success',()=>{
  const withoutImmutableSql=source.replace(/^const RECONCILE_DO_SQL=.+;$/m,'');
  assert.match(withoutImmutableSql,/const EXPECTED='installed'/);
  assert.match(withoutImmutableSql,
    /const MARKER='PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED'/);
  assert.match(withoutImmutableSql,/reconcile_expected','installed',true/);
  assert.doesNotMatch(withoutImmutableSql,
    /PASS_BACKEND16_SQL0008_READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL/);
  assert.doesNotMatch(withoutImmutableSql,/const EXPECTED='absent'/);
  assert.match(source,/BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY/);
  assert.doesNotMatch(withoutImmutableSql,/(?:ALTER ROLE|CREATE FUNCTION|INSERT INTO|DELETE FROM|UPDATE saas_)/i);
});


test('wrong Railway staging Function ID is refused before opening a database socket',()=>{
  const file=new URL('../scripts/saas-staging/backend16-railway-readonly-preflight.ts',
    import.meta.url);
  const syntheticUrl='postgres://postgres:SYNTHETIC_TEST_PASSWORD@public.example:5432/saas_staging';
  const child=spawnSync(process.execPath,[file.pathname],{
    encoding:'utf8',timeout:8000,env:{
      RAILWAY_PROJECT_ID:'a9703851-6eb1-406c-bb15-7d3a89359fb7',
      RAILWAY_ENVIRONMENT_ID:'b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b',
      RAILWAY_ENVIRONMENT_NAME:'staging',
      RAILWAY_SERVICE_NAME:'saas-b16-0008-readonly-preflight',
      RAILWAY_SERVICE_ID:'00000000-0000-0000-0000-000000000000',
      SAAS_B16_READONLY_PREFLIGHT_EXPLICIT_ENABLE:'true',
      STAGING_POSTGRES_PRIVATE_URL:syntheticUrl,
      GITHUB_ACTIONS:'false',
    },
  });
  assert.notEqual(child.status,0);
  const output=child.stdout+child.stderr;
  assert.match(output,/B16_READONLY_PREFLIGHT_STOP_NO_DATABASE_WRITES/);
  assert.doesNotMatch(output,/PASS_BACKEND16|SYNTHETIC_TEST_PASSWORD|public\.example/);
});

test('public PostgreSQL hostname is rejected even with exact Railway service ID',()=>{
  const file=new URL('../scripts/saas-staging/backend16-railway-readonly-preflight.ts',
    import.meta.url);
  const child=spawnSync(process.execPath,[file.pathname],{
    encoding:'utf8',timeout:8000,env:{
      RAILWAY_PROJECT_ID:'a9703851-6eb1-406c-bb15-7d3a89359fb7',
      RAILWAY_ENVIRONMENT_ID:'b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b',
      RAILWAY_ENVIRONMENT_NAME:'staging',
      RAILWAY_SERVICE_NAME:'saas-b16-0008-readonly-preflight',
      RAILWAY_SERVICE_ID:'ff2df1d3-3bca-483c-bc2a-0edea01dd3f1',
      SAAS_B16_READONLY_PREFLIGHT_EXPLICIT_ENABLE:'true',
      STAGING_POSTGRES_PRIVATE_URL:
        'postgres://postgres:SYNTHETIC_TEST_PASSWORD@public.example:5432/saas_staging',
      GITHUB_ACTIONS:'false',
    },
  });
  assert.notEqual(child.status,0);
  const output=child.stdout+child.stderr;
  assert.match(output,/B16_READONLY_PREFLIGHT_STOP_NO_DATABASE_WRITES/);
  assert.doesNotMatch(output,/PASS_BACKEND16|SYNTHETIC_TEST_PASSWORD|public\.example/);
});

test('only reviewed SQL catalog STOP codes can reach Railway logs',()=>{
  const capture=source.match(/^const ALLOWED_CATALOG_STOP_MARKERS=new Set\((.+)\);$/m);
  assert.ok(capture);
  const actual=JSON.parse(capture[1]) as string[];
  const expected=[...new Set([...reconcile.matchAll(
    /RAISE EXCEPTION '(B16_READONLY_STOP_[A-Z0-9_]+)'/g,
  )].map(m=>m[1]))].sort();
  assert.deepEqual(actual,expected);
  assert.equal(actual.length,17);
  assert.ok(actual.every(v=>/^B16_READONLY_STOP_[A-Z0-9_]+$/.test(v)));
  assert.match(source,/error\.message\.match\(\/B16_READONLY_STOP_\[A-Z0-9_\]\+\//);
});

test('staging-only context label exactly matches original approved operator PGOPTIONS',()=>{
  const runbook=readFileSync(new URL(
    '../docs/saas/BACKEND_16_SQL0008_READONLY_RECONCILIATION.md',
    import.meta.url),'utf8');
  assert.ok(runbook.includes("PGOPTIONS='-c saas.staging_only=true'"));
  const matched=source.match(/set_config\('saas\.staging_only','true',true\)/g);
  assert.equal(matched?.length,1,
    'one constant LOCAL tag; never derive authorization from client input');
  assert.match(source,/current_setting\('saas\.staging_only'/);
  assert.doesNotMatch(source,/set_config\('saas\.tenant_id'/);
});

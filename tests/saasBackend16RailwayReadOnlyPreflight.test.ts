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
test('read-only PostgreSQL transaction, exact operator expectation and no retry',()=>{
  const index=(s:string)=>source.indexOf(s);
  assert.ok(index("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")>=0);
  assert.ok(index('RECONCILE_DO_SQL,[]')>
            index("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"));
  assert.ok(index("connection.unsafe('COMMIT',[])")>index('RECONCILE_DO_SQL,[]'));
  assert.ok(index('console.info(MARKER)')>index("connection.unsafe('COMMIT',[])"));
  assert.ok(index('if(!closed||EXPECTED')>index("connection.unsafe('COMMIT',[])"));
  assert.match(source,/commitSent=true/);
  assert.match(source,/if\(transaction&&!commitSent&&connection\)/);
  assert.match(source,/const EXPECTED='absent'/);
  assert.match(source,/saas\.b16\.reconcile_expected','absent',true/);
  assert.match(source,/READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL/);
  assert.doesNotMatch(source,/retry\s*\(/);
  assert.doesNotMatch(source,/Bun\.serve|createServer|listen\(/);
});
test('context pins private PostgreSQL16 with no public proxy, credentials or logs',()=>{
  for(const v of [
    'RAILWAY_PROJECT_ID','RAILWAY_ENVIRONMENT_ID',
    'RAILWAY_ENVIRONMENT_NAME','RAILWAY_SERVICE_NAME',
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

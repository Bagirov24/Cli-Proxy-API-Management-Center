import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  createBackend16CiBunPhysicalPgPool,
} from '../src/features/saasBlueprint/controlApi/server/backend16CiBunPhysicalPgPool.ts';

const module=readFileSync(new URL(
  '../src/features/saasBlueprint/controlApi/server/backend16CiBunPhysicalPgPool.ts',
  import.meta.url),'utf8');
const runner=readFileSync(new URL(
  '../scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts',
  import.meta.url),'utf8');
const harness=readFileSync(new URL(
  '../scripts/saas-staging/verify-backend16-exact-session-pg16.sh',
  import.meta.url),'utf8');

test('Bun physical driver constructor never creates real DB outside gated CI',()=>{
  assert.throws(()=>createBackend16CiBunPhysicalPgPool(
    async login=>({username:login,password:'f'.repeat(64)})),
  /limited to disposable GitHub PG16/);
});
test('driver is pinned to exact synthetic CI-only database and physical LOGIN',()=>{
  for(const marker of [
    "const DB='saas_staging_ci'","const HOST='127.0.0.1'",
    "env.GITHUB_ACTIONS!=='true'","env.SAAS_B16_EPHEMERAL_CI!=='true'",
    "env.SAAS_B16_PHYSICAL_CI!=='true'","env.RAILWAY_PROJECT_ID",
    "credentials.username!==login","DENIED_LOGINS.has(login)",
    "login.startsWith('pg_')","max:1,connectionTimeout:4",
    "reserved=await native.reserve({signal})",
    "pg_catalog.set_config('saas.staging_only','true',false)",
    "ALLOWED=new Map<string,number>","ALLOWED.has(sql)",
    "slots>=MAX_ACTIVE","PASSWORD.test(credentials.password)",
  ]) assert.ok(module.includes(marker),marker);
  assert.doesNotMatch(module,/Bun\.serve|createServer|\.listen\(|setInterval|cronSchedule/);
  assert.doesNotMatch(module,/DATABASE_PUBLIC_URL|railway\.internal|custom-no-apikey-fun/);
  assert.doesNotMatch(module,/\b(?:SET\s+ROLE|pg_terminate_backend)\b/i);
});
test('every physical backend is always destroyed, even on cancel/unknown COMMIT',()=>{
  for(const marker of [
    "native.close({timeout:0})","db.close({timeout:0})",
    "function quarantine(","quarantined=true",
    "void native.close({timeout:0}).catch",
    "requestSignal.addEventListener('abort',cancel",
    "quarantine('query-uncertain')",
    "quarantine('release-uncertain')",
    "slots--",
    "active.delete(db)",
  ])assert.ok(module.includes(marker),marker);
  assert.doesNotMatch(module,/\.release\(false\)/);
  assert.doesNotMatch(module,/retry\s*\(/);
});
test('real PG16 harness uses two distinct passworded logins + PID death',()=>{
  for(const marker of [
    'SAAS_B16_PHYSICAL_CI','SAAS_B16_CI_A_PASSWORD',
    'SAAS_B16_CI_B_PASSWORD','SAAS_B16_CI_A_TENANT',
    'SAAS_B16_CI_B_TENANT','SAAS_B16_CI_A_SESSION',
    'SAAS_B16_CI_B_SESSION','SAAS_B16_CI_A_BINDING',
    'SAAS_B16_CI_B_BINDING','PASS Backend16.7:',
    'pg_stat_activity','wait_event_type','FOR UPDATE',
    'createBackend16ExactSqlReadPort','read(a,ta,fresh())',
    'abort.abort()','gone(pid)','forged',
    "username:B,password:approved[B]",
  ])assert.ok(runner.includes(marker),marker);
  assert.ok(harness.includes('bun scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts'));
  assert.ok(harness.indexOf('bun scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts')<
            harness.indexOf('B16_EXACT_LOCK_HELD'));
  assert.doesNotMatch(runner,/DATABASE_PUBLIC_URL|postgres\.railway\.internal/);
  assert.doesNotMatch(runner,/Bun\.serve|createServer/);
});

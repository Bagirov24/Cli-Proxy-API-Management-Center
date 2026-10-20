import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createBackend16DisposableCiNodePgPhysicalPool}
  from '../src/features/saasBlueprint/controlApi/server/backend16DisposableNodePgPhysicalPool.ts';

const filename=new URL(
  '../src/features/saasBlueprint/controlApi/server/backend16DisposableNodePgPhysicalPool.ts',
  import.meta.url);
const source=readFileSync(filename,'utf8');
const vault={async readPrincipal(login:string){
  return {username:login,password:'x'.repeat(64)};
}};
class ClientFixture{
  constructor(_opts:Readonly<Record<string,unknown>>){}
  async connect(){throw Error('must never construct outside disposable CI');}
  async query(_sql:string,_params:readonly string[]=[]){
    return {rows:[]};
  }
  async end(){}
  on(_ev:'error',_cb:()=>void){}
}

test('Node PG physical factory cannot run outside disposable GitHub PG16',()=>{
  assert.throws(()=>createBackend16DisposableCiNodePgPhysicalPool(
    vault,null as never,ClientFixture),
    /Backend16 Node PostgreSQL physical TLS unavailable/);
});
test('Node PG uses reviewed TLS callback, no plaintext or shared LOGIN',()=>{
  for(const required of [
    "e.GITHUB_ACTIONS!=='true'",
    "e.SAAS_B16_EPHEMERAL_CI!=='true'",
    "e.SAAS_B16_NODEPG_PHYSICAL_CI!=='true'",
    "e.PGHOST!=='127.0.0.1'",
    "e.PGDATABASE!=='saas_ephemeral_test'",
    "e.NODE_TLS_REJECT_UNAUTHORIZED==='0'",
    'backend16IsApprovedStagingPgTlsTrust(trust)',
    "servername:HOST,rejectUnauthorized:true",
    'checkServerIdentity:(hostname:string,cert:unknown)',
    'return trust.checkServerIdentity(hostname,cert)',
    'vault.readPrincipal(login,signal)',
    'credential.username!==login',
    'client.connection?.stream?.destroy()',
    'quarantine(\'query-uncertain\')',
    'AbortSignal.timeout(6500)',
    'SQL.exact,4',
    'SQL.commit,0',
    "application_name:'b16-nodepg-exact-ci'",
    "options:'-c saas.staging_only=true'",
  ])assert.ok(source.includes(required),required);
  assert.doesNotMatch(source,/Bun\.serve|createServer\(|\.listen\(|DATABASE_PUBLIC_URL/);
  assert.doesNotMatch(source,/tls:'require'|rejectUnauthorized:false/);
  assert.doesNotMatch(source,/SET ROLE|CREATE ROLE|ALTER ROLE|DROP ROLE/i);
});
test('adapter is neither a production staging factory nor a packaged dependency',()=>{
  assert.ok(source.includes('createBackend16DisposableCiNodePgPhysicalPool'));
  assert.doesNotMatch(source,/createBackend16StagingNodePgPhysicalPool/);
  assert.doesNotMatch(source,/import\s+.*\s+from\s+['"]pg['"]/);
  assert.ok(source.includes('const poison=discard||stopped||!steps.finished()'));
});

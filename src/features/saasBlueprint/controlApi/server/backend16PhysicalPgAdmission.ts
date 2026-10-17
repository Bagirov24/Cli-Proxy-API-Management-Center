/**
 * Backend16.3: UNMOUNTED physical PostgreSQL LOGIN + SQL0007 RLS probe.
 * NOT a readAuthorized adapter: a positive result lacks exact sessionId and
 * bindingId DB attestation. Never use it to publish tenant/project data.
 *
 * SQL0007's can_read_tenant() takes FOR SHARE locks. PostgreSQL cannot take
 * these locks in a READ ONLY transaction. Use bounded READ COMMITTED plus
 * least-privilege LOGIN, FORCE RLS and a server-only SELECT allowlist instead.
 */
import type {VerifiedPrincipal} from './backend16PrivateTenantProjectRead';

export type Backend16PgRow=Readonly<Record<string,unknown>>;
export interface Backend16PhysicalPgConnection {
  query(sql:string,params:readonly string[],signal:AbortSignal):
    Promise<{readonly rows:readonly Backend16PgRow[]}>;
  /** discard=true physically terminates this backend; never pool it again. */
  release(discard:boolean):Promise<void>|void;
}
export interface Backend16PhysicalPgPool {
  /** Credentials are resolved ONLY from an operator-owned vault. No SET ROLE. */
  acquirePrincipal(login:string,signal:AbortSignal):
    Promise<Backend16PhysicalPgConnection>;
  /** Synchronously prevents future acquisitions and destroys poisoned clients. */
  quarantine(reason:'acquire-uncertain'|'query-uncertain'|'release-uncertain'):void;
}
export const BACKEND16_PHYSICAL_PG_SQL=Object.freeze({
  begin:'BEGIN ISOLATION LEVEL READ COMMITTED',
  statementTimeout:"SET LOCAL statement_timeout = '5000ms'",
  lockTimeout:"SET LOCAL lock_timeout = '1500ms'",
  identity:'SELECT session_user::text AS session_login, '+
    'current_user::text AS active_role, '+
    'current_database()::text AS database_name, '+
    "current_setting('saas.staging_only',true)::text AS staging_only, "+
    'pg_backend_pid()::int AS backend_pid, '+
    'r.rolcanlogin AS can_login, r.rolsuper AS superuser, '+
    'r.rolbypassrls AS bypass_rls, r.rolcreaterole AS create_role, '+
    'r.rolcreatedb AS create_db, r.rolreplication AS replication, '+
    "pg_has_role(session_user,'saas_runtime_reader','member') AS reader_member "+
    'FROM pg_catalog.pg_roles AS r WHERE r.rolname=session_user',
  // In SQL0007 this SECURITY DEFINER function takes ACL/session/binding
  // FOR SHARE locks until COMMIT; do not convert this to a stale cache.
  acl:'SELECT saas_acl.can_read_tenant($1::uuid) AS allowed',
  tenant:'SELECT tenant_id::text AS tenant_id FROM saas_data.tenants '+
    'WHERE tenant_id=$1::uuid LIMIT 1',
  commit:'COMMIT',
} as const);

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256=/^[0-9a-f]{64}$/;
const LOGIN=/^[a-z][a-z0-9_]{2,62}$/;
const RESERVED=new Set([
  'postgres','saas_schema_migrator','saas_runtime_reader','saas_runtime_writer',
]);
const IDENTITY_KEYS=[
  'active_role','backend_pid','bypass_rls','can_login','create_db',
  'create_role','database_name','reader_member','replication',
  'session_login','staging_only','superuser',
].join(',');
const DENIED=Object.freeze({kind:'denied'} as const);

/** Positive evidence is intentionally NOT compatible with ReaderDecision. */
export type Backend16PgAdmission=typeof DENIED|
  Readonly<{kind:'physical-rls-observed'}>;
export interface Backend16PgAdmissionOptions {
  readonly pool:Backend16PhysicalPgPool;
  readonly expectedDatabase:'saas_staging'|'saas_staging_ci';
  readonly nowMs?:()=>number;
}
function validPrincipal(p:unknown,now:number):p is VerifiedPrincipal{
  if(!p||typeof p!=='object'||!Number.isSafeInteger(now))return false;
  const x=p as Partial<VerifiedPrincipal>;
  return x.kind==='verified-server-session' &&
    typeof x.issuer==='string'&&x.issuer.startsWith('https://') &&
    typeof x.subjectFingerprintSha256==='string' &&
    SHA256.test(x.subjectFingerprintSha256) &&
    typeof x.pgLogin==='string'&&LOGIN.test(x.pgLogin) &&
    !RESERVED.has(x.pgLogin)&&!x.pgLogin.startsWith('pg_') &&
    typeof x.sessionId==='string'&&UUID.test(x.sessionId) &&
    typeof x.bindingId==='string'&&UUID.test(x.bindingId) &&
    typeof x.sessionExpiresAtMs==='number' &&
    Number.isSafeInteger(x.sessionExpiresAtMs) &&
    x.sessionExpiresAtMs>now&&x.sessionExpiresAtMs<=now+900_000;
}
function exactRow(result:unknown,expected:string):Backend16PgRow{
  if(!result||typeof result!=='object'||!('rows' in result)||
     !Array.isArray(result.rows)||result.rows.length!==1) {
    throw new Error('Backend16 PostgreSQL result refused');
  }
  const row=result.rows[0];
  if(!row||typeof row!=='object'||Array.isArray(row)||
     Object.keys(row).sort().join(',')!==expected) {
    throw new Error('Backend16 malformed PostgreSQL row');
  }
  return row as Backend16PgRow;
}
function trustedPhysicalRole(row:Backend16PgRow,login:string,db:string):boolean{
  return row.session_login===login && row.active_role===login &&
    row.database_name===db && row.staging_only==='true' &&
    Number.isSafeInteger(row.backend_pid) &&
    (row.backend_pid as number)>0 && row.can_login===true &&
    row.superuser===false && row.bypass_rls===false &&
    row.create_role===false && row.create_db===false &&
    row.replication===false && row.reader_member===true;
}
function abortable<T>(pending:Promise<T>,signal:AbortSignal):Promise<T>{
  if(signal.aborted)return Promise.reject(new Error('Backend16 cancelled'));
  return new Promise<T>((resolve,reject)=>{
    let done=false;
    const detach=()=>{if(done)return false;done=true;
      signal.removeEventListener('abort',onAbort);return true;};
    const onAbort=()=>{if(detach())reject(new Error('Backend16 cancelled'));};
    signal.addEventListener('abort',onAbort,{once:true});
    if(signal.aborted)onAbort();
    pending.then(value=>{if(detach())resolve(value);},
      error=>{if(detach())reject(error);});
  });
}
async function boundedRelease(promise:Promise<unknown>):Promise<boolean>{
  let timeout:ReturnType<typeof setTimeout>|undefined;
  try{
    await Promise.race([promise,new Promise<never>((_,reject)=>{
      timeout=setTimeout(()=>reject(new Error('Backend16 release timeout')),1200);
    })]);
    return true;
  }catch{return false;}
  finally{if(timeout!==undefined)clearTimeout(timeout);}
}
/**
 * Observes only per-login PG identity + current RLS gate; does NOT verify
 * the exact principal.sessionId/bindingId. A new DB function is required
 * before this can ever be used to construct authorized project DTOs.
 */
export function createBackend16PhysicalPgAdmission(options:Backend16PgAdmissionOptions){
  if(!options||!options.pool ||
     typeof options.pool.acquirePrincipal!=='function' ||
     typeof options.pool.quarantine!=='function' ||
     !['saas_staging','saas_staging_ci'].includes(options.expectedDatabase) ||
     (options.nowMs!==undefined&&typeof options.nowMs!=='function')){
    throw new Error('Backend16 physical PG admission configuration refused');
  }
  const {pool,expectedDatabase}=options;
  const now=options.nowMs??Date.now;
  function poison(reason:Parameters<Backend16PhysicalPgPool['quarantine']>[0]){
    try{pool.quarantine(reason);}catch{/* still fail closed */}
  }
  return async function probe(
    principal:VerifiedPrincipal,tenantId:string,requestSignal:AbortSignal
  ):Promise<Backend16PgAdmission>{
    if(!requestSignal||requestSignal.aborted||
       typeof tenantId!=='string'||!UUID.test(tenantId) ||
       !validPrincipal(principal,now()))return DENIED;
    const signal=AbortSignal.any([requestSignal,AbortSignal.timeout(8000)]);
    let conn:Backend16PhysicalPgConnection|undefined;
    let result:Backend16PgAdmission=DENIED,ok=false,bad=false;
    try{
      conn=await abortable(Promise.resolve().then(()=>
        pool.acquirePrincipal(principal.pgLogin,signal)),signal);
      if(!conn||typeof conn.query!=='function'||
         typeof conn.release!=='function')
        throw new Error('Backend16 invalid PG physical client');
      const q=(sql:string,params:readonly string[]=[])=>abortable(
        Promise.resolve().then(()=>conn!.query(sql,params,signal)),signal);
      await q(BACKEND16_PHYSICAL_PG_SQL.begin);
      await q(BACKEND16_PHYSICAL_PG_SQL.statementTimeout);
      await q(BACKEND16_PHYSICAL_PG_SQL.lockTimeout);
      const role=exactRow(await q(BACKEND16_PHYSICAL_PG_SQL.identity),
        IDENTITY_KEYS);
      if(!trustedPhysicalRole(role,principal.pgLogin,expectedDatabase))
        throw new Error('Backend16 physical PG login refused');
      const acl=exactRow(await q(BACKEND16_PHYSICAL_PG_SQL.acl,[tenantId]),
        'allowed');
      if(typeof acl.allowed!=='boolean')
        throw new Error('Backend16 malformed tenant ACL');
      if(acl.allowed===true){
        const tenant=exactRow(await q(BACKEND16_PHYSICAL_PG_SQL.tenant,[tenantId]),
          'tenant_id');
        if(tenant.tenant_id!==tenantId)
          throw new Error('Backend16 FORCE RLS witness mismatch');
        result=Object.freeze({kind:'physical-rls-observed'});
      }
      if(signal.aborted||now()>=principal.sessionExpiresAtMs)
        throw new Error('Backend16 admission expired');
      // Lost COMMIT acknowledgement is UNKNOWN, never success or retry.
      await q(BACKEND16_PHYSICAL_PG_SQL.commit);
      if(signal.aborted||now()>=principal.sessionExpiresAtMs)
        throw new Error('Backend16 admission no longer valid');
      ok=true;
    }catch{
      bad=true;
      poison(conn?'query-uncertain':'acquire-uncertain');
      // Do not send ROLLBACK concurrently with an unknown in-flight COMMIT.
      // An uncertain physical backend MUST be destroyed by the pool.
    }finally{
      if(conn){
        const released=await boundedRelease(Promise.resolve().then(()=>conn!.release(bad||!ok)));
        if(!released){bad=true;poison('release-uncertain');}
      }
    }
    if(bad||!ok)throw new Error('Backend16 physical PostgreSQL unavailable');
    return result;
  };
}

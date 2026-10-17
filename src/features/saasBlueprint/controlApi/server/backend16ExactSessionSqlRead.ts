/**
 * Backend16.6: UNMOUNTED /internal/saas/v1 readAuthorized port candidate.
 *
 * SQL0008's exact locked subject/session/binding predicate and both FORCE
 * RLS tenant/project reads must execute on ONE dedicated physical PostgreSQL
 * LOGIN and within ONE bounded READ COMMITTED transaction. SQL0007 RLS takes
 * FOR SHARE locks, which PostgreSQL READ ONLY transactions forbid.
 *
 * This code is NOT a real PG driver, credential vault, durable audit,
 * transport publication protocol, private ingress or production deployment.
 * Its injected pool must independently prove real per-principal PG backend
 * credentials, session_user, no role escalation, and physical discard/PID
 * quarantine. NEVER mount until those external gates and durable audit pass.
 */
import type {
  Backend16PrivateReadPorts, VerifiedPrincipal, ReaderDecision,
} from './backend16PrivateTenantProjectRead';
import type {
  Backend16PhysicalPgPool, Backend16PhysicalPgConnection,
  Backend16PgRow,
} from './backend16PhysicalPgAdmission';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA=/^[0-9a-f]{64}$/;
const LOGIN=/^[a-z][a-z0-9_]{2,62}$/;
const RESERVED=new Set([
  'postgres','saas_schema_migrator','saas_runtime_reader','saas_runtime_writer',
]);
const MAX_PROJECTS=50;
const DENIED=Object.freeze({kind:'denied'} as const);

/** No interpolated SQL, SET ROLE, tenant GUC, write statements or bulk DTOs. */
export const BACKEND16_EXACT_READ_SQL=Object.freeze({
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
    "pg_has_role(session_user,'saas_runtime_reader','member') AS reader_member, "+
    "pg_has_role(session_user,'saas_runtime_writer','member') AS writer_member "+
    'FROM pg_catalog.pg_roles AS r WHERE r.rolname=session_user',
  exact:'SELECT saas_acl.exact_subject_session_authorized('+
    '$1::uuid,$2::uuid,$3::uuid,$4::text) AS allowed',
  tenant:'SELECT tenant_id::text AS tenant_id FROM saas_data.tenants '+
    'WHERE tenant_id=$1::uuid LIMIT 1',
  projects:'SELECT project_id::text AS project_id FROM saas_data.projects '+
    'WHERE tenant_id=$1::uuid ORDER BY project_id LIMIT 51',
  commit:'COMMIT',
} as const);

const ROLE_KEYS=[
  'active_role','backend_pid','bypass_rls','can_login','create_db',
  'create_role','database_name','reader_member','replication',
  'session_login','staging_only','superuser','writer_member',
].join(',');

export interface Backend16ExactSqlReadOptions {
  readonly pool:Backend16PhysicalPgPool;
  readonly expectedDatabase:'saas_staging'|'saas_staging_ci';
  readonly nowMs?:()=>number;
}
function valid(p:unknown,now:number):p is VerifiedPrincipal {
  if(!p||typeof p!=='object'||!Number.isSafeInteger(now))return false;
  const x=p as Partial<VerifiedPrincipal>;
  return x.kind==='verified-server-session' &&
    typeof x.issuer==='string'&&x.issuer.startsWith('https://') &&
    typeof x.subjectFingerprintSha256==='string'&&SHA.test(x.subjectFingerprintSha256) &&
    typeof x.pgLogin==='string'&&LOGIN.test(x.pgLogin) &&
    !RESERVED.has(x.pgLogin)&&!x.pgLogin.startsWith('pg_') &&
    typeof x.sessionId==='string'&&UUID.test(x.sessionId) &&
    typeof x.bindingId==='string'&&UUID.test(x.bindingId) &&
    typeof x.sessionExpiresAtMs==='number' &&
    Number.isSafeInteger(x.sessionExpiresAtMs) &&
    x.sessionExpiresAtMs>now&&x.sessionExpiresAtMs<=now+900_000;
}
function rows(result:unknown,max:number,keys:string):readonly Backend16PgRow[] {
  if(!result||typeof result!=='object'||!('rows' in result)||
     !Array.isArray(result.rows)||result.rows.length>max)return fail();
  for(const x of result.rows){
    if(!x||typeof x!=='object'||Array.isArray(x)||
       Object.keys(x).sort().join(',')!==keys)return fail();
  }
  return result.rows as readonly Backend16PgRow[];
}
function fail():never {throw new Error('Backend16 exact SQL row refused');}
function roleMatches(row:Backend16PgRow,login:string,db:string):boolean {
  return row.session_login===login&&row.active_role===login&&
    row.database_name===db&&row.staging_only==='true'&&
    Number.isSafeInteger(row.backend_pid)&&(row.backend_pid as number)>0 &&
    row.can_login===true&&row.superuser===false&&
    row.bypass_rls===false&&row.create_role===false&&
    row.create_db===false&&row.replication===false&&
    ((row.reader_member===true&&row.writer_member===false) ||
     (row.reader_member===false&&row.writer_member===true));
}
function cancellable<T>(pending:Promise<T>,signal:AbortSignal):Promise<T> {
  if(signal.aborted)return Promise.reject(new Error('Backend16 query aborted'));
  return new Promise<T>((resolve,reject)=>{
    let done=false;
    const cleanup=()=>{if(done)return false;done=true;
      signal.removeEventListener('abort',onAbort);return true;};
    const onAbort=()=>{if(cleanup())reject(new Error('Backend16 query aborted'));};
    signal.addEventListener('abort',onAbort,{once:true});
    if(signal.aborted)onAbort();
    pending.then(x=>{if(cleanup())resolve(x);},e=>{if(cleanup())reject(e);});
  });
}
async function boundedRelease(pending:Promise<unknown>):Promise<boolean> {
  let timer:ReturnType<typeof setTimeout>|undefined;
  try{
    await Promise.race([pending,new Promise<never>((_,reject)=>{
      timer=setTimeout(()=>reject(new Error('Backend16 SQL release timed out')),1200);
    })]);return true;
  }catch{return false;}
  finally{if(timer!==undefined)clearTimeout(timer);}
}

/**
 * Fully typed adapter for Backend16PrivateReadPorts.readAuthorized.
 * It does NOT implement the physical credential driver or attested authority;
 * both must be supplied and independently E2E reviewed before mounting.
 */
export function createBackend16ExactSqlReadPort(
  options:Backend16ExactSqlReadOptions,
):Backend16PrivateReadPorts['readAuthorized'] {
  if(!options||!options.pool ||
     typeof options.pool.acquirePrincipal!=='function' ||
     typeof options.pool.quarantine!=='function' ||
     !['saas_staging','saas_staging_ci'].includes(options.expectedDatabase) ||
     (options.nowMs!==undefined&&typeof options.nowMs!=='function')){
    throw new Error('Backend16 exact PG read configuration refused');
  }
  const {pool,expectedDatabase}=options;
  const now=options.nowMs??Date.now;
  function quarantine(reason:Parameters<Backend16PhysicalPgPool['quarantine']>[0]){
    try{pool.quarantine(reason);}catch{/* fail-closed on unavailable poison */ }
  }

  return async function readAuthorized(
    principal:VerifiedPrincipal, tenantId:string, requestSignal:AbortSignal,
  ):Promise<ReaderDecision>{
    if(!requestSignal||requestSignal.aborted ||
       typeof tenantId!=='string'||!UUID.test(tenantId) ||
       !valid(principal,now()))return DENIED;
    const signal=AbortSignal.any([requestSignal,AbortSignal.timeout(8000)]);
    let conn:Backend16PhysicalPgConnection|undefined;
    let result:ReaderDecision=DENIED;
    let knownCommit=false,failed=false;
    try{
      conn=await cancellable(Promise.resolve().then(()=>
        pool.acquirePrincipal(principal.pgLogin,signal)),signal);
      if(!conn||typeof conn.query!=='function'||
         typeof conn.release!=='function')
        fail();
      const q=(sql:string,params:readonly string[]=[])=>cancellable(
        Promise.resolve().then(()=>conn!.query(sql,params,signal)),signal);
      await q(BACKEND16_EXACT_READ_SQL.begin);
      await q(BACKEND16_EXACT_READ_SQL.statementTimeout);
      await q(BACKEND16_EXACT_READ_SQL.lockTimeout);

      const r=rows(await q(BACKEND16_EXACT_READ_SQL.identity),1,ROLE_KEYS);
      if(r.length!==1||!roleMatches(r[0],principal.pgLogin,expectedDatabase))
        fail();
      const decision=rows(await q(BACKEND16_EXACT_READ_SQL.exact,[
        tenantId,principal.sessionId,principal.bindingId,
        principal.subjectFingerprintSha256,
      ]),1,'allowed');
      if(decision.length!==1||typeof decision[0].allowed!=='boolean')
        fail();
      if(decision[0].allowed===true){
        const tenant=rows(await q(BACKEND16_EXACT_READ_SQL.tenant,[tenantId]),1,
          'tenant_id');
        if(tenant.length!==1||tenant[0].tenant_id!==tenantId)fail();
        const projectRows=rows(await q(BACKEND16_EXACT_READ_SQL.projects,[tenantId]),
          MAX_PROJECTS+1,'project_id');
        if(projectRows.length>MAX_PROJECTS)fail();
        const ids=projectRows.map(x=>x.project_id);
        if(!ids.every(x=>typeof x==='string'&&UUID.test(x))||
           new Set(ids).size!==ids.length)fail();
        result=Object.freeze({kind:'authorized',tenantId,
          projectIds:Object.freeze(ids.slice() as string[])});
      }
      if(signal.aborted||now()>=principal.sessionExpiresAtMs)
        fail();
      // SQL0008 FOR SHARE and FORCE RLS stay within this transaction.
      // UNKNOWN COMMIT ACK = NO publish, poison and NO retries.
      await q(BACKEND16_EXACT_READ_SQL.commit);
      if(signal.aborted||now()>=principal.sessionExpiresAtMs)
        fail();
      knownCommit=true;
    }catch{
      failed=true;
      quarantine(conn?'query-uncertain':'acquire-uncertain');
      // Never speculate ROLLBACK while a COMMIT could be in flight.
      // Pool MUST physically discard an uncertain backend by PID.
    }finally{
      if(conn){
        const ok=await boundedRelease(
          Promise.resolve().then(()=>conn!.release(failed||!knownCommit)));
        if(!ok){failed=true;quarantine('release-uncertain');}
      }
    }
    if(failed||!knownCommit)
      throw new Error('Backend16 exact SQL data source unavailable');
    return result;
  };
}

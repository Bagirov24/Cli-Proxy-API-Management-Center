/**
 * Backend16.9: staging-only candidate for real Bun.SQL physical PostgreSQL
 * connections. NOT mounted, NOT a credential vault, NOT production-approved.
 *
 * Only an operator-owned, server-side vault may resolve each exact LOGIN.
 * A fresh max:1 native pool is reserved for each request and closed before the
 * caller can publish a response. No SET ROLE, client credentials, dynamic SQL,
 * reusable connection, automatic retry, HTTP listener or migration privileges.
 *
 * Deployment MUST remain blocked until SQL0008 is independently reconciled as
 * installed, private TLS identity is reviewed, and the staging audit/authority
 * gates are complete. The runtime opt-in flags are defense in depth, not proof.
 */
import type {
  Backend16PhysicalPgConnection, Backend16PhysicalPgPool, Backend16PgRow,
} from './backend16PhysicalPgAdmission';
import {BACKEND16_EXACT_READ_SQL as SQL}
  from './backend16ExactSessionSqlRead';

type NativeRow=Record<string,unknown>;
type NativeQuery={execute():PromiseLike<NativeRow[]>;cancel():void};
type NativeReserved={
  unsafe(sql:string,params?:string[]):NativeQuery;
  release():void;
};
type NativeSQL={
  reserve(options?:{signal:AbortSignal}):Promise<NativeReserved>;
  close(options?:{timeout:number}):Promise<void>;
};
type NativeCtor=new(options:Readonly<Record<string,unknown>>)=>NativeSQL;

export interface Backend16StagingPrincipalVault {
  /** Must resolve ONLY the exact server-authorized LOGIN, never client data. */
  readPrincipal(login:string,signal:AbortSignal):Promise<
    Readonly<{username:string;password:string}>
  >;
}

const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENVIRONMENT='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const SERVICE='a0ff5420-95e8-4fab-88f6-623f75dd03c6';
const HOST='postgres.railway.internal';
const DATABASE='saas_staging';
const MAX_ACTIVE=4;
const LOGIN=/^[a-z][a-z0-9_]{2,62}$/;
const PASSWORD=/^[\x21-\x7e]{32,256}$/;
const FORBIDDEN=new Set([
  'postgres','saas_schema_migrator','saas_runtime_reader',
  'saas_runtime_writer',
]);
const PARAM_COUNTS=new Map<string,number>([
  [SQL.begin,0],[SQL.statementTimeout,0],[SQL.lockTimeout,0],
  [SQL.identity,0],[SQL.exact,4],[SQL.tenant,1],
  [SQL.projects,1],[SQL.commit,0],
]);
type Step=keyof typeof SQL|'done';

/**
 * Vaults and native driver internals may ignore AbortSignal. Bound every
 * acquisition/SQL await anyway: an aborted request MUST stop awaiting even
 * when the upstream promise never settles. Native resources are quarantined
 * separately; late resolution cannot re-enter an authenticated read.
 */
function rejectOnAbort<T>(pending:PromiseLike<T>,signal:AbortSignal):Promise<T>{
  if(signal.aborted)
    return Promise.reject(new Error('Backend16 staging operation aborted'));
  return new Promise<T>((resolve,reject)=>{
    let done=false;
    const finish=()=>{
      if(done)return false;
      done=true;
      signal.removeEventListener('abort',onAbort);
      return true;
    };
    const onAbort=()=>{
      if(finish())reject(new Error('Backend16 staging operation aborted'));
    };
    signal.addEventListener('abort',onAbort,{once:true});
    if(signal.aborted)onAbort();
    Promise.resolve(pending).then(
      value=>{if(finish())resolve(value);},
      error=>{if(finish())reject(error);},
    );
  });
}


/**
 * Pure request-local state machine; exported to test its exact protocol
 * without creating Railway connections or accepting test credentials.
 * The adapter independently verifies physical session_user / PID and rows.
 */
export function createBackend16StagingSqlSequence(){
  let step:Step='begin';
  return Object.freeze({
    check(sql:string,params:readonly string[]):void{
      if(step==='done'||sql!==SQL[step]||
         !Array.isArray(params)||params.length!==PARAM_COUNTS.get(sql)||
         params.some(p=>typeof p!=='string'||p.length>256))
        throw new Error('Backend16 staging SQL protocol refused');
    },
    completed(sql:string,rows:readonly Backend16PgRow[]):void{
      if(step==='done'||sql!==SQL[step]||!Array.isArray(rows))
        throw new Error('Backend16 staging SQL result refused');
      if(step==='exact'){
        if(rows.length!==1||Object.keys(rows[0]??{}).join(',')!=='allowed'||
           typeof rows[0].allowed!=='boolean')
          throw new Error('Backend16 staging exact gate refused');
        step=rows[0].allowed===true?'tenant':'commit';
        return;
      }
      const next:Partial<Record<Step,Step>>={
        begin:'statementTimeout',statementTimeout:'lockTimeout',
        lockTimeout:'identity',identity:'exact',
        tenant:'projects',projects:'commit',commit:'done',
      };
      const nextStep=next[step];
      if(!nextStep)throw new Error('Backend16 staging SQL transition refused');
      step=nextStep;
    },
    finished():boolean{return step==='done';},
  });
}

/**
 * Injecting a vault interface does NOT implement a trusted vault. Production
 * and real staging deployment remain prohibited until a separately audited
 * server-only resolver and release gates exist. No secret ever enters logs.
 */
type Backend16BunPgProfile=Readonly<{
  hostname:string;
  database:string;
  tls?:'verify-full';
}>;
const STAGING_PROFILE:Backend16BunPgProfile=Object.freeze({
  hostname:HOST,database:DATABASE,tls:'verify-full',
});
const DISPOSABLE_CI_PROFILE:Backend16BunPgProfile=Object.freeze({
  hostname:'127.0.0.1',database:'saas_staging_ci',
});
const runtimeEnv=()=>(globalThis as unknown as {
  process?:{env:Record<string,string|undefined>};
}).process?.env??{};

/** No public profile or arbitrary hostname can be selected by the caller. */
export function createBackend16StagingBunPhysicalPgPool(
  vault:Backend16StagingPrincipalVault,
):Backend16PhysicalPgPool & {shutdown():Promise<void>} {
  const env=runtimeEnv();
  if(!vault||typeof vault.readPrincipal!=='function'||
     env.RAILWAY_PROJECT_ID!==PROJECT||
     env.RAILWAY_ENVIRONMENT_ID!==ENVIRONMENT||
     env.RAILWAY_SERVICE_ID!==SERVICE||
     env.RAILWAY_ENVIRONMENT_NAME!=='staging'||
     env.SAAS_B16_STAGING_0008_INDEPENDENT_READBACK!=='true'||
     env.SAAS_B16_STAGING_PRIVATE_ONLY!=='true'||
     env.GITHUB_ACTIONS==='true'||
     env.SAAS_B16_EPHEMERAL_CI==='true')
    throw new Error('Backend16 staging driver release gates not met');
  return buildBackend16StagingPhysicalPgPool(vault,STAGING_PROFILE);
}

/**
 * Identical physical/query/discard implementation exercised with *real*
 * isolated PG16 in GitHub Actions. This entrypoint cannot connect to Railway,
 * production, any TCP proxy, or a non-local database. It is NOT a fallback.
 */
export function createBackend16StagingDisposableCiPhysicalPgPool(
  vault:Backend16StagingPrincipalVault,
):Backend16PhysicalPgPool & {shutdown():Promise<void>} {
  const env=runtimeEnv();
  if(!vault||typeof vault.readPrincipal!=='function'||
     env.GITHUB_ACTIONS!=='true'||
     env.SAAS_B16_EPHEMERAL_CI!=='true'||
     env.SAAS_B16_PHYSICAL_CI!=='true'||
     env.PGHOST!=='127.0.0.1'||
     env.PGPORT!=='5432'||
     env.PGDATABASE!=='saas_ephemeral_test'||
     env.PGPASSWORD!=='ci_ephemeral_test_only'||
     env.NODE_ENV==='production'||
     env.RAILWAY_PROJECT_ID||env.RAILWAY_ENVIRONMENT_ID||
     env.RAILWAY_SERVICE_ID||env.RAILWAY_ENVIRONMENT)
    throw new Error('Backend16 staging test driver limited to disposable GitHub PG16');
  return buildBackend16StagingPhysicalPgPool(vault,DISPOSABLE_CI_PROFILE);
}

function buildBackend16StagingPhysicalPgPool(
  vault:Backend16StagingPrincipalVault,
  profile:Backend16BunPgProfile,
):Backend16PhysicalPgPool & {shutdown():Promise<void>} {
  const Ctor=(globalThis as unknown as {Bun?:{SQL?:NativeCtor}}).Bun?.SQL;
  if(typeof Ctor!=='function')
    throw new Error('Backend16 staging Bun.SQL unavailable');

  let stopped=false;
  let slots=0;
  const active=new Set<NativeSQL>();
  const closeImmediately=(native:NativeSQL):void=>{
    try{void native.close({timeout:0}).catch(()=>{/* fail closed */});}
    catch{/* fail closed */}
  };
  const quarantine:Backend16PhysicalPgPool['quarantine']=(_reason)=>{
    stopped=true; // synchronous barrier, before any asynchronous close
    for(const native of active)closeImmediately(native);
  };
  const assertAvailable=(signal:AbortSignal):void=>{
    if(stopped||signal.aborted)
      throw new Error('Backend16 staging physical backend unavailable');
  };

  return Object.freeze({
    quarantine,
    async acquirePrincipal(login:string,requestSignal:AbortSignal):
      Promise<Backend16PhysicalPgConnection> {
      if(!requestSignal||requestSignal.aborted||stopped||
         typeof login!=='string'||!LOGIN.test(login)||
         FORBIDDEN.has(login)||login.startsWith('pg_')||
         slots>=MAX_ACTIVE)
        throw new Error('Backend16 staging physical LOGIN refused');
      slots++;
      const signal=AbortSignal.any([
        requestSignal,AbortSignal.timeout(6500),
      ]);
      let native:NativeSQL|undefined;
      let reserved:NativeReserved|undefined;
      let acquirePhase:'VAULT'|'MAPPING'|'CONSTRUCTOR'|'RESERVE'|'MARKER'='VAULT';
      try{
        const credentials=await rejectOnAbort(vault.readPrincipal(login,signal),signal);
        assertAvailable(signal);
        acquirePhase='MAPPING';
        if(!credentials||credentials.username!==login||
           typeof credentials.password!=='string'||
           !PASSWORD.test(credentials.password))
          throw new Error('Backend16 staging vault mapping refused');
        acquirePhase='CONSTRUCTOR';
        native=new Ctor({
          adapter:'postgres',hostname:profile.hostname,port:5432,
          database:profile.database,
          username:credentials.username,password:credentials.password,
          ...(profile.tls?{tls:profile.tls}:{}),
          max:1,connectionTimeout:4,idleTimeout:0,
          prepare:false,
        });
        active.add(native);
        acquirePhase='RESERVE';
        reserved=await rejectOnAbort(native.reserve({signal}),signal);
        assertAvailable(signal);
        acquirePhase='MARKER';
        // Same reserved physical LOGIN, never a user-supplied tenant GUC.
        await rejectOnAbort(reserved.unsafe(
          "SELECT pg_catalog.set_config('saas.staging_only','true',false)",[],
        ).execute(),signal);
        assertAvailable(signal);
      }catch{
        quarantine('acquire-uncertain');
        // Bun.SQL reserve() transfers ownership until release(). If a
        // subsequent marker/query fails, giving back the reserved handle
        // is required for close({timeout:0}) to settle on some runtimes.
        // This max:1 pool is quarantined and NEVER offered to a caller.
        if(reserved){try{reserved.release();}catch{/* still destroy pool */}}
        if(native){
          closeImmediately(native);
          active.delete(native);
        }
        slots--;
        const ci=runtimeEnv();
        if(ci.GITHUB_ACTIONS==='true'&&ci.SAAS_B16_EPHEMERAL_CI==='true')
          throw new Error('Backend16 staging disposable CI stopped at '+acquirePhase);
        throw new Error('Backend16 staging physical acquisition failed');
      }
      if(!native||!reserved){
        quarantine('acquire-uncertain');
        throw new Error('Backend16 staging native reservation missing');
      }
      const db=native;
      const connection=reserved;
      const sequence=createBackend16StagingSqlSequence();
      let closed=false;
      let busy=false;
      return Object.freeze({
        async query(sql:string,params:readonly string[],request:AbortSignal){
          if(!request||closed||busy||stopped||request.aborted){
            quarantine('query-uncertain');
            throw new Error('Backend16 staging physical query unavailable');
          }
          try{sequence.check(sql,params);}
          catch{
            quarantine('query-uncertain');
            throw new Error('Backend16 staging SQL refused');
          }
          busy=true;
          let query:NativeQuery;
          try{query=connection.unsafe(sql,[...params]);}
          catch{
            busy=false;
            quarantine('query-uncertain');
            throw new Error('Backend16 staging physical query creation failed');
          }
          const signal=AbortSignal.any([
            request,AbortSignal.timeout(6000),
          ]);
          let aborted=false;
          const cancel=()=>{
            aborted=true;
            quarantine('query-uncertain');
            try{query.cancel();}catch{/* destroy native pool regardless */}
          };
          signal.addEventListener('abort',cancel,{once:true});
          if(signal.aborted)cancel();
          try{
            if(aborted)throw new Error('Backend16 staging query aborted');
            const result=await rejectOnAbort(query.execute(),signal);
            if(aborted||stopped||signal.aborted||!Array.isArray(result))
              throw new Error('Backend16 staging query uncertain');
            sequence.completed(sql,result);
            return {rows:result as readonly Backend16PgRow[]};
          }catch{
            quarantine('query-uncertain');
            throw new Error('Backend16 staging physical SQL failed');
          }finally{
            signal.removeEventListener('abort',cancel);
            busy=false;
          }
        },
        async release(discard:boolean){
          if(closed){
            quarantine('release-uncertain');
            throw new Error('Backend16 staging duplicate release');
          }
          closed=true;
          if(!discard&&!sequence.finished()){
            quarantine('release-uncertain');
            discard=true;
          }
          try{
            if(discard||stopped){
              // IMPORTANT: this Bun.SQL max:1 pool is request-private; no
              // caller receives db and this connection is already closed
              // to new queries. Releasing its reserved handle BEFORE
              // close() avoids a native wait-for-reservation deadlock.
              // No other request can borrow this pool; close({timeout:0})
              // physically ends the uncommitted read transaction.
              let refusedRelease=false;
              try{connection.release();}catch{refusedRelease=true;}
              await db.close({timeout:0});
              if(refusedRelease)
                throw new Error('Backend16 staging reserved close uncertain');
            }else{
              connection.release();
              await db.close({timeout:0});
            }
          }catch{
            quarantine('release-uncertain');
            throw new Error('Backend16 staging physical close uncertain');
          }finally{
            active.delete(db);
            slots--;
          }
          if(discard||stopped)
            throw new Error('Backend16 staging physical backend discarded');
        },
      });
    },
    async shutdown():Promise<void>{
      quarantine('release-uncertain');
      await Promise.allSettled([...active].map(db=>db.close({timeout:0})));
      active.clear();
    },
  });
}

/**
 * Backend16.7 — DISPOSABLE GITHUB PG16 ONLY, actual Bun.SQL physical backend.
 *
 * This is a deliberately restricted, unmounted, CI-only experimental pool:
 * credentials are injected from the synthetic test operator, never HTTP;
 * PostgreSQL hostname/database are immutable localhost CI pins. Production
 * and permanent Railway staging are refused, even if this module is imported.
 *
 * Every acquisition makes a distinct Bun.SQL max:1 pool, reserves ONE physical
 * connection, enforces the server-owned SQL0008 query allowlist and closes
 * that entire pool (not just release-to-pool) before any DTO is returned.
 * Query abort and unknown COMMIT force a synchronous quarantine barrier plus
 * best-effort immediate pool close; a real PG16 PID disappearance test is
 * mandatory before promoting this experiment to a reviewed staging driver.
 */
import type {
  Backend16PhysicalPgConnection, Backend16PhysicalPgPool,
  Backend16PgRow,
} from './backend16PhysicalPgAdmission';
import {BACKEND16_EXACT_READ_SQL} from './backend16ExactSessionSqlRead';

type NativeRow=Record<string,unknown>;
type NativeQuery={
  execute():PromiseLike<NativeRow[]>;
  cancel():void;
};
type Reserved={
  unsafe(query:string,values?:string[]):NativeQuery;
  release():void;
};
type NativeSQL={
  reserve(options?:{signal:AbortSignal}):Promise<Reserved>;
  close(options?:{timeout:number}):Promise<void>;
};
type NativeCtor=new(options:Readonly<Record<string,unknown>>)=>NativeSQL;
const ALLOWED=new Map<string,number>([
  [BACKEND16_EXACT_READ_SQL.begin,0],
  [BACKEND16_EXACT_READ_SQL.statementTimeout,0],
  [BACKEND16_EXACT_READ_SQL.lockTimeout,0],
  [BACKEND16_EXACT_READ_SQL.identity,0],
  [BACKEND16_EXACT_READ_SQL.exact,4],
  [BACKEND16_EXACT_READ_SQL.tenant,1],
  [BACKEND16_EXACT_READ_SQL.projects,1],
  [BACKEND16_EXACT_READ_SQL.commit,0],
]);
const LOGIN=/^[a-z][a-z0-9_]{2,62}$/;
const DENIED_LOGINS=new Set([
  'postgres','saas_schema_migrator','saas_runtime_reader','saas_runtime_writer',
]);
const PASSWORD=/^[0-9a-f]{64}$/;
const DB='saas_staging_ci';
const HOST='127.0.0.1';
const MAX_ACTIVE=3;

export type Backend16CiCredentialProvider=(
  login:string,signal:AbortSignal,
)=>Promise<Readonly<{username:string;password:string}>>;

export function createBackend16CiBunPhysicalPgPool(
  credentialProvider:Backend16CiCredentialProvider,
):Backend16PhysicalPgPool & {shutdown:()=>Promise<void>} {
  const env=process.env;
  if(typeof credentialProvider!=='function'||
     env.GITHUB_ACTIONS!=='true' ||
     env.SAAS_B16_EPHEMERAL_CI!=='true' ||
     env.SAAS_B16_PHYSICAL_CI!=='true' ||
     env.PGHOST!==HOST || env.PGPORT!=='5432' ||
     env.PGDATABASE!=='saas_ephemeral_test' ||
     env.NODE_ENV==='production'||
     env.RAILWAY_PROJECT_ID || env.RAILWAY_ENVIRONMENT_ID ||
     env.RAILWAY_SERVICE_ID || env.RAILWAY_ENVIRONMENT)
    throw new Error('Backend16 Bun physical pool limited to disposable GitHub PG16');
  const BunRuntime=(globalThis as unknown as {
    Bun?:{SQL?:NativeCtor};
  }).Bun;
  if(typeof BunRuntime?.SQL!=='function')
    throw new Error('Backend16 Bun.SQL runtime missing');

  let quarantined=false,slots=0;
  const active=new Set<NativeSQL>();
  function closeNative(native:NativeSQL){
    // Do not await: quarantine MUST synchronously reject new acquisitions.
    void native.close({timeout:0}).catch(()=>{/* fail closed */});
  }
  function quarantine(_reason:Parameters<Backend16PhysicalPgPool['quarantine']>[0]){
    quarantined=true;
    for(const client of active)closeNative(client);
  }
  function assertActive(signal:AbortSignal){
    if(quarantined||signal.aborted)
      throw new Error('Backend16 disposable physical connection unavailable');
  }
  return {
    quarantine,
    async acquirePrincipal(login:string,signal:AbortSignal):
      Promise<Backend16PhysicalPgConnection> {
      assertActive(signal);
      if(typeof login!=='string'||!LOGIN.test(login)||
         DENIED_LOGINS.has(login)||login.startsWith('pg_')||
         slots>=MAX_ACTIVE)throw new Error('Backend16 CI LOGIN refused');
      slots++;
      let native:NativeSQL|undefined;
      let reserved:Reserved|undefined;
      try{
        const credentials=await credentialProvider(login,signal);
        assertActive(signal);
        if(!credentials || credentials.username!==login||
           typeof credentials.password!=='string'||
           !PASSWORD.test(credentials.password))
          throw new Error('Backend16 physical credential mapping refused');
        native=new BunRuntime.SQL({
          adapter:'postgres',hostname:HOST,port:5432,database:DB,
          username:credentials.username,password:credentials.password,
          max:1,connectionTimeout:4,idleTimeout:0,prepare:false,
        });
        active.add(native);
        reserved=await native.reserve({signal});
        assertActive(signal);
        // Server-owned session marker on the SAME authenticated backend,
        // never a client/tenant GUC and never a role impersonation.
        await reserved.unsafe(
          "SELECT pg_catalog.set_config('saas.staging_only','true',false)",
          [],
        ).execute();
        assertActive(signal);
      }catch{
        if(native){try{await native.close({timeout:0});}catch{/* no retry */}
          active.delete(native);}
        slots--;
        throw new Error('Backend16 disposable connection acquisition failed');
      }
      if(!native||!reserved){
        quarantine('acquire-uncertain');
        throw new Error('Backend16 native reservation unavailable');
      }
      const db=native;
      const connection=reserved;
      let closed=false;
      return {
        async query(sql:string,params:readonly string[],requestSignal:AbortSignal){
          assertActive(requestSignal);
          if(closed||typeof sql!=='string'||
             !ALLOWED.has(sql)||params.length!==ALLOWED.get(sql)||
             params.some(p=>typeof p!=='string'||p.length>256)){
            quarantine('query-uncertain');
            throw new Error('Backend16 physical SQL allowlist refused');
          }
          const query=connection.unsafe(sql,[...params]);
          let aborted=false;
          const cancel=()=>{
            aborted=true;
            quarantine('query-uncertain');
            try{query.cancel();}catch{/* pool closes regardless */}
          };
          requestSignal.addEventListener('abort',cancel,{once:true});
          if(requestSignal.aborted)cancel();
          try{
            if(aborted)throw new Error('Backend16 query cancelled');
            const result=await query.execute();
            if(aborted||requestSignal.aborted||quarantined||
               !Array.isArray(result))
              throw new Error('Backend16 query discarded');
            return {rows:result as readonly Backend16PgRow[]};
          }catch{
            quarantine('query-uncertain');
            throw new Error('Backend16 physical SQL failed');
          }finally{
            requestSignal.removeEventListener('abort',cancel);
          }
        },
        async release(discard:boolean){
          if(closed){
            quarantine('release-uncertain');
            throw new Error('Backend16 duplicate physical release refused');
          }
          closed=true;
          try{
            // The max:1 pool belongs to this request only. With discard it
            // closes the backend BEFORE any release-to-pool; on success release
            // and then close, so no physical connection is ever reused.
            if(discard||quarantined){
              await db.close({timeout:0});
              try{connection.release();}catch{/* already destroyed */}
            }else{
              connection.release();
              await db.close({timeout:0});
            }
          }catch{
            quarantine('release-uncertain');
            throw new Error('Backend16 physical backend close uncertain');
          }finally{
            active.delete(db);
            slots--;
          }
        },
      };
    },
    async shutdown(){
      quarantine('release-uncertain');
      await Promise.allSettled([...active].map(x=>x.close({timeout:0})));
      active.clear();
    },
  };
}

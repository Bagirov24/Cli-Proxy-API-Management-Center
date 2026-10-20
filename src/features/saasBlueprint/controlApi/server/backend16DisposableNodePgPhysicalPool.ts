/**
 * Backend16: UNMOUNTED CI-ONLY node-postgres physical TLS/read adapter.
 *
 * Native Bun.SQL TLS verification failed genuine PG16 same-socket negatives.
 * This alternative requires a caller-supplied, reviewed Node pg.Client ctor,
 * an independently branded exact-SAN CA and a fresh per-LOGIN vault lookup.
 * NO production factory, public endpoint, shared-login fallback or deployment.
 * All supported SQL is the original Backend16.6 exact-session allowlist.
 */
import type {
  Backend16PhysicalPgConnection, Backend16PhysicalPgPool, Backend16PgRow,
} from './backend16PhysicalPgAdmission';
import {BACKEND16_EXACT_READ_SQL as SQL} from './backend16ExactSessionSqlRead.ts';
import {backend16IsApprovedStagingPgTlsTrust,
  type Backend16StagingPgTlsTrust} from './backend16StagingPgTlsTrust.ts';
import type {Backend16StagingPrincipalVault}
  from './backend16StagingBunPhysicalPgPool';

type QueryResult={rows:Backend16PgRow[]};
type NodePgClient={
  connect():Promise<void>;
  query(sql:string,params?:readonly string[]):Promise<QueryResult>;
  end():Promise<void>;
  on(event:'error',listener:()=>void):unknown;
  connection?:{stream?:{destroy():void}};
};
export type Backend16NodePgClientConstructor=
  new(options:Readonly<Record<string,unknown>>)=>NodePgClient;

const HOST='postgres.railway.internal';
const LOGIN=/^[a-z][a-z0-9_]{2,62}$/;
const PASSWORD=/^[\x21-\x7e]{32,256}$/;
const FORBIDDEN=new Set([
  'postgres','saas_schema_migrator','saas_runtime_reader',
  'saas_runtime_writer',
]);
const MAX_ACTIVE=3;
type Step=keyof typeof SQL|'done';
const PARAM_COUNT=new Map<string,number>([
  [SQL.begin,0],[SQL.statementTimeout,0],[SQL.lockTimeout,0],
  [SQL.identity,0],[SQL.exact,4],[SQL.tenant,1],
  [SQL.projects,1],[SQL.commit,0],
]);
const env=()=>(globalThis as unknown as {
  process?:{env:Record<string,string|undefined>};
}).process?.env??{};
function refuse():never{
  throw new Error('Backend16 Node PostgreSQL physical TLS unavailable');
}
function sequence(){
  let step:Step='begin';
  return {
    check(sql:string,params:readonly string[]){
      if(step==='done'||sql!==SQL[step]||
         !Array.isArray(params)||params.length!==PARAM_COUNT.get(sql)||
         params.some(x=>typeof x!=='string'||x.length>256))refuse();
    },
    completed(sql:string,rows:readonly Backend16PgRow[]){
      if(step==='done'||sql!==SQL[step]||!Array.isArray(rows))refuse();
      if(step==='exact'){
        if(rows.length!==1||typeof rows[0]?.allowed!=='boolean'||
           Object.keys(rows[0]).join(',')!=='allowed')refuse();
        step=rows[0].allowed?'tenant':'commit';
        return;
      }
      const next:Partial<Record<Step,Step>>={
        begin:'statementTimeout',statementTimeout:'lockTimeout',
        lockTimeout:'identity',identity:'exact',
        tenant:'projects',projects:'commit',commit:'done',
      };
      const nextStep=next[step];
      if(!nextStep)refuse();
      step=nextStep;
    },
    finished(){return step==='done';},
  };
}
function abortable<T>(pending:Promise<T>,signal:AbortSignal):Promise<T>{
  if(signal.aborted)return Promise.reject(new Error('B16 Node PG cancelled'));
  return new Promise<T>((resolve,reject)=>{
    let done=false;
    const finish=()=>{
      if(done)return false;
      done=true;
      signal.removeEventListener('abort',onAbort);
      return true;
    };
    const onAbort=()=>{
      if(finish())reject(new Error('B16 Node PG cancelled'));
    };
    signal.addEventListener('abort',onAbort,{once:true});
    if(signal.aborted)onAbort();
    pending.then(x=>{if(finish())resolve(x);},
      ()=>{if(finish())reject(new Error('B16 Node PG unavailable'));});
  });
}
async function bounded<T>(pending:Promise<T>,ms:number):Promise<T>{
  return abortable(pending,AbortSignal.timeout(ms));
}

/** Explicitly limited to ephemeral GitHub PG16; no staging/runtime route. */
export function createBackend16DisposableCiNodePgPhysicalPool(
  vault:Backend16StagingPrincipalVault,
  trust:Backend16StagingPgTlsTrust,
  Client:Backend16NodePgClientConstructor,
):Backend16PhysicalPgPool&{shutdown():Promise<void>}{
  const e=env();
  if(!vault||typeof vault.readPrincipal!=='function'||
     typeof Client!=='function'||
     !backend16IsApprovedStagingPgTlsTrust(trust)||
     e.GITHUB_ACTIONS!=='true'||e.SAAS_B16_EPHEMERAL_CI!=='true'||
     e.SAAS_B16_NODEPG_PHYSICAL_CI!=='true'||
     e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||
     e.PGDATABASE!=='saas_ephemeral_test'||
     e.PGPASSWORD!=='ci_ephemeral_test_only'||
     e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
     e.RAILWAY_PROJECT_ID||e.RAILWAY_ENVIRONMENT_ID||
     e.RAILWAY_SERVICE_ID||e.RAILWAY_ENVIRONMENT)refuse();
  let stopped=false;
  let slots=0;
  const active=new Set<NodePgClient>();
  const destroy=(client:NodePgClient)=>{
    // Physical socket destruction is synchronous even if pg.end() hangs.
    try{client.connection?.stream?.destroy();}catch{/* fail closed */}
    try{void client.end().catch(()=>{});}catch{/* fail closed */}
  };
  const quarantine:Backend16PhysicalPgPool['quarantine']=()=>{
    stopped=true;
    for(const client of active)destroy(client);
  };
  const available=(signal:AbortSignal)=>{
    if(signal.aborted||stopped||!backend16IsApprovedStagingPgTlsTrust(trust))
      refuse();
  };
  return Object.freeze({
    quarantine,
    async acquirePrincipal(login:string,requestSignal:AbortSignal):
      Promise<Backend16PhysicalPgConnection>{
      if(!requestSignal||requestSignal.aborted||stopped||
         typeof login!=='string'||!LOGIN.test(login)||
         FORBIDDEN.has(login)||login.startsWith('pg_')||
         slots>=MAX_ACTIVE)refuse();
      slots++;
      const signal=AbortSignal.any([
        requestSignal,AbortSignal.timeout(6500),
      ]);
      let client:NodePgClient|undefined;
      try{
        available(signal);
        const credential=await abortable(
          Promise.resolve().then(()=>vault.readPrincipal(login,signal)),signal);
        available(signal);
        if(!credential||credential.username!==login||
           typeof credential.password!=='string'||
           !PASSWORD.test(credential.password))refuse();
        client=new Client({
          host:'127.0.0.1',port:5432,database:'saas_staging_ci',
          user:login,password:credential.password,
          // Fixed PostgreSQL startup marker; NOT a client-controlled GUC.
          options:'-c saas.staging_only=true',
          application_name:'b16-nodepg-exact-ci',
          connectionTimeoutMillis:4000,
          statement_timeout:5000,
          ssl:{
            ca:trust.ca,servername:HOST,rejectUnauthorized:true,
            minVersion:'TLSv1.2',maxVersion:'TLSv1.3',
            checkServerIdentity:(hostname:string,cert:unknown)=>{
              if(hostname!==HOST)return new Error('B16 private PG SAN denied');
              return trust.checkServerIdentity(hostname,cert);
            },
          },
        });
        client.on('error',()=>{/* private, generic failure */});
        active.add(client);
        await abortable(client.connect(),signal);
        available(signal);
      }catch{
        quarantine('acquire-uncertain');
        if(client)destroy(client);
        slots--;
        refuse();
      }
      if(!client)refuse();
      const db=client;
      const steps=sequence();
      let closed=false,busy=false;
      return Object.freeze({
        async query(sql:string,params:readonly string[],req:AbortSignal):
          Promise<{rows:readonly Backend16PgRow[]}>{
          if(closed||busy||stopped||!req||req.aborted){
            quarantine('query-uncertain');refuse();
          }
          try{steps.check(sql,params);}
          catch{quarantine('query-uncertain');refuse();}
          busy=true;
          const deadline=AbortSignal.any([req,AbortSignal.timeout(6000)]);
          const cancel=()=>{quarantine('query-uncertain');destroy(db);};
          deadline.addEventListener('abort',cancel,{once:true});
          if(deadline.aborted)cancel();
          try{
            available(deadline);
            const result=await abortable(
              db.query(sql,[...params]),deadline);
            available(deadline);
            if(!result||!Array.isArray(result.rows))refuse();
            steps.completed(sql,result.rows);
            return {rows:result.rows};
          }catch{
            quarantine('query-uncertain');refuse();
          }finally{
            deadline.removeEventListener('abort',cancel);
            busy=false;
          }
        },
        async release(discard:boolean){
          if(closed){quarantine('release-uncertain');refuse();}
          closed=true;
          const poison=discard||stopped||!steps.finished();
          try{
            if(poison)destroy(db);
            await bounded(Promise.resolve().then(()=>db.end()),1200);
          }catch{
            quarantine('release-uncertain');refuse();
          }finally{
            active.delete(db);slots--;
          }
          if(poison)refuse();
        },
      });
    },
    async shutdown(){
      quarantine('release-uncertain');
      await Promise.allSettled([...active].map(c=>
        bounded(Promise.resolve().then(()=>c.end()),1200)));
      active.clear();
    },
  });
}

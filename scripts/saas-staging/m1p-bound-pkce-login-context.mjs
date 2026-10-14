/**
 * M1p disposable, in-process OAuth login-context binding.
 * NOT an HTTP callback, cookie, browser session, real logout, distributed
 * actor directory or durable multi-process revocation mechanism.
 *
 * Each unforgeable local object owns a distinct M1m one-use state/PKCE map.
 * Invalid cross-context callbacks never consume a legitimate peer's state.
 * Cancelled contexts reject in-flight verified tokens BEFORE synchronous
 * mock PG16 session registration; no retry/reissue/fallback is introduced.
 */
import {createHash} from 'node:crypto';
import {createSyntheticPkceClient} from './m1m-synthetic-pkce-code-flow.mjs';

const sha=value=>createHash('sha256').update(value,'utf8').digest('hex');
const denied=()=>new Error('M1p synthetic bound login context denied');

export function m1pCiEnabled(){
  const env=process.env;
  return env.GITHUB_ACTIONS==='true' &&
    env.SAAS_EPHEMERAL_M1M_PKCE_CI==='true' &&
    env.SAAS_EPHEMERAL_M1N_TLS_CI==='true' &&
    env.SAAS_EPHEMERAL_M1O_TRUST_CI==='true' &&
    env.SAAS_EPHEMERAL_M1P_CONTEXT_CI==='true' &&
    env.NODE_ENV!=='production' &&
    !env.RAILWAY_PROJECT_ID && !env.RAILWAY_ENVIRONMENT &&
    !env.RAILWAY_SERVICE_ID;
}

export function createM1pBoundPkceClient(config){
  if(!m1pCiEnabled())throw denied();
  if(!config||typeof config!=='object'||
     typeof config.provisionSessionSync!=='function'||
     config.provisionSession!==undefined ||
     config.provisionSessionSync.constructor?.name==='AsyncFunction'){
    throw denied();
  }
  const {provisionSessionSync,...clientConfig}=config;
  const records=new WeakMap();
  let active=0;
  const ensure=context=>{
    if(!m1pCiEnabled()||!context||typeof context!=='object')
      throw denied();
    const row=records.get(context);
    if(!row||!row.active)throw denied();
    return row;
  };
  return Object.freeze({
    openContext(){
      if(!m1pCiEnabled()||active>=8)throw denied();
      const context=Object.freeze(Object.create(null));
      const row={active:true,pending:null,client:null};
      row.client=createSyntheticPkceClient({
        ...clientConfig,
        provisionSession(input){
          // Called only AFTER one-use PKCE token + pinned JWT + actor check
          // and BEFORE any DB registration. Cancellation during an earlier
          // await is observed here. Synchronous CI registrar prevents the
          // event loop from interleaving cancellation with enrollment.
          if(!row.active||!m1pCiEnabled())throw denied();
          const result=provisionSessionSync(input);
          if(result&&typeof result.then==='function')
            throw denied();
          return result;
        },
      });
      records.set(context,row);
      active++;
      return context; // Opaque reference: never placed in an OAuth URL.
    },
    begin(context){
      const row=ensure(context);
      if(row.pending!==null)throw denied(); // At most one pending login per context.
      const started=row.client.begin();
      const state=new URL(started.authorizationUrl).searchParams.get('state');
      if(!state||!/^[A-Za-z0-9_-]{43}$/.test(state))throw denied();
      row.pending=sha(state); // No PKCE verifier/state in public session fields.
      return started;
    },
    async complete(context,callbackUri){
      const row=ensure(context);
      if(row.pending===null||typeof callbackUri!=='string'||
         callbackUri.length>2048)throw denied();
      let callback;
      try{callback=new URL(callbackUri);}catch{throw denied();}
      const state=callback.searchParams.get('state');
      // Wrong context: fail without consuming either context's valid state.
      if(typeof state!=='string'||sha(state)!==row.pending)
        throw denied();
      // Single-use claim BEFORE any network/await, including bad callbacks.
      row.pending=null;
      try{
        const result=await row.client.complete(callbackUri);
        if(!row.active||!m1pCiEnabled())throw denied();
        return result;
      }catch{throw denied();}
    },
    cancelContext(context){
      const row=ensure(context);
      // Terminal cancellation of ONLY this pending/in-flight login context.
      // Already-issued PG sessions require M1k DB revoke, separately.
      row.active=false;
      row.pending=null;
      active--;
      return true;
    },
    stats(){
      return Object.freeze({activeContexts:active});
    },
  });
}

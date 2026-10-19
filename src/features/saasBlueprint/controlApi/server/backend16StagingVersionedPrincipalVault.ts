/**
 * Backend16.11: UNMOUNTED version-pinned, per-physical-LOGIN credential
 * source boundary for the staging-only Bun.SQL driver.
 *
 * This is a defensive adapter, NOT a secret store / live Vault, not a
 * credential provisioning service, and not approval to deploy staging.
 * The operator separately pins the manifest digest and supplies a trusted
 * private-network versioned secret reader. No HTTP, DB, Railway variables,
 * token inputs, secret enumeration, cache, retry, or logging exist here.
 */
import type {Backend16StagingPrincipalVault}
  from './backend16StagingBunPhysicalPgPool';

const LOGIN=/^[a-z][a-z0-9_]{2,62}$/;
const SECRET_ID=/^b16-stg-pg-[a-z0-9_-]{16,80}$/;
const VERSION=/^[a-f0-9]{32,64}$/;
const SHA256=/^[a-f0-9]{64}$/;
const PASSWORD=/^[\x21-\x7e]{32,256}$/;
const RESERVED=new Set([
  'postgres','saas_schema_migrator','saas_runtime_reader',
  'saas_runtime_writer',
]);
const MAX_PRINCIPALS=128;
const MIN_LEASE_MS=60_000;
const MAX_LEASE_MS=5*60_000;
const FETCH_TIMEOUT_MS=4500;
const ENTRY_KEYS='pgLogin,secretId,version';
const OPTIONS_KEYS='manifest,source';
const MANIFEST_KEYS='approvedManifestSha256,entries';
const RECORD_KEYS='expiresAtMs,password,username,version';

export type Backend16StagingVaultEntry=Readonly<{
  /** Server-reviewed physical PostgreSQL LOGIN, never supplied by HTTP. */
  pgLogin:string;
  /** Opaque, versioned external-secret locator selected from this manifest. */
  secretId:string;
  /** Exact immutable version; never "latest" or a mutable alias. */
  version:string;
}>;

export type Backend16OperatorVaultManifest=Readonly<{
  entries:readonly Backend16StagingVaultEntry[];
  /** Independent operator-approved SHA256 of canonical public manifest. */
  approvedManifestSha256:string;
}>;

export interface Backend16StagingVersionedSecretReader {
  /**
   * A separately authenticated secret service implementation. The runtime
   * caller must have get-by-id+exact-version permission only, never list,
   * create, update, delete, IAM, or arbitrary credential path capabilities.
   */
  readVersion(
    secretId:string,version:string,signal:AbortSignal,
  ):Promise<unknown>;
}

export interface Backend16StagingVersionedVaultOptions {
  readonly manifest:Backend16OperatorVaultManifest;
  readonly source:Backend16StagingVersionedSecretReader;
}

function refuse():never{
  throw new Error('Backend16 staging principal credential vault unavailable');
}
function goodLogin(login:string):boolean{
  return LOGIN.test(login)&&!RESERVED.has(login)&&
    !login.startsWith('pg_');
}
function clock(now:unknown):now is number{
  return typeof now==='number'&&Number.isSafeInteger(now)&&now>0;
}
function exactKeys(value:unknown,keys:string):boolean{
  if(value===null||typeof value!=='object'||Array.isArray(value))
    return false;
  // External provider records must be plain data, not accessor-bearing
  // objects that can change LOGIN, version or password between reads.
  const proto=Object.getPrototypeOf(value);
  if(proto!==Object.prototype&&proto!==null)return false;
  const props=Object.getOwnPropertyDescriptors(value);
  return Object.keys(props).sort().join(',')===keys &&
    Object.values(props).every(d=>'value' in d);
}
function digest(canonical:string):Promise<string>{
  // Inline TextEncoder yields a DOM-compatible BufferSource on the frontend
  // TypeScript project without adding Node or browser-insecure crypto shims.
  return crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical))
    .then(buffer=>Array.from(new Uint8Array(buffer),n=>
      n.toString(16).padStart(2,'0')).join(''));
}
function abortable<T>(promise:Promise<T>,signal:AbortSignal):Promise<T>{
  if(signal.aborted)return Promise.reject(new Error('vault aborted'));
  return new Promise<T>((resolve,reject)=>{
    let settled=false;
    const finish=()=>{
      if(settled)return false;
      settled=true;
      signal.removeEventListener('abort',onAbort);
      return true;
    };
    const onAbort=()=>{if(finish())reject(new Error('vault aborted'));};
    signal.addEventListener('abort',onAbort,{once:true});
    if(signal.aborted)onAbort();
    promise.then(value=>{if(finish())resolve(value);},
      error=>{if(finish())reject(error);});
  });
}

/**
 * Caller must supply TWO independently reviewed sources: the manifest and
 * its pinned digest. Both from the same untrusted request is not approval.
 *
 * SHA256's preimage is exactly:
 *   JSON.stringify({schema:'backend16-staging-vault-v1',
 *     entries:[[login,secretId,version],...]})
 * ordered lexicographically by pgLogin (ASCII). No passwords are in it.
 */
export async function createBackend16StagingVersionedPrincipalVault(
  options:Backend16StagingVersionedVaultOptions,
):Promise<Backend16StagingPrincipalVault>{
  try{
    // Snapshot approved inputs BEFORE the first await. An attacker must not
    // swap the operator pin or credential source while SHA256 is pending.
    // Extra fields including a caller-provided nowMs are never accepted.
    if(!exactKeys(options,OPTIONS_KEYS))refuse();
    const {manifest,source}=options;
    if(!exactKeys(manifest,MANIFEST_KEYS)||
       !Array.isArray(manifest.entries)||
       manifest.entries.length<1||
       manifest.entries.length>MAX_PRINCIPALS||
       typeof manifest.approvedManifestSha256!=='string'||
       !SHA256.test(manifest.approvedManifestSha256))refuse();
    const approvedManifestSha256=manifest.approvedManifestSha256;

    const entries:Backend16StagingVaultEntry[]=[];
    const ids=new Set<string>();
    let previous='';
    for(const item of manifest.entries){
      if(!exactKeys(item,ENTRY_KEYS))refuse();
      if(typeof item.pgLogin!=='string'||!goodLogin(item.pgLogin)||
         item.pgLogin<=previous||
         typeof item.secretId!=='string'||!SECRET_ID.test(item.secretId)||
         ids.has(item.secretId)||
         typeof item.version!=='string'||!VERSION.test(item.version))refuse();
      previous=item.pgLogin;
      ids.add(item.secretId);
      entries.push(Object.freeze({
        pgLogin:item.pgLogin,secretId:item.secretId,version:item.version,
      }));
    }
    const canonical=JSON.stringify({
      schema:'backend16-staging-vault-v1',
      entries:entries.map(item=>[item.pgLogin,item.secretId,item.version]),
    });
    // Snapshot all approved manifest data before invoking a provider getter:
    // synchronous provider code must not rewrite the pin or secret locations.
    const readVersion=source?.readVersion; // read exactly once, preserve receiver
    if(typeof readVersion!=='function')refuse();
    if(await digest(canonical)!==approvedManifestSha256)refuse();

    const lookup=new Map(entries.map(item=>[item.pgLogin,item] as const));

    return Object.freeze({
      async readPrincipal(login:string,requestSignal:AbortSignal){
        try{
          if(typeof login!=='string'||!goodLogin(login)||
             !requestSignal||requestSignal.aborted)refuse();
          const entry=lookup.get(login);
          if(!entry)refuse(); // no arbitrary secret-ID lookup or fallback
          const before=Date.now();
          if(!clock(before))refuse();
          const signal=AbortSignal.any([
            requestSignal,AbortSignal.timeout(FETCH_TIMEOUT_MS),
          ]);
          const raw=await abortable(Promise.resolve().then(()=>{
            if(signal.aborted)refuse();
            return readVersion.call(source,entry.secretId,entry.version,signal);
          }),signal);
          const after=Date.now();
          if(signal.aborted||!clock(after)||after<before||
             !exactKeys(raw,RECORD_KEYS))refuse();
          // Snapshot each external value exactly once, before validating;
          // no provider callback/getter may swap credentials after checking.
          const row=raw as Record<string,unknown>;
          const {username,password,version,expiresAtMs}=row;
          if(username!==login||version!==entry.version||
             typeof password!=='string'||!PASSWORD.test(password)||
             !clock(expiresAtMs)||
             expiresAtMs-after<=MIN_LEASE_MS||
             expiresAtMs-after>MAX_LEASE_MS)refuse();

          // Do not retain passwords, sessions, tenant IDs or provider rows in
          // this adapter. Every acquisition fetches the exact pinned version.
          // Password strings in JS cannot be reliably zeroized; this module
          // is not a substitute for real vault isolation and rotation.
          return Object.freeze({username:login,password});
        }catch{refuse();}
      },
    });
  }catch{refuse();}
}

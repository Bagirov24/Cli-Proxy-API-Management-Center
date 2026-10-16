/**
 * Backend 04: private, PostgreSQL-backed verified subject and bearer/session
 * lookup. This is NOT an IdP, session issuer, enrollment route or public API.
 *
 * The caller MUST verify the pinned JWT cryptographically before consulting
 * this directory. Session fingerprint MUST be SHA-256 of that full verified
 * access token. Roles and project writes still require independent current
 * membership and PG25/SQL026 signed write transaction checks.
 *
 * Connections must use a distinct least-privilege login which can SET ROLE
 * saas_m1_identity_resolver but cannot SET ROLE the project executor, access
 * private tables, make grants or execute provisioning/revocation functions.
 */
import type {VerifiedAccessIdentity} from './trustedAccessToken';
import type {TenantProjectWriteSessionAuthority} from './tenantProjectsWriteHttpHandler';

export const PG_IDENTITY_SQL=Object.freeze({
  begin:'BEGIN READ ONLY',
  role:'SET LOCAL ROLE saas_m1_identity_resolver',
  actor:'SELECT actor_id FROM saas_m1_api.resolve_verified_subject_actor($1::text,$2::text)',
  session:'SELECT session_id::text AS session_id, session_revision::text AS session_revision '+
    'FROM saas_m1_api.resolve_verified_project_session($1::text,$2::text,$3::text)',
  commit:'COMMIT',
  rollback:'ROLLBACK',
});
export type PgIdentityParam=string;
export type PgIdentityRow=Readonly<Record<string,unknown>>;
export interface PgIdentityConnection {
  query(sql:string,params:readonly PgIdentityParam[],signal:AbortSignal):
    Promise<{readonly rows:readonly PgIdentityRow[]}>;
  /** Must destroy the physical backend on discard, never return it to pool. */
  release(discard:boolean): void | Promise<void>;
}
export interface PgIdentityPool {
  connect(signal:AbortSignal):Promise<PgIdentityConnection>;
  /** Synchronous barrier: stop all reservations before async shutdown. */
  quarantine(reason:'acquire-uncertain'|'query-uncertain'|'release-uncertain'):void;
}
const ACTOR=/^[A-Za-z0-9_-]{1,128}$/;
const TENANT=/^[A-Za-z0-9_-]{1,64}$/;
const FINGERPRINT=/^[a-f0-9]{64}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function subject(value: unknown): value is string {
  return typeof value==='string' && value.length>=1 && value.length<=256 &&
    ![...value].some(c=>c.charCodeAt(0)<32||c.charCodeAt(0)===127);
}
function issuer(value:unknown): value is string {
  if(typeof value!=='string'||value.length<10||value.length>256)return false;
  try {
    const u=new URL(value);
    return u.protocol==='https:' && u.href===value &&
      !u.username&&!u.password&&!u.search&&!u.hash;
  }catch{return false;}
}

/** No process.env, DB credentials, actor IDs or SQL chosen by HTTP caller. */
export function createPgDurableIdentitySessionAuthority(pool:PgIdentityPool) {
  if(!pool||typeof pool.connect!=='function'||
     typeof pool.quarantine!=='function')
    throw new Error('Durable identity authority requires isolated PG pool');

  async function one(
    sql:string,params:readonly string[],signal:AbortSignal,
    validRow:(row:PgIdentityRow)=>boolean,
  ): Promise<readonly PgIdentityRow[]> {
    if(signal.aborted)throw new Error('Trusted identity request cancelled');
    let conn:PgIdentityConnection;
    try {conn=await pool.connect(signal);}
    catch {
      pool.quarantine('acquire-uncertain');
      throw new Error('Durable identity source unavailable');
    }
    let discard=true;
    let failed=false;
    let acceptedRows:readonly PgIdentityRow[]|null=null;
    try {
      if(signal.aborted)throw new Error('Trusted identity request cancelled');
      for(const q of [PG_IDENTITY_SQL.begin,PG_IDENTITY_SQL.role]){
        await conn.query(q,[],signal);
      }
      const result=await conn.query(sql,params,signal);
      // Validate the exact private SQL DTO BEFORE COMMIT. A malformed
      // row is an untrusted data boundary and poisons the physical pool.
      if(signal.aborted||!result||!Array.isArray(result.rows)||
         result.rows.length>1||
         (result.rows.length===1 && !validRow(result.rows[0])))
        throw new Error('Invalid identity result');
      await conn.query(PG_IDENTITY_SQL.commit,[],signal);
      if(signal.aborted)throw new Error('Identity response cancelled');
      acceptedRows=result.rows;
      discard=false;
    } catch {
      failed=true;
      // A lost COMMIT acknowledgement is UNKNOWN, not a rollback.
      // Quarantine synchronously and do NOT retry this transaction.
      pool.quarantine('query-uncertain');
      try {await conn.query(PG_IDENTITY_SQL.rollback,[],signal);}
      catch { /* connection is already quarantined */ }
    } finally {
      try {await conn.release(discard);}
      catch {
        failed=true;
        pool.quarantine('release-uncertain');
      }
    }
    // No return or throw from finally: release failure cannot accidentally
    // publish a previous successful read or suppress original uncertainty.
    if(failed || acceptedRows===null)
      throw new Error('Durable identity source unavailable');
    return acceptedRows;
  }

  const directory=Object.freeze({
    async resolveActorId(identity:VerifiedAccessIdentity):Promise<string|null>{
      if(!identity||!issuer(identity.issuer)||!subject(identity.subject))
        return null;
      const rows=await one(PG_IDENTITY_SQL.actor,
        [identity.issuer,identity.subject],new AbortController().signal,
        row=>Object.keys(row).sort().join(',')==='actor_id' &&
          typeof row.actor_id==='string'&&ACTOR.test(row.actor_id));
      return rows.length===0?null:rows[0].actor_id as string;
    },
  });
  const sessions:TenantProjectWriteSessionAuthority=Object.freeze({
    async resolve(input,signal){
      if(!input||!ACTOR.test(input.actorId)||!TENANT.test(input.tenantId)||
         !FINGERPRINT.test(input.tokenFingerprint)||signal.aborted)
        return null;
      const rows=await one(PG_IDENTITY_SQL.session,
        [input.actorId,input.tenantId,input.tokenFingerprint],signal,
        row=>Object.keys(row).sort().join(',')==='session_id,session_revision' &&
          typeof row.session_id==='string'&&UUID.test(row.session_id) &&
          typeof row.session_revision==='string' &&
          /^[1-9][0-9]{0,15}$/.test(row.session_revision) &&
          Number.isSafeInteger(Number(row.session_revision)));
      if(rows.length===0)return null;
      return Object.freeze({
        sessionId:rows[0].session_id as string,
        sessionRevision:Number(rows[0].session_revision),
      });
    },
  });
  return Object.freeze({directory,sessions});
}

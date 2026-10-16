/**
 * M1l: ephemeral MOCK OIDC discovery/JWKS over real 127.0.0.1 HTTP, rotating
 * RS256 signing public keys A -> A+B -> B. Real client POST requests are
 * checked by M1i HTTP+trusted actor, M1k signed PG16 session epoch FOR SHARE,
 * and M1g mandatory project+audit UUID COMMIT, preceded by local M1h fsync.
 *
 * Synthetic GitHub PostgreSQL16 only. No real IdP, refresh token, callback,
 * SSO session, HSM, off-host WORM, production network or safe retry.
 */
import { createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createM1ProjectHttpHandler } from
  '../../src/features/saasBlueprint/controlApi/server/m1ProjectHttpHandler.ts';
import { createSyntheticOidcKeyRotation } from
  './m1l-synthetic-oidc-rotation.mjs';
import { startWitness, runOffline } from './verify-m1h-precommit-intent.mjs';

const ISSUER = 'https://m1l.synthetic-oidc.invalid/realm';
const AUDIENCE = 'saas-m1l-ci';
const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROJECT = /^m1l-[a-z-]{1,48}$/;
const sha256 = token => createHash('sha256').update(token).digest('hex');
const bytes = x => new TextEncoder().encode(x);
const b64 = x => Buffer.from(x).toString('base64url');
const NOW = 1_800_000_000;

function sqlScalar(assert, statement) {
  const proc = Bun.spawnSync(
    ['psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-c',statement],
    { stdout:'pipe', stderr:'pipe' }
  );
  assert.equal(proc.exitCode,0,'M1l privileged PG16 fixture failed');
  return new TextDecoder().decode(proc.stdout).trim().split('\n')[0].trim();
}
function projectCounts(assert, project) {
  assert.ok(PROJECT.test(project));
  return sqlScalar(assert,
    "SELECT (SELECT COUNT(*) FROM saas_m1_private.projects " +
    "WHERE tenant_id='demo-north' AND project_id='" + project + "')::TEXT || ':' || " +
    "(SELECT COUNT(*) FROM saas_m1_private.project_write_audit_outbox " +
    "WHERE tenant_id='demo-north' AND project_id='" + project + "')::TEXT || ':' || " +
    "(SELECT COUNT(*) FROM saas_m1_private.project_attempt_bindings b " +
    "JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id " +
    "WHERE a.tenant_id='demo-north' AND a.project_id='" + project + "')::TEXT"
  );
}
function registerSession(assert, id) {
  assert.ok(V4.test(id));
  const row=sqlScalar(assert,
    "INSERT INTO saas_m1_private.project_session_epochs " +
    "(session_id,actor_id,tenant_id,revision,status) VALUES('" +
    id + "'::UUID,'actor-north','demo-north',1,'active') RETURNING status");
  assert.equal(row,'active');
}
function revokeSession(assert, id) {
  assert.ok(V4.test(id));
  assert.equal(sqlScalar(assert,
    "UPDATE saas_m1_private.project_session_epochs " +
    "SET status='revoked',revision=revision+1 " +
    "WHERE session_id='" + id + "'::UUID AND status='active' " +
    "RETURNING status"), 'revoked');
}
function jwk(key, kid) {
  return { alg:'RS256', e:key.e, key_ops:['verify'],
    kid,kty:'RSA',n:key.n,use:'sig' };
}
async function keypair() {
  const key=await crypto.subtle.generateKey({
    name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
    publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256',
  },true,['sign','verify']);
  return { key, publicJwk:await crypto.subtle.exportKey('jwk',key.publicKey) };
}
async function tokenFor(keys, kid, overrides={}) {
  const head=b64(bytes(JSON.stringify({alg:'RS256',typ:'at+jwt',kid})));
  const claims=b64(bytes(JSON.stringify({
    iss:ISSUER,aud:AUDIENCE,sub:'north',
    iat:NOW-30,exp:NOW+120,
    // These claims are FORGERY TESTS, not sources for session/role.
    actorId:'actor-orbit',tenantId:'demo-orbit',
    role:'tenant-owner',sid:'FAKE_HTTP_SID',
    ...overrides,
  })));
  const signature=await crypto.subtle.sign('RSASSA-PKCS1-v1_5',
    keys[kid].key.privateKey,bytes(head+'.'+claims));
  return head+'.'+claims+'.'+b64(signature);
}

export async function verifyM1l({assert,makeDriver,actors}) {
  if (process.env.GITHUB_ACTIONS!=='true' ||
      process.env.SAAS_EPHEMERAL_M1_PG_CI!=='true' ||
      process.env.SAAS_EPHEMERAL_M1G_ATTEMPT_CI!=='true' ||
      process.env.SAAS_EPHEMERAL_M1_HTTP_CI!=='true' ||
      process.env.SAAS_EPHEMERAL_M1L_OIDC_CI!=='true' ||
      process.env.SAAS_EPHEMERAL_M1K_SESSION_CI==='true' ||
      process.env.SAAS_EPHEMERAL_M1J_HTTP_PG_CI==='true' ||
      process.env.PGHOST!=='127.0.0.1' ||
      process.env.PGPORT!=='5432' ||
      process.env.PGDATABASE!=='saas_ephemeral_test' ||
      process.env.NODE_ENV==='production' ||
      process.env.RAILWAY_PROJECT_ID ||
      process.env.RAILWAY_ENVIRONMENT ||
      process.env.RAILWAY_SERVICE_ID) {
    throw new Error('M1l synthetic issuer+PG16 requires separate GitHub CI');
  }
  console.info('STEP M1l: real loopback synthetic OIDC JWKS rollover -> signed PG16 session fence');
  const stamp=crypto.randomUUID();
  const witness=await startWitness(assert,
    '/tmp/saas-m1h-intent-'+stamp+'.jsonl');
  const keys={ A:await keypair(), B:await keypair() };
  let kids=['A'];
  let documentIssuer=ISSUER;
  const issuerRequests=[];
  let oidcServer, projectServer, holdRace=null;
  const attempts=[];
  const sessions=new Map();
  const context=new AsyncLocalStorage();
  const driver=makeDriver({attemptTagging:true,sessionGuard:true});
  let signerStopped=false;
  try {
    oidcServer=Bun.serve({
      hostname:'127.0.0.1',port:0,
      fetch(request){
        const pathname=new URL(request.url).pathname;
        issuerRequests.push(pathname);
        if(pathname==='/.well-known/openid-configuration'){
          return Response.json({
            id_token_signing_alg_values_supported:['RS256'],
            issuer:documentIssuer,
            jwks_uri:'http://127.0.0.1:'+oidcServer.port+'/jwks',
          });
        }
        if(pathname==='/jwks')return Response.json({
          keys:kids.map(kid=>jwk(keys[kid].publicJwk,kid)),
        });
        return new Response('no such resource',{status:404});
      },
    });
    const issuerUrl='http://127.0.0.1:'+oidcServer.port;
    const oidc=createSyntheticOidcKeyRotation({
      issuer:ISSUER,audience:AUDIENCE,
      discoveryUrl:issuerUrl+'/.well-known/openid-configuration',
      jwksUrl:issuerUrl+'/jwks',nowSeconds:()=>NOW,
    });
    const directory={
      async resolveActorId(identity){
        return identity.issuer===ISSUER && identity.subject==='north'
          ? 'actor-north' : null;
      },
    };
    const verifier={
      async verifyAccessToken(token){
        // Reject retired/unknown issuer keys BEFORE consulting the private
        // token-fingerprint registry. Neither JWT sid/role nor HTTP claims
        // choose the database session ID.
        const identity=await oidc.verifyAccessToken(token);
        if(!identity)return null;
        const privateSession=sessions.get(sha256(token));
        const ctx=context.getStore();
        // The existing M1a boundary deliberately re-verifies the same
        // bearer after actor lookup. Permit that exact immutable session
        // only; a request cannot change UUID/epoch between both checks.
        if(!privateSession||!ctx ||
           (ctx.session && (ctx.session.id!==privateSession.id ||
             ctx.session.revision!==privateSession.revision ||
             ctx.session.actorId!==privateSession.actorId ||
             ctx.session.tenantId!==privateSession.tenantId))) return null;
        ctx.session=privateSession;
        return identity;
      },
    };
    const writer={
      async execute(input){
        const session=context.getStore()?.session;
        if(!session || !V4.test(session.id) ||
            session.actorId!==input.scope.actorId ||
            session.tenantId!==input.scope.tenantId ||
            !Number.isSafeInteger(session.revision)) {
          throw new Error('M1l trusted issuer session unavailable');
        }
        const attemptId=crypto.randomUUID();
        const entry={
          attemptId, actorId:input.scope.actorId,
          tenantId:input.scope.tenantId, projectId:input.projectId,
          operation:input.operation,
          expectedVersion:input.expectedVersion??null,
        };
        const receipt=await witness.prepare(entry);
        assert.equal(receipt.attemptId,attemptId);
        attempts.push({...entry,sessionId:session.id});
        if(holdRace && input.projectId==='m1l-race-a') {
          holdRace.entered();
          await holdRace.releasePromise;
        }
        return driver.execute({
          ...input,attemptId,sessionId:session.id,sessionRevision:session.revision,
        });
      },
    };
    const handler=createM1ProjectHttpHandler({
      tokens:verifier, directory, actors, writer,
      newCorrelationId:()=> 'm1l-server-correlation',
    },{enabledForDisposableCi:true});
    projectServer=Bun.serve({
      hostname:'127.0.0.1',port:0,
      fetch:request=>context.run({session:null},()=>handler(request)),
    });
    const apiUrl='http://127.0.0.1:'+projectServer.port;
    async function send(bearer,project){
      assert.ok(PROJECT.test(project));
      const response=await fetch(apiUrl+
        '/control-api/v1/tenants/demo-north/metadata/projects/'+project,{
        method:'POST',
        headers:{Authorization:'Bearer '+bearer,
          'Content-Type':'application/json'},
        body:JSON.stringify({name:'M1l synthetic OIDC project'}),
        signal:AbortSignal.timeout(12000),
      });
      const serialized=JSON.stringify(await response.json());
      assert.ok(!serialized.includes(bearer));
      assert.ok(response.headers.get('Cache-Control')?.includes('no-store'));
      assert.equal(response.headers.get('Set-Cookie'),null);
      assert.equal(response.headers.get('Access-Control-Allow-Origin'),null);
      return response.status;
    }
    const a=await tokenFor(keys,'A');
    const b=await tokenFor(keys,'B');
    const sessionA={id:crypto.randomUUID(),revision:1,
      actorId:'actor-north',tenantId:'demo-north'};
    const sessionB={id:crypto.randomUUID(),revision:1,
      actorId:'actor-north',tenantId:'demo-north'};
    for(const s of [sessionA,sessionB])registerSession(assert,s.id);
    sessions.set(sha256(a),Object.freeze(sessionA));
    sessions.set(sha256(b),Object.freeze(sessionB));

    assert.deepEqual(await oidc.reload(1),{revision:1,keyIds:['A']});
    assert.equal((await send(a,'m1l-a-first')),201);
    assert.equal(projectCounts(assert,'m1l-a-first'),'1:1:1');
    assert.equal((await send(b,'m1l-b-before-rotation')),401);
    assert.equal(projectCounts(assert,'m1l-b-before-rotation'),'0:0:0');

    kids=['A','B'];
    assert.deepEqual(await oidc.reload(2),{revision:2,keyIds:['A','B']});
    assert.equal((await send(b,'m1l-b-after-rotation')),201);
    assert.equal((await send(a,'m1l-a-overlap')),201);
    // A valid but UNREGISTERED B-signed token is never allowed to take a
    // session from JWT actor/role/sid claims (the private registry is exact).
    const unregistered=await tokenFor(keys,'B',{jti:crypto.randomUUID()});
    assert.equal((await send(unregistered,'m1l-unknown-session')),401);
    assert.equal(projectCounts(assert,'m1l-unknown-session'),'0:0:0');

    // A real HTTP A request has PASSED pinned RS256 + private session
    // mapping, and fsynced a pre-COMMIT intent, then pauses BEFORE PG
    // reservation. Server activates B-only JWKS while privileged fixture
    // revokes session A in PG. Stale in-flight A MUST be denied by DB.
    let entered;
    const enteredPromise=new Promise(resolve=>{entered=resolve;});
    let release;
    const releasePromise=new Promise(resolve=>{release=resolve;});
    holdRace={entered,releasePromise};
    const pending=send(a,'m1l-race-a');
    try {
      await Promise.race([
        enteredPromise,
        new Promise((_,reject)=>setTimeout(
          ()=>reject(new Error('M1l real HTTP did not reach post-auth writer')),7000)),
      ]);
      kids=['B'];
      assert.deepEqual(await oidc.reload(3),{revision:3,keyIds:['B']});
      revokeSession(assert,sessionA.id);
      release();
      assert.equal(await pending,404);
    } finally {
      release();
      holdRace=null;
    }
    assert.equal(projectCounts(assert,'m1l-race-a'),'0:0:0');
    assert.equal((await send(a,'m1l-retired-a')),401);
    assert.equal((await send(b,'m1l-b-live')),201);

    // Discovery mismatch QUARANTINES all tokens and NEVER retrieves an
    // attacker-supplied JWT jku/x5u/JWKS URL. Requires fresh valid snapshot.
    const before=driver.stats().reservations;
    documentIssuer='https://attacker.invalid/';
    await assert.rejects(()=>oidc.reload(4),/quarantined/);
    assert.equal((await send(b,'m1l-b-discovery-down')),401);
    assert.equal(driver.stats().reservations,before);
    assert.equal(projectCounts(assert,'m1l-b-discovery-down'),'0:0:0');
    documentIssuer=ISSUER;
    assert.deepEqual(await oidc.reload(5),{revision:5,keyIds:['B']});
    assert.equal((await send(b,'m1l-b-recovered')),201);

    // Attempt to roll keyset BACK to retired A: QUARANTINE, never
    // silently reaccept previously trusted A even if exp is in future.
    kids=['A'];
    await assert.rejects(()=>oidc.reload(6),/quarantined/);
    assert.equal((await send(b,'m1l-b-rollback-denied')),401);
    assert.equal((await send(a,'m1l-a-rollback-denied')),401);
    assert.equal(projectCounts(assert,'m1l-b-rollback-denied'),'0:0:0');

    // Reestablish B only and fail closed on unavailable pre-COMMIT signer.
    kids=['B'];
    await oidc.reload(7);
    await witness.stop();
    signerStopped=true;
    const noSigner=driver.stats().reservations;
    assert.equal((await send(b,'m1l-signer-dead')),503);
    assert.equal(driver.stats().reservations,noSigner);
    assert.equal(projectCounts(assert,'m1l-signer-dead'),'0:0:0');

    // Exactly SIX authorized signed precommit attempts: 5 committed and
    // 1 revoked after HTTP authentication before signed PG16 COMMIT.
    assert.equal(attempts.length,6);
    const proof=runOffline(assert,'/tmp/saas-m1h-intent-'+stamp+'.jsonl',
      witness.publicKey,6);
    assert.ok(proof && proof.count===6);
    assert.deepEqual(proof.attempts,
      attempts.map(({sessionId,...entry})=>entry));
    assert.equal(sqlScalar(assert,
      "SELECT COUNT(*) FROM saas_m1_private.project_session_proofs p " +
      "JOIN saas_m1_private.project_write_audit_outbox a " +
      "ON a.pg_txid=p.pg_txid WHERE a.project_id LIKE 'm1l-%'"),'5');
    assert.equal(sqlScalar(assert,
      "SELECT status||':'||revision::TEXT FROM " +
      "saas_m1_private.project_session_epochs WHERE session_id='" +
      sessionA.id+"'::UUID"),'revoked:2');
    assert.equal(sqlScalar(assert,
      "SELECT status||':'||revision::TEXT FROM " +
      "saas_m1_private.project_session_epochs WHERE session_id='" +
      sessionB.id+"'::UUID"),'active:1');
    assert.ok(issuerRequests.length>=12 &&
      issuerRequests.every(p=>p==='/jwks' ||
        p==='/.well-known/openid-configuration'));
    console.info(
      'PASS M1l: bounded real synthetic OIDC metadata/JWKS A->A+B->B, ' +
      'retired/rollback/foreign issuer QUARANTINE; real HTTP JWT precheck ' +
      '-> M1h fsync -> signed PG16 M1k session epoch/M1d audit/M1g UUID; ' +
      'in-flight verified A revoked BEFORE COMMIT denies 0/0/0, ' +
      'B unaffected; no live OIDC/SSO/refresh/WORM/retry/deploy'
    );
  } finally {
    if(holdRace)holdRace=null;
    projectServer?.stop(true);
    oidcServer?.stop(true);
    if(!signerStopped)await witness.stop();
    await driver.close();
  }
}

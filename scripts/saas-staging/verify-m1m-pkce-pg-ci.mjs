/**
 * M1m disposable GitHub PG16 E2E:
 * REAL loopback OAuth authorization-code+PKCE S256 -> pinned M1l mock JWKS
 * -> private issuer/subject actor -> PG16 session UUID/revision ->
 * real M1i HTTP write -> fsynced M1h PRE-COMMIT intent -> signed M1k
 * session + M1d tenant locks -> M1c audit/M1g attempt COMMIT.
 *
 * No real IdP/PKCE callback deployment, refresh tokens, public listener,
 * off-host independent journal, production DB/keys, reissue or auto-retry.
 */
import { createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createSyntheticPkceClient,createSyntheticPkceIssuer } from
  './m1m-synthetic-pkce-code-flow.mjs';
import { createSyntheticOidcKeyRotation } from
  './m1l-synthetic-oidc-rotation.mjs';
import { createM1ProjectHttpHandler } from
  '../../src/features/saasBlueprint/controlApi/server/m1ProjectHttpHandler.ts';
import { startWitness,runOffline } from './verify-m1h-precommit-intent.mjs';

const ISSUER='https://m1m-ci-issuer.invalid/realm';
const AUDIENCE='saas-m1m-ci';
const CLIENT_ID='m1m-ephemeral-client';
const NOW=1_800_000_000;
const V4=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROJECT=/^m1m-[a-z-]{1,48}$/;
const sha=value=>createHash('sha256').update(value).digest('hex');
function pg(assert,sql){
  const command=Bun.spawnSync(
    ['psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-c',sql],
    { stdout:'pipe',stderr:'pipe' });
  assert.equal(command.exitCode,0,'M1m disposable privileged PG16 fixture failed');
  return new TextDecoder().decode(command.stdout).trim().split('\n')[0].trim();
}
function register(assert,id){
  assert.ok(V4.test(id));
  assert.equal(pg(assert,
    "INSERT INTO saas_m1_private.project_session_epochs "+
    "(session_id,actor_id,tenant_id,revision,status) VALUES ('"+
    id+"'::UUID,'actor-north','demo-north',1,'active') RETURNING status"),
    'active');
}
function revoke(assert,id){
  assert.ok(V4.test(id));
  assert.equal(pg(assert,
    "UPDATE saas_m1_private.project_session_epochs "+
    "SET status='revoked',revision=revision+1 WHERE session_id='"+
    id+"'::UUID AND status='active' RETURNING status"),'revoked');
}
function evidence(assert,name){
  assert.ok(PROJECT.test(name));
  return pg(assert,
    "SELECT (SELECT COUNT(*) FROM saas_m1_private.projects "+
    "WHERE tenant_id='demo-north' AND project_id='"+name+"')::TEXT || ':' || "+
    "(SELECT COUNT(*) FROM saas_m1_private.project_write_audit_outbox "+
    "WHERE tenant_id='demo-north' AND project_id='"+name+"')::TEXT || ':' || "+
    "(SELECT COUNT(*) FROM saas_m1_private.project_attempt_bindings b "+
    "JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id "+
    "WHERE a.tenant_id='demo-north' AND a.project_id='"+name+"')::TEXT");
}
export async function verifyM1m({assert,makeDriver,actors}){
  if(process.env.GITHUB_ACTIONS!=='true'||
     process.env.SAAS_EPHEMERAL_M1_PG_CI!=='true'||
     process.env.SAAS_EPHEMERAL_M1G_ATTEMPT_CI!=='true'||
     process.env.SAAS_EPHEMERAL_M1_HTTP_CI!=='true'||
     process.env.SAAS_EPHEMERAL_M1M_PKCE_CI!=='true'||
     process.env.SAAS_EPHEMERAL_M1K_SESSION_CI==='true'||
     process.env.SAAS_EPHEMERAL_M1L_OIDC_CI==='true'||
     process.env.SAAS_EPHEMERAL_M1J_HTTP_PG_CI==='true'||
     process.env.SAAS_EPHEMERAL_M1H_INTENT_CI==='true'||
     process.env.PGHOST!=='127.0.0.1'||
     process.env.PGPORT!=='5432'||
     process.env.PGDATABASE!=='saas_ephemeral_test'||
     process.env.NODE_ENV==='production'||
     process.env.RAILWAY_PROJECT_ID||
     process.env.RAILWAY_ENVIRONMENT||
     process.env.RAILWAY_SERVICE_ID){
    throw new Error('M1m OAuth/PG16 proof denied outside disposable GitHub CI');
  }
  console.info('STEP M1m: real mock OAuth PKCE code/state -> pinned JWT -> signed PG16 session');
  const stamp=crypto.randomUUID();
  const journal='/tmp/saas-m1h-intent-'+stamp+'.jsonl';
  const witness=await startWitness(assert,journal);
  let mockIssuer=null, issuerServer=null, projectServer=null,hold=null;
  const registry=new Map();
  const context=new AsyncLocalStorage();
  const attempts=[];
  const driver=makeDriver({attemptTagging:true,sessionGuard:true});
  try{
    const rsa=await crypto.subtle.generateKey({
      name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
      publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256',
    },true,['sign','verify']);
    const publicJwk=await crypto.subtle.exportKey('jwk',rsa.publicKey);
    issuerServer=Bun.serve({
      hostname:'127.0.0.1',port:0,
      fetch:req=>mockIssuer?.handle(req)??new Response('',{status:503}),
    });
    const issuerBase='http://127.0.0.1:'+issuerServer.port;
    const oidc=createSyntheticOidcKeyRotation({
      issuer:ISSUER,audience:AUDIENCE,nowSeconds:()=>NOW,
      discoveryUrl:issuerBase+'/.well-known/openid-configuration',
      jwksUrl:issuerBase+'/jwks',
    });
    const trustedTokens={
      async verifyAccessToken(token){
        const identity=await oidc.verifyAccessToken(token);
        if(!identity)return null;
        const pinned=registry.get(sha(token));
        const ctx=context.getStore();
        if(!pinned||!ctx||
           (ctx.session&&(ctx.session.id!==pinned.id||
             ctx.session.revision!==pinned.revision||
             ctx.session.actorId!==pinned.actorId||
             ctx.session.tenantId!==pinned.tenantId)))return null;
        ctx.session=pinned;
        return identity;
      },
    };
    const writer={
      async execute(input){
        const session=context.getStore()?.session;
        if(!session||!V4.test(session.id)||
           session.actorId!==input.scope.actorId||
           session.tenantId!==input.scope.tenantId||
           !Number.isSafeInteger(session.revision))throw new Error(
             'M1m trusted login-to-session binding absent');
        const attemptId=crypto.randomUUID();
        const entry={
          attemptId,actorId:input.scope.actorId,
          tenantId:input.scope.tenantId,projectId:input.projectId,
          operation:input.operation,
          expectedVersion:input.expectedVersion??null,
        };
        const receipt=await witness.prepare(entry);
        assert.equal(receipt.attemptId,attemptId);
        attempts.push({...entry,sessionId:session.id});
        if(hold&&input.projectId==='m1m-race-revoked'){
          hold.enter();
          await hold.resume;
        }
        return driver.execute({
          ...input,attemptId,sessionId:session.id,
          sessionRevision:session.revision,
        });
      },
    };
    const directory={
      async resolveActorId(identity){
        return identity.issuer===ISSUER && identity.subject==='north'
          ? 'actor-north':null;
      },
    };
    const handler=createM1ProjectHttpHandler({
      tokens:trustedTokens,directory,actors,writer,
      newCorrelationId:()=> 'm1m-server-correlation',
    },{enabledForDisposableCi:true});
    projectServer=Bun.serve({
      hostname:'127.0.0.1',port:0,
      fetch:req=>context.run({session:null},()=>handler(req)),
    });
    const projectBase='http://127.0.0.1:'+projectServer.port;
    const redirectUri=projectBase+'/oauth/callback'; // NOT mounted
    mockIssuer=createSyntheticPkceIssuer({
      issuer:ISSUER,audience:AUDIENCE,origin:issuerBase,
      clientId:CLIENT_ID,redirectUri,privateKey:rsa.privateKey,
      publicJwk,nowSeconds:()=>NOW,
    });
    assert.deepEqual(await oidc.reload(1),{revision:1,keyIds:['M1m']});
    const client=createSyntheticPkceClient({
      issuer:ISSUER,clientId:CLIENT_ID,redirectUri,
      authorizationUrl:issuerBase+'/authorize',
      tokenUrl:issuerBase+'/token',tokenVerifier:oidc,
      nowSeconds:()=>NOW,
      resolveActorId:directory.resolveActorId,
      async provisionSession({token,actorId}){
        assert.equal(actorId,'actor-north');
        const item=Object.freeze({
          id:crypto.randomUUID(),revision:1,
          actorId,tenantId:'demo-north',
        });
        register(assert,item.id);
        registry.set(sha(token),item);
        return item;
      },
    });
    async function authorize(){
      const flow=client.begin();
      const res=await fetch(flow.authorizationUrl,{redirect:'manual'});
      assert.equal(res.status,302);
      const callback=res.headers.get('location');
      assert.ok(callback?.startsWith(redirectUri+'?'));
      assert.ok(!callback.includes('access_token'));
      return callback;
    }
    async function login(){
      const callback=await authorize();
      const result=await client.complete(callback);
      assert.equal(result.actorId,'actor-north');
      assert.ok(V4.test(result.sessionId));
      assert.equal(result.tenantId,'demo-north');
      await assert.rejects(()=>client.complete(callback),
        /M1m synthetic OAuth authorization denied/);
      return result;
    }
    async function post(loginSession,project){
      assert.ok(PROJECT.test(project));
      const response=await fetch(projectBase+
        '/control-api/v1/tenants/demo-north/metadata/projects/'+project,{
        method:'POST',
        headers:{ Authorization:'Bearer '+loginSession.accessToken,
          'Content-Type':'application/json' },
        body:JSON.stringify({name:'M1m synthetic PKCE project'}),
        signal:AbortSignal.timeout(12000),
      });
      const body=JSON.stringify(await response.json());
      assert.ok(!body.includes(loginSession.accessToken));
      assert.equal(response.headers.get('Set-Cookie'),null);
      assert.equal(response.headers.get('Access-Control-Allow-Origin'),null);
      assert.ok(response.headers.get('Cache-Control')?.includes('no-store'));
      return response.status;
    }

    // Each real one-shot code exchange provisions ONE fresh private PG16
    // session. Both logins resolve the SAME server-held actor; JWT role/sid
    // forgery never supplies this UUID.
    const a=await login(),b=await login(),c=await login();
    assert.notEqual(a.sessionId,b.sessionId);
    assert.notEqual(b.sessionId,c.sessionId);
    assert.equal(mockIssuer.stats().redeemedCodes,3);
    assert.equal(registry.size,3);
    assert.equal((await post(a,'m1m-a-first')),201);
    assert.equal((await post(b,'m1m-b-first')),201);

    // Forged callback state and an OAuth error must not provision any
    // session, touch PG or trigger a second code exchange.
    const thirdParty=await authorize();
    const wrong=new URL(thirdParty);
    wrong.searchParams.set('state','A'.repeat(43));
    await assert.rejects(()=>client.complete(wrong.href),
      /M1m synthetic OAuth authorization denied/);
    const failure=new URL(redirectUri);
    failure.searchParams.set('state',new URL(thirdParty).searchParams.get('state'));
    failure.searchParams.set('error','access_denied');
    await assert.rejects(()=>client.complete(failure.href),
      /M1m synthetic OAuth authorization denied/);
    await assert.rejects(()=>client.complete(thirdParty),
      /M1m synthetic OAuth authorization denied/);
    assert.equal(registry.size,3);

    // Critical race: an actual C-session bearer was verified twice by
    // M1a, passed HTTP authorization and fsynced a separate PRE-COMMIT
    // intent; before ANY PG reservation, privileged fixture revokes C.
    // The signed M1k session row lock must reject the in-flight write.
    let entered;
    const reached=new Promise(resolve=>{entered=resolve;});
    let release;
    const released=new Promise(resolve=>{release=resolve;});
    hold={enter:entered,resume:released};
    const inFlight=post(c,'m1m-race-revoked');
    try{
      await Promise.race([reached,new Promise((_,reject)=>setTimeout(
        ()=>reject(new Error('M1m HTTP did not reach signed write gate')),8000))]);
      revoke(assert,c.sessionId);
      release();
      assert.equal(await inFlight,404);
    }finally{
      release();
      hold=null;
    }
    assert.equal(evidence(assert,'m1m-race-revoked'),'0:0:0');
    revoke(assert,a.sessionId);
    assert.equal((await post(a,'m1m-a-revoked')),404);
    assert.equal(evidence(assert,'m1m-a-revoked'),'0:0:0');
    assert.equal((await post(b,'m1m-b-after-revoke')),201);
    assert.equal(evidence(assert,'m1m-a-first'),'1:1:1');
    assert.equal(evidence(assert,'m1m-b-first'),'1:1:1');
    assert.equal(evidence(assert,'m1m-b-after-revoke'),'1:1:1');

    // Exactly 5 precommit signed intents: 3 committed and 2 rejected by
    // a REAL PG session revocation, NEVER retried. The signer and database
    // share one CI trust domain (not WORM).
    assert.equal(attempts.length,5);
    await witness.stop();
    const verification=runOffline(assert,journal,witness.publicKey,5);
    assert.ok(verification&&verification.count===5);
    assert.deepEqual(verification.attempts,
      attempts.map(({sessionId,...entry})=>entry));
    assert.equal(pg(assert,
      "SELECT COUNT(*) FROM saas_m1_private.project_session_proofs p "+
      "JOIN saas_m1_private.project_write_audit_outbox a "+
      "ON a.pg_txid=p.pg_txid WHERE a.project_id LIKE 'm1m-%'"),'3');
    const held=driver.stats().reservations;
    assert.equal((await post(b,'m1m-signer-dead')),503);
    assert.equal(driver.stats().reservations,held);
    assert.equal(evidence(assert,'m1m-signer-dead'),'0:0:0');
    assert.equal(mockIssuer.stats().redeemedCodes,3);
    console.info(
      'PASS M1m: real synthetic OAuth code+PKCE S256/state, one-time '+
      'callback -> pinned RS256 -> server-provisioned PG16 UUID session; '+
      'signed HTTP project/audit/UUID 3/3/3; revoked in-flight C and A '+
      'after login 404 0/0/0, B remains active, signer loss 503/0 PG '+
      'reservation, no refresh/login deployment/WORM/retry'
    );
  }finally{
    if(hold)hold=null;
    projectServer?.stop(true);
    issuerServer?.stop(true);
    await witness.stop();
    await driver.close();
  }
}

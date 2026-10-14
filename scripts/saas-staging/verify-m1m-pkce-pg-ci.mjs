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
import { createM1pBoundPkceClient } from './m1p-bound-pkce-login-context.mjs';
import { createM1oExplicitTrustRotation } from './m1o-explicit-trust-rotation.mjs';
import { createServer } from 'node:https';
import { createDisposableM1nTlsFixture } from './m1n-ephemeral-tls-fixture.mjs';
import {
  createM1nPinnedHttpsTransport,loadM1nVerifiedOidc,
} from './m1n-synthetic-https-trust.mjs';
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
const PROJECT=/^m1[mnop]-[a-z-]{1,48}$/;
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
export async function verifyM1m({assert,makeDriver,actors,httpsMode=false,trustEpochMode=false,loginContextMode=false}){
  if(process.env.GITHUB_ACTIONS!=='true'||
     process.env.SAAS_EPHEMERAL_M1_PG_CI!=='true'||
     process.env.SAAS_EPHEMERAL_M1G_ATTEMPT_CI!=='true'||
     process.env.SAAS_EPHEMERAL_M1_HTTP_CI!=='true'||
     process.env.SAAS_EPHEMERAL_M1M_PKCE_CI!=='true'||
     process.env.SAAS_EPHEMERAL_M1K_SESSION_CI==='true'||
     process.env.SAAS_EPHEMERAL_M1L_OIDC_CI!=='true'||
     process.env.SAAS_EPHEMERAL_M1J_HTTP_PG_CI==='true'||
     process.env.SAAS_EPHEMERAL_M1H_INTENT_CI==='true'||
     (loginContextMode&&(!trustEpochMode||!httpsMode||
       process.env.SAAS_EPHEMERAL_M1P_CONTEXT_CI!=='true'))||
     (trustEpochMode&&(!httpsMode||process.env.SAAS_EPHEMERAL_M1O_TRUST_CI!=='true'))||
      (httpsMode&&process.env.SAAS_EPHEMERAL_M1N_TLS_CI!=='true')||
     (!httpsMode&&process.env.SAAS_EPHEMERAL_M1N_TLS_CI==='true')||
     process.env.PGHOST!=='127.0.0.1'||
     process.env.PGPORT!=='5432'||
     process.env.PGDATABASE!=='saas_ephemeral_test'||
     process.env.NODE_ENV==='production'||
     process.env.RAILWAY_PROJECT_ID||
     process.env.RAILWAY_ENVIRONMENT||
     process.env.RAILWAY_SERVICE_ID){
    throw new Error('M1m OAuth/PG16 proof denied outside disposable GitHub CI');
  }
  console.info(loginContextMode
    ? 'STEP M1p: bound login contexts, pre-enrollment cancellation, HTTPS PG16'
    : trustEpochMode
    ? 'STEP M1o: explicit HTTPS trust epoch -> PKCE -> signed PG16'
    : httpsMode
    ? 'STEP M1n: real pinned HTTPS IdP CA/SAN/SPKI -> PKCE/state -> signed PG16'
    : 'STEP M1m: real mock OAuth PKCE code/state -> pinned JWT -> signed PG16 session');
  const prefix=loginContextMode?'m1p':trustEpochMode?'m1o':httpsMode?'m1n':'m1m';
  const project=suffix=>prefix+'-'+suffix;
  const stamp=crypto.randomUUID();
  const journal='/tmp/saas-m1h-intent-'+stamp+'.jsonl';
  const witness=await startWitness(assert,journal);
  let mockIssuer=null, issuerServer=null, projectServer=null,hold=null,loginHold=null;
  let tlsFixture=null,secureTransport=null,tlsHandler=null;
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
    let issuerBase;
    if(httpsMode){
      tlsFixture=createDisposableM1nTlsFixture();
      tlsHandler=async(req,res)=>{
        try {
          const chunks=[];
          let size=0;
          for await(const chunk of req){
            size+=chunk.byteLength;
            if(size>4096)throw new Error('M1n bounded mock issuer POST overflow');
            chunks.push(chunk);
          }
          const canonical='https://127.0.0.1:'+issuerServer.address().port;
          const input=new Request(canonical+req.url,{
            method:req.method,
            headers:{'Content-Type':req.headers['content-type']||'application/json'},
            body:req.method==='POST'?Buffer.concat(chunks):undefined,
          });
          const reply=await mockIssuer.handle(input);
          // Explicit bound for the preverified M1n TLS socket's strict
          // one-response HTTP/1.1 parser; no Transfer-Encoding ambiguity.
          const data=Buffer.from(await reply.arrayBuffer());
          res.writeHead(reply.status,{
            ...Object.fromEntries(reply.headers),
            'Content-Length':String(data.byteLength),
            Connection:'close',
          });
          res.end(data);
        }catch{
          res.writeHead(503,{'Content-Type':'application/json'});
          res.end('{"error":"CI HTTPS IdP unavailable"}');
        }
      };
      issuerServer=createServer({
        cert:tlsFixture.primary.cert,key:tlsFixture.primary.key,
        minVersion:'TLSv1.2',
      },tlsHandler);
      await new Promise(resolve=>issuerServer.listen(0,'127.0.0.1',resolve));
      issuerBase='https://127.0.0.1:'+issuerServer.address().port;
    }else{
      issuerServer=Bun.serve({
        hostname:'127.0.0.1',port:0,
        fetch:req=>mockIssuer?.handle(req)??new Response('',{status:503}),
      });
      issuerBase='http://127.0.0.1:'+issuerServer.port;
    }
    let oidc=httpsMode?null:createSyntheticOidcKeyRotation({
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
        if(hold&&input.projectId===project('race-revoked')){
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
    if(httpsMode){
      if(trustEpochMode){
        const manager=createM1oExplicitTrustRotation({
          baseUrl:issuerBase,callbackUri:redirectUri,
          initial:{revision:1,caPem:tlsFixture.trustedCaPem,
            spkiSha256:tlsFixture.primary.spkiSha256},
        });
        const old=manager.currentTransport();
        secureTransport=manager.commitExplicitRotation({
          revision:2,expectedRevision:1,caPem:tlsFixture.trustedCaPem,
          spkiSha256:tlsFixture.rotated.spkiSha256,
        });
        await assert.rejects(()=>old.fetch(issuerBase+'/jwks'),/stale/);
        await assert.rejects(()=>secureTransport.fetch(issuerBase+'/jwks'),
          /M1n verified HTTPS request denied/);
        assert.throws(()=>manager.commitExplicitRotation({
          revision:3,expectedRevision:2,caPem:tlsFixture.trustedCaPem,
          spkiSha256:tlsFixture.primary.spkiSha256,
        }),/retired/);
        // Bun v1.3.14 does not expose Node's setSecureContext().
        // Shut down only the ephemeral mock TLS listener, preserve the
        // exact local pinned origin and launch a fresh rotated TLS leaf.
        const samePort=issuerServer.address().port;
        await new Promise(resolve=>{
          issuerServer.close(resolve);issuerServer.closeAllConnections?.();
        });
        issuerServer=createServer({
          cert:tlsFixture.rotated.cert,key:tlsFixture.rotated.key,
          minVersion:'TLSv1.2',
        },tlsHandler);
        await new Promise(resolve=>
          issuerServer.listen(samePort,'127.0.0.1',resolve));
      }else secureTransport=createM1nPinnedHttpsTransport({
        baseUrl:issuerBase,caPem:tlsFixture.trustedCaPem,
        spkiSha256:tlsFixture.primary.spkiSha256,callbackUri:redirectUri,
      });
      // Actual TLS handshake trust failures occur BEFORE code issuance.
      const wrongCa=createM1nPinnedHttpsTransport({
        baseUrl:issuerBase,caPem:tlsFixture.rogueCaPem,
        spkiSha256:tlsFixture.primary.spkiSha256,callbackUri:redirectUri,
      });
      await assert.rejects(()=>wrongCa.fetch(issuerBase+'/jwks'),
        /M1n verified HTTPS request denied/);
      const wrongPin=createM1nPinnedHttpsTransport({
        baseUrl:issuerBase,caPem:tlsFixture.trustedCaPem,
        spkiSha256:(trustEpochMode?tlsFixture.primary:tlsFixture.rotated).spkiSha256,
        callbackUri:redirectUri,
      });
      await assert.rejects(()=>wrongPin.fetch(issuerBase+'/jwks'),
        /M1n verified HTTPS request denied/);
      oidc=await loadM1nVerifiedOidc({
        transport:secureTransport,issuer:ISSUER,audience:AUDIENCE,
        nowSeconds:()=>NOW,
      });
      assert.equal(registry.size,0);
    }else{
      assert.deepEqual(await oidc.reload(1),{revision:1,keyIds:['M1m']});
    }
    function provisionSessionSync({token,actorId}){
      assert.equal(actorId,'actor-north');
      const item=Object.freeze({
        id:crypto.randomUUID(),revision:1,
        actorId,tenantId:'demo-north',
      });
      register(assert,item.id);
      registry.set(sha(token),item);
      return item;
    }
    const clientConfig={
      issuer:ISSUER,clientId:CLIENT_ID,redirectUri,
      authorizationUrl:issuerBase+'/authorize',
      tokenUrl:issuerBase+'/token',
      tokenVerifier:loginContextMode?{
        async verifyAccessToken(token){
          const identity=await oidc.verifyAccessToken(token);
          if(loginHold){loginHold.enter();await loginHold.resume;}
          return identity;
        },
      }:oidc,
      ...(httpsMode?{secureTransport}:{}),
      nowSeconds:()=>NOW,
      resolveActorId:directory.resolveActorId,
    };
    const client=loginContextMode
      ?createM1pBoundPkceClient({
        ...clientConfig,provisionSessionSync,
      })
      :createSyntheticPkceClient({
        ...clientConfig,provisionSession:provisionSessionSync,
      });
    async function authorize(loginContext=null){
      const flow=loginContextMode?client.begin(loginContext):client.begin();
      const res=await (httpsMode?secureTransport.fetch:fetch)(flow.authorizationUrl,{redirect:'manual'});
      assert.equal(res.status,302);
      const callback=res.headers.get('location');
      assert.ok(callback?.startsWith(redirectUri+'?'));
      assert.ok(!callback.includes('access_token'));
      return callback;
    }
    async function login(){
      const loginContext=loginContextMode?client.openContext():null;
      const callback=await authorize(loginContext);
      const complete=()=>loginContextMode
        ?client.complete(loginContext,callback)
        :client.complete(callback);
      const result=await complete();
      assert.equal(result.actorId,'actor-north');
      assert.ok(V4.test(result.sessionId));
      assert.equal(result.tenantId,'demo-north');
      await assert.rejects(complete,loginContextMode
        ?/M1p synthetic bound login context denied/
        :/M1m synthetic OAuth authorization denied/);
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
    assert.equal((await post(a,project('a-first'))),201);
    assert.equal((await post(b,project('b-first'))),201);

    // Forged callback state and an OAuth error must not provision any
    // session, touch PG or trigger a second code exchange.
    const thirdPartyContext=loginContextMode?client.openContext():null;
    const thirdParty=await authorize(thirdPartyContext);
    const wrong=new URL(thirdParty);
    wrong.searchParams.set('state','A'.repeat(43));
    await assert.rejects(()=>loginContextMode
      ?client.complete(thirdPartyContext,wrong.href)
      :client.complete(wrong.href),loginContextMode
      ?/M1p synthetic bound login context denied/
      :/M1m synthetic OAuth authorization denied/);
    const failure=new URL(redirectUri);
    failure.searchParams.set('state',new URL(thirdParty).searchParams.get('state'));
    failure.searchParams.set('error','access_denied');
    await assert.rejects(()=>loginContextMode
      ?client.complete(thirdPartyContext,failure.href)
      :client.complete(failure.href),loginContextMode
      ?/M1p synthetic bound login context denied/
      :/M1m synthetic OAuth authorization denied/);
    await assert.rejects(()=>loginContextMode
      ?client.complete(thirdPartyContext,thirdParty)
      :client.complete(thirdParty),loginContextMode
      ?/M1p synthetic bound login context denied/
      :/M1m synthetic OAuth authorization denied/);
    assert.equal(registry.size,3);

    if(loginContextMode){
      // Valid HTTPS+PKCE callbacks from D/E must never be accepted
      // in the opposite server-held opaque login context.
      const contextD=client.openContext(),contextE=client.openContext();
      const callbackD=await authorize(contextD);
      const callbackE=await authorize(contextE);
      const beforeSwap=mockIssuer.stats().redeemedCodes;
      await assert.rejects(()=>client.complete(contextD,callbackE),
        /M1p synthetic bound login context denied/);
      await assert.rejects(()=>client.complete(contextE,callbackD),
        /M1p synthetic bound login context denied/);
      assert.equal(mockIssuer.stats().redeemedCodes,beforeSwap);
      assert.equal(registry.size,3);
      client.cancelContext(contextE);
      await assert.rejects(()=>client.complete(contextE,callbackE),
        /M1p synthetic bound login context denied/);
      const beforeEnrollment=pg(assert,
        "SELECT COUNT(*) FROM saas_m1_private.project_session_epochs "+
        "WHERE actor_id='actor-north' AND tenant_id='demo-north'");
      let entered,release;
      const reached=new Promise(resolve=>{entered=resolve;});
      const resumed=new Promise(resolve=>{release=resolve;});
      loginHold={enter:entered,resume:resumed};
      const inflight=client.complete(contextD,callbackD);
      try{
        await Promise.race([reached,new Promise((_,reject)=>setTimeout(
          ()=>reject(new Error('M1p token verifier pause not reached')),8000))]);
        assert.equal(registry.size,3);
        client.cancelContext(contextD);
      }finally{
        release();
        loginHold=null;
      }
      await assert.rejects(inflight,/M1p synthetic bound login context denied/);
      assert.equal(pg(assert,
        "SELECT COUNT(*) FROM saas_m1_private.project_session_epochs "+
        "WHERE actor_id='actor-north' AND tenant_id='demo-north'"),
        beforeEnrollment,'cancelled callback cannot register PG session');
      assert.equal(registry.size,3,'cancelled callback cannot bind bearer');
      assert.equal(mockIssuer.stats().redeemedCodes,4,
        'one code spent at issuer without PG session or retry');
      await assert.rejects(()=>client.complete(contextD,callbackD),
        /M1p synthetic bound login context denied/);
    }

    // Critical race: an actual C-session bearer was verified twice by
    // M1a, passed HTTP authorization and fsynced a separate PRE-COMMIT
    // intent; before ANY PG reservation, privileged fixture revokes C.
    // The signed M1k session row lock must reject the in-flight write.
    let entered;
    const reached=new Promise(resolve=>{entered=resolve;});
    let release;
    const released=new Promise(resolve=>{release=resolve;});
    hold={enter:entered,resume:released};
    const inFlight=post(c,project('race-revoked'));
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
    assert.equal(evidence(assert,project('race-revoked')),'0:0:0');
    revoke(assert,a.sessionId);
    assert.equal((await post(a,project('a-revoked'))),404);
    assert.equal(evidence(assert,project('a-revoked')),'0:0:0');
    assert.equal((await post(b,project('b-after-revoke'))),201);
    assert.equal(evidence(assert,project('a-first')),'1:1:1');
    assert.equal(evidence(assert,project('b-first')),'1:1:1');
    assert.equal(evidence(assert,project('b-after-revoke')),'1:1:1');

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
      "ON a.pg_txid=p.pg_txid WHERE a.project_id LIKE '"+prefix+"-%'"),'3');
    const held=driver.stats().reservations;
    assert.equal((await post(b,project('signer-dead'))),503);
    assert.equal(driver.stats().reservations,held);
    assert.equal(evidence(assert,project('signer-dead')),'0:0:0');
    assert.equal(mockIssuer.stats().redeemedCodes,loginContextMode?4:3);
    if(loginContextMode) console.info(
      'PASS M1p: real pinned HTTPS PKCE callbacks bound to opaque per-login contexts; '+
      'cross-context swap 0 bearer/0 PG, cancelled verified token BEFORE '+
      'PG enrollment 0 session; signed PG16 3/3/3 project/audit/UUID, '+
      'C/A revoked 0 ghosts, B active, signer 503/0 reservations; no retry'
    );
    else if(trustEpochMode) console.info(
      'PASS M1o: explicit HTTPS CA/SPKI revision CAS and retired-pin deny BEFORE OAuth; '+
      'rotated HTTPS PKCE -> pinned JWT -> PG16 3/3/3 project/audit/UUID; '+
      'revoked C/A no ghosts, B active, signer 503, no retry/Railway changes'
    );
    else if(httpsMode) console.info(
      'PASS M1n: real ephemeral HTTPS CA/SAN/leaf SPKI pinned IdP '+
      'rejects rogue root and rotated unapproved leaf BEFORE OAuth; '+
      'HTTPS code+PKCE S256/state, pinned JWKS RSA JWT -> signed PG16 '+
      'session/Audit/UUID 3/3/3; revoked C in-flight and A 404 0/0/0, '+
      'B active, witness 503 without PG reservation; no production/TLS cert reuse'
    );
    else console.info(
      'PASS M1m: real synthetic OAuth code+PKCE S256/state, one-time '+
      'callback -> pinned RS256 -> server-provisioned PG16 UUID session; '+
      'signed HTTP project/audit/UUID 3/3/3; revoked in-flight C and A '+
      'after login 404 0/0/0, B remains active, signer loss 503/0 PG '+
      'reservation, no refresh/login deployment/WORM/retry'
    );
  }finally{
    if(hold)hold=null;
    projectServer?.stop(true);
    if(httpsMode&&issuerServer){
      await new Promise(resolve=>{
        issuerServer.close(()=>resolve());
        issuerServer.closeAllConnections?.();
      });
    }else issuerServer?.stop(true);
    tlsFixture?.dispose();
    await witness.stop();
    await driver.close();
  }
}

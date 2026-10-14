/**
 * M1k: ephemeral GitHub PG16 ONLY — synthetic server-managed session
 * fingerprint -> session UUID/revision -> SAME signed PG16 transaction.
 * The session table is not an OIDC identity/session store. Same-host witness
 * is not an external WORM, and 503 NEVER licenses automatic retry.
 */
import { createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createM1ProjectHttpHandler } from
  '../../src/features/saasBlueprint/controlApi/server/m1ProjectHttpHandler.ts';
import { startWitness, runOffline } from './verify-m1h-precommit-intent.mjs';

const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SAFE_PROJECT = /^m1k-[a-z-]{1,48}$/;
const sha256 = value => createHash('sha256').update(value).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function pg(assert, sql) {
  const result = Bun.spawnSync(
    ['psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-c',sql],
    { stdout:'pipe',stderr:'pipe' }
  );
  assert.equal(result.exitCode,0,'M1k privileged disposable PG16 fixture failed');
  return new TextDecoder().decode(result.stdout).trim();
}
function state(assert, sessionId) {
  assert.ok(V4.test(sessionId));
  return pg(assert,
    "SELECT status||':'||revision::TEXT FROM " +
    "saas_m1_private.project_session_epochs WHERE session_id='" + sessionId + "'::UUID");
}
function change(assert, sessionId, mode) {
  assert.ok(V4.test(sessionId));
  assert.ok(['revoke','rotate'].includes(mode));
  const sql = "UPDATE saas_m1_private.project_session_epochs SET " +
    (mode === 'revoke' ? "status='revoked', " : '') +
    "revision=revision+1 WHERE session_id='" + sessionId + "'::UUID " +
    "AND status='active' RETURNING revision::TEXT";
  return pg(assert, sql);
}
function projectEvidence(assert, project) {
  assert.ok(SAFE_PROJECT.test(project));
  return pg(assert,
    "SELECT (SELECT COUNT(*) FROM saas_m1_private.projects " +
    "WHERE tenant_id='demo-north' AND project_id='" + project + "')::TEXT || ':' || " +
    "(SELECT COUNT(*) FROM saas_m1_private.project_write_audit_outbox " +
    "WHERE tenant_id='demo-north' AND project_id='" + project + "')::TEXT || ':' || " +
    "(SELECT COUNT(*) FROM saas_m1_private.project_attempt_bindings b " +
    "JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id " +
    "WHERE a.tenant_id='demo-north' AND a.project_id='" + project + "')::TEXT"
  );
}
function spawnAdmin(assert, app, sql) {
  assert.ok(/^m1k_[a-z_]{1,32}$/.test(app));
  const child = Bun.spawn(
    ['psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-c',sql],
    {
      env:{...process.env,PGAPPNAME:app},
      stdout:'pipe',stderr:'pipe',
    }
  );
  assert.ok(child.pid>0,'M1k disposable privileged fixture PID absent');
  return child;
}
async function waitUntil(assert, description, fn, timeoutMs=7000) {
  const start=Date.now();
  while(Date.now()-start < timeoutMs) {
    if(fn()) return;
    await delay(75);
  }
  assert.fail('M1k did not observe required physical PG ' + description);
}

export async function verifyM1k({
  assert,makeDriver,verifier,directory,actors,signToken,northScope,
}) {
  if(process.env.GITHUB_ACTIONS!=='true' ||
     process.env.SAAS_EPHEMERAL_M1_PG_CI!=='true' ||
     process.env.SAAS_EPHEMERAL_M1G_ATTEMPT_CI!=='true' ||
     process.env.SAAS_EPHEMERAL_M1_HTTP_CI!=='true' ||
     process.env.SAAS_EPHEMERAL_M1K_SESSION_CI!=='true' ||
     process.env.SAAS_EPHEMERAL_M1J_HTTP_PG_CI==='true' ||
     process.env.PGHOST!=='127.0.0.1' ||
     process.env.PGPORT!=='5432' ||
     process.env.PGDATABASE!=='saas_ephemeral_test' ||
     process.env.NODE_ENV==='production' ||
     process.env.RAILWAY_PROJECT_ID || process.env.RAILWAY_ENVIRONMENT ||
     process.env.RAILWAY_SERVICE_ID) {
    throw new Error('M1k session proof denied outside disposable GitHub PG16');
  }
  console.info('STEP M1k: real HTTP -> server session fingerprint -> signed PG16 FOR SHARE epoch gate');
  const stamp=crypto.randomUUID();
  const intentPath='/tmp/saas-m1h-intent-'+stamp+'.jsonl';
  const witness=await startWitness(assert,intentPath);
  const registry=new Map();
  const context=new AsyncLocalStorage();
  const attempts=[];
  const drivers=[];
  let currentDriver=makeDriver({attemptTagging:true,sessionGuard:true});
  drivers.push(currentDriver);
  let listener;
  let revoker;
  let blocker;
  let releaseHold=()=>{};
  async function addSession(subject='north') {
    const token=await signToken(subject,{
      jti:crypto.randomUUID(),role:'tenant-owner',actorId:'actor-orbit',
      tenantId:'demo-orbit',sessionId:'FORGED_JWT_SESSION',
    });
    const entry=Object.freeze({
      id:crypto.randomUUID(), revision:1,
      actorId:subject==='north'?'actor-north':'actor-orbit',
      tenantId:subject==='north'?'demo-north':'demo-orbit',
    });
    assert.ok(V4.test(entry.id));
    registry.set(sha256(token),entry);
    assert.equal(pg(assert,
      "INSERT INTO saas_m1_private.project_session_epochs " +
      "(session_id,actor_id,tenant_id,revision,status) VALUES('" +
      entry.id + "'::UUID,'" + entry.actorId + "','" + entry.tenantId +
      "',1,'active') RETURNING status"),'active');
    return {token,entry};
  }
  function setDriver(options) {
    currentDriver=makeDriver({attemptTagging:true,sessionGuard:true,...options});
    drivers.push(currentDriver);
    return currentDriver;
  }
  const trustedTokens={
    async verifyAccessToken(token) {
      // A server-held SHA256 fingerprint maps an otherwise VALID signed
      // access token to a private session. JWT sid/role/tenant are IGNORED.
      const identity=await verifier.verifyAccessToken(token);
      if(!identity) return null;
      const pinned=registry.get(sha256(token));
      const ctx=context.getStore();
      if(!pinned||!ctx) return null;
      if(ctx.session && (ctx.session.id!==pinned.id ||
          ctx.session.revision!==pinned.revision)) return null;
      ctx.session=pinned;
      return identity;
    },
  };
  const writer=Object.freeze({
    async execute(input) {
      const session=context.getStore()?.session;
      if(!session || !V4.test(session.id) ||
         session.actorId!==input.scope.actorId ||
         session.tenantId!==input.scope.tenantId ||
         !Number.isSafeInteger(session.revision)) {
        throw new Error('M1k trusted request-to-session binding unavailable');
      }
      const attemptId=crypto.randomUUID();
      const intent={
        attemptId,actorId:input.scope.actorId,tenantId:input.scope.tenantId,
        projectId:input.projectId,operation:input.operation,
        expectedVersion:input.expectedVersion??null,
      };
      const receipt=await witness.prepare(intent);
      assert.equal(receipt.attemptId,attemptId);
      attempts.push({...intent,sessionId:session.id,sessionRevision:session.revision});
      return currentDriver.execute({...input,attemptId,
        sessionId:session.id,sessionRevision:session.revision});
    },
  });
  const handler=createM1ProjectHttpHandler({
    tokens:trustedTokens,directory,actors,writer,
    newCorrelationId:()=> 'm1k-synthetic-server-correlation',
  },{enabledForDisposableCi:true});
  listener=Bun.serve({
    hostname:'127.0.0.1',port:0,
    fetch:request=>context.run({session:null},()=>handler(request)),
  });
  const origin='http://127.0.0.1:'+listener.port;
  async function post(session,project) {
    assert.ok(SAFE_PROJECT.test(project));
    const response=await fetch(origin+
      '/control-api/v1/tenants/demo-north/metadata/projects/'+project,{
      method:'POST',
      headers:{Authorization:'Bearer '+session.token,
        'Content-Type':'application/json'},
      body:JSON.stringify({name:'M1k synthetic'}),
      signal:AbortSignal.timeout(15000),
    });
    const body=await response.json();
    assert.ok(!JSON.stringify(body).includes(session.token));
    assert.ok(response.headers.get('Cache-Control')?.includes('no-store'));
    assert.equal(response.headers.get('Set-Cookie'),null);
    assert.equal(response.headers.get('Access-Control-Allow-Origin'),null);
    return response.status;
  }
  try {
    const a=await addSession(),b=await addSession(),
      c=await addSession(),d=await addSession();
    // A and B share SAME signed actor and tenant, but private
    // server-issued token fingerprints and session UUIDs are distinct.
    assert.notEqual(a.entry.id,b.entry.id);
    assert.equal((await post(a,'m1k-a-first')),201);
    assert.equal((await post(b,'m1k-b-first')),201);
    const unregistered=await signToken('north',{jti:crypto.randomUUID()});
    assert.equal((await post({token:unregistered},'m1k-unregistered')),401);
    assert.equal(projectEvidence(assert,'m1k-unregistered'),'0:0:0');

    // Revoke only A in real DB. HTTP holds a STALE active actor snapshot
    // and a correctly signed token, yet its signed PG session gate denies.
    assert.equal(change(assert,a.entry.id,'revoke'),'2');
    assert.equal(state(assert,a.entry.id),'revoked:2');
    assert.equal((await post(a,'m1k-a-revoked')),404);
    assert.equal(projectEvidence(assert,'m1k-a-revoked'),'0:0:0');
    assert.equal((await post(b,'m1k-b-after-a-revoke')),201);

    // Forced epoch rotation without status change invalidates the
    // original server-held revision even for the SAME valid RS256 token.
    assert.equal(change(assert,b.entry.id,'rotate'),'2');
    assert.equal(state(assert,b.entry.id),'active:2');
    assert.equal((await post(b,'m1k-b-stale-epoch')),404);
    assert.equal(projectEvidence(assert,'m1k-b-stale-epoch'),'0:0:0');
    registry.set(sha256(b.token),Object.freeze({...b.entry,revision:2}));
    assert.equal((await post(b,'m1k-b-fresh-epoch')),201);

    // A legacy signed native Bun.SQL writer which avoids the session
    // gate can no longer COMMIT project+M1d audit+M1g binding: SQL025's
    // final trigger requires a DEFNER-created signed transaction proof.
    const legacy=makeDriver({attemptTagging:true});
    try{
      const rejected=await legacy.execute({
        scope:northScope,operation:'create',
        projectId:'m1k-legacy-bypass',name:'Denied unguarded',
        attemptId:crypto.randomUUID(),signal:AbortSignal.timeout(9000),
      });
      assert.equal(rejected,false);
    }finally{await legacy.close();}
    assert.equal(projectEvidence(assert,'m1k-legacy-bypass'),'0:0:0');

    // ORDER 1: signed HTTP+PG mutation reaches beforeCommit, holding
    // FOR SHARE on session C and existing M1d tenant auth revision. A
    // competing committed session revoke MUST BLOCK until HTTP COMMIT.
    let arrived;
    const held=new Promise(resolve=>{arrived=resolve;});
    const released=new Promise(resolve=>{releaseHold=resolve;});
    const firstDriver=setDriver({
      beforeCommit({backendPid}){
        assert.ok(Number.isSafeInteger(backendPid)&&backendPid>0);
        arrived(backendPid);
        return released;
      },
    });
    const firstPost=post(c,'m1k-write-first');
    let firstCommitted;
    try{
      await Promise.race([
        held,new Promise((_,reject)=>setTimeout(
          ()=>reject(new Error('M1k signed HTTP mutation did not reach PG COMMIT gate')),8000)),
      ]);
      revoker=spawnAdmin(assert,'m1k_revoke_after',
        "UPDATE saas_m1_private.project_session_epochs " +
        "SET status='revoked',revision=revision+1 " +
        "WHERE session_id='"+c.entry.id+"'::UUID AND status='active'");
      await waitUntil(assert,'revoke blocked behind signed HTTP write',
        ()=>pg(assert,"SELECT COUNT(*) FROM pg_stat_activity " +
          "WHERE application_name='m1k_revoke_after' AND wait_event_type='Lock'")==='1');
      releaseHold();
      firstCommitted=await firstPost;
      assert.equal(await revoker.exited,0);
      revoker=null;
    }finally{
      releaseHold();
      if(revoker){revoker.kill();await revoker.exited;revoker=null;}
    }
    assert.equal(firstCommitted,201);
    assert.equal(firstDriver.stats().poisoned,false);
    assert.equal(state(assert,c.entry.id),'revoked:2');
    assert.equal(projectEvidence(assert,'m1k-write-first'),'1:1:1');
    assert.equal((await post(c,'m1k-c-after-revoke')),404);

    // ORDER 2: revoker updates D first and holds its lock while a REAL
    // HTTP write attempts SELECT FOR SHARE. Check physical PG lock wait,
    // then revoke COMMIT: the stale signed session MUST be denied.
    blocker=spawnAdmin(assert,'m1k_revoke_first',
      "BEGIN;SET LOCAL statement_timeout='20000ms';" +
      "UPDATE saas_m1_private.project_session_epochs " +
      "SET status='revoked',revision=revision+1 " +
      "WHERE session_id='"+d.entry.id+"'::UUID AND status='active';" +
      "SELECT pg_sleep(3);COMMIT;");
    try{
      await waitUntil(assert,'revoke-first transaction held',
        ()=>pg(assert,"SELECT COUNT(*) FROM pg_stat_activity " +
          "WHERE application_name='m1k_revoke_first' AND wait_event='PgSleep'")==='1');
      setDriver({});
      const latePost=post(d,'m1k-revoke-first');
      await waitUntil(assert,'signed writer blocked behind session revoke',
        ()=>pg(assert,"SELECT COUNT(*) FROM pg_stat_activity " +
          "WHERE usename='saas_ci_runner' AND wait_event_type='Lock' " +
          "AND query LIKE '%lock_project_session_epoch%'")!=='0');
      assert.equal(await blocker.exited,0);
      blocker=null;
      assert.equal(await latePost,404);
    }finally{
      if(blocker){blocker.kill();await blocker.exited;blocker=null;}
    }
    assert.equal(state(assert,d.entry.id),'revoked:2');
    assert.equal(projectEvidence(assert,'m1k-revoke-first'),'0:0:0');
    assert.equal(projectEvidence(assert,'m1k-c-after-revoke'),'0:0:0');

    // Extra trusted per-session data is NEVER returned in HTTP and the
    // offline witness remains on this same runner, not an external WORM.
    await witness.stop();
    assert.equal(attempts.length,8);
    const checked=runOffline(assert,intentPath,witness.publicKey,8);
    assert.ok(checked && checked.count===8);
    assert.deepEqual(checked.attempts,
      attempts.map(({sessionId,sessionRevision,...record})=>record));
    const noSigner=setDriver({});
    assert.equal((await post(b,'m1k-signer-dead')),503);
    assert.equal(noSigner.stats().reservations,0);
    assert.equal(projectEvidence(assert,'m1k-signer-dead'),'0:0:0');
    console.info(
      'PASS M1k: two real synthetic RS256 sessions share actor; ' +
      'server fingerprint+UUID+epoch checked by signed PG16 FOR SHARE, ' +
      'revoke/rotation stale token DENY, legacy bypass DENY, ' +
      'HTTP-first COMMIT precedes blocked revoke, revoke-first blocks and DENIES, ' +
      '0 ghost audit, dead signer 0 PG reservations, NO OIDC/retry/production'
    );
  }finally{
    releaseHold();
    if(revoker){revoker.kill();await revoker.exited;}
    if(blocker){blocker.kill();await blocker.exited;}
    listener?.stop(true);
    await witness.stop();
    await Promise.all(drivers.map(d=>d.close()));
  }
}

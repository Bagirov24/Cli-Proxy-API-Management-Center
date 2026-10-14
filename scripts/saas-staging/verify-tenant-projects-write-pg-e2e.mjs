/**
 * Backend slice 02: real loopback POST/PATCH -> ephemeral native PG16.
 *
 * Reuses exactly the existing M1g native signed transaction writer, SQL021
 * project+mandatory audit, SQL024 bound server UUID and M1h fsynced signer.
 * NO mocks for the PostgreSQL commit/revoke/lost-ack evidence. This is
 * disposable GitHub CI; no production adapter, OIDC keys or deployment.
 */
import {createTenantProjectsWriteHttpHandler} from
  '../../src/features/saasBlueprint/controlApi/server/tenantProjectsWriteHttpHandler.ts';
import {startWitness,runOffline} from './verify-m1h-precommit-intent.mjs';
import {createHash} from 'node:crypto';

const V4=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function fixtureSql(assert,statement){
  const run=Bun.spawnSync(
    ['psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-c',statement],
    {stdout:'pipe',stderr:'pipe'},
  );
  assert.equal(run.exitCode,0,'Disposable PG16 fixture unavailable');
  return new TextDecoder().decode(run.stdout).trim();
}
function counts(assert,projectId){
  assert.match(projectId,V4,'Only server-issued UUID may be queried in fixture');
  return fixtureSql(assert,
    "SELECT (SELECT COUNT(*) FROM saas_m1_private.projects "+
    "WHERE tenant_id='demo-north' AND project_id='"+projectId+"')::TEXT || ':' || "+
    "(SELECT COUNT(*) FROM saas_m1_private.project_write_audit_outbox "+
    "WHERE tenant_id='demo-north' AND project_id='"+projectId+"')::TEXT || ':' || "+
    "(SELECT COUNT(*) FROM saas_m1_private.project_attempt_bindings b "+
    "JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id "+
    "WHERE a.tenant_id='demo-north' AND a.project_id='"+projectId+"')::TEXT"
  );
}
function bound(assert,projectId,attemptId){
  assert.match(projectId,V4);assert.match(attemptId,V4);
  return fixtureSql(assert,
    "SELECT COUNT(*) FROM saas_m1_private.project_attempt_bindings b "+
    "JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id "+
    "WHERE a.tenant_id='demo-north' AND a.project_id='"+projectId+"' "+
    "AND b.attempt_id='"+attemptId+"'::uuid"
  );
}
function projectSessionProofs(assert,projectId,sessionId){
  assert.match(projectId,V4);assert.match(sessionId,V4);
  return fixtureSql(assert,
    "SELECT COUNT(*) FROM saas_m1_private.project_session_proofs p "+
    "JOIN saas_m1_private.project_write_audit_outbox a "+
    "ON a.pg_txid=p.pg_txid "+
    "WHERE a.tenant_id='demo-north' AND a.project_id='"+projectId+"' "+
    "AND p.session_id='"+sessionId+"'::uuid"
  );
}
function setMembership(assert,state){
  const sql=state==='revoke'
    ? "UPDATE saas_rls.memberships SET status='revoked' "+
      "WHERE actor_id='actor-north' AND tenant_id='demo-north' AND status='active'"
    :state==='restore'
      ? "UPDATE saas_rls.memberships SET status='active' "+
        "WHERE actor_id='actor-north' AND tenant_id='demo-north' AND status='revoked'"
      :null;
  assert.ok(sql,'Only fixed disposable PG16 mutation allowed');
  assert.equal(fixtureSql(assert,sql),'UPDATE 1');
}

export async function verifyTenantProjectWriteHttpPg({
  assert,makeDriver,verifier,directory,actors,signToken,northScope,
}){
  if(process.env.GITHUB_ACTIONS!=='true' ||
      process.env.SAAS_EPHEMERAL_M1_PG_CI!=='true' ||
      process.env.SAAS_EPHEMERAL_M1G_ATTEMPT_CI!=='true' ||
      process.env.SAAS_EPHEMERAL_M1_HTTP_CI!=='true' ||
      process.env.SAAS_EPHEMERAL_M1J_HTTP_PG_CI!=='true' ||
      process.env.SAAS_PROJECT_WRITE_HTTP_CI!=='true' ||
      process.env.PGHOST!=='127.0.0.1' ||
      process.env.PGPORT!=='5432' ||
      process.env.PGDATABASE!=='saas_ephemeral_test' ||
      process.env.NODE_ENV==='production' ||
      process.env.RAILWAY_PROJECT_ID ||
      process.env.RAILWAY_ENVIRONMENT ||
      process.env.RAILWAY_SERVICE_ID){
    throw new Error('Backend write HTTP only on disposable signed PG16 GitHub CI');
  }
  console.info('STEP backend-02: real HTTP POST/PATCH -> signed native PostgreSQL16');
  const path='/tmp/saas-m1h-intent-'+crypto.randomUUID()+'.jsonl';
  const witness=await startWitness(assert,path);
  const issued=[];
  const drivers=[];
  let driver=makeDriver({attemptTagging:true,sessionGuard:true});
  const sessionId=crypto.randomUUID();
  assert.match(sessionId,V4);
  let trustedFingerprint=null;
  drivers.push(driver);
  const registry={
    async prepare(entry){
      assert.ok(V4.test(entry.attemptId));
      assert.ok(entry.actorId==='actor-north'&&entry.tenantId==='demo-north');
      const receipt=await witness.prepare(entry);
      assert.equal(receipt.attemptId,entry.attemptId);
      assert.equal(receipt.sequence,issued.length+1);
      issued.push(entry);
      return receipt;
    },
  };
  const writer={
    async execute(input){
      assert.ok(V4.test(input.attemptId));
      assert.equal(input.sessionId,sessionId);
      assert.equal(input.sessionRevision,1);
      assert.ok(['create','rename'].includes(input.operation));
      return driver.execute(input);
    },
  };
  let handler;
  const server=Bun.serve({
    hostname:'127.0.0.1',port:0,
    fetch:req=>handler?handler(req):new Response('',{status:503}),
  });
  const origin='http://127.0.0.1:'+server.port;
  handler=createTenantProjectsWriteHttpHandler({
    expectedOrigin:origin,tokens:verifier,directory,actors,
    journal:registry,writer,
    sessions:{
      async resolve(input,signal){
        if(signal.aborted||input.actorId!=='actor-north'||
            input.tenantId!=='demo-north'||
            !trustedFingerprint||input.tokenFingerprint!==trustedFingerprint) return null;
        return {sessionId,sessionRevision:1};
      },
    },
    newCorrelationId:()=> 'backend02-server-generated',
  });
  const root='/control-api/v1/tenants/demo-north/projects';
  const north=await signToken('north',{
    actorId:'actor-orbit',tenantId:'demo-orbit',role:'tenant-owner',
    attemptId:'FORGED_HTTP_ATTEMPT',
  });
  trustedFingerprint=createHash('sha256').update(north).digest('hex');
  assert.match(trustedFingerprint,/^[0-9a-f]{64}$/);
  // psql -t/-A still prints the DML command tag after RETURNING on PG16.
  // Match the specific returned row *and* the successful insert tag.
  assert.equal(fixtureSql(assert,
    "INSERT INTO saas_m1_private.project_session_epochs "+
    "(session_id,actor_id,tenant_id,revision,status) VALUES ('"+
    sessionId+"'::uuid,'actor-north','demo-north',1,'active') "+
    "RETURNING status"),'active'+String.fromCharCode(10)+'INSERT 0 1');
  const viewer=await signToken('orbit');
  const auditor=await signToken('auditor');
  async function send(method,route,bearer,body,headers={}){
    const response=await fetch(origin+route,{
      method,headers:{
        ...(bearer?{Authorization:'Bearer '+bearer}:{}),
        'Content-Type':'application/json',
        ...headers,
      },body:JSON.stringify(body),signal:AbortSignal.timeout(12000),
    });
    assert.equal(response.headers.get('Access-Control-Allow-Origin'),null);
    assert.equal(response.headers.get('Set-Cookie'),null);
    assert.match(response.headers.get('Cache-Control')||'',/no-store/);
    const payload=await response.json();
    const text=JSON.stringify(payload);
    assert.equal(text.includes(north),false);
    assert.equal(text.includes('FORGED_HTTP_ATTEMPT'),false);
    assert.equal(text.includes('saas_m1_private'),false);
    assert.equal(text.includes('attemptId'),false);
    return {status:response.status,data:payload};
  }
  function replaceDriver(options){
    driver=makeDriver({...options,sessionGuard:true});
    drivers.push(driver);
    return driver;
  }
  let revoked=false;
  try {
    const invalid=[
      await send('POST',root,viewer,{name:'Not allowed'}),
      await send('POST',root,auditor,{name:'Not allowed'}),
      await send('POST',root,north,{name:'Not allowed'},{
        'X-Actor-ID':'actor-north',
      }),
      await send('POST',root,north,{name:'Not allowed',attemptId:crypto.randomUUID()}),
      await send('POST',root,north,{name:'Not allowed'},{Cookie:'malicious=true'}),
      await send('POST',root,null,{name:'Not allowed'}),
    ];
    assert.deepEqual(invalid.map(x=>x.status),[404,404,403,404,403,401]);
    assert.equal(issued.length,0);
    assert.equal(driver.stats().reservations,0);
    const created=await send('POST',root,north,{name:'Backend Two'});
    assert.equal(created.status,201);
    const project=created.data.projectId;
    assert.match(project,V4);
    assert.equal(counts(assert,project),'1:1:1');
    assert.equal(bound(assert,project,issued[0].attemptId),'1');
    assert.equal(projectSessionProofs(assert,project,sessionId),'1');
    assert.equal(issued[0].projectId,project);
    assert.equal(issued[0].expectedVersion,null);
    const initial=await driver.read(northScope,project);
    assert.equal(initial[0].version,'1');
    assert.equal(initial[0].name,'Backend Two');
    assert.equal(initial[0].status,'active');

    const renamed=await send('PATCH',root+'/'+project,north,{
      name:'Backend Two Renamed',expectedVersion:1,
    });
    assert.equal(renamed.status,200);
    assert.equal(counts(assert,project),'1:2:2');
    assert.equal(bound(assert,project,issued[1].attemptId),'1');
    assert.equal(projectSessionProofs(assert,project,sessionId),'2');
    const stale=await send('PATCH',root+'/'+project,north,{
      name:'Stale Version Must Deny',expectedVersion:1,
    });
    assert.equal(stale.status,404);
    assert.equal(counts(assert,project),'1:2:2');
    assert.equal(bound(assert,project,issued[2].attemptId),'0');
    assert.equal(projectSessionProofs(assert,project,sessionId),'2');
    const after=await driver.read(northScope,project);
    assert.equal(after[0].version,'2');
    assert.equal(after[0].name,'Backend Two Renamed');

    // A stale server-held role does not override actual current database
    // membership: PG RLS + signed authorization fence independently denies.
    setMembership(assert,'revoke');
    revoked=true;
    const beforeRevokedReservations=driver.stats().reservations;
    const denied=await send('POST',root,north,{name:'Current DB denies'});
    assert.equal(denied.status,404);
    assert.equal(driver.stats().reservations,beforeRevokedReservations+1);
    assert.equal(issued.length,4);
    assert.equal(counts(assert,issued[3].projectId),'0:0:0');
    setMembership(assert,'restore');
    revoked=false;

    // Actual PG COMMIT success, but synthetic connection ACK lost:
    // one durable project+mandatory audit+UUID, no retry or false success.
    const ack=replaceDriver({attemptTagging:true,dropAckAfterCommit:true});
    const unknown=await send('POST',root,north,{name:'Committed No ACK'});
    assert.equal(unknown.status,503);
    assert.deepEqual(ack.stats(),{
      poisoned:true,reservations:1,commitAcks:0,
    });
    assert.equal(issued.length,5);
    assert.equal(counts(assert,issued[4].projectId),'1:1:1');
    assert.equal(bound(assert,issued[4].projectId,issued[4].attemptId),'1');
    assert.equal(projectSessionProofs(assert,issued[4].projectId,sessionId),'1');

    // Real physical PG backend terminated BEFORE COMMIT; same client 503
    // but zero project/audit/attempt binding persisted, no automatic retry.
    let backendPid=null;
    const interrupted=replaceDriver({
      attemptTagging:true,
      beforeCommit({backendPid:pid}){
        assert.ok(Number.isSafeInteger(pid)&&pid>0);
        backendPid=pid;
        const status=fixtureSql(assert,
          'SELECT CASE WHEN pg_terminate_backend('+pid+
          ") THEN 'terminated' ELSE 'missing' END");
        assert.equal(status,'terminated');
      },
    });
    const lost=await send('POST',root,north,{name:'Must Rollback'});
    assert.equal(lost.status,503);
    assert.deepEqual(interrupted.stats(),{
      poisoned:true,reservations:1,commitAcks:0,
    });
    assert.ok(backendPid>0);
    assert.equal(counts(assert,issued[5].projectId),'0:0:0');
    assert.equal(bound(assert,issued[5].projectId,issued[5].attemptId),'0');
    assert.equal(projectSessionProofs(assert,issued[5].projectId,sessionId),'0');

    // Independent local witness contains six unique, ordered fsync seals.
    // It is NOT off-host WORM or a production settlement authority.
    await witness.stop();
    const verified=runOffline(assert,path,witness.publicKey,6);
    assert.ok(verified&&verified.count===6);
    assert.deepEqual(verified.attempts,issued);
    assert.equal(new Set(issued.map(x=>x.attemptId)).size,6);

    const dead=replaceDriver({attemptTagging:true});
    const deadResult=await send('POST',root,north,{name:'No Signer'});
    assert.equal(deadResult.status,503);
    assert.equal(dead.stats().reservations,0);
    assert.equal(issued.length,6);
    console.info(
      'PASS backend-02: REAL HTTP POST/PATCH -> server IDs+fsynced one-use '+
      'UUID -> locked PG25 token-mapped session epoch, signed non-superuser '+
      'PG16 CAS+mandatory audit/proof; stale CAS 404, '+
      'revoked DB 404, unknown COMMIT 503 1:1:1, killed preCOMMIT 503 0:0:0, '+
      'dead witness 0 reservations, no retry'
    );
  }finally{
    if(revoked)setMembership(assert,'restore');
    server.stop(true);
    await witness.stop();
    await Promise.all(drivers.map(d=>d.close()));
  }
}

import {describe,expect,test} from 'bun:test';
import {
  createPgDurableIdentitySessionAuthority, PG_IDENTITY_SQL,
  type PgIdentityPool,
} from '../src/features/saasBlueprint/controlApi/server/pgDurableIdentitySessionAuthority';
const identity={issuer:'https://trusted.example.org/issuer',subject:'north'};
const HASH='a'.repeat(64);
const UUID='12345678-1234-4234-8234-123456789abc';
type Outcome='valid'|'empty'|'malformed'|'failure'|'commit-unknown'|'release-error'|'cancel';
function fixture(outcome:Outcome='valid'){
  const events:string[]=[];
  let poisoned=false;
  const signalAbort=new AbortController();
  const pool:PgIdentityPool={
    quarantine(reason){poisoned=true;events.push('QUARANTINE:'+reason);},
    async connect(signal){
      if(poisoned||signal.aborted)throw new Error('pool poisoned');
      events.push('CONNECT');
      return {
        async query(sql,params){
          events.push(sql);
          if(poisoned)throw new Error('unexpected poisoned connection');
          if(sql===PG_IDENTITY_SQL.commit&&outcome==='commit-unknown')
            throw new Error('TCP_DISCONNECT_SECRET');
          if(sql===PG_IDENTITY_SQL.actor||sql===PG_IDENTITY_SQL.session){
            if(outcome==='failure')throw new Error('SQL_PRIVATE_ERROR');
            if(outcome==='cancel')signalAbort.abort();
            if(outcome==='empty')return {rows:[]};
            if(outcome==='malformed')return {rows:[{
              actor_id:'actor-north',session_id:UUID,session_revision:1,
            }]};
            if(sql===PG_IDENTITY_SQL.actor){
              expect(params).toEqual([identity.issuer,identity.subject]);
              return {rows:[{actor_id:'actor-north'}]};
            }
            expect(params).toEqual(['actor-north','demo-north',HASH]);
            return {rows:[{session_id:UUID,session_revision:'17'}]};
          }
          if(sql!==PG_IDENTITY_SQL.begin&&sql!==PG_IDENTITY_SQL.role&&
             sql!==PG_IDENTITY_SQL.commit&&sql!==PG_IDENTITY_SQL.rollback)
            throw new Error('unexpected SQL');
          return {rows:[]};
        },
        async release(discard){
          events.push('RELEASE:'+discard);
          if(outcome==='release-error')throw new Error('RELEASE_SECRET');
        },
      };
    },
  };
  return {...createPgDurableIdentitySessionAuthority(pool),events,signalAbort};
}
describe('private PostgreSQL issuer identity and token session boundary',()=>{
  test('resolved issuer+subject only from a readonly transaction and fixed SQL',async()=>{
    const f=fixture();
    expect(await f.directory.resolveActorId(identity)).toBe('actor-north');
    expect(f.events).toEqual([
      'CONNECT',PG_IDENTITY_SQL.begin,PG_IDENTITY_SQL.role,
      PG_IDENTITY_SQL.actor,PG_IDENTITY_SQL.commit,'RELEASE:false',
    ]);
  });
  test('single verified token fingerprint resolves exactly one PG25 UUID+revision',async()=>{
    const f=fixture();
    expect(await f.sessions.resolve({actorId:'actor-north',
      tenantId:'demo-north',tokenFingerprint:HASH},
      new AbortController().signal)).toEqual({
        sessionId:UUID,sessionRevision:17,
      });
    expect(f.events).toContain(PG_IDENTITY_SQL.session);
    expect(f.events).toContain('RELEASE:false');
  });
  test('missing, revoked or expired PG identity/session returns no role or UUID',async()=>{
    const f=fixture('empty');
    expect(await f.directory.resolveActorId(identity)).toBeNull();
    expect(await f.sessions.resolve({actorId:'actor-north',
      tenantId:'demo-north',tokenFingerprint:HASH},
      new AbortController().signal)).toBeNull();
  });
  test('does not accept client-controlled tenant, session or malformed raw token',async()=>{
    const f=fixture();
    for(const input of [
      {actorId:'attacker!',tenantId:'demo-north',tokenFingerprint:HASH},
      {actorId:'actor-north',tenantId:'demo!other',tokenFingerprint:HASH},
      {actorId:'actor-north',tenantId:'demo-north',tokenFingerprint:'notsha256'},
      {actorId:'actor-north',tenantId:'demo-north',tokenFingerprint:UUID},
    ]){
      expect(await f.sessions.resolve(input,
        new AbortController().signal)).toBeNull();
    }
    expect(await f.directory.resolveActorId({...identity,
      subject:'bad\nsubject'})).toBeNull();
    expect(await f.directory.resolveActorId({issuer:'http://evil.org',
      subject:'north'})).toBeNull();
    expect(f.events).toHaveLength(0);
  });
  test('malformed SQL result fails closed and never returns extra columns',async()=>{
    const f=fixture('malformed');
    await expect(f.directory.resolveActorId(identity)).rejects.toThrow(
      'Durable identity source unavailable'
    );
    expect(f.events).toContain('QUARANTINE:query-uncertain');
    expect(f.events).toContain('RELEASE:true');
    expect(f.events).not.toContain(PG_IDENTITY_SQL.commit);
    await expect(f.sessions.resolve({actorId:'actor-north',tenantId:'demo-north',
      tokenFingerprint:HASH},new AbortController().signal)).rejects.toThrow(
      'Durable identity source unavailable'
    );
  });
  test('empty current identity is a normal deny, not pool corruption',async()=>{
    const f=fixture('empty');
    expect(await f.directory.resolveActorId(identity)).toBeNull();
    expect(f.events).toContain('RELEASE:false');
    expect(f.events.some(x=>x.startsWith('QUARANTINE:'))).toBe(false);
  });
  test('query error, unknown COMMIT and release error quarantine without leaking SQL',async()=>{
    for(const outcome of ['failure','commit-unknown','release-error'] as const){
      const f=fixture(outcome);
      const operation=f.directory.resolveActorId(identity);
      await expect(operation).rejects.toThrow('Durable identity source unavailable');
      expect(f.events.some(x=>x.startsWith('QUARANTINE:'))).toBe(true);
      expect(f.events.some(x=>x==='RELEASE:true')).toBe(
        outcome!=='release-error'
      );
      expect(f.events.join(',')).not.toContain('SQL_PRIVATE_ERROR');
    }
  });
  test('aborted session lookup fails before reservation',async()=>{
    const f=fixture();
    const ctrl=new AbortController();
    ctrl.abort();
    expect(await f.sessions.resolve({actorId:'actor-north',
      tenantId:'demo-north',tokenFingerprint:HASH},ctrl.signal)).toBeNull();
    expect(f.events).toHaveLength(0);
  });
  test('misconfigured connection pool rejected at initialization',()=>{
    expect(()=>createPgDurableIdentitySessionAuthority(undefined as never))
      .toThrow();
    expect(()=>createPgDurableIdentitySessionAuthority({
      connect:async()=>null as never,quarantine:null as never,
    })).toThrow();
  });
});

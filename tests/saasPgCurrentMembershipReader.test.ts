import {describe,expect,test} from 'bun:test';
import {
  createPgDurableIdentitySessionAuthority,PG_IDENTITY_SQL,
  type PgIdentityPool, type PgIdentityRow,
} from '../src/features/saasBlueprint/controlApi/server/pgDurableIdentitySessionAuthority';

type Scenario =
  'valid'|'none'|'duplicate'|'overflow'|'wrong-role'|'revoked-row'|
  'extra-field'|'bad-tenant'|'query-error'|'commit-unknown'|'release-error'|
  'acquire-error';
const ACTOR='actor-memberships';
const entry=(tenant_id:string, membership_role='tenant-admin',
  membership_status='active'):PgIdentityRow=>({
  tenant_id,membership_role,membership_status,
});

function fixture(scenario:Scenario='valid'){
  const events:string[]=[];
  let quarantined=false;
  const pool:PgIdentityPool={
    quarantine(reason){quarantined=true;events.push('QUARANTINE:'+reason);},
    async connect(signal){
      if(scenario==='acquire-error')throw Error('PRIVATE_CONNECTION_ERROR');
      if(quarantined||signal.aborted)throw Error('Private pool poisoned');
      events.push('CONNECT');
      return {
        async query(sql,params){
          events.push(sql);
          if(sql===PG_IDENTITY_SQL.memberships){
            expect(params).toEqual([ACTOR]);
            if(scenario==='query-error')throw Error('PRIVATE_SQL_DETAIL');
            const cases:Record<string,readonly PgIdentityRow[]>={
              valid:[entry('demo-north'),entry('demo-orbit','tenant-viewer')],
              none:[],duplicate:[entry('demo-north'),entry('demo-north')],
              overflow:Array.from({length:33},(_,i)=>entry('tenant-'+i)),
              'wrong-role':[entry('demo-north','super-admin')],
              'revoked-row':[entry('demo-north','tenant-admin','revoked')],
              'extra-field':[{...entry('demo-north'),raw_token:'never'}],
              'bad-tenant':[entry('bad/tenant')],
            };
            return {rows:cases[scenario]??cases.valid};
          }
          expect(params).toHaveLength(0);
          expect([
            PG_IDENTITY_SQL.begin,PG_IDENTITY_SQL.role,
            PG_IDENTITY_SQL.commit,PG_IDENTITY_SQL.rollback,
          ]).toContain(sql);
          if(sql===PG_IDENTITY_SQL.commit&&scenario==='commit-unknown')
            throw Error('PRIVATE_LOST_ACK');
          return {rows:[]};
        },
        async release(discard){
          events.push('RELEASE:'+String(discard));
          if(scenario==='release-error')throw Error('PRIVATE_RELEASE_FAILURE');
        },
      };
    },
  };
  return {...createPgDurableIdentitySessionAuthority(pool),events};
}

describe('Backend05: active tenant membership from restricted PostgreSQL',()=>{
  test('fixed read-only role SQL, exact DTO and two server-owned active roles',async()=>{
    const f=fixture();
    const got=await f.actors.lookup(ACTOR,new AbortController().signal);
    expect(got).toEqual({id:ACTOR,memberships:[
      {tenantId:'demo-north',role:'tenant-admin',status:'active'},
      {tenantId:'demo-orbit',role:'tenant-viewer',status:'active'},
    ]});
    expect(Object.isFrozen(got)).toBe(true);
    expect(Object.isFrozen(got!.memberships)).toBe(true);
    expect(f.events).toEqual([
      'CONNECT',PG_IDENTITY_SQL.begin,PG_IDENTITY_SQL.role,
      PG_IDENTITY_SQL.memberships,PG_IDENTITY_SQL.commit,'RELEASE:false',
    ]);
  });

  test('unknown, suspended or fully revoked actor has no memberships, no poison',async()=>{
    const f=fixture('none');
    expect(await f.actors.lookup(ACTOR,new AbortController().signal)).toBeNull();
    expect(f.events).toContain('RELEASE:false');
    expect(f.events.some(s=>s.startsWith('QUARANTINE'))).toBe(false);
  });

  test('invalid actor or cancelled request cannot reserve a PG connection',async()=>{
    const f=fixture();
    const signal=new AbortController().signal;
    for(const bad of ['','actor/foreign',' actor','\n','x'.repeat(129)]){
      expect(await f.actors.lookup(bad,signal)).toBeNull();
    }
    const ctrl=new AbortController();
    ctrl.abort();
    expect(await f.actors.lookup(ACTOR,ctrl.signal)).toBeNull();
    expect(f.events).toHaveLength(0);
  });

  test('duplicate tenants, overflow >32 and invalid roles/status/extra columns quarantine BEFORE COMMIT',async()=>{
    for(const scenario of [
      'duplicate','overflow','wrong-role','revoked-row','extra-field','bad-tenant',
    ] as const){
      const f=fixture(scenario);
      await expect(f.actors.lookup(ACTOR,new AbortController().signal))
        .rejects.toThrow('Durable identity source unavailable');
      expect(f.events).toContain('QUARANTINE:query-uncertain');
      expect(f.events).toContain('RELEASE:true');
      expect(f.events).not.toContain(PG_IDENTITY_SQL.commit);
    }
  });

  test('query failure, unknown read COMMIT, physical release uncertainty stop future authorization',async()=>{
    for(const scenario of [
      'query-error','commit-unknown','release-error','acquire-error',
    ] as const){
      const f=fixture(scenario);
      await expect(f.actors.lookup(ACTOR,new AbortController().signal))
        .rejects.toThrow('Durable identity source unavailable');
      expect(f.events.some(x=>x.startsWith('QUARANTINE:'))).toBe(true);
      expect(f.events.join(' ')).not.toContain('PRIVATE_');
      await expect(f.actors.lookup(ACTOR,new AbortController().signal))
        .rejects.toThrow('Durable identity source unavailable');
    }
  });
});

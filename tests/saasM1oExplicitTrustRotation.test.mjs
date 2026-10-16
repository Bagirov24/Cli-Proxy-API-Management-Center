import {afterAll,afterEach,beforeAll,describe,expect,test} from 'bun:test';
import {createServer} from 'node:https';
import {createDisposableM1nTlsFixture} from '../scripts/saas-staging/m1n-ephemeral-tls-fixture.mjs';
import {createM1oExplicitTrustRotation} from '../scripts/saas-staging/m1o-explicit-trust-rotation.mjs';

const active=process.env.GITHUB_ACTIONS==='true'&&
  process.env.SAAS_EPHEMERAL_M1M_PKCE_CI==='true'&&
  process.env.SAAS_EPHEMERAL_M1N_TLS_CI==='true'&&
  process.env.SAAS_EPHEMERAL_M1O_TRUST_CI==='true';
const ciTest=active?test:test.skip;
const callbackUri='http://127.0.0.1:18882/oauth/callback';
let fixture;const servers=[];
beforeAll(()=>{if(active)fixture=createDisposableM1nTlsFixture();});
afterAll(()=>fixture?.dispose());
afterEach(async()=>{await Promise.all(servers.splice(0).map(s=>new Promise(resolve=>{
  s.close(resolve);s.closeAllConnections?.();
})));});
async function serverFor(leaf){
  let hits=0,release=null,blocked=null;
  const server=createServer({cert:fixture[leaf].cert,key:fixture[leaf].key},
    async(req,res)=>{
      hits++;
      if(blocked){await blocked;}
      const bytes=Buffer.from('{"ok":true}');
      res.writeHead(200,{'Content-Type':'application/json',
        'Content-Length':String(bytes.length),'Connection':'close'});
      res.end(bytes);
    });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  servers.push(server);
  return {url:'https://127.0.0.1:'+server.address().port,hits:()=>hits,
    hold(){blocked=new Promise(resolve=>{release=resolve;});},
    resume(){release?.();blocked=null;}};
}
function policy(leaf,revision,caPem=fixture.trustedCaPem){
  return {revision,caPem,spkiSha256:fixture[leaf].spkiSha256};
}
function manager(url){
  return createM1oExplicitTrustRotation({
    baseUrl:url,callbackUri,initial:policy('primary',1),
  });
}
describe('M1o atomic single-active synthetic HTTPS trust epochs',()=>{
  test('opt-in required; no production/public trust registry',()=>{
    if(!active)expect(()=>createM1oExplicitTrustRotation({
      baseUrl:'https://127.0.0.1:1234',callbackUri,
      initial:{revision:1,caPem:'bad',spkiSha256:'a'.repeat(64)},
    })).toThrow();
  });
  ciTest('real pinned handshake, explicit replacement; old handle refuses before HTTP',async()=>{
    const rotated=await serverFor('rotated');
    const m=manager(rotated.url);
    const stale=m.currentTransport();
    await expect(stale.fetch(rotated.url+'/jwks')).rejects.toThrow();
    expect(rotated.hits()).toBe(0);
    const fresh=m.commitExplicitRotation({...policy('rotated',2),expectedRevision:1});
    expect(m.revision()).toBe(2);
    expect(m.currentTransport()).toBe(fresh);
    expect(m.fingerprints().revision).toBe(2);
    await expect(stale.fetch(rotated.url+'/jwks')).rejects.toThrow(/stale/);
    expect(rotated.hits()).toBe(0);
    expect((await fresh.fetch(rotated.url+'/jwks')).status).toBe(200);
    expect(rotated.hits()).toBe(1);
  });
  ciTest('stale CAS, skipped revision, duplicate and rollback leave trust unchanged',async()=>{
    const s=await serverFor('primary');const m=manager(s.url);
    for(const attempt of [
      {...policy('rotated',2),expectedRevision:0},
      {...policy('rotated',3),expectedRevision:1},
      {...policy('primary',2),expectedRevision:1},
      {...policy('untrusted',2,fixture.rogueCaPem),expectedRevision:0},
    ])expect(()=>m.commitExplicitRotation(attempt)).toThrow();
    expect(m.revision()).toBe(1);
    expect((await m.currentTransport().fetch(s.url+'/jwks')).status).toBe(200);
    m.commitExplicitRotation({...policy('rotated',2),expectedRevision:1});
    expect(()=>m.commitExplicitRotation({...policy('primary',3),expectedRevision:2}))
      .toThrow(/retired/);
    expect(m.revision()).toBe(2);
  });
  ciTest('untrusted CA never bypassed by matched leaf pin, SAN mismatch refuses HTTP',async()=>{
    const rogue=await serverFor('untrusted');
    const m=createM1oExplicitTrustRotation({
      baseUrl:rogue.url,callbackUri,initial:policy('primary',1),
    });
    const changed=m.commitExplicitRotation({
      ...policy('untrusted',2),expectedRevision:1,
    });
    await expect(changed.fetch(rogue.url+'/jwks')).rejects.toThrow();
    expect(rogue.hits()).toBe(0);
    const badSan=await serverFor('wrongHost');
    const n=createM1oExplicitTrustRotation({
      baseUrl:badSan.url,callbackUri,initial:policy('wrongHost',1),
    });
    await expect(n.currentTransport().fetch(badSan.url+'/jwks')).rejects.toThrow();
    expect(badSan.hits()).toBe(0);
  });
  ciTest('blocked response holds rotation; no partial policy publication',async()=>{
    const s=await serverFor('primary');const m=manager(s.url);s.hold();
    const pending=m.currentTransport().fetch(s.url+'/jwks');
    try{
      const deadline=Date.now()+3000;
      while(s.hits()===0&&Date.now()<deadline)
        await new Promise(resolve=>setTimeout(resolve,10));
      expect(s.hits()).toBe(1);
      expect(()=>m.commitExplicitRotation({
        ...policy('rotated',2),expectedRevision:1,
      })).toThrow(/in flight/);
      expect(m.revision()).toBe(1);
    }finally{s.resume();}
    expect((await pending).status).toBe(200);
  });
  ciTest('invalid policies fail atomically, no implicit key union or downgraded URL',async()=>{
    const s=await serverFor('primary');const m=manager(s.url);
    for(const input of [
      {revision:2,expectedRevision:1,caPem:'wrong',
        spkiSha256:fixture.rotated.spkiSha256},
      {...policy('rotated',2),expectedRevision:1,unexpected:true},
      {...policy('rotated',2),expectedRevision:1,spkiSha256:'Z'.repeat(64)},
    ])expect(()=>m.commitExplicitRotation(input)).toThrow();
    expect(m.revision()).toBe(1);
    await expect(m.currentTransport().fetch('http://127.0.0.1:1234/jwks'))
      .rejects.toThrow();
    expect((await m.currentTransport().fetch(s.url+'/jwks')).status).toBe(200);
  });
});

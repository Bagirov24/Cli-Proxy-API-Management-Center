import { afterEach, beforeAll, describe, expect, test } from 'bun:test';
import { createSyntheticOidcKeyRotation } from
  '../scripts/saas-staging/m1l-synthetic-oidc-rotation.mjs';

const ISSUER='https://m1l.synthetic-oidc.invalid/realm';
const AUDIENCE='saas-m1l-ci';
const NOW=1_800_000_000;
const enabled=process.env.GITHUB_ACTIONS==='true' &&
  process.env.SAAS_EPHEMERAL_M1L_OIDC_CI==='true';
const ciTest=enabled?test:test.skip;
const servers=[];
let rsa;
const bytes=value=>new TextEncoder().encode(value);
const encode=value=>btoa(String.fromCharCode(...value))
  .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
function expectRsaJwk(jwk,kid){
  return Object.freeze({
    alg:'RS256', e:jwk.e, key_ops:['verify'], kid,
    kty:'RSA', n:jwk.n, use:'sig',
  });
}
async function sign(kid='A',claims={},headers={}) {
  const head=encode(bytes(JSON.stringify({
    alg:'RS256',typ:'at+jwt',kid,...headers,
  })));
  const body=encode(bytes(JSON.stringify({
    iss:ISSUER,aud:AUDIENCE,sub:'sub-north',
    iat:NOW-20,exp:NOW+120,...claims,
  })));
  const signed=await crypto.subtle.sign('RSASSA-PKCS1-v1_5',
    rsa[kid].privateKey,bytes(head+'.'+body));
  return head+'.'+body+'.'+encode(new Uint8Array(signed));
}
async function fixture() {
  let issuer=ISSUER;
  let overrideJwks=null;
  let keyIds=['A'];
  let invalid=null;
  let redirect=false;
  const visits=[];
  const server=Bun.serve({
    hostname:'127.0.0.1',port:0,
    fetch(req){
      const pathname=new URL(req.url).pathname;
      visits.push(pathname);
      if(redirect && pathname==='/jwks')
        return Response.redirect('http://127.0.0.1:'+server.port+'/escape',302);
      if(invalid && pathname==='/jwks')
        return new Response(invalid,{headers:{'Content-Type':'application/json'}});
      if(pathname==='/.well-known/openid-configuration')
        return Response.json({
          issuer,id_token_signing_alg_values_supported:['RS256'],
          jwks_uri:overrideJwks??'http://127.0.0.1:'+server.port+'/jwks',
        });
      if(pathname==='/jwks')
        return Response.json({keys:keyIds.map(id=>expectRsaJwk(
          rsa[id].jwk,id))});
      return new Response('denied',{status:404});
    },
  });
  servers.push(server);
  const origin='http://127.0.0.1:'+server.port;
  const verifier=createSyntheticOidcKeyRotation({
    issuer:ISSUER,audience:AUDIENCE,
    discoveryUrl:origin+'/.well-known/openid-configuration',
    jwksUrl:origin+'/jwks',nowSeconds:()=>NOW,
  });
  return {
    verifier,visits,
    setKids(value){keyIds=value;},
    setIssuer(value){issuer=value;},
    setJwksOverride(value){overrideJwks=value;},
    setInvalid(value){invalid=value;},
    setRedirect(value){redirect=value;},
  };
}
beforeAll(async ()=>{
  if(!enabled)return;
  rsa={};
  for(const kid of ['A','B','C']){
    const key=await crypto.subtle.generateKey({
      name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
      publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256',
    },true,['sign','verify']);
    rsa[kid]={...key,jwk:await crypto.subtle.exportKey('jwk',key.publicKey)};
  }
});
afterEach(()=>{
  for(const server of servers.splice(0))server.stop(true);
});

describe('M1l default-off, CI-only pinned synthetic OIDC/JWKS key rotation',()=>{
  test('fail closed before explicit disposable CI opt-in',()=>{
    if(!enabled){
      expect(()=>createSyntheticOidcKeyRotation({
        issuer:ISSUER,audience:AUDIENCE,
        discoveryUrl:'http://127.0.0.1:1234/.well-known/openid-configuration',
        jwksUrl:'http://127.0.0.1:1234/jwks',nowSeconds:()=>NOW,
      })).toThrow();
    }
  });
  ciTest('accepts A -> A+B -> B, retires A even before JWT expiry',async()=>{
    const f=await fixture();
    const a=await sign('A'), b=await sign('B');
    expect(await f.verifier.reload(1)).toEqual({revision:1,keyIds:['A']});
    expect(await f.verifier.verifyAccessToken(a)).toEqual({
      issuer:ISSUER,subject:'sub-north',expiresAtSeconds:NOW+120,
    });
    expect(await f.verifier.verifyAccessToken(b)).toBeNull();
    f.setKids(['A','B']);
    expect(await f.verifier.reload(2)).toEqual({revision:2,keyIds:['A','B']});
    expect(await f.verifier.verifyAccessToken(a)).not.toBeNull();
    expect(await f.verifier.verifyAccessToken(b)).not.toBeNull();
    f.setKids(['B']);
    expect(await f.verifier.reload(3)).toEqual({revision:3,keyIds:['B']});
    expect(await f.verifier.verifyAccessToken(a)).toBeNull();
    expect(await f.verifier.verifyAccessToken(b)).not.toBeNull();
    expect(f.visits).toEqual(Array(3).fill(
      ['/.well-known/openid-configuration','/jwks']).flat());
  });
  ciTest('rejects unpinned issuer/JWKS and quarantines prior keyset',async()=>{
    const f=await fixture(),a=await sign();
    await f.verifier.reload(1);
    f.setIssuer('https://evil.invalid/issuer');
    await expect(f.verifier.reload(2)).rejects.toThrow('quarantined');
    expect(f.verifier.status()).toEqual({
      enabled:false,revision:null,quarantined:true,
    });
    expect(await f.verifier.verifyAccessToken(a)).toBeNull();
    f.setIssuer(ISSUER);
    f.setJwksOverride('http://169.254.169.254/latest/meta-data/');
    const prior=f.visits.length;
    await expect(f.verifier.reload(3)).rejects.toThrow('quarantined');
    expect(f.visits.slice(prior)).toEqual(['/.well-known/openid-configuration']);
    f.setJwksOverride(null);
    expect(await f.verifier.reload(4)).toEqual({revision:4,keyIds:['A']});
    expect(await f.verifier.verifyAccessToken(a)).not.toBeNull();
  });
  ciTest('rejects JWT algorithm/header injection, ID tokens and wrong claims',async()=>{
    const f=await fixture();
    await f.verifier.reload(1);
    for(const t of [
      await sign('A',{}, {typ:'JWT'}),
      await sign('A',{}, {alg:'none'}),
      await sign('A',{}, {jku:'http://127.0.0.1:9090/jwks'}),
      await sign('A',{iss:'https://other.invalid/'}),
      await sign('A',{aud:'other-audience'}),
      await sign('A',{iat:NOW+60}),
      await sign('A',{exp:NOW-1}),
      await sign('A',{exp:NOW+8000}),
      await sign('A',{sub:'\nunsafe'}),
    ]) expect(await f.verifier.verifyAccessToken(t)).toBeNull();
  });
  ciTest('quarantines retired kid rollback, duplicate kid and invalid key attributes',async()=>{
    const f=await fixture(),a=await sign();
    await f.verifier.reload(1);
    f.setKids(['B']);
    await f.verifier.reload(2);
    f.setKids(['A']);
    await expect(f.verifier.reload(3)).rejects.toThrow('quarantined');
    expect(await f.verifier.verifyAccessToken(a)).toBeNull();
    f.setKids(['B','B']);
    await expect(f.verifier.reload(4)).rejects.toThrow('quarantined');
    f.setInvalid(JSON.stringify({keys:[{
      ...expectRsaJwk(rsa.B.jwk,'B'),d:'private-must-not-be-accepted',
    }]}));
    await expect(f.verifier.reload(5)).rejects.toThrow('quarantined');
    f.setInvalid(JSON.stringify({keys:[{
      ...expectRsaJwk(rsa.B.jwk,'B'),alg:'HS256',
    }]}));
    await expect(f.verifier.reload(6)).rejects.toThrow('quarantined');
    f.setInvalid(null);
    f.setKids(['B']);
    expect(await f.verifier.reload(7)).toEqual({revision:7,keyIds:['B']});
  });
  ciTest('invalid refresh version, response redirect and oversized body deny ALL tokens',async()=>{
    const f=await fixture(),a=await sign();
    await f.verifier.reload(1);
    await expect(f.verifier.reload(1)).rejects.toThrow('quarantined');
    expect(await f.verifier.verifyAccessToken(a)).toBeNull();
    f.setRedirect(true);
    await expect(f.verifier.reload(2)).rejects.toThrow('quarantined');
    f.setRedirect(false);
    f.setInvalid('{"keys":['+' '.repeat(17*1024)+']}');
    await expect(f.verifier.reload(3)).rejects.toThrow('quarantined');
    f.setInvalid(null);
    await f.verifier.reload(4);
    expect(await f.verifier.verifyAccessToken(a)).not.toBeNull();
  });
  ciTest('refuses external, mispinned or insecure discovery/JWKS URLs',async()=>{
    for(const [a,b] of [
      ['http://example.org/.well-known/openid-configuration',
        'http://example.org/jwks'],
      ['http://127.0.0.1:1234/.well-known/openid-configuration',
        'http://localhost:1234/jwks'],
      ['http://127.0.0.1:1234/.well-known/openid-configuration',
        'http://127.0.0.1:4567/jwks'],
      ['http://127.0.0.1:1234/.well-known/openid-configuration?evil=1',
        'http://127.0.0.1:1234/jwks'],
    ]){
      expect(()=>createSyntheticOidcKeyRotation({
        issuer:ISSUER,audience:AUDIENCE,discoveryUrl:a,
        jwksUrl:b,nowSeconds:()=>NOW,
      })).toThrow();
    }
  });
});

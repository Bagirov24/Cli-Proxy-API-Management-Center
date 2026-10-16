import {beforeAll,describe,expect,test} from 'bun:test';
import {
  createOperatorPinnedOidcAccessVerifier,
  pinnedOidcConfigFromServerEnvironment,
  type OperatorPinnedOidcAccessConfig,
} from '../src/features/saasBlueprint/controlApi/server/operatorPinnedOidcAccessVerifier';

const ISSUER='https://accounts.operator-service.org/issuer';
const AUDIENCE='urn:saas:management-api';
const NOW=()=>Math.floor(Date.now()/1000);
const bytes=(s:string)=>new TextEncoder().encode(s);
const b64=(v:Uint8Array)=>btoa(String.fromCharCode(...v))
  .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
const json=(v:unknown)=>b64(bytes(JSON.stringify(v)));
type Pair=CryptoKeyPair;
let A: Pair;
let B: Pair;
let aJwk: JsonWebKey;
let bJwk: JsonWebKey;
beforeAll(async()=>{
  const generate=()=>crypto.subtle.generateKey(
    {name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
      publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},
    true,['sign','verify'],
  ) as Promise<CryptoKeyPair>;
  A=await generate();
  B=await generate();
  aJwk=await crypto.subtle.exportKey('jwk',A.publicKey);
  bJwk=await crypto.subtle.exportKey('jwk',B.publicKey);
});
function pub(jwk:JsonWebKey,kid:string) {
  return {kty:'RSA',kid,alg:'RS256',use:'sig',
    n:jwk.n!,e:jwk.e!};
}
function config(keys:unknown[],overrides:Partial<OperatorPinnedOidcAccessConfig>={}):
  OperatorPinnedOidcAccessConfig {
  return {issuer:ISSUER,audience:AUDIENCE,
    pinnedPublicJwksJson:JSON.stringify({keys}),...overrides};
}
async function token(pair:Pair,kid:string,
  claimOverrides:Record<string,unknown>={},
  headerOverrides:Record<string,unknown>={}) {
  const header=json({alg:'RS256',typ:'at+jwt',kid,...headerOverrides});
  const claims=json({iss:ISSUER,aud:AUDIENCE,sub:'subject-from-issuer',
    iat:NOW()-20,exp:NOW()+300,...claimOverrides});
  const data=header+'.'+claims;
  const signature=new Uint8Array(await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',pair.privateKey,bytes(data),
  ));
  return data+'.'+b64(signature);
}

describe('real operator-curated RSA access-token public key trust',()=>{
  test('accepts only real signed at+jwt, returns issuer/subject not role claims',async()=>{
    const verify=await createOperatorPinnedOidcAccessVerifier(config([
      pub(aJwk,'issuer-2026-a'),
    ]));
    const t=await token(A,'issuer-2026-a',{
      actorId:'fake-actor',role:'tenant-owner',tenantId:'different-tenant',
    });
    const got=await verify.verifyAccessToken(t);
    expect(got).toEqual({
      issuer:ISSUER,subject:'subject-from-issuer',
      expiresAtSeconds:expect.any(Number),
    });
    expect(JSON.stringify(got)).not.toContain('fake-actor');
    expect(JSON.stringify(got)).not.toContain('tenant-owner');
    expect(JSON.stringify(got)).not.toContain('different-tenant');
  });

  test('forged key ID/header, issuer, audience, typ and RS256 signature deny',async()=>{
    const verify=await createOperatorPinnedOidcAccessVerifier(config([
      pub(aJwk,'issuer-2026-a'),
    ]));
    const invalid=[
      await token(B,'issuer-2026-a'),
      await token(A,'unknown-kid'),
      await token(A,'issuer-2026-a',{iss:'https://attacker.org/'}),
      await token(A,'issuer-2026-a',{aud:'some-client-id'}),
      await token(A,'issuer-2026-a',{}, {typ:'JWT'}),
      await token(A,'issuer-2026-a',{}, {typ:'id+jwt'}),
      await token(A,'issuer-2026-a',{}, {jku:'https://attacker.org/jwks'}),
      await token(A,'issuer-2026-a',{}, {x5u:'https://attacker.org/cert'}),
      await token(A,'issuer-2026-a',{}, {alg:'none'}),
      await token(A,'issuer-2026-a',{exp:NOW()-1}),
      await token(A,'issuer-2026-a',{nbf:NOW()+90}),
      await token(A,'issuer-2026-a',{exp:NOW()+999}),
    ];
    for(const t of invalid) expect(await verify.verifyAccessToken(t)).toBeNull();
    expect(await verify.verifyAccessToken('not.a.jwt')).toBeNull();
    expect(await verify.verifyAccessToken('a'.repeat(8193))).toBeNull();
  });

  test('explicit dual-key trust and operator removal of old key fail closed',async()=>{
    const old=await token(A,'old');
    const future=await token(B,'future');
    const verifierOld=await createOperatorPinnedOidcAccessVerifier(
      config([pub(aJwk,'old')])
    );
    const verifierDual=await createOperatorPinnedOidcAccessVerifier(
      config([pub(aJwk,'old'),pub(bJwk,'future')])
    );
    const verifierFuture=await createOperatorPinnedOidcAccessVerifier(
      config([pub(bJwk,'future')])
    );
    expect(await verifierOld.verifyAccessToken(old)).not.toBeNull();
    expect(await verifierOld.verifyAccessToken(future)).toBeNull();
    expect(await verifierDual.verifyAccessToken(old)).not.toBeNull();
    expect(await verifierDual.verifyAccessToken(future)).not.toBeNull();
    expect(await verifierFuture.verifyAccessToken(old)).toBeNull();
    expect(await verifierFuture.verifyAccessToken(future)).not.toBeNull();
  });

  test('does not import URL authority, private RSA parameters, weak or malformed JWKS',async()=>{
    const valid=pub(aJwk,'a');
    const malformed=[
      {keys:[]},
      {keys:[{...valid,kty:'oct',alg:'HS256'}]},
      {keys:[{...valid,d:'private-key-material'}]},
      {keys:[{...valid,x5u:'https://evil.org/key'}]},
      {keys:[{...valid,e:'Aw'}]},
      {keys:[{...valid,n:'abc'}]},
      {keys:[{...valid,alg:'RS512'}]},
      {keys:[{...valid,use:'enc'}]},
      {keys:[{...valid,key_ops:['sign']}]},
      {keys:[{...valid,key_ops:['verify','sign']}]},
      {keys:[{...valid,kid:'wrong kid'}]},
      {keys:[valid,valid]},
      {keys:[valid,{...valid,kid:'same-key-other-kid'}]},
      {keys:[valid,valid,valid,valid,valid]},
      {keys:[valid],jku:'https://host.invalid/jwks'},
    ];
    for(const doc of malformed){
      await expect(createOperatorPinnedOidcAccessVerifier(config([],
        {pinnedPublicJwksJson:JSON.stringify(doc)}
      ))).rejects.toThrow('Operator-pinned');
    }
  });

  test('misconfigured issuer and resource audience fail before any request',async()=>{
    for(const issuer of [
      '', 'http://accounts.operator-service.org/issuer',
      'https://localhost/', 'https://127.0.0.1/',
      'https://login.example.test/',
      'https://accounts.operator-service.org/?secret=a',
      'https://operator:password@accounts.operator-service.org/',
      'https://accounts.operator-service.org/#fragment',
    ]){
      await expect(createOperatorPinnedOidcAccessVerifier(
        config([pub(aJwk,'a')],{issuer})
      )).rejects.toThrow('Operator-pinned');
    }
    for(const audience of ['', 'a b','\n','A'.repeat(257)]){
      await expect(createOperatorPinnedOidcAccessVerifier(
        config([pub(aJwk,'a')],{audience})
      )).rejects.toThrow('Operator-pinned');
    }
  });

  test('server-only environment allowlist never falls back to synthetic credentials',async()=>{
    expect(()=>pinnedOidcConfigFromServerEnvironment({})).toThrow();
    expect(()=>pinnedOidcConfigFromServerEnvironment({
      SAAS_OIDC_ISSUER:ISSUER, SAAS_OIDC_AUDIENCE:AUDIENCE,
    })).toThrow();
    const c=pinnedOidcConfigFromServerEnvironment({
      SAAS_OIDC_ISSUER:ISSUER,
      SAAS_OIDC_AUDIENCE:AUDIENCE,
      SAAS_OIDC_PINNED_PUBLIC_JWKS_JSON:JSON.stringify({
        keys:[pub(aJwk,'active')],
      }),
      // Any HTTP claims, actor/role or signer secrets are NOT config inputs.
      role:'tenant-owner',actorId:'external' 
    } as never);
    expect(Object.keys(c).sort()).toEqual([
      'audience','issuer','pinnedPublicJwksJson',
    ]);
    const verify=await createOperatorPinnedOidcAccessVerifier(c);
    expect(await verify.verifyAccessToken(await token(A,'active'))).not.toBeNull();
  });
});

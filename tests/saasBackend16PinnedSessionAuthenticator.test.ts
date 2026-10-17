import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  createBackend16PinnedSessionAuthenticator,
  type Backend16AuthoritativeSessionLookup,
  type Backend16CurrentSessionSnapshot,
  type Backend16PinnedSessionLookupKey,
} from '../src/features/saasBlueprint/controlApi/server/backend16PinnedSessionAuthenticator.ts';
import {createBackend16PrivateReadHandler}
  from '../src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts';
import {createOperatorPinnedOidcAccessVerifier}
  from '../src/features/saasBlueprint/controlApi/server/operatorPinnedOidcAccessVerifier.ts';
import {createOperatorVerifiedSubjectFingerprintGate}
  from '../src/features/saasBlueprint/controlApi/server/verifiedSubjectBinding.ts';

const ISSUER = 'https://login.saas-unit.example.net/tenant';
const AUDIENCE = 'saas-control-api';
const TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OTHER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PROJECT = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const SESSION = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const BINDING = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const ORIGIN = 'https://private.saas-unit.example.net';
const NOW = Math.floor(Date.now()/1000);
const NEXT = NOW + 300;
const PREFIX = 'saas:issuer-subject:v1\0';

type KeyMaterial = {
  readonly privateKey: CryptoKey;
  readonly publicJwks: string;
};
const material: Promise<KeyMaterial> = (async () => {
  const pair = await crypto.subtle.generateKey(
    {name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
     publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},
    true,['sign','verify'],
  );
  const jwk=await crypto.subtle.exportKey('jwk',pair.publicKey);
  return {
    privateKey:pair.privateKey,
    publicJwks:JSON.stringify({keys:[{
      alg:'RS256',e:'AQAB',kid:'test-k1',kty:'RSA',
      n:jwk.n,use:'sig',key_ops:['verify'],
    }]}),
  };
})();
const b64=(s:string)=>Buffer.from(s,'utf8').toString('base64url');
function hex(raw:string): string {
  return createHash('sha256').update(raw,'utf8').digest('hex');
}
async function token(
  opts: {
    sub?:string, aud?:string, iss?:string, typ?:string,
    kid?:string, exp?:number, iat?:number, jti?:string
  } = {},
):Promise<string> {
  const keys=await material;
  const header=b64(JSON.stringify({alg:'RS256',typ:opts.typ??'at+jwt',
    kid:opts.kid??'test-k1'}));
  const claims=b64(JSON.stringify({
    iss:opts.iss??ISSUER,sub:opts.sub??'operator-enrolled-subject',
    aud:opts.aud??AUDIENCE,iat:opts.iat??NOW,
    exp:opts.exp??NEXT,jti:opts.jti??'session-token-a',
  }));
  const raw=header+'.'+claims;
  const signature=await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',keys.privateKey,
    new TextEncoder().encode(raw),
  );
  return raw+'.'+Buffer.from(signature).toString('base64url');
}
function snapshot(
  key:Backend16PinnedSessionLookupKey,
  patch:Partial<Backend16CurrentSessionSnapshot>={},
):Backend16CurrentSessionSnapshot {
  return {
    issuer:key.issuer,
    subjectFingerprintSha256:key.subjectFingerprintSha256,
    tokenFingerprintSha256:key.tokenFingerprintSha256,
    pgLogin:'saas_principal_operator_01',
    sessionId:SESSION,bindingId:BINDING,
    sessionExpiresAtMs:(NOW+500)*1000,
    ...patch,
  };
}
async function fixture(
  resolve:Backend16AuthoritativeSessionLookup['resolveCurrent'] =
    async key => snapshot(key),
) {
  const keys=await material;
  const called:{keys:Backend16PinnedSessionLookupKey[],aborted:number}={
    keys:[],aborted:0,
  };
  const authenticate=await createBackend16PinnedSessionAuthenticator({
    oidc:{issuer:ISSUER,audience:AUDIENCE,pinnedPublicJwksJson:keys.publicJwks},
    sessionAuthority:{async resolveCurrent(key,signal){
      called.keys.push(key);
      if(signal.aborted)called.aborted++;
      return resolve(key,signal);
    }},
    nowMs:()=>NOW*1000,
  });
  return {authenticate,called};
}
const signal=()=>new AbortController().signal;

test('operator JWKS signature and subject fingerprint pass their standalone gates',async()=>{
  const keys=await material;
  const jwt=await token();
  const verifier=await createOperatorPinnedOidcAccessVerifier({
    issuer:ISSUER,audience:AUDIENCE,pinnedPublicJwksJson:keys.publicJwks,
  });
  const identity=await verifier.verifyAccessToken(jwt);
  assert.ok(identity,'pinned RS256 verifier rejected fixture');
  assert.equal(identity.issuer,ISSUER);
  assert.equal(identity.subject,'operator-enrolled-subject');
  const fingerprint=await createOperatorVerifiedSubjectFingerprintGate(verifier,()=>NOW)
    .verify(jwt);
  assert.ok(fingerprint,'verified subject fingerprint gate rejected fixture');
  assert.equal(fingerprint.fingerprint,hex(PREFIX+ISSUER+'\0'+'operator-enrolled-subject'));
});

test('real RS256 at+jwt produces only pinned immutable enrolled session metadata',async()=>{
  let returned:Backend16CurrentSessionSnapshot|null=null;
  const {authenticate,called}=await fixture(async key=>{
    returned=snapshot(key);
    return returned;
  });
  const jwt=await token();
  const result=await authenticate(jwt,signal());
  assert.equal(called.keys.length,1,'signed JWT never reached session lookup');
  assert.ok(returned,'current session authority failed to return its snapshot');
  const key=called.keys[0], returned=snapshot(key);
  const fixtureConditions={
    issuer:returned.issuer===key.issuer,
    subject:returned.subjectFingerprintSha256===key.subjectFingerprintSha256,
    bearer:returned.tokenFingerprintSha256===key.tokenFingerprintSha256,
    subjectHex:/^[a-f0-9]{64}$/.test(returned.subjectFingerprintSha256),
    bearerHex:/^[a-f0-9]{64}$/.test(returned.tokenFingerprintSha256),
    login:/^[a-z][a-z0-9_]{2,62}$/.test(returned.pgLogin),
    loginReserved:!returned.pgLogin.startsWith('pg_'),
    session:/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(returned.sessionId),
    binding:/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(returned.bindingId),
    validExpiry:returned.sessionExpiresAtMs>NOW*1000 &&
      returned.sessionExpiresAtMs<=NOW*1000+15*60_000,
    tokenExpiry:NEXT*1000>NOW*1000 &&
      NEXT*1000<=NOW*1000+15*60_000,
  };
  assert.ok(Object.values(fixtureConditions).every(Boolean),
    JSON.stringify(fixtureConditions));
  assert.deepEqual(result,{
    kind:'verified-server-session',
    issuer:ISSUER,
    subjectFingerprintSha256:hex(PREFIX+ISSUER+'\0'+'operator-enrolled-subject'),
    pgLogin:'saas_principal_operator_01',
    sessionId:SESSION,
    bindingId:BINDING,
    sessionExpiresAtMs:NEXT*1000,
  });
  assert.equal(Object.isFrozen(result),true);
  assert.equal(called.keys.length,1);
  assert.deepEqual(called.keys[0],{
    issuer:ISSUER,
    subjectFingerprintSha256:result?.subjectFingerprintSha256,
    tokenFingerprintSha256:hex(jwt),
    tokenExpiresAtSeconds:NEXT,
  });
  assert.equal(Object.isFrozen(called.keys[0]),true);
  assert.equal(JSON.stringify(result).includes(jwt),false);
  assert.equal(JSON.stringify(called.keys).includes('operator-enrolled-subject'),false);
});

test('DB session shorter than verified access token is the effective TTL',async()=>{
  const {authenticate}=await fixture(async key=>
    snapshot(key,{sessionExpiresAtMs:(NOW+100)*1000}));
  const p=await authenticate(await token(),signal());
  assert.equal(p?.sessionExpiresAtMs,(NOW+100)*1000);
});

test('invalid JWT, modified payload, wrong audience and ID tokens never query session',async()=>{
  const {authenticate,called}=await fixture();
  const good=await token();
  const pieces=good.split('.');
  const forged=pieces[0]+'.'+b64(JSON.stringify({
    iss:ISSUER,sub:'attacker',aud:AUDIENCE,iat:NOW,exp:NEXT,
  }))+'.'+pieces[2];
  const bad=[
    '', 'three.unsafe.parts',
    forged,
    await token({typ:'JWT'}),
    await token({aud:'other-resource'}),
    await token({iss:'https://other.unit-example.net'}),
    await token({exp:NOW-1,iat:NOW-100}),
    await token({kid:'unapproved-kid'}),
  ];
  for(const jwt of bad){
    assert.equal(await authenticate(jwt,signal()),null);
  }
  assert.equal(called.keys.length,0);
});

test('untrusted DB session fields cannot substitute for the verified bearer',async()=>{
  const cases:Partial<Backend16CurrentSessionSnapshot>[]=[
    {issuer:'https://attacker.unit-example.net'},
    {subjectFingerprintSha256:'0'.repeat(64)},
    {tokenFingerprintSha256:'f'.repeat(64)},
    {tokenFingerprintSha256:'not-a-hash'},
    {pgLogin:'postgres'},
    {pgLogin:'saas_schema_migrator'},
    {pgLogin:'saas_runtime_reader'},
    {pgLogin:'saas_runtime_writer'},
    {pgLogin:'a-bad-login'},
    {pgLogin:'pg_superuser'},
    {sessionId:'made-up-uuid'},
    {bindingId:'made-up-uuid'},
    {sessionExpiresAtMs:NOW*1000},
    {sessionExpiresAtMs:(NOW+1200)*1000},
    {sessionExpiresAtMs:Number.POSITIVE_INFINITY},
  ];
  for(const fields of cases) {
    const {authenticate}=await fixture(async key=>snapshot(key,fields));
    const result=await authenticate(await token(),signal());
    // The physical PG adapter must ALSO attest real session_user and role
    // flags. This string guard only rejects known dangerous role namespaces.
    assert.equal(result,null,JSON.stringify(fields));
  }
});

test('two signed JWTs for same OIDC subject have distinct bearer fingerprints',async()=>{
  const first=await token({jti:'token-1'});
  const second=await token({jti:'token-2'});
  const expected=hex(first);
  let calls=0;
  const {authenticate}=await fixture(async key=>{
    calls++;
    return snapshot(key,{tokenFingerprintSha256:expected});
  });
  assert.ok(await authenticate(first,signal()));
  assert.equal(await authenticate(second,signal()),null);
  assert.equal(calls,2);
});

test('request cancellation and authority failure fail closed with no retry',async()=>{
  const jwt=await token();
  const abort=new AbortController();
  abort.abort();
  const noCalls=await fixture(async()=>{throw Error('must never be called');});
  assert.equal(await noCalls.authenticate(jwt,abort.signal),null);
  assert.equal(noCalls.called.keys.length,0);

  const mid=new AbortController();
  const midFlight=await fixture(async key=>{
    mid.abort();
    return snapshot(key);
  });
  assert.equal(await midFlight.authenticate(jwt,mid.signal),null);
  assert.equal(midFlight.called.keys.length,1);

  const failure=await fixture(async()=>{throw Error('SQLSTATE 08006 token private');});
  assert.equal(await failure.authenticate(jwt,signal()),null);
  assert.equal(failure.called.keys.length,1);
});

test('invalid session authority and unpinned JWKS fail during startup',async()=>{
  const keys=await material;
  await assert.rejects(createBackend16PinnedSessionAuthenticator({
    oidc:{issuer:ISSUER,audience:AUDIENCE,pinnedPublicJwksJson:keys.publicJwks},
    sessionAuthority:null as unknown as Backend16AuthoritativeSessionLookup,
  }),/session authority unavailable/);
  await assert.rejects(createBackend16PinnedSessionAuthenticator({
    oidc:{issuer:ISSUER,audience:AUDIENCE,pinnedPublicJwksJson:'{"keys":[]}'},
    sessionAuthority:{resolveCurrent:async()=>null},
  }),/configuration refused/);
});

test('integrates only as unmounted private handler authenticate port',async()=>{
  const {authenticate}=await fixture();
  let reads=0;
  const h=createBackend16PrivateReadHandler({
    enabled:()=>true,
    expectedOrigin:ORIGIN,
    authenticate,
    readAuthorized:async(_principal,tenant)=>{
      reads++;
      return tenant===TENANT
        ? {kind:'authorized' as const,tenantId:tenant,projectIds:[PROJECT]}
        : {kind:'denied' as const};
    },
    now:()=>NOW*1000,
  });
  const jwt=await token();
  const mk=(tenant:string,bearer:string)=>
    new Request(ORIGIN+'/internal/saas/v1/tenants/'+tenant+'/projects',{
      headers:{Authorization:'Bearer '+bearer},
    });
  const allowed=await h(mk(TENANT,jwt));
  assert.equal(allowed.status,200);
  assert.deepEqual(await allowed.json(),{tenantId:TENANT,projectIds:[PROJECT]});
  const denied=await h(mk(OTHER,jwt));
  assert.equal(denied.status,404);
  const parts=jwt.split('.');
  const corrupted=parts[0]+'.'+parts[1]+'.'+
    (parts[2][0]==='a'?'b':'a')+parts[2].slice(1);
  const bad=await h(mk(TENANT,corrupted));
  assert.equal(bad.status,401);
  assert.equal(reads,2);
  // The readAuthorized port is deliberately a TEST DOUBLE here, not PostgreSQL.
});

test('authority response only carries server-selected fields, never secrets',async()=>{
  const {authenticate}=await fixture(async key=>({
    ...snapshot(key),
    privateSessionKey:'private_secret',
    operatorNotes:'should not serialize',
  }));
  const result=await authenticate(await token(),signal());
  assert.ok(result);
  assert.equal(JSON.stringify(result).includes('private_secret'),false);
  assert.equal(JSON.stringify(result).includes('operatorNotes'),false);
});

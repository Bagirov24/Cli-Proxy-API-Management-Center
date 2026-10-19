import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {
  BACKEND16_REQUIRED_STAGING_GATES,
  backend16CanonicalOperatorKeyset,
  backend16CanonicalReleaseEvidence,
  backend16CanonicalSignedTechnicalBundle,
  verifyBackend16ReleaseEvidence,
  type Backend16StagingGate,
  type Backend16EvidenceSignerRole,
  type Backend16OperatorEvidenceKey,
  type Backend16ReleaseEvidence,
  type Backend16ReleaseEvidencePolicy,
  type Backend16SignedReleaseEvidence,
} from '../src/features/saasBlueprint/controlApi/server/backend16ReleaseEvidenceGate.ts';

const REPO='Bagirov24/Cli-Proxy-API-Management-Center';
const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const STAGING='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const COMMIT='8'.repeat(40);
// Tests validate the exported production entrypoint against the REAL clock.
const NOW=Date.now();
const VALID_UNTIL=NOW+10*60_000;
const ROLES=[
  'db-operator','security-reviewer','runtime-reviewer','operations-reviewer',
] as const;
const ROLE:Record<Backend16StagingGate,Backend16EvidenceSignerRole>={
  'sql0008-installed-catalog-readback':'db-operator',
  'restore-drill-proven':'operations-reviewer',
  'pg-tls-verify-full-proven':'security-reviewer',
  'vault-versioned-login-iam-proven':'security-reviewer',
  'live-oidc-session-revocation-proven':'security-reviewer',
  'durable-offhost-audit-replay-proven':'security-reviewer',
  'private-two-tenant-e2e-proven':'runtime-reviewer',
  'staging-canary-rollback-proven':'runtime-reviewer',
  'security-release-review':'security-reviewer',
  'operations-release-review':'operations-reviewer',
};
const APPROVALS=new Set(['security-release-review','operations-release-review']);
const DIGEST=(s:string)=>createHash('sha256').update(s).digest('hex');
const HEX=(bytes:ArrayBuffer)=>Array.from(new Uint8Array(bytes),b=>
  b.toString(16).padStart(2,'0')).join('');
type Keyset=Map<Backend16EvidenceSignerRole,CryptoKeyPair>;
interface Fixture {
  policy:Backend16ReleaseEvidencePolicy;
  attestations:Backend16SignedReleaseEvidence[];
  keypairs:Keyset;
}
let fixtures:Promise<Fixture>|undefined;

async function reSign(
  e:Backend16ReleaseEvidence, keys:Keyset,
):Promise<Backend16SignedReleaseEvidence>{
  const key=keys.get(e.role)?.privateKey;
  assert.ok(key);
  return {
    evidence:e,
    signatureHex:HEX(await crypto.subtle.sign(
      'Ed25519',key,new TextEncoder().encode(
        backend16CanonicalReleaseEvidence(e)))),
  };
}
async function makeFixture():Promise<Fixture>{
  const keypairs=new Map<Backend16EvidenceSignerRole,CryptoKeyPair>();
  const signers:Backend16OperatorEvidenceKey[]=[];
  for(const [i,role] of ROLES.entries()){
    const kp=await crypto.subtle.generateKey(
      'Ed25519',true,['sign','verify']) as CryptoKeyPair;
    keypairs.set(role,kp);
    const publicKeyHex=HEX(await crypto.subtle.exportKey('raw',kp.publicKey));
    signers.push({role,signerId:'operator-'+(i+1),publicKeyHex});
  }
  const policy:Backend16ReleaseEvidencePolicy={
    expectedSourceCommitSha:COMMIT,
    approvedSignerKeysetSha256:DIGEST(
      backend16CanonicalOperatorKeyset(signers)),
    signers,
  };
  const technical=BACKEND16_REQUIRED_STAGING_GATES.filter(
    gate=>!APPROVALS.has(gate));
  const proofs=new Map(technical.map(gate=>[gate,DIGEST('proof/'+gate)]));
  const attestations:Backend16SignedReleaseEvidence[]=[];
  for(const gate of technical){
    const role=ROLE[gate];
    const signerId=signers.find(k=>k.role===role)?.signerId;
    assert.ok(signerId);
    const e:Backend16ReleaseEvidence={
      schema:'backend16-release-evidence-v1',gate,role,signerId,
      repo:REPO,projectId:PROJECT,environmentId:STAGING,
      sourceCommitSha:COMMIT,observedAtMs:NOW-2000,
      validUntilMs:VALID_UNTIL,outcome:'pass',
      proofUri:'https://github.com/'+REPO+'/actions/runs/39062972244',
      proofSha256:proofs.get(gate)!,
    };
    attestations.push(await reSign(e,keypairs));
  }
  const approvalDigest=DIGEST(
    backend16CanonicalSignedTechnicalBundle(attestations));
  for(const gate of BACKEND16_REQUIRED_STAGING_GATES.filter(
    gate=>APPROVALS.has(gate))){
    const role=ROLE[gate];
    const signerId=signers.find(k=>k.role===role)?.signerId;
    assert.ok(signerId);
    const e:Backend16ReleaseEvidence={
      schema:'backend16-release-evidence-v1',gate,role,signerId,
      repo:REPO,projectId:PROJECT,environmentId:STAGING,
      sourceCommitSha:COMMIT,observedAtMs:NOW-1000,
      validUntilMs:VALID_UNTIL,outcome:'pass',
      proofUri:'https://github.com/'+REPO+'/actions/runs/39062972244',
      proofSha256:approvalDigest,
    };
    attestations.push(await reSign(e,keypairs));
  }
  return{policy,attestations,keypairs};
}
async function fixture():Promise<Fixture>{
  if(!fixtures)fixtures=makeFixture();
  const f=await fixtures;
  return {
    policy:{...f.policy,signers:f.policy.signers.map(k=>({...k}))},
    attestations:f.attestations.map(t=>({
      evidence:{...t.evidence},signatureHex:t.signatureHex,
    })),
    keypairs:f.keypairs,
  };
}
async function verify(input:Fixture){
  return verifyBackend16ReleaseEvidence({
    policy:input.policy,
    attestations:input.attestations,
  });
}
function changed(
  f:Fixture,gate:Backend16StagingGate,delta:Partial<Backend16ReleaseEvidence>,
):Fixture{
  return {...f,attestations:f.attestations.map(t=>t.evidence.gate===gate?
    {evidence:{...t.evidence,...delta},signatureHex:t.signatureHex}:t)};
}
const BLOCKED=BACKEND16_REQUIRED_STAGING_GATES;

test('signed, bounded ten-gate case is ONLY ready for independent review, not production',async()=>{
  const f=await fixture();
  const x=await verify(f);
  assert.deepEqual(x,{
    result:'READY_FOR_INDEPENDENT_REVIEW',
    missing:[],productionAuthorized:false,
  });
  assert.equal(Object.isFrozen(x),true);
  assert.equal(Object.isFrozen(x.missing),true);
  assert.equal(f.attestations.length,10);
  assert.equal(new Set(f.attestations.map(t=>t.evidence.gate)).size,10);
});

test('missing and duplicate or unknown gate cannot create partial authorization',async()=>{
  const f=await fixture();
  f.attestations.pop();
  const a=await verify(f);
  assert.equal(a.result,'BLOCKED');
  assert.deepEqual(a.missing,BLOCKED);
  assert.equal(a.productionAuthorized,false);
  const x=await fixture();
  x.attestations[9]=x.attestations[8];
  assert.equal((await verify(x)).result,'BLOCKED');
  const y=await fixture();
  y.attestations[9]={
    ...y.attestations[9],
    evidence:{...y.attestations[9].evidence,gate:'new-unknown-gate' as never},
  };
  assert.equal((await verify(y)).result,'BLOCKED');
});

test('tampering with ANY signed gate property invalidates signature',async()=>{
  for(const delta of [
    {outcome:'denied' as never},
    {projectId:'bd565370-7321-4dba-908a-412186b1b986' as never},
    {environmentId:'1ae8fb62-814e-4a37-bdde-383b9f8a8740' as never},
    {sourceCommitSha:'a'.repeat(40)},
    {proofSha256:'0'.repeat(64)},
    {signerId:'other-signer'},
    {validUntilMs:NOW+120_000},
    {proofUri:'https://example.com/malicious'},
  ]){
    const f=changed(await fixture(),
      'pg-tls-verify-full-proven',delta);
    assert.equal((await verify(f)).result,'BLOCKED',
      'tampering must invalidate '+Object.keys(delta).join(','));
  }
});

test('signature bytes, revoked keyset, wrong role and duplicated public keys are rejected',async()=>{
  const f=await fixture();
  f.attestations[1]={...f.attestations[1],signatureHex:'0'.repeat(128)};
  assert.equal((await verify(f)).result,'BLOCKED');
  const g=await fixture();
  g.policy={...g.policy,approvedSignerKeysetSha256:'f'.repeat(64)};
  assert.equal((await verify(g)).result,'BLOCKED');
  const h=await fixture();
  h.policy={...h.policy,signers:h.policy.signers.map((key,i)=>i===1?
    {...key,publicKeyHex:h.policy.signers[0].publicKeyHex}:key)};
  h.policy={...h.policy,approvedSignerKeysetSha256:DIGEST(
    backend16CanonicalOperatorKeyset(h.policy.signers))};
  assert.equal((await verify(h)).result,'BLOCKED');
  const j=changed(await fixture(),'sql0008-installed-catalog-readback',
    {role:'security-reviewer'});
  assert.equal((await verify(j)).result,'BLOCKED');
});

test('signed stale/future evidence and improper lease fail closed',async()=>{
  for(const mutation of [
    {observedAtMs:NOW-3_600_001},
    {observedAtMs:NOW+60_000},
    {validUntilMs:NOW},
    {validUntilMs:NOW+3_600_001},
  ]){
    const f=await fixture();
    const t=f.attestations.findIndex(
      r=>r.evidence.gate==='pg-tls-verify-full-proven');
    const e={...f.attestations[t].evidence,...mutation};
    f.attestations[t]=await reSign(e,f.keypairs);
    assert.equal((await verify(f)).result,'BLOCKED');
  }
});

test('proof expiring during async cryptographic review cannot become READY',async()=>{
  const f=await fixture();
  const originalNow=Date.now;
  let afterInitialCheck=false;
  let clockReads=0;
  try{
    Date.now=()=>{
      clockReads++;
      // The invocation begins with fresh, authentic signed evidence.
      // Before WebCrypto returns, the real-world clock advances past expiry.
      return afterInitialCheck?NOW+11*60_000:NOW;
    };
    const verification=verify(f);
    afterInitialCheck=true;
    assert.equal((await verification).result,'BLOCKED');
    assert.ok(clockReads>=2,'system clock checked at invocation and completion');
  }finally{
    Date.now=originalNow;
  }
});

test('security and operations approvals must sign AFTER technical evidence',async()=>{
  for(const gate of ['security-release-review',
    'operations-release-review'] as const){
    for(const observation of [NOW-2500,NOW-2000]){
      const f=await fixture();
      const i=f.attestations.findIndex(t=>t.evidence.gate===gate);
      f.attestations[i]=await reSign({
        ...f.attestations[i].evidence,observedAtMs:observation,
      },f.keypairs);
      assert.equal((await verify(f)).result,'BLOCKED',
        'a final approval must be STRICTLY AFTER every technical record');
    }
  }
  const f=await fixture();
  const i=f.attestations.findIndex(t=>
    t.evidence.gate==='security-release-review');
  f.attestations[i]=await reSign({
    ...f.attestations[i].evidence,proofSha256:'a'.repeat(64),
  },f.keypairs);
  assert.equal((await verify(f)).result,'BLOCKED',
    'signature must bind the exact combined technical proof digest');
});


test('final approvals bind exact signed observations even with identical proof hashes',async()=>{
  // A technically valid observation may be re-signed with a fresher
  // timestamp or a different archive URI without changing proofSha256.
  // Both final approvals must be renewed for the new signed record.
  for(const change of [
    {observedAtMs:NOW-1800},
    {proofUri:'https://github.com/'+REPO+'/issues/650'},
    {validUntilMs:NOW+45_000},
  ]){
    const f=await fixture();
    const index=f.attestations.findIndex(t=>
      t.evidence.gate==='pg-tls-verify-full-proven');
    assert.ok(index>=0);
    const old=f.attestations[index];
    const replacement=await reSign({...old.evidence,...change},f.keypairs);
    assert.equal(replacement.evidence.proofSha256,old.evidence.proofSha256);
    assert.notEqual(replacement.signatureHex,old.signatureHex);
    f.attestations[index]=replacement;
    assert.equal((await verify(f)).result,'BLOCKED',
      'unreviewed signed record substitution: '+Object.keys(change).join(','));
  }
});

test('old proof-digest-only v1 review signatures never validate under v2 binding',async()=>{
  const f=await fixture();
  const technical=BACKEND16_REQUIRED_STAGING_GATES.filter(
    gate=>!APPROVALS.has(gate));
  const v1Digest=DIGEST(JSON.stringify({
    schema:'backend16-technical-release-evidence-v1',
    gates:technical.map(gate=>[gate,
      f.attestations.find(x=>x.evidence.gate===gate)?.evidence.proofSha256]),
  }));
  const v2Digest=DIGEST(backend16CanonicalSignedTechnicalBundle(
    f.attestations.filter(x=>technical.includes(x.evidence.gate))));
  assert.notEqual(v1Digest,v2Digest);
  for(let i=0;i<f.attestations.length;i++){
    if(!APPROVALS.has(f.attestations[i].evidence.gate))continue;
    const e={...f.attestations[i].evidence,proofSha256:v1Digest};
    f.attestations[i]=await reSign(e,f.keypairs);
  }
  assert.equal((await verify(f)).result,'BLOCKED');
});

test('signed technical canonical aggregate preserves order, identity, timing and signature',async()=>{
  const f=await fixture();
  const technical=f.attestations.filter(x=>!APPROVALS.has(x.evidence.gate));
  const canonical=backend16CanonicalSignedTechnicalBundle(technical);
  assert.ok(canonical.startsWith(
    '{"schema":"backend16-technical-signed-release-evidence-v2"'));
  assert.ok(canonical.includes(backend16CanonicalReleaseEvidence(
    technical[0].evidence).replaceAll('"','\\"')));
  assert.ok(canonical.includes(technical[0].signatureHex));
  const reversed=backend16CanonicalSignedTechnicalBundle([...technical].reverse());
  assert.notEqual(canonical,reversed);
});

test('reviewed signer keys must be sorted by role and distinct by ID and key',async()=>{
  const f=await fixture();
  const signers=[...f.policy.signers].reverse();
  f.policy={...f.policy,signers,
    approvedSignerKeysetSha256:DIGEST(
      backend16CanonicalOperatorKeyset(signers))};
  assert.equal((await verify(f)).result,'BLOCKED');
  const g=await fixture();
  g.policy={...g.policy,signers:g.policy.signers.map((x,i)=>i===1?
    {...x,signerId:g.policy.signers[0].signerId}:x)};
  g.policy={...g.policy,approvedSignerKeysetSha256:DIGEST(
    backend16CanonicalOperatorKeyset(g.policy.signers))};
  assert.equal((await verify(g)).result,'BLOCKED');
});

test('rejects accessor-bearing, extra-field and prototype attacker objects',async()=>{
  const x=await fixture();
  const i=0;
  x.attestations[i]={...x.attestations[i],
    evidence:{...x.attestations[i].evidence,rawBearer:'bearer-secret'} as never};
  assert.equal((await verify(x)).result,'BLOCKED');
  const f=await fixture();
  f.attestations[0]={
    ...f.attestations[0],
    evidence:Object.defineProperty({...f.attestations[0].evidence},
      'proofSha256',{get(){return '0'.repeat(64)},enumerable:true}),
  };
  assert.equal((await verify(f)).result,'BLOCKED');
  const h=await fixture();
  h.attestations[0]={
    evidence:Object.assign(Object.create({get privileged(){return true}}),
      h.attestations[0].evidence),
    signatureHex:h.attestations[0].signatureHex,
  };
  assert.equal((await verify(h)).result,'BLOCKED');
});

test('operator key and proof mutations after invocation cannot race WebCrypto awaits',async()=>{
  const f=await fixture();
  const result=verify(f);
  // The result must describe the entire exact signed input as it existed
  // synchronously at the time verification was invoked, not a later
  // attacker mutation scheduled before subtle.importKey/verify resolves.
  (f.policy.signers[1] as {publicKeyHex:string}).publicKeyHex='0'.repeat(64);
  (f.attestations[0].evidence as {proofSha256:string}).proofSha256='0'.repeat(64);
  assert.equal((await result).result,'READY_FOR_INDEPENDENT_REVIEW');

  // The exported verifier does not accept a caller-controlled nowMs hook;
  // there is no untrusted callback between snapshot and signature verification.

  const tampered=await fixture();
  (tampered.attestations[0].evidence as {proofSha256:string}).proofSha256=
    '0'.repeat(64);
  assert.equal((await verify(tampered)).result,'BLOCKED',
    'a forged field PRESENT before invocation is never signed');
});

test('invalid key crypto, caller time injection and absent operator policy block',async()=>{
  const x=await fixture();
  x.policy={...x.policy,signers:x.policy.signers.map((k,i)=>i===0?
    {...k,publicKeyHex:'0'.repeat(64)}:k)};
  x.policy={...x.policy,approvedSignerKeysetSha256:DIGEST(
    backend16CanonicalOperatorKeyset(x.policy.signers))};
  assert.equal((await verify(x)).result,'BLOCKED');
  const y=await fixture();
  assert.equal((await verifyBackend16ReleaseEvidence({
    policy:y.policy,attestations:y.attestations,
    nowMs:()=>NOW,
  } as never)).result,'BLOCKED',
  'unexpected caller-supplied time is not an authorized release clock');
  const payload={
    policy:y.policy,attestations:y.attestations,
  };
  Object.defineProperty(payload,'nowMs',{
    enumerable:true,get(){throw new Error('attacker time getter');},
  });
  assert.equal((await verifyBackend16ReleaseEvidence(payload as never)).result,
    'BLOCKED','accessor cannot turn a caller clock into release time');
  assert.equal((await verifyBackend16ReleaseEvidence({
    policy:null as never,attestations:[],
  })).result,'BLOCKED');
});

test('verifier is offline, read-only and contains no release deploy or bypass path',()=>{
  const source=readFileSync(new URL(
    '../src/features/saasBlueprint/controlApi/server/backend16ReleaseEvidenceGate.ts',
    import.meta.url),'utf8');
  for(const marker of [
    'READY_FOR_INDEPENDENT_REVIEW','productionAuthorized:false',
    'crypto.subtle.verify(','approvedSignerKeysetSha256',
    'BACKEND16_REQUIRED_STAGING_GATES',
    'sql0008-installed-catalog-readback','restore-drill-proven',
    'pg-tls-verify-full-proven','durable-offhost-audit-replay-proven',
    'security-release-review','operations-release-review',
    'approval.proofSha256!==technicalDigest',
    'backend16CanonicalSignedTechnicalBundle',
    "const now=Date.now();",'const finishedAt=Date.now();',
    'plainExact(input,INPUT_KEYS)',
    'approval.observedAtMs<=maxTechnicalTime',
  ])assert.ok(source.includes(marker),marker);
  assert.doesNotMatch(source,
    /\b(?:fetch\(|Bun\.serve|createServer|\.listen\(|\.query\(|\.unsafe\(|ALTER ROLE|CREATE ROLE|DROP ROLE|UPDATE\s+|INSERT\s+|DELETE\s+|railway up)\b/i);
  assert.doesNotMatch(source,/DATABASE_URL|DATABASE_PUBLIC_URL|STAGING_POSTGRES_PRIVATE_URL|console\.log|console\.info|process\.env/);
});

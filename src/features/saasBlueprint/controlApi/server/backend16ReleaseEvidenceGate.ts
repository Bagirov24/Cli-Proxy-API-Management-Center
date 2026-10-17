/**
 * Backend16.13 — offline, no-side-effect staging release evidence verifier.
 *
 * The verifier cannot deploy, authenticate PostgreSQL, issue tokens, send
 * traffic, retrieve secrets, or install SQL0008. Even a complete signed set
 * says only READY_FOR_INDEPENDENT_REVIEW, never "production approved".
 *
 * The approval keyset fingerprint and expected source commit MUST be provided
 * from an independently reviewed operator release policy, not from the same
 * request, evidence archive, database, HTTP header or secrets response.
 */
const REPO='Bagirov24/Cli-Proxy-API-Management-Center';
const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const STAGING='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const EVIDENCE_SCHEMA='backend16-release-evidence-v1';
const POLICY_SCHEMA='backend16-release-reviewer-keys-v1';
const SHA=/^[a-f0-9]{64}$/;
const SHA_COMMIT=/^[a-f0-9]{40}$/;
const ED25519_SIGNATURE=/^[a-f0-9]{128}$/;
const OPERATOR_ID=/^[a-z][a-z0-9_-]{3,63}$/;
const EVIDENCE_KEYS='environmentId,gate,observedAtMs,outcome,projectId,proofSha256,proofUri,repo,role,schema,signerId,sourceCommitSha,validUntilMs';
const SIGNED_KEYS='evidence,signatureHex';
const SIGNER_KEYS='publicKeyHex,role,signerId';

export const BACKEND16_REQUIRED_STAGING_GATES=Object.freeze([
  'sql0008-installed-catalog-readback',
  'restore-drill-proven',
  'pg-tls-verify-full-proven',
  'vault-versioned-login-iam-proven',
  'live-oidc-session-revocation-proven',
  'durable-offhost-audit-replay-proven',
  'private-two-tenant-e2e-proven',
  'staging-canary-rollback-proven',
  'security-release-review',
  'operations-release-review',
] as const);
export type Backend16StagingGate=typeof BACKEND16_REQUIRED_STAGING_GATES[number];
export type Backend16EvidenceSignerRole=
  'db-operator'|'security-reviewer'|'runtime-reviewer'|'operations-reviewer';

const ROLE:Readonly<Record<Backend16StagingGate,Backend16EvidenceSignerRole>>=
  Object.freeze({
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
  });
const APPROVAL_GATES=Object.freeze([
  'security-release-review','operations-release-review',
] as const);
const OPERATOR_ROLES=Object.freeze([
  'db-operator','security-reviewer','runtime-reviewer','operations-reviewer',
] as const);
const HOUR=3_600_000;
const MAX_AGE_MS:Readonly<Record<Backend16StagingGate,number>>=
  Object.freeze({
    'sql0008-installed-catalog-readback':HOUR,
    'restore-drill-proven':24*HOUR,
    'pg-tls-verify-full-proven':HOUR,
    'vault-versioned-login-iam-proven':HOUR,
    'live-oidc-session-revocation-proven':HOUR,
    'durable-offhost-audit-replay-proven':HOUR,
    'private-two-tenant-e2e-proven':HOUR,
    'staging-canary-rollback-proven':30*60_000,
    'security-release-review':30*60_000,
    'operations-release-review':30*60_000,
  });

export type Backend16OperatorEvidenceKey=Readonly<{
  role:Backend16EvidenceSignerRole;
  signerId:string;
  /** Exactly 32 public Ed25519 bytes encoded as lowercase hex. */
  publicKeyHex:string;
}>;

export type Backend16ReleaseEvidence=Readonly<{
  schema:typeof EVIDENCE_SCHEMA;
  gate:Backend16StagingGate;
  role:Backend16EvidenceSignerRole;
  signerId:string;
  repo:typeof REPO;
  projectId:typeof PROJECT;
  environmentId:typeof STAGING;
  sourceCommitSha:string;
  observedAtMs:number;
  validUntilMs:number;
  outcome:'pass';
  proofUri:string;
  /** Digest of independently archived redacted proof, not a shared secret. */
  proofSha256:string;
}>;

export type Backend16SignedReleaseEvidence=Readonly<{
  evidence:Backend16ReleaseEvidence;
  /** Ed25519 signature over backend16CanonicalReleaseEvidence(evidence). */
  signatureHex:string;
}>;

export type Backend16ReleaseEvidencePolicy=Readonly<{
  /** Code/rollout's exact audited immutable git source, never moving main. */
  expectedSourceCommitSha:string;
  /** SHA256 of canonical reviewed role/signing-key set, pinned out-of-band. */
  approvedSignerKeysetSha256:string;
  readonly signers:readonly Backend16OperatorEvidenceKey[];
}>;

export type Backend16ReleaseEvidenceVerdict=Readonly<{
  result:'BLOCKED'|'READY_FOR_INDEPENDENT_REVIEW';
  /** Names only. No actual secret, key, URL or operator content is returned. */
  missing:readonly Backend16StagingGate[];
  /** A green gate is never authorization to deploy SaaS to production. */
  productionAuthorized:false;
}>;

function plainExact(obj:unknown,keys:string):boolean{
  if(!obj||typeof obj!=='object'||Array.isArray(obj))return false;
  if(Object.getPrototypeOf(obj)!==Object.prototype &&
     Object.getPrototypeOf(obj)!==null)return false;
  const props=Object.getOwnPropertyDescriptors(obj);
  return Object.keys(props).sort().join(',')===keys &&
    Object.values(props).every(d=>'value' in d);
}
function blocked():Backend16ReleaseEvidenceVerdict{
  return Object.freeze({
    result:'BLOCKED',
    missing:BACKEND16_REQUIRED_STAGING_GATES,
    productionAuthorized:false,
  });
}
function verdict(missing:readonly Backend16StagingGate[]):
  Backend16ReleaseEvidenceVerdict{
  return Object.freeze({
    result:missing.length===0?'READY_FOR_INDEPENDENT_REVIEW':'BLOCKED',
    missing:Object.freeze([...missing]),productionAuthorized:false,
  });
}
function bytesFromHex(hex:string):Uint8Array<ArrayBuffer>{
  // Always allocate the exact ArrayBuffer, never a SharedArrayBuffer,
  // to satisfy strict DOM BufferSource types and WebCrypto internals.
  const b=new Uint8Array(new ArrayBuffer(hex.length/2));
  for(let i=0;i<b.length;i++)b[i]=Number.parseInt(hex.slice(i*2,i*2+2),16);
  return b;
}
async function sha256(data:string):Promise<string>{
  const digest=await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(data));
  return Array.from(new Uint8Array(digest),b=>
    b.toString(16).padStart(2,'0')).join('');
}

/**
 * Immutable signed payload with explicit canonical property order.
 * Do not change order or field names without bumping the schema and
 * obtaining an entirely new independent reviewer keyset and signatures.
 */
export function backend16CanonicalReleaseEvidence(
  e:Backend16ReleaseEvidence,
):string{
  return JSON.stringify({
    schema:e.schema,gate:e.gate,role:e.role,signerId:e.signerId,
    repo:e.repo,projectId:e.projectId,environmentId:e.environmentId,
    sourceCommitSha:e.sourceCommitSha,observedAtMs:e.observedAtMs,
    validUntilMs:e.validUntilMs,outcome:e.outcome,proofUri:e.proofUri,
    proofSha256:e.proofSha256,
  });
}
export function backend16CanonicalOperatorKeyset(
  keys:readonly Backend16OperatorEvidenceKey[],
):string{
  return JSON.stringify({
    schema:POLICY_SCHEMA,
    signers:keys.map(k=>[k.role,k.signerId,k.publicKeyHex]),
  });
}

function validProofUri(uri:unknown):uri is string{
  if(typeof uri!=='string'||uri.length>320)return false;
  // Reviewed provenance URLs only; never user-controlled URLs or fetch().
  return /^https:\/\/github\.com\/Bagirov24\/Cli-Proxy-API-Management-Center\/(?:actions\/runs\/[1-9]\d*|pull\/[1-9]\d*|issues\/[1-9]\d*)$/.test(uri)||
    new RegExp('^https://railway\\.com/project/'+PROJECT+
      '/service/[a-f0-9-]{36}\\?environmentId='+STAGING+'$').test(uri);
}
function validEvidence(
  e:Backend16ReleaseEvidence, expectedCommit:string, now:number,
):boolean{
  const gate=e.gate;
  if(!plainExact(e,EVIDENCE_KEYS)||
     !BACKEND16_REQUIRED_STAGING_GATES.includes(gate)||
     e.role!==ROLE[gate]||
     typeof e.signerId!=='string'||!OPERATOR_ID.test(e.signerId)||
     e.schema!==EVIDENCE_SCHEMA||e.repo!==REPO||
     e.projectId!==PROJECT||e.environmentId!==STAGING||
     e.sourceCommitSha!==expectedCommit||e.outcome!=='pass'||
     typeof e.proofSha256!=='string'||!SHA.test(e.proofSha256)||
     !validProofUri(e.proofUri)||
     !Number.isSafeInteger(e.observedAtMs)||
     !Number.isSafeInteger(e.validUntilMs))return false;
  const age=MAX_AGE_MS[gate];
  return e.observedAtMs>0&&e.observedAtMs<=now&&
    e.observedAtMs>=now-age&&
    e.validUntilMs>now&&e.validUntilMs<=e.observedAtMs+age;
}

async function trustedKeyset(policy:Backend16ReleaseEvidencePolicy):
  Promise<Map<Backend16EvidenceSignerRole,{
    signerId:string;publicKey:CryptoKey;
  }> | null>{
  if(!policy||typeof policy.expectedSourceCommitSha!=='string'||
     !SHA_COMMIT.test(policy.expectedSourceCommitSha)||
     typeof policy.approvedSignerKeysetSha256!=='string'||
     !SHA.test(policy.approvedSignerKeysetSha256)||
     !Array.isArray(policy.signers)||
     policy.signers.length!==OPERATOR_ROLES.length)return null;

  const signers=policy.signers;
  const ids=new Set<string>(),keys=new Set<string>();
  const trusted=new Map<Backend16EvidenceSignerRole,{
    signerId:string;publicKey:CryptoKey;
  }>();
  for(let i=0;i<signers.length;i++){
    const signer=signers[i];
    if(!plainExact(signer,SIGNER_KEYS)||
       signer.role!==OPERATOR_ROLES[i]||
       typeof signer.signerId!=='string'||
       !OPERATOR_ID.test(signer.signerId)||
       ids.has(signer.signerId)||
       typeof signer.publicKeyHex!=='string'||
       !SHA.test(signer.publicKeyHex)||
       keys.has(signer.publicKeyHex))return null;
    ids.add(signer.signerId);
    keys.add(signer.publicKeyHex);
  }
  if(await sha256(backend16CanonicalOperatorKeyset(signers))!==
     policy.approvedSignerKeysetSha256)return null;

  for(const signer of signers){
    const key=await crypto.subtle.importKey(
      'raw',bytesFromHex(signer.publicKeyHex),'Ed25519',false,['verify']);
    trusted.set(signer.role,{signerId:signer.signerId,publicKey:key});
  }
  return trusted;
}

/**
 * Verify all required, fresh, role-bound signed release attestations.
 * A forged/missing/duplicate/expired/unknown set is BLOCKED, not partial
 * approval. Operator-approved source SHA/keyset must come from independent
 * code/release review. A complete set is only ready for final human review,
 * never permission to mutate production or run SQL0008.
 */
export async function verifyBackend16ReleaseEvidence(input:Readonly<{
  policy:Backend16ReleaseEvidencePolicy;
  attestations:readonly Backend16SignedReleaseEvidence[];
  /** Injectable only for deterministic unit tests. */
  nowMs?:()=>number;
}>):Promise<Backend16ReleaseEvidenceVerdict>{
  try{
    if(!input||!Array.isArray(input.attestations)||
       input.attestations.length!==BACKEND16_REQUIRED_STAGING_GATES.length||
       (input.nowMs!==undefined&&typeof input.nowMs!=='function'))
      return blocked();
    const now=(input.nowMs??Date.now)();
    if(!Number.isSafeInteger(now)||now<=0)return blocked();
    const keyset=await trustedKeyset(input.policy);
    if(!keyset)return blocked();
    const accepted=new Map<Backend16StagingGate,Backend16ReleaseEvidence>();
    for(const item of input.attestations){
      if(!plainExact(item,SIGNED_KEYS)||
         !item.evidence||
         typeof item.signatureHex!=='string'||
         !ED25519_SIGNATURE.test(item.signatureHex)||
         !validEvidence(item.evidence,input.policy.expectedSourceCommitSha,now)||
         accepted.has(item.evidence.gate))return blocked();
      const signer=keyset.get(item.evidence.role);
      if(!signer||signer.signerId!==item.evidence.signerId)return blocked();
      const signature=bytesFromHex(item.signatureHex);
      const valid=await crypto.subtle.verify(
        'Ed25519',signer.publicKey,signature,
        new TextEncoder().encode(
          backend16CanonicalReleaseEvidence(item.evidence)));
      if(!valid)return blocked();
      accepted.set(item.evidence.gate,item.evidence);
    }
    const technical=BACKEND16_REQUIRED_STAGING_GATES.filter(
      gate=>!APPROVAL_GATES.some(review=>review===gate));
    const maxTechnicalTime=Math.max(...technical.map(
      gate=>accepted.get(gate)?.observedAtMs??Infinity));
    const technicalDigest=await sha256(JSON.stringify({
      schema:'backend16-technical-release-evidence-v1',
      gates:technical.map(gate=>[gate,accepted.get(gate)?.proofSha256]),
    }));
    for(const gate of APPROVAL_GATES){
      const approval=accepted.get(gate);
      if(!approval||approval.observedAtMs<maxTechnicalTime||
         approval.proofSha256!==technicalDigest)return blocked();
    }
    return verdict(BACKEND16_REQUIRED_STAGING_GATES.filter(
      gate=>!accepted.has(gate)));
  }catch{
    // Suppress crypto/internal/attestation errors; no secret-bearing output.
    return blocked();
  }
}

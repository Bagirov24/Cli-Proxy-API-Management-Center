/**
 * M1o: opt-in, disposable per-process CA/SPKI trust epoch for synthetic IdP.
 * This is NOT an operator signature, durable pin registry, real PKI rotation,
 * Railway configuration, production authority, or a live OAuth client.
 * There is exactly ONE trusted CA/leaf-SPKI pair at each revision.
 */
import { createHash, X509Certificate } from 'node:crypto';
import { m1nCiEnabled } from './m1n-ephemeral-tls-fixture.mjs';
import { createM1nPinnedHttpsTransport } from './m1n-synthetic-https-trust.mjs';

const HEX64=/^[0-9a-f]{64}$/;
const ciEnabled=()=>m1nCiEnabled() &&
  process.env.SAAS_EPHEMERAL_M1O_TRUST_CI==='true';
const fail=message=>new Error('M1o explicit TLS trust rotation denied: '+message);
const exact=(value,keys)=>value!==null&&typeof value==='object'&&
  !Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;

function parsePolicy(input){
  if(!exact(input,'caPem,revision,spkiSha256')||
     !Number.isSafeInteger(input.revision)||input.revision<1||
     typeof input.caPem!=='string'||!HEX64.test(input.spkiSha256))
    throw fail('invalid exact CA/SPKI/revision policy');
  let ca;
  try{ca=new X509Certificate(input.caPem);}catch{
    throw fail('malformed CA certificate');
  }
  if(!ca.ca)throw fail('trust anchor is not a CA');
  const caFingerprint=createHash('sha256').update(ca.raw).digest('hex');
  return Object.freeze({
    ...input,caFingerprint,pair:caFingerprint+':'+input.spkiSha256,
  });
}

export function createM1oExplicitTrustRotation({baseUrl,callbackUri,initial}){
  if(!ciEnabled())throw fail('CI-only switch absent');
  let current=parsePolicy(initial);
  if(current.revision!==1)throw fail('initial revision must be 1');
  const retired=new Set([current.pair]);
  let inFlight=0;
  function bind(policy){
    // Construct M1n's CA/SAN/SPKI-pinned transport before publishing policy.
    // Its handshake finishes BEFORE any HTTP/OAuth bytes are sent.
    const pinned=createM1nPinnedHttpsTransport({
      baseUrl,callbackUri,caPem:policy.caPem,
      spkiSha256:policy.spkiSha256,
    });
    return Object.freeze({
      origin:pinned.origin,
      revision:policy.revision,
      async fetch(url,options){
        if(!ciEnabled()||current.revision!==policy.revision)
          throw fail('stale or disabled trust epoch BEFORE network');
        inFlight++;
        try{
          const response=await pinned.fetch(url,options);
          if(current.revision!==policy.revision)
            throw fail('trust changed during HTTPS operation');
          return response;
        }finally{inFlight--;}
      },
    });
  }
  let active=bind(current);
  return Object.freeze({
    currentTransport:()=>active,
    revision:()=>current.revision,
    fingerprints:()=>Object.freeze({
      revision:current.revision,caSha256:current.caFingerprint,
      leafSpkiSha256:current.spkiSha256,
    }),
    commitExplicitRotation(input){
      if(!ciEnabled())throw fail('CI-only switch absent');
      if(inFlight!==0)throw fail('HTTPS request in flight');
      if(!exact(input,'caPem,expectedRevision,revision,spkiSha256')||
         input.expectedRevision!==current.revision||
         input.revision!==current.revision+1||
         !Number.isSafeInteger(input.revision))
        throw fail('stale writer or non-sequential revision');
      const next=parsePolicy({
        caPem:input.caPem,spkiSha256:input.spkiSha256,
        revision:input.revision,
      });
      if(retired.has(next.pair))
        throw fail('same or retired CA/SPKI pair cannot be reactivated');
      // Construct first, then perform the synchronous swap. Any invalid
      // input leaves the old pinned policy unchanged; never union pinsets.
      const nextTransport=bind(next);
      current=next;
      active=nextTransport;
      retired.add(next.pair);
      return nextTransport;
    },
  });
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  BACKEND16_STAGING_PG_TLS_HOST,
  backend16IsApprovedStagingPgTlsTrust,
  createBackend16StagingPgTlsTrust,
} from '../src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts';
import {
  createBackend16StagingBunPhysicalPgPool,
} from '../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts';

const ca=readFileSync(
  new URL('./fixtures/backend16-synthetic-root-ca.pem',import.meta.url),
  'utf8');
const pin='8ee35a165c52eedf6d6f148618e151b8eb7f93af1318125dcc1aab33c72638bc';
const syntheticClock=Date.UTC(2027,0,1);
const input=()=>({caPem:ca,approvedCaDerSha256:pin});
const refuse=(fn:()=>unknown)=>assert.throws(fn,
  /Backend16 staging PostgreSQL TLS trust refused/);

test('only independently pinned self-signed strong root is accepted',()=>{
  const tls=createBackend16StagingPgTlsTrust(input(),syntheticClock);
  assert.ok(Object.isFrozen(tls));
  assert.equal(tls.serverName,'postgres.railway.internal');
  assert.equal(tls.serverName,BACKEND16_STAGING_PG_TLS_HOST);
  assert.equal(tls.rejectUnauthorized,true);
  assert.equal(tls.ca,ca);
  assert.equal(typeof tls.checkServerIdentity,'function');
  assert.deepEqual(Object.keys(tls).sort(),[
    'ca','checkServerIdentity','rejectUnauthorized','serverName',
  ]);
  assert.equal(backend16IsApprovedStagingPgTlsTrust(tls),true);
  assert.equal(backend16IsApprovedStagingPgTlsTrust({...tls}),false,
    'unbranded clone can never bypass certificate approval');
  assert.equal(backend16IsApprovedStagingPgTlsTrust(
    {ca:ca,serverName:tls.serverName,rejectUnauthorized:true}),false);
  assert.equal(backend16IsApprovedStagingPgTlsTrust(null),false);
});

test('mismatched, noncanonical, multiple and unparseable CAs refuse',()=>{
  refuse(()=>createBackend16StagingPgTlsTrust({
    caPem:ca,approvedCaDerSha256:'0'.repeat(64),
  },syntheticClock));
  refuse(()=>createBackend16StagingPgTlsTrust({
    caPem:ca,approvedCaDerSha256:pin.toUpperCase(),
  },syntheticClock));
  refuse(()=>createBackend16StagingPgTlsTrust({
    caPem:ca+ca,approvedCaDerSha256:pin,
  },syntheticClock));
  refuse(()=>createBackend16StagingPgTlsTrust({
    caPem:'not a certificate',approvedCaDerSha256:pin,
  },syntheticClock));
  refuse(()=>createBackend16StagingPgTlsTrust({
    caPem:ca.replace('MIIETD','MIIETX'),approvedCaDerSha256:pin,
  },syntheticClock));
  refuse(()=>createBackend16StagingPgTlsTrust({
    caPem:ca+'-----BEGIN PRIVATE KEY-----',approvedCaDerSha256:pin,
  },syntheticClock));
});

test('accessor CA substitution cannot receive an approved trust brand',()=>{
  let reads=0;
  const mutable={
    get caPem(){return ++reads<=5?ca:'UNVALIDATED_CA_AFTER_PIN_CHECK';},
    approvedCaDerSha256:pin,
  };
  refuse(()=>createBackend16StagingPgTlsTrust(mutable,syntheticClock));
  assert.equal(reads,0,'reject accessors without invoking provider code');
  refuse(()=>createBackend16StagingPgTlsTrust(
    Object.assign(Object.create({}),input()),syntheticClock));
  refuse(()=>createBackend16StagingPgTlsTrust(
    {...input(),extra:true} as never,syntheticClock));
});

test('CA not yet valid, soon expiring or bogus clock are fail-closed',()=>{
  refuse(()=>createBackend16StagingPgTlsTrust(input(),Date.UTC(2026,9,16)));
  refuse(()=>createBackend16StagingPgTlsTrust(input(),Date.UTC(2036,9,13)));
  refuse(()=>createBackend16StagingPgTlsTrust(input(),Number.NaN));
  refuse(()=>createBackend16StagingPgTlsTrust(input(),0));
});

test('staging physical pool denies unapproved trust and TLS downgrade',()=>{
  const vault={async readPrincipal(login:string){
    return {username:login,password:'x'.repeat(64)};
  }};
  assert.throws(
    ()=>createBackend16StagingBunPhysicalPgPool(vault,null as never),
    /release gates not met/,
  );
  const source=readFileSync(new URL(
    '../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts',
    import.meta.url),'utf8');
  const trustSource=readFileSync(new URL(
    '../src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts',
    import.meta.url),'utf8');
  for(const fragment of [
    '!backend16IsApprovedStagingPgTlsTrust(tlsTrust)',
    'Object.freeze({...STAGING_PROFILE,tls:tlsTrust})',
    "env.NODE_TLS_REJECT_UNAUTHORIZED==='0'",
    "hostname:HOST,database:DATABASE",
  ])assert.ok(source.includes(fragment),fragment);
  assert.doesNotMatch(source,/tls:'require'|tls:'disable'|tls:'prefer'/);
  assert.ok(trustSource.includes('cert.checkIssued(cert)'));
  assert.ok(trustSource.includes('cert.verify(key)'));
  assert.ok(trustSource.includes("serverName:BACKEND16_STAGING_PG_TLS_HOST"));
  assert.ok(trustSource.includes('rejectUnauthorized:true as const'));
  assert.ok(trustSource.includes('checkServerIdentity:exactPrivatePgServerIdentity'));
  assert.ok(trustSource.includes('wildcards:false'));
  assert.ok(trustSource.includes("san.split(/,\\s*/).includes('DNS:'+BACKEND16_STAGING_PG_TLS_HOST)"));
  assert.doesNotMatch(trustSource,/Bun\.serve|fetch\(|DATABASE_PUBLIC_URL/);
});

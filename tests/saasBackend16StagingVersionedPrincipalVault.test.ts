import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {
  createBackend16StagingVersionedPrincipalVault,
  type Backend16StagingVaultEntry,
  type Backend16StagingVersionedSecretReader,
} from '../src/features/saasBlueprint/controlApi/server/backend16StagingVersionedPrincipalVault.ts';
import type {Backend16StagingPrincipalVault}
  from '../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts';

const NOW=Date.now();
const A='saas_b16_reader_a',B='saas_b16_reader_b';
const PASS='x'.repeat(64),VERSION='a'.repeat(32),OTHER_VERSION='b'.repeat(32);
const aId='b16-stg-pg-'+('a'.repeat(20));
const bId='b16-stg-pg-'+('b'.repeat(20));
const first=()=>({pgLogin:A,secretId:aId,version:VERSION});
const second=()=>({pgLogin:B,secretId:bId,version:OTHER_VERSION});
const pinned=(entries:readonly Backend16StagingVaultEntry[])=>({
  entries,
  approvedManifestSha256:createHash('sha256').update(JSON.stringify({
    schema:'backend16-staging-vault-v1',
    entries:entries.map(i=>[i.pgLogin,i.secretId,i.version]),
  })).digest('hex'),
});
const expires=(username=A,version=VERSION,expiry=Date.now()+120_000)=>
  ({username,password:PASS,version,expiresAtMs:expiry});
const signal=()=>new AbortController().signal;
const sourceText=readFileSync(new URL(
  '../src/features/saasBlueprint/controlApi/server/backend16StagingVersionedPrincipalVault.ts',
  import.meta.url),'utf8');

test('only manifest-selected exact secret ID and immutable version are requested',async()=>{
  const calls:Array<[string,string,AbortSignal]>=[];
  const source:Backend16StagingVersionedSecretReader={
    async readVersion(id,version,abort){
      calls.push([id,version,abort]);
      return id===aId?expires():expires(B,OTHER_VERSION);
    },
  };
  const manifest=pinned([first(),second()]);
  const vault:Backend16StagingPrincipalVault=
    await createBackend16StagingVersionedPrincipalVault({
      manifest,source,
    });
  const x=await vault.readPrincipal(A,signal());
  assert.deepEqual(x,{username:A,password:PASS});
  assert.equal(Object.isFrozen(x),true);
  const y=await vault.readPrincipal(B,signal());
  assert.equal(y.username,B);
  assert.deepEqual(calls.map(([id,version])=>[id,version]),
    [[aId,VERSION],[bId,OTHER_VERSION]]);
  assert.deepEqual(calls.map(([,,abort])=>abort.aborted),[false,false]);
  assert.equal(Object.keys(vault).join(','),'readPrincipal');
  await assert.rejects(vault.readPrincipal('postgres',signal()),/unavailable/);
  await assert.rejects(vault.readPrincipal('saas_b16_missing',signal()),/unavailable/);
  assert.equal(calls.length,2,'no secret enumeration or client-chosen path');
});

test('manifest must be sorted, nonduplicated, canonical and independently SHA-pinned',async()=>{
  const reader={async readVersion(){return expires();}};
  for(const manifest of [
    {...pinned([first()]),approvedManifestSha256:'0'.repeat(64)},
    pinned([second(),first()]),
    pinned([first(),first()]),
    pinned([{...first(),pgLogin:'postgres'}]),
    pinned([{...first(),pgLogin:'pg_owner'}]),
    pinned([{...first(),secretId:bId}, {...second(),secretId:bId}]),
    pinned([{...first(),secretId:'../pg-secret'}]),
    pinned([{...first(),version:'latest'}]),
    pinned([{...first(),unexpected:'admin'} as never]),
    pinned([]),
    pinned(Array.from({length:129},(_,i)=>({
      pgLogin:'usr_'+i.toString().padStart(3,'0'),
      secretId:'b16-stg-pg-'+i.toString().padStart(20,'0'),
      version:VERSION,
    }))),
  ])await assert.rejects(
    createBackend16StagingVersionedPrincipalVault({
      manifest,source:reader,
    }),/principal credential vault unavailable/);
  const good=pinned([first()]);
  await assert.rejects(createBackend16StagingVersionedPrincipalVault({
    manifest:{...good,approvedManifestSha256:good.approvedManifestSha256.toUpperCase()},
    source:reader,
  }),/unavailable/);
  await assert.rejects(createBackend16StagingVersionedPrincipalVault({
    manifest:good,source:{} as never,
  }),/unavailable/);
});

test('snapshot cannot substitute a different LOGIN, version or leaked extra property',async()=>{
  for(const wrong of [
    expires(B),expires(A,OTHER_VERSION),
    {...expires(),role:'superuser'},
    {...expires(),password:'weak'},
    {...expires(),password:'bad\npass'},
    Object.defineProperty({...expires()},'password',{
      enumerable:true,get(){return PASS;},
    }),
    {...expires(),expiresAtMs:NOW-1000},
    {...expires(),expiresAtMs:NOW+500},
    {...expires(),expiresAtMs:NOW+60_000},
    {...expires(),expiresAtMs:NOW+330_000},
    {...expires(),expiresAtMs:NaN},
    null,
    'temporary-secret',
  ]){
    const vault=await createBackend16StagingVersionedPrincipalVault({
      manifest:pinned([first()]),
      source:{async readVersion(){return wrong;}},
    });
    await assert.rejects(vault.readPrincipal(A,signal()),/unavailable/);
  }
});

test('never cache an approved password: next lookup observes revocation',async()=>{
  let count=0;
  const vault=await createBackend16StagingVersionedPrincipalVault({
    manifest:pinned([first()]),
    source:{async readVersion(){
      count++;
      return count===1?expires():null;
    }},
  });
  assert.equal((await vault.readPrincipal(A,signal())).username,A);
  await assert.rejects(vault.readPrincipal(A,signal()),/unavailable/);
  assert.equal(count,2);
});

test('abort races provider that ignores AbortSignal, including late data',async()=>{
  let resolveProvider:((value:unknown)=>void)|undefined;
  const vault=await createBackend16StagingVersionedPrincipalVault({
    manifest:pinned([first()]),
    source:{readVersion(){
      return new Promise<unknown>(resolve=>{resolveProvider=resolve;});
    }},
  });
  const controller=new AbortController();
  const request=vault.readPrincipal(A,controller.signal);
  await Promise.resolve();
  await Promise.resolve();
  controller.abort();
  await assert.rejects(request,/principal credential vault unavailable/);
  resolveProvider?.(expires());
  await Promise.resolve();
  await assert.rejects(vault.readPrincipal(A,controller.signal),/unavailable/);
});


test('operator digest and provider method are snapshotted before asynchronous SHA256',async()=>{
  const good=pinned([first()]);
  let approvedCalls=0,substitutedCalls=0;
  const approved:Backend16StagingVersionedSecretReader={
    async readVersion(){approvedCalls++;return expires();},
  };
  const substituted:Backend16StagingVersionedSecretReader={
    async readVersion(){substitutedCalls++;return {
      ...expires(),password:'z'.repeat(64),
    };},
  };
  const options={manifest:{...good},source:approved};
  const constructing=createBackend16StagingVersionedPrincipalVault(options);
  // No untrusted mutation after the SHA256 invocation may redirect reads.
  options.source=substituted;
  options.manifest.approvedManifestSha256='0'.repeat(64);
  const vault=await constructing;
  assert.deepEqual(await vault.readPrincipal(A,signal()),
    {username:A,password:PASS});
  assert.equal(approvedCalls,1);
  assert.equal(substitutedCalls,0);

  // Conversely, an originally WRONG approval cannot become valid by
  // substituting an approved digest while WebCrypto is awaiting.
  const unapproved={
    manifest:{...good,approvedManifestSha256:'0'.repeat(64)},
    source:approved,
  };
  const pending=createBackend16StagingVersionedPrincipalVault(unapproved);
  unapproved.manifest.approvedManifestSha256=good.approvedManifestSha256;
  await assert.rejects(pending,/principal credential vault unavailable/);
  assert.equal(approvedCalls,1,'failed manifest never calls external secret provider');
});

test('caller-supplied release clock and accessor/prototype manifests fail closed',async()=>{
  const manifest=pinned([first()]);
  const source={async readVersion(){return expires();}};
  await assert.rejects(createBackend16StagingVersionedPrincipalVault({
    manifest,source,nowMs:()=>NOW,
  } as never),/principal credential vault unavailable/);

  let getterCalled=false;
  const accessor=Object.defineProperty({
    entries:[first()],
  },'approvedManifestSha256',{
    enumerable:true,get(){getterCalled=true;return manifest.approvedManifestSha256;},
  });
  await assert.rejects(createBackend16StagingVersionedPrincipalVault({
    manifest:accessor as never,source,
  }),/principal credential vault unavailable/);
  assert.equal(getterCalled,false,'operator approval getter must not execute');

  const inheritedManifest=Object.assign(
    Object.create({unexpectedInheritedPolicy:true}),manifest);
  await assert.rejects(createBackend16StagingVersionedPrincipalVault({
    manifest:inheritedManifest,source,
  }),/principal credential vault unavailable/);

  const inheritedRow=Object.assign(Object.create({unreviewed:true}),expires());
  const vault=await createBackend16StagingVersionedPrincipalVault({
    manifest,source:{async readVersion(){return inheritedRow;}},
  });
  await assert.rejects(vault.readPrincipal(A,signal()),/unavailable/);
});

test('provider errors, secrets, credentials and tenancy never surface in exceptions',async()=>{
  const secretMarker='very_private_secret_marker';
  const vault=await createBackend16StagingVersionedPrincipalVault({
    manifest:pinned([first()]),
    source:{async readVersion(){throw Error('vault error '+secretMarker);}},
  });
  await assert.rejects(vault.readPrincipal(A,signal()),err=>{
    assert.ok(err instanceof Error);
    assert.equal(err.message,'Backend16 staging principal credential vault unavailable');
    assert.ok(!err.stack?.includes(secretMarker));
    return true;
  });
  assert.doesNotMatch(sourceText,/Bun\.serve|createServer|\.listen\(|DATABASE_URL|DATABASE_PUBLIC_URL|setInterval|retry\s*\(/);
  assert.doesNotMatch(sourceText,/\b(?:SET ROLE|ALTER ROLE|CREATE ROLE|DROP ROLE|pg_terminate_backend)\b/i);
  assert.ok(sourceText.includes("readVersion.call(source,entry.secretId,entry.version,signal)"));
  assert.ok(sourceText.includes('AbortSignal.timeout(FETCH_TIMEOUT_MS)'));
  assert.ok(sourceText.includes('const lookup=new Map(entries.map'));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {enforceNativeBunCi,verifyNativeBunArchive,
  readBoundedNativeBunResponse,NATIVE_BUN_CI_PIN}
  from '../scripts/saas-staging/install-backend16-native-bun-ci.mjs';

test('upstream native SQL fix is an immutable CI-only binary, never a floating canary',()=>{
  const e={GITHUB_ACTIONS:'true',CI:'true',GITHUB_ENV:'/tmp/synthetic-github-env'};
  assert.doesNotThrow(()=>enforceNativeBunCi(e,24,'linux','x64'));
  for(const key of Object.keys(e))assert.throws(()=>enforceNativeBunCi({...e,[key]:''},24,'linux','x64'));
  for(const [key,value] of Object.entries({NODE_ENV:'production',
    NODE_TLS_REJECT_UNAUTHORIZED:'0',RAILWAY_SERVICE_ID:'x'}))
    assert.throws(()=>enforceNativeBunCi({...e,[key]:value},24,'linux','x64'));
  assert.throws(()=>enforceNativeBunCi(e,22,'linux','x64'));
  assert.throws(()=>enforceNativeBunCi(e,24,'win32','x64'));
  assert.match(NATIVE_BUN_CI_PIN.url,/1\.4\.3-canary\.20261019\.1\.tgz$/);
  assert.equal(Buffer.from(NATIVE_BUN_CI_PIN.sha512,'base64').length,64);
});
test('missing, truncated or tampered native runtime cannot reach extraction',()=>{
  for(const bytes of [undefined,new Uint8Array(),new Uint8Array(1_000_001)])
    assert.throws(()=>verifyNativeBunArchive(bytes));
});

function response(chunks,length,options={}){
  const body=new ReadableStream({
    start(controller){
      for(const bytes of chunks)controller.enqueue(Uint8Array.from(bytes));
      controller.close();
    },
  });
  return new Response(body,{
    status:options.status??200,
    headers:length===undefined?{}:{'content-length':length},
  });
}

test('CI-only upstream archive fetch is bounded before SHA512 or tar execution',()=>{
  const src=readFileSync(new URL(
    '../scripts/saas-staging/install-backend16-native-bun-ci.mjs',
    import.meta.url),'utf8');
  assert.doesNotMatch(src,/response[.]arrayBuffer[(]/);
  const receive=src.indexOf('const bytes=await readBoundedNativeBunResponse(response)');
  const integrity=src.indexOf('verifyNativeBunArchive(bytes);',receive);
  const unpack=src.indexOf("execFileSync('tar'",integrity);
  const revision=src.indexOf("execFileSync(binary,['--revision']",unpack);
  assert.ok(receive>0&&integrity>receive&&unpack>integrity&&revision>unpack);
  assert.match(src,/redirect:'error',signal:AbortSignal[.]timeout[(]120_000[)]/);
  assert.match(src,/MAX_NATIVE_BUN_ARCHIVE_BYTES=150_000_000/);
  assert.match(src,/response[.]redirected!==false/);
});

test('bounded archive response accepts a complete stream but never grants integrity',async()=>{
  const bytes=await readBoundedNativeBunResponse(
    response([[1,2],[3,4]],'4'),4);
  assert.deepEqual([...bytes],[1,2,3,4]);
  assert.throws(()=>verifyNativeBunArchive(bytes));
  assert.deepEqual([...await readBoundedNativeBunResponse(
    response([[5],[6]],undefined),2)],[5,6]);
});

test('declared oversize, malformed framing and incomplete response refuse',async()=>{
  for(const length of ['0','03','2, 2','NaN','150000001','7']){
    await assert.rejects(
      readBoundedNativeBunResponse(response([[1,2,3]],length),5),
      /Backend16 pinned native Bun CI refused/,
    );
  }
  for(const actual of [response([[1,2,3]],'2'),response([[1,2]],'3')]){
    await assert.rejects(readBoundedNativeBunResponse(actual,5),
      /Backend16 pinned native Bun CI refused/);
  }
  await assert.rejects(readBoundedNativeBunResponse(
    response([[1,2]],undefined),MAX_TEST_INVALID_LIMIT),
    /Backend16 pinned native Bun CI refused/);
});

const MAX_TEST_INVALID_LIMIT=150_000_001;
test('untrusted HTTP status, redirect and stream overflow refuse without tar',async()=>{
  await assert.rejects(readBoundedNativeBunResponse(
    response([[1]],'1',{status:206}),2));
  await assert.rejects(readBoundedNativeBunResponse(
    response([[1]],'1',{status:403}),2));
  const redirected=response([[1]],'1');
  Object.defineProperty(redirected,'redirected',{value:true});
  await assert.rejects(readBoundedNativeBunResponse(redirected,2));
  await assert.rejects(readBoundedNativeBunResponse(
    response([[1,2,3],[4,5,6]],undefined),5));
  await assert.rejects(readBoundedNativeBunResponse(
    response([[1]],'1'),0));
});

test('network read errors never surface untrusted response details',async()=>{
  const stream=new ReadableStream({
    start(controller){controller.error(new Error('private-broker-value'));},
  });
  const result=new Response(stream,{status:200});
  await assert.rejects(readBoundedNativeBunResponse(result,6),
    error=>error instanceof Error&&
      error.message==='Backend16 pinned native Bun CI refused');
});

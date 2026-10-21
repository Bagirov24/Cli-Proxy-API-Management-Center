/** Immutable, integrity-pinned upstream SQL TLS fix. Disposable Linux CI only. */
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {appendFileSync,chmodSync,mkdtempSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

export const NATIVE_BUN_CI_PIN=Object.freeze({
  version:'1.4.3-canary.20261019.1',
  revision:'6bb5dc1956505dd1113455f58d4757c924f3ad54',
  url:'https://registry.npmjs.org/@oven/bun-linux-x64/-/bun-linux-x64-1.4.3-canary.20261019.1.tgz',
  sha512:'sCvV4dCwRYWTeGqDNYsPntfJyb7Pp9wGbvRXF/UVBqcG9bGaDv3YdLHfxLy+DM3J+FjnC11M+ukisEp0J145Hg==',
});
const denied=()=>{throw new Error('Backend16 pinned native Bun CI refused');};
const MAX_NATIVE_BUN_ARCHIVE_BYTES=150_000_000;

/**
 * Bound the untrusted HTTP body BEFORE accumulating or unpacking the tarball.
 * A valid SHA512 is checked separately after the final byte is received.
 * The optional lower test limit can never exceed the production CI ceiling.
 */
export async function readBoundedNativeBunResponse(
  response,maxBytes=MAX_NATIVE_BUN_ARCHIVE_BYTES,
){
  if(!Number.isSafeInteger(maxBytes)||maxBytes<1||
     maxBytes>MAX_NATIVE_BUN_ARCHIVE_BYTES||
     response?.status!==200||response.redirected!==false||
     typeof response.headers?.get!=='function'||
     !response.body||typeof response.body.getReader!=='function')denied();
  const length=response.headers.get('content-length');
  if(length!==null&&
     (!/^[1-9][0-9]{0,8}$/.test(length)||Number(length)>maxBytes))denied();
  let reader;
  try{reader=response.body.getReader();}
  catch{denied();}
  // Never retain individual network chunks: a million 1-byte chunks
  // must not allocate a million JS objects beyond the byte-size ceiling.
  // Exact Content-Length allocates once; chunked bodies grow geometrically,
  // with bounded reallocations independent of the number of read() calls.
  const declaredBytes=length===null?null:Number(length);
  let storage=Buffer.allocUnsafe(
    declaredBytes??Math.min(maxBytes,1_048_576),
  );
  let total=0;
  try{
    for(;;){
      const part=await reader.read();
      if(part.done)break;
      const bytes=part.value;
      if(!(bytes instanceof Uint8Array)||bytes.byteLength===0||
         bytes.byteLength>maxBytes-total)denied();
      const needed=total+bytes.byteLength;
      if(needed>storage.length){
        if(declaredBytes!==null)denied();
        const capacity=Math.min(maxBytes,Math.max(needed,storage.length*2));
        const grown=Buffer.allocUnsafe(capacity);
        storage.copy(grown,0,0,total);
        storage=grown;
      }
      storage.set(bytes,total);
      total=needed;
    }
    if(total===0||(declaredBytes!==null&&total!==declaredBytes))denied();
    // Every returned byte was copied from the complete HTTP response.
    return storage.subarray(0,total);
  }catch{denied();}
  finally{
    // No partially received archive is written or passed to tar.
    try{void reader.cancel().catch(()=>{});}catch{/* refused */ }
    try{reader.releaseLock();}catch{/* refused */ }
  }
}
export function enforceNativeBunCi(e,nodeMajor,platform,arch){
  if(e.GITHUB_ACTIONS!=='true'||e.CI!=='true'||nodeMajor!==24||
     platform!=='linux'||arch!=='x64'||!e.GITHUB_ENV||
     e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
     Object.keys(e).some(k=>k.startsWith('RAILWAY_')&&e[k]))denied();
}
export function verifyNativeBunArchive(bytes){
  if(!(bytes instanceof Uint8Array)||bytes.length<1_000_000||bytes.length>MAX_NATIVE_BUN_ARCHIVE_BYTES||
     createHash('sha512').update(bytes).digest('base64')!==NATIVE_BUN_CI_PIN.sha512)denied();
}
async function main(){
  enforceNativeBunCi(process.env,Number(process.versions.node.split('.')[0]),process.platform,process.arch);
  const response=await fetch(NATIVE_BUN_CI_PIN.url,{
    redirect:'error',signal:AbortSignal.timeout(120_000),
  });
  const bytes=await readBoundedNativeBunResponse(response);
  verifyNativeBunArchive(bytes); // No extraction or execution before the pinned hash matches.
  const dir=mkdtempSync(join(tmpdir(),'b16-native-bun-pinned-'));
  const archive=join(dir,'bun.tgz');
  writeFileSync(archive,bytes,{mode:0o600});
  execFileSync('tar',['-xzf',archive,'-C',dir,'--no-same-owner',
    '--no-same-permissions','package/bin/bun'],{stdio:'pipe',timeout:20_000});
  const binary=join(dir,'package/bin/bun');
  chmodSync(binary,0o700);
  // --revision is public build provenance, not a secret or approval receipt.
  const revision=execFileSync(binary,['--revision'],{encoding:'utf8',timeout:5000}).trim();
  if(revision!=='1.4.4-canary.1+6bb5dc195'||
     execFileSync(binary,['-p','Bun.revision'],{encoding:'utf8',timeout:5000}).trim()!==NATIVE_BUN_CI_PIN.revision)denied();
  appendFileSync(process.env.GITHUB_ENV,'SAAS_B16_NATIVE_BUN_BIN='+binary+'\n');
  console.info('B16_NATIVE_BUN_ARCHIVE_SHA512_VERIFIED');
  console.info('B16_NATIVE_BUN_PINNED_REVISION '+revision);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)
  main().catch(()=>{console.error('STOP Backend16 pinned native Bun CI refused');process.exitCode=1;});

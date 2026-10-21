/**
 * Backend16 P1/P2: OFFLINE, side-effect-free, integrity-only examination of a
 * hypothetical independently pinned stable Bun Linux x64 npm archive.
 *
 * Does not fetch, unpack, execute, install, sign, attest or approve anything.
 * In particular, no checked-in stable candidate exists at this checkpoint.
 */
import {createHash,timingSafeEqual} from 'node:crypto';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

export const BACKEND16_NATIVE_STABLE_PREFLIGHT_SCHEMA=
  'backend16-native-bun-stable-archive-preflight-v1';
const DENIED='Backend16 stable Native Bun archive preflight refused';
const MIN_BYTES=1_000_000;
const MAX_BYTES=150_000_000;
const PACKAGE='@oven/bun-linux-x64';
const HEX40=/^[0-9a-f]{40}$/;
const CANONICAL_KEYS=Object.freeze([
  'archiveByteLength','archiveSha512','architecture','cliRevision',
  'npmPackage','platform','registryURL','schema','sourceRevision','version',
].sort());
const refuse=()=>{throw new Error(DENIED);};

function exactSha512(value){
  if(typeof value!=='string'||value.length!==88||
     !/^[A-Za-z0-9+/]{86}==$/.test(value))return false;
  const decoded=Buffer.from(value,'base64');
  return decoded.length===64&&decoded.toString('base64')===value;
}

export function assertBackend16StableNativeBunDescriptor(desc){
  if(!desc||typeof desc!=='object'||Array.isArray(desc)||
     Object.getPrototypeOf(desc)!==Object.prototype||
     Object.keys(desc).sort().join(',')!==CANONICAL_KEYS.join(',')||
     desc.schema!==BACKEND16_NATIVE_STABLE_PREFLIGHT_SCHEMA||
     desc.npmPackage!==PACKAGE||desc.platform!=='linux'||
     desc.architecture!=='x64'||typeof desc.version!=='string'||
     desc.version.length>32||
     !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(desc.version)||
     !Number.isSafeInteger(desc.archiveByteLength)||
     desc.archiveByteLength<MIN_BYTES||desc.archiveByteLength>MAX_BYTES||
     !exactSha512(desc.archiveSha512)||
     !HEX40.test(desc.sourceRevision)||
     desc.sourceRevision==='0'.repeat(40))refuse();

  const numbers=desc.version.split('.').map(Number);
  if(numbers.some(n=>!Number.isSafeInteger(n))||
     numbers[0]<1||
     (numbers[0]===1&&(numbers[1]<4||
       (numbers[1]===4&&numbers[2]<=3))))refuse();

  // The CLI and complete source revision must agree. In a later, separately
  // authorized job the *actual binary* must be checked against BOTH again.
  if(desc.cliRevision!==desc.version+'+'+desc.sourceRevision.slice(0,9)||
     desc.registryURL!==
       'https://registry.npmjs.org/@oven/bun-linux-x64/-/bun-linux-x64-'
       +desc.version+'.tgz')refuse();
  return true; // descriptor shape only; NOT a release/transport verdict
}

export function inspectBackend16StableNativeBunArchive(desc,bytes){
  assertBackend16StableNativeBunDescriptor(desc);
  if(!(bytes instanceof Uint8Array)||
     bytes.byteLength!==desc.archiveByteLength)refuse();
  const computed=createHash('sha512').update(bytes).digest();
  const expected=Buffer.from(desc.archiveSha512,'base64');
  if(!timingSafeEqual(computed,expected))refuse();
  return Object.freeze({
    result:'ARCHIVE_INTEGRITY_ONLY_NOT_APPROVED',
    stableRuntimeApproved:false,
    stagingAuthorized:false,
    productionAuthorized:false,
  });
}

// No standalone success path, even if accidentally invoked in a release job.
// A future candidate requires separate upstream release and signed reviews.
if(process.argv[1]&&
   import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  console.error('STOP Backend16 Native Bun stable runtime is NOT PINNED OR APPROVED');
  process.exitCode=1;
}

/**
 * Backend16 P1 disposable security comparator for officially published Bun
 * v1.4.4 Linux x64. NOT the application's runtime, a publisher signature,
 * a production installer, a server artifact, or any release approval.
 */
import {createHash,timingSafeEqual} from 'node:crypto';
import {execFileSync,spawnSync} from 'node:child_process';
import {
  appendFileSync,chmodSync,closeSync,fstatSync,lstatSync,
  mkdtempSync,openSync,readSync,rmSync,writeFileSync,
} from 'node:fs';
import {constants} from 'node:fs';
import {tmpdir} from 'node:os';
import {isAbsolute,join,relative,resolve,sep} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const DENIED='Backend16 official stable Bun144 disposable CI refused';
const MAX_ARCHIVE_BYTES=150_000_000;
const MAX_BINARY_BYTES=240_000_000;
const REPO='Bagirov24/Cli-Proxy-API-Management-Center';
const HEX40=/^[0-9a-f]{40}$/;
const ELF=Buffer.from([0x7f,0x45,0x4c,0x46]);
const ZIP_MEMBER='bun-linux-x64/bun';
const CDN=new Set([
  'github.com','release-assets.githubusercontent.com',
  'objects.githubusercontent.com','github-releases.githubusercontent.com',
]);
const refuse=()=>{throw new Error(DENIED);};

// Independently reviewed values from upstream GitHub release/tag on 2026-10-23.
// This checks transport byte consistency, NOT publisher or security approval.
export const B16_OFFICIAL_STABLE_144=Object.freeze({
  tag:'bun-v1.4.4',
  version:'1.4.4',
  fullRevision:'38afee6c84fcf48c0edb2466aa4b27d287a59c30',
  cliRevision:'1.4.4+38afee6c8',
  filename:'bun-linux-x64.zip',
  url:'https://github.com/oven-sh/bun/releases/download/bun-v1.4.4/bun-linux-x64.zip',
  archiveSize:51794595,
  archiveSha256:'bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c',
});
const PIN_KEYS=Object.freeze(Object.keys(B16_OFFICIAL_STABLE_144).sort());

export function assertBackend16OfficialStable144CandidatePin(pin){
  if(!pin||typeof pin!=='object'||Array.isArray(pin)||
     Object.getPrototypeOf(pin)!==Object.prototype||
     Object.keys(pin).sort().join(',')!==PIN_KEYS.join(',')||
     PIN_KEYS.some(k=>pin[k]!==B16_OFFICIAL_STABLE_144[k]))refuse();
  return true;
}

export function verifyBackend16OfficialStable144Archive(bytes){
  if(!(bytes instanceof Uint8Array)||
     bytes.byteLength!==B16_OFFICIAL_STABLE_144.archiveSize||
     bytes.byteLength>MAX_ARCHIVE_BYTES)refuse();
  const hash=createHash('sha256').update(bytes).digest();
  const expected=Buffer.from(B16_OFFICIAL_STABLE_144.archiveSha256,'hex');
  if(!timingSafeEqual(hash,expected))refuse();
  return Object.freeze({
    result:'B16_STABLE_144_ARCHIVE_BYTES_MATCH_ONLY',
    officialReleaseTag:B16_OFFICIAL_STABLE_144.tag,
    stableRuntimeApproved:false,
    stagingAuthorized:false,
    productionAuthorized:false,
  });
}

export function enforceBackend16OfficialStable144CiEnvironment(
  env,major,platform,arch
){
  if(!env||typeof env!=='object'||major!==24||platform!=='linux'||arch!=='x64'||
     env.CI!=='true'||env.GITHUB_ACTIONS!=='true'||
     env.SAAS_B16_STABLE_144_CI!=='true'||
     env.GITHUB_EVENT_NAME!=='pull_request'||
     env.GITHUB_REPOSITORY!==REPO||
     env.RUNNER_OS!=='Linux'||env.RUNNER_ARCH!=='X64'||
     !/^refs\/pull\/[1-9]\d*\/merge$/.test(env.GITHUB_REF??'')||
     !HEX40.test(env.B16_PR_HEAD_SHA??'')||
     !HEX40.test(env.GITHUB_SHA??'')||
     !isAbsolute(env.RUNNER_TEMP??'')||
     !isAbsolute(env.GITHUB_ENV??'')||
     env.NODE_ENV==='production'||env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
     env.PGHOST!=='127.0.0.1'||env.PGPORT!=='5432'||
     env.PGUSER!=='postgres'||env.PGDATABASE!=='saas_ephemeral_test'||
     env.PGPASSWORD!=='ci_ephemeral_test_only'||
     env.DATABASE_URL||env.SAAS_B16_NATIVE_BUN_BIN||
     env.SAAS_B16_LOCKED_FULL_CHAIN_CI||
     Object.keys(env).some(k=>k.startsWith('RAILWAY_')&&env[k]))
    refuse();
  const rel=relative(env.RUNNER_TEMP,env.GITHUB_ENV).split(sep).join('/');
  if(!/^_runner_file_commands\/set_env_[A-Za-z0-9-]{8,}$/.test(rel))
    refuse();
  return true;
}

export function assertBackend16OfficialStable144Redirect(current,location){
  let next;
  try{next=new URL(location,current);}catch{refuse();}
  if(next.protocol!=='https:'||!CDN.has(next.hostname)||
     next.port||next.username||next.password||next.hash)refuse();
  return next.href;
}

async function fetchPinnedArchive(){
  let url=B16_OFFICIAL_STABLE_144.url;
  for(let i=0;i<5;i++){
    const response=await fetch(url,{
      redirect:'manual',
      signal:AbortSignal.timeout(115_000),
      headers:{'Accept':'application/octet-stream'},
    });
    if([301,302,303,307,308].includes(response.status)){
      const location=response.headers.get('location');
      if(!location)refuse();
      url=assertBackend16OfficialStable144Redirect(url,location);
      await response.body?.cancel();
      continue;
    }
    if(response.status!==200||!response.body)refuse();
    const length=response.headers.get('content-length');
    if(length!==null&&length!==String(B16_OFFICIAL_STABLE_144.archiveSize))
      refuse();
    const reader=response.body.getReader();
    const chunks=[];
    let total=0;
    while(true){
      const next=await reader.read();
      if(next.done)break;
      total+=next.value.byteLength;
      if(total>MAX_ARCHIVE_BYTES||
         total>B16_OFFICIAL_STABLE_144.archiveSize){
        await reader.cancel();
        refuse();
      }
      chunks.push(Buffer.from(next.value));
    }
    if(total!==B16_OFFICIAL_STABLE_144.archiveSize)refuse();
    return Buffer.concat(chunks,total);
  }
  refuse();
}

function checkoutSha(root){
  const command=spawnSync('git',['rev-parse','HEAD'],{
    cwd:root,encoding:'utf8',stdio:['ignore','pipe','pipe'],
    timeout:5_000,maxBuffer:1_024,
  });
  if(command.error||command.signal||command.status!==0||
     typeof command.stdout!=='string'||
     !HEX40.test(command.stdout.trim())||
     command.stderr!=='')refuse();
  return command.stdout.trim();
}

function verifyArchiveMembers(archive){
  const names=execFileSync('unzip',['-Z','-1',archive],{
    encoding:'utf8',stdio:['ignore','pipe','ignore'],
    timeout:8_000,maxBuffer:4_096,
  }).trim().split('\n');
  // unzip -p only reads the literal reviewed binary entry. Never let unzip
  // extract arbitrary ZIP paths, symlinks or additional unreviewed members.
  if(![1,2].includes(names.length)||
     !names.includes(ZIP_MEMBER)||
     names.some(n=>n!==ZIP_MEMBER&&n!=='bun-linux-x64/')||
     new Set(names).size!==names.length)refuse();
}

function extractPinnedBinary(archive,dir){
  verifyArchiveMembers(archive);
  const binary=join(dir,'bun');
  let fd;
  try{
    fd=openSync(binary,constants.O_WRONLY|constants.O_CREAT|
      constants.O_EXCL|constants.O_NOFOLLOW,0o600);
    const child=spawnSync('unzip',['-p',archive,ZIP_MEMBER],{
      stdio:['ignore',fd,'pipe'],timeout:35_000,maxBuffer:4_096,
    });
    if(child.error||child.signal||child.status!==0||
       child.stderr?.length)refuse();
    const opened=fstatSync(fd);
    if(!opened.isFile()||opened.size<20_000_000||
       opened.size>MAX_BINARY_BYTES)refuse();
  }finally{if(fd!==undefined)closeSync(fd);}
  const stat=lstatSync(binary);
  if(!stat.isFile()||stat.isSymbolicLink()||
     stat.size<20_000_000||stat.size>MAX_BINARY_BYTES)refuse();
  const readFd=openSync(binary,constants.O_RDONLY|constants.O_NOFOLLOW);
  let header;
  try{
    header=Buffer.alloc(4);
    if(readSync(readFd,header,0,4,0)!==4)refuse();
  }finally{closeSync(readFd);}
  if(!header.equals(ELF))refuse();
  chmodSync(binary,0o700);
  return binary;
}

function verifyRuntime(binary){
  const run=args=>execFileSync(binary,args,{
    encoding:'utf8',stdio:['ignore','pipe','ignore'],
    timeout:10_000,maxBuffer:2_048,
  }).trim();
  if(run(['--revision'])!==B16_OFFICIAL_STABLE_144.cliRevision||
     run(['-p','Bun.version'])!==B16_OFFICIAL_STABLE_144.version||
     run(['-p','Bun.revision'])!==B16_OFFICIAL_STABLE_144.fullRevision)
    refuse();
}

async function main(){
  const e=process.env;
  enforceBackend16OfficialStable144CiEnvironment(
    e,Number(process.versions.node.split('.')[0]),
    process.platform,process.arch);
  const root=fileURLToPath(new URL('../../',import.meta.url));
  if(checkoutSha(root)!==e.B16_PR_HEAD_SHA)refuse();
  const file=lstatSync(e.GITHUB_ENV);
  if(!file.isFile()||file.isSymbolicLink())refuse();
  assertBackend16OfficialStable144CandidatePin(B16_OFFICIAL_STABLE_144);
  const bytes=await fetchPinnedArchive();
  verifyBackend16OfficialStable144Archive(bytes); // BEFORE unzip / execution.
  const dir=mkdtempSync(join(tmpdir(),'b16-official-stable-144-ci-'));
  let successful=false;
  try{
    const archive=join(dir,'release.zip');
    writeFileSync(archive,bytes,{mode:0o600,flag:'wx'});
    const binary=extractPinnedBinary(archive,dir);
    verifyRuntime(binary);
    appendFileSync(e.GITHUB_ENV,'SAAS_B16_STABLE_144_BIN='+binary+'\n');
    successful=true;
    console.info('B16_OFFICIAL_STABLE_144_ASSET_SHA256_VERIFIED');
    console.info('B16_OFFICIAL_STABLE_144_BINARY_REVISION_MATCH');
    console.info('B16_OFFICIAL_STABLE_144_NOT_APPROVED_FOR_RELEASE');
    console.info('NO RELEASE AUTHORIZATION');
  }finally{
    if(!successful)rmSync(dir,{recursive:true,force:true});
  }
}

if(process.argv[1]&&
   import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  main().catch(()=>{
    console.error('STOP Backend16 official stable Bun144 disposable CI refused');
    process.exitCode=1;
  });
}

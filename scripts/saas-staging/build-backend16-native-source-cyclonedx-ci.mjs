/**
 * Backend16 P2 CI-only CycloneDX 1.6 inventory for the EXACT seven reviewed
 * unmounted Native Bun transport source files. NOT a full runtime/package
 * SBOM, Bun executable, artifact, approval, or signed provenance.
 */
import {createHash} from 'node:crypto';
import {closeSync,constants,fstatSync,lstatSync,openSync,readFileSync} from 'node:fs';
import {isAbsolute,join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {
  assertBackend16NativeSourceClosurePolicy,
  inspectBackend16NativeSourceClosure,
} from './verify-backend16-native-source-closure-ci.mjs';

const ROOT='src/features/saasBlueprint/controlApi/server';
const DENIED='Backend16 Native source CycloneDX CI refused';
const SCOPE='UNMOUNTED_NATIVE_TRANSPORT_AND_SECRET_CLIENTS_ONLY';
const REF='backend16-native-source:';
const MAX_FILE_BYTES=1_000_000;
const MAX_TOTAL_BYTES=5_000_000;
const refuse=()=>{throw new Error(DENIED);};

function secureDirectory(path){
  let stat;
  try{stat=lstatSync(path);}catch{refuse();}
  if(!stat.isDirectory()||stat.isSymbolicLink()||(stat.mode&0o022))refuse();
}
function contents(repoRoot,name){
  if(typeof repoRoot!=='string'||!isAbsolute(repoRoot)||
     repoRoot.includes('\0')||!/^backend16[A-Za-z0-9]+\.ts$/.test(name))
    refuse();
  secureDirectory(repoRoot);
  let parent=repoRoot;
  for(const part of ROOT.split('/')){
    parent=join(parent,part);
    secureDirectory(parent);
  }
  const path=join(parent,name);
  let fd,stat,opened,bytes;
  try{
    stat=lstatSync(path);
    if(!stat.isFile()||stat.isSymbolicLink()||
       (stat.mode&0o022)||stat.size<1||stat.size>MAX_FILE_BYTES)refuse();
    fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
    opened=fstatSync(fd);
    if(!opened.isFile()||opened.dev!==stat.dev||
       opened.ino!==stat.ino||opened.size!==stat.size)refuse();
    bytes=readFileSync(fd);
    if(bytes.length!==stat.size)refuse();
  }catch{refuse();}
  finally{if(fd!==undefined)try{closeSync(fd);}catch{refuse();}}
  return bytes;
}
function readPolicy(){
  let source;
  try{source=readFileSync(new URL(
    './backend16-native-server-source-closure.v1.json',import.meta.url));}
  catch{refuse();}
  if(source.length<10||source.length>12_000)refuse();
  let data;
  try{data=JSON.parse(source.toString('utf8'));}catch{refuse();}
  assertBackend16NativeSourceClosurePolicy(data);
  return data;
}
const hash256=bytes=>createHash('sha256').update(bytes).digest('hex');
const gitBlob=bytes=>createHash('sha1').update(
  'blob '+bytes.length+'\0').update(bytes).digest('hex');

/**
 * Results carry JSON text rather than a mutable object. No IO output is
 * produced by this function; the caller must not publish it as a release BOM.
 */
export function buildBackend16NativeSourceCycloneDx(repoRoot){
  // First validate all bytes and declared imports in the independent,
  // fail-closed reviewed-closure gate, then independently re-read/rehash.
  const observed=inspectBackend16NativeSourceClosure(repoRoot);
  if(observed.result!=='B16_NATIVE_BUN_SOURCE_CLOSURE_CI_PASS'||
     observed.fileCount!==7||observed.externalPackageCount!==0||
     observed.serverArtifactBuilt!==false||
     observed.stableRuntimeApproved!==false||
     observed.productionAuthorized!==false)refuse();
  const policy=readPolicy();
  let total=0;
  const files=[];
  for(const entry of policy.modules){
    const bytes=contents(repoRoot,entry.file);
    total+=bytes.length;
    if(total>MAX_TOTAL_BYTES||gitBlob(bytes)!==entry.gitBlobSha1)refuse();
    files.push({
      path:ROOT+'/'+entry.file,
      gitBlobSha1:entry.gitBlobSha1,
      bytes:bytes.length,
      sha256:hash256(bytes),
      imports:entry.imports,
    });
  }
  // Bind the second read to the first verifier's *complete* inventory:
  // paths, hashes, import kinds/edges, builtins and all release hard stops.
  const inventory={
    schema:'backend16-native-source-inventory-ci-v1',
    scope:SCOPE,
    files,
    builtinDependencies:policy.allowedBuiltins,
    externalPackageDependencies:[],
    serverArtifactBuilt:false,
    stableRuntimeApproved:false,
    productionAuthorized:false,
  };
  if(hash256(JSON.stringify(inventory))!==observed.sourceInventorySha256)
    refuse();

  const components=files.map(file=>({
    type:'file',
    'bom-ref':REF+file.path,
    name:file.path,
    hashes:[{alg:'SHA-256',content:file.sha256}],
    properties:[
      {name:'backend16:gitBlobSha1',value:file.gitBlobSha1},
      {name:'backend16:byteLength',value:String(file.bytes)},
    ],
  }));
  const dependencies=policy.modules.map(entry=>({
    ref:REF+ROOT+'/'+entry.file,
    dependsOn:[...new Set(entry.imports
      .filter(item=>item.specifier.startsWith('./'))
      .map(item=>REF+ROOT+'/'+item.specifier.slice(2).replace(/\.ts$/,'')+'.ts'))]
      .sort(),
  }));
  const bom={
    bomFormat:'CycloneDX',
    specVersion:'1.6',
    version:1,
    metadata:{
      properties:[
        {name:'backend16:sourceScope',value:SCOPE},
        {name:'backend16:sourceInventorySha256',value:observed.sourceInventorySha256},
        {name:'backend16:sourceEdgesIncludeTypeImports',value:'true'},
        {name:'backend16:NOT_A_PRODUCTION_SBOM',value:'true'},
        {name:'backend16:serverArtifactBuilt',value:'false'},
        {name:'backend16:stableRuntimeApproved',value:'false'},
        {name:'backend16:productionAuthorized',value:'false'},
      ],
    },
    components,
    dependencies,
  };
  const json=JSON.stringify(bom);
  return Object.freeze({
    result:'B16_NATIVE_BUN_SOURCE_CYCLONEDX_CI_PASS',
    bomJson:json,
    bomSha256:hash256(json),
    sourceInventorySha256:observed.sourceInventorySha256,
    fileCount:files.length,
    serverArtifactBuilt:false,
    stableRuntimeApproved:false,
    productionAuthorized:false,
  });
}

if(process.argv[1]&&
   import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{
    const e=process.env;
    if(process.argv.length!==2||e.CI!=='true'||
       e.GITHUB_ACTIONS!=='true'||
       process.versions.node.split('.')[0]!=='24'||
       process.platform!=='linux'||process.arch!=='x64'||
       e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
       Object.keys(e).some(k=>k.startsWith('RAILWAY_')&&e[k]))
      refuse();
    const result=buildBackend16NativeSourceCycloneDx(
      fileURLToPath(new URL('../../',import.meta.url)));
    console.info(result.result);
    console.info('B16_NATIVE_BUN_SOURCE_CYCLONEDX_SHA256='+result.bomSha256);
    console.info('B16_NATIVE_BUN_SOURCE_CYCLONEDX_NOT_PRODUCTION_SBOM');
    console.info('NO RELEASE AUTHORIZATION');
  }catch{
    console.error('STOP Backend16 Native source CycloneDX CI refused');
    process.exitCode=1;
  }
}

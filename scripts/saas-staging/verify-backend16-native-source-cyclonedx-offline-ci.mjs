/**
 * Backend16 P2: fail-closed, offline verification of the exact reviewed
 * seven-file source-only CycloneDX subset. NOT upstream schema validation,
 * a runtime dependency SBOM, executable, signature or release approval.
 */
import {createHash} from 'node:crypto';
import {
  closeSync,constants,fstatSync,lstatSync,openSync,readFileSync,
} from 'node:fs';
import {isAbsolute,join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {
  assertBackend16NativeSourceClosurePolicy,
  inspectBackend16NativeSourceClosure,
} from './verify-backend16-native-source-closure-ci.mjs';

const ROOT='src/features/saasBlueprint/controlApi/server';
const SCOPE='UNMOUNTED_NATIVE_TRANSPORT_AND_SECRET_CLIENTS_ONLY';
const REF='backend16-native-source:';
const DENIED='Backend16 Native source CycloneDX offline verification refused';
const MAX_BOM_BYTES=65_536;
const MAX_SOURCE_BYTES=1_000_000;
const hash=(name,bytes)=>createHash(name).update(bytes).digest('hex');
const refuse=()=>{throw new Error(DENIED);};

function record(value,keys){
  if(!value||typeof value!=='object'||Array.isArray(value)||
     Object.getPrototypeOf(value)!==Object.prototype||
     Object.keys(value).sort().join(',')!==[...keys].sort().join(','))
    refuse();
}
function identical(a,b){
  return JSON.stringify(a)===JSON.stringify(b);
}
function directory(path){
  let stat;
  try{stat=lstatSync(path);}catch{refuse();}
  if(!stat.isDirectory()||stat.isSymbolicLink()||(stat.mode&0o022))refuse();
}
function sourceBytes(repoRoot,file){
  if(typeof repoRoot!=='string'||!isAbsolute(repoRoot)||
     repoRoot.includes('\0')||!/^backend16[A-Za-z0-9]+\.ts$/.test(file))
    refuse();
  directory(repoRoot);
  let parent=repoRoot;
  for(const part of ROOT.split('/')){
    parent=join(parent,part);
    directory(parent);
  }
  let fd,stat,opened,bytes;
  try{
    const path=join(parent,file);
    stat=lstatSync(path);
    if(!stat.isFile()||stat.isSymbolicLink()||
       (stat.mode&0o022)||stat.size<1||stat.size>MAX_SOURCE_BYTES)
      refuse();
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
function policyFromDisk(){
  let bytes,policy;
  try{
    bytes=readFileSync(new URL(
      './backend16-native-server-source-closure.v1.json',import.meta.url));
    if(bytes.length<10||bytes.length>12_000)refuse();
    policy=JSON.parse(bytes.toString('utf8'));
    assertBackend16NativeSourceClosurePolicy(policy);
  }catch{refuse();}
  return policy;
}

/**
 * The claimed digest is supplied by the caller, not inferred from the BOM.
 * A matching digest proves only byte consistency, never publisher trust.
 * All graph refs and file hashes are checked against pinned sources anew.
 */
export function verifyBackend16NativeSourceCycloneDxOffline(
  repoRoot,bomJson,claimedBomSha256
){
  if(typeof bomJson!=='string'||!bomJson.startsWith('{')||
     Buffer.byteLength(bomJson,'utf8')>MAX_BOM_BYTES||
     !/^[a-f0-9]{64}$/.test(claimedBomSha256)||
     hash('sha256',Buffer.from(bomJson,'utf8'))!==claimedBomSha256)
    refuse();
  let bom;
  try{bom=JSON.parse(bomJson);}catch{refuse();}
  // Reject noncanonical JSON, duplicate keys and ambiguous encodings.
  if(!identical(bomJson,JSON.stringify(bom)))refuse();
  record(bom,['bomFormat','specVersion','version','metadata','components','dependencies']);
  if(bom.bomFormat!=='CycloneDX'||bom.specVersion!=='1.6'||bom.version!==1)
    refuse();

  // Authenticate current reviewed sources and re-open each one separately:
  // not only the checksum printed by a potentially faulty BOM producer.
  const observed=inspectBackend16NativeSourceClosure(repoRoot);
  if(observed.result!=='B16_NATIVE_BUN_SOURCE_CLOSURE_CI_PASS'||
     observed.fileCount!==7||observed.externalPackageCount!==0||
     observed.serverArtifactBuilt!==false||
     observed.stableRuntimeApproved!==false||
     observed.productionAuthorized!==false)refuse();
  const policy=policyFromDisk();
  const expectedProperties=[
    {name:'backend16:sourceScope',value:SCOPE},
    {name:'backend16:sourceInventorySha256',value:observed.sourceInventorySha256},
    {name:'backend16:sourceEdgesIncludeTypeImports',value:'true'},
    {name:'backend16:NOT_A_PRODUCTION_SBOM',value:'true'},
    {name:'backend16:serverArtifactBuilt',value:'false'},
    {name:'backend16:stableRuntimeApproved',value:'false'},
    {name:'backend16:productionAuthorized',value:'false'},
  ];
  record(bom.metadata,['properties']);
  if(!identical(bom.metadata.properties,expectedProperties)||
     !Array.isArray(bom.components)||!Array.isArray(bom.dependencies)||
     bom.components.length!==policy.modules.length||
     bom.dependencies.length!==policy.modules.length)
    refuse();

  const refs=new Set(policy.modules.map(entry=>REF+ROOT+'/'+entry.file));
  for(let i=0;i<policy.modules.length;i++){
    const entry=policy.modules[i];
    const path=ROOT+'/'+entry.file;
    const ref=REF+path;
    const component=bom.components[i];
    const dependency=bom.dependencies[i];
    record(component,['type','bom-ref','name','hashes','properties']);
    if(component.type!=='file'||component['bom-ref']!==ref||
       component.name!==path||!Array.isArray(component.hashes)||
       component.hashes.length!==1||!Array.isArray(component.properties)||
       component.properties.length!==2)refuse();
    record(component.hashes[0],['alg','content']);
    const bytes=sourceBytes(repoRoot,entry.file);
    const gitSha=createHash('sha1').update(
      'blob '+bytes.length+'\0').update(bytes).digest('hex');
    if(gitSha!==entry.gitBlobSha1||
       component.hashes[0].alg!=='SHA-256'||
       component.hashes[0].content!==hash('sha256',bytes)||
       !identical(component.properties,[
         {name:'backend16:gitBlobSha1',value:entry.gitBlobSha1},
         {name:'backend16:byteLength',value:String(bytes.length)},
       ]))refuse();

    record(dependency,['ref','dependsOn']);
    const expectedEdges=[...new Set(entry.imports
      .filter(item=>item.specifier.startsWith('./'))
      .map(item=>REF+ROOT+'/'+item.specifier.slice(2)
        .replace(/\.ts$/,'')+'.ts'))].sort();
    if(dependency.ref!==ref||!Array.isArray(dependency.dependsOn)||
       !identical(dependency.dependsOn,expectedEdges)||
       dependency.dependsOn.some(target=>!refs.has(target)))refuse();
  }
  return Object.freeze({
    result:'B16_NATIVE_BUN_SOURCE_CYCLONEDX_OFFLINE_VERIFIED',
    bomSha256:claimedBomSha256,
    sourceInventorySha256:observed.sourceInventorySha256,
    fileCount:7,
    upstreamSchemaValidated:false,
    serverArtifactBuilt:false,
    stableRuntimeApproved:false,
    productionAuthorized:false,
  });
}

// There is deliberately no CLI ingestion of arbitrary BOM paths or release
// attestation. The only CI consumer is the adversarial Node24 test harness.
if(process.argv[1]&&
   import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  console.error('STOP Backend16 Native source CycloneDX offline verification refused');
  process.exitCode=1;
}

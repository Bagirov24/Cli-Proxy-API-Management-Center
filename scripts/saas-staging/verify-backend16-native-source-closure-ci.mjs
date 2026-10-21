/**
 * Backend16 P2, CI-only: reviewed source closure of UNMOUNTED Native Bun.SQL
 * physical transport + vault/broker contracts. Not a bundle, production SBOM,
 * signed provenance, stable runtime acceptance or live operator permission.
 *
 * The checked-in Git object IDs are manual review pins, never generated or
 * refreshed automatically by this verifier. Updating them requires a PR.
 */
import {createHash} from 'node:crypto';
import {
  closeSync,constants,fstatSync,lstatSync,openSync,readFileSync,
} from 'node:fs';
import {isAbsolute,join,resolve,sep} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const DENIED='Backend16 Native Bun server source closure CI refused';
const SCHEMA='backend16-native-server-source-closure-v1';
const ROOT='src/features/saasBlueprint/controlApi/server';
const SCOPE='UNMOUNTED_NATIVE_TRANSPORT_AND_SECRET_CLIENTS_ONLY';
const FILE_NAMES=Object.freeze([
  'backend16ExactSessionSqlRead.ts',
  'backend16PhysicalPgAdmission.ts',
  'backend16PrivateMtlsVersionedSecretReader.ts',
  'backend16PrivateTenantProjectRead.ts',
  'backend16StagingBunPhysicalPgPool.ts',
  'backend16StagingPgTlsTrust.ts',
  'backend16StagingVersionedPrincipalVault.ts',
]);
const ENTRYPOINTS=Object.freeze([
  'backend16PrivateMtlsVersionedSecretReader.ts',
  'backend16PrivateTenantProjectRead.ts',
  'backend16StagingBunPhysicalPgPool.ts',
  'backend16StagingVersionedPrincipalVault.ts',
]);
const BUILTINS=Object.freeze(['node:crypto','node:https','node:tls']);
const HEX40=/^[a-f0-9]{40}$/;
const MAX_FILE_BYTES=1_000_000;
const MAX_POLICY_BYTES=12_000;
const MAX_TOTAL_BYTES=5_000_000;
const MAX_IMPORTS=24;
const refuse=()=>{throw new Error(DENIED);};
const sourceRoot=fileURLToPath(new URL('../../',import.meta.url));

function data(value,keys){
  if(!value||typeof value!=='object'||Array.isArray(value)||
     Object.getPrototypeOf(value)!==Object.prototype)refuse();
  const descriptors=Object.getOwnPropertyDescriptors(value);
  if(Object.keys(descriptors).sort().join(',')!==keys.slice().sort().join(',')||
     Object.values(descriptors).some(d=>!('value' in d)))refuse();
}
function same(actual,expected){
  return JSON.stringify(actual)===JSON.stringify(expected);
}
function importName(value){
  return value.kind+':'+value.specifier;
}
function normalizedImports(imports){
  if(!Array.isArray(imports)||imports.length>MAX_IMPORTS)refuse();
  const normalized=imports.map(entry=>{
    data(entry,['kind','specifier']);
    if(!['type','value'].includes(entry.kind)||
       typeof entry.specifier!=='string')refuse();
    const spec=entry.specifier;
    if(!BUILTINS.includes(spec)&&!/^\.\/[A-Za-z0-9_-]+(?:\.ts)?$/.test(spec))
      refuse();
    return {kind:entry.kind,specifier:spec};
  });
  normalized.sort((a,b)=>importName(a)<importName(b)?-1:
    importName(a)>importName(b)?1:0);
  if(new Set(normalized.map(importName)).size!==normalized.length)refuse();
  return normalized;
}
export function assertBackend16NativeSourceClosurePolicy(policy){
  data(policy,[
    'allowedBuiltins','entrypoints','modules','productionAuthorized','root',
    'schema','scope','serverArtifactBuilt','stableRuntimeApproved',
  ]);
  if(policy.schema!==SCHEMA||policy.scope!==SCOPE||policy.root!==ROOT||
     policy.serverArtifactBuilt!==false||
     policy.stableRuntimeApproved!==false||
     policy.productionAuthorized!==false||
     !same(policy.entrypoints,ENTRYPOINTS)||
     !same(policy.allowedBuiltins,BUILTINS)||
     !Array.isArray(policy.modules)||policy.modules.length!==FILE_NAMES.length)
    refuse();
  for(let i=0;i<FILE_NAMES.length;i++){
    const module=policy.modules[i];
    data(module,['file','gitBlobSha1','imports']);
    if(module.file!==FILE_NAMES[i]||!HEX40.test(module.gitBlobSha1)||
       module.gitBlobSha1==='0'.repeat(40))refuse();
    const imports=normalizedImports(module.imports);
    if(!same(imports,module.imports))refuse();
    for(const entry of imports){
      const spec=entry.specifier;
      if(spec.startsWith('node:')){
        if(entry.kind!=='value')refuse();
      }else{
        const target=spec.slice(2).replace(/\.ts$/,'')+'.ts';
        if(!FILE_NAMES.includes(target))refuse();
      }
    }
  }
  const builtinUnion=[...new Set(policy.modules.flatMap(m=>m.imports)
    .filter(i=>i.specifier.startsWith('node:'))
    .map(i=>i.specifier))].sort();
  if(!same(builtinUnion,BUILTINS))refuse();
  return true;
}

const UNSAFE_SOURCE=Object.freeze([
  /\b(?:eval|Function|require)\s*\(/,
  /\bimport\s*\(/,
  /\bimport\.meta\b/,
  /\b(?:Bun|Deno)\.serve\s*\(/,
  /\bnew\s+WebSocket\s*\(/,
  /\bfetch\s*\(/,
  /\bprocess\.env\b/,
  /^\s*export\b[^;\n]*\bfrom\s*['"]/m,
]);
function parseImports(source){
  if(typeof source!=='string'||!source.length||
     UNSAFE_SOURCE.some(pattern=>pattern.test(source)))refuse();
  const start=[...source.matchAll(/^import\b/gm)].length;
  const statements=[...source.matchAll(/^import\b([^;]*);/gm)];
  if(start!==statements.length||start>MAX_IMPORTS)refuse();
  const imports=statements.map(match=>{
    const statement=match[0];
    const capture=/\bfrom\s*(['"])([^'"\r\n]+)\1\s*;$/.exec(statement);
    if(!capture)refuse(); // no bare import, dynamic import or malformed import
    return {
      kind:/^import\s+type\b/.test(statement)?'type':'value',
      specifier:capture[2],
    };
  });
  return normalizedImports(imports);
}
function folder(path){
  let st;
  try{st=lstatSync(path);}catch{refuse();}
  if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o022))refuse();
}
function contentOf(repoRoot,filename){
  if(typeof repoRoot!=='string'||!isAbsolute(repoRoot)||
     repoRoot.includes('\0'))refuse();
  folder(repoRoot);
  const parts=ROOT.split('/');
  let dir=repoRoot;
  for(const part of parts){
    dir=join(dir,part);
    folder(dir); // no symlink aliases in any source-directory component
  }
  const path=join(dir,filename);
  let fd,stat,opened,bytes;
  try{
    stat=lstatSync(path);
    if(!stat.isFile()||stat.isSymbolicLink()||
       (stat.mode&0o022)||stat.size<1||stat.size>MAX_FILE_BYTES)
      refuse();
    fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
    opened=fstatSync(fd);
    if(!opened.isFile()||opened.ino!==stat.ino||
       opened.dev!==stat.dev||opened.size!==stat.size)refuse();
    bytes=readFileSync(fd);
    if(bytes.length!==stat.size)refuse();
  }catch{refuse();}
  finally{if(fd!==undefined)try{closeSync(fd);}catch{refuse();}}
  return bytes;
}
function policyFromDisk(){
  const bytes=readFileSync(new URL(
    './backend16-native-server-source-closure.v1.json',import.meta.url));
  if(!bytes.length||bytes.length>MAX_POLICY_BYTES)refuse();
  let parsed;
  try{parsed=JSON.parse(bytes.toString('utf8'));}catch{refuse();}
  assertBackend16NativeSourceClosurePolicy(parsed);
  return parsed;
}
export function inspectBackend16NativeSourceClosure(repoRoot){
  const policy=policyFromDisk(); // NEVER accept caller- or env-supplied pins
  const evidence=[];
  let total=0;
  for(const entry of policy.modules){
    const bytes=contentOf(repoRoot,entry.file);
    total+=bytes.length;
    if(total>MAX_TOTAL_BYTES)refuse();
    // Git object SHA-1 is an exact reviewed *repository blob identifier*,
    // NOT package publisher authentication or a cryptographic release signer.
    const objectSha=createHash('sha1')
      .update('blob '+bytes.length+'\0').update(bytes).digest('hex');
    if(objectSha!==entry.gitBlobSha1)refuse();
    const observedImports=parseImports(bytes.toString('utf8'));
    if(!same(observedImports,entry.imports))refuse();
    evidence.push({
      path:ROOT+'/'+entry.file,gitBlobSha1:objectSha,bytes:bytes.length,
      sha256:createHash('sha256').update(bytes).digest('hex'),
      imports:observedImports,
    });
  }
  const receipt={
    schema:'backend16-native-source-inventory-ci-v1',
    scope:SCOPE,
    files:evidence,
    builtinDependencies:BUILTINS,
    externalPackageDependencies:[],
    serverArtifactBuilt:false,
    stableRuntimeApproved:false,
    productionAuthorized:false,
  };
  const digest=createHash('sha256')
    .update(JSON.stringify(receipt)).digest('hex');
  return Object.freeze({
    result:'B16_NATIVE_BUN_SOURCE_CLOSURE_CI_PASS',
    sourceInventorySha256:digest,
    fileCount:evidence.length,
    externalPackageCount:0,
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
       e.GITHUB_ACTIONS!=='true'||process.versions.node.split('.')[0]!=='24'||
       e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
       Object.keys(e).some(k=>k.startsWith('RAILWAY_')&&e[k]))refuse();
    const proof=inspectBackend16NativeSourceClosure(sourceRoot);
    console.info(proof.result);
    console.info('B16_NATIVE_BUN_SOURCE_CLOSURE_SHA256='+proof.sourceInventorySha256);
    console.info('B16_NATIVE_BUN_SOURCE_CLOSURE_NO_SERVER_ARTIFACT');
    console.info('NO RELEASE AUTHORIZATION');
  }catch{
    console.error('STOP Backend16 Native Bun source closure CI refused');
    process.exitCode=1;
  }
}

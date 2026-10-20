/**
 * Offline, source-only Backend16 Node24 PostgreSQL package-lock contract.
 * This does not install dependencies, connect to Railway, inspect credentials,
 * prove any security-review approval, or grant a staging/production release.
 *
 * Usage: node scripts/saas-staging/verify-backend16-nodepg-runtime-lock.mjs \
 *   <isolated-server-package.json> <isolated-server-package-lock.json> \
 *   [frontend-package.json]
 */
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

export const EXPECTED_NAME='@saas/backend16-private-reader';
export const EXPECTED_PG_VERSION='8.23.1';
const MAX_FILE_BYTES=1_000_000;
const EXACT_VERSION=/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;
const SAFE_DEP_RANGE=/^(?:[~^<>]=?|=)?\s?\d+(?:\.\d+){0,2}(?:[-+.][a-zA-Z0-9.-]+)?(?:\s*(?:\|\||[<>]=?)\s*(?:[~^<>]=?|=)?\d+(?:\.\d+){0,2}(?:[-+.][a-zA-Z0-9.-]+)?)*$/;
const INSTALL_LIFECYCLE=/^(?:preinstall|install|postinstall|prepublish|prepublishOnly|prepare|prepack|postpack)$/i;
const BANNED_PACKAGES=new Set([
  'pg-native','node-gyp','node-pre-gyp','prebuild-install',
  'bindings','node-addon-api',
]);
const VALID_PACKAGE_SEGMENT=/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;

function refuse(){throw new Error('Backend16 NodePG package pinning gate refused');}
function plainObject(x){
  if(x===null||typeof x!=='object'||Array.isArray(x))return false;
  const p=Object.getPrototypeOf(x);
  return p===Object.prototype||p===null;
}
function exactKeys(x,keys){
  return plainObject(x)&&Object.keys(x).sort().join(',')===keys.sort().join(',');
}
function packageNameFromPath(path){
  if(typeof path!=='string'||!path.startsWith('node_modules/'))refuse();
  const parts=path.split('/');
  let cursor=0;
  let lastName='';
  while(cursor<parts.length){
    if(parts[cursor++]!=='node_modules')refuse();
    let name=parts[cursor++];
    if(name?.startsWith('@'))name+='/'+parts[cursor++];
    if(!name||!VALID_PACKAGE_SEGMENT.test(name)||name==='.'||name==='..')refuse();
    lastName=name;
  }
  return lastName;
}
function auditIntegrity(integrity){
  if(typeof integrity!=='string'||!/^sha512-[A-Za-z0-9+/]{86}==$/.test(integrity))
    refuse();
  const raw=Buffer.from(integrity.slice(7),'base64');
  if(raw.length!==64||raw.toString('base64')!==integrity.slice(7))refuse();
}
function auditResolved(name,version,urlText){
  if(typeof urlText!=='string'||urlText.length>512)refuse();
  let url;
  try{url=new URL(urlText);}catch{refuse();}
  if(url.protocol!=='https:'||url.hostname!=='registry.npmjs.org'||
     url.port||url.username||url.password||url.search||url.hash)refuse();
  // Do not allow a different registry tarball name merely because its
  // suffix resembles the requested package's version.
  let pathname;
  try{pathname=decodeURIComponent(url.pathname);}catch{refuse();}
  const basename=name.split('/').at(-1);
  if(pathname!=='/'+name+'/-/'+basename+'-'+version+'.tgz')refuse();
}
function auditDeps(deps){
  if(deps===undefined)return;
  if(!plainObject(deps))refuse();
  for(const [name,version] of Object.entries(deps)){
    if(!VALID_PACKAGE_SEGMENT.test(name)||BANNED_PACKAGES.has(name)||
       typeof version!=='string'||version.length>120||!SAFE_DEP_RANGE.test(version))refuse();
  }
}
/** Every package in an approved lock must be reachable from its pinned root.
 * Required package edges may not silently resolve to a missing tarball.
 * npm ci remains separately mandatory to check semantic version satisfaction.
 */
function resolveDependency(parentPath,name,packages){
  let cursor=parentPath;
  for(;;){
    const path=(cursor?cursor+'/':'')+'node_modules/'+name;
    if(Object.hasOwn(packages,path))return path;
    if(!cursor)return null;
    const i=cursor.lastIndexOf('/node_modules/');
    cursor=i===-1?'':cursor.slice(0,i);
  }
}
function verifyDependencyClosure(packages){
  const seen=new Set(['']);
  const waiting=[''];
  while(waiting.length){
    const origin=waiting.pop();
    const metadata=packages[origin];
    for(const category of ['dependencies','optionalDependencies','peerDependencies']){
      const deps=metadata[category];
      if(deps===undefined)continue;
      if(!plainObject(deps))refuse();
      for(const name of Object.keys(deps)){
        // pg-native may be mentioned as an optional peer, but must NEVER
        // resolve to an installed native module in this JS-only candidate.
        if(!VALID_PACKAGE_SEGMENT.test(name))refuse();
        const path=resolveDependency(origin,name,packages);
        if(!path){if(category==='dependencies')refuse();continue;}
        if(!seen.has(path)){seen.add(path);waiting.push(path);}
      }
    }
  }
  if(seen.size!==Object.keys(packages).length)refuse();
}
function auditScripts(scripts){
  if(scripts===undefined)return;
  if(!plainObject(scripts))refuse();
  if(Object.keys(scripts).some(x=>INSTALL_LIFECYCLE.test(x)))refuse();
}
export function verifyBackend16NodePgRuntimePackage(pkg,lock,frontend){
  if(!plainObject(pkg)||pkg.name!==EXPECTED_NAME||pkg.private!==true||
     pkg.type!=='module'||pkg.engines?.node!=='24.x'||
     !exactKeys(pkg.dependencies,['pg'])||
     pkg.dependencies.pg!==EXPECTED_PG_VERSION||
     pkg.workspaces!==undefined||pkg.optionalDependencies!==undefined||
     pkg.peerDependencies!==undefined||pkg.overrides!==undefined||
     pkg.bundledDependencies!==undefined||pkg.bundleDependencies!==undefined)
    refuse();
  if(pkg.devDependencies!==undefined&&
     (!plainObject(pkg.devDependencies)||Object.keys(pkg.devDependencies).length!==0))
    refuse();
  auditScripts(pkg.scripts);
  if(!plainObject(lock)||lock.lockfileVersion!==3||
     lock.name!==EXPECTED_NAME||!plainObject(lock.packages)||
     !plainObject(lock.packages[''])||
     !exactKeys(lock.packages[''].dependencies,['pg'])||
     lock.packages[''].dependencies.pg!==EXPECTED_PG_VERSION||
     lock.packages[''].engines?.node!=='24.x'||
     lock.packages[''].name!==EXPECTED_NAME||
     lock.packages[''].version!==pkg.version||
     typeof pkg.version!=='string'||!EXACT_VERSION.test(pkg.version))
    refuse();
  const installed=Object.entries(lock.packages).filter(([p])=>p!=='');
  if(installed.length===0||installed.length>100)refuse();
  const pg=lock.packages['node_modules/pg'];
  if(!plainObject(pg)||pg.version!==EXPECTED_PG_VERSION)refuse();
  for(const [path,item] of installed){
    const name=packageNameFromPath(path);
    if(BANNED_PACKAGES.has(name)||!plainObject(item)||
       typeof item.version!=='string'||!EXACT_VERSION.test(item.version)||
       (item.link!==undefined&&item.link!==false)||
       (item.inBundle!==undefined&&item.inBundle!==false)||
       (item.hasInstallScript!==undefined&&item.hasInstallScript!==false))
      refuse();
    auditResolved(name,item.version,item.resolved);
    auditIntegrity(item.integrity);
    auditDeps(item.dependencies);
    auditDeps(item.optionalDependencies);
  }
  verifyDependencyClosure(lock.packages);
  if(frontend!==undefined){
    if(!plainObject(frontend))refuse();
    for(const key of ['dependencies','devDependencies','optionalDependencies']){
      if(frontend[key]!==undefined){
        if(!plainObject(frontend[key]))refuse();
        if(Object.keys(frontend[key]).some(name=>name==='pg'||
          name==='pg-native'||name.startsWith('@saas/backend16-private-reader')))
          refuse();
      }
    }
  }
  return Object.freeze({
    status:'PACKAGE_LOCK_CONTRACT_PASS_NOT_RELEASE_APPROVAL',
    runtime:'node24',
    dependency:'pg@'+EXPECTED_PG_VERSION,
    packageCount:installed.length,
  });
}
function parseLimited(path){
  let bytes;
  try{bytes=readFileSync(path);}catch{refuse();}
  if(bytes.length>MAX_FILE_BYTES||bytes.length===0)refuse();
  try{return JSON.parse(bytes.toString('utf8'));}catch{refuse();}
}
function main(argv){
  if(argv.length<2||argv.length>3)refuse();
  const [pkg,lock,frontend]=argv.map(p=>parseLimited(resolve(p)));
  const receipt=verifyBackend16NodePgRuntimePackage(pkg,lock,frontend);
  // Print strictly static labels and a package count, never package contents.
  console.log('PASS Backend16 NodePG runtime lock contract: '+receipt.dependency+
    ' ('+receipt.packageCount+' pinned packages); NO RELEASE AUTHORIZATION');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{main(process.argv.slice(2));}
  catch{console.error('STOP Backend16 NodePG runtime lock contract refused');process.exitCode=1;}
}

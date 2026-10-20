import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {
  EXPECTED_NAME, EXPECTED_PG_VERSION, verifyBackend16NodePgRuntimePackage,
} from '../scripts/saas-staging/verify-backend16-nodepg-runtime-lock.mjs';
const integrity='sha512-'+'A'.repeat(86)+'==';
const pgUrl='https://registry.npmjs.org/pg/-/pg-'+EXPECTED_PG_VERSION+'.tgz';
const pkg=()=>({
  name:EXPECTED_NAME,version:'0.0.0',private:true,type:'module',
  engines:{node:'24.x'},dependencies:{pg:EXPECTED_PG_VERSION},
});
const lock=()=>({
  name:EXPECTED_NAME,version:'0.0.0',lockfileVersion:3,
  packages:{
    '':{name:EXPECTED_NAME,version:'0.0.0',engines:{node:'24.x'},dependencies:{pg:EXPECTED_PG_VERSION}},
    'node_modules/pg':{version:EXPECTED_PG_VERSION,resolved:pgUrl,integrity},
  },
});
const frontend=()=>({dependencies:{react:'19.2.7'}});
const refuse=(fn)=>assert.throws(fn,/Backend16 NodePG package pinning gate refused/);

test('isolated Node24 direct pg dependency is exact, no release authority',()=>{
  const result=verifyBackend16NodePgRuntimePackage(pkg(),lock(),frontend());
  assert.equal(result.status,'PACKAGE_LOCK_CONTRACT_PASS_NOT_RELEASE_APPROVAL');
  assert.equal(result.dependency,'pg@8.23.1');
  assert.equal(result.packageCount,1);
  assert.ok(Object.isFrozen(result));
});
test('pin mismatch, floating package dependency and lock drift fail closed',()=>{
  for(const deps of [{pg:'^8.23.1'},{pg:'latest'},{pg:'8.23.2'},
    {pg:'8.23.1',axios:'1.0.0'},{}]){
    refuse(()=>verifyBackend16NodePgRuntimePackage({...pkg(),dependencies:deps},lock()));
  }
  const wrong=lock();wrong.packages['node_modules/pg'].version='8.23.2';
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),wrong));
  const wrongRoot=lock();wrongRoot.packages[''].dependencies.pg='^8.23.1';
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),wrongRoot));
});
test('transitive sources and integrity must be pinned to npm HTTPS',()=>{
  for(const bad of [
    'http://registry.npmjs.org/pg/-/pg-8.23.1.tgz',
    'https://example.com/pg/-/pg-8.23.1.tgz',
    'https://registry.npmjs.org:444/pg/-/pg-8.23.1.tgz',
    'https://evil@registry.npmjs.org/pg/-/pg-8.23.1.tgz',
    'https://registry.npmjs.org/pg/-/pg-8.23.1.tgz#sneaky',
    'file:///tmp/pg-8.23.1.tgz',
  ]){
    const l=lock();l.packages['node_modules/pg'].resolved=bad;
    refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),l));
  }
  for(const bad of [null,'sha1-'+'A'.repeat(86)+'==','sha512-AAA']){
    const l=lock();l.packages['node_modules/pg'].integrity=bad;
    refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),l));
  }
});
test('lifecycle scripts, native addons and unreviewed package edges deny',()=>{
  const packageWithHook={...pkg(),scripts:{postinstall:'curl example.invalid'}};
  refuse(()=>verifyBackend16NodePgRuntimePackage(packageWithHook,lock()));
  const l=lock();l.packages['node_modules/pg'].hasInstallScript=true;
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),l));
  const ambiguous=lock();ambiguous.packages['node_modules/pg'].hasInstallScript='true';
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),ambiguous));
  const l2=lock();l2.packages['node_modules/pg-native']={
    version:'1.0.0',resolved:'https://registry.npmjs.org/pg-native/-/pg-native-1.0.0.tgz',integrity,
  };
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),l2));
  const l3=lock();l3.packages['node_modules/pg'].dependencies={'pg-native':'1.0.0'};
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),l3));
});
test('realistic transitive caret ranges require locked reachable tarballs',()=>{
  const l=lock();
  l.packages['node_modules/pg'].dependencies={'pg-protocol':'^1.9.0'};
  l.packages['node_modules/pg-protocol']={
    version:'1.9.0',
    resolved:'https://registry.npmjs.org/pg-protocol/-/pg-protocol-1.9.0.tgz',
    integrity,
  };
  const checked=verifyBackend16NodePgRuntimePackage(pkg(),l);
  assert.equal(checked.packageCount,2);
  const missing=lock();
  missing.packages['node_modules/pg'].dependencies={'pg-protocol':'^1.9.0'};
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),missing));
  const unused=lock();
  unused.packages['node_modules/other']={
    version:'1.0.0',resolved:'https://registry.npmjs.org/other/-/other-1.0.0.tgz',integrity,
  };
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),unused));
  const mismatched=lock();
  mismatched.packages['node_modules/pg'].resolved=
    'https://registry.npmjs.org/another/-/pg-8.23.1.tgz';
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),mismatched));
});
test('actual repository frontend manifest excludes server-only pg dependency',()=>{
  const realFrontend=JSON.parse(readFileSync(
    new URL('../package.json',import.meta.url),'utf8'));
  assert.equal(verifyBackend16NodePgRuntimePackage(
    pkg(),lock(),realFrontend).status,'PACKAGE_LOCK_CONTRACT_PASS_NOT_RELEASE_APPROVAL');
});

test('frontend must not accidentally absorb server database package',()=>{
  for(const key of ['dependencies','devDependencies','optionalDependencies']){
    const f={...frontend(),[key]:{pg:'8.23.1'}};
    refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),lock(),f));
  }
});
test('wrong Node/lock format, untrusted lock paths and not-private deny',()=>{
  refuse(()=>verifyBackend16NodePgRuntimePackage({...pkg(),private:false},lock()));
  refuse(()=>verifyBackend16NodePgRuntimePackage({...pkg(),engines:{node:'22.x'}},lock()));
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),{...lock(),lockfileVersion:2}));
  const l=lock();l.packages['node_modules/../../tmp/evil']={
    version:'1.0.0',resolved:'https://registry.npmjs.org/evil/-/evil-1.0.0.tgz',integrity,
  };
  refuse(()=>verifyBackend16NodePgRuntimePackage(pkg(),l));
});
test('CLI fails cleanly for a missing lock, succeeds on synthetic schema only',()=>{
  const dir=mkdtempSync(join(tmpdir(),'b16-pg-lock-contract-'));
  const script=resolve('scripts/saas-staging/verify-backend16-nodepg-runtime-lock.mjs');
  try{
    const a=join(dir,'package.json'),b=join(dir,'package-lock.json');
    writeFileSync(a,JSON.stringify(pkg()));
    let run=spawnSync(process.execPath,[script,a,b],{encoding:'utf8'});
    assert.equal(run.status,1);
    assert.match(run.stderr,/STOP Backend16 NodePG runtime lock contract refused/);
    assert.doesNotMatch(run.stderr,/ENOENT|\/tmp\//);
    writeFileSync(b,JSON.stringify(lock()));
    run=spawnSync(process.execPath,[script,a,b],{encoding:'utf8'});
    assert.equal(run.status,0);
    assert.match(run.stdout,/NO RELEASE AUTHORIZATION/);
  }finally{rmSync(dir,{recursive:true,force:true});}
});

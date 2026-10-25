import assert from 'node:assert/strict';
import test from 'node:test';
import {
  chmodSync,linkSync,mkdtempSync,mkdirSync,readFileSync,rmSync,symlinkSync,writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  assertTransportPackageInputs,compareTransportBuildReceipts,
  inspectTransportBuildGraph,readTransportPackageFile,sha256,transportChildEnvironment,
} from '../scripts/saas-staging/verify-backend16-native-transport-package-ci.mjs';

const pkg=new URL('../scripts/saas-staging/backend16-native-transport-package-ci/',import.meta.url);
const manifest=readFileSync(new URL('package.json',pkg));
const lock=readFileSync(new URL('bun.lock',pkg));
const mutate=(bytes,f)=>{const value=JSON.parse(bytes);f(value);return Buffer.from(JSON.stringify(value));};
const temporary=fn=>{
  const dir=mkdtempSync(join(tmpdir(),'b16-package-test-'));
  try{fn(dir);}finally{rmSync(dir,{recursive:true,force:true});}
};

test('isolated private zero-dependency manifest and real Bun text lock have exact review pins',()=>{
  assert.equal(assertTransportPackageInputs(manifest,lock),true);
  const m=JSON.parse(manifest),l=JSON.parse(lock);
  assert.equal(m.private,true);assert.equal(m.packageManager,'bun@1.4.4');
  assert.deepEqual(m.dependencies,{});assert.deepEqual(l.packages,{});
  assert.deepEqual(Object.keys(l.workspaces),['']);
});
test('package injection, lifecycle hooks, workspaces and dependency fallback are rejected',()=>{
  for(const [key,value] of Object.entries({
    dependencies:{pg:'8.16.3'},devDependencies:{react:'19.2.0'},
    optionalDependencies:{vite:'7.0.0'},peerDependencies:{pg:'*'},
    scripts:{preinstall:'touch sentinel'},trustedDependencies:['pg'],workspaces:['../*'],
    overrides:{pg:'*'},resolutions:{pg:'*'},private:false,packageManager:'bun@latest',
  }))assert.throws(()=>assertTransportPackageInputs(mutate(manifest,m=>m[key]=value),lock));
});
test('lock omission, foreign package/workspace, duplicate keys and hidden string whitespace deny',()=>{
  for(const bad of [Buffer.alloc(0),Buffer.from('{}'),
    mutate(lock,x=>x.packages.pg=['pg@8.16.3','',{},'sha512-fake']),
    mutate(lock,x=>x.workspaces.other={name:'other'}),
    Buffer.from(lock.toString().replace('"packages": {}','"packages": {},"packages": {}')),
  ])assert.throws(()=>assertTransportPackageInputs(manifest,bad));
  assert.throws(()=>assertTransportPackageInputs(Buffer.from(manifest.toString()
    .replace('backend16-native','back end16-native')),lock));
  assert.throws(()=>assertTransportPackageInputs(Buffer.from(manifest.toString()
    .replace('"private": true','"private": false,"private": true')),lock));
});
test('child environment is allowlisted, independent, and cannot inherit credentials or loaders',()=>{
  const env=transportChildEnvironment('/tmp/build-a','net:[123]');
  for(const key of ['PGPASSWORD','DATABASE_URL','RAILWAY_PROJECT_ID','GITHUB_TOKEN',
    'NODE_OPTIONS','BUN_OPTIONS','NODE_PATH','LD_PRELOAD','HTTPS_PROXY'])assert.equal(env[key],undefined);
  assert.equal(env.HOME,'/tmp/build-a/home');assert.equal(env.PATH,'/usr/bin:/bin');
  assert.equal(Object.isFrozen(env),true);
  assert.notEqual(transportChildEnvironment('/tmp/build-b','net:[123]').HOME,env.HOME);
  for(const dir of ['relative','/tmp/x/../a','/tmp/a\0b'])
    assert.throws(()=>transportChildEnvironment(dir,'net:[123]'));
  assert.throws(()=>transportChildEnvironment('/tmp/a','forged'));
});
test('metadata/source reader denies aliases, writable files, missing and oversized input',()=>temporary(dir=>{
  const file=join(dir,'file');writeFileSync(file,'ok',{mode:0o600});
  assert.equal(readTransportPackageFile(file).toString(),'ok');
  assert.throws(()=>readTransportPackageFile(file,1));
  const link=join(dir,'symlink');symlinkSync(file,link);
  assert.throws(()=>readTransportPackageFile(link));
  const hard=join(dir,'hard');linkSync(file,hard);
  assert.throws(()=>readTransportPackageFile(hard));rmSync(hard);
  chmodSync(file,0o666);assert.throws(()=>readTransportPackageFile(file));
  assert.throws(()=>readTransportPackageFile(join(dir,'absent')));
}));

function graphFixture(dir){
  for(const file of ['index.ts','source.ts'])writeFileSync(join(dir,file),'x',{mode:0o600});
  mkdirSync(join(dir,'dist'));writeFileSync(join(dir,'dist/transport.mjs'),'y',{mode:0o600});
  return {inputs:{'index.ts':{bytes:1,imports:[{path:'source.ts',kind:'import-statement'}]},
    'source.ts':{bytes:1,imports:['node:crypto','node:https','node:tls'].map(path=>
      ({path,kind:'import-statement',external:true}))}},
  outputs:{'dist/transport.mjs':{bytes:1,entryPoint:'index.ts',inputs:{'source.ts':{bytesInOutput:1}},
    imports:['node:crypto','node:https','node:tls'].map(path=>
      ({path,kind:'import-statement',external:true})),exports:[]}}};
}
test('emitted import graph accepts only copied source and the three reviewed builtins',()=>temporary(dir=>{
  const graph=graphFixture(dir);
  assert.match(inspectTransportBuildGraph(graph,dir,['source.ts']),/^[a-f0-9]{64}$/);
  for(const edit of [
    x=>x.inputs['node_modules/pg/index.js']={bytes:1,imports:[]},
    x=>delete x.inputs['source.ts'],
    x=>x.inputs['source.ts'].bytes=2,
    x=>x.inputs['source.ts'].imports.push({path:'pg',kind:'import-statement',external:true}),
    x=>x.inputs['source.ts'].imports.push({path:'../escape.ts',kind:'import-statement'}),
    x=>x.inputs['source.ts'].imports[0].kind='dynamic-import',
    x=>x.inputs['source.ts'].imports[0].kind='require-call',
    x=>x.outputs['dist/transport.mjs'].entryPoint='../index.ts',
    x=>x.outputs['dist/transport.mjs'].bytes=99,
    x=>x.outputs['dist/extra.js']={},
  ]){
    const changed=structuredClone(graph);edit(changed);
    assert.throws(()=>inspectTransportBuildGraph(changed,dir,['source.ts']));
  }
}));
test('two cold build receipts require identical bytes and exact source inventory, never approval',()=>{
  const a={bundleSha256:sha256('bundle'),graphSha256:sha256('graph'),
    lockSha256:sha256(lock),manifestSha256:sha256(manifest),recipeSha256:sha256('recipe'),
    sourceInventorySha256:'9a0e30c78d1c2d07ee3b4695cdfa1d570f5c8f0e2f75f2371b010a8edad5687c'};
  assert.equal(compareTransportBuildReceipts(a,{...a}),true);
  for(const key of Object.keys(a))assert.throws(()=>compareTransportBuildReceipts(a,
    {...a,[key]:sha256('other')}));
  assert.throws(()=>compareTransportBuildReceipts({...a,productionAuthorized:true},a));
  assert.throws(()=>compareTransportBuildReceipts({...a,bundleSha256:'0'.repeat(64)},a));
});
test('recipe uses pinned runtime, fresh non-root network namespace and emitted-only smoke',()=>{
  const code=readFileSync(new URL('../scripts/saas-staging/verify-backend16-native-transport-package-ci.mjs',import.meta.url),'utf8');
  for(const text of ['verifyBackend16OfficialStable144Archive','unzip',"'--net'","'--clear-groups'",
    "'/usr/bin/env','-i'","'--frozen-lockfile','--ignore-scripts','--dry-run'",
    "['--no-install','build.mjs']","['--no-install','smoke.mjs']",
    'rmSync(dir,{recursive:true})','compareTransportBuildReceipts(...results)',
    'serverArtifactBuilt:false','productionAuthorized:false'])assert.ok(code.includes(text),text);
  const build=readFileSync(new URL('build.mjs',pkg),'utf8');
  assert.ok(build.includes("env:'disable',plugins:[],metafile:true"));
  const smoke=readFileSync(new URL('smoke.mjs',pkg),'utf8');
  assert.ok(smoke.includes("from './transport.mjs'"));
  assert.ok(smoke.includes('createBackend16StagingBunPhysicalPgPool'));
  assert.ok(!smoke.includes("from './src/"));
});
test('new paths trigger stable/canary/source CI; all previous workflow commands stay byte-identical',async()=>{
  const {createHash}=await import('node:crypto');
  const additions=[
    'scripts/saas-staging/backend16-native-transport-package-ci/**',
    'scripts/saas-staging/verify-backend16-native-transport-package-ci.mjs',
    'tests/saasBackend16NativeTransportPackageCi.test.mjs',
    'docs/saas/BACKEND_16_P2_NATIVE_TRANSPORT_PACKAGE_CI.md',
  ];
  for(const [name,pin] of [
    ['saas-backend16-stable-144-tls-ci.yml','7976fd4a64a0023828158124d4f3dc66207ad0d5'],
    ['saas-backend16-native-source-repro-ci.yml','d53da232cd7157922c3580760473c05f499eacb8'],
    ['saas-backend16-native-tls-experiment.yml','4c59282654812dfc5bb8a751a3d400bcae304c6b'],
  ]){
    let text=readFileSync(new URL('../.github/workflows/'+name,import.meta.url),'utf8');
    const paths=[...text.matchAll(/^      - '([^']+)'$/gm)].map(x=>x[1]);
    assert.equal(new Set(paths).size,paths.length);
    for(const path of additions){
      assert.ok(paths.includes(path));text=text.replace("      - '"+path+"'\n",'');
    }
    if(name.includes('stable-144')){
      for(const path of ['scripts/saas-staging/backend16-native-server-source-closure.v1.json',
        'scripts/saas-staging/verify-backend16-native-source-closure-ci.mjs']){
        assert.ok(paths.includes(path));text=text.replace("      - '"+path+"'\n",'');
      }
      assert.ok(text.includes('node --test tests/saasBackend16NativeTransportPackageCi.test.mjs'));
      assert.ok(text.includes('node scripts/saas-staging/verify-backend16-native-transport-package-ci.mjs'));
      text=text.split('      - name: P2 isolated transport package - two offline builds, never server release\n')[0];
    }
    assert.equal(createHash('sha1').update('blob '+Buffer.byteLength(text)+'\0')
      .update(text).digest('hex'),pin);
  }
});

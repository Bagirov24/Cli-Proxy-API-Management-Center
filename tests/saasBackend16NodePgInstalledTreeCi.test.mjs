import test from 'node:test';
import assert from 'node:assert/strict';
import {chmodSync,mkdirSync,mkdtempSync,readFileSync,rmSync,
  symlinkSync,truncateSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  inspectBackend16NodePgInstalledTree,
  assertMatchingBackend16NodePgInstalledTrees,
} from '../scripts/saas-staging/verify-backend16-nodepg-installed-tree-ci.mjs';

const denied=fn=>assert.throws(fn,/Backend16 installed NodePG tree CI refused/);
function fixture(run){
  const scratch=mkdtempSync(join(tmpdir(),'b16-nodepg-file-tree-unit-'));
  const a=join(scratch,'independent-a','node_modules');
  const b=join(scratch,'independent-b','node_modules');
  try{
    for(const root of [a,b]){
      mkdirSync(join(root,'pg','lib'),{recursive:true});
      mkdirSync(join(root,'pg-protocol'),{recursive:true});
      writeFileSync(join(root,'pg','package.json'),
        JSON.stringify({name:'pg',version:'8.23.1'}));
      writeFileSync(join(root,'pg','lib','client.js'),
        'export const peer = true;\n');
      writeFileSync(join(root,'pg-protocol','package.json'),
        JSON.stringify({name:'pg-protocol',version:'1.9.0'}));
    }
    run(a,b);
  }finally{rmSync(scratch,{recursive:true,force:true});}
}

test('independent installs compare installed bytes rather than lock metadata',()=>{
  fixture((a,b)=>{
    const first=inspectBackend16NodePgInstalledTree(a);
    const second=inspectBackend16NodePgInstalledTree(b);
    assert.notEqual(first,second);
    assert.equal(first.format,'backend16-nodepg-install-tree-sha256-v1');
    assert.equal(first.fileCount,3);
    assert.equal(first.totalBytes,second.totalBytes);
    assert.match(first.digest,/^[a-f0-9]{64}$/);
    assert.equal(first.digest,second.digest);
    assert.ok(Object.isFrozen(first)&&Object.isFrozen(second));
    assert.equal(assertMatchingBackend16NodePgInstalledTrees(first,second),
      'B16_NODEPG_FROZEN_TREE_INDEPENDENT_MATCH_PASS');
  });
});

test('mutated installed code or added post-install file cannot reuse approval',()=>{
  fixture((a,b)=>{
    const verified=inspectBackend16NodePgInstalledTree(a);
    const clean=inspectBackend16NodePgInstalledTree(b);
    writeFileSync(join(b,'pg','lib','client.js'),
      'export const peer = false;\n');
    const corrupted=inspectBackend16NodePgInstalledTree(b);
    assert.notEqual(corrupted.digest,clean.digest);
    denied(()=>assertMatchingBackend16NodePgInstalledTrees(verified,corrupted));
    writeFileSync(join(b,'pg','lib','unreviewed.js'),'side effect');
    const extra=inspectBackend16NodePgInstalledTree(b);
    denied(()=>assertMatchingBackend16NodePgInstalledTrees(verified,extra));
  });
});

test('symlinks and native addons inside node_modules are refused',()=>{
  fixture((a,b)=>{
    symlinkSync('package.json',join(a,'pg','alien.js'));
    denied(()=>inspectBackend16NodePgInstalledTree(a));
    writeFileSync(join(b,'pg','native.node'),'binary');
    denied(()=>inspectBackend16NodePgInstalledTree(b));
  });
});

test('malformed node_modules root and world-writable files refuse',()=>{
  fixture((a,b)=>{
    denied(()=>inspectBackend16NodePgInstalledTree(join(a,'pg')));
    denied(()=>inspectBackend16NodePgInstalledTree('node_modules'));
    chmodSync(join(b,'pg','lib','client.js'),0o666);
    denied(()=>inspectBackend16NodePgInstalledTree(b));
  });
});

test('oversized files and deep directory trees fail without reading their content',()=>{
  fixture((a,b)=>{
    truncateSync(join(a,'pg','lib','client.js'),24_000_001);
    denied(()=>inspectBackend16NodePgInstalledTree(a));
    let cursor=join(b,'pg');
    for(let i=0;i<21;i++){
      cursor=join(cursor,'d'+i);
      mkdirSync(cursor);
    }
    denied(()=>inspectBackend16NodePgInstalledTree(b));
  });
});

test('tree receipt mismatches, forged schema and reused proof fail closed',()=>{
  fixture((a,b)=>{
    const first=inspectBackend16NodePgInstalledTree(a);
    const second=inspectBackend16NodePgInstalledTree(b);
    denied(()=>assertMatchingBackend16NodePgInstalledTrees(first,first));
    denied(()=>assertMatchingBackend16NodePgInstalledTrees(
      first,{...second,digest:'0'.repeat(64)}));
    denied(()=>assertMatchingBackend16NodePgInstalledTrees(
      first,{...second,format:'other'}));
    denied(()=>assertMatchingBackend16NodePgInstalledTrees(
      first,{...second,fileCount:NaN}));
    denied(()=>assertMatchingBackend16NodePgInstalledTrees(null,second));
  });
});

test('byte-tree proof runs after TWO authentic npm ci and before all PG16 E2E',()=>{
  const gate=readFileSync(new URL(
    '../scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs',
    import.meta.url),'utf8');
  const compare=gate.indexOf('assertMatchingBackend16NodePgInstalledTrees(');
  const frozen=gate.indexOf("console.info('B16_REAL_LOCK_CI_FROZEN_INSTALL_PASS')");
  const physical=gate.indexOf("if(process.env.SAAS_B16_LOCKED_PG16_CI!==undefined)");
  const full=gate.indexOf("if(process.env.SAAS_B16_LOCKED_FULL_CHAIN_CI!==undefined)");
  assert.ok(compare>0&&frozen>0&&physical>0&&full>0);
  assert.ok(gate.indexOf('for(const {dir,lockFile,digest} of receipts)')<
    compare);
  assert.ok(compare<frozen&&frozen<physical&&physical<full);
  assert.ok(gate.includes('receipts.map(r=>r.dir)'));
  assert.ok(gate.includes('B16_NODEPG_FROZEN_TREE_INDEPENDENT_MATCH_PASS'));
  assert.doesNotMatch(gate,/NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=true/);
});

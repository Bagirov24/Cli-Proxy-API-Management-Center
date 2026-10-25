/** Runs only inside a newly materialized, zero-package, network-isolated CI directory. */
import assert from 'node:assert/strict';
import {readlinkSync,readFileSync,writeFileSync} from 'node:fs';

assert.equal(process.env.B16_TRANSPORT_PACKAGE_CI,'true');
assert.equal(process.getuid()===0,false);
assert.equal(Bun.version,'1.4.4');
assert.equal(Bun.revision,'38afee6c84fcf48c0edb2466aa4b27d287a59c30');
assert.notEqual(readlinkSync('/proc/self/ns/net'),process.env.B16_PARENT_NETWORK_NS);
const interfaces=readFileSync('/proc/net/dev','utf8').split('\n').slice(2)
  .filter(line=>line.trim()).map(line=>line.split(':')[0].trim());
assert.deepEqual(interfaces,['lo']);
assert.equal(Object.keys(process.env).some(k=>
  /^(?:PG|RAILWAY_|NODE_OPTIONS$|BUN_OPTIONS$|DATABASE_URL$|GITHUB_TOKEN$)/.test(k)),false);

const result=await Bun.build({
  entrypoints:['./index.ts'],root:'.',outdir:'./dist',
  naming:'transport.mjs',target:'bun',format:'esm',
  splitting:false,sourcemap:'none',minify:false,
  env:'disable',plugins:[],metafile:true,
});
assert.equal(result.success,true);
assert.equal(result.logs.length,0);
assert.equal(result.outputs.length,1);
assert.equal(result.outputs[0].kind,'entry-point');
assert.ok(result.metafile);
writeFileSync('dist/graph.json',JSON.stringify(result.metafile)+'\n',{flag:'wx',mode:0o600});
console.info('B16_TRANSPORT_PACKAGE_OFFLINE_BUILD_PASS');

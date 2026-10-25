/** Only the emitted ESM is available here: no source tree, manifest, lock or node_modules. */
import assert from 'node:assert/strict';
import {readlinkSync,readFileSync} from 'node:fs';
import * as transport from './transport.mjs';

assert.equal(process.env.B16_TRANSPORT_PACKAGE_CI,'true');
assert.equal(process.getuid()===0,false);
assert.equal(Bun.version,'1.4.4');
assert.equal(Bun.revision,'38afee6c84fcf48c0edb2466aa4b27d287a59c30');
assert.notEqual(readlinkSync('/proc/self/ns/net'),process.env.B16_PARENT_NETWORK_NS);
const interfaces=readFileSync('/proc/net/dev','utf8').split('\n').slice(2)
  .filter(line=>line.trim()).map(line=>line.split(':')[0].trim());
assert.deepEqual(interfaces,['lo']);
assert.deepEqual(Object.keys(transport).sort(),[
  'exactSqlRead','physicalAdmission','physicalPool','privateRead','productionAuthorized',
  'releaseState','secretReader','serverArtifactBuilt','stableRuntimeApproved',
  'stagingAuthorized','tlsTrust','versionedVault',
].sort());
assert.equal(transport.releaseState,'BLOCKED_RELEASE');
for(const key of ['serverArtifactBuilt','stableRuntimeApproved',
  'stagingAuthorized','productionAuthorized'])assert.equal(transport[key],false);
for(const key of ['exactSqlRead','physicalAdmission','physicalPool','privateRead',
  'secretReader','tlsTrust','versionedVault'])assert.equal(typeof transport[key],'object');

// Exercise emitted functions, not strings/markers or source imports. No DB/vault connection.
assert.throws(()=>transport.exactSqlRead.createBackend16ExactSqlReadPort({}),
  /Backend16 exact PG read configuration refused/);
let acquired=0;
const read=transport.exactSqlRead.createBackend16ExactSqlReadPort({
  expectedDatabase:'saas_staging_ci',
  pool:{acquirePrincipal:async()=>{acquired++;throw Error('must not acquire');},quarantine(){}},
});
assert.deepEqual(await read(null,'invalid',new AbortController().signal),{kind:'denied'});
assert.equal(acquired,0);
const sequence=transport.physicalPool.createBackend16StagingSqlSequence();
assert.throws(()=>sequence.check('COMMIT',[]),/Backend16 staging SQL protocol refused/);
const sql=transport.exactSqlRead.BACKEND16_EXACT_READ_SQL;
sequence.check(sql.begin,[]);
sequence.completed(sql.begin,[]);
assert.throws(()=>sequence.check(sql.begin,[]),/Backend16 staging SQL protocol refused/);
assert.equal(sequence.finished(),false);

// Even forged live-looking flags cannot turn this library into an approved runtime.
Object.assign(process.env,{
  RAILWAY_PROJECT_ID:'a9703851-6eb1-406c-bb15-7d3a89359fb7',
  RAILWAY_ENVIRONMENT_ID:'b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b',
  RAILWAY_SERVICE_ID:'a0ff5420-95e8-4fab-88f6-623f75dd03c6',
  RAILWAY_ENVIRONMENT_NAME:'staging',
  SAAS_B16_STAGING_0008_INDEPENDENT_READBACK:'true',
  SAAS_B16_STAGING_PRIVATE_ONLY:'true',
});
assert.throws(()=>transport.physicalPool.createBackend16StagingBunPhysicalPgPool(
  {readPrincipal:async()=>{throw Error('must not resolve');}},{}
),/Backend16 staging driver release gates not met/);
console.info('B16_TRANSPORT_PACKAGE_EMITTED_FAIL_CLOSED_SMOKE_PASS');

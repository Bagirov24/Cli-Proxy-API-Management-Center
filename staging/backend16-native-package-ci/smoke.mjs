/** Run only against the emitted bundle, never against the source entrypoint. */
import assert from 'node:assert/strict';
import {releaseState, transport} from './dist/transport.js';

assert.equal(releaseState, 'BLOCKED_RELEASE');
assert.equal(Object.isFrozen(transport), true);
assert.deepEqual(Object.keys(transport).sort(), [
  'admission', 'exactRead', 'physicalPool', 'privateRead',
  'secretReader', 'tlsTrust', 'vault',
]);
for (const module of Object.values(transport)) {
  assert.ok(Object.values(module).some(value => typeof value === 'function'));
}
assert.equal(typeof transport.exactRead.createBackend16ExactSqlReadPort, 'function');
assert.equal(transport.exactRead.BACKEND16_EXACT_READ_SQL.commit, 'COMMIT');
let credentialReads = 0;
const forbiddenVault = {
  async readPrincipal() {
    credentialReads++;
    throw new Error('Credential resolution must not occur in a packaging smoke test');
  },
};
assert.throws(
  () => transport.physicalPool.createBackend16StagingBunPhysicalPgPool(forbiddenVault, null),
  {message: 'Backend16 staging driver release gates not met'},
);
assert.equal(credentialReads, 0);
console.info('B16_NATIVE_PACKAGE_BUNDLE_IMPORT_AND_DEFAULT_DENIAL_PASS');

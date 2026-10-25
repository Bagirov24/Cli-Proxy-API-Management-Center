/** Pure guards for the isolated, UNAPPROVED Native transport library build. */
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {
  closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync,
} from 'node:fs';
import {isAbsolute, join, relative, resolve, sep} from 'node:path';

export const BASE_HEAD = '3b82a99e2798e2d0b05cbd3f70bef815ab01ea1a';
export const SOURCE_ROOT = 'src/features/saasBlueprint/controlApi/server';
export const PACKAGE_ROOT = 'staging/backend16-native-package-ci';
export const SOURCE_INVENTORY_SHA256 =
  '9a0e30c78d1c2d07ee3b4695cdfa1d570f5c8f0e2f75f2371b010a8edad5687c';
export const PACKAGE_NAME = 'backend16-native-transport-ci-only';
export const CANDIDATE_REVISION = '38afee6c84fcf48c0edb2466aa4b27d287a59c30';
export const MODULE_PINS = Object.freeze([
  ['backend16ExactSessionSqlRead.ts', '8edd2bbb331f264536ce65824c1b61dd9f502b4e'],
  ['backend16PhysicalPgAdmission.ts', 'af73b78f3fcc6c31881a39049f01d0ef6d446bec'],
  ['backend16PrivateMtlsVersionedSecretReader.ts', '12f6e69423aed3d3f86e0ecbee17bdc26bb16352'],
  ['backend16PrivateTenantProjectRead.ts', '096f4490efc9985f583b26f13ed708605365dc56'],
  ['backend16StagingBunPhysicalPgPool.ts', 'd0e05e0b814e040991ba131eb982df4eb70b6948'],
  ['backend16StagingPgTlsTrust.ts', '4e2a60f4365e5d6020bd9196b7fb46343353c566'],
  ['backend16StagingVersionedPrincipalVault.ts', '9281864cbdabfe5e0809d923c25716715ffc0d96'],
].map(entry => Object.freeze(entry)));
export const TEMPLATE_FILES = Object.freeze(['package.json', 'transport-inputs.lock.json', 'index.ts', 'smoke.mjs']);
const EXPECTED_MANIFEST = {
  name: PACKAGE_NAME, version: '0.0.0-ci-only', private: true, type: 'module',
  packageManager: 'bun@1.4.4', engines: {bun: '1.4.4'},
  dependencies: {}, devDependencies: {}, optionalDependencies: {}, peerDependencies: {},
  trustedDependencies: [],
};
const EXPECTED_INPUT_LOCK = {
  schema: 'backend16-native-transport-input-lock-v1',
  scope: 'SOURCE_INPUTS_ONLY_NOT_A_PACKAGE_MANAGER_LOCK',
  sourceInventorySha256: SOURCE_INVENTORY_SHA256,
  modules: MODULE_PINS.map(([file, gitBlobSha1]) => ({file, gitBlobSha1})),
  allowedBuiltins: ['node:crypto', 'node:https', 'node:tls'],
  externalPackageDependencies: [],
  packageManagerLockVerified: false,
  serverEntrypointBuilt: false,
  releaseState: 'BLOCKED_RELEASE',
};
const HEX40 = /^[a-f0-9]{40}$/;
const HEX64 = /^[a-f0-9]{64}$/;
export const refuse = () => { throw new Error('Backend16 isolated package CI refused'); };
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const gitBlob = bytes => createHash('sha1')
  .update('blob ' + bytes.length + '\0').update(bytes).digest('hex');

function plain(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).some(key => typeof key !== 'string') ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !('value' in d))) {
    refuse();
  }
}
function exact(value, expected) {
  plain(value);
  if (!isDeepStrictEqual(value, expected)) refuse();
}
export function assertPackageManifest(value) {
  exact(value, EXPECTED_MANIFEST);
  return true;
}
export function assertSourceInputLock(value) {
  exact(value, EXPECTED_INPUT_LOCK);
  return true;
}

/** Fixed checked-in JSON shapes, not a general-purpose JSON parser. Compare
 * tokens before parsing so duplicate keys, comments and escapes cannot hide
 * changes. These locks describe source inputs only, NOT Bun dependencies. */
function parseFixedJson(text, expected) {
  if (typeof text !== 'string' || text.length > 8192) refuse();
  const token = /"[^"\\\r\n]*"|[{}\[\]:,]|[0-9]+|true|false|null/g;
  const tokens = text.match(token) ?? [];
  if (/\S/.test(text.replace(token, '')) ||
      tokens.join('') !== JSON.stringify(expected)) refuse();
  return JSON.parse(tokens.join(''));
}
export function parsePackageManifest(text) {
  return parseFixedJson(text, EXPECTED_MANIFEST);
}
export function parseSourceInputLock(text) {
  return parseFixedJson(text, EXPECTED_INPUT_LOCK);
}

/** Read only regular, owner-controlled files. Reject every relative directory
 * symlink, path escape, group/world-writable component and changed inode. */
export function readInput(root, path, maxBytes = 1_000_000) {
  if (typeof root !== 'string' || !isAbsolute(root) || root !== resolve(root) ||
      typeof path !== 'string' || !/^[A-Za-z0-9_./-]+$/.test(path) ||
      path.split('/').some(part => !part || part === '.' || part === '..') ||
      isAbsolute(path) || !Number.isSafeInteger(maxBytes) || maxBytes < 1) refuse();
  if (realpathSync(root) !== root) refuse();
  let dir = root;
  for (const component of ['', ...path.split('/').slice(0, -1)]) {
    if (component) dir = join(dir, component);
    const stat = lstatSync(dir);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022)) refuse();
  }
  let fd;
  try {
    const file = join(root, path);
    const before = lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o022) ||
        before.size < 1 || before.size > maxBytes) refuse();
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (opened.ino !== before.ino || opened.dev !== before.dev ||
        opened.size !== before.size || !opened.isFile()) refuse();
    // Read at most the inspected size plus one byte, even if a file grows.
    const buffer = Buffer.alloc(before.size + 1);
    let total = 0;
    while (total < buffer.length) {
      const count = readSync(fd, buffer, total, buffer.length - total, null);
      if (count === 0) break;
      total += count;
    }
    const bytes = buffer.subarray(0, total);
    const after = fstatSync(fd);
    if (bytes.length !== before.size || after.size !== before.size ||
        after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) refuse();
    return bytes;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function collectInputs(root) {
  const files = TEMPLATE_FILES.map(name => ({
    path: name, bytes: readInput(root, PACKAGE_ROOT + '/' + name, 32_768),
  }));
  const get = path => files.find(file => file.path === path).bytes;
  parsePackageManifest(get('package.json').toString('utf8'));
  parseSourceInputLock(get('transport-inputs.lock.json').toString('utf8'));
  for (const [name, pin] of MODULE_PINS) {
    const bytes = readInput(root, SOURCE_ROOT + '/' + name);
    if (gitBlob(bytes) !== pin) refuse();
    files.push({path: 'src/' + name, bytes});
  }
  const sourcePolicy = JSON.parse(readInput(root,
    'scripts/saas-staging/backend16-native-server-source-closure.v1.json', 12_000));
  if (!Array.isArray(sourcePolicy.modules) ||
      !isDeepStrictEqual(sourcePolicy.modules.map(m => [m.file, m.gitBlobSha1]), MODULE_PINS)) {
    refuse();
  }
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return files;
}

export function assertCiEnvironment(env, nodeMajor, platform, arch) {
  if (!env || typeof env !== 'object' || nodeMajor !== 24 ||
      platform !== 'linux' || arch !== 'x64' || env.CI !== 'true' ||
      env.GITHUB_ACTIONS !== 'true' || env.GITHUB_EVENT_NAME !== 'pull_request' ||
      env.GITHUB_REPOSITORY !== 'Bagirov24/Cli-Proxy-API-Management-Center' ||
      env.SAAS_B16_NATIVE_PACKAGE_CI !== 'true' ||
      !HEX40.test(env.B16_PR_HEAD_SHA ?? '') ||
      !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID ?? '') ||
      !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT ?? '') ||
      !isAbsolute(env.RUNNER_TEMP ?? '') ||
      env.NODE_ENV === 'production' || env.NODE_TLS_REJECT_UNAUTHORIZED === '0' ||
      env.DATABASE_URL || Object.keys(env).some(k => k.startsWith('RAILWAY_') && env[k])) {
    refuse();
  }
  return true;
}

/** Deliberate allowlist: no PG passwords, cloud identity, token, preload,
 * proxy, parent HOME, NODE_PATH or arbitrary BUN/NODE options reach Bun. */
export function isolatedEnvironment(stage) {
  if (!isAbsolute(stage) || stage !== resolve(stage)) refuse();
  return {
    PATH: '/usr/bin:/bin', HOME: join(stage, 'home'), TMPDIR: join(stage, 'tmp'),
    BUN_INSTALL_CACHE_DIR: join(stage, 'cache'),
    BUN_RUNTIME_TRANSPILER_CACHE_PATH: '0', DO_NOT_TRACK: '1',
    TZ: 'UTC', LC_ALL: 'C', LANG: 'C', CI: 'true',
  };
}

const RECEIPT_KEYS = [
  'schema', 'lane', 'headSha', 'runId', 'runAttempt', 'runtimeRevision',
  'runtimeSha256', 'sourceInventorySha256', 'inputSha256', 'recipeSha256',
  'manifestSha256', 'sourceInputLockSha256', 'bundleSha256', 'bundleBytes',
  'sourceFileCount', 'externalPackageCount', 'bundleImportSmokePassed',
  'packageManagerLockVerified', 'serverEntrypointBuilt', 'stableRuntimeApproved',
  'productionAuthorized', 'releaseState',
];
export function assertReceipt(receipt, expected) {
  plain(receipt);
  if (!isDeepStrictEqual(Object.keys(receipt).sort(), RECEIPT_KEYS.slice().sort()) ||
      receipt.schema !== 'backend16-native-transport-package-ci-v1' ||
      !['A', 'B'].includes(receipt.lane) || receipt.headSha !== expected.headSha ||
      receipt.runId !== expected.runId || receipt.runAttempt !== expected.runAttempt ||
      !HEX40.test(receipt.headSha) || !/^[1-9][0-9]*$/.test(receipt.runId) ||
      !/^[1-9][0-9]*$/.test(receipt.runAttempt) ||
      receipt.runtimeRevision !== CANDIDATE_REVISION ||
      receipt.sourceInventorySha256 !== SOURCE_INVENTORY_SHA256 ||
      receipt.sourceFileCount !== 7 || receipt.externalPackageCount !== 0 ||
      receipt.bundleImportSmokePassed !== true || receipt.packageManagerLockVerified !== false ||
      receipt.serverEntrypointBuilt !== false ||
      receipt.stableRuntimeApproved !== false || receipt.productionAuthorized !== false ||
      receipt.releaseState !== 'BLOCKED_RELEASE' ||
      !Number.isSafeInteger(receipt.bundleBytes) || receipt.bundleBytes < 1024 ||
      receipt.bundleBytes > 1_000_000) refuse();
  for (const key of ['runtimeSha256', 'inputSha256', 'recipeSha256',
    'manifestSha256', 'sourceInputLockSha256', 'bundleSha256']) {
    if (!HEX64.test(receipt[key] ?? '') || receipt[key] === '0'.repeat(64)) refuse();
  }
  return true;
}
export function compareReceipts(a, b, expected) {
  assertReceipt(a, expected);
  assertReceipt(b, expected);
  if (a.lane !== 'A' || b.lane !== 'B') refuse();
  const left = {...a}; delete left.lane;
  const right = {...b}; delete right.lane;
  if (!isDeepStrictEqual(left, right)) refuse();
  return Object.freeze({
    result: 'B16_NATIVE_PACKAGE_TWO_RUNNER_BYTES_MATCH',
    headSha: a.headSha, bundleSha256: a.bundleSha256, releaseState: 'BLOCKED_RELEASE',
  });
}

export function isOutside(root, destination) {
  const rel = relative(root, destination);
  return rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel);
}

import assert from 'node:assert/strict';
import {test} from 'node:test';
import {spawnSync} from 'node:child_process';
import {
  chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  assertCiEnvironment, assertSourceInputLock, assertPackageManifest, assertReceipt,
  CANDIDATE_REVISION, collectInputs, compareReceipts, gitBlob, isolatedEnvironment,
  isOutside, MODULE_PINS, PACKAGE_ROOT, parsePackageManifest, parseSourceInputLock, readInput,
  sha256, SOURCE_INVENTORY_SHA256, SOURCE_ROOT, TEMPLATE_FILES,
} from '../scripts/saas-staging/backend16-native-package-contract.mjs';

const root = resolve(fileURLToPath(new URL('../', import.meta.url)));
const read = path => readFileSync(join(root, path), 'utf8');
const manifest = () => JSON.parse(read(PACKAGE_ROOT + '/package.json'));
const lock = () => parseSourceInputLock(read(PACKAGE_ROOT + '/transport-inputs.lock.json'));
const copy = value => JSON.parse(JSON.stringify(value));
function temporary(run) {
  const dir = mkdtempSync(join(tmpdir(), 'b16-native-package-unit-'));
  try { return run(dir); } finally { rmSync(dir, {recursive: true, force: true}); }
}
function env() {
  return {
    CI: 'true', GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: 'pull_request',
    GITHUB_REPOSITORY: 'Bagirov24/Cli-Proxy-API-Management-Center',
    SAAS_B16_NATIVE_PACKAGE_CI: 'true', B16_PR_HEAD_SHA: 'a'.repeat(40),
    GITHUB_RUN_ID: '123456', GITHUB_RUN_ATTEMPT: '1', RUNNER_TEMP: '/tmp/runner',
  };
}
const expected = {headSha: 'a'.repeat(40), runId: '123456', runAttempt: '1'};
function receipt(lane = 'A') {
  return {
    schema: 'backend16-native-transport-package-ci-v1', lane, ...expected,
    runtimeRevision: CANDIDATE_REVISION, runtimeSha256: '1'.repeat(64),
    sourceInventorySha256: SOURCE_INVENTORY_SHA256,
    inputSha256: '2'.repeat(64), recipeSha256: '3'.repeat(64),
    manifestSha256: '4'.repeat(64), sourceInputLockSha256: '5'.repeat(64),
    bundleSha256: '6'.repeat(64), bundleBytes: 25_000,
    sourceFileCount: 7, externalPackageCount: 0, bundleImportSmokePassed: true,
    packageManagerLockVerified: false, serverEntrypointBuilt: false, stableRuntimeApproved: false,
    productionAuthorized: false, releaseState: 'BLOCKED_RELEASE',
  };
}

test('candidate package is private Bun-only with zero external dependencies', () => {
  assert.equal(assertPackageManifest(manifest()), true);
  assert.equal(assertSourceInputLock(lock()), true);
  assert.equal(manifest().packageManager, 'bun@1.4.4');
});
test('manifest rejects frontend, pg fallback, runtime ranges and lifecycle scripts', () => {
  const changes = [
    {dependencies: {react: '19.0.0'}}, {dependencies: {pg: '8.23.1'}},
    {devDependencies: {typescript: 'latest'}}, {optionalDependencies: {pg: '*'}},
    {peerDependencies: {react: '*'}}, {trustedDependencies: ['pg']},
    {packageManager: 'bun@latest'}, {engines: {bun: '^1.4.4'}},
    {scripts: {postinstall: 'echo unsafe'}}, {workspaces: ['../../*']},
    {private: false}, {exports: './index.ts'},
  ];
  for (const change of changes) assert.throws(() => assertPackageManifest({...manifest(), ...change}));
});
test('manifest and lock reject missing and extra fields', () => {
  for (const make of [manifest, lock]) {
    const check = make === manifest ? assertPackageManifest : assertSourceInputLock;
    for (const field of Object.keys(make())) {
      const value = make(); delete value[field]; assert.throws(() => check(value));
    }
    assert.throws(() => check({...make(), approved: true}));
  }
});
test('input lock parser accepts only the fixed source-only JSON shape', () => {
  assert.deepEqual(parseSourceInputLock(JSON.stringify(lock())), lock());
  assert.deepEqual(parseSourceInputLock(read(PACKAGE_ROOT + '/transport-inputs.lock.json')), lock());
});
test('input lock rejects dependencies, duplicate keys, comments and false package-lock claims', () => {
  const good = JSON.stringify(lock());
  for (const text of [
    good.replace('"externalPackageDependencies":[]', '"externalPackageDependencies":["pg"]'),
    good.replace('"modules":', '"modules":[],"modules":'),
    good.replace('"schema":', '"unexpected":{},"schema":'),
    good.replace('"packageManagerLockVerified":false', '"packageManagerLockVerified":true'),
    '// ignored?\n' + good, good + 'garbage', good.slice(0, -1),
    good.replace('BLOCKED_RELEASE', 'APPROVED'), ' '.repeat(8193),
    good.replace('"serverEntrypointBuilt":false', '"serverEntrypointBuilt":true'),
    good.replace('"node:tls"', '"pg"'), good.replace(/}$/, ',}'),
  ]) assert.throws(() => parseSourceInputLock(text));
});
test('reviewed seven-file pins are unique and deeply frozen', () => {
  assert.equal(MODULE_PINS.length, 7);
  assert.equal(new Set(MODULE_PINS.map(([name]) => name)).size, 7);
  assert.equal(Object.isFrozen(MODULE_PINS), true);
  for (const entry of MODULE_PINS) assert.equal(Object.isFrozen(entry), true);
  assert.throws(() => { MODULE_PINS[0][1] = '0'.repeat(40); });
});
test('byte hashes distinguish changed source without silently refreshing pins', () => {
  assert.equal(gitBlob(Buffer.from('test\n')), '9daeafb9864cf43055ae93beb0afd6c7d144bfa4');
  assert.notEqual(gitBlob(Buffer.from('test')), gitBlob(Buffer.from('test\n')));
  assert.equal(sha256(Buffer.from('abc')),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
test('safe input reader accepts an ordinary owner-controlled nested file', () => temporary(dir => {
  mkdirSync(join(dir, 'src')); writeFileSync(join(dir, 'src/test.ts'), 'export {};\n');
  assert.equal(readInput(dir, 'src/test.ts').toString(), 'export {};\n');
}));
test('safe input reader rejects path traversal and absolute input paths', () => temporary(dir => {
  for (const path of ['../outside', '/etc/passwd', 'a/../b', './x', 'a//b', 'a\0b']) {
    assert.throws(() => readInput(dir, path));
  }
}));
test('safe input reader rejects file symlinks', () => temporary(dir => {
  writeFileSync(join(dir, 'target'), 'data'); symlinkSync('target', join(dir, 'link'));
  assert.throws(() => readInput(dir, 'link'));
}));
test('safe input reader rejects directory symlinks', () => temporary(dir => {
  mkdirSync(join(dir, 'real')); writeFileSync(join(dir, 'real/file'), 'data');
  symlinkSync('real', join(dir, 'alias')); assert.throws(() => readInput(dir, 'alias/file'));
}));
test('safe input reader rejects writable, empty, oversized and nonregular files', () => temporary(dir => {
  writeFileSync(join(dir, 'file'), 'data'); chmodSync(join(dir, 'file'), 0o666);
  assert.throws(() => readInput(dir, 'file')); chmodSync(join(dir, 'file'), 0o600);
  assert.throws(() => readInput(dir, 'file', 3));
  writeFileSync(join(dir, 'empty'), ''); assert.throws(() => readInput(dir, 'empty'));
  mkdirSync(join(dir, 'directory')); assert.throws(() => readInput(dir, 'directory'));
}));
test('safe input reader rejects writable source directories', () => temporary(dir => {
  mkdirSync(join(dir, 'src')); writeFileSync(join(dir, 'src/file'), 'data');
  chmodSync(join(dir, 'src'), 0o777); assert.throws(() => readInput(dir, 'src/file'));
}));
test('collection rejects a counterfeit module even with valid candidate templates', () => temporary(dir => {
  mkdirSync(join(dir, PACKAGE_ROOT), {recursive: true});
  for (const file of TEMPLATE_FILES) writeFileSync(join(dir, PACKAGE_ROOT, file), read(PACKAGE_ROOT + '/' + file));
  mkdirSync(join(dir, SOURCE_ROOT), {recursive: true});
  writeFileSync(join(dir, SOURCE_ROOT, MODULE_PINS[0][0]), 'export const counterfeit = true;\n');
  assert.throws(() => collectInputs(dir));
}));
test('CI guard accepts only explicit synthetic Linux/x64 Node24 context', () => {
  assert.equal(assertCiEnvironment(env(), 24, 'linux', 'x64'), true);
  for (const args of [[22, 'linux', 'x64'], [24, 'darwin', 'arm64'], [24, 'linux', 'arm64']]) {
    assert.throws(() => assertCiEnvironment(env(), ...args));
  }
});
test('CI guard refuses production, Railway, push, foreign repo and invalid head/run', () => {
  for (const change of [
    {CI: 'false'}, {GITHUB_ACTIONS: 'false'}, {GITHUB_EVENT_NAME: 'push'},
    {GITHUB_REPOSITORY: 'someone/else'}, {SAAS_B16_NATIVE_PACKAGE_CI: 'false'},
    {B16_PR_HEAD_SHA: 'main'}, {GITHUB_RUN_ID: '0'}, {GITHUB_RUN_ATTEMPT: '0'},
    {RUNNER_TEMP: 'relative'}, {NODE_ENV: 'production'}, {NODE_TLS_REJECT_UNAUTHORIZED: '0'},
    {RAILWAY_PROJECT_ID: 'live'}, {RAILWAY_NEW_UNKNOWN_FIELD: 'live'}, {DATABASE_URL: 'live'},
  ]) assert.throws(() => assertCiEnvironment({...env(), ...change}, 24, 'linux', 'x64'));
});
test('Bun child environment cannot inherit PG credentials, tokens, injection or proxies', () => {
  const child = isolatedEnvironment('/tmp/b16-stage');
  assert.deepEqual(Object.keys(child).sort(), [
    'BUN_INSTALL_CACHE_DIR', 'BUN_RUNTIME_TRANSPILER_CACHE_PATH', 'CI',
    'DO_NOT_TRACK', 'HOME', 'LANG', 'LC_ALL', 'PATH', 'TMPDIR', 'TZ',
  ]);
  for (const key of ['PGPASSWORD', 'GITHUB_TOKEN', 'RAILWAY_TOKEN', 'NODE_OPTIONS',
    'NODE_PATH', 'BUN_OPTIONS', 'LD_PRELOAD', 'HTTPS_PROXY']) assert.equal(child[key], undefined);
  assert.equal(child.BUN_RUNTIME_TRANSPILER_CACHE_PATH, '0');
  assert.equal(child.DO_NOT_TRACK, '1');
  assert.throws(() => isolatedEnvironment('relative'));
});
test('stage must be outside the repository, not a prefix-confused child', () => {
  assert.equal(isOutside('/repo', '/repo/stage'), false);
  assert.equal(isOutside('/repo', '/repo'), false);
  assert.equal(isOutside('/repo', '/repo-other/stage'), true);
});
test('receipt comparison requires matching independent A/B lanes on same head and run', () => {
  assert.equal(assertReceipt(receipt(), expected), true);
  assert.equal(compareReceipts(receipt('A'), receipt('B'), expected).releaseState, 'BLOCKED_RELEASE');
  assert.throws(() => compareReceipts(receipt('A'), receipt('A'), expected));
  assert.throws(() => compareReceipts(receipt('B'), receipt('A'), expected));
});
test('receipts reject stale head, run, attempt, source closure and runtime revision', () => {
  for (const change of [
    {headSha: 'b'.repeat(40)}, {runId: '123455'}, {runAttempt: '2'},
    {sourceInventorySha256: '7'.repeat(64)}, {runtimeRevision: '8'.repeat(40)},
  ]) assert.throws(() => compareReceipts(receipt(), {...receipt('B'), ...change}, expected));
});
test('receipts reject differing build, lock, source, runtime and emitted bundle bytes', () => {
  for (const key of ['runtimeSha256', 'inputSha256', 'recipeSha256',
    'manifestSha256', 'sourceInputLockSha256', 'bundleSha256']) {
    assert.throws(() => compareReceipts(receipt(), {...receipt('B'), [key]: '9'.repeat(64)}, expected));
    assert.throws(() => assertReceipt({...receipt(), [key]: '0'.repeat(64)}, expected));
  }
  assert.throws(() => compareReceipts(receipt(), {...receipt('B'), bundleBytes: 25001}, expected));
});
test('receipt cannot claim server, stable-runtime or production approval', () => {
  for (const change of [
    {packageManagerLockVerified: true}, {serverEntrypointBuilt: true}, {stableRuntimeApproved: true}, {productionAuthorized: true},
    {releaseState: 'APPROVED'}, {bundleImportSmokePassed: false}, {externalPackageCount: 1},
    {sourceFileCount: 8}, {bundleBytes: NaN}, {bundleBytes: 1}, {bundleBytes: 1_000_001},
    {independentSecurityApproval: true},
  ]) assert.throws(() => assertReceipt({...receipt(), ...change}, expected));
  for (const field of Object.keys(receipt())) {
    const value = receipt(); delete value[field]; assert.throws(() => assertReceipt(value, expected));
  }
});
test('receipt refuses accessors and non-plain objects', () => {
  const value = receipt(); Object.defineProperty(value, 'lane', {get() { throw Error('getter'); }});
  assert.throws(() => assertReceipt(value, expected));
  assert.throws(() => assertReceipt(Object.assign(Object.create({}), receipt()), expected));
});
test('untrusted local runner exits nonzero before runtime acquisition or source copy', () => {
  const result = spawnSync(process.execPath,
    ['scripts/saas-staging/verify-backend16-native-package-ci.mjs', '--build', 'A'], {
      cwd: root, env: {PATH: process.env.PATH, NODE_ENV: 'production'},
      timeout: 5000, encoding: 'utf8',
    });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr.trim(), 'STOP Backend16 isolated package CI refused');
});
test('source facade includes all seven frozen modules and no server listener', () => {
  const source = read(PACKAGE_ROOT + '/index.ts');
  for (const [name] of MODULE_PINS) assert.ok(source.includes("'./src/" + name + "'"));
  assert.equal([...source.matchAll(/^import /gm)].length, 7);
  assert.doesNotMatch(source, /Bun\.serve|createServer|\.listen\(|\bfetch\(|process\.env/);
});
test('workflow uses exact HEAD, two isolated lanes, current-run receipts and no release', () => {
  const source = read('.github/workflows/saas-backend16-native-package-ci.yml');
  assert.match(source, /lane: \[A, B\]/);
  assert.match(source, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/);
  assert.match(source, /persist-credentials: false/);
  assert.match(source, /contents: read/);
  assert.match(source, /needs: package/);
  assert.match(source, /verify-backend16-official-stable-144-tls-ci\.ts/);
  assert.match(source, /--compare/);
  assert.doesNotMatch(source, /pull_request_target|continue-on-error|secrets\.|workflow_dispatch|contents: write/);
});
test('runner pins inputs without manufacturing a Bun lock and checks emitted-bundle smoke', () => {
  const source = read('scripts/saas-staging/verify-backend16-native-package-ci.mjs');
  assert.doesNotMatch(source, /--frozen-lockfile|--lockfile-only|const INSTALL|const GENERATE/);
  assert.match(source, /--no-install/); assert.match(source, /--no-env-file/); assert.match(source, /inspectBackend16NativeSourceClosure/);
  assert.match(source, /unchanged\(stage, files\)/); assert.match(source, /readInput\(ROOT, path\)\.equals/);
  assert.match(read(PACKAGE_ROOT + '/smoke.mjs'), /from '\.\/dist\/transport\.js'/);
  assert.doesNotMatch(source, /--compile|bun run start|npm install|process\.env\s*,|\.\.\.process\.env/);
});

test('manifest parser refuses duplicate dependency keys before JSON normalization', () => {
  const good = read(PACKAGE_ROOT + '/package.json');
  assert.deepEqual(parsePackageManifest(good), manifest());
  assert.throws(() => parsePackageManifest(good.replace('"dependencies": {}',
    '"dependencies": {"pg": "8.23.1"}, "dependencies": {}')));
});
test('input reader rejects a root reached through a parent-directory symlink', () => temporary(dir => {
  mkdirSync(join(dir, 'real')); mkdirSync(join(dir, 'real/child'));
  writeFileSync(join(dir, 'real/child/file'), 'data');
  symlinkSync('real', join(dir, 'alias'));
  assert.throws(() => readInput(join(dir, 'alias/child'), 'file'));
}));

test('new workflow retains the historical all-null P2 evidence gate as a mandatory step', () => {
  const source = read('.github/workflows/saas-backend16-native-package-ci.yml');
  assert.match(source,
    /node scripts\/saas-staging\/verify-backend16-native-server-artifact-evidence-contract-ci\.mjs/);
  assert.doesNotMatch(source, /continue-on-error|always\(\)|if: failure/);
});

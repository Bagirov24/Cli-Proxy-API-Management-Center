/**
 * Builds an UNAPPROVED transport LIBRARY, not a server or executable.
 * The historical P2 all-null evidence plan is not modified or promoted.
 */
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {
  closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync,
  openSync, readSync, readdirSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import {dirname, isAbsolute, join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {
  assertCiEnvironment, assertReceipt, CANDIDATE_REVISION, collectInputs, compareReceipts,
  isolatedEnvironment, isOutside, readInput, refuse, sha256,
  SOURCE_INVENTORY_SHA256,
} from './backend16-native-package-contract.mjs';

const ROOT = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const BUILD = Object.freeze([
  'build', './index.ts', '--target=bun', '--format=esm',
  '--packages=bundle', '--outfile=./dist/transport.js',
]);

function command(binary, args, cwd, env, timeout = 30_000) {
  // Never stream child diagnostics, secrets or arbitrary source into CI logs.
  return execFileSync(binary, args, {
    cwd, env, timeout, maxBuffer: 2_000_000,
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  });
}
function writeNew(path, bytes) {
  writeFileSync(path, bytes, {flag: 'wx', mode: 0o600});
}
function binaryDigest(binary) {
  if (!isAbsolute(binary) || binary !== resolve(binary) ||
      !/^\/tmp\/b16-official-stable-144-ci-[A-Za-z0-9]+\/bun$/.test(binary)) refuse();
  if (realpathSync(binary) !== binary) refuse();
  const parent = lstatSync(dirname(binary));
  if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o022)) refuse();
  const before = lstatSync(binary);
  if (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o022) ||
      before.size < 20_000_000 || before.size > 240_000_000) refuse();
  let fd;
  try {
    fd = openSync(binary, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.ino !== before.ino || stat.dev !== before.dev ||
        stat.size !== before.size) refuse();
    const hash = createHash('sha256');
    const chunk = Buffer.alloc(1024 * 1024);
    let length, total = 0;
    while ((length = readSync(fd, chunk, 0, chunk.length, null)) > 0) {
      total += length;
      if (total > before.size) refuse();
      hash.update(chunk.subarray(0, length));
    }
    const after = fstatSync(fd);
    if (total !== before.size || after.mtimeMs !== before.mtimeMs ||
        after.ctimeMs !== before.ctimeMs) refuse();
    return hash.digest('hex');
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
function noAncestorConfig(stage) {
  // No accidental frontend workspace, root tsconfig, .env or node_modules
  // resolution. This is input isolation, NOT an OS/network sandbox.
  for (let dir = dirname(stage); ; dir = dirname(dir)) {
    const names = readdirSync(dir);
    if (names.some(name => ['node_modules', 'package.json', 'bunfig.toml', '.npmrc',
      'tsconfig.json', 'jsconfig.json'].includes(name) ||
      name === '.env' || name.startsWith('.env.'))) refuse();
    if (dirname(dir) === dir) break;
  }
}
function sortedFiles(root, current = '') {
  const output = [];
  for (const name of readdirSync(join(root, current)).sort()) {
    const path = current ? current + '/' + name : name;
    const st = lstatSync(join(root, path));
    if (st.isSymbolicLink()) refuse();
    if (st.isDirectory()) output.push(...sortedFiles(root, path));
    else if (st.isFile()) output.push(path);
    else refuse();
  }
  return output.sort();
}
function inputInventory(files) {
  return files.map(file => ({path: file.path, bytes: file.bytes.length, sha256: sha256(file.bytes)}));
}
function unchanged(stage, files) {
  for (const file of files) {
    if (!readInput(stage, file.path).equals(file.bytes)) refuse();
  }
}
function snapshots(root) {
  return new Map([
    'package.json', 'bun.lock',
    'scripts/saas-staging/backend16-native-server-artifact-evidence-contract.v1.json',
  ].map(path => [path, readInput(root, path)]));
}

async function build(lane, env) {
  if (!['A', 'B'].includes(lane)) refuse();
  const head = command('git', ['rev-parse', 'HEAD'], ROOT, {
    PATH: '/usr/bin:/bin', LC_ALL: 'C',
  }, 5000).trim();
  if (head !== env.B16_PR_HEAD_SHA) refuse();
  const saved = snapshots(ROOT);
  const {inspectBackend16NativeSourceClosure} = await import(
    './verify-backend16-native-source-closure-ci.mjs');
  const closure = inspectBackend16NativeSourceClosure(ROOT);
  if (closure.sourceInventorySha256 !== SOURCE_INVENTORY_SHA256 ||
      closure.fileCount !== 7 || closure.externalPackageCount !== 0 ||
      closure.stableRuntimeApproved !== false || closure.productionAuthorized !== false) refuse();
  const files = collectInputs(ROOT); // Full byte pins; no caller-selected modules.
  const recipe = [
    'scripts/saas-staging/backend16-native-package-contract.mjs',
    'scripts/saas-staging/verify-backend16-native-package-ci.mjs',
    'scripts/saas-staging/install-backend16-official-stable-144-ci.mjs',
    'scripts/saas-staging/verify-backend16-native-source-closure-ci.mjs',
    'scripts/saas-staging/backend16-native-server-source-closure.v1.json',
    '.github/workflows/saas-backend16-native-package-ci.yml',
  ].map(path => ({path, sha256: sha256(readInput(ROOT, path))}));
  const stage = mkdtempSync(join(env.RUNNER_TEMP, 'b16-native-package-'));
  try {
    if (!isOutside(ROOT, stage)) refuse();
    noAncestorConfig(stage);
    for (const directory of ['src', 'home', 'tmp', 'cache']) {
      mkdirSync(join(stage, directory), {mode: 0o700});
    }
    for (const file of files) writeNew(join(stage, file.path), file.bytes);
    const childEnv = isolatedEnvironment(stage);
    const binary = env.SAAS_B16_STABLE_144_BIN;
    if (typeof binary !== 'string') refuse();
    const runtimeHash = binaryDigest(binary);
    if (command(binary, ['--revision'], stage, childEnv).trim() !== '1.4.4+38afee6c8' ||
        command(binary, ['-p', 'Bun.revision'], stage, childEnv).trim() !== CANDIDATE_REVISION) {
      refuse();
    }
    // Zero external packages: do NOT invent a Bun-generated empty lock or add
    // a dummy dependency to retain one. No package manager install is run.
    // The checked-in input lock and existing source verifier pin all inputs.
    const manifest = files.find(file => file.path === 'package.json').bytes;
    unchanged(stage, files);
    command(binary, BUILD, stage, childEnv);
    const output = readInput(stage, 'dist/transport.js', 1_000_000);
    if (output.length < 1024 || sortedFiles(join(stage, 'dist')).join(',') !== 'transport.js') {
      refuse();
    }
    const smoke = command(binary, ['--no-install', '--no-env-file', 'smoke.mjs'], stage, childEnv);
    if (smoke !== 'B16_NATIVE_PACKAGE_BUNDLE_IMPORT_AND_DEFAULT_DENIAL_PASS\n') refuse();
    unchanged(stage, files);
    if (binaryDigest(binary) !== runtimeHash) refuse();
    // No source maps, compiled executable or hidden packages may be emitted.
    const expected = [...files.map(file => file.path), 'dist/transport.js'].sort();
    if (JSON.stringify(sortedFiles(stage)) !== JSON.stringify(expected)) refuse();
    for (const [path, bytes] of saved) {
      if (!readInput(ROOT, path).equals(bytes)) refuse();
    }
    const receipt = {
      schema: 'backend16-native-transport-package-ci-v1', lane,
      headSha: head, runId: env.GITHUB_RUN_ID, runAttempt: env.GITHUB_RUN_ATTEMPT,
      runtimeRevision: CANDIDATE_REVISION, runtimeSha256: runtimeHash,
      sourceInventorySha256: SOURCE_INVENTORY_SHA256,
      inputSha256: sha256(JSON.stringify(inputInventory(files))),
      recipeSha256: sha256(JSON.stringify({files: recipe, build: BUILD})),
      manifestSha256: sha256(manifest),
      sourceInputLockSha256: sha256(files.find(file =>
        file.path === 'transport-inputs.lock.json').bytes),
      bundleSha256: sha256(output), bundleBytes: output.length,
      sourceFileCount: 7, externalPackageCount: 0, bundleImportSmokePassed: true,
      packageManagerLockVerified: false, serverEntrypointBuilt: false, stableRuntimeApproved: false,
      productionAuthorized: false, releaseState: 'BLOCKED_RELEASE',
    };
    assertReceipt(receipt, {
      headSha: head, runId: env.GITHUB_RUN_ID, runAttempt: env.GITHUB_RUN_ATTEMPT,
    });
    // Only small unsigned receipts leave the build stage; NEVER the executable,
    // generated secrets, certificate material, dependency cache or a deployable server.
    const evidence = join(env.RUNNER_TEMP, 'b16-native-package-evidence-' + lane);
    mkdirSync(evidence, {mode: 0o700}); // Refuse stale/reused output directories.
    writeNew(join(evidence, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
    console.info('B16_NATIVE_PACKAGE_PINNED_INPUTS_AND_BUNDLE_PASS');
    console.info('B16_NATIVE_PACKAGE_BUNDLE_SHA256=' + receipt.bundleSha256);
    console.info('NO RELEASE AUTHORIZATION');
  } finally {
    rmSync(stage, {recursive: true, force: true});
  }
}

export async function main(argv, env = process.env) {
  assertCiEnvironment(env, Number(process.versions.node.split('.')[0]),
    process.platform, process.arch);
  if (argv.length === 2 && argv[0] === '--build') return build(argv[1], env);
  if (argv.length === 3 && argv[0] === '--compare') {
    const root = resolve(env.RUNNER_TEMP);
    // Paths from this fixed workflow only; no arbitrary absolute files.
    const names = ['b16-native-package-compare/A/receipt.json',
      'b16-native-package-compare/B/receipt.json'];
    if (argv[1] !== names[0] || argv[2] !== names[1]) refuse();
    const [a, b] = names.map(name => JSON.parse(readInput(root, name, 8192)));
    const result = compareReceipts(a, b, {
      headSha: env.B16_PR_HEAD_SHA, runId: env.GITHUB_RUN_ID,
      runAttempt: env.GITHUB_RUN_ATTEMPT,
    });
    console.info(result.result);
    console.info('B16_NATIVE_PACKAGE_BUNDLE_SHA256=' + result.bundleSha256);
    console.info('NO RELEASE AUTHORIZATION');
    return;
  }
  refuse();
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(() => {
    console.error('STOP Backend16 isolated package CI refused');
    process.exitCode = 1;
  });
}

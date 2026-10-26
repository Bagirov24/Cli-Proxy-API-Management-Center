# Backend16: emitted transport-library physical CI

Preparation: 2026-10-26. Base: PR107 at
`1385a29f9275da0bb520ba257c570942018a695d`.

**BLOCKED_RELEASE / NO RELEASE AUTHORIZATION.** This change proposes an
additional disposable integration check. Local guard tests and syntax checks
are not evidence that Bun, Docker, mTLS or PostgreSQL were executed locally.
Actual acceptance requires freshly inspected exact-HEAD GitHub Actions.

## What is added

The existing stable combined source supervisor first completes its unchanged
13-command source scenario. It then requires a second scenario using a fresh
Node24 synthetic broker and the emitted Bun transport library. Removing the
three-line addition recovers original supervisor Git blob
`7c36338dbc96557d4df991acd5739a34a46ba542` exactly. A separate bounded receipt-readback addition in the physical shell
recovers its previous Git blob `838e0279200947a206230f593aa44a7a7f0ae782`
when removed. All original physical assertions, tests, seven production
modules, source pins and root Bun lock are unchanged. Original canary, stable and Node pg comparator checks still run.

The new supervisor reuses PR107's source inventory, input collection and exact
Bun build command. It checks actual runtime bytes, full revision and actual
bundle bytes against the inspected PR107 A/B receipts, not the PR prose. Build
subprocesses receive an allowlisted environment without any PG credentials,
cloud tokens, inherited loaders or proxies. No dependency installation is run.

After the original bundle default-deny smoke succeeds, only `transport.js` and
a generated `probe.ts` are copied to a different fresh execution directory.
The entire build directory, including copied source, manifest and input lock,
is removed BEFORE the second broker and Bun child start. The child runs with
`--no-install --no-env-file`, outside the repository, with a fresh HOME and
transpiler cache disabled. Its application imports all resolve to the emitted
library. The child still has the known disposable PostgreSQL fixture admin
credential for setup/independent observation; application LOGIN passwords
arrive only through the authenticated mTLS reader/vault path.

## Assertion preservation and acceptance

The original combined child is pinned to Git blob
`d51205e37bf0c07827e448f469e78b850821f8a9`. Only its import bindings and the
erased VerifiedPrincipal type are adapted. Every byte from `let phase` through
the end of the original test is preserved, including the error and cleanup
paths. No modified or appended harness is accepted by the transformation.

The additional scenario requires two real LOGINs, same-physical-PID TLS
observation, authorized tenant reads, both cross-tenant denials, physical PID
destruction, wrong-version and expired secrets, a deferred authenticated
response revoked before credential release, an actual FOR SHARE wait and
abort, pool quarantine, fresh second-tenant recovery and wrong PG root denial.
The child must finish with exactly nine credential releases. The independent
broker must observe exactly twelve versioned requests: eight A and four B.
A strict ordered command parser, zero child exit, bounded output, timeout,
post-execution byte readback and restoration of `ssl=off` are mandatory.

A small **unsigned** log receipt binds current HEAD/run/attempt, source/input,
runtime, bundle, original/generated harness and recipe hashes. Eight distinct
`B16_EMITTED_BUNDLE_*` markers appear only after all checks succeed. The shell requires each marker
exactly once and parses one canonical, current-run receipt from a bounded
regular no-symlink log before echoing only those validated fields. No bundle,
runtime, keys, database dumps or credentials are uploaded. Both existing
unfiltered package lanes also run the new guard tests.

## PR107 receipt correction discovered during preparation

Freshly downloaded original artifacts 12613639411 (A) and 12613404931 (B)
matched the GitHub archive SHA256 values. Their fields agree except lane.
The earlier PR107 narrative and handoff had incorrect ancillary digests;
those prose values must NOT be used as pins. Actual receipt values are:

- runtime SHA256: `10702245766b225e70bbf6235fd6b47214fd94b4760d00ffaed8ab0df57ac235`
- input SHA256: `df6943ecb1da2d395f362d44d988a18fc7afd7bde371916d93de9f0e68250379`
- original package recipe SHA256: `45fd270bc15c783b70b7478b90ac24f70e98d129dfebb8e060f953fa85095fd0`
- manifest SHA256: `c22a6ea52f9b0a3ad4912c8fb1f440905ebedcf5ac93c0b2b29040a84e23d3d0`
- source-input-lock SHA256: `eeeaa23b881c20fe417b9fa49646510844b7f33dd92f049b873172d7ac5ac997`

The previously reported bundle SHA256 remains correct:
`21ae8f82c05ff2b8a3ae2e096f7d1262107fd5e924bf3212ad3c354ebea9cd56`,
59,771 bytes. The physical recipe hash is distinct from the old package recipe.

## Limits

This is the existing combined scenario executed through a compiled transport
LIBRARY, not an HTTP server or complete executable. The separate historical
standalone TLS/mTLS negatives still execute their existing source harnesses;
this change does not claim those entire suites run through the bundle.
The build/execution directories and environment allowlists are not an OS or
network sandbox. The repository remains accessible to the same runner account.
Brokers, fixtures and observers share GitHub infrastructure; unsigned receipts
are not independent administrative trust or signed provenance. Byte equality
to PR107 does not establish general hermetic reproducibility.

`packageManagerLockVerified`, `serverEntrypointBuilt`, `stableRuntimeApproved`
and `productionAuthorized` remain false. All seventeen historical P2 evidence
slots remain null. No full server dependency lock, complete runtime/native SBOM,
OIDC/session-authority composition, live IAM/PKI, off-host audit/PITR or independent
security/operations approval is supplied. No change to root `bun@1.3.14`, root
`bun.lock`, or `NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false`.
No repair of Draft106, production Node pg fallback, Railway operation,
permanent SQL0008 replay, deployment, tag, release or merge is authorized.

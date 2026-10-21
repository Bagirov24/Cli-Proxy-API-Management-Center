# Backend16 P2 — future Native Bun.SQL server-only artifact evidence contract

**Status: `P2_UNBUILT_SERVER_ARTIFACT_CONTRACT_ONLY`, `BLOCKED_RELEASE`.**
This is a reproducible, fail-closed *evidence plan*, not a runnable server,
full SBOM, complete dependency lock, signed attestation or authorization.
P1 still has **no security-approved stable Bun release** (last observed
official stable 1.4.3 fails mandatory exact peer TLS negatives).

## Inputs locked by the v1 precursor

The manually reviewed
`backend16-native-server-artifact-evidence-contract.v1.json`
states exact Linux/x64 Native Bun.SQL transport, denies Node24 `pg`
production fallback, denies bundling frontend React/Vite into the server,
and binds to the **seven pinned but unmounted source files**. Its source
inventory SHA256 and source-only CycloneDX SHA256 are pinned explicitly
to the observed reviewed values, not recalculated into the plan on drift.

The offline
`verify-backend16-native-server-artifact-evidence-contract-ci.mjs`
runs existing frozen source-closure checks and deterministic CycloneDX
generation, then the independent offline verifier from #99. It confirms
those independent values against the manually pinned policy and
re-verifies the policy's exact closed shape and release hard stops.
The policy has 17 named **missing** evidence slots, all required to
remain `null` in this v1 precursor. It is deliberately impossible
to mark even one field as approved and still get a positive result.

The missing evidence includes exact published and independently reviewed
stable Bun revision, npm archive length/SHA512, real physical PG16 peer
identity receipt, standalone server manifest/lock, reproducible runtime
dependency graph, actual Bun-only entrypoint, OIDC/session composition,
off-host audit integration, deterministic build recipe and executable SHA256,
**complete** runtime/transitive SBOM, signed build provenance, and
independent security and operations approval.

The deterministic policy receipt SHA256 covers only the JSON evidence
plan. **It does not hash an executable or authenticate a publisher,
signature or operator approval.** Passing this check cannot prove the
missing fields. This intentionally avoids a fake stable 1.4.4 fixture,
CI-only canary upgrade or placeholder production build.

## CI and adversarial acceptance

Native TLS CI runs seven fail-closed Node24 tests plus direct CI-mode
policy inspection before installing the fixed SHA512-pinned CI-only Bun.
Both Native TLS and physical PostgreSQL16/RLS workflows are path-triggered
on the v1 policy, verifier, tests and this documentation. Physical TLS
wrong-root, CA-signed wildcard, always-deny callback, real backend PID
lifecycle, RLS, mTLS broker/vault and backup/restore remain mandatory.

The tests reject forged artifact/provenance/SBOM hashes, omitted fields,
wrong source inventory or graph, unknown dependencies, Node `pg` fallback,
wrong platform, missing/changed source files and fake approval flags.

Only these CI-only results are allowed:
`B16_NATIVE_SERVER_ARTIFACT_EVIDENCE_CONTRACT_CI_PASS`,
`B16_NATIVE_SERVER_ARTIFACT_EVIDENCE_CONTRACT_SHA256=<sha256>`,
`B16_NATIVE_SERVER_ARTIFACT_MISSING_EVIDENCE_COUNT=17`,
`B16_NATIVE_SERVER_ARTIFACT_BLOCKED_RELEASE`, and
`NO RELEASE AUTHORIZATION`.

## Conditions for a future real artifact

A future independent P2 change must add *separately reviewed* stable
runtime evidence and secure binary testing, Bun-only package/lock,
complete dependency inventory and build graph, genuine server
composition and executable, signed source-to-build provenance,
independent approval and actual full SBOM. This v1 **must not be
rewritten into a permissive approval parser** merely because CI is green.

Root `bun@1.3.14` and `bun.lock` remain unchanged.
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` stays enforced.
No executable, network fetch/install, global Bun upgrade, real IAM,
Railway, SQL0008 replay, private database, production Core/Gateway,
deployment, GitHub Release or merge is included. All P3–P13 live
operator gates remain `LIVE_UNVERIFIED`.

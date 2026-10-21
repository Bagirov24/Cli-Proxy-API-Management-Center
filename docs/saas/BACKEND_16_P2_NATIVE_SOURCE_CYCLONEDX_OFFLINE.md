# Backend16 P2 — independent offline source-only CycloneDX verifier

**Evidence:** `UNMOUNTED_SOURCE_SCOPE_ONLY`, `NOT_A_PRODUCTION_SBOM`,
`BLOCKED_RELEASE`. This narrowly follows the existing frozen source
closure and seven-file CycloneDX 1.6 JSON generator.

The pure `verifyBackend16NativeSourceCycloneDxOffline(repoRoot,bomJson,claimedBomSha256)`
function checks exact canonical JSON bytes and caller-supplied SHA256, strict
closed-field shape for the project's current CycloneDX 1.6 **subset**, metadata
with all release hard stops, seven ordered unique file `bom-ref` identifiers,
actual pinned Git blob and SHA256 source bytes, byte lengths, and precisely
reconstructed source import edges (including TypeScript type-only imports).
All dependency references must resolve to one of seven reviewed components.
It runs the existing source-closure verifier and independently reads each
pinned module with no-follow filesystem checks.

The verifier refuses missing/duplicate/dangling refs, false approval flags,
malformed or noncanonical JSON, altered bytes/hashes, changed import graph,
unexpected fields, and reordered records. An observed digest is **not**
trusted publisher provenance or an out-of-band signed release attestation.

This is **not full validation against the official CycloneDX JSON schema**.
There is no vendored upstream schema or general CycloneDX parser; the
independently enforced shape is intentionally limited to the checked-in
seven-file producer's existing output. It is not a full runtime SBOM or
a future Bun executable/build/lock/provenance verifier.

The independent Native TLS workflow runs its offline adversarial tests before
the CI-only pinned canary install, and the physical PG16/RLS workflow is
path-triggered for all three files. It does not skip or replace physical
wrong-root, wildcard, always-deny, physical PID and RLS checks.

There is no package install, network request, public listener, server build,
artifact release, Bun pin or root lockfile change, live PostgreSQL, Railway,
IAM, credentials or deployment. Production fallback to Node `pg` remains
forbidden. `NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` remains
unchanged. P1 stable peer identity, complete P2 packaging, independent
reviews and all live gates remain blocked/unverified.

**Positive offline result:** `B16_NATIVE_BUN_SOURCE_CYCLONEDX_OFFLINE_VERIFIED`
with `upstreamSchemaValidated:false`, `serverArtifactBuilt:false`,
`stableRuntimeApproved:false`, `productionAuthorized:false`.
**NO RELEASE AUTHORIZATION.**

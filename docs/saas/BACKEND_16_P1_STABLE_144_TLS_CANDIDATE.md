# Backend16 P1 — Official Bun 1.4.4 stable Native.SQL security candidate

**2026-10-23 checkpoint: `OFFICIAL_STABLE_PUBLISHED_NOT_APPROVED`,
`DISPOSABLE_PG16_PROBE_ONLY`, `BLOCKED_RELEASE`.**

Bun **1.4.4** was officially published on **2026-10-22**, unlike the
historical 2026-10-21 checkpoint describing stable 1.4.3 as latest.
This is a new *candidate*, not a revision of the original owner-selected
Native Bun.SQL architecture and not a stable runtime security approval.
Older documentation remains a dated factual record, not a currently
valid claim that stable 1.4.4 is unavailable.

## Independently observed official upstream coordinates

- [Official Bun v1.4.4 release](https://github.com/oven-sh/bun/releases/tag/bun-v1.4.4)
  (published 2026-10-22T10:11:32Z).
- Tag and signed GitHub commit
  `38afee6c84fcf48c0edb2466aa4b27d287a59c30`.
- Linux/x64, glibc, **non-baseline release ZIP only**:
  `bun-linux-x64.zip`,
  `https://github.com/oven-sh/bun/releases/download/bun-v1.4.4/bun-linux-x64.zip`.
- GitHub published ZIP asset ID `665259752`,
  exact byte length `51794595`,
  published digest
  `sha256:bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c`.
- **Candidate expectation, to be verified against executed bytes:**
  `Bun.version=1.4.4`,
  `Bun.revision=38afee6c84fcf48c0edb2466aa4b27d287a59c30`,
  `bun --revision=1.4.4+38afee6c8`.

The GitHub asset digest is not itself a signed publisher or SLSA
attestation. The published git tag/commit verification is separately
checked upstream; the downloaded executable itself must independently
match the immutable ZIP hash and running revision.

## New limited CI acceptance

`.github/workflows/saas-backend16-stable-144-tls-ci.yml` runs only
for pull requests changing its reviewed inputs, on Ubuntu 24.04 and
Node24 with an **isolated PostgreSQL16.6 service**. It checks out the
exact PR head (not a synthetic merge); no app package-manager or
frontend Bun version changes are made.

`install-backend16-official-stable-144-ci.mjs` rejects non-GitHub,
non-PR, non-Node24, wrong OS/arch, release/production, Railway,
unexpected PostgreSQL identity, TLS-verification-disabled and
untrusted GitHub output environments. It permits HTTPS redirects only
to known GitHub release CDNs; caps the download and enforces exact
length plus pinned SHA256 *before* any ZIP inspection or execution.
It inspects ZIP member names and extracts only the literal
`bun-linux-x64/bun` entry, never arbitrary paths. The ELF header,
bounded decompressed length, `--revision`, `Bun.version`, and
`Bun.revision` must match the exact reviewed release. Only then is
an absolute temporary binary path set for a subsequent CI-only step.
No global PATH, npm/bun installation, root lock change, deployment,
Railway service, GitHub Release or durable artifact is generated.

`verify-backend16-official-stable-144-tls-ci.ts` is **exactly the
existing canary same-socket PostgreSQL TLS physical probe**, except
the independently pinned full source revision and stable-specific
CI-only environment flag. A test refuses any other difference.
The physical, real-service acceptance must keep **both**
`new SQL(options)` and `new SQL(url, options)` always-deny
`checkServerIdentity` callback tests; authenticated exact-SAN positive;
wrong-root; CA-signed wildcard; explicit `tls:'disable'`; and
`pg_stat_ssl` evidence. All must pass. The separate existing canary,
full physical PostgreSQL16/RLS and source cross-runner acceptance
are triggered by changes to these files too, and are not skipped.

## What success would—and would not—mean

Even if all independent exact-head CI jobs succeed, the verdict is only
`STABLE_144_DISPOSABLE_TLS_CANDIDATE_PASSED`: a *candidate* passed
the limited real PostgreSQL16 peer TLS comparison. No already-passed
canary run, official release or changed CLI revision alone can satisfy it.
This does **not** prove full two-tenant stable runtime SQL/RLS,
mTLS broker/vault, OIDC/session, physical PID lifecycle, a separately
reviewed Linux production package/lock, reproducible server build,
complete SBOM, signed provenance or operator-owned live evidence.
It also does not replace the existing
`verify-backend16-native-stable-archive-preflight.mjs` (npm SHA512
descriptor gate); this is a **GitHub release ZIP SHA256** candidate
from a different reviewed upstream distribution route.

The policy must remain
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false`.
The React/Vite root `bun@1.3.14`, `bun.lock` and all negative TLS
assertions remain unchanged. Node24 `pg` is a CI-only comparator,
**never** production fallback. No permanent SQL0008 replay,
private Railway, IAM/secrets, live operator receipts, Core/Gateway
mutation, staging/production rollout, source PR merge or release.
Independent code/security/operations reviews are still required.
All 17 P2 artifact evidence slots and all live P3–P13 gates remain
missing/unverified. **NO RELEASE AUTHORIZATION.**

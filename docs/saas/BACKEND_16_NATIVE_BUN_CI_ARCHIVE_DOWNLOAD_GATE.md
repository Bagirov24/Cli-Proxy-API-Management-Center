# Backend16 — bounded CI-only native Bun archive acquisition

**Scope: unmounted, disposable GitHub Actions proof only.** This change
does not qualify a stable server runtime, grant staging access, provision
credentials or permit production rollout.

## Gap

The upstream Bun PostgreSQL TLS canary was already fixed to a single published
npm archive, with SHA512 before extraction and the exact full executable
revision before use. However, the Node24 installer read an HTTP body using
`response.arrayBuffer()`, which could allocate an unbounded download before
the old 150,000,000-byte size guard ran. The tarball hash does not prevent
resource exhaustion during retrieval.

## Fail-closed contract

`readBoundedNativeBunResponse` now rejects any non-200 or redirected response,
invalid or oversized declared Content-Length, body/stream failure, zero-length
stream, truncated length or additional bytes, and any streaming total above
150,000,000 bytes. Missing Content-Length is permitted **only** because the
stream itself is bounded: it does not bypass the exact SHA512 check.
Errors are generic, no partial body is written or passed to `tar`, and
the network request retains a 120-second abort timeout and redirect refusal.

A bounded response is **not** an accepted artifact: the unchanged
`verifyNativeBunArchive` must still verify the immutable historical
`NATIVE_BUN_CI_PIN.sha512` and 1,000,000-byte minimum **before tar**.
The installer checks the same exact Bun CLI/full-source revisions afterward.
The limit override in the exported decoder is a unit-test input only, never
greater than the built-in production-CI ceiling; the actual installer uses
the fixed default. The independent native acceptance job now executes
stream/framing/security negative tests before downloading its pinned archive.

## Mandatory evidence and release boundaries

On the change's **exact head**, require the independent native TLS probe
and full disposable PG16 workflow, including physical backend PID, correct
CA/exact DNS SAN, always-deny callback enforcement, wrong-root denial and
CA-valid wildcard denial. The dual independently locked Node24 PG full-chain,
RLS, cancellation and quarantine evidence must remain green. This is an
additional guard around upstream artifact transport, **not** a new root
lockfile, a new Bun release pin, a dependency graph fingerprint update, a
replacement for human security review or real operator trust approval.

Stable Bun 1.3.14 / 1.4.3 same-socket TLS negative findings remain historical
RED observations. CI still installs only
`@oven/bun-linux-x64@1.4.3-canary.20261019.1` from the pinned SHA512,
and the normal app remains `bun@1.3.14`. In particular
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` remains a hard stop.
No live Railway, permanent SQL0008, IAM/credentials, volumes, release,
Core/Gateway, or `custom-no-apikey-fun` operation is part of this step.

# Backend16 P1 — official stable Bun 1.4.4 full disposable physical regression

**Date:** 2026-10-23. **Status:** `STABLE144_FULL_PHYSICAL_CI_CANDIDATE`,
`BLOCKED_RELEASE`, `NO RELEASE AUTHORIZATION`.
Built strictly on the verified stable-asset TLS candidate in PR #103.
The official GitHub Linux/x64 ZIP `bun-v1.4.4` is fixed at SHA256
`bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c`,
full source `38afee6c84fcf48c0edb2466aa4b27d287a59c30`.
Its SHA256, size, exact executable revision, and restricted CI runner
are verified by the **unchanged** #103 installer before execution.

## Motivation and exact scope

PR #103 proved the *published stable binary's isolated TLS peer identity
negative cases*, but the existing full physical SQL0008 job still used
frontend Bun 1.3.14 for physical two-LOGIN/PID/revocation and the
fixed **canary** for its two-tenant TLS/RLS harness. It did not
run the same full tests on the official stable 1.4.4.

This PR adds **extra tests on the same disposable PG16.6 service and
the same freshly minted synthetic SQL0008 grants/sessions**. It
**does not replace or skip** any previous PG16 acceptance. The
existing Node24 independent dual-install `pg` + synthetic mTLS
broker/immutable vault, frontend Bun1.3.14 physical PID tests and
SHA512-pinned canary negative TLS all stay mandatory, unchanged.

The PG16 workflow now checks out exact `github.event.pull_request.head.sha`
with credentials persistence off, and installs the official stable
SHA256-verified binary **before** the canary sets its distinct bin path.
No global PATH, package manifest, frontend `bun@1.3.14`, `bun.lock`,
npm lock, server release or Bun runtime swap is made.

## Physical additions

1. **Stable exact SQL0008 full native PID lifecycle:** rerun
   `verify-backend16-bun-physical-pid-ci.ts` with official stable
   `SAAS_B16_STABLE_144_BIN` against **both** freshly generated
   distinct authenticated LOGINs. It exercises session/binding/subject
   fingerprints, two-tenant RLS allow/deny, same real backend PID
   disposal, immutable-version vault, credential spoof denial, active
   `FOR SHARE` lock abort, PID death, pool quarantine and fresh
   acquisition/no retry. Separate marker:
   `B16_STABLE_144_PHYSICAL_VAULT_FOR_SHARE_REVOKE_PID_PASS`.
2. **Independent stable mTLS client:** a byte-parity-guarded
   copy of the existing Node24 disposable HTTPS/mTLS broker fixture
   launches the *actual official stable* Bun executable (rather than
   frontend `bun`) for its client request. All existing exact SAN,
   pinned roots, immutable-version vault, revoked, expired,
   wrong version, redirect, oversize, wildcard, and wrong-root denial
   assertions are unchanged. Marker:
   `B16_STABLE_144_MTLS_BROKER_VERSIONED_VAULT_PASS`.
   The official stable candidate's focused workflow repeats this mTLS
   regression in a separate runner as an early failure gate.
3. **Stable native verify-full, real RLS, physical PID and TLS negatives:**
   after the unchanged canary physical probe finishes, reset only
   **disposable** PostgreSQL16 `ssl=off` and verify readback so the
   stable probe can repeat the exact fixture setup. Its TypeScript
   source is byte-identical to the canary's full Native TLS/RLS
   probe except for the official source revision and an extra
   stable-only environment guard. All real same-socket authenticated
   positives, both tenants' allowed/denied reads, vault refresh,
   wrong-root, CA-signed wildcard, callback always-deny, exact physical
   backend PID shutdown, TLS versions and negative assertions remain.
   Marker: `B16_STABLE_144_TLS_TWO_TENANT_VAULT_RLS_PID_NEGATIVES_PASS`.

All three stable additions must succeed **before** the old shell's
adversarial subject/session/binding, `SET ROLE`, lock-held revoke,
post-commit re-enrollment/no ABA, second-tenant grant revoke/regrant
and eight-migration-receipt assertions continue unmodified.
Only then may the shell print
`B16_STABLE_144_FULL_DISPOSABLE_PG16_CANDIDATE_PASS_NOT_RELEASE_APPROVAL`
and `NO RELEASE AUTHORIZATION`.

## CI and limitations

A new fail-closed Node24 regression suite checks byte parity between
stable/canary physical TLS code and original/stable broker fixture,
per-file routing into the stable, canary, full-PG16 and cross-runner
workflows, exact PR head, stable-before-canary ordering, preserved
existing mandatory negative assertions, revocation ordering and
unchanged root package pin. The full physical PG16 workflow alone
provides live fixture evidence; unit tests cannot replace it.

**Limitations:** stable 1.4.4 now participates in two-tenant Native
PG16/RLS/PID and a separately exercised Bun mTLS broker client. The
Node24 `pg` full-chain integration remains an **independent
comparator**: the stable mTLS broker result and stable PG credential
vault are tested separately, not yet joined in a *single*
end-to-end stable HTTPS broker-to-PG call. This is not a signed
runtime provenance, independently approved stable Bun transport,
production package/lock, complete runtime SBOM or Bun executable
build. The full P2 artifact evidence plan still has 17 missing
proofs; independent reviews and P3–P13 live operator evidence,
including OIDC/IAM/PKI/audit/PITR/rollback, remain unverified.

**Release hard stop remains**
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false`.
No Railway, permanent SQL0008 replay, production DB, real credentials,
Core/Gateway, staging rollout, deployment, GitHub Release or merge.
A green CI result only justifies **independent security review**,
never staging or production authorization.

# Backend16 — Node 24 same-socket PostgreSQL TLS identity experiment

**Status: CI-only experiment; no release, deployment, merge permission or
production-runtime choice.** Stacked on the security-blocked Draft PR #76.
Its native Bun.SQL staging hard stop must remain enabled. This experiment
does not satisfy Backend16 production readiness by itself.

## Motivation

Backend16.10 (PR #75) added a synchronous strict DNS SAN callback to the
native Bun.SQL TLS trust object. Actual PostgreSQL16 adversarial tests in
PR #76 showed Bun 1.3.14 accepting an unrelated CA and CA-valid wildcard SAN.
Bun 1.4.3 rejected the unrelated CA but still ignored an always-deny
checkServerIdentity callback and accepted the same-CA wildcard. Therefore
an isolated TLS probe or pg_stat_ssl.ssl=true alone does not authorize login.

The maintained node-postgres library passes its SSL configuration to the
Node TLSSocket. This experiment must **demonstrate** that Node actually
invokes the strict callback on the same PostgreSQL backend that authenticates,
and refuses adversarial identities before DB login.

## Experimental acceptance (disposable GitHub Actions only)

- PostgreSQL16.6 in the workflow's own fresh Docker service, exact service
  container ID, 127.0.0.1:5432, synthetic saas_ephemeral_test sentinel,
  GitHub-only flag. Fail closed in Railway, production or disabled global TLS.
- Node 24 and precisely node-postgres 8.23.1 installed under /tmp. This is
  a **temporary comparison**, not a change to project package.json, Bun.lock,
  package manager policy or release dependencies.
- Mint a synthetic 3072-bit trust root, independent different root,
  2048-bit signed matching leaf, and matching-root wildcard, wrong-DNS and
  CN-only leaves. All certificates and private keys exist only in the runner
  and temporary PostgreSQL container; none are Git-tracked or exported.
- A genuine login to PostgreSQL must return the same physical backend PID
  and pg_stat_ssl.ssl=true/TLSv1.2-or-v1.3 after the exact-SAN callback has
  been invoked exactly once. Closing the client must remove that PID.
- Callback that always denies, a different CA, same-CA wildcard, wrong
  SAN and CN-only certificates must all fail the genuine PostgreSQL TLS
  connection. Certificate chain failure precedes the hostname callback;
  the other cases must trigger the exact-SAN callback. No authenticated
  application-name session may remain after refusal.
- All refusals are assertions; log markers are supplementary only. Never
  log credential or certificate private-key material.

## Deliberate limitations and next engineering steps

The test uses an ephemeral PostgreSQL operator fixture solely to validate
the transport. It does not prove distinct least-privilege principals, the
existing SQL0008 exact-session predicate, tenant FORCE RLS, mTLS secret
broker, immutable-version vault, cancellation during SQL execution or
durable audit. It also does not establish trust in any real staging CA.

After this independent transport experiment is green, propose a separate,
reviewed Node physical PostgreSQL adapter (with a **proper Bun.lock-reviewed
dependency**) that retains exact SQL allowlisting, dedicated physical
LOGIN, fail-closed revocation, quarantine, PID teardown, request-scoped
COMMIT and multi-tenant PostgreSQL16 acceptance. Then add the combined
mTLS broker → versioned vault → authenticated TLS PostgreSQL16 → tenant RLS
test. Production OIDC, IAM, independent signed review, off-host audit,
restore/DR, multi-instance behavior, private deployment, canary and rollback
remain distinct blockers.

Native Bun.SQL production staging driver remains hard-blocked in PR #76.
No production Core/Gateway or custom-no-apikey-fun branch, permanent SQL0008,
Railway config/deployment, credentials, real user traffic, persistent
volumes or /data may be modified from this experiment. Do not merge without
an independent current-head security review and explicit new owner approval.

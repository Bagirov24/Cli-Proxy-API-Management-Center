# Backend16.11 — version-pinned principal credential vault adapter

**Source-only candidate. UNMOUNTED. NOT a deployed/connected secret vault.**
This adapter implements the existing Backend16.9
`Backend16StagingPrincipalVault` contract. There is no Railway or
production configuration change, no SQL migration and no HTTP endpoint.

## Threat boundary

Previously, the physical Bun.SQL pool accepted an injected credential
resolver, but there was no standalone adapter that tied each approved
physical PostgreSQL `LOGIN` to an **exact immutable secret version**.

`createBackend16StagingVersionedPrincipalVault` takes:

- An operator-reviewed, sorted, static manifest of distinct
  `pgLogin` -> opaque `secretId`, immutable `version` records;
- A separately approved SHA256 fingerprint of the canonical manifest;
- An external **server-only** `readVersion(secretId,version,signal)`
  provider with permissions limited to **get exact ID + exact version**,
  with no list, discover, create, update, delete or credential-rotation
  privilege in the request runtime.

The source is not a vault product, persistent store, IAM configuration,
operator signer, certificate authority or provisioning mechanism.
The provider is **not implemented here**. No passwords or arbitrary
secret URLs are accepted from the JWT, request, tenant, or environment.

## Manifest pin / rotation

Canonical SHA256 preimage, with ASCII-ascending LOGIN order and without
any secret material:

```ts
JSON.stringify({
  schema: 'backend16-staging-vault-v1',
  entries: manifest.entries.map(e=>[e.pgLogin,e.secretId,e.version]),
})
```

Each `secretId` must match
`b16-stg-pg-[a-z0-9_-]{16,80}`, `version` is 32–64 lowercase
hexadecimal characters, all LOGINs are unique, and at most 128
principal entries are permitted. Privileged PostgreSQL identities
(`postgres`, migrator, runtime roles, and `pg_*`) are rejected.
The expected digest must originate from a **separately reviewed
release manifest**, not be generated on the fly from untrusted API
parameters. Both values provided by the same attacker are not a proof
of trust.

### Backend16.19 — immutable approval and provider reference

The source-only adapter now accepts **exactly** the `manifest` and
`source` fields. The manifest has exactly `entries` and
`approvedManifestSha256`. Extra fields or getter/prototype-bearing
approval records are refused; in particular **no caller-provided
`nowMs` clock** is accepted in runtime configuration. Freshness
checks use the system `Date.now()` at each credential acquisition.

The approved SHA256 and exact provider's `readVersion` function are
captured **synchronously before the first SHA256 `await`**. Even if
an external config object changes while hashing is pending, a wrong
initial digest must not become approved, and an approved provider
must not be silently exchanged for a different secret reader. The
canonical per-principal manifest entries are also copied and frozen
before verification. Provider records must be ordinary own-data
objects, not accessor/prototype-bearing credential wrappers. Real
operator approval and provider IAM remain independent prerequisites.

Synthetic CI tests exercise digest replacement, provider substitution,
malicious manifest accessors and inherited response fields. These are
pure JavaScript contract tests, **not** proof of a deployed or
approved external vault.

Rotate by preparing a new version of the *same* external secret, review
and pin a new release manifest, and switch composition only after
physical old-connection drain and operator review. Do not accept
mutable versions like `latest` or a fallback secret after revocation.
Any revocation or disabled secret must cause the upstream provider to
return null/error; no cache in the adapter may continue authorizing it.

## Every physical connection / failure handling

Each `readPrincipal(pgLogin,signal)` resolves only the manifest entry
and calls `readVersion` anew. The returned object must have EXACTLY
`username, password, version, expiresAtMs`. Username/version must
match the pinned request; password is a bounded printable 32–256
character value; the provider's **short-lived credential snapshot
lease** expires in 1–5 minutes from the checked server clock.
This is a *snapshot freshness lease*, **not proof of the PostgreSQL
role's password expiration or server-side vault revocation**.

External lookup timeout: 4500 ms, independent of caller cancellation;
a provider that ignores abort does not block the caller indefinitely.
Provider messages/stack traces are redacted by returning only a generic
failure. No automatic retries, caching, secret enumeration, logging,
SQL queries or network requests are implemented by the adapter.
The existing physical pool still verifies exactly the PostgreSQL
`session_user` on its dedicated `max:1` backend, with quarantine on
uncertain authentication, query or physical close.

JavaScript strings are not reliably zeroizable. A real external secrets
implementation must separately enforce key protection, transport mTLS,
server identity, IAM, rotation, revocation, secure service identity and
audit of secret access. It must not return a secret after its lease has
expired or after revoked operator approval.

## Not yet cleared for staging or production

- No actual external provider/IAM, versioned secret records, credentials
  or operator-controlled manifest signature have been provisioned.
- No verified private-network PostgreSQL CA/SAN handshake exists yet;
  Backend16.10 still refuses an unapproved TLS root.
- SQL0008 was installed **once** on permanent staging PostgreSQL16 on
  2026-10-19 and independently reconciled as **INSTALLED**, sealed,
  with eight receipts: installer deployment
  `36fb4858-3d5b-4c15-a115-ba4a2a56cba6`, independent
  read-only postflight `623f00ff-92f0-4fb5-9a91-d7ba0d33a3df`.
  The one-shot installer was then deleted. Evidence:
  https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/53#issuecomment-6265741781 .
  **Never rerun SQL0008 or recreate its installer.** This migration
  does not itself satisfy signed release or runtime approval.
- Independent OIDC session-authority, per-principal live grants, durable
  off-host audit, private service deployment, real staging E2E and
  release review are separate blockers.
- Never modify production Core/Gateway, `custom-no-apikey-fun`,
  `/data` or permanent staging PostgreSQL/volume from this phase.

**CI contract:** `tests/saasBackend16StagingVersionedPrincipalVault.test.ts`
checks canonical pin, exact secret-ID/version/LOGIN binding, freshness
limits, operator digest/provider snapshot across asynchronous SHA256,
rejection of caller clocks and accessor/prototype records, provider errors,
revocation observation, caller abort while source is hung, and absence
of HTTP/SQL/migration capabilities.

## Physical PostgreSQL16 E2E (disposable GitHub Actions)

The existing `verify-backend16-bun-physical-pid-ci.ts` now supplies the
version-pinned adapter to the **same staging physical-query core** under
the strictly local-only disposable PostgreSQL16 profile. The test's
provider returns synthetic per-principal passwords only after matching
the exact static secret ID and immutable version; each new PG backend
requires an independent provider lookup. It then verifies the unchanged
exact-session SQL0008 predicate, tenant isolation, backend PID death,
read lock cancellation/revocation and fresh-pool recovery.

This is real PostgreSQL/Bun.SQL validation of adapter *composition*,
not proof of a live external secret manager, actual Railway certificate
identity, permanent staging SQL0008 installation, or production
authorization. No fixture password, database URL or IAM token is
published by the adapter.

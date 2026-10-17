# Backend16.10 — operator-pinned PostgreSQL16 TLS identity (staging)

**Status: source-only / UNMOUNTED / NOT APPROVED for a live staging or
production connection.** This work is stacked on Backend16.9's physical
PostgreSQL driver. No SQL migration or Railway configuration is changed.

## Why it exists

Backend16.9 initially configured Bun.SQL with `tls:'verify-full'` but
had not supplied a separately reviewed trust anchor for the actual
`postgres.railway.internal` server. A stock Postgres SSL template may
present a self-signed certificate or a leaf certificate whose DNS SAN
does not match the private hostname. An encrypted preflight using
`tls:'require'` is **not** TLS server identity verification.

Backend16.10 makes **absence of approved root CA an immediate startup
failure** in `createBackend16StagingBunPhysicalPgPool`. The selected
Bun.SQL TLS options contain only:

- `ca`: exactly one operator-approved, strong, self-signed root CA PEM;
- `serverName`: the hardcoded `postgres.railway.internal`;
- `rejectUnauthorized:true`: TLS chain and hostname verification.

Bun's documented PostgreSQL TLS object with a custom CA selects
`verify-full`; the hostname is never read from HTTP, JWT, `Host`,
connection strings, environment variables, or tenant configuration.

## Release inputs (not yet available)

The server-only operator composition must supply
`Backend16OperatorApprovedPgCa` to
`createBackend16StagingPgTlsTrust` **before** constructing the physical
pool:

1. The actual private PostgreSQL server's root CA certificate, read and
   independently verified out-of-band. It is public trust material, not
   a PostgreSQL user password.
2. Its independently reviewed 64-character, lowercase SHA256 digest of
   the certificate's **DER** bytes, pinned to an approved release
   manifest. The CA and digest must never be accepted from a single
   untrusted request or generated at startup.
3. A certificate chain + DNS SAN handshake check performed from the
   private staging network for `postgres.railway.internal`, archived
   with the approved CA thumbprint and actual staging deployment ID.
4. A controlled certificate issuance/renewal process with pin rollover,
   expiry monitoring, revocation policy and independent reviewer.
5. Independent per-principal credential vault, live issuer/session
   authority, SQL0008 installed state, and off-host audit. These are
   **separate** required release gates.

The trust constructor checks exact PEM framing, only one CA, DER
SHA256 equality, CA basic constraints, a valid self-signed signature,
strong RSA (>=3072 bits) or reviewed NIST EC curves, and at least
seven days of remaining validity. Errors disclose neither CA material
nor authentication secrets. Staging pool creation rechecks trust
expiration, branded object provenance, exact Railway service IDs,
private-only flags, and rejects an insecure
`NODE_TLS_REJECT_UNAUTHORIZED=0` override.

The *test-only* certificate at
`tests/fixtures/backend16-synthetic-root-ca.pem` is deliberately
isolated: a public **synthetic** root, not a production trust anchor.
Its private key was not committed and must never be provisioned on
Railway. A green CI run proves that the offline trust-policy parser
operates as intended; **it does not prove the Railway server SAN or
certificate chain**, and cannot authorize deployment.

## Immutable boundaries

- No modification to SQL0001–SQL0008, database schema/roles/data,
  Railway staging DB/volume, or production Core/Gateway /data.
- The local disposable GitHub PG16 profile **remains separate**, with
  no TLS exception available to a staging/production caller.
- There is no public HTTP endpoint, no credential discovery, no TLS
  downgrade, no SET ROLE, no fallback to a shared login and no retry
  after uncertain COMMIT.
- If the present Railway PostgreSQL certificate fails chain or
  hostname validation, **STOP** and arrange reviewed certificate
  provisioning. Never weaken `verify-full` to bypass a failed SAN.

Reference: https://bun.com/docs/runtime/sql (PostgreSQL SSL mode and
custom CA sections). Real staging/production rollout still requires
complete Backend16 release gates and separate approval.

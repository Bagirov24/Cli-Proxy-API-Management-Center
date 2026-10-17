# Backend16.12 — observe the live staging PG16 TLS peer without a credential

**Scope:** Railway staging **only**, private hostname `postgres.railway.internal:5432`.
**Status:** isolated certificate-only observation candidate. This is **NOT**
PostgreSQL authentication, a secrets source, a certificate trust pin, or a
reason to allow an application to publish tenant data.

## Observation protocol

Source: `scripts/saas-staging/backend16-pg-tls-peer-observation.ts`.

The new one-shot Function sends only the 8-byte PostgreSQL protocol
`SSLRequest` (int32 `8`, int32 `80877103`), requires the one-byte
`S` reply, and negotiates TLS to fetch the *public server certificate*.
No PostgreSQL StartupMessage, LOGIN, database name, password, OAuth token,
SQL statement, HTTP listener, migration or writable transaction is ever sent.

This probe intentionally uses `rejectUnauthorized:false` **solely for
observing a possibly self-signed certificate on an unauthenticated
connection**. It transmits **no credentials**. A successful handshake proves
only that an endpoint presented a particular certificate, not that it is
the genuine PostgreSQL server. The real Backend16.10 PG driver must remain
`rejectUnauthorized:true` with separately operator-approved root CA
and a matching private DNS SAN. Never reuse the probe as a DB connection.

Output is restricted to SHA256 of peer DER leaf/issuer certificate,
whether a *DNS SAN* matches the exact private hostname, leaf validity
at observation time, expiry, TLS protocol and mandatory
`unverifiedChain:true`. No PEM, private key or identity/login data
is logged. A host mismatch logs a STOP marker but does not attempt
fallback or alter certificates.

## Safe isolated execution plan

1. Independently review source/CI and require **exact-head** success.
   Record the commit and the source's GitHub file SHA.
2. Confirm Railway project
   `a9703851-6eb1-406c-bb15-7d3a89359fb7`,
   environment `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`,
   name `staging`, with no pending PostgreSQL/volume/Core/Gateway patch.
3. Stage a **new** Railway Function named
   `saas-b16-pg-tls-peer-probe` with the exact one-file source,
   **no domain, TCP proxy, cron, volume, shared variables, API tokens
   or PostgreSQL credentials**. The only per-service variable allowed is
   `SAAS_B16_TLS_PEER_PROBE_EXPLICIT_ENABLE=true`.
   Preview the full staged patch and refuse unrelated resources.
4. Deploy the Function-only patch, require terminal deployment
   status, and record sanitized runtime markers and the SHA256 evidence
   without treating them as trust approval.
5. Reset the enable variable to `false` and redeploy the single
   Function with a reviewed patch. Confirm its terminal state and no
   further live probing.
6. Have an independent operator provision or approve a CA and a DNS SAN
   for the private hostname. Archive a **separate** verified-full
   authenticated TLS handshake using the approved CA and a known
   non-privileged principal, with safe redacted evidence.

**If SAN or chain is missing, stop:** arrange controlled PostgreSQL
certificate issuance/rotation with an operator-approved CA and rollback
plan. This may restart PostgreSQL and is **not** authorized by this probe.

## Invariant constraints

- No changes to SQL0001–0008, migration receipt or schema migrator.
  Permanent staging SQL0008 was last observed ABSENT via an independent
  read-only probe; the one-shot installer's `Restart Policy = Never`
  is unverified and still blocks SQL writes.
- No production Core/Gateway, `custom-no-apikey-fun` or volume `/data`
  changes. Never touch the existing staging PostgreSQL volume.
- This runbook does not replace the real versioned secret service (PR60),
  OIDC session authority, independent audit, backup/PITR or release review.
- A certificate fingerprint taken from an unverified peer MUST NOT be
  promoted automatically into an operator-trusted CA pin. Trust requires
  independent verification, not trust-on-first-use.

References: PostgreSQL Frontend/Backend Protocol SSLRequest and TLS
handshake, and Node TLS certificate SAN identity check.

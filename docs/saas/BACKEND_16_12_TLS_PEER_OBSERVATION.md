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


## Observed private staging result — 2026-10-17 UTC

This is a **public-certificate, no-credentials** observation of a private
network peer, not proof that a trusted PostgreSQL server was reached.

| Field | Observed evidence |
| --- | --- |
| GitHub source HEAD | `8bf3dcfae5413cb369ac69fa63f4eaeaa32f5a31` |
| Source blob SHA | `b8a32714e7025d350bd3c00d3c994f0ae374b159` |
| Exact-head CI | 6/6 SUCCESS |
| Staging-only patch | `03139592-d502-43af-8cba-d96339ea435e` (no Postgres/volume modifications) |
| Probe service | `25c0e001-40a6-4b69-a1c7-94be39a872c1` |
| Certificate observation deployment | `08cdd4e2-93eb-4d0d-940b-8530c9a04153`, SUCCESS |
| Leaf DER SHA256 | `de0dfc96c1a6daee914b30f4b7e7453a74d641df34ca52e22976b919a4687948` |
| Issuer DER SHA256 | `807ddbbe843a01e4495860c24c8477ad288b7c8acacccc7c8fa435857a6f22d2` |
| Private host / DNS SAN | `postgres.railway.internal`, SAN present and **matched** |
| Leaf validity | Valid at observation; expires `2029-01-13T09:42:26Z` |
| Leaf is CA | `false` |
| TLS | `TLSv1.3` |
| Certificate chain authenticated | **NO** (`unverifiedChain=true`) |
| PostgreSQL StartupMessage/password/SQL | **NONE** (`noCredentialsOrSql=true`) |
| Disable deployment | `e51a3878-8919-4f5f-8089-7b719ecbe09b`, SUCCESS |
| Disable evidence | Explicit-enable changed to false; startup emitted `B16_TLS_PEER_PROBE_REFUSED_NO_DATABASE_AUTH`; `restartPolicyType=NEVER` |
| Remaining Railway patch | None |

The no-credential probe itself printed
`B16_TLS_PEER_OBSERVED_CERTIFICATE_ONLY_NO_SQL` followed by
`B16_TLS_PEER_HOST_AND_VALIDITY_OBSERVED_CA_UNAPPROVED`. It returned
public digests, DNS SAN and clock evidence. This **refutes the working
hypothesis that the observed leaf omitted the private hostname SAN**,
but not the possibility of a forged or misconfigured TLS peer.

The disable deployment intentionally fails closed with a generic refusal
before opening a socket; the Railway deployment record reports SUCCESS,
which is not proof that a normal application server started. No recurring
cron, listener, credentials or permission to retry exists.

**Next release gate:** an independent operator obtains the actual trusted
root CA (not merely this untrusted peer's claimed issuer), compares its
DER fingerprint with independently approved trust records, proves the
issued chain and private DNS SAN using `verify-full`, archives certificate
rotation/expiration controls, and validates a real least-privileged
PostgreSQL LOGIN. The certificate observation alone cannot authorize a
production connection. SQL0008 and off-host audit remain separate gates.

# Backend16.14 — PostgreSQL verified-full TLS proof without DB authentication

**Status: source-only / unmounted, awaiting independent root-CA approval.**
This is NOT the final release, migration or production permission.

## Scope and hard separation

Backend16.12 established that a peer on the staging private network presents
a certificate with a DNS SAN for `postgres.railway.internal`. Its TLS handshake
was deliberately unauthenticated (`unverifiedChain=true`). **Those observed
leaf and issuer SHA256 fingerprints are not trust anchors** and must never
be used automatically as a root pin or proof of PostgreSQL server identity.

Backend16.14 adds
`src/features/saasBlueprint/controlApi/server/backend16VerifiedPrivatePgTls.ts`.
It sends the PostgreSQL protocol SSLRequest (**only eight application bytes**),
expects exactly one `S` response, then negotiates TLS 1.2/1.3 with
`rejectUnauthorized:true`, the fixed private SNI, a separately approved CA
and a custom `checkServerIdentity` requiring a DNS SAN matching the private
hostname **without Common Name fallback**. The verified TLS chain must have
`authorized===true`, the leaf must be time-valid, and the root trust must
be an unforgeable branded object returned by Backend16.10's operator-approved
CA validation.

The module never sends PostgreSQL StartupMessage, database name, LOGIN,
password, token, SQL or tenant data. There is no HTTP ingress, listener, cron,
retry, plaintext fallback, auto-trust-on-first-use or untrusted discovery.
All rejection messages are deliberately generic. On cancellation, protocol
error or any TLS failure the single socket is destroyed.

## Where the root CA must come from

The **operator**, not the certificate-only observation, must obtain the
genuine root CA public certificate from an independently authenticated
Postgres administrative or certificate-provisioning channel. Separately
approve the SHA256 of the CA DER bytes in an immutable reviewed release
manifest. Do not derive both certificate and expected digest from one
attacker-controlled source, a peer TLS handshake, API headers or JWT claims.

Compose the approved trust using
`createBackend16StagingPgTlsTrust({caPem,approvedCaDerSha256})`.
The trusted object must be passed to
`verifyBackend16StagingPrivatePgTls(trust,abortSignal)`, with the
exact staging project `a9703851-6eb1-406c-bb15-7d3a89359fb7`,
environment `b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`,
service name `saas-b16-pg-verified-tls-once` and explicit per-service
`SAAS_B16_VERIFIED_TLS_EXPLICIT_ENABLE=true`. It refuses production
and GitHub Actions environments. **No new Railway Function or variables
are deployed by this PR.** Before any staging deployment independently
review the source, trust manifest, operator identity and the entire
Function-only Railway staged patch.

Success returns public leaf DER/root DER hashes, hostname, TLS protocol,
observation time and `tlsChainAuthorized:true`, but **always**
`productionAuthorized:false` and `noPostgresqlCredentialsOrSql:true`.
An actual least-privileged PostgreSQL LOGIN, SQL0008 catalog state, bearer
session authority, off-host audit and recovery remain separate gates.
Do not confuse verified TLS server identity with authenticated database
authorization.

## Disposable CI acceptance

`scripts/saas-staging/verify-backend16-verified-private-pg-tls-ci.ts` generates RSA private
keys and temporary certificates in an ephemeral local test directory,
using OpenSSL from the GitHub runner. Private keys never go into Git,
build artifacts, Railway variables or logs; the test erases temporary
files after completion. A loopback fake PostgreSQL server accepts only
the literal eight-byte SSLRequest and then upgrades to a real TLS socket.

The Node 24 transport test verifies a valid signed leaf using a pinned synthetic root and
denies a different root, wrong hostname SAN, **CN-only certificate**,
plaintext `N` SSL rejection, a hung server after abort, unbranded CA
objects and malformed local ports. TLS SNI remains the exact private
hostname even when the TCP socket is loopback.

The isolated acceptance runner executes under **Node 24** with
TypeScript stripping rather than Bun's auto-discovered `*.test.ts` process.
The real loopback OpenSSL/TLS chain test therefore validates the Node TLS
transport and security invariant; a separate Bun bundling check validates
that the same source builds for Bun. A second isolated CI runner, `verify-backend16-bun-tls-client-ci.ts`,
runs the **actual Bun TLS client** against a separate Node 24 SSLRequest/TLS
fixture (`backend16-ci-node-pg-ssl-sidecar.cjs`). It uses synthetic CA
and leaf certificates and checks acceptance plus wrong-root, wrong-SAN
and no-SSL denial. This exercises Bun's client handshake without relying
on Bun's unsupported synthetic server-side TLSSocket upgrade.

**Neither local Node nor Bun test proves the real Railway PostgreSQL
server's CA identity or its live authenticated connection.** The private
staging root/handshake and independently signed operator evidence are still
mandatory before staging SQL/data access. The disposable CI entrypoint requires GitHub Actions and three
positive CI-only environment gates, and refuses all Railway IDs.
It is not a staging fallback. CI root keys are not approved real roots.

## Remaining release blockers

- Actual independently approved root CA and a successful private Railway
  verified-full handshake, accompanied by independently archived evidence.
- Real per-principal versioned secret provider/IAM/rotation (PR #60 is
  source-only) and physical least-privileged PostgreSQL authentication.
- Live OIDC session authority; independent durable off-host audit;
  installed-mode SQL0008 readback and one-shot execution discipline.
- Confirmed recoverability/restoration before any irreversible database
  operation, private multi-tenant E2E and separate security/operations
  release review (PR #62).
- Production Core/Gateway `custom-no-apikey-fun` and `/data` remain untouched.

This source does not authorize SQL0008 writes, a Railway deploy, trust
downgrade or any change to production services.

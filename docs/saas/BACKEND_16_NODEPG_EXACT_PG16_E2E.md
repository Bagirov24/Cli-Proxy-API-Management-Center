# Backend16 — Node24 same-socket PostgreSQL16 exact-session RLS acceptance

**Status: SOURCE-ONLY / CI-ONLY, not a release, staging deployment or
production-enabled adapter.** Stacked on Draft #77 / #76 / #75. Keep the
native Bun.SQL trust hard stop from #76. No reviewed Node runtime package
has been added to the app or its Bun.lock.

## Security experiment

After the independent real Node24 TLS peer experiment in #77, this
increment adds a **different** source-only physical PostgreSQL16 pool
behind createBackend16DisposableCiNodePgPhysicalPool. It shares the
previously reviewed Backend16 exact-subject/session/tenant SQL allowlist
and createBackend16ExactSqlReadPort, but uses a new PostgreSQL client
per physical LOGIN (node-postgres 8.23.1 installed in GitHub runner /tmp).

The pool:
- Refuses every non-GitHub CI environment and any Railway IDs, production,
  TLS verification disablement, wrong disposable DB sentinel or unbranded
  CA object; there is NO staging/production constructor or arbitrary host.
- Acquires exact immutable-version secrets from an injected trusted
  vault and checks exact LOGIN mapping for every connection.
- Connects only to a loopback fixture, pins the *PostgreSQL TLS identity*
  to postgres.railway.internal through Node24 TLS options, CA validation
  and the exact-DNS-SAN callback; no trust-on-first-use or fallback.
- Uses a dedicated client/socket per requested physical principal;
  no SET ROLE, shared runtime LOGIN, public listener, dynamic SQL or
  automatic retry. It only accepts the existing SQL0008 transaction
  sequence and parameters.
- Rejects cancellation, failed or unknown COMMIT, stale trust,
  malformed result, owner-revoked connection and TLS mismatch with
  synchronous pool quarantine and physical stream destruction.
  Successful reads may publish only after acknowledged COMMIT and close.
- Does not prove backend identity with a disconnected TLS-only probe.

## Actual disposable PostgreSQL16 end-to-end acceptance

Inside the existing one-off **throwaway** GitHub Postgres:16.6 test
database, after the unchanged SQL0008 CI fixture and before synthetic
revocation, the Node24 runner creates a temporary private root CA and
an exact-SAN server certificate, enables SSL *in that GitHub container
only*, and uses two independently authenticated PostgreSQL LOGINs.

Assertions include:
- Successful A→tenant A, B→tenant B reads, with exact session UUID,
  binding, subject digest and committed FORCE RLS tenant/project rows.
- Both cross-tenant directions are denied; no authenticated subject
  connection remains after each read.
- The same physical LOGIN's backend PID is observed under pg_stat_ssl
  as TLS-authenticated; discard actually terminates that PID.
- An unrelated approved-but-wrong CA and CA-valid wildcard server
  certificate both prevent database authentication.
- A real FOR UPDATE lock versus exact-session FOR SHARE blocks the
  read; AbortSignal destroys the physical backend PID without leaking a
  successful response. The second principal remains independent.
- At least one fresh exact secret-version resolution per connection.
  Secrets and private-key contents never enter logs or Git.

The existing Bun.SQL native TLS negative experiment from PR #76 is
still expected to FAIL and blocks its staging factory; a separate
green Node adapter proof does not retroactively make Bun secure.
A full set of exact-head CI, independent review, lockfile-tested
production dependencies and separately reviewed staging integration
are required before replacement.

## Still missing from production

The original #78 test used an *in-memory synthetic provider*. A new
stacked CI-only increment adds a genuine **loopback mutual-TLS secret broker**
feeding that same version-pinned vault and Node24 physical PostgreSQL16
TLS/session/RLS path. This is still NOT real external broker IAM, durable
secret rotation or Railway private deployment. Remaining gates include
real operator-approved root CA,
workload client certs/secret rotation, issuer OIDC, durable audit/WORM,
multi-replica cancellation and session fences, PITR/DR, signed release
evidence, private domain/listener review, tenant IDOR, canary/rollback,
CPA/Gateway integration and permissioned production deployment.

Neither this code nor green CI authorizes SQL0008 replay in permanent
staging; no Railway project/service/volume, production Core/Gateway,
custom-no-apikey-fun branch, /data or credentials may be touched.
This stage NEVER enables a public SaaS API or production data access.


## Stacked combined broker → verified PostgreSQL16 read (CI PENDING)

A separate source-only increment drives the existing Node24 exact-session
RLS acceptance through createBackend16DisposableCiMtlsSecretReader.
The broker service is a 127.0.0.1-only Node HTTPS fixture in the same
disposable GitHub Actions runner, with its own independent synthetic
RSA3072 root CA, a verified clientAuth certificate and exact private
broker DNS SAN. It only allows the two pinned synthetic principal
secret IDs and exact immutable versions. Its response is a bounded,
canonical no-store JSON secret lease; passwords/private keys never go to
Git and should never be printed in logs.

The transport chain under test is:

- mTLS workload client → synthetic exact-version broker;
- createBackend16StagingVersionedPrincipalVault → fresh secret per physical LOGIN;
- Node24 pg@8.23.1 CI-only client with independent pinned PostgreSQL CA,
  verified exact DNS:postgres.railway.internal SAN and no downgrade;
- physical PostgreSQL16 LOGIN/SSL PID → SQL0008 current session/binding →
  FORCE RLS tenant/project read → acknowledged COMMIT → physical socket close.

Negative tests also require wrong secret versions, expired leases, and
revocation of the client approval while a real mTLS response is held
to refuse before any PostgreSQL login. Wrong PostgreSQL CA, CA-valid
wildcard SAN, cross-tenant reads, FOR UPDATE/FOR SHARE cancellation and
backend PID discard remain in the same real PostgreSQL CI run. The
script must report explicit positive and negative markers on its exact
head before even limited CI acceptance.

This is evidence of genuine protocol connections with **ephemeral
synthetic** identities, not external IAM, off-host high-water/WORM,
independently provisioned keys, live OIDC session authority, signed
production release approval or complete application/CPA integration.
The permanent Railway SQL0008 installer must never be re-run. The
native Bun.SQL same-socket TLS-negative test from #76 remains RED:
NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false. This experiment
must not bypass, edit, or skip that security blocker to produce
superficially green CI. Real transport replacement is separately
reviewed and production is blocked.

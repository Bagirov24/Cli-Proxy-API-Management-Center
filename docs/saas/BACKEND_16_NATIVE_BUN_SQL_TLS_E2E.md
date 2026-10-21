# Backend16 — native Bun.SQL authenticated TLS on disposable PostgreSQL16

> **Post-merge status (2026-10-21):** The RED observations below remain valid for stable Bun 1.3.14 and 1.4.3. The independently SHA512-pinned **CI-only** upstream `1.4.4-canary.1+6bb5dc195` passed real disposable PG16 TLS-negative acceptance on main `b0fd2b66fba5fc93c4e669ba4240fe38aef9c40e` ([run 39486761812](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39486761812)). Production/runtime trust is still **not approved**; `NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` remains the staging hard stop. See [owner integration](BACKEND_16_OWNER_INTEGRATION.md).

**Status: SECURITY BLOCKED / RED.** Stacked CI-only Draft, unmounted/default-off.
Native Bun.SQL PostgreSQL server identity is NOT verified by the required
same-socket negative tests. This is neither production ready nor authorization
for any staging deployment, Railway changes or merge.

## Gap addressed

Backend16.14's SSLRequest-only transport verifier proves TLS peer identity
without DB authentication. Backend16.10 / PR #75 supplied an exact DNS SAN
callback on the native Bun.SQL TLS options but, until this follow-up, no
disposable PostgreSQL16 read had used those TLS options on the physical
authenticated tenant-RLS connection.

The new standalone GitHub runner test is invoked after the existing
Backend16.7/16.9 physical two-principal acceptance and BEFORE test fixture
revocation. The fixture reuses the identical unmounted native Bun.SQL
physical/query/discard code and the version-pinned credential vault adapter.

## Isolation and acceptance

- Must run under explicit GitHub Actions / ephemeral / physical TLS flags with
  fixed PGHOST 127.0.0.1, port 5432, disposable database marker, and the
  exact GitHub postgres:16.6 service container ID. Refuse Railway project,
  environment or service IDs and production / disabled certificate checks.
- Generate a synthetic RSA3072 root, independent untrusted root and valid
  / wildcard RSA2048 server leaf certificates in runner-local temporary
  storage. The script changes SSL configuration only in that ephemeral
  PostgreSQL16 service container and wipes local fixtures afterward.
- A fresh branded CA trust object uses the fixed SNI
  postgres.railway.internal, strict exact DNS SAN, preserved native Node
  peer validation and rejectUnauthorized:true.
- Observe the physical LOGIN's pg_backend_pid() and the SAME PID's
  pg_stat_ssl.ssl=true + TLSv1.2/1.3 before demonstrating physical discard.
  Then read two tenant/project sets under the existing exact-session
  SQL0008 and FORCE RLS predicates; deny both cross-tenant directions
  and assert fresh versioned vault lookup per physical attempt.
- Reject the same server under an unrelated but correctly pinned CA,
  then reload a genuinely CA-signed wildcard server cert in the disposable
  container and prove actual native Bun.SQL connection denial without
  remaining authenticated principal backends. A generic mocked callback
  rejection alone does not pass this test.
- CI must show explicit positive and negative log markers on the exact PR
  HEAD, with full baseline RLS and remaining workflows still successful.


## Actual native PostgreSQL16 security evidence — 2026-10-20

The disposable, real physical PostgreSQL16 test was executed using
Bun 1.3.14 against the ephemeral GitHub postgres:16.6 container:
[PG16 #39386345179](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39386345179).
The positive checks **passed**: physical LOGIN and PID in
`pg_stat_ssl.ssl=true`, both authorized tenant reads, both cross-tenant
denials and connection discard. TLS *encryption* is established.

However all three **must-refuse** cases failed:
`B16_NATIVE_SQL_TLS_ALWAYS_DENY_CALLBACK_NOT_ENFORCED`,
`B16_NATIVE_SQL_TLS_WRONG_ROOT_UNEXPECTEDLY_ACCEPTED`,
`B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_UNEXPECTEDLY_ACCEPTED`.
The full CI job intentionally failed with a hard assertion.

To exclude a simple Bun 1.3.14 runtime-version issue, a **separate,
isolated** GitHub service test ran Bun 1.4.3 without updating the
repository's Bun 1.3.14 pin or touching the original database fixture:
[experimental PG16 #39387874219](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39387874219).
It confirmed:
- Valid CA and exact SAN: accepted, TLS enabled.
- Always-deny `tls.checkServerIdentity`: **ignored** for both
  `new SQL(options)` and `new SQL(url, options)`.
- Explicit `tls:'disable'`: honored; shows SSL mode selection is
  effective but does not prove certificate identity.
- Wrong root CA: **denied** on Bun 1.4.3 (improvement over 1.3.14).
- CA-signed wildcard SAN: **unexpectedly accepted** on Bun 1.4.3,
  despite strict exact SAN being rejected by the isolated callback.

Therefore upgrading to Bun 1.4.3 alone is **NOT** an acceptable fix.
The current native staging Bun.SQL factory is explicitly hard-stopped by
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false`.
Do not switch it to true based on mocks, an unauthenticated SSLRequest-only
handshake or `pg_stat_ssl.ssl=true`. The same physical authenticated
driver MUST reject independent wrong CA, CA-valid wildcard and
always-deny callbacks under actual PG16 before enabling any staging use.

A next independent, reviewed workstream should evaluate a maintained
PostgreSQL driver with demonstrably effective Node TLS peer verification,
credential isolation and physical connection discard; preserve the
existing exact-session SQL templates, RLS/admission, cancellation and
two-tenant acceptance. No fallback to `tls:'require'`, public proxy,
plaintext, unverified default trust or borrowed privileged LOGIN.
Only after these gates pass should the mTLS-broker→vault combination be
considered. The upstream Bun documentation describes callback support,
but **the exact runtime/build must be empirically verified**.

## Incomplete production gates

The current vault source in this increment is still a LOCAL SYNTHETIC
versioned reader; this is not yet a combined real mTLS secret-broker ->
versioned vault -> native Bun.SQL TLS -> PG16 tenant-RLS test. That is the
next isolated acceptance increment. All test identities are synthetic and
no live OIDC, workload IAM, root CA approval, durable audit/off-host witness,
PITR recovery, tenant-facing listener, Core/Gateway isolation, or canary
exists in this proof.

The historical SQL0008 is **never rerun on permanent Railway staging**.
The unchanged SQL0008 CI fixture is applied only to a newly created
throwaway PostgreSQL16 database by the pre-existing GitHub workflow.
No original migration or installer byte is edited here. No Railway resource,
production Core/Gateway, credentials, volumes or GitHub Release is changed.
Green CI is not an approval to merge, deploy or advertise production readiness.

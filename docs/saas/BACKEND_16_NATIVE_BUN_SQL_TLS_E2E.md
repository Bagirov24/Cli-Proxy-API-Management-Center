# Backend16 — native Bun.SQL authenticated TLS on disposable PostgreSQL16

**Status:** stacked CI-only Draft, unmounted/default-off. Not production ready
and not authorization for any staging deployment or Railway changes.

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

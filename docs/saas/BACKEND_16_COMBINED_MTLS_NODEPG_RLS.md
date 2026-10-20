# Backend16 — combined disposable mTLS broker → vault → PostgreSQL16 RLS

**Status: CI-only proposed acceptance; NOT production or staging deployment.**
Stacked Draft after #78, #77, #76 and #75. The native Bun.SQL TLS
security regression and its factory hard stop remain explicitly RED;
this separate Node24 transport is not a waiver or an automatic release.

## New executable boundary

A single Node24 runner, invoked by the existing isolated GitHub PostgreSQL16
workflow **after** SQL0008's disposable fixture install but **before**
the existing intentionally failing native Bun TLS security probe, connects:

1. A loopback `https.createServer` with genuine temporary CA/server/client
   certificates and `requestCert:true,rejectUnauthorized:true`. It verifies
   the exact approved client leaf SHA256 and permits only two fixed
   immutable-version GET secret paths. No list/search/write/redirect.
2. The real `createBackend16DisposableCiMtlsSecretReader`, using an
   independently pinned broker root CA, exact broker DNS SAN, matching
   client certificate/private key and runtime approval recheck.
3. The unchanged `createBackend16StagingVersionedPrincipalVault`,
   using a canonical, fixed two-LOGIN manifest digest, exact secret ID and
   immutable version. No unversioned secret or credential cache.
4. The unmounted `createBackend16DisposableCiNodePgPhysicalPool`
   (Node24, node-postgres **8.23.1 installed under CI /tmp only**),
   with *different* independently pinned PostgreSQL root/leaf identity
   and exact private hostname, per-principal physical session and
   SQL allowlist.
5. The existing `createBackend16ExactSqlReadPort`, requiring real
   PostgreSQL16 SQL0008 session/binding digest, current tenant grant,
   FORCE RLS, committed tenant/project data and no cross-tenant IDOR.

## Required checks

- A and B's separate physical LOGIN sessions each read their own tenants;
  both cross-tenant routes are denied. Every new connection causes a
  fresh authenticated mTLS request; no physical LOGIN is retained.
- Inspect `pg_stat_ssl` for the same physical `backend_pid` under the
  actual LOGIN; closing/poisoning that socket removes the PostgreSQL PID.
- Pause a **fully authenticated mTLS broker request** just before HTTP 200,
  revoke the local CI-only broker workload approval, then send a canonical
  secret response. The vault must refuse it and **no new authenticated
  PostgreSQL session** may be allocated, without retry or logging a secret.
- All certificate material is generated only in disposable GitHub runners
  and discarded. The exact GitHub service container is checked by Docker
  ID + postgres:16.6 image + disposable DB marker; no Railway IDs or
  global certificate bypass permitted. The permanent SQL0008 installer
  is never invoked, replayed or edited.

**Caveat:** The test broker's client-auth trust and local enable flag are
synthetic, not real workload IAM or a durable revocation authority.
Remaining genuine staging/release blockers include independently approved
CA and SAN policy, an operator-run secret broker with exact IAM grants
and durable audit/rotation, OIDC/session authority, signed release evidence,
PITR/restore, off-host immutable audit/WORM and UNKNOWN-COMMIT settlement,
multi-process isolation, private ingress and tenant IDOR, CPA/Gateway
network/egress isolation, recovery/load/canary and explicit independent
security/ops approval.

The package dependencies are not changed. No production Core/Gateway,
`custom-no-apikey-fun`, `/data`, permanent Railway staging PostgreSQL,
SQL0008, deployments, credentials, real volumes or live users are touched.
Existing native Bun TLS RED may keep the overall RLS workflow RED even if
this new narrow Node+mTLS proof passes: do not hide or skip that failing gate.

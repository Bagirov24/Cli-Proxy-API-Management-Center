# Backend16 P1 - combined official stable Bun mTLS-to-PostgreSQL16 candidate

**Scope:** disposable GitHub CI, `BLOCKED_RELEASE`, `NO RELEASE AUTHORIZATION`.
This follows PR #104 at `109c9966415193129655d2418e2574721b13785b`.
It tests the previously missing composition, not a new production server.
The official Bun 1.4.4 ZIP/revision installer, frontend `bun@1.3.14`,
`bun.lock`, existing canary, production modules and all TLS hard stops are unchanged.

## One actual credential path

The new Node24 supervisor reuses `startSyntheticBackend16MtlsBroker` from
`backend16-nodepg-synthetic-mtls-broker-ci.ts` without changing that fixture.
The fixture's historically named NodePG opt-in is needed to start the broker;
no Node `pg` client, dependency or production fallback is used by the new path.
The supervisor owns the two randomly generated disposable LOGIN passwords.
It launches the exact verified official stable Bun binary with an **allowlisted
child environment that contains neither principal password**. Only synthetic
broker PKI and its loopback port cross a private stdin pipe. No credential,
private key, raw response or untrusted diagnostic is forwarded to CI logs.
The known fixture administrator password remains available to observe PG state;
it is not supplied to either application LOGIN or the production pool.

Inside the stable Bun child the actual unmodified components are composed:

`createBackend16DisposableCiMtlsSecretReader` ->
`createBackend16StagingVersionedPrincipalVault` ->
`createBackend16StagingDisposableCiTlsPhysicalPgPool` ->
`createBackend16ExactSqlReadPort` -> authenticated SQL0008 / FORCE RLS.

Both tenant identities must read their own data and be denied the other tenant.
The test observes each actual PostgreSQL backend PID and `pg_stat_ssl` for that
PID, then requires physical disappearance after discard. Credentials are never
substituted by an in-memory source in the Bun child: its vault source is the
real mutually authenticated HTTPS reader. The source module release hard stop
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` remains intact.

## Mandatory adversarial execution

The same composed path rejects a broker response with the wrong immutable
version and an expired lease. Both must fail at the pool's VAULT phase, without
releasing a credential; the quarantined pool cannot acquire the other LOGIN.
For revocation, the broker holds an already-authenticated response. A bounded,
sequence-checked control protocol acknowledges that hold; the Bun child then
revokes its local CI workload approval before the parent releases the response.
A valid secret must not escape the revoked reader, and no application backend
may remain. This is a synthetic workload-approval race, not live IAM/OIDC proof.

A real PostgreSQL `FOR UPDATE` lock then blocks the composed tenant read's
`FOR SHARE`. Caller cancellation must terminate the observed backend and
quarantine the pool; a fresh pool must still authorize the other tenant.
Finally a separately minted, incorrect PostgreSQL root CA must be denied after
an authentic broker secret read. No TLS-negative assertion is removed or
marked expected-failure. Existing independent wildcard/callback/canary probes
run afterwards unchanged.

The supervisor requires exactly **12 authenticated exact-version broker GETs**,
8 for LOGIN A and 4 for B, with 9 credentials released by the vault. The three
invalid/revoked replies must release none. A fixed 13-command protocol refuses
extra/reordered/duplicated commands, unknown fields and noncanonical JSON.
Success requires child exit zero, no signal, the complete protocol and the
independent broker's exact receipt; a printed marker alone is insufficient.
Streams and process lifetime are bounded. The broker and synthetic keys are
cleaned up; the child restores and reads back `ssl=off` on the disposable PG16
service before the unchanged canary test starts. A failed child aborts CI.

## Routing and evidence

The existing full PG16 shell invokes this extra scenario before its canary
TLS tests and before its final SQL0008 revocation/no-ABA checks. A regression
removes only the delimited new block and verifies the previous shell Git blob
`09ae6983e3f87df3edd20d957a08f0b2706edb46` byte-for-byte.
Seven new regression tests extend the already-routed full-physical suite.
Native canary, stable candidate and cross-runner workflows watch all new
inputs and the reused broker fixture; the full PG16 workflow's existing
`scripts/saas-staging/**`, `docs/saas/**` and explicit test path cover them.
The physical shell requires each of the seven `B16_STABLE_144_COMBINED_*`
markers once, including `BLOCKED_RELEASE`, before proceeding.

## Remaining boundaries

This is not an independently signed publisher/build attestation, stable
runtime approval, complete server package/lock, reproducible executable or
runtime SBOM. Real operator PKI/IAM, current OIDC sessions, durable off-host
audit, PITR/restore, genuine tenant identities, rollback and independent
security/operations approvals remain unverified. The HTTP and DB services,
certificates and identities here are disposable fixtures. Process environment
filtering is a test of credential handoff, not an OS sandbox claim.

No production/staging deployment, Railway operation, permanent SQL0008 replay,
Core/Gateway change, release tag, PR merge or change of the 17-missing-proof P2
artifact contract is authorized by this test. Ready-for-review is not approval.

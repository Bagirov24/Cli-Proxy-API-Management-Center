# Backend 15 Phase B — private staging SQL 0007 one-shot installer

## Boundary

Scope: *only* Railway project \`cliproxyapi-saas-staging\` (\`a9703851-6eb1-406c-bb15-7d3a89359fb7\`), environment \`staging\` (\`b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b\`), PostgreSQL16 service \`37f8f166-75a6-4617-b243-8e681181c16d\`, database \`saas_staging\`. No public DB route. Never run SQL001–027 here. Staging holds disposable test data only; no real customer data. No production Core, Gateway, \`/data\`, \`custom-no-apikey-fun\`, live tokens or public SaaS API changes.

GitHub immutable SQL commit: \`6cc4a76a0b3144380ccc95f0ca1c275ae312cae3\`.

SQL \`staging/saas-bootstrap/0007_operator_subject_binding_fence.sql\` exact-byte SHA-256:
\`1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0\`.

The installer at \`scripts/saas-staging/backend15-subject-binding-once.ts\` downloads that immutable source, refuses redirects and mismatched bytes *before* any database connection, and interpolates only the three expected immutable psql attestation values.

## Gate before execution

1. On exact final feature-branch HEAD, all five workflows must be SUCCESS: Main CI; SaaS Staging RLS Contract / PostgreSQL16; SaaS Blueprint Demo Build; SaaS Blueprint Browser QA; Management release guard. Check PR mergeability, target \`main\` unchanged, then merge. An open PR, queued CI or green check on an earlier SHA does not authorize deployment.
2. Re-check real staging state and migration ledger **before** creating a Function. If 0007 already exists, STOP; do not launch installer again. PostgreSQL16 must be healthy, permanent volume mounted, and no unrelated staged changes. Do not assume a Railway SUCCESS status confirms migration.
3. Create one Railway *Function* named exactly \`saas-b15-binding-once\` in **staging only**, with the committed one-file installer as its complete source. \`staged: true\` for the initial create. No HTTP listener, cron, public domain, public TCP proxy, restart or retry. Set \`restartPolicyType=NEVER\`; \`cronSchedule=null\`. Review the pending patch; it may contain ONLY this temporary Function and its own config/variables, never changes to Postgres, volumes, \`saas-control-api\`, or another environment.
4. Function variables: \`SAAS_B15_APPLY_EXPLICIT_ENABLE=true\`, \`SAAS_B15_ACCEPT_DISPOSABLE_STAGING=true\` and \`STAGING_POSTGRES_PRIVATE_URL\` referencing **only** the Postgres service's private URL for \`postgres.railway.internal:5432/saas_staging\` as the PostgreSQL superuser. Do not expose resolved credential values in logs or PR. Railway-provided project/environment/name/service metadata must match exact pins.
5. Commit the reviewed patch once; never accept a patch containing other resources. Do not use the runner in production or pilot CI.

## Runtime behavior / read-back

The Function checks exact PG16 and writable staging DB, real PostgreSQL admin, expected \`saas_schema_migrator NOLOGIN PASSWORD NULL\` and unprivileged role configuration; all six migration receipts; no new \`saas_*\` roles or membership changes, unrelated DB connections, customer rows, grants/sessions/events; preexisting FORCE RLS, policies, functions, ACL and Backend14 triggers; and absence of Backend15 objects. Any mismatch is fail-closed **without** executing SQL.

Only after preflight, it activates the existing non-superuser migrator with an in-memory 32-byte cryptographic random password and five-minute expiry, runs the pinned SQL once in its transaction, then verifies the 7 receipts and expected source SHA/commit, existing schemas and roles, new tables, unique indexes, functions, five triggers, private ACL, empty data and FORCE RLS. The migrator is returned to \`NOLOGIN PASSWORD NULL\`; PostgreSQL's privileged \`pg_authid\` must confirm this. A single positive runtime marker is emitted only after full read-back and catalog sealing:

\`PASS_BACKEND15_STAGING_PG16_0007_SUBJECT_BINDING_FORCE_RLS_NOLOGIN\`

Required evidence: Railway deployment terminal \`SUCCESS\` **and** the exact positive marker in deploy/runtime logs, matching Function/service/environment IDs. No positive marker means migration is **not** confirmed even when Railway reports SUCCESS.

## Unknown COMMIT and cleanup

Every failure prints \`BACKEND15_STOP_UNKNOWN_COMMIT_RECONCILE_NEVER_RETRY\` and exits nonzero; this marker does **not** imply the transaction committed. The runner never retries. If network/disconnect/timeout causes an UNKNOWN COMMIT, **do not redeploy or rerun**. Independently reconcile the six/seven ledger rows, \`pg_authid\` migrator seal, schema, triggers and ACL using a separately reviewed operator-only diagnostic before any further action. The finalizer attempts best-effort sealing without issuing another migration. A failed seal also requires operator intervention.

After explicit positive Railway deployment and read-back evidence, save the Function/deployment IDs, immutable hashes, receipt summary and positive log marker in the PR Conversation. Then delete **only** the temporary Function in staging; verify PostgreSQL and its volume persist without changes. Do not delete the Postgres service or volume.

## Tests

\`bun test tests/saasBackend15PrivateOnce.test.ts\` is a no-Railway contract test. The pre-existing disposable GitHub Actions PostgreSQL16 suite already exercises migration \`0007\` and subject-binding RLS/revoke behavior; no test touches permanent Railway staging. This phase does not complete OIDC login or trusted tenant provisioning; that requires later security gates.

**Migration receipt author attestation:** SQL0003 creates the NOLOGIN runtime roles, so it is deliberately executed by the PostgreSQL `postgres` operator and its ledger `applied_by` is `postgres`. SQL0001, SQL0002 and SQL0004–0006 (plus SQL0007 when installed) must instead be authored by `saas_schema_migrator`. This exception is explicitly enforced in both preflight and read-back. Any other authorship is STOP, not a reason to retry.

## Recovery after missing Railway Function deployment (2026-10-17)

The original accepted staging patch did **not** yield a Railway Function deployment ID or migration-positive log, so its result was treated as UNKNOWN and it was **never redeployed**. Independently reviewed SQL0007 read-only reconciliation on the persistent staging PostgreSQL16 at 2026-10-17T09:07:23Z (deployment `afb8987e-82da-4539-b025-7461784e9d4a`) emitted `PASS_BACKEND15_READONLY_RECONCILE_0007_ABSENT_SEALED_NOLOGIN`. This independently verified exact six SQL0001–0006 receipts, no SQL0007 objects, clean FORCE RLS/ACL/triggers and a `NOLOGIN PASSWORD NULL` migrator **at that snapshot**. Evidence is in PR #47 Conversation.

A **new** direct-live Function (`saas-b15-binding-once`, exact service ID `8ab01c09-d9c3-4a48-af49-73f43dab579c`) has a harmless no-DB bootstrap deployment `c8d0b45e-1d6a-4889-8438-030ed50d2e2c`, positive `PASS_BACKEND15_INSTALLER_NO_DATABASE_BOOTSTRAP`, restart policy `NEVER` and no cron/public endpoint/volume. Its live variables are staged in-place with `skipDeploys:true`: private server-side password reference and hardcoded `postgres.railway.internal:5432/saas_staging`, plus explicit staging/enable flags. **The real SQL installer source has not been deployed at this point.**

Only after the exact final feature HEAD passes all required CI, source review and a fresh PostgreSQL gate may an independent operator approve **one new audited execution**, not a replay or redeploy of the orphan original Function. The new installer pins the exact new Function service ID and rechecks all six receipts, missing SQL0007 objects, no active conflicting clients, empty data and sealed migrator immediately before beginning a new transaction. Any failure/UNKNOWN COMMIT is STOP, not a reason to run this new Function again. A positive migration marker and catalog seal require a deployment-specific operator log and read-back. Production remains entirely out of scope and blocked by `PRODUCTION_READINESS_GATES_V1.ru.md`.

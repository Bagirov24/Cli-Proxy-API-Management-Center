# Backend16 — полный план до staging и production SaaS

> Зафиксировано 2026-10-21 по GitHub. Это план, не разрешение на
> deployment, IAM, миграцию SQL0008, Railway или GitHub Release.
> `CI_VERIFIED` != `LIVE_VERIFIED` != `PRODUCTION_APPROVED`.
> Все десять live signed release gates пока `LIVE_UNVERIFIED`.

## A. Проверенный checkpoint и границы

- `main`: `b0fd2b66fba5fc93c4e669ba4240fe38aef9c40e`.
- [PR #89](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/89):
  CI paths/Ubuntu-24.04/PG16 client pin,
  `a4a7fab747fcf87c3fdb225d06bc82c91743a5e2`.
- [PR #90](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/90):
  bounded Native Bun canary download and Native TLS paths,
  `f75503ce19bbd1485581028059fb97e4d166880c`, based on #89.
- [PR #91](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/91):
  locked standalone Node24 `pg` peer TLS probe,
  `0607a1ec4ba27f49234353a46c4b5eddc812fbd4`, based on #90.
- Additional PRs [#92](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/92)
  (roadmap, `e24bf070f153abbb12cd4f8a567b1bb07b004e3a`),
  [#93](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/93)
  (two frozen installed byte trees, `c9e10837f5758ac6759431c39bb5e2cc76328d59`)
  and [#94](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/94)
  (cross-runner comparator, `644507a813b283723c50bb57138dea9fea38bd41`)
  remain open; all six PRs #89–94 MERGEABLE/CLEAN with zero
  independent approvals as of this decision.
  `main` has `protected:false`; branch protection requires separate
  owner-authorized governance action.
- Exact #91 [Main CI 39573861124](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39573861124):
  **2152 pass, 43 skip, 0 fail**;
  [PG16/RLS 39573860910](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39573860910):
  39/39 steps success; [peer 39573860827](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39573860827):
  both independent locked Node24 pg peer TLS probes passed.
- This is disposable GitHub CI evidence ONLY. No live staging IAM,
  OIDC, broker, CA, off-host audit, restore/PITR, canary or release
  attestations are established by it.

Preserve the root `bun@1.3.14` and `bun.lock`. The SHA512-pinned
Native Bun `1.4.4-canary.1+6bb5dc195` is CI-only; stable Bun
1.3.14/1.4.3 had real TLS negative failures. The staging factory
keeps `NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false`.
The disposable Node `pg@8.23.1` graph has 14 packages and observed
canonical SHA256
`b5e2aa1735babcbca40748c0983a73c36c57488f96d857fd4087ae4e7a5341fa`.
Registry drift MUST fail closed; never auto-update the fingerprint.

## B. Stages to a private staging release (ordered by dependencies)

### P0. Review, merge, governance — READY_FOR_REVIEW

**Work:** independently review PR #89, then stacked #90 → #91 →
#93 → #94; review #92 (roadmap) separately atop #89, followed by
this Native Bun.SQL ADR. Respect real branch dependencies instead
of assuming every PR is on one linear branch. Resolve security comments,
check exact head/base SHA, all applicable
jobs, MERGEABLE/CLEAN, use matching-head merge protection and
observe new `main` CI/PG16 after each merge. With explicit owner
approval, enable GitHub required checks, branch protection,
CODEOWNERS/security reviews, and no privileged bypass.
**Evidence/owner:** maintainer + independent security reviewer.
**Done:** reviewed merges, no unresolved critical findings, protected
release branch and fresh post-merge CI. No live release authority.

### P1. Native Bun.SQL выбран — ARCHITECTURE_SELECTED_RELEASE_BLOCKED

**Архитектурное решение владельца (2026-10-21):**
[ADR Native Bun.SQL](BACKEND_16_P1_NATIVE_BUN_SQL_ADR.ru.md).
**Вариант A — Native Bun.SQL** единственный целевой физический
PostgreSQL16 transport Backend16. **Вариант B — Node24 pg**
сохраняется только как независимый CI-only security comparator,
**не** как production fallback. Выбор архитектуры зафиксирован;
stable runtime и live PKI не одобрены, поэтому **BLOCKED_RELEASE**.

**Работа:** после выхода подходящего стабильного Bun runtime с
точно закреплёнными revision, OS/arch и SHA512 — проверить
same-socket authenticated PG16 exact CA+SAN, обе формы SQL ctor
с always-deny callback, wrong-root, CA-signed wildcard denial,
physical PID discard, два tenant RLS, cancellation и отказ
при revocation. Canary `1.4.4-canary.1+6bb5dc195`
остаётся **строго CI-only**; stable 1.3.14 и 1.4.3 отказались
выполнять обязательные отрицательные TLS-тесты.
Не включать staging factory и не обновлять root `bun@1.3.14`
ради этого ADR.

**Файлы:** `backend16StagingBunPhysicalPgPool.ts`,
`backend16StagingPgTlsTrust.ts`,
`verify-backend16-native-pg-tls-ci.ts`,
`verify-backend16-native-tls-version-probe-ci.ts`.
**Done для runtime (ещё НЕ достигнуто):** independent stable
artifact/security review и полный physical TLS/RLS acceptance на
точном source+binary SHA без skip или обхода hard stop.

### P2. Воспроизводимая Bun server-only упаковка — BLOCKED_RELEASE

**Работа:** build из выбранной **stable Native Bun.SQL** версии,
отдельный от React/Vite Management Center server-only runtime
manifest/lock, exact binary/archive SHA512 и revision, SBOM,
provenance, подписанные immutable artifact receipts, OS/arch pin,
no install-script side effects, isolated credentials и bounded
clean startup/teardown. Никакой Node24 `pg` fallback в production
bundle, npm lockfile в корне Bun-фронтенда или floating canary.

Проверенные dual-lock/cross-runner Node `pg` CI и historical graph
оставить для независимого TLS/RLS сравнения, но не выдавать их за
одобренный Bun server artifact. Основные `bun@1.3.14` / `bun.lock`
пока неизменны.

**Файлы:** `backend16StagingBunPhysicalPgPool.ts`,
`install-backend16-native-bun-ci.mjs` (CI-only, не runtime
installer), `verify-backend16-native-pg-tls-ci.ts`,
`verify-backend16-native-tls-version-probe-ci.ts`,
новый отдельно reviewed server-only build boundary.
**Done:** reproducible stable Bun-only server build,
подписанные source+artifact receipts и независимое утверждение
package/runtime/security. Staging hard stop всё ещё регулируется
отдельными P3–P13 и не снимается этим этапом.

### P3. Live private PostgreSQL TLS/PKI — LIVE_UNVERIFIED

**Work:** operator-pinned root DER digest out-of-band, exact
`postgres.railway.internal` DNS SAN, live CA chain/expiry/rotation,
authenticated same-socket physical PG LOGIN PID and `verify-full`.
Must reject wrong CA, wildcard SAN, CN fallback, TLS downgrade.
**Files:** `backend16StagingPgTlsTrust.ts`,
`backend16VerifiedPrivatePgTls.ts`, physical pool.
**Done:** independent security signer and fresh live proof;
one isolated TLS probe without DB LOGIN does not pass.

### P4. Live mTLS broker, vault and per-LOGIN IAM — LIVE_UNVERIFIED

**Work:** genuinely separate broker trust root and client identity,
server get-only exact-ID+immutable-version IAM, two real least-privilege
LOGINs and rotation/revocation/expiry. No HTTP-supplied secret path,
tenant, identity or `latest` fallback.
**Files:** `backend16PrivateMtlsVersionedSecretReader.ts`,
`backend16StagingVersionedPrincipalVault.ts`.
**Done:** approved IAM policy, verified external secret versions,
wrong-version/expired/pre-auth denial, in-flight revoke and audit,
all observed independently on staging.

### P5. Real OIDC and current bearer-bound sessions — LIVE_UNVERIFIED

**Work:** reviewed issuer/audience/pinned JWKS lifecycle, private
enrollment/session authority shared across multiple instances,
exact raw JWT fingerprint and subject/binding checks. Test key
rotation, current grant revision, token-A revoke vs token-B,
subject logout, clock skew, old session/no-ABA.
**Files:** `backend16PinnedSessionAuthenticator.ts`,
`operatorPinnedOidcAccessVerifier.ts`,
`backend16ExactSessionSqlRead.ts`.
**Done:** real IdP + approved private authority and live revoke races;
a synthetic JWT and injected fake authority never count.

### P6. Fresh SQL0008 installed-catalog readback — LIVE_UNVERIFIED

**Work:** independently approved **read-only** permanent PG16
installed-mode readback: exact migration receipt SHA, sealed migrator,
function owner/grants, FORCE RLS, current session-binding and
privilege invariants. SQL0008 has an historical installed observation,
not a fresh signed 1-hour receipt. NEVER replay permanent SQL0008.
**Files:** `verify-backend16-exact-session-pg16.sh`,
`BACKEND_16_SQL0008_EXACT_SESSION.md`, reviewed read-only probe.
**Done:** signed DB-operator catalog proof; zero staging mutations.

### P7. Private read HTTP composition + network policy — LIVE_UNVERIFIED

**Work:** link real OIDC auth, real physical per-principal pool,
trusted SQL allowlist and private-only GET handler. Keep listener
unmounted until P1–P6 and the audit prerequisite are independently
proved. Origin/header/tenant IDOR and DTO allowlisting remain strict.
Network controls: private ingress, egress, DNS and SSRF restrictions;
never silently reach public DB or CPA production.
**Files:** `backend16PrivateTenantProjectRead.ts`,
`backend16PhysicalPgAdmission.ts`.
**Done:** no public route; denied cross-tenant lookups, cancellation,
COMMIT uncertainty and quarantined PID documented on live private path.

### P8. Real independent off-host durable audit/high-water — LIVE_UNVERIFIED

**Work:** tamper-evident, independent witness/outbox consumer,
durable fsync ACK, replay and rollback detection, redacted event
retention, independent service identity, secure operation/runbooks.
Solve publication vs revoke/COMMIT/remote ACK ordering explicitly;
synthetic localhost high-water does not satisfy live durability.
**Files:** existing `scripts/saas-staging/` witness/outbox contracts
plus separately reviewed server-only live service.
**Done:** off-host restart, crash/partition/tamper/replay drill,
fresh security attestation and independently archived proof.

### P9. Actual staging backup/PITR/DR proof — LIVE_UNVERIFIED

**Work:** isolated live restore to reviewed target, independent
backup policy, RTO/RPO, least-privilege readback, revoked-session
high-water/rollback behavior and signed operations receipt. Real
GitHub `pg_dump/pg_restore` is not live PITR or disaster recovery.
**Done:** verified independent operations restore drill, retention
and no resurrection of revoked sessions.

### P10. Real private two-tenant E2E — LIVE_UNVERIFIED

**Work:** two real enrolled identities, two physical LOGINs,
two tenants and secret versions, exact session/binding/subject RLS,
IDOR denial, lock contention and abort, wrong root/wildcard,
revocation between broker and SQL, lost COMMIT ACK,
no-ABA and physical PID disappearance. Reuse existing exact-session
tests as a suite TEMPLATE; generated CI identities are NOT live proof.
**Done:** source SHA + driver artifact digest + independently
observed redacted staging E2E with actual trusted services.

### P11. Canary safety, rollback, SLO/incident drills — LIVE_UNVERIFIED

**Work:** authorized private-only canary rehearsal, error budget,
bounded pools/timeouts, observability/on-call, rollback to safe
baseline with explicit fail-closed behavior after IAM, PKI or DB
faults. Never implicitly turn on a public SaaS listener.
**Done:** runtime reviewer signed rollback/incident receipt with
<=30-minute freshness, separate operations approval.

### P12. Archive and independently sign all release proofs — LIVE_UNVERIFIED

**Work:** independent operator keyset pinned out-of-band, exact
source SHA, proof URI, redacted proof SHA256, bounded freshness
and Ed25519 signatures for all eight technical gates P3–P11
including P6/P9. TWO final security and operations approvals must
be signed **after** the exact eight technical signed records, over
their complete v2 canonical bundle.
**Files:** `backend16ReleaseEvidenceGate.ts` and
`BACKEND_16_13_SIGNED_RELEASE_EVIDENCE.md`.
**Done:** all ten valid receipts pass offline verifier, which can
return `READY_FOR_INDEPENDENT_REVIEW` but always
`productionAuthorized:false`. No fixture signs live evidence.

### P13. Separately authorized private staging rollout — BLOCKED_RELEASE

**Work:** only after P0–P12 and a distinct human go/no-go, scoped
change window, exact reviewed server artifact and private canary,
monitored rollback and post-start receipts. This is not automatic
release; no GitHub tag, `railway up` or production Core/Gateway action.
**Done:** independent operations decision and live post-deploy
read-only/negative acceptance with rollback still available.

## C. Signed live-gate ledger: exact verifier order and freshness

Every row is deliberately **unverified live**. The operator,
cryptographic signer and independent archive verifier must provide
fresh real evidence; documentation edits cannot elevate status.

<!-- BEGIN BACKEND16 LIVE GATE LEDGER -->
| Gate | Подписант | Свежесть | Этап | Live status |
| --- | --- | --- | --- | --- |
| `sql0008-installed-catalog-readback` | `db-operator` | `1h` | `P6` | `LIVE_UNVERIFIED` |
| `restore-drill-proven` | `operations-reviewer` | `24h` | `P9` | `LIVE_UNVERIFIED` |
| `pg-tls-verify-full-proven` | `security-reviewer` | `1h` | `P3` | `LIVE_UNVERIFIED` |
| `vault-versioned-login-iam-proven` | `security-reviewer` | `1h` | `P4` | `LIVE_UNVERIFIED` |
| `live-oidc-session-revocation-proven` | `security-reviewer` | `1h` | `P5` | `LIVE_UNVERIFIED` |
| `durable-offhost-audit-replay-proven` | `security-reviewer` | `1h` | `P8` | `LIVE_UNVERIFIED` |
| `private-two-tenant-e2e-proven` | `runtime-reviewer` | `1h` | `P10` | `LIVE_UNVERIFIED` |
| `staging-canary-rollback-proven` | `runtime-reviewer` | `30m` | `P11` | `LIVE_UNVERIFIED` |
| `security-release-review` | `security-reviewer` | `30m` | `P12` | `LIVE_UNVERIFIED` |
| `operations-release-review` | `operations-reviewer` | `30m` | `P12` | `LIVE_UNVERIFIED` |
<!-- END BACKEND16 LIVE GATE LEDGER -->

## D. Beyond Backend16 private read: full SaaS product — FUTURE_PRODUCT

Even ten signed Backend16 staging proofs do **not** make a complete
multi-tenant commercial SaaS. These need separate product and
production-security authorization:

1. Authoritative SaaS Control API for tenant/project/app CRUD,
   RBAC/ABAC/IDOR, idempotent writes and versioned allowlisted DTO.
2. Production organization ownership, invites/roles, onboarding,
   subject lifecycle, anti-replay session management and data deletion.
3. BYOK/BYOA/OAuth/AuthFiles, KMS/HSM vault, encryption at rest,
   key rotation and strict per-tenant credential isolation.
4. CPA/Gateway-bound Pool/Account/Egress policy, service accounts,
   request authorization and independently allowed integration with
   production Core/Gateway (outside current scope).
5. Enforced outbound firewall, SSRF/DNS rebinding/IPv6/metadata denial,
   provider allowlists, proxy controls and bounded network egress.
6. Formal SQL COMMIT vs remote HTTP delivery/revoke semantics,
   durable receiver ACK, outbox idempotency, recovery and retention.
7. Token/cost metering, quotas/budgets, usage ledger, billing, invoices,
   idempotent reconciliation, disputes and abuse/rate controls.
8. Tenant/project/provider/quota/audit UI with accessibility,
   keyboard focus, reduced motion and all six current i18n locales.
9. Production SLO, safe tracing/logs, security scans, load/chaos tests,
   incident drills, regional policy, backups/PITR and observability.
10. Separate production deployment ADR, changeset, branch/reviewer
    protection, threat model, security/operations approvals,
    progressive release, rollback and ongoing monitoring.

See [broader historical SaaS production readiness]
(PRODUCTION_READINESS_GATES_V1.ru.md). Backend16's ten
staging gates are necessary for its private reader, not sufficient for
the complete product above.

## E. Critical path and non-negotiable limits

**Order:** P0 → P1 → P2; Native Bun.SQL selected but stable runtime and
Bun-only server artifact still blocked. P3/P4/P5/P6 can then proceed with their
independent operator approvals; P7 and P8/P9 enable P10; then P11 →
P12 → separately authorized P13. The product work in section D
requires its own roadmap, scopes, code review and production gates.

No permanent SQL0008 replay, unapproved Railway, real IAM/credentials
or volumes, production Core/Gateway, `custom-no-apikey-fun`,
public API mount, GitHub Release or production `/data` changes.
No `rejectUnauthorized:false`, skipped security checks, floating
canary tags, fabricated signatures or changing
`NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` to make CI green.

**Current release decision: BLOCKED_RELEASE.**

# Backend16 security review and blocked merge checkpoint

Date: 2026-10-19. Repository: Bagirov24/Cli-Proxy-API-Management-Center.

## Decision

Technical AI review and a separate read-only agent review have been performed.
Neither is a formal GitHub approval, an operator signature or release approval.
At discovery all PRs #60–71 were open, all had successful checks at their exact
heads, all reviews were empty, and #70/#71 were drafts. The collaborator list
contained only PR author Bagirov24. Main remained
`8008df941249cf6a942360039077b827f1401d1f`; no GitHub PR was merged.

The `review/backend16-security-20261019` branch is a draft review composition.
It preserves independent branch history and combines workflow coverage. The
three duplicate vault-overlay commits in #70 are excluded: #68 already contains
their source changes. Only #70's unique acceptance checks and documentation,
then #71's framing change, are included for compatibility testing. This is not
permission to merge #70/#71 or this entire draft to main.

## Confirmed findings and source remediations

| ID | Severity and precondition | Result |
| --- | --- | --- |
| B16-SEC-01 | High within executable configuration threat model: CA accessor changes PEM after fingerprint check, before trust branding | Exact plain descriptors are validated and CA/pin values snapshotted before validation; accessor regression RED before fix, GREEN after. |
| B16-SEC-02 | High: authenticated staging postflight uses `tls:'require'`, permitting server impersonation on a compromised network path | Same Bun.SQL connection requires current branded pinned CA trust. No approved real policy exists, so standalone execution stops before password decoding/SQL construction. Global TLS verification disablement is rejected. Existing Railway Function was not updated or executed. |
| B16-SEC-03 | Medium: installed function evidence checks only text fragments; altered behavior can preserve those fragments | Read-only catalog inspection additionally verifies exact original `prosrc` SHA256, argument names, PL/pgSQL language and exact search path. A disposable PG16 regression rejects an altered body and restores the saved original function, without replaying SQL0008. |
| B16-SEC-04 | High within executable provider threat model: provider getter changes approved manifest before snapshot | Complete manifest/pin snapshot precedes provider method capture. Getter regression RED before fix, GREEN after. |
| B16-SEC-05 | High within executable input threat model: caller array method rewrites reviewer keyset pin before snapshot | Authority scalars are captured first; dense data arrays are copied from descriptors without invoking caller array methods/getters. Regression RED before fix, GREEN after. |

The accessor/array cases require active JavaScript objects in the server process.
They are not unauthenticated attacks through ordinary deserialized JSON. The
adapters are unmounted; this review does not assert that these source defects
were exploited or that live credentials were exposed.

Findings 01 and 02 are inherited from main; 04 and 05 remain at the original
latest #68/#67 heads. Therefore parent PR green CI is insufficient. Remediation
commits in this branch must themselves receive independent review.

## Review coverage and evidence limits

- #60/#68: pinned manifest, exact LOGIN/secret ID/version, no credential cache,
  fresh bounded lease, cancellation and redacted errors; fixed synchronous
  provider callback ordering.
- #61: certificate observation sends only SSLRequest/TLS, no DB authentication;
  unverified observation never establishes approved CA identity.
- #62/#67: Ed25519 role-separated keyset, exact commit/environment, full signed
  technical bundle, strict final review ordering, revalidation after async work,
  expiry and old-schema denial; fixed authority snapshot ordering.
- #63/#66: fixed hostname, pinned CA, exact DNS SAN and wildcard denial,
  plaintext downgrade refusal, cancellation and deadlines; shared CA snapshot
  corrected. Native Node/Bun transport acceptance remains required in CI.
- #64/#69/#70/#71: client certificate/key binding, exact broker SAN, canonical
  bounded fixed-length JSON, no redirect/retry/cache, finish-time local grant
  revalidation and combined reader/vault denial after local approval revocation.
- #65: installed-only postflight, eight receipts, sealed migrator, FORCE RLS,
  constant SQL and generic logs; same-connection TLS and function-body evidence
  corrected without modifying or executing the original migration.

Local flags do not implement durable broker IAM revocation. Separate component
tests do not prove one real mTLS → vault → verify-full PostgreSQL16 → tenant RLS
stack. Policy/trigger counts do not fully attest all installed policy/trigger
definitions. Live IAM, private CA, OIDC/session authority, durable audit,
restore/recovery, canary/rollback and release approvals remain release blockers.

## Protected state and merge procedure

SQL0008 remains installed in permanent staging. The historical read-only marker
was read from deployment `623f00ff-92f0-4fb5-9a91-d7ba0d33a3df` at
`2026-10-19T10:56:34.185861091Z`. This is historical evidence; no new DB snapshot
or migration was executed. Original bootstrap/installer files are unchanged.

No production Core/Gateway deployment, credential, `/data` volume or protected
`custom-no-apikey-fun` branch is changed. No Railway mutation API was called.
Inventory snapshots record deployment IDs and volume configuration; they do
not claim byte-for-byte verification of volume data.

Before any main merge, obtain a genuine independent GitHub APPROVED review on
each current reviewed head, successful current-head CI and separately authorized
integration of #70/#71. Use the requested dependency order: #65/#61, #62→#67,
#63→#66, #60→#68, #64→#69, then separately reviewed unique #70→#71 changes.
Reconcile new bases without dropping security invariants. Use matching-head
merge protection. After each merge verify its parents, SHA and diff. The main
branch currently has no branch protection/rulesets, so this manual gate is
mandatory and must never be bypassed using admin permissions.

After the last approved main merge, capture its exact SHA and run CI, Backend16
Private Read Contract, PostgreSQL16 E2E, Browser QA, Demo Build and Management
release guard on that same SHA. Draft-branch or earlier-SHA green results are
preparation only. Deployment and release publication remain unauthorized.

## Technical references

Bun distinguishes encryption-only `require` from `verify-full`, and a TLS
options object with explicit CA/rejectUnauthorized enables full verification:
[Bun SQL TLS modes](https://bun.com/docs/runtime/sql#ssl-modes-overview).
PostgreSQL16 provides built-in SHA256 over bytea, used by the read-only catalog
check without installing an extension:
[PostgreSQL16 binary string functions](https://www.postgresql.org/docs/16/functions-binarystring.html).

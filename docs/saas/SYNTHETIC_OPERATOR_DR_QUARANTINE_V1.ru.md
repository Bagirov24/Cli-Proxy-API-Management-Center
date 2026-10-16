# Stage 2G.4d.7u — operator onboarding + disaster-recovery quarantine (SPEC/CI)

**Status:** CI-only cryptographic shape and adversarial checks. NO real operators, remote WORM, disaster-recovery cutover, production authorization or recovery executor. All six signing roots in this experiment (governance, security, operations, external-authority mock, witness, journal) remain on **one disposable GitHub Actions runner and OS trust domain**. Prior physical PostgreSQL16 tests 7l–7t remain enabled.

## Scope, trust boundaries and non-goals

7t defined a proposed signed external high-water and independently retained minimum, but its signer and minimum were simulated locally. 7u describes future **independent operator onboarding** and tests an offline, manual-only disaster-recovery evidence review. A human/organization, HSM, KMS, remote network identity or WORM independence is **not** established by signatures generated inside one CI process.

The new `archive-witness-operator-dr-contract.mjs` accepts only an `inspect` operation, with all proof inputs in a disposable private test directory; the child-process environment **must not contain PG*/RAILWAY*/DATABASE_URL/production credentials**. No network listener, SQL statement, state repair, delivery endpoint, recovery service, issuer or GC path exists.

## Proposed onboarding protocol (future off-host requirement)

1. **Independent governance:** secure out-of-band bootstrap pins governance Ed25519 root, off-host authority key, witness and high-water keys, `logId`, epoch and two **distinct** operator identities/roles (`security` and `operations`), signed in a policy. Real implementation MUST validate human identity, lifecycle/revocation, authorization scope, key custody, hardware-backed keys, separation of duties and immutable audit out-of-band. CI ONLY checks that the cryptographic keys and roles differ.
2. **Sealed retained minimum:** operators independently retain a **durable external high-water signed receipt**, protected from the local issuer/witness operator. They must not accept a proposal whose authoritative signed head regresses or forks relative to this minimum; offline status cannot itself prove pin was stored off-host.
3. **Per-incident manual request:** security incident controller creates a `nonce`, `logId`/`epoch`, `retainedDigest` and `evidenceDigest`, action exactly `MANUAL_EVIDENCE_INSPECTION_ONLY`. Distinct security and operations keys must both sign the **same** request and **same governance policy digest**. A replay, substituted dossier, obsolete policy, one missing role or swapped role DENY. A genuine remote implementation MUST maintain a monotonic durable nonce ledger and revoke authorizations across identity/epoch changes.
4. **Read-only proof verification:** verifier checks Ed25519 governance policy/dual role signatures, exact external signed 7t receipt and retained minimum, journal and witness Ed25519 signatures, direct previous signed receipt, witness predecessor/sequence/digest, lossless UUID commitment sets and exactly one new commitment on an external successor. It classifies no more than `MATCHED_EVIDENCE_QUARANTINE_REVIEW`, `LOCAL_ROLLBACK_QUARANTINE_REVIEW`, `EXTERNAL_LAG_QUARANTINE_REVIEW`, `SPLIT_LOCAL_EVIDENCE_QUARANTINE_REVIEW`, or `SIGNED_FORK_QUARANTINE_REVIEW`.
5. **No action:** even two valid CI operator signatures and matched evidence **never** authorize production resume, repair, UUID reissue/retry, outbound delivery, physical tombstone deletion or GC. A separately reviewed real settlement process would need actor/issuer authorization, true WAL/LSN/PITR proof, fenced/atomic COMMIT and independently durable high-water before any release decision.

## Synthetic wire contract

- `saas-synthetic-operator-policy-v1` signed by pinned governance root, `data={protocol,audience,logId,epoch,governanceFingerprint,authorityFingerprint,witnessFingerprint,journalFingerprint,operatorFingerprints:{security,operations},minimumQuorum:2}`.
- `saas-synthetic-dr-review-request-v1`, `{protocol,audience,logId,epoch,nonce,action:'MANUAL_EVIDENCE_INSPECTION_ONLY',retainedDigest,evidenceDigest}`.
- Two `saas-synthetic-dr-review-approval-v1` signatures, one each for `security` and `operations`, on `{protocol,audience,role,logId,epoch,nonce,policyDigest,requestDigest}`, using distinct pinned keys. Signatures use Ed25519 over `protocol + '\n' + JSON.stringify(data)`.
- Input dossier: existing `saas-synthetic-offhost-inspection-bundle-v1` signed external and local `{external:{receipt,envelope,journalReceipt,previousReceipt,previousEnvelope},local:{envelope,journalReceipt}}`, plus independently supplied previous retained receipt; no tenant/payload/issuer secrets.
- Audience `disposable-ci-operator-dr-only`, fixed CI `epoch=1`, fixed `minimumQuorum=2`. This is **not** a completed production identity, OIDC, policy rotation or actual two-person authorization.
- Every successful `saas-synthetic-dr-operator-conformance-result-v1` sets `manualReviewRequired=true` and `cryptographicQuorumShapeVerified=true`, but **all** of `authenticHumanIdentityVerified`, `independentOperatorCustodyVerified`, `independentlyHeldMinimumVerified`, `realDisasterRecoveryTested`, `disasterRecoveryComplete`, `authorityToResume`, `authorizationGranted`, `retryPermitted`, `reissuePermitted`, `repairPermitted`, `deliveryPermitted`, `gcPermitted` **false**.

## Adversarial acceptance in disposable GitHub Actions PG16 job

New isolated `verify-archive-witness-operator-dr.mjs` builds mock signed governance/roles, legitimate witness→journal→external genesis and one successor, checks matching vs local rollback, external lag, signed local split and fork; tests stale retained minimum, signed external equivocation at the same revision, missing predecessor, altered UUID projection and forged journal. Missing/swap/duplicate operator role, unknown role key, changed request/nonce/dossier/minimum/policy epoch, attempted `REISSUE_UUID`, `repair` operation, PG/production env leakage, additional fields all DENY.

**Intentional negative control:** verbatim replay of the exact same fully signed synthetic incident still passes cryptographic verification — no durable independently protected nonce ledger exists. No human operators, true remote storage, HSM/WORM, live PITR, quorum, mTLS or disaster drill are tested. This replay limitation is **explicitly logged** and is a release blocker, not a passing production anti-replay claim. Physical PG16 COMMIT/rollback tests remain in 7m–7t separate steps; 7u itself neither connects to PostgreSQL nor asserts physical DR.

## Manual disaster-recovery runbook (SPEC, no executor)

1. Quarantine issuance/dispatch and preserve immutable source/WAL, signed PG projection, witness and high-water journal, recipient ACK evidence and old independent external minimum. Record incident ID, time, origin, reason and affected scope without releasing secrets.
2. Independent operations and security confirm their root-of-trust fingerprints and hold separate tamper-evident copies. Verify authenticated actor/tenant/issuer revocation, key rotation policy and receipt consistency. Never infer a safe UUID retry from UNKNOWN.
3. Independently reconcile committed PostgreSQL UUID identity after backup/PITR/replica promotion and compare to **durable off-host authoritative** high-water. Exercise network partition, stale replica, orphan journal, signer outage, rollback and lost ACK on separate hosts; sign evidence/decisions in a protected independent audit log. Split evidence remains quarantined until independently resolved.
4. Define separate, explicit **human operational authorization** for planned resumption **only after** a distinct fenced/atomic settlement and security release gate exists; never let this verifier emit an operational allow bit. Maintain non-reuse/lifetime-cap and retention/legal constraints.
5. Repeat actual off-host WORM/backup/restore and human identity revocation drills. Capture independently verified SLA/RPO/RTO and threshold alarms, and obtain security/privacy approval before any production release. No success or completion is claimed here.

## Open production gates

- Real independent off-host authority, WORM append log, monotonic trusted revision/nonces, separate operator/governance root custody, authenticated transport, mTLS/OIDC, role revocation, audit/gossip/equivocation defense.
- Signed actual PG COMMIT/WAL/LSN/PITR identity plus fenced cross-system settlement; safe UNKNOWN after crash/partition/replica promotion, durable recipient ACK and issuer actor authorization.
- Verifiable independent disaster-recovery drill, human signoff, retention/legal/privacy/security gates, operational monitoring and rollback-resistant key rotation.

**Unchanged safety:** Draft PR only, no merge/force push, production/Railway/Core/Gateway/CPA/OAuth/`/data`/management.html, no migration 019 or edits to 008–018, no real keys/payload/network delivery/GC, no deletion or reuse of UUIDs, no automatic restart/repair. `gcPermitted=false`.

**CODE VERIFIED:** `89c4560e3b4dcf9e2d8091585351dbb0517098d4`, **4/4 GitHub Actions SUCCESS**:
[Main CI #38396579965](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38396579965) (1,829 Bun PASS, 0 FAIL),
[Ephemeral PG16 #38396579883](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38396579883),
[Demo #38396580104](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38396580104),
[Chromium #38396580074](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38396580074). В PG16 job отдельно напечатаны три `PASS 7u` и отрицательный `LIMITATION 7u` о replay без независимого nonce-ledger и отсутствии реального DR.

**Final docs SHA** должен получить отдельные 4/4 SUCCESS. CI доказал только cryptographic conformance; настоящие operator onboarding, WORM и disaster recovery НЕ VERIFIED.

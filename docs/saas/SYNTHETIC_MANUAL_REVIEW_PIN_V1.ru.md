# Stage 2G.4d.7s — simulated reviewer-pinned high-water and manual-only dispute dossier

**Scope: IMPLEMENTED as a disposable CI security experiment. NOT a production independently hosted witness, WORM root, automated rollback repair, incident closure or issuer/GC permission.** The reviewer key and retained pin are generated in an isolated **directory**, but on the **same GitHub Actions runner and OS trust domain** as PostgreSQL, Unix witness, local high-water and CI fixture. No real human signer, independent custody or remote quorum is exercised.

## Goal: preserve a trusted head in manual review despite two rolled-back local stores

Previous stages: 7o signs a restricted read-only PG16 UUID projection; 7p requires this PG attestation inside protected witness append; 7q requires a second **local** signed high-water acknowledgement; 7r classifies pre/post-COMMIT UNKNOWN with **read-only** signed evidence and no authorization. Yet 7q demonstrated that **joint rollback of witness and high-water** appears internally consistent if the caller loses the last independently pinned head.

7s introduces only `scripts/saas-staging/archive-witness-manual-review-pin.mjs` with two offline commands, `pin` and `inspect`. The signing key is separate from the witness and high-water process keypairs. The proof remains **a simulation of separately retained reviewer evidence**, not actual independence from the shared runner.

### `pin`: monotonic signed review anchor, not operational approval

- Inputs: CI reviewer Ed25519 private/public keypair, pinned witness/journal public keys, witness-signed checkpoint, separately signed journal high-water receipt, previous signed reviewer pin (or `-` **only for genesis**), output path and mandatory `--no-gc`.
- Verifies signatures and fingerprints of both local signers, exact matching `sequence/digest`, valid reviewer signing key, and **direct** predecessor of the previously signed reviewer pin. A genesis pin requires sequence 1 and null predecessor. Gaps, forks, changed keys and journal divergence DENY.
- Signs `saas-synthetic-manual-review-pin-v1` with domain-separated Ed25519 and an explicit `disposable-ci-manual-review-only` audience. The compact signed record contains only sequence/digest, signer-key fingerprints and previous reviewer receipt digest. No raw operation UUID, tenant/actor ID, database credentials, scope token, real payload, external address or recipient ACK.
- The simulated reviewer root stays in a separate 0700 local CI test folder. Pin records are written with exclusive creation (`wx`), fsync file and parent directory; **reusing an output filename cannot overwrite a previous pin**, even under two concurrent test processes. These filesystem properties are only local runner durability, not WORM.

### `inspect`: read-only manual dispute classification

Inputs: three *explicitly chosen* pinned public keys (reviewer, witness, high-water), signed current witness checkpoint, signed local high-water receipt, and previously **retained** reviewer pin. Validates all three Ed25519 signatures and witness-key/journal-key fingerprint binding, then classifies:

| Status | Narrowly observed fact | Operational action |
| --- | --- | --- |
| `PIN_MATCHED_FOR_MANUAL_INSPECTION` | Current signed witness and journal match the supplied reviewer pin | **No approval**, manual review still required |
| `UNPINNED_LOCAL_ADVANCE_REVIEW_REQUIRED` | Local signed pair moved beyond supplied pin | No automatic re-pin/dispatch/reissue |
| `SPLIT_SIGNED_LOCAL_HEADS_REVIEW_REQUIRED` | Witness and journal disagree despite valid individual signatures | Manual incident; DENY automatic repair |
| `COORDINATED_LOCAL_ROLLBACK_SUSPECTED` | Both current local heads agree but are **behind** the preserved reviewer pin | Manual incident; do not resume issuing |
| `CONFLICTING_SIGNED_HEAD_REVIEW_REQUIRED` | Same sequence as reviewer pin but different signed digest | Manual incident; possible signed fork |

The returned JSON has `manualReviewRequired=true`, `locallySignedOnly=true`, `offHostAnchorVerified=false` and **ALL** `authorizationGranted=false`, `reissuePermitted=false`, `retryPermitted=false`, `deliveryPermitted=false`, `gcPermitted=false`, `repairPermitted=false`. Missing, malformed, forged, cross-key or tampered input, illegal action, PG/production credentials or non-CI execution produces **MANUAL REVIEW DENIED**, no positive JSON. A matching pin is explicitly **not** permission to close the incident or resume writes.

The inspector does not read SQL, modify witness/journal, submit credentials, touch persistent production files or contact a remote host. It verifies the signed pair and supplied retained reviewer head, **not** a complete signed PG→recipient settlement history; previously constructed PG attestation remains covered by 7p/7r tests.

## Physical CI and adversarial acceptance

The dedicated 7s ephemeral PG16 workflow step reruns the **unchanged earlier 7q–7r cases** against **distinct** disposable UUID fixture values, then exercises third-key reviewer validation. It does not replace existing 7l, 7m, 7n, 7o, 7p, 7q or 7r named steps.

- Real PG connection severed before and after COMMIT, signed projector/witness/journal observation, lost IPC ACK across restart, orphan/crash windows and multi-COMMIT drift remain DENY on actions.
- Reviewer pin genesis (seq 1), direct successor after lost ACK (seq 2), explicit reviewer pin lag, and valid matching inspection have **only non-authorizing statuses**.
- Jointly rolled-back local witness+journal are detected with **newer preserved reviewer pin**. The test intentionally replaces it with an **old** reviewer pin and observes `PIN_MATCHED_FOR_MANUAL_INSPECTION`: **a coordinated rollback of all three local histories cannot be detected** in this trust domain. This is a proven blocker, not a mitigation claim.
- Witness ahead/journal behind and journal checkpoint signed before publication become manual split incidents; no auto-repair or delivery.
- Duplicate file destination / two concurrent pin writers: at most one write succeeds. Skipped review sequence/fork, forged reviewer/journal/witness key, altered receipt/signature, malformed evidence, unapproved command and supplying `PGHOST` or `PGUSER` to reviewer DENY.
- Zero 009/013 effects, no raw UUID in reviewer JSON, retention/GC check remains false.

## Production blockers (OPEN)

The simulated reviewer key/pin shares CI runner ownership with both local signers. A compromised reviewer can sign a new false anchor; rolling back **all** locally retained pins/keys is undetectable without a genuinely independent off-host trusted high-water. The test does not establish a human dual-control or key custody process, network partition resilience, WORM, global monotonic/anti-replay guarantees, signed WAL COMMIT proof, atomic/fenced PG→witness settlement, protected recovery from journal orphan/failover/PITR, issuer-scoped actor authorization, durable outbound recipient ACK or safe retention/GC approvals. **No automatic reconciliation, retry, UUID reuse, dispatch or GC** is introduced.

No production API/Railway/Core/Gateway/CPA/OAuth edit, no migrations 008–018/019, no `/data`, no `management.html`, no real credentials/payload, no base branch edit, merge, force push, archive/tombstone deletion, cap reset. `gcPermitted=false`.

**CODE VERIFIED:** `7f1496fd15a1670b19b7d840317ca6891d205d8d` — 4/4 GitHub Actions SUCCESS:
[Main CI #38390870305](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38390870305),
[disposable PostgreSQL 16 #38390870200](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38390870200),
[Demo #38390870210](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38390870210),
[Chromium #38390870216](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38390870216).
В PG16 job log — отдельные PASS для genesis reviewer pin, lost IPC ACK, joint local rollback с сохранившимся новым pin, доказанной незащищённости при откате всех трёх pin, split/crash, concurrent writers, key substitution и флагов no-retry/no-repair/no-GC.

**Final documentation SHA:** требует отдельные 4/4 GitHub Actions SUCCESS; CI proof никогда не означает production readiness.

# Stage 2G.4d.7o — challenge-bound PostgreSQL projection attestation (CI proof only)

**Status:** implementation and adversarial validation only in the
disposable PostgreSQL16 GitHub Actions workflow. **Not** an independent
production data authority, append-only archive, irreversible GC gate or
atomic producer-to-witness settlement.

## Why 7o exists

7n's separate Unix-socket witness can sign canonical UUID commitments,
persist signed receipts and reject mismatched expected-head writes, but
its input projection is supplied by a potentially dishonest client.
The signer has no PostgreSQL credentials and cannot know whether the
projection really contains the most recently COMMITTED identities.

7o introduces a **second test-only Ed25519 key and a restricted PostgreSQL
projector process**. Unlike a caller-provided JSON array, this process
obtains its own UUID set inside a genuine PostgreSQL16
`REPEATABLE READ READ ONLY` transaction. It signs:
- exact fixed synthetic source database identifier;
- its PostgreSQL transaction snapshot descriptor;
- a fresh 128-bit challenge nonce supplied and independently pinned
  by the verifier within the same ephemeral CI test;
- the predecessor witness checkpoint `sequence/digest` or null;
- the exact sorted and deduplicated domain-separated SHA-256
  commitments from both 015 producer and 016 issued UUID registries.

Only the independently read UUIDs go into the signed commitment
projection. No raw operation UUID, tenant, actor, API token, payload,
scope signer secret, local audit or recipient receipt is signed.

The standalone source attestor is
`scripts/saas-staging/archive-witness-pg-projection-proof.mjs`,
with modes `attest` and `verify`. The physical adversarial test is
`verify-archive-witness-pg-projection.mjs`.

## Disposable read-only PostgreSQL principal

The test creates `saas_witness_projection_7o` **only** in the
ephemeral `saas_ephemeral_test` database. A new, random test-only
password is used. The attestor rejects any other PGHOST/PGPORT/
PGUSER/PGDATABASE, Railway variables or production URL.

The role has schema USAGE and column-level SELECT on **only**
`operation_id` in:
- `saas_rls_private.synthetic_operation_issues`;
- `saas_rls_private.synthetic_producer_operations`.

Tests assert it CANNOT select tenant/actor columns, read
`scope_signers` secrets, or update the issued registry. The test
revokes its issued-operation SELECT grant, then confirms signing a
new projection fails, rather than falling back to a caller-provided
snapshot or a privileged PostgreSQL role. Role grants are revoked
and the ephemeral test principal is dropped at cleanup.

An administrative CI harness creates the role and inserts exactly
one synthetic issue fixture. That admin is not the attestor.
The attestor itself has no write permission. It invokes `psql`
once for one transaction: both registries and
`txid_current_snapshot()` are observed from the same
repeatable-read snapshot. A transaction snapshot value is
**context**, not independent cryptographic proof of WAL position,
physical database identity or external COMMIT certification.

## Verification and negative tests

The offline verifier receives **no PostgreSQL credentials**. It
checks that the separate attestor public key validates the exact,
canonical domain-separated Ed25519 attestation; challenge nonce,
source and expected predecessor all match independently pinned
evidence. It then verifies the separately pinned witness public key,
signed 7j checkpoint, direct predecessor link and committed UUID
history. The witness-signed projection and projector-signed
projection must be **identical**, not a mere subset. Each
non-genesis proof must add exactly one immutable UUID commitment.

The CI tests:
1. A least-privileged read-only role can select only immutable
   UUID identities; attempts to read sensitive columns/keys or
   mutate UUIDs fail.
2. Separate attestor and witness ephemeral Ed25519 keys sign
   a genesis projection from real PostgreSQL16. The verifier
   accepts a nonce-bound, pinned genesis proof.
3. The admin physically COMMITs one new synthetic issued UUID.
   A fresh read-only attestation observes the new identity;
   the earlier witness checkpoint cannot pass as the successor.
4. After the witness signs the exact same new projection with
   a direct predecessor link, the verifier passes the new
   signed snapshot.
5. A forged client commitment array, old signature reused
   with a different fresh challenge, wrong attestor public
   key, stale witness head and inconsistent predecessor DENY.
6. Revoking the read-only projection role denies subsequent
   attestations. Local signed audit and 013 event intent are not
   created by the test, and the retention view still reports
   `gc_permitted=false`.
7. All temporary signing keys, attestation artifacts and test
   role credentials are deleted after one ephemeral CI job.
   Nothing is published as an external trust root or artifact.

All prior 7j–7n RLS, revocation, physical concurrency,
`pg_dump`/`pg_restore`, unknown-COMMIT and witness
lost-ACK checks remain enabled and unchanged.

## Explicit limits and threat boundaries

The attestor does **not** run on a separate host or trust domain.
Its PostgreSQL role and private signing key are created and managed
by the same temporary CI runner. An adversarial PostgreSQL owner,
attestor process, shared host admin or compromised ephemeral key
can forge/withhold data. The verifier challenge is also pinned
only in this CI test, not by a durable anti-replay service. The
attestor's snapshot is authentic only within the assumptions
that its restricted process and PostgreSQL source have not been
compromised. Signing historical snapshot data is not proof that
a previously unseen COMMIT could not occur subsequently.

This new signed proof is a **separate, read-only CI gate**.
It does NOT replace 7n's existing unrestricted test-only Unix
daemon `append` route, and does NOT gate any real producer.
There is no issuer-authorized tenant/role binding, cross-system
atomic/fenced PostgreSQL-to-witness publication, durable
off-host high-water, WORM, hardware key, consensus, physical
WAL/PITR/failover identity, network partition resolution,
remote recipient ACK or safe tombstone deletion protocol.

**Future production release gates (SPEC):** independent trusted
source and persistent signer, attestation anti-replay enforcement
in the actual witness server, trusted cross-host monotonic head,
actor-scoped authorization for every producer path, atomic/fenced
COMMIT→witness settlement and unknown outcomes, real disaster
recovery/partition testing, privacy retention and signed-off
archive/GC capacity policy. The inherited pre-COMMIT local
handoff and external ACK gaps remain.

**Always `gcPermitted=false`.** No migration 019, production/Railway,
Core/Gateway/CPA/OAuth, new public endpoint, credential export,
actual payload, tombstone UPDATE/DELETE/TRUNCATE/reuse, archive or merge.


**CODE VERIFIED at `7fb367fee12074eb8c5144de36897b54f2caa546`**:
[Main CI #38378826303](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38378826303),
[ephemeral PG16 #38378826250](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38378826250),
[Demo #38378826247](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38378826247),
[Chromium #38378826258](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38378826258)
— **4/4 SUCCESS**. The final documentation SHA must pass its own CI.
No production, independent durability, archive or GC authorization.

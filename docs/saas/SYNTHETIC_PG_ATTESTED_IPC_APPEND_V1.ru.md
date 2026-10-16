# Stage 2G.4d.7p — PostgreSQL-attested IPC witness append (CI only)

**IMPLEMENTED in isolated staging proof path, NOT production settlement.**
The protected daemon starts with `SAAS_EPHEMERAL_PG_WITNESS_PROOF_CI=true` and a **startup-pinned** ephemeral Ed25519 PostgreSQL projector public key. This mode rejects all legacy `append` calls and accepts only `challenge-pg` / `append-pg`. The old 7n `append` is maintained solely for its separate unprotected backwards-compatibility staging test.

## Protocol

1. The caller requests `challenge-pg {requestId, expected}`; the server checks the current head and issues one fresh 128-bit nonce, with a bounded in-memory pending set. Nonces are never chosen by clients.
2. The 7o least-privileged `saas_witness_projection_7o` role independently reads issued and producer `operation_id` UUIDs under a `REPEATABLE READ READ ONLY` transaction, signs the canonical commitment projection with nonce, predecessor, source DB and snapshot descriptor.
3. The `append-pg {requestId, expected, attestation}` handler checks the challenge pinned to that request, the server-held public key, exact signed fields, source database `saas_ephemeral_test`, Ed25519 signature, canonical projection and current predecessor; then it enforces exactly one new UUID commitment per successor. No caller-provided projection is permitted in the protected operation.
4. The witness signs and fsyncs the checkpoint **with its original signed source proof and nonce**; its receipt and head are published durably to the same disposable runner. On startup the daemon re-verifies every persisted source attestation, exact projection digest, witness signature and predecessor chain. Its projector-key fingerprint cannot be changed on restart.
5. When IPC ACK is lost after durable publication, replay of the **same requestId, expected and identical signed attestation** returns the same signed receipt. A different request ID or source proof, missing challenge, stale expected head, replay across head changes or fork are refused.

A pre-publication daemon crash invalidates in-memory challenges; the caller must obtain a fresh challenge and new PG read-only proof. A crash after checkpoint fsync but before head publication leaves an orphan and triggers startup DENY (inherited from 7n). An UNKNOWN PostgreSQL COMMIT, missing projector proof, disconnected socket or invalid signature **never** means authorization to issue/retry a new operation UUID.

## CI adversarial coverage

New `verify-archive-witness-pg-append.mjs`, called by ephemeral PostgreSQL16 workflow, checks restricted SELECT, metadata/secrets/DML denial, actual PG COMMIT then source proof, challenge replay under new request IDs, client-array and signature/DB/digest forgery, competing publishers, lost IPC ACK/restart recovery, projector auth failure, role grant revocation, daemon partition, proof loss on restart, signed persisted proof tamper, key substitution, audit/intent unchanged, and `gcPermitted=false`.

**Boundaries:** projector, signer, trusted pin and filesystem are still managed by the SAME CI runner and operator. PostgreSQL snapshot descriptor is not a signed WAL or a proof of all later COMMITs. No independent off-host high-water, cross-system atomic/fenced settlement, issuer-authorized tenant/actor identity, production OAuth/OIDC, network partition guarantee, PITR/replica promotion, external transport/recipient ACK, safe non-reuse archival, lifetime-cap reset or GC. Migration 008–018 unchanged; no 019 or production endpoint, Railway deployment, Core/Gateway/CPA/OAuth edit, `/data` or real payload. **`gcPermitted=false`**.

**CODE VERIFIED:** `7bbfc07d81914e95b16af93318f99d7d27781f59`, 4/4 Actions SUCCESS:
[CI #38382005330](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38382005330),
[PG16 #38382005244](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38382005244),
[Demo #38382005231](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38382005231),
[Chromium #38382005246](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38382005246).
Final documentation SHA requires its own 4/4 verification.

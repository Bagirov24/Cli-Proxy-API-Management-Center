# 2G.4d.6a — actor-wide PostgreSQL session revocation (ephemeral pilot)

**IMPLEMENTED / CI PENDING.** This is NOT an OIDC/session-token registry.
Only the synthetic singleton actor session state is authoritative in PG16.

Migration `008_actor_session_epoch_pilot.sql` creates a private
`actor_session_state` registry with one synthetic active/revoked
kill-switch per actor. The `scope_membership_matches` signed gate now
requires BOTH private actor active state and current DB membership
with the exact server-authorized role, tenant and HMAC-verified actor
signature. The least-privileged reader cannot SELECT, UPDATE or
enumerate the private session table.

A row-level trigger increments the same PostgreSQL tenant epoch as
migration 004 when an actor session is inserted, revoked, restored or
deleted. An actor with memberships in multiple tenants advances ALL
affected tenant revisions in deterministic order, in the same
transaction. UPDATE with no change leaves epochs unchanged; rollback
undoes state and epoch. Replaying 008 never silently reactivates a
previously revoked actor.

The staging trusted publication chain still derives the actor from the
pinned synthetic JWT/issuer+subject directory. Because that original
signed transaction scope contains actor+tenant+txid+expiry rather than a
token ID/subject, a second token for the same actor is not individually
revocable; the pilot intentionally revokes the WHOLE actor. A proper
token/session-scoped signed attestation and production identity issuer
require a separate design, without trusting client-supplied claims.

SQL acceptance checks signed grant read, actor-wide denial across
revision, expiry attestation and publication FOR SHARE; unaffected
Orbit state; multi-tenant fanout, private ACLs and rollback.
The real PostgreSQL E2E additionally revokes the actor after the
second metadata COMMIT, while both LIMITed project reads remain
identical, and expects a generic tenantless Deny.

No public endpoint, Core/Gateway, CPA/egress, production OIDC,
Railway, credentials or production deploy/merge.

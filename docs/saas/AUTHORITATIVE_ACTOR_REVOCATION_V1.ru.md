# 2G.4d.6a — actor-wide PostgreSQL session revocation (ephemeral pilot)

**IMPLEMENTED / VERIFIED** only in disposable PostgreSQL16, code SHA
`2df528fa665a4702003fbf834e75e25e815e1025`:
[PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787), [CI #38292965756](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965756), [Demo #38292965740](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965740), [Chromium #38292965795](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965795) — 4/4 SUCCESS.
This is NOT an OIDC/session-token registry.
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

## Multi-process actor logout serialization (2G.4d.6a)

`verify-publication-barrier.sh` now also opens a signed PostgreSQL
reader and a privileged synthetic actor-wide logout writer in separate
physical connections. A third observer must see old actor-active state
and unchanged epoch while the reader holds FOR SHARE. Logout COMMIT is
required to wait until that reader commits; the newly signed scope
afterward is denied and restoration bumps North again, not Orbit.
This proves cooperative PostgreSQL DB ordering only, not remote
transport delivery or real OIDC session logout.

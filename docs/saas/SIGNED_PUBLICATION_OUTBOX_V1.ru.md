# Stage 2G.4d.6b — signed durable-on-COMMIT publication outbox

**IMPLEMENTED / VERIFIED** in disposable PG16 on code SHA
`2df528fa665a4702003fbf834e75e25e815e1025`, [PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787),
[CI #38292965756](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965756) (1 815 tests PASS, 0 FAIL), Demo and Chromium SUCCESS.
No production
logging or HTTP transport. Migration 009 follows migrations 001–008.

A private append-only `local_publication_audit_outbox` stores ONLY
tenant_id, actor_id, collection, trusted server correlation_id,
transactional tenant revision, `result=allow`, event_id and recorded_at.
No credentials, JWT, subject, secret, SQL result, resource ID, grant ID
or network address is stored. A duplicate correlation per tenant is
rejected rather than silently overwriting an authorized receipt.

A reader with signed transaction scope can call only the
`saas_rls.record_signed_local_publication` SECURITY DEFINER function.
It verifies current signed actor and exact tenant/role/collection via
the same migration-007 `acquire_authorized_read_barrier`, including
the private actor-wide session gate introduced in migration 008.
The least-privileged reader cannot SELECT or mutate the audit table
and cannot view the signing keys.

All INSERTs occur inside the same signed PG transaction as the local
publication lease, so they are durable only once COMMIT succeeds. A
ROLLBACK removes both the audit event and authorization changes.
The outbox is not a network queue and records a signed authorization
decision, not proof of remote client receipt. A local synchronous
handoff might execute before an eventual SQL COMMIT failure and cannot
be retracted: the audit and transport are not atomically coupled.

No real production actor sessions, retention, immutable storage,
tamper-evident signatures, audit delivery consumer, cross-region
replication or production approvals. See
[PRODUCTION_READINESS_GATES_V1.ru.md](PRODUCTION_READINESS_GATES_V1.ru.md).

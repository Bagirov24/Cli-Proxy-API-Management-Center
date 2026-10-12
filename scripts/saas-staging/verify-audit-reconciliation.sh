#!/usr/bin/env bash
# 2G.4d.7c: committed PG audit recovery; NOT HTTP/network acknowledgement.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" ||
      "${SAAS_EPHEMERAL_AUDIT_RECONCILE_CI:-}" != "true" ||
      "${PGHOST:-}" != "127.0.0.1" ||
      "${PGPORT:-}" != "5432" ||
      "${PGDATABASE:-}" != "saas_ephemeral_test" ||
      "${PGUSER:-}" != "postgres" ||
      -n "${RAILWAY_ENVIRONMENT:-}" ||
      -n "${RAILWAY_PROJECT_ID:-}" ]]; then
  echo "Refusing audit recovery probe outside disposable GitHub PG16"
  exit 1
fi
query() { psql -X -q -A -t -v ON_ERROR_STOP=1 -c "$1"; }
worker_pid=""
cleanup() {
  [[ -z "$worker_pid" ]] || kill "$worker_pid" 2>/dev/null || true
}
trap cleanup EXIT

# Only a previous signed authorization decision can enter the audit outbox.
psql -X -q -v ON_ERROR_STOP=1 > /tmp/saas-reconcile-seed.log <<'SQL'
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.record_signed_local_publication(
  'demo-north','actor-north','tenant-admin','projects','ci-reconcile-crash'),
 'Signed Allow creates append-only pending local audit event');
RESET ROLE;
COMMIT;
SQL
id="$(query "SELECT event_id FROM saas_rls_private.local_publication_audit_outbox WHERE correlation_id='ci-reconcile-crash'")"
[[ "$id" =~ ^[0-9]+$ ]] || { echo "No committed signed audit event"; exit 1; }

# First physical reconciler transaction holds the source FOR UPDATE, but
# cannot expose its uncommitted lease/history to another connection.
PGAPPNAME=saas_audit_crashed_worker psql -X -q -v ON_ERROR_STOP=1 \
 > /tmp/saas-audit-crashed-worker.log 2>&1 <<SQL &
BEGIN;
SET LOCAL statement_timeout='20000ms';
SET LOCAL ROLE saas_audit_reconciler;
SELECT * FROM saas_rls_private.claim_committed_local_audit(1,15,$id);
SELECT pg_sleep(14);
COMMIT;
SQL
worker_pid="$!"
ready=0
for i in {1..65}; do
 if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_audit_crashed_worker' AND wait_event='PgSleep'")" == "1" ]]; then
  ready=1
  break
 fi
 sleep 0.1
done
if [[ "$ready" != "1" ]]; then
 echo "Uncommitted worker failed to acquire event lease"
 tail -n 22 /tmp/saas-audit-crashed-worker.log
 exit 1
fi
skipped="$(query "BEGIN; SET LOCAL ROLE saas_audit_reconciler; SELECT COUNT(*) FROM saas_rls_private.claim_committed_local_audit(1,2,$id); COMMIT;")"
state_before="$(query "SELECT COUNT(*) FROM saas_rls_private.local_audit_reconciliation_state WHERE event_id=$id")"
if [[ "$skipped" != "0" || "$state_before" != "0" ]]; then
 echo "SKIP LOCKED or visibility of uncommitted lease violated"
 exit 1
fi
backend="$(query "SELECT pid FROM pg_stat_activity WHERE application_name='saas_audit_crashed_worker' AND wait_event='PgSleep'")"
[[ "$backend" =~ ^[0-9]+$ ]] || { echo "Missing backend to terminate"; exit 1; }
terminated="$(query "SELECT pg_terminate_backend($backend)")"
[[ "$terminated" == "t" ]] || { echo "Backend termination refused"; exit 1; }
if wait "$worker_pid"; then
 echo "Terminated uncommitted worker unexpectedly COMMITted"
 exit 1
fi
worker_pid=""
if [[ "$(query "SELECT COUNT(*) FROM saas_rls_private.local_audit_reconciliation_state WHERE event_id=$id")" != "0" ||
      "$(query "SELECT COUNT(*) FROM saas_rls_private.local_audit_reconciliation_history WHERE event_id=$id")" != "0" ]]; then
 echo "Backend termination failed to roll back pending lease/history"
 exit 1
fi

# Simulate death after a committed claim: expiry must permit recovery with a
# NEW monotonically increasing generation and non-replayable fencing UUID.
first="$(query "BEGIN; SET LOCAL ROLE saas_audit_reconciler; SELECT generation::text || '|' || lease_token::text FROM saas_rls_private.claim_committed_local_audit(1,1,$id); COMMIT;")"
IFS='|' read -r gen1 key1 <<< "$first"
[[ "$gen1" == "1" && "$key1" =~ ^[0-9a-f-]{36}$ ]] || {
 echo "Invalid first committed lease"; exit 1;
}
sleep 1.3
second="$(query "BEGIN; SET LOCAL ROLE saas_audit_reconciler; SELECT generation::text || '|' || lease_token::text FROM saas_rls_private.claim_committed_local_audit(1,25,$id); COMMIT;")"
IFS='|' read -r gen2 key2 <<< "$second"
[[ "$gen2" == "2" && "$key2" =~ ^[0-9a-f-]{36}$ && "$key1" != "$key2" ]] || {
 echo "Committed lease recovery failed to rotate generation/UUID"; exit 1;
}
old_ack="$(query "BEGIN; SET LOCAL ROLE saas_audit_reconciler; SELECT saas_rls_private.mark_local_audit_reconciled($id,$gen1,'$key1'::uuid); COMMIT;")"
new_ack="$(query "BEGIN; SET LOCAL ROLE saas_audit_reconciler; SELECT saas_rls_private.mark_local_audit_reconciled($id,$gen2,'$key2'::uuid); COMMIT;")"
duplicate_ack="$(query "BEGIN; SET LOCAL ROLE saas_audit_reconciler; SELECT saas_rls_private.mark_local_audit_reconciled($id,$gen2,'$key2'::uuid); COMMIT;")"
status="$(query "SELECT status FROM saas_rls_private.local_audit_reconciliation_state WHERE event_id=$id AND generation=2 AND lease_token IS NULL")"
history="$(query "SELECT COUNT(*) FROM saas_rls_private.local_audit_reconciliation_history WHERE event_id=$id")"
if [[ "$old_ack" != "f" || "$new_ack" != "t" ||
      "$duplicate_ack" != "f" || "$status" != "reconciled_local" ||
      "$history" != "3" ]]; then
 echo "Stale ACK or duplicate local reconciliation after worker crash"
 exit 1
fi
echo "PASS: PG16 crashed audit worker rollback, SKIP LOCKED and fenced lease reclaim"

# 2G.4d.7d: SAME committed+locally observed source event has an independent
# append-only synthetic intent. Two physical workers must not double-claim;
# termination before synthetic claim COMMIT rolls back its lease/history.
stable_key="$(query "SELECT idempotency_key FROM saas_rls_private.synthetic_delivery_intents WHERE event_id=$id")"
[[ "$stable_key" =~ ^[0-9a-f-]{36}$ ]] || {
 echo "Synthetic intent was not committed with the signed audit"; exit 1;
}
PGAPPNAME=saas_mock_crashed_claimer psql -X -q -v ON_ERROR_STOP=1 \
 > /tmp/saas-mock-crashed-claimer.log 2>&1 <<SQL &
BEGIN;
SET LOCAL statement_timeout='18000ms';
SET LOCAL ROLE saas_mock_delivery_worker;
SELECT * FROM saas_rls_private.claim_synthetic_delivery(1,14,$id);
SELECT pg_sleep(10);
COMMIT;
SQL
worker_pid="$!"
ready=0
for i in {1..65}; do
 if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_mock_crashed_claimer' AND wait_event='PgSleep'")" == "1" ]]; then
  ready=1
  break
 fi
 sleep 0.1
done
if [[ "$ready" != "1" ]]; then
 echo "Synthetic delivery claimer failed to hold uncommitted intent lock"
 tail -n 20 /tmp/saas-mock-crashed-claimer.log
 exit 1
fi
second_claim="$(query "BEGIN; SET LOCAL ROLE saas_mock_delivery_worker; SELECT COUNT(*) FROM saas_rls_private.claim_synthetic_delivery(1,2,$id); COMMIT;")"
uncommitted_state="$(query "SELECT COUNT(*) FROM saas_rls_private.synthetic_delivery_state WHERE event_id=$id")"
if [[ "$second_claim" != "0" || "$uncommitted_state" != "0" ]]; then
 echo "Mock worker bypassed SKIP LOCKED or exposed an uncommitted intent lease"
 exit 1
fi
pg_pid="$(query "SELECT pid FROM pg_stat_activity WHERE application_name='saas_mock_crashed_claimer' AND wait_event='PgSleep'")"
[[ "$pg_pid" =~ ^[0-9]+$ ]] || { echo "Missing mock worker backend"; exit 1; }
[[ "$(query "SELECT pg_terminate_backend($pg_pid)")" == "t" ]] || {
 echo "Mock worker backend termination failed"; exit 1;
}
if wait "$worker_pid"; then
 echo "Terminated mock delivery worker unexpectedly COMMITted"
 exit 1
fi
worker_pid=""
if [[ "$(query "SELECT COUNT(*) FROM saas_rls_private.synthetic_delivery_state WHERE event_id=$id")" != "0" ||
      "$(query "SELECT COUNT(*) FROM saas_rls_private.synthetic_delivery_history WHERE event_id=$id")" != "0" ]]; then
 echo "Uncommitted synthetic claim survived backend crash"
 exit 1
fi

# Worker crashed AFTER claim COMMIT: immutable key survives expired lease.
mock_first="$(query "BEGIN; SET LOCAL ROLE saas_mock_delivery_worker; SELECT delivery_generation::text || '|' || fencing_token::text || '|' || idempotency_key::text FROM saas_rls_private.claim_synthetic_delivery(1,1,$id); COMMIT;")"
IFS='|' read -r mock_gen1 mock_fence1 mock_key1 <<< "$mock_first"
[[ "$mock_gen1" == "1" && "$mock_key1" == "$stable_key" ]] || {
 echo "Invalid first committed synthetic attempt"; exit 1;
}
sleep 1.3
mock_second="$(query "BEGIN; SET LOCAL ROLE saas_mock_delivery_worker; SELECT delivery_generation::text || '|' || fencing_token::text || '|' || idempotency_key::text FROM saas_rls_private.claim_synthetic_delivery(1,25,$id); COMMIT;")"
IFS='|' read -r mock_gen2 mock_fence2 mock_key2 <<< "$mock_second"
if [[ "$mock_gen2" != "2" || "$mock_key2" != "$stable_key" ||
      "$mock_fence1" == "$mock_fence2" ]]; then
 echo "Synthetic retry changed immutable receiver key or reused stale fence"
 exit 1
fi
mock_stale="$(query "BEGIN; SET LOCAL ROLE saas_mock_delivery_worker; SELECT saas_rls_private.mark_mock_delivery_ack($id,$mock_gen1,'$mock_fence1'::uuid,'$stable_key'::uuid); COMMIT;")"
mock_ack="$(query "BEGIN; SET LOCAL ROLE saas_mock_delivery_worker; SELECT saas_rls_private.mark_mock_delivery_ack($id,$mock_gen2,'$mock_fence2'::uuid,'$stable_key'::uuid); COMMIT;")"
mock_duplicate="$(query "BEGIN; SET LOCAL ROLE saas_mock_delivery_worker; SELECT saas_rls_private.mark_mock_delivery_ack($id,$mock_gen2,'$mock_fence2'::uuid,'$stable_key'::uuid); COMMIT;")"
mock_state="$(query "SELECT status FROM saas_rls_private.synthetic_delivery_state WHERE event_id=$id AND generation=2")"
mock_history="$(query "SELECT COUNT(*) FROM saas_rls_private.synthetic_delivery_history WHERE event_id=$id")"
if [[ "$mock_stale" != "f" || "$mock_ack" != "t" ||
      "$mock_duplicate" != "f" || "$mock_state" != "mock_acked" ||
      "$mock_history" != "3" ]]; then
 echo "Mock delivery crashed-worker recovery or stale fence ACK failed"
 exit 1
fi
echo "PASS: PG16 physical synthetic delivery worker crash, dedup key and fenced mock ACK"


#!/usr/bin/env bash
# 2G.4d.7h physical PostgreSQL16 concurrent status budget proof.
# Isolated ephemeral CI only. No HTTP, production data or network dispatch.
set -euo pipefail
if [[ "$GITHUB_ACTIONS" != "true" ||
      "$SAAS_EPHEMERAL_ABUSE_CI" != "true" ||
      "$PGHOST" != "127.0.0.1" ||
      "$PGPORT" != "5432" ||
      "$PGUSER" != "postgres" ||
      "$PGDATABASE" != "saas_ephemeral_test" ||
      -n "$(printenv RAILWAY_ENVIRONMENT || true)" ||
      -n "$(printenv RAILWAY_PROJECT_ID || true)" ]]; then
  echo 'Refusing status budget concurrency outside disposable PG16'
  exit 1
fi
query() { psql -X -q -A -t -v ON_ERROR_STOP=1 -c "$1"; }
first_pid=''
second_pid=''
cleanup() {
  [[ -z "$first_pid" ]] || kill "$first_pid" 2>/dev/null || true
  [[ -z "$second_pid" ]] || kill "$second_pid" 2>/dev/null || true
}
trap cleanup EXIT

# Test-only privileged saturation of an existing disposable budget row.
# No tombstones can be deleted or overwritten by this helper.
changed="$(query "UPDATE saas_rls_private.synthetic_operation_budgets
  SET window_until=clock_timestamp()+interval '45 seconds',used_count=15
 WHERE scope_kind='actor' AND tenant_id='demo-orbit'
   AND actor_id='actor-orbit' AND action_kind='status'
 RETURNING used_count")"
[[ "$changed" == "15" ]] || { echo 'Missing controlled actor budget fixture'; exit 1; }
before="$(query "SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox")"

# Process A debits the last free status slot and HOLDS PG row lock.
PGAPPNAME=ci_abuse_first psql -X -q -t -A -v ON_ERROR_STOP=1 \
 > /tmp/saas-abuse-first.log 2>&1 <<'SQL' &
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.read_signed_synthetic_operation_status_bounded(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '99999999-9999-4999-8999-999999999991'::UUID,1);
RESET ROLE;
SELECT pg_sleep(3);
COMMIT;
SQL
first_pid="$!"
ready=0
for i in {1..80}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity
    WHERE application_name='ci_abuse_first' AND wait_event='PgSleep'")" == 1 ]]; then
    ready=1
    break
  fi
  sleep 0.03
done
if [[ "$ready" != 1 ]]; then
  echo 'First physical status call not staged'
  tail -n 25 /tmp/saas-abuse-first.log
  exit 1
fi
[[ "$(query "SELECT used_count FROM saas_rls_private.synthetic_operation_budgets
 WHERE scope_kind='actor' AND tenant_id='demo-orbit'
 AND actor_id='actor-orbit' AND action_kind='status'")" == "15" ]] || {
  echo 'Uncommitted status budget debit leaked across physical connections'
  exit 1
}

PGAPPNAME=ci_abuse_second psql -X -q -t -A -v ON_ERROR_STOP=1 \
 > /tmp/saas-abuse-second.log 2>&1 <<'SQL' &
BEGIN;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls.read_signed_synthetic_operation_status_bounded(
 'demo-orbit','actor-orbit','tenant-viewer','projects',
 '99999999-9999-4999-8999-999999999992'::UUID,1);
RESET ROLE;
COMMIT;
SQL
second_pid="$!"
blocked=0
for i in {1..85}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE
    application_name='ci_abuse_second' AND wait_event_type='Lock'")" == 1 ]]; then
    blocked=1
    break
  fi
  sleep 0.03
done
if [[ "$blocked" != 1 ]]; then
  echo 'Second status probe did not block on the uncommitted quota debit'
  tail -n 30 /tmp/saas-abuse-second.log
  exit 1
fi
wait "$first_pid" || { echo 'First physical status failed'; tail -n 30 /tmp/saas-abuse-first.log; exit 1; }
first_pid=''
wait "$second_pid" || { echo 'Second physical status failed'; tail -n 30 /tmp/saas-abuse-second.log; exit 1; }
second_pid=''
if ! grep -qx 'absent' /tmp/saas-abuse-first.log ||
   ! grep -qx 'throttled' /tmp/saas-abuse-second.log ||
   [[ "$(query "SELECT used_count FROM saas_rls_private.synthetic_operation_budgets
      WHERE scope_kind='actor' AND tenant_id='demo-orbit'
      AND actor_id='actor-orbit' AND action_kind='status'")" != '16' ]] ||
   [[ "$(query "SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox")" != "$before" ]]; then
  echo 'Physical status race bypassed strict 16-per-actor limit'
  tail -n 20 /tmp/saas-abuse-first.log
  tail -n 20 /tmp/saas-abuse-second.log
  exit 1
fi
echo 'PASS: physical PG16 status race SERIALIZES budget; 16th admitted, 17th throttled'

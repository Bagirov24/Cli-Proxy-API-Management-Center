#!/usr/bin/env bash
# Stage 2G.4d.7f: independent PG connections, same producer UUID.
# Strictly ephemeral PG16. No HTTP, external account, Railway or /data.
set -euo pipefail
if [[ "$GITHUB_ACTIONS" != "true" ||
      "$SAAS_EPHEMERAL_PRODUCER_CI" != "true" ||
      "$PGHOST" != "127.0.0.1" || "$PGPORT" != "5432" ||
      "$PGUSER" != "postgres" || "$PGDATABASE" != "saas_ephemeral_test" ||
      -n "$(printenv RAILWAY_ENVIRONMENT || true)" ||
      -n "$(printenv RAILWAY_PROJECT_ID || true)" ]]; then
  echo "Refusing producer recovery probe outside disposable PG16"
  exit 1
fi
query() { psql -X -q -A -t -v ON_ERROR_STOP=1 -c "$1"; }
operation='33333333-3333-4333-8333-333333333333'
first_pid=''
second_pid=''
cleanup() {
  [[ -z "$first_pid" ]] || kill "$first_pid" 2>/dev/null || true
  [[ -z "$second_pid" ]] || kill "$second_pid" 2>/dev/null || true
}
trap cleanup EXIT

# Process A writes signed audit + immutable operation mapping but holds
# transaction uncommitted, allowing us to observe B's advisory lock wait.
PGAPPNAME=ci_producer_first psql -X -q -v ON_ERROR_STOP=1 \
 > /tmp/saas-producer-first.log 2>&1 <<'SQL' &
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.record_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects',
 'ci-producer-concurrent-first',
 '33333333-3333-4333-8333-333333333333'::UUID,1),
 'First signed operation staged');
RESET ROLE;
SELECT pg_sleep(4);
COMMIT;
SQL
first_pid="$!"
ready=0
for i in {1..70}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='ci_producer_first' AND wait_event='PgSleep'")" == 1 ]]; then
    ready=1
    break
  fi
  sleep 0.04
done
if [[ "$ready" != 1 ]]; then
  echo 'First operation was not staged in time'
  tail -n 25 /tmp/saas-producer-first.log
  exit 1
fi
[[ "$(query "SELECT COUNT(*) FROM saas_rls_private.synthetic_producer_operations WHERE operation_id='$operation'::UUID")" == 0 ]] || {
  echo 'Uncommitted producer operation leaked to separate connection'
  exit 1
}

PGAPPNAME=ci_producer_second psql -X -q -v ON_ERROR_STOP=1 \
 > /tmp/saas-producer-second.log 2>&1 <<'SQL' &
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.record_signed_synthetic_operation(
 'demo-north','actor-north','tenant-admin','projects',
 'ci-producer-concurrent-second',
 '33333333-3333-4333-8333-333333333333'::UUID,1),
 'Second independent connection must observe first durable op');
RESET ROLE;
COMMIT;
SQL
second_pid="$!"
blocked=0
for i in {1..85}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='ci_producer_second' AND wait_event_type='Lock' AND wait_event='advisory'")" == 1 ]]; then
    blocked=1
    break
  fi
  sleep 0.03
done
if [[ "$blocked" != 1 ]]; then
  echo 'Independent duplicate producer did not wait on advisory lock'
  tail -n 25 /tmp/saas-producer-second.log
  exit 1
fi
[[ "$(query "SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox WHERE correlation_id IN ('ci-producer-concurrent-first','ci-producer-concurrent-second')")" == 0 ]] || {
  echo 'Uncommitted event leaked before first COMMIT'
  exit 1
}
wait "$first_pid" || { echo 'First producer transaction failed'; tail -n 30 /tmp/saas-producer-first.log; exit 1; }
first_pid=''
wait "$second_pid" || { echo 'Second producer duplicate failed'; tail -n 30 /tmp/saas-producer-second.log; exit 1; }
second_pid=''
outbox_count="$(query "SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox WHERE correlation_id IN ('ci-producer-concurrent-first','ci-producer-concurrent-second')")"
registry_count="$(query "SELECT COUNT(*) FROM saas_rls_private.synthetic_producer_operations WHERE operation_id='$operation'::UUID")"
intent_count="$(query "SELECT COUNT(*) FROM saas_rls_private.synthetic_delivery_intents i JOIN saas_rls_private.synthetic_producer_operations o ON o.event_id=i.event_id WHERE o.operation_id='$operation'::UUID")"
second_count="$(query "SELECT COUNT(*) FROM saas_rls_private.local_publication_audit_outbox WHERE correlation_id='ci-producer-concurrent-second'")"
if [[ "$outbox_count" != 1 || "$registry_count" != 1 ||
      "$intent_count" != 1 || "$second_count" != 0 ]]; then
  echo 'Concurrent producer retry minted multiple immutable events'
  exit 1
fi
echo 'PASS: physical PG16 concurrent same-UUID producer serialized; one audit/intent'

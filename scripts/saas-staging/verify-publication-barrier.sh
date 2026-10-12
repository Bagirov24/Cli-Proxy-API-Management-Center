#!/usr/bin/env bash
# Stage 2G.4d.4c: two physical PostgreSQL sessions + a third observer.
# Never execute against Railway, production, real Core or real credentials.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" ||
      "${SAAS_EPHEMERAL_PUBLICATION_CI:-}" != "true" ||
      "${PGHOST:-}" != "127.0.0.1" ||
      "${PGPORT:-}" != "5432" ||
      "${PGDATABASE:-}" != "saas_ephemeral_test" ||
      "${PGUSER:-}" != "postgres" ||
      -n "${RAILWAY_ENVIRONMENT:-}" ||
      -n "${RAILWAY_PROJECT_ID:-}" ]]; then
  echo "Refusing publication barrier probe outside ephemeral PostgreSQL CI"
  exit 1
fi
query() { psql -X -A -t -v ON_ERROR_STOP=1 -c "$1"; }
start="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
orbit="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-orbit'")"
[[ "$start" =~ ^[0-9]+$ && "$orbit" =~ ^[0-9]+$ ]] || exit 1

reader_pid=""
writer_pid=""
cleanup() {
  [[ -z "$reader_pid" ]] || kill "$reader_pid" 2>/dev/null || true
  [[ -z "$writer_pid" ]] || kill "$writer_pid" 2>/dev/null || true
}
trap cleanup EXIT

# The privileged fixture creates a synthetic signed scope first. Subsequent
# SQL runs under reader privileges. The transaction stays open at the
# simulated publication point; this is NOT actual HTTP delivery.
PGAPPNAME=saas_publication_reader psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-publication-reader.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='15000ms';
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.acquire_authorized_read_barrier(
    'demo-north','actor-north','tenant-admin','projects') IS NOT NULL,
  'signed reader must acquire North publication epoch lock');
SELECT pg_sleep(6);
RESET ROLE;
COMMIT;
SQL
reader_pid="$!"

ready=0
for i in {1..65}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_publication_reader' AND wait_event='PgSleep'")" == "1" ]]; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  echo "Signed publication reader did not reach read-publication barrier"
  tail -n 15 /tmp/saas-publication-reader.log
  exit 1
fi

# An independent privileged fixture writer changes an auth grant. The 004
# row trigger must wait on the reader's held FOR SHARE epoch lock.
PGAPPNAME=saas_publication_revoke psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-publication-writer.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='15000ms';
UPDATE saas_rls.resource_grants
   SET status='disabled'
 WHERE id='grant-pool' AND grantee_tenant_id='demo-north'
   AND status='active';
COMMIT;
SQL
writer_pid="$!"

blocked=0
for i in {1..45}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_publication_revoke' AND wait_event_type='Lock'")" == "1" ]]; then
    blocked=1
    break
  fi
  sleep 0.1
done
if [[ "$blocked" != "1" ]]; then
  echo "Revocation writer failed to wait for the read-publication epoch"
  tail -n 20 /tmp/saas-publication-writer.log
  exit 1
fi

mid="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
status="$(query "SELECT status FROM saas_rls.resource_grants WHERE id='grant-pool'")"
if [[ "$mid" != "$start" || "$status" != "active" ]]; then
  echo "Revocation became committed before the reader publication barrier ended"
  exit 1
fi

wait "$reader_pid"
reader_pid=""
wait "$writer_pid"
writer_pid=""
after="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
independent="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-orbit'")"
status="$(query "SELECT status FROM saas_rls.resource_grants WHERE id='grant-pool'")"
if (( after != start + 1 )) || [[ "$independent" != "$orbit" || "$status" != "disabled" ]]; then
  echo "Revocation epoch/order/tenant isolation assertion failed"
  exit 1
fi

# Restore a synthetic grant through the SAME versioned trigger.
query "UPDATE saas_rls.resource_grants SET status='active' WHERE id='grant-pool' AND grantee_tenant_id='demo-north' AND status='disabled'" >/dev/null
final="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
if (( final != start + 2 )); then
  echo "Restoration failed to advance revocation epoch"
  exit 1
fi
echo "PASS: PG16 shared publication lock orders reader COMMIT before revoke COMMIT"

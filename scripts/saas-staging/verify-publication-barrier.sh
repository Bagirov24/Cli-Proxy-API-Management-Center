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

# Abort/crash probe: a forcibly terminated PG reader backend MUST release
# its FOR SHARE row lock and unblock a separately queued revocation writer.
# This simulates loss of DB connection, not real HTTP cancellation.
PGAPPNAME=saas_terminated_publication_reader psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-publication-aborted-reader.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='30000ms';
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.acquire_authorized_read_barrier(
    'demo-north','actor-north','tenant-admin','projects') IS NOT NULL,
  'reader must acquire a cancellable epoch barrier');
SELECT pg_sleep(20);
RESET ROLE;
COMMIT;
SQL
reader_pid="$!"
ready=0
for i in {1..65}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_terminated_publication_reader' AND wait_event='PgSleep'")" == "1" ]]; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  echo "Cancellable signed reader did not acquire barrier"
  tail -n 15 /tmp/saas-publication-aborted-reader.log
  exit 1
fi

PGAPPNAME=saas_terminated_publication_writer psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-publication-aborted-writer.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='15000ms';
UPDATE saas_rls.resource_grants SET status='active'
WHERE id='grant-egress' AND grantee_tenant_id='demo-north' AND status='disabled';
COMMIT;
SQL
writer_pid="$!"
blocked=0
for i in {1..40}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_terminated_publication_writer' AND wait_event_type='Lock'")" == "1" ]]; then
    blocked=1
    break
  fi
  sleep 0.1
done
if [[ "$blocked" != "1" ]]; then
  echo "Forced-termination writer did not wait on publication lock"
  tail -n 20 /tmp/saas-publication-aborted-writer.log
  exit 1
fi

# This is explicitly the disposable container postgres fixture superuser,
# never a live backend or network request. Termination rolls back the reader.
terminated="$(query "SELECT bool_and(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE application_name='saas_terminated_publication_reader'")"
if [[ "$terminated" != "t" ]]; then
  echo "Failed to terminate disposable reader backend"
  exit 1
fi
wait "$reader_pid" || true
reader_pid=""
wait "$writer_pid"
writer_pid=""
after_abort="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
if (( after_abort != final + 1 )); then
  echo "Revocation writer did not commit after aborted reader released lock"
  exit 1
fi
query "UPDATE saas_rls.resource_grants SET status='disabled' WHERE id='grant-egress' AND grantee_tenant_id='demo-north' AND status='active'" >/dev/null
restored="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
if (( restored != final + 2 )); then
  echo "Failed to restore versioned synthetic Egress fixture after aborted reader"
  exit 1
fi
echo "PASS: terminated PG16 reader rolls back FOR SHARE; pending revoke COMMIT unblocks"

# 2G.4d.6a: actor-wide logout writer MUST use the same per-tenant
# revision lock as grants. Two independent PG backends + an observer.
initial_actor_epoch="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
initial_orbit_epoch="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-orbit'")"

PGAPPNAME=saas_actor_publication_reader psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-actor-publication-reader.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='15000ms';
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  saas_rls.acquire_authorized_read_barrier(
    'demo-north','actor-north','tenant-admin','projects') IS NOT NULL,
  'Signed active actor must hold epoch while publishing');
SELECT pg_sleep(4);
RESET ROLE;
COMMIT;
SQL
reader_pid="$!"
ready=0
for i in {1..65}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_actor_publication_reader' AND wait_event='PgSleep'")" == "1" ]]; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  echo "Actor publication reader failed to acquire private epoch lock"
  tail -n 20 /tmp/saas-actor-publication-reader.log
  exit 1
fi

PGAPPNAME=saas_actor_logout_writer psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-actor-logout-writer.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='15000ms';
UPDATE saas_rls_private.actor_session_state
 SET status='revoked',revision=revision+1
 WHERE actor_id='actor-north' AND status='active';
COMMIT;
SQL
writer_pid="$!"
blocked=0
for i in {1..45}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_actor_logout_writer' AND wait_event_type='Lock'")" == "1" ]]; then
    blocked=1
    break
  fi
  sleep 0.1
done
if [[ "$blocked" != "1" ]]; then
  echo "Actor logout writer did not wait for signed reader epoch"
  tail -n 20 /tmp/saas-actor-logout-writer.log
  exit 1
fi
pre_logout_status="$(query "SELECT status FROM saas_rls_private.actor_session_state WHERE actor_id='actor-north'")"
pre_logout_epoch="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
if [[ "$pre_logout_status" != "active" || "$pre_logout_epoch" != "$initial_actor_epoch" ]]; then
  echo "Uncommitted logout became visible before signed publication COMMIT"
  exit 1
fi

wait "$reader_pid"
reader_pid=""
wait "$writer_pid"
writer_pid=""
post_logout_status="$(query "SELECT status FROM saas_rls_private.actor_session_state WHERE actor_id='actor-north'")"
post_logout_epoch="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
if [[ "$post_logout_status" != "revoked" ]] || (( post_logout_epoch != initial_actor_epoch + 1 )); then
  echo "Actor-wide logout must COMMIT once after signed publication releases lock"
  exit 1
fi

psql -X -q -v ON_ERROR_STOP=1 <<'SQL' > /tmp/saas-actor-after-logout-check.log
BEGIN;
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  NOT saas_rls.scope_membership_matches(
    'demo-north','actor-north','tenant-admin'),
  'Previously valid signed actor must be denied after logout COMMIT');
RESET ROLE;
ROLLBACK;
SQL

query "UPDATE saas_rls_private.actor_session_state SET status='active',revision=revision+1 WHERE actor_id='actor-north' AND status='revoked'" >/dev/null
restored_actor_epoch="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
restored_orbit_epoch="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-orbit'")"
if (( restored_actor_epoch != initial_actor_epoch + 2 )) ||
   [[ "$restored_orbit_epoch" != "$initial_orbit_epoch" ]]; then
  echo "Actor logout recovery must version North and leave Orbit unchanged"
  exit 1
fi
echo "PASS: PG16 actor-wide logout COMMIT waits for signed publication; old scope then denied"

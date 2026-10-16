#!/usr/bin/env bash
# M1d: competing tenant revoke/status vs signed project COMMIT in real PG16.
# All psql connections are privileged CI fixtures; SET LOCAL ROLE enforces
# the actual NOLOGIN M1 project executor and SECURITY DEFINER/RLS functions.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" ||
      "${SAAS_EPHEMERAL_M1_FENCE_CI:-}" != "true" ||
      "${PGHOST:-}" != "127.0.0.1" ||
      "${PGPORT:-}" != "5432" ||
      "${PGDATABASE:-}" != "saas_ephemeral_test" ||
      "${PGUSER:-}" != "postgres" ||
      "${NODE_ENV:-}" == "production" ||
      -n "${RAILWAY_PROJECT_ID:-}" ||
      -n "${RAILWAY_ENVIRONMENT:-}" ]]; then
  echo 'DENY M1d: refusing non-ephemeral GitHub PG16 execution'
  exit 1
fi
test ! -e .env.production
test ! -e /data/auths
query() { psql -X -A -t -v ON_ERROR_STOP=1 -c "$1"; }
first_pid=""
second_pid=""
cleanup() {
  if [[ -n "$first_pid" ]]; then kill "$first_pid" 2>/dev/null || true; fi
  if [[ -n "$second_pid" ]]; then kill "$second_pid" 2>/dev/null || true; fi
  if [[ -n "$first_pid" ]]; then wait "$first_pid" 2>/dev/null || true; fi
  if [[ -n "$second_pid" ]]; then wait "$second_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT
wait_for_sleep() {
  local app="$1" seen=0
  for i in {1..55}; do
    if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='$app' AND wait_event='PgSleep'")" == "1" ]]; then
      seen=1
      break
    fi
    sleep 0.1
  done
  if [[ "$seen" != "1" ]]; then
    echo 'FAIL M1d: fixture did not reach transaction hold'
    exit 1
  fi
}
wait_for_lock() {
  local app="$1" seen=0
  for i in {1..45}; do
    if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='$app' AND wait_event_type='Lock'")" == "1" ]]; then
      seen=1
      break
    fi
    sleep 0.1
  done
  if [[ "$seen" != "1" ]]; then
    echo 'FAIL M1d: expected authorization row-lock wait not observed'
    exit 1
  fi
}
finish_pair() {
  wait "$first_pid"
  first_pid=""
  wait "$second_pid"
  second_pid=""
}
require_result() {
  if ! grep -Fxq "$2" "$1"; then
    echo 'FAIL M1d: unexpected signed SQL decision'
    tail -n 10 "$1"
    exit 1
  fi
}
# A. Writer acquires signed FOR SHARE, writes project+audit, holds its
# transaction. Competing membership revoke MUST WAIT to update same epoch.
PGAPPNAME=m1d_writer_first psql -X -A -t -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-m1d-writer-first.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='20000ms';
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120) \gset
SET LOCAL ROLE saas_m1_project_executor;
SELECT CASE WHEN saas_m1_api.create_project('demo-north','m1d-write-first','Commit before revoke')
  THEN 'M1D_WRITE_ALLOWED' ELSE 'M1D_WRITE_DENIED' END;
RESET ROLE;
SELECT pg_sleep(5);
COMMIT;
SQL
first_pid="$!"
wait_for_sleep 'm1d_writer_first'
PGAPPNAME=m1d_revoke_after psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-m1d-revoke-after.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='20000ms';
UPDATE saas_rls.memberships SET status='revoked'
 WHERE tenant_id='demo-north' AND actor_id='actor-north' AND status='active';
COMMIT;
SQL
second_pid="$!"
wait_for_lock 'm1d_revoke_after'
finish_pair
require_result /tmp/saas-m1d-writer-first.log 'M1D_WRITE_ALLOWED'
psql -X -q -v ON_ERROR_STOP=1 <<'SQL' > /tmp/saas-m1d-first-check.log 2>&1
SELECT saas_rls_test.assert_true(
  (SELECT status='revoked' FROM saas_rls.memberships
   WHERE tenant_id='demo-north' AND actor_id='actor-north')
  AND EXISTS (SELECT 1 FROM saas_m1_private.projects
              WHERE tenant_id='demo-north' AND project_id='m1d-write-first'
                AND version=1 AND status='active')
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id='m1d-write-first'
         AND operation='create' AND actor_id='actor-north' AND project_version=1)
  AND (SELECT authorization_revision <
      (SELECT revision FROM saas_rls_private.tenant_authorization_revisions
       WHERE tenant_id='demo-north')
      FROM saas_m1_private.project_write_audit_outbox
      WHERE tenant_id='demo-north' AND project_id='m1d-write-first'),
  'M1d project and one audit committed BEFORE a competing revoke'
);
SQL
query "UPDATE saas_rls.memberships SET status='active' WHERE tenant_id='demo-north' AND actor_id='actor-north' AND status='revoked'" >/dev/null

# B. Revoke commits first. A concurrent writer may have read the OLD
# committed membership, but the barrier rechecks AFTER epoch lock wait:
# forbidden project and zero audit events, not a late success.
PGAPPNAME=m1d_revoke_first psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-m1d-revoke-first.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='20000ms';
UPDATE saas_rls.memberships SET status='revoked'
 WHERE tenant_id='demo-north' AND actor_id='actor-north' AND status='active';
SELECT pg_sleep(5);
COMMIT;
SQL
first_pid="$!"
wait_for_sleep 'm1d_revoke_first'
PGAPPNAME=m1d_writer_after psql -X -A -t -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-m1d-writer-after.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='20000ms';
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120) \gset
SET LOCAL ROLE saas_m1_project_executor;
SELECT CASE WHEN saas_m1_api.create_project('demo-north','m1d-revoke-first','Must be denied')
  THEN 'M1D_WRITE_ALLOWED' ELSE 'M1D_WRITE_DENIED' END;
RESET ROLE;
COMMIT;
SQL
second_pid="$!"
wait_for_lock 'm1d_writer_after'
finish_pair
require_result /tmp/saas-m1d-writer-after.log 'M1D_WRITE_DENIED'
query "UPDATE saas_rls.memberships SET status='active' WHERE tenant_id='demo-north' AND actor_id='actor-north' AND status='revoked'" >/dev/null

# C. Tenant suspension commits first, even while the actor membership is
# active. It updates the SAME shared tenant epoch and forces a late deny.
PGAPPNAME=m1d_tenant_suspender psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-m1d-tenant-suspend.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='20000ms';
UPDATE saas_rls.tenants SET status='suspended'
 WHERE id='demo-north' AND status='active';
SELECT pg_sleep(5);
COMMIT;
SQL
first_pid="$!"
wait_for_sleep 'm1d_tenant_suspender'
PGAPPNAME=m1d_writer_suspended psql -X -A -t -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-m1d-writer-suspended.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout='20000ms';
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120) \gset
SET LOCAL ROLE saas_m1_project_executor;
SELECT CASE WHEN saas_m1_api.create_project('demo-north','m1d-suspend-first','Must be denied')
  THEN 'M1D_WRITE_ALLOWED' ELSE 'M1D_WRITE_DENIED' END;
RESET ROLE;
COMMIT;
SQL
second_pid="$!"
wait_for_lock 'm1d_writer_suspended'
finish_pair
require_result /tmp/saas-m1d-writer-suspended.log 'M1D_WRITE_DENIED'
query "UPDATE saas_rls.tenants SET status='active' WHERE id='demo-north' AND status='suspended'" >/dev/null

psql -X -q -v ON_ERROR_STOP=1 <<'SQL' > /tmp/saas-m1d-final-check.log 2>&1
SELECT saas_rls_test.assert_true(
  NOT EXISTS (SELECT 1 FROM saas_m1_private.projects
    WHERE project_id IN ('m1d-revoke-first','m1d-suspend-first'))
  AND NOT EXISTS (SELECT 1 FROM saas_m1_private.project_write_audit_outbox
    WHERE project_id IN ('m1d-revoke-first','m1d-suspend-first'))
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_write_audit_outbox
       WHERE project_id='m1d-write-first')
  AND (SELECT status='active' FROM saas_rls.tenants WHERE id='demo-north')
  AND (SELECT status='active' FROM saas_rls.memberships
       WHERE tenant_id='demo-north' AND actor_id='actor-north'),
  'M1d no unaudited delayed project; tenant and membership restored'
);
SQL
echo 'PASS M1d: real PG16 FOR SHARE serializes write-first/revoke-first/tenant-suspend; denied DML has no audit, no retry'

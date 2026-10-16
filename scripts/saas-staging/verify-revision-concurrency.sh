#!/usr/bin/env bash
# Disposable PostgreSQL 16 ONLY. Never run on a production DB.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" ||
      "${SAAS_EPHEMERAL_REVISION_CI:-}" != "true" ||
      "${PGHOST:-}" != "127.0.0.1" ||
      "${PGPORT:-}" != "5432" ||
      "${PGDATABASE:-}" != "saas_ephemeral_test" ||
      "${PGUSER:-}" != "postgres" ||
      -n "${RAILWAY_ENVIRONMENT:-}" ||
      -n "${RAILWAY_PROJECT_ID:-}" ]]; then
  echo "Refusing authorization revision concurrency outside disposable CI"
  exit 1
fi
query() { psql -X -A -t -v ON_ERROR_STOP=1 -c "$1"; }
start="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
orbit="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-orbit'")"
[[ "$start" =~ ^[0-9]+$ && "$orbit" =~ ^[0-9]+$ ]] || exit 1
first_pid=""
second_pid=""
cleanup() {
  if [[ -n "$first_pid" ]]; then kill "$first_pid" 2>/dev/null || true; fi
  if [[ -n "$second_pid" ]]; then kill "$second_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

# Writer 1 holds the tenant revision row while its transaction is uncommitted.
PGAPPNAME=saas_revision_writer_one psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-revision-writer-1.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout = '20000ms';
UPDATE saas_rls.memberships SET role='tenant-owner'
WHERE actor_id='actor-north' AND tenant_id='demo-north' AND role='tenant-admin';
SELECT pg_sleep(6);
COMMIT;
SQL
first_pid="$!"

seen=0
for i in {1..50}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_revision_writer_one' AND wait_event='PgSleep'")" == "1" ]]; then
    seen=1
    break
  fi
  sleep 0.1
done
if [[ "$seen" != "1" ]]; then
  echo "First writer did not reach the post-update barrier"
  tail -n 15 /tmp/saas-revision-writer-1.log
  exit 1
fi

# Different physical session and a DIFFERENT grant row for the same tenant.
# It must wait on the epoch lock rather than overwrite the first update.
PGAPPNAME=saas_revision_writer_two psql -X -q -v ON_ERROR_STOP=1 \
  > /tmp/saas-revision-writer-2.log 2>&1 <<'SQL' &
BEGIN;
SET LOCAL statement_timeout = '20000ms';
UPDATE saas_rls.resource_grants SET status='active'
WHERE id='grant-egress' AND grantee_tenant_id='demo-north' AND status='disabled';
COMMIT;
SQL
second_pid="$!"

blocked=0
for i in {1..35}; do
  if [[ "$(query "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name='saas_revision_writer_two' AND wait_event_type='Lock'")" == "1" ]]; then
    blocked=1
    break
  fi
  sleep 0.1
done
if [[ "$blocked" != "1" ]]; then
  echo "Concurrent grant writer did not block on the shared tenant epoch"
  tail -n 15 /tmp/saas-revision-writer-2.log
  exit 1
fi

# Another PostgreSQL session sees committed baseline, not uncommitted bump.
mid="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
if [[ "$mid" != "$start" ]]; then
  echo "Uncommitted authorization epoch was visible to another reader"
  exit 1
fi

wait "$first_pid"
first_pid=""
wait "$second_pid"
second_pid=""
after="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
other="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-orbit'")"
if (( after != start + 2 )) || [[ "$other" != "$orbit" ]]; then
  echo "Concurrent committed mutations lost an epoch increment or touched Orbit"
  exit 1
fi
# Undo fixture mutations with NEW committed, versioned writes. No production.
psql -X -q -v ON_ERROR_STOP=1 <<'SQL' > /tmp/saas-revision-reset.log 2>&1
BEGIN;
UPDATE saas_rls.memberships SET role='tenant-admin'
WHERE actor_id='actor-north' AND tenant_id='demo-north' AND role='tenant-owner';
UPDATE saas_rls.resource_grants SET status='disabled'
WHERE id='grant-egress' AND grantee_tenant_id='demo-north' AND status='active';
COMMIT;
SQL
final="$(query "SELECT revision FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'")"
if (( final != start + 4 )); then
  echo "Restoring fixture rights did not version both changes"
  exit 1
fi
echo "PASS: concurrent PG16 reader/writers serialize tenant revision; no dirty read, no lost bumps"

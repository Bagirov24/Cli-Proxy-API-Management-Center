#!/usr/bin/env bash
# Backend13: disposable PostgreSQL16 GitHub CI ONLY. No Railway, no pilot DB,
# no real principals, customer data, public HTTP, or privileged live SQL.
set -euo pipefail
fail(){ echo 'Backend13 isolated PG16 CI failed or refused' >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == 'true' && "${SAAS_B13_EPHEMERAL_CI:-}" == 'true' ]] || fail
[[ "${PGHOST:-}" == '127.0.0.1' && "${PGPORT:-}" == '5432' ]] || fail
[[ "${PGDATABASE:-}" == 'saas_ephemeral_test' && "${PGUSER:-}" == 'postgres' ]] || fail
[[ -z "${RAILWAY_PROJECT_ID:-}" && -z "${RAILWAY_ENVIRONMENT_ID:-}" ]] || fail
[[ -z "${RAILWAY_SERVICE_ID:-}" && "${NODE_ENV:-}" != 'production' ]] || fail
[[ "${SAAS_B13_EPHEMERAL_MIGRATOR_PASSWORD:-}" =~ ^[a-f0-9]{64}$ ]] || fail
migrator_password="$SAAS_B13_EPHEMERAL_MIGRATOR_PASSWORD"
unset SAAS_B13_EPHEMERAL_MIGRATOR_PASSWORD
[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || fail
sha5="$(sha256sum staging/saas-bootstrap/0005_principal_lifecycle_revocation_fence.sql | cut -d ' ' -f1)"
sha4="$(sha256sum staging/saas-bootstrap/0004_principal_bound_read_rls.sql | cut -d ' ' -f1)"
[[ "$sha5" =~ ^[a-f0-9]{64}$ && "$sha4" == '4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980' ]] || fail

PGOPTIONS='-c saas.staging_only=true' \
PGUSER=saas_schema_migrator PGPASSWORD="$migrator_password" \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
    -v expected_0004_sha256="$sha4" -v migration_sha256="$sha5" \
    -v source_commit="$GITHUB_SHA" \
    -f staging/saas-bootstrap/0005_principal_lifecycle_revocation_fence.sql \
    > /tmp/saas-b13-apply.log 2>&1 || {
      tail -n 25 /tmp/saas-b13-apply.log >&2
      fail
    }
PGOPTIONS='-c saas.staging_only=true' psql -X -v ON_ERROR_STOP=1 \
  -d saas_staging_ci -f tests/sql/saas_backend13_principal_lifecycle.test.sql \
  > /tmp/saas-b13-contract.log 2>&1 || {
    tail -n 25 /tmp/saas-b13-contract.log >&2
    fail
  }
grep -q 'PASS Backend13' /tmp/saas-b13-contract.log || fail

# Backend13 is not replayable after even an UNKNOWN COMMIT.
if PGOPTIONS='-c saas.staging_only=true' \
  PGUSER=saas_schema_migrator PGPASSWORD="$migrator_password" \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
    -v expected_0004_sha256="$sha4" -v migration_sha256="$sha5" \
    -v source_commit="$GITHUB_SHA" \
    -f staging/saas-bootstrap/0005_principal_lifecycle_revocation_fence.sql \
    > /tmp/saas-b13-replay-refused.log 2>&1; then fail; fi
if PGOPTIONS='-c saas.staging_only=true' \
  PGUSER=saas_schema_migrator PGPASSWORD="$migrator_password" \
  psql -X -v ON_ERROR_STOP=1 -d saas_ephemeral_test \
    -v expected_0004_sha256="$sha4" -v migration_sha256="$sha5" \
    -v source_commit="$GITHUB_SHA" \
    -f staging/saas-bootstrap/0005_principal_lifecycle_revocation_fence.sql \
    > /tmp/saas-b13-pilot-refused.log 2>&1; then fail; fi

a_pw="$(openssl rand -hex 32)"
b_pw="$(openssl rand -hex 32)"
c_pw="$(openssl rand -hex 32)"
[[ "$a_pw" =~ ^[a-f0-9]{64}$ && "$b_pw" =~ ^[a-f0-9]{64}$ && "$c_pw" =~ ^[a-f0-9]{64}$ ]] || fail
PGOPTIONS='-c saas.staging_only=true' \
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -v a_pw="$a_pw" -v b_pw="$b_pw" -v c_pw="$c_pw" \
  > /tmp/saas-b13-fixture.log 2>&1 <<'SQL'
CREATE ROLE saas_b13_a LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD :'a_pw';
CREATE ROLE saas_b13_b LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD :'b_pw';
CREATE ROLE saas_b13_c LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD :'c_pw';
GRANT saas_runtime_reader TO saas_b13_a,saas_b13_c;
GRANT saas_runtime_writer TO saas_b13_b;
GRANT CONNECT ON DATABASE saas_staging_ci TO saas_b13_a,saas_b13_b,saas_b13_c;
INSERT INTO saas_data.tenants(tenant_key,display_name) VALUES
 ('ci_alpha','CI Alpha'),('ci_beta','CI Beta'),('ci_third','CI Unmapped');
INSERT INTO saas_data.projects(tenant_id,project_key,display_name)
 SELECT tenant_id,'ci_project','Synthetic' FROM saas_data.tenants;
SQL

admin(){
  PGOPTIONS='-c saas.staging_only=true' PGUSER=postgres \
    psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$1"
}
read_as(){
  PGOPTIONS='-c saas.staging_only=true' PGUSER="$1" PGPASSWORD="$2" \
    psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$3"
}
check(){
  local label="$1" want="$2" got="$3"
  [[ "$want" == "$got" ]] || {
    printf 'Backend13 fixture %s expected=%q observed=%q\n' "$label" "$want" "$got" >&2
    fail
  }
}
a_grant="SELECT saas_acl.change_principal_access('saas_b13_a',(SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_alpha'),0,'reader','ci approve alpha login')"
b_grant="SELECT saas_acl.change_principal_access('saas_b13_b',(SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_beta'),0,'writer','ci approve beta login')"
check grant_a 1 "$(admin "$a_grant")"
check grant_b 1 "$(admin "$b_grant")"
check see_alpha ci_alpha "$(read_as saas_b13_a "$a_pw" 'SELECT tenant_key FROM saas_data.tenants')"
check see_beta ci_beta "$(read_as saas_b13_b "$b_pw" 'SELECT tenant_key FROM saas_data.tenants')"
check see_unmapped '' "$(read_as saas_b13_c "$c_pw" 'SELECT tenant_key FROM saas_data.tenants')"
check project_a 1 "$(read_as saas_b13_a "$a_pw" 'SELECT COUNT(*) FROM saas_data.projects')"
check project_b 1 "$(read_as saas_b13_b "$b_pw" 'SELECT COUNT(*) FROM saas_data.projects')"
check project_c 0 "$(read_as saas_b13_c "$c_pw" 'SELECT COUNT(*) FROM saas_data.projects')"
# Both spoofed custom GUC and explicit SET ROLE do not change session_user.
check spoofed_tenant ci_alpha "$(read_as saas_b13_a "$a_pw" \
  "SET saas.tenant_id='ci_beta'; SELECT tenant_key FROM saas_data.tenants")"
check set_role ci_alpha "$(read_as saas_b13_a "$a_pw" \
  'SET ROLE saas_runtime_reader; SELECT tenant_key FROM saas_data.tenants')"

# Duplicate first-grant/cross-tenant active scope, unknown principal, and
# unexpected initial revoked state must fail without new ledger events.
for sql in \
  "$a_grant" \
  "SELECT saas_acl.change_principal_access('saas_b13_a',(SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_beta'),0,'reader','ci forged second tenant')" \
  "SELECT saas_acl.change_principal_access('saas_b13_missing',(SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_alpha'),0,'reader','ci missing role forbidden')" \
  "SELECT saas_acl.change_principal_access('saas_b13_c',(SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_third'),0,'revoked','ci no prior grant revoke')"; do
  if admin "$sql" > /tmp/saas-b13-negative.log 2>&1; then fail; fi
done
# Untrusted LOGIN cannot read/write the ACL or call the operator function,
# even after setting an attacker-selected operator GUC.
for cmd in \
  "SELECT * FROM saas_acl.principal_access_audit" \
  "SELECT * FROM saas_acl.principal_tenants" \
  "UPDATE saas_acl.principal_tenants SET access_level='writer'" \
  "SELECT saas_acl.change_principal_access('saas_b13_a','00000000-0000-0000-0000-000000000000',1,'writer','ci forged operator grant')" \
  "SET saas.b13.operator_reason='fake operator intent'; DELETE FROM saas_acl.principal_tenants"; do
  if read_as saas_b13_a "$a_pw" "$cmd" > /tmp/saas-b13-negative.log 2>&1; then fail; fi
done
# A superuser can override DB auditing by disabling triggers; in ordinary
# SQL, however, append-only triggers reject rewriting audit or raw DML.
for cmd in \
  "UPDATE saas_acl.principal_access_audit SET reason='ci forged audit evidence'" \
  "DELETE FROM saas_acl.principal_access_audit" \
  "TRUNCATE saas_acl.principal_access_audit" \
  "DELETE FROM saas_acl.principal_tenants"; do
  if admin "$cmd" > /tmp/saas-b13-negative.log 2>&1; then fail; fi
done

# Revocation ACK denies all NEW reads. Regrant requires the monotonic
# tombstone revision, and a stale revision cannot resurrect an old grant.
b_revoke="SELECT saas_acl.change_principal_access('saas_b13_b',(SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_beta'),1,'revoked','ci revoke beta login')"
b_regrant="SELECT saas_acl.change_principal_access('saas_b13_b',(SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_beta'),2,'writer','ci reapprove beta login')"
check rev_b 2 "$(admin "$b_revoke")"
check b_cannot_read 0 "$(read_as saas_b13_b "$b_pw" 'SELECT COUNT(*) FROM saas_data.projects')"
if admin "$b_grant" > /tmp/saas-b13-stale.log 2>&1; then fail; fi
check regrant_b 3 "$(admin "$b_regrant")"
check b_regranted 1 "$(read_as saas_b13_b "$b_pw" 'SELECT COUNT(*) FROM saas_data.projects')"
if admin "$b_revoke" > /tmp/saas-b13-stale.log 2>&1; then fail; fi
check b_revision3 3 "$(admin "SELECT access_revision FROM saas_acl.principal_tenants WHERE principal_name='saas_b13_b'")"

# Existing transaction takes FOR SHARE of ACL row via VOLATILE RLS, so
# a concurrent revoke cannot claim success until that transaction releases
# its grant. Lock timeout is a certain statement rollback, NOT unknown COMMIT.
PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_b13_a PGPASSWORD="$a_pw" \
  psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci \
  > /tmp/saas-b13-held-read.log 2>&1 <<'SQL' &
BEGIN;
SELECT COUNT(*) FROM saas_data.projects;
\echo B13_READ_LOCK_HELD
SELECT pg_sleep(6);
COMMIT;
SQL
hold_pid=$!
held=0
for i in $(seq 1 60); do
  if grep -q 'B13_READ_LOCK_HELD' /tmp/saas-b13-held-read.log; then
    held=1
    break
  fi
  sleep 0.1
done
[[ "$held" == 1 ]] || {
  wait "$hold_pid" || true
  fail
}
a_revoke="SELECT saas_acl.change_principal_access('saas_b13_a',(SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_alpha'),1,'revoked','ci revoke alpha after read')"
if PGOPTIONS='-c saas.staging_only=true -c lock_timeout=150ms' PGUSER=postgres \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$a_revoke" \
  > /tmp/saas-b13-held-revoke-denied.log 2>&1; then
  wait "$hold_pid" || true
  fail
fi
check a_still_active 1 "$(admin "SELECT access_revision FROM saas_acl.principal_tenants WHERE principal_name='saas_b13_a'")"
wait "$hold_pid" || fail
check rev_a 2 "$(admin "$a_revoke")"
check a_after_revoke 0 "$(read_as saas_b13_a "$a_pw" 'SELECT COUNT(*) FROM saas_data.projects')"
check no_stale_a 0 "$(read_as saas_b13_a "$a_pw" "SET saas.tenant_id='ci_alpha'; SELECT COUNT(*) FROM saas_data.projects")"
check ledger_after5 5 "$(admin 'SELECT COUNT(*) FROM saas_bootstrap.schema_migrations')"
check audit5 5 "$(admin 'SELECT COUNT(*) FROM saas_acl.principal_access_audit')"
check audit_revision3 3 "$(admin "SELECT MAX(revision) FROM saas_acl.principal_access_audit WHERE principal_name='saas_b13_b'")"
check old_beta_access_revoked_then_regrant 'writer' "$(admin "SELECT new_access FROM saas_acl.principal_access_audit WHERE principal_name='saas_b13_b' AND revision=3")"

visible="$(PGOPTIONS='-c saas.staging_only=true' \
 PGUSER=saas_schema_migrator PGPASSWORD="$migrator_password" \
 psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -c 'SELECT COUNT(*) FROM saas_data.projects')" || fail
check owner_force_rls 0 "$visible"
unset a_pw b_pw c_pw migrator_password
echo 'PASS Backend13: live PG16 CAS/tombstone/atomic audit, FOR SHARE revoke fence and tenant isolation'

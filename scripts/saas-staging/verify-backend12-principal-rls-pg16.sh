#!/usr/bin/env bash
# Backend12 disposable PostgreSQL16 CI ONLY, never against Railway.
set -euo pipefail
fail(){ echo 'Backend12 disposable PostgreSQL16 CI proof refused or failed' >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == 'true' && "${SAAS_B12_EPHEMERAL_CI:-}" == 'true' ]] || fail
[[ "${PGHOST:-}" == '127.0.0.1' && "${PGPORT:-}" == '5432' ]] || fail
[[ "${PGDATABASE:-}" == 'saas_ephemeral_test' && "${PGUSER:-}" == 'postgres' ]] || fail
[[ -z "${RAILWAY_PROJECT_ID:-}" && -z "${RAILWAY_ENVIRONMENT:-}" ]] || fail
[[ -z "${RAILWAY_SERVICE_ID:-}" && "${NODE_ENV:-}" != 'production' ]] || fail
[[ "${SAAS_B12_EPHEMERAL_MIGRATOR_PASSWORD:-}" =~ ^[a-f0-9]{64}$ ]] || fail
migrator_pw="$SAAS_B12_EPHEMERAL_MIGRATOR_PASSWORD"
unset SAAS_B12_EPHEMERAL_MIGRATOR_PASSWORD
[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || fail
roles_sha="$(sha256sum staging/saas-bootstrap/0003_operator_runtime_roles.sql | cut -d ' ' -f1)"
policy_sha="$(sha256sum staging/saas-bootstrap/0004_principal_bound_read_rls.sql | cut -d ' ' -f1)"
[[ "$roles_sha" =~ ^[a-f0-9]{64}$ && "$policy_sha" =~ ^[a-f0-9]{64}$ ]] || fail

PGOPTIONS="-c saas.staging_only=true" psql -X -v ON_ERROR_STOP=1 \
  -d saas_staging_ci \
  -v migration_sha256="$roles_sha" -v source_commit="$GITHUB_SHA" \
  -f staging/saas-bootstrap/0003_operator_runtime_roles.sql \
  > /tmp/saas-b12-role-create.log 2>&1 || {
    tail -n 20 /tmp/saas-b12-role-create.log >&2
    fail
  }
PGOPTIONS="-c saas.staging_only=true" \
PGUSER=saas_schema_migrator PGPASSWORD="$migrator_pw" \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
    -v expected_0003_sha256="$roles_sha" \
    -v migration_sha256="$policy_sha" -v source_commit="$GITHUB_SHA" \
    -f staging/saas-bootstrap/0004_principal_bound_read_rls.sql \
    > /tmp/saas-b12-rls-apply.log 2>&1 || {
      tail -n 22 /tmp/saas-b12-rls-apply.log >&2
      fail
    }
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -f tests/sql/saas_backend12_principal_rls.test.sql \
  > /tmp/saas-b12-contract.log 2>&1 || {
    tail -n 20 /tmp/saas-b12-contract.log >&2
    fail
  }
grep -q 'PASS Backend12' /tmp/saas-b12-contract.log || fail

# UNKNOWN COMMIT = STOP; neither replay nor pilot DB is acceptable.
if PGOPTIONS="-c saas.staging_only=true" \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
    -v migration_sha256="$roles_sha" -v source_commit="$GITHUB_SHA" \
    -f staging/saas-bootstrap/0003_operator_runtime_roles.sql \
    > /tmp/saas-b12-role-replay-denied.log 2>&1; then fail; fi
if PGOPTIONS="-c saas.staging_only=true" \
  PGUSER=saas_schema_migrator PGPASSWORD="$migrator_pw" \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
    -v expected_0003_sha256="$roles_sha" -v migration_sha256="$policy_sha" \
    -v source_commit="$GITHUB_SHA" \
    -f staging/saas-bootstrap/0004_principal_bound_read_rls.sql \
    > /tmp/saas-b12-policy-replay-denied.log 2>&1; then fail; fi
if PGOPTIONS="-c saas.staging_only=true" \
  psql -X -v ON_ERROR_STOP=1 -d saas_ephemeral_test \
    -v migration_sha256="$roles_sha" -v source_commit="$GITHUB_SHA" \
    -f staging/saas-bootstrap/0003_operator_runtime_roles.sql \
    > /tmp/saas-b12-pilot-denied.log 2>&1; then fail; fi

fixture_a_pw="$(openssl rand -hex 32)"
fixture_b_pw="$(openssl rand -hex 32)"
fixture_c_pw="$(openssl rand -hex 32)"
[[ "$fixture_a_pw" =~ ^[a-f0-9]{64}$ ]] || fail
[[ "$fixture_b_pw" =~ ^[a-f0-9]{64}$ ]] || fail
[[ "$fixture_c_pw" =~ ^[a-f0-9]{64}$ ]] || fail

# Synthetic fixture roles + records ONLY in disposable GitHub PG16.
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -v a_pw="$fixture_a_pw" -v b_pw="$fixture_b_pw" -v c_pw="$fixture_c_pw" \
  > /tmp/saas-b12-fixture-create.log 2>&1 <<'SQL'
CREATE ROLE saas_scope_a LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'a_pw';
CREATE ROLE saas_scope_b LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'b_pw';
CREATE ROLE saas_scope_c LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'c_pw';
GRANT saas_runtime_reader TO saas_scope_a,saas_scope_c;
GRANT saas_runtime_writer TO saas_scope_b;
GRANT CONNECT ON DATABASE saas_staging_ci TO saas_scope_a,saas_scope_b,saas_scope_c;
INSERT INTO saas_data.tenants(tenant_key,display_name) VALUES
  ('ci_tenant_alpha','Synthetic A'), ('ci_tenant_beta','Synthetic B'),
  ('ci_tenant_unbound','Unmapped');
INSERT INTO saas_data.projects(tenant_id,project_key,display_name)
  SELECT tenant_id,'ci_proj','CI Only' FROM saas_data.tenants;
INSERT INTO saas_acl.principal_tenants(principal_name,tenant_id,access_level)
  SELECT 'saas_scope_a',tenant_id,'reader' FROM saas_data.tenants
    WHERE tenant_key='ci_tenant_alpha';
INSERT INTO saas_acl.principal_tenants(principal_name,tenant_id,access_level)
  SELECT 'saas_scope_b',tenant_id,'writer' FROM saas_data.tenants
    WHERE tenant_key='ci_tenant_beta';
SQL

read_as(){
  local login="$1" pass="$2" sql="$3"
  PGOPTIONS="-c saas.staging_only=true" PGUSER="$login" PGPASSWORD="$pass" \
    psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$sql"
}
case_index=0
expect_as(){
  local wanted="$1" login="$2" pass="$3" sql="$4" got
  case_index=$((case_index + 1))
  got="$(read_as "$login" "$pass" "$sql")" || fail
  [[ "$got" == "$wanted" ]] || {
    # The only values here are synthetic CI tenants, never real data.
    printf 'Backend12 synthetic isolation case %d expected=%q actual=%q\n' \
      "$case_index" "$wanted" "$got" >&2
    fail
  }
}
expect_as 'ci_tenant_alpha' saas_scope_a "$fixture_a_pw" \
  'SELECT tenant_key FROM saas_data.tenants ORDER BY tenant_key'
expect_as 'ci_tenant_beta' saas_scope_b "$fixture_b_pw" \
  'SELECT tenant_key FROM saas_data.tenants ORDER BY tenant_key'
expect_as '' saas_scope_c "$fixture_c_pw" \
  'SELECT tenant_key FROM saas_data.tenants ORDER BY tenant_key'
expect_as '1' saas_scope_a "$fixture_a_pw" \
  'SELECT COUNT(*) FROM saas_data.projects'
expect_as '1' saas_scope_b "$fixture_b_pw" \
  'SELECT COUNT(*) FROM saas_data.projects'
expect_as '0' saas_scope_c "$fixture_c_pw" \
  'SELECT COUNT(*) FROM saas_data.projects'
# Spoofed GUC and SET ROLE do not replace authenticated session_user.
expect_as 'ci_tenant_alpha' saas_scope_a "$fixture_a_pw" \
  "SET saas.tenant_id='ci_tenant_beta'; SELECT tenant_key FROM saas_data.tenants"
expect_as 'ci_tenant_alpha' saas_scope_a "$fixture_a_pw" \
  "SET ROLE saas_runtime_reader; SELECT tenant_key FROM saas_data.tenants"
if PGOPTIONS="-c saas.staging_only=true" PGUSER=saas_scope_a PGPASSWORD="$fixture_a_pw" \
   psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
     -c 'SET ROLE saas_runtime_writer' > /tmp/saas-b12-role-escalation-denied.log 2>&1; then fail; fi

for login in saas_scope_a saas_scope_b; do
  pass="$fixture_a_pw"
  [[ "$login" == 'saas_scope_b' ]] && pass="$fixture_b_pw"
  for statement in \
    "INSERT INTO saas_data.tenants (tenant_key, display_name) VALUES ('ci_hijack', 'Denied')" \
    "UPDATE saas_data.projects SET display_name='Hijack' WHERE project_key='ci_proj'" \
    "DELETE FROM saas_data.projects WHERE project_key='ci_proj'" \
    "SELECT * FROM saas_acl.principal_tenants" \
    "INSERT INTO saas_acl.principal_tenants(principal_name,tenant_id,access_level) SELECT '$login',tenant_id,'writer' FROM saas_data.tenants LIMIT 1" \
    "SELECT * FROM saas_bootstrap.schema_migrations"; do
    if PGOPTIONS="-c saas.staging_only=true" PGUSER="$login" PGPASSWORD="$pass" \
      psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$statement" \
      > /tmp/saas-b12-runtime-denied.log 2>&1; then fail; fi
  done
done

visible="$(PGOPTIONS='-c saas.staging_only=true' \
  PGUSER=saas_schema_migrator PGPASSWORD="$migrator_pw" \
  psql -XAt -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -c 'SELECT COUNT(*) FROM saas_data.projects')" || fail
[[ "$visible" == '0' ]] || fail

unset fixture_a_pw fixture_b_pw fixture_c_pw migrator_pw
echo 'PASS Backend12: real PG16 tenant isolation, spoofed GUC/SET ROLE denied, read-only grants, no replay'

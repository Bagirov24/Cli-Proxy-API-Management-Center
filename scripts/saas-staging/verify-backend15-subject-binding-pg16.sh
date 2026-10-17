#!/usr/bin/env bash
# Backend15 disposable GitHub Actions PostgreSQL16 ONLY, AFTER Backend14.
set -euo pipefail
fail(){ echo 'Backend15 isolated PG16 subject-binding acceptance failed/refused' >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == 'true' && "${SAAS_B15_EPHEMERAL_CI:-}" == 'true' ]] || fail
[[ "${PGHOST:-}" == '127.0.0.1' && "${PGPORT:-}" == '5432' &&
   "${PGUSER:-}" == 'postgres' && "${PGDATABASE:-}" == 'saas_ephemeral_test' ]] || fail
[[ -z "${RAILWAY_PROJECT_ID:-}" && -z "${RAILWAY_SERVICE_ID:-}" &&
   -z "${RAILWAY_ENVIRONMENT:-}" && "${NODE_ENV:-}" != 'production' ]] || fail
[[ "${SAAS_B15_EPHEMERAL_MIGRATOR_PASSWORD:-}" =~ ^[a-f0-9]{64}$ ]] || fail
migrator_pw="$SAAS_B15_EPHEMERAL_MIGRATOR_PASSWORD"
unset SAAS_B15_EPHEMERAL_MIGRATOR_PASSWORD
[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || fail
sql_sha="$(sha256sum staging/saas-bootstrap/0007_operator_subject_binding_fence.sql | cut -d ' ' -f1)"
prior_sha="$(sha256sum staging/saas-bootstrap/0006_principal_session_fence.sql | cut -d ' ' -f1)"
[[ "$sql_sha" =~ ^[a-f0-9]{64}$ &&
   "$prior_sha" == 'b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505' ]] || fail
PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_schema_migrator PGPASSWORD="$migrator_pw" \
 psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -v expected_0006_sha256="$prior_sha" -v migration_sha256="$sql_sha" \
 -v source_commit="$GITHUB_SHA" \
 -f staging/saas-bootstrap/0007_operator_subject_binding_fence.sql \
 > /tmp/b15-apply.log 2>&1 || { tail -n 20 /tmp/b15-apply.log >&2; fail; }
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -f tests/sql/saas_backend15_subject_binding.test.sql \
 > /tmp/b15-contract.log 2>&1 || { tail -n 18 /tmp/b15-contract.log >&2; fail; }
grep -q 'PASS Backend15' /tmp/b15-contract.log || fail
if PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_schema_migrator PGPASSWORD="$migrator_pw" \
 psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -v expected_0006_sha256="$prior_sha" -v migration_sha256="$sql_sha" \
 -v source_commit="$GITHUB_SHA" \
 -f staging/saas-bootstrap/0007_operator_subject_binding_fence.sql \
 > /tmp/b15-replay-denied.log 2>&1; then fail; fi
if PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_schema_migrator PGPASSWORD="$migrator_pw" \
 psql -X -v ON_ERROR_STOP=1 -d saas_ephemeral_test \
 -v expected_0006_sha256="$prior_sha" -v migration_sha256="$sql_sha" \
 -v source_commit="$GITHUB_SHA" \
 -f staging/saas-bootstrap/0007_operator_subject_binding_fence.sql \
 > /tmp/b15-wrong-db-denied.log 2>&1; then fail; fi

# Backend14 left synthetic saas_b14_person with an active session/grant rev3.
# Reset this disposable DB-login password. This NEVER runs on Railway.
actor_password="$(openssl rand -hex 32)"
[[ "$actor_password" =~ ^[a-f0-9]{64}$ ]] || fail
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci -v pwd="$actor_password" \
 > /tmp/b15-ci-login.log 2>&1 <<'SQL'
ALTER ROLE saas_b14_person PASSWORD :'pwd';
SQL
admin(){ PGOPTIONS='-c saas.staging_only=true' PGUSER=postgres \
 psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$1"; }
actor(){ PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_b14_person PGPASSWORD="$actor_password" \
 psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$1"; }
eq(){ [[ "$2" == "$3" ]] || {
 printf 'B15 synthetic assertion %s expected=%q actual=%q\n' "$1" "$2" "$3" >&2; fail; }; }
tenant="(SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_third')"
eq old_session_denied '' "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
fingerprint="$(printf 'saas:issuer-subject:v1\0https://synthetic-idp.invalid\0ci-subject-a' | sha256sum | cut -d ' ' -f1)"
[[ "$fingerprint" =~ ^[a-f0-9]{64}$ ]] || fail
binding="$(admin "SELECT saas_identity.register_subject_binding('saas_b14_person',$tenant,3,'$fingerprint','CI operator verified synthetic subject')")" || fail
[[ "$binding" =~ ^[0-9a-f-]{36}$ ]] || fail
eq prior_session_still_denied '' "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
old_session="$(admin "SELECT session_id FROM saas_identity.principal_sessions WHERE principal_name='saas_b14_person' AND revoked_at IS NULL")"
[[ "$old_session" =~ ^[0-9a-f-]{36}$ ]] || fail
eq old_revoked 2 "$(admin "SELECT saas_identity.revoke_principal_session('$old_session',1,'CI revoke pre-binding session')")"
for sql in \
 "SELECT saas_identity.register_subject_binding('saas_b14_person',$tenant,1,'$fingerprint','CI stale grant revision rejected')" \
 "SELECT saas_identity.register_subject_binding('saas_b14_person',$tenant,3,'$fingerprint','CI duplicate subject rejected')" \
 "SELECT saas_identity.issue_principal_session('saas_b14_person',$tenant,3,'11111111-1111-4111-8111-111111111111',clock_timestamp()+interval '5 minutes','CI unknown identity reference rejected')"; do
 if admin "$sql" > /tmp/b15-enrollment-denied.log 2>&1; then fail; fi
done
session="$(admin "SELECT saas_identity.issue_principal_session('saas_b14_person',$tenant,3,'$binding',clock_timestamp()+interval '7 minutes','CI verified subject binding session')")" || fail
[[ "$session" =~ ^[0-9a-f-]{36}$ ]] || fail
eq authorized ci_third "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
eq spoofed_guc ci_third "$(actor "SET saas.tenant_id='ci_alpha'; SELECT tenant_key FROM saas_data.tenants")"
eq set_role ci_third "$(actor 'SET ROLE saas_runtime_reader; SELECT tenant_key FROM saas_data.tenants')"
for sql in \
 "SELECT * FROM saas_identity.subject_bindings" \
 "SELECT * FROM saas_identity.subject_binding_events" \
 "SELECT saas_identity.revoke_subject_binding('$binding',1,'CI unauthorized revoke')" \
 "INSERT INTO saas_data.tenants(tenant_key,display_name) VALUES ('ci_b15_forbidden','Denied')"; do
 if actor "$sql" > /tmp/b15-runtime-denied.log 2>&1; then fail; fi
done
# A live scoped SELECT retains ACL/session/binding FOR SHARE until COMMIT.
PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_b14_person PGPASSWORD="$actor_password" \
 psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci > /tmp/b15-held.log 2>&1 <<'SQL' &
BEGIN;
SELECT COUNT(*) FROM saas_data.tenants;
\echo B15_BINDING_READ_LOCK_HELD
SELECT pg_sleep(4);
COMMIT;
SQL
reader_pid=$!
held=0
for i in $(seq 1 60); do
 if grep -q B15_BINDING_READ_LOCK_HELD /tmp/b15-held.log; then held=1; break; fi
 sleep 0.1
done
[[ "$held" == 1 ]] || { wait "$reader_pid" || true; fail; }
if PGOPTIONS='-c saas.staging_only=true -c lock_timeout=150ms' PGUSER=postgres \
 psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -c "SELECT saas_identity.revoke_subject_binding('$binding',1,'CI revoke blocked by reader')" \
 > /tmp/b15-lock-denied.log 2>&1; then wait "$reader_pid" || true; fail; fi
eq no_false_ack 1 "$(admin "SELECT binding_revision FROM saas_identity.subject_bindings WHERE binding_id='$binding'")"
wait "$reader_pid" || fail
eq revoked 2 "$(admin "SELECT saas_identity.revoke_subject_binding('$binding',1,'CI explicit subject binding revoke')")"
eq denied_after_revoke '' "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
eq audit_issued 1 "$(admin "SELECT COUNT(*) FROM saas_identity.subject_binding_events WHERE kind='enrolled'")"
eq audit_revoked 1 "$(admin "SELECT COUNT(*) FROM saas_identity.subject_binding_events WHERE kind='revoked'")"
eq receipts 7 "$(admin 'SELECT COUNT(*) FROM saas_bootstrap.schema_migrations')"
for sql in \
 "SELECT saas_identity.revoke_subject_binding('$binding',1,'CI stale revocation rejected')" \
 "SELECT saas_identity.register_subject_binding('saas_b14_person',$tenant,3,'$fingerprint','CI spent digest must never rebind')" \
 "UPDATE saas_identity.subject_bindings SET status='active',revoked_at=NULL WHERE binding_id='$binding'" \
 "DELETE FROM saas_identity.subject_bindings WHERE binding_id='$binding'" \
 "UPDATE saas_identity.subject_binding_events SET kind='enrolled' WHERE binding_id='$binding'" \
 "TRUNCATE saas_identity.subject_binding_events"; do
 if admin "$sql" > /tmp/b15-abuse-denied.log 2>&1; then fail; fi
done
eq session_revoke 2 "$(admin "SELECT saas_identity.revoke_principal_session('$session',1,'CI end revoked binding session')")"
if admin "SELECT saas_identity.issue_principal_session('saas_b14_person',$tenant,3,'$binding',clock_timestamp()+interval '5 minutes','CI revoked subject cannot log in')" \
 > /tmp/b15-session-denied.log 2>&1; then fail; fi
unset actor_password migrator_pw
echo 'PASS Backend15: private PG16 identity digest enrollment, RLS deny old sessions, revoke FOR SHARE, no role escalation'

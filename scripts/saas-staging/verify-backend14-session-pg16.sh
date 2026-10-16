#!/usr/bin/env bash
# Backend14: GitHub disposable loopback PG16 only. NEVER Railway or production.
set -euo pipefail
fail(){ echo 'Backend14 disposable PG16 session proof failed/refused' >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == 'true' && "${SAAS_B14_EPHEMERAL_CI:-}" == 'true' ]] || fail
[[ "${PGHOST:-}" == '127.0.0.1' && "${PGPORT:-}" == '5432' ]] || fail
[[ "${PGUSER:-}" == 'postgres' && "${PGDATABASE:-}" == 'saas_ephemeral_test' ]] || fail
[[ -z "${RAILWAY_PROJECT_ID:-}" && -z "${RAILWAY_ENVIRONMENT_ID:-}" && -z "${RAILWAY_SERVICE_ID:-}" ]] || fail
[[ "${NODE_ENV:-}" != 'production' ]] || fail
[[ "${SAAS_B14_EPHEMERAL_MIGRATOR_PASSWORD:-}" =~ ^[a-f0-9]{64}$ ]] || fail
[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || fail
migrator_pw="$SAAS_B14_EPHEMERAL_MIGRATOR_PASSWORD"
unset SAAS_B14_EPHEMERAL_MIGRATOR_PASSWORD
sha5="$(sha256sum staging/saas-bootstrap/0005_principal_lifecycle_revocation_fence.sql | cut -d' ' -f1)"
sha6="$(sha256sum staging/saas-bootstrap/0006_principal_session_fence.sql | cut -d' ' -f1)"
[[ "$sha5" == 'b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556' ]] || fail
[[ "$sha6" =~ ^[a-f0-9]{64}$ ]] || fail
PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_schema_migrator PGPASSWORD="$migrator_pw" \
 psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -v expected_0005_sha256="$sha5" -v migration_sha256="$sha6" -v source_commit="$GITHUB_SHA" \
 -f staging/saas-bootstrap/0006_principal_session_fence.sql > /tmp/b14-apply.log 2>&1 || {
 tail -n 30 /tmp/b14-apply.log >&2; fail;
}
PGOPTIONS='-c saas.staging_only=true' \
 psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -f tests/sql/saas_backend14_session_fence.test.sql > /tmp/b14-contract.log 2>&1 || {
 tail -n 25 /tmp/b14-contract.log >&2; fail;
}
grep -q 'PASS Backend14:' /tmp/b14-contract.log || fail
# No replay after COMMIT and no synthetic pilot DB imports.
if PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_schema_migrator PGPASSWORD="$migrator_pw" \
 psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci -v expected_0005_sha256="$sha5" \
 -v migration_sha256="$sha6" -v source_commit="$GITHUB_SHA" \
 -f staging/saas-bootstrap/0006_principal_session_fence.sql > /tmp/b14-replay-denied.log 2>&1; then fail; fi
if PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_schema_migrator PGPASSWORD="$migrator_pw" \
 psql -X -v ON_ERROR_STOP=1 -d saas_ephemeral_test -v expected_0005_sha256="$sha5" \
 -v migration_sha256="$sha6" -v source_commit="$GITHUB_SHA" \
 -f staging/saas-bootstrap/0006_principal_session_fence.sql > /tmp/b14-pilot-denied.log 2>&1; then fail; fi

password="$(openssl rand -hex 32)"
[[ "$password" =~ ^[a-f0-9]{64}$ ]] || fail
# A synthetic unmapped tenant 'ci_third' remains after Backend13 CI.
PGOPTIONS='-c saas.staging_only=true' psql -X -v ON_ERROR_STOP=1 \
 -d saas_staging_ci -v pwd="$password" > /tmp/b14-fixture.log 2>&1 <<'SQL'
CREATE ROLE saas_b14_person LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'pwd';
GRANT saas_runtime_reader TO saas_b14_person;
GRANT CONNECT ON DATABASE saas_staging_ci TO saas_b14_person;
SQL
admin(){ PGOPTIONS='-c saas.staging_only=true' PGUSER=postgres \
 psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$1"; }
actor(){ PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_b14_person PGPASSWORD="$password" \
 psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$1"; }
eq(){ if [[ "$2" != "$3" ]]; then printf 'B14 CI fixture %s expected=%q actual=%q\n' "$1" "$2" "$3" >&2; fail; fi; }
tenant="(SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_third')"
grant="SELECT saas_acl.change_principal_access('saas_b14_person',$tenant,0,'reader','CI approve disposable session actor')"
eq grant 1 "$(admin "$grant")"
eq default_deny '' "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
eq no_project 0 "$(actor 'SELECT COUNT(*) FROM saas_data.projects')"
id1="$(admin "SELECT saas_identity.issue_principal_session('saas_b14_person',$tenant,1,'11111111-1111-4111-8111-111111111111',clock_timestamp()+interval '4 seconds','CI temporary short-lived session')")" || fail
[[ "$id1" =~ ^[a-f0-9-]{36}$ ]] || fail
eq scope_before_expiry ci_third "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
eq spoofed_tenant ci_third "$(actor "SET saas.tenant_id='ci_alpha'; SELECT tenant_key FROM saas_data.tenants")"
eq set_role ci_third "$(actor 'SET ROLE saas_runtime_reader; SELECT tenant_key FROM saas_data.tenants')"
sleep 5
eq expired_deny '' "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
# Expired-but-unrevoked session is a tombstone candidate; new login requires an explicit revoke.
if admin "SELECT saas_identity.issue_principal_session('saas_b14_person',$tenant,1,'22222222-2222-4222-8222-222222222222',clock_timestamp()+interval '10 minutes','CI duplicate active session refused')" > /tmp/b14-denied.log 2>&1; then fail; fi
eq expired_revoked 2 "$(admin "SELECT saas_identity.revoke_principal_session('$id1',1,'CI explicitly revoke expired login')")"
id2="$(admin "SELECT saas_identity.issue_principal_session('saas_b14_person',$tenant,1,'22222222-2222-4222-8222-222222222222',clock_timestamp()+interval '10 minutes','CI second synthetic operator session')")" || fail
eq valid_scope ci_third "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
# A reader transaction holds FOR SHARE on session; revoke cannot ACK until COMMIT.
PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_b14_person PGPASSWORD="$password" \
 psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci > /tmp/b14-held.log 2>&1 <<'SQL' &
BEGIN;
SELECT COUNT(*) FROM saas_data.projects;
\echo B14_READ_LOCK_HELD
SELECT pg_sleep(5);
COMMIT;
SQL
reader_pid=$!
held=0
for i in $(seq 1 70); do
 if grep -q B14_READ_LOCK_HELD /tmp/b14-held.log; then held=1; break; fi
 sleep 0.1
done
[[ "$held" == 1 ]] || { wait "$reader_pid" || true; fail; }
if PGOPTIONS='-c saas.staging_only=true -c lock_timeout=150ms' PGUSER=postgres \
 psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -c "SELECT saas_identity.revoke_principal_session('$id2',1,'CI concurrent revoke is blocked')" \
 > /tmp/b14-lock-denied.log 2>&1; then wait "$reader_pid" || true; fail; fi
eq no_false_ack 1 "$(admin "SELECT session_revision FROM saas_identity.principal_sessions WHERE session_id='$id2'")"
wait "$reader_pid" || fail
eq revoked 2 "$(admin "SELECT saas_identity.revoke_principal_session('$id2',1,'CI revoke after reader COMMIT')")"
eq revoked_denies 0 "$(actor 'SELECT COUNT(*) FROM saas_data.projects')"
for statement in \
 "SELECT saas_identity.revoke_principal_session('$id2',1,'CI stale replay forbidden')" \
 "SELECT saas_identity.issue_principal_session('saas_b14_person',$tenant,2,'33333333-3333-4333-8333-333333333333',clock_timestamp()+interval '10 minutes','CI wrong grant revision refused')" \
 "UPDATE saas_identity.principal_sessions SET expires_at=expires_at+interval '1 hour' WHERE session_id='$id2'" \
 "DELETE FROM saas_identity.principal_sessions WHERE session_id='$id2'" \
 "UPDATE saas_identity.session_events SET reason='CI forged event text'" \
 "DELETE FROM saas_identity.session_events" \
 "TRUNCATE saas_identity.session_events" \
 "TRUNCATE saas_identity.principal_sessions"; do
 if admin "$statement" > /tmp/b14-denied.log 2>&1; then fail; fi
done
for statement in \
 "SELECT * FROM saas_identity.principal_sessions" \
 "SELECT * FROM saas_identity.session_events" \
 "SELECT saas_identity.revoke_principal_session('$id1',1,'CI unauthenticated operator')" \
 "SET saas.b14.operator_reason='forged'; UPDATE saas_identity.principal_sessions SET revoked_at=clock_timestamp()" \
 "SELECT * FROM saas_acl.principal_tenants"; do
 if actor "$statement" > /tmp/b14-runtime-denied.log 2>&1; then fail; fi
done
# Changing ACL revision invalidates old session across revoke -> regrant (ABA).
id3="$(admin "SELECT saas_identity.issue_principal_session('saas_b14_person',$tenant,1,'33333333-3333-4333-8333-333333333333',clock_timestamp()+interval '10 minutes','CI session tied to prior grant')")" || fail
eq live_third ci_third "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
eq revoke_acl 2 "$(admin "SELECT saas_acl.change_principal_access('saas_b14_person',$tenant,1,'revoked','CI revoke tenant access fence')")"
eq denied_after_acl '' "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
eq regrant_acl 3 "$(admin "SELECT saas_acl.change_principal_access('saas_b14_person',$tenant,2,'reader','CI grant new authorized revision')")"
eq old_session_still_denied '' "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
eq clear_old 2 "$(admin "SELECT saas_identity.revoke_principal_session('$id3',1,'CI clear stale session after regrant')")"
id4="$(admin "SELECT saas_identity.issue_principal_session('saas_b14_person',$tenant,3,'44444444-4444-4444-8444-444444444444',clock_timestamp()+interval '10 minutes','CI new authenticated DB session')")" || fail
eq reauthorized ci_third "$(actor 'SELECT tenant_key FROM saas_data.tenants')"
eq events 7 "$(admin 'SELECT COUNT(*) FROM saas_identity.session_events')"
eq issued 4 "$(admin "SELECT COUNT(*) FROM saas_identity.session_events WHERE kind='issued'")"
eq revoked_events 3 "$(admin "SELECT COUNT(*) FROM saas_identity.session_events WHERE kind='revoked'")"
eq receipts 6 "$(admin 'SELECT COUNT(*) FROM saas_bootstrap.schema_migrations')"
if actor "INSERT INTO saas_data.tenants(tenant_key,display_name) VALUES ('ci_hijack','Denied')" > /tmp/b14-write-denied.log 2>&1; then fail; fi
unset password migrator_pw
echo 'PASS Backend14: real PG16 login expiry, session revocation lock, CAS grant fence, private audit and read-only scope'

#!/usr/bin/env bash
# Backend16.4 ephemeral GitHub PG16 ONLY, after SQL0007; never Railway.
set -euo pipefail
fail(){ echo 'Backend16 SQL0008 disposable PG16 acceptance STOP' >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == true && "${SAAS_B16_EPHEMERAL_CI:-}" == true ]] || fail
[[ "${PGHOST:-}" == 127.0.0.1 && "${PGPORT:-}" == 5432 &&
   "${PGUSER:-}" == postgres && "${PGDATABASE:-}" == saas_ephemeral_test ]] || fail
[[ -z "${RAILWAY_PROJECT_ID:-}" && -z "${RAILWAY_SERVICE_ID:-}" &&
   -z "${RAILWAY_ENVIRONMENT_ID:-}" && -z "${RAILWAY_ENVIRONMENT:-}" &&
   "${NODE_ENV:-}" != production ]] || fail
[[ "${SAAS_B16_EPHEMERAL_MIGRATOR_PASSWORD:-}" =~ ^[a-f0-9]{64}$ ]] || fail
migrator_pw="$SAAS_B16_EPHEMERAL_MIGRATOR_PASSWORD"
unset SAAS_B16_EPHEMERAL_MIGRATOR_PASSWORD
# Stable Bun v1.4.4 remains strictly a disposable EXTRA CI candidate.
# The exact-head, SHA256/revision-pinned binary was installed BEFORE canary.
[[ "${SAAS_B16_STABLE_144_FULL_PG16_CI:-}" == true &&
   "${B16_PR_HEAD_SHA:-}" =~ ^[0-9a-f]{40}$ &&
   "$(git rev-parse HEAD)" == "$B16_PR_HEAD_SHA" ]] || fail
[[ "${SAAS_B16_STABLE_144_BIN:-}" =~ ^/tmp/b16-official-stable-144-ci-[A-Za-z0-9]{6}/bun$ ]] || fail
[[ "$("$SAAS_B16_STABLE_144_BIN" --revision)" == '1.4.4+38afee6c8' ]] || fail

[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || fail
sha7="$(sha256sum staging/saas-bootstrap/0007_operator_subject_binding_fence.sql | cut -d ' ' -f1)"
sha8="$(sha256sum staging/saas-bootstrap/0008_exact_subject_session_gate.sql | cut -d ' ' -f1)"
[[ "$sha7" == 1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0 &&
   "$sha8" =~ ^[a-f0-9]{64}$ ]] || fail

# CI-only: independently inspect the seven-receipt baseline through a
# read-only REPEATABLE READ snapshot with the migrator SEALED. Re-enable it
# after the readback solely to apply one SQL0008 transaction in ephemeral PG16.
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -c 'ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL' \
  > /tmp/b16-preflight-ci-seal.log 2>&1 || fail
PGOPTIONS='-c saas.staging_only=true' PGUSER=postgres \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -v b16_expected_state=absent \
  -f scripts/saas-staging/backend16-0008-readonly-reconcile.sql \
  > /tmp/b16-readonly-absent.log 2>&1 ||
  { tail -n 14 /tmp/b16-readonly-absent.log >&2; fail; }
grep -q 'PASS_BACKEND16_SQL0008_READONLY_ABSENT_SEALED_NEVER_AUTO_INSTALL' \
  /tmp/b16-readonly-absent.log || fail
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -v ci_migrator_pwd="$migrator_pw" > /tmp/b16-ci-migrator-reenable.log 2>&1 <<'SQL'
ALTER ROLE saas_schema_migrator LOGIN PASSWORD :'ci_migrator_pwd';
SQL

PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_schema_migrator \
  PGPASSWORD="$migrator_pw" psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -v expected_0007_sha256="$sha7" -v migration_sha256="$sha8" \
  -v source_commit="$GITHUB_SHA" \
  -f staging/saas-bootstrap/0008_exact_subject_session_gate.sql \
  > /tmp/b16-apply.log 2>&1 || { tail -n 20 /tmp/b16-apply.log >&2; fail; }
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -f tests/sql/saas_backend16_exact_session_gate.test.sql \
  > /tmp/b16-contract.log 2>&1 || { tail -n 18 /tmp/b16-contract.log >&2; fail; }
grep -q 'PASS Backend16.4:' /tmp/b16-contract.log || fail
for database in saas_staging_ci saas_ephemeral_test; do
 if PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_schema_migrator \
    PGPASSWORD="$migrator_pw" psql -X -v ON_ERROR_STOP=1 -d "$database" \
    -v expected_0007_sha256="$sha7" -v migration_sha256="$sha8" \
    -v source_commit="$GITHUB_SHA" \
    -f staging/saas-bootstrap/0008_exact_subject_session_gate.sql \
    > /tmp/b16-replay-or-db-denied.log 2>&1; then fail; fi
done

# Seal again before independently observing the *installed* eight-receipt
# catalog. The inspection SQL cannot apply or retry any migration.
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -c 'ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL' \
  > /tmp/b16-postflight-ci-seal.log 2>&1 || fail
PGOPTIONS='-c saas.staging_only=true' PGUSER=postgres \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
  -v b16_expected_state=installed \
  -f scripts/saas-staging/backend16-0008-readonly-reconcile.sql \
  > /tmp/b16-readonly-installed.log 2>&1 ||
  { tail -n 14 /tmp/b16-readonly-installed.log >&2; fail; }
grep -q 'PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED' \
  /tmp/b16-readonly-installed.log || fail
bash scripts/saas-staging/verify-backend16-readonly-drift-ci.sh || fail

a_pw="$(openssl rand -hex 32)"
b_pw="$(openssl rand -hex 32)"
[[ "$a_pw" =~ ^[a-f0-9]{64}$ && "$b_pw" =~ ^[a-f0-9]{64}$ ]] || fail
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -v a_pwd="$a_pw" -v b_pwd="$b_pw" > /tmp/b16-ci-logins.log 2>&1 <<'SQL'
ALTER ROLE saas_b14_person PASSWORD :'a_pwd';
CREATE ROLE saas_b16_person_b LOGIN INHERIT NOSUPERUSER NOBYPASSRLS
  NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'b_pwd';
GRANT saas_runtime_reader TO saas_b16_person_b;
GRANT CONNECT ON DATABASE saas_staging_ci TO saas_b16_person_b;
SQL
admin(){ PGOPTIONS='-c saas.staging_only=true' PGUSER=postgres \
 psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$1"; }
a(){ PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_b14_person \
 PGPASSWORD="$a_pw" psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$1"; }
b(){ PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_b16_person_b \
 PGPASSWORD="$b_pw" psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c "$1"; }
eq(){ [[ "$2" == "$3" ]] || {
 printf 'Backend16 synthetic %s expected=%q actual=%q\n' "$1" "$2" "$3" >&2; fail; }; }
uuid(){ [[ "$1" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]] || fail; }
hash(){ [[ "$1" =~ ^[a-f0-9]{64}$ ]] || fail; }
tenant_a="$(admin "SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_third'")"
tenant_b="$(admin "SELECT tenant_id FROM saas_data.tenants WHERE tenant_key='ci_alpha'")"
uuid "$tenant_a"; uuid "$tenant_b"
[[ "$tenant_a" != "$tenant_b" ]] || fail
fp_a="$(printf 'saas:issuer-subject:v1\0https://ci-b16-idp.invalid\0subject-A' | sha256sum | cut -d' ' -f1)"
fp_b="$(printf 'saas:issuer-subject:v1\0https://ci-b16-idp.invalid\0subject-B' | sha256sum | cut -d' ' -f1)"
fp_rotated="$(printf 'saas:issuer-subject:v1\0https://ci-b16-idp.invalid\0subject-A-re-enrolled' | sha256sum | cut -d' ' -f1)"
hash "$fp_a"; hash "$fp_b"; hash "$fp_rotated"
eq old_grant 3 "$(admin "SELECT access_revision FROM saas_acl.principal_tenants WHERE principal_name='saas_b14_person' AND tenant_id='$tenant_a'")"
eq new_grant 1 "$(admin "SELECT saas_acl.change_principal_access('saas_b16_person_b','$tenant_b',0,'reader','CI B16 grant physical reader B')")"
binding_a="$(admin "SELECT saas_identity.register_subject_binding('saas_b14_person','$tenant_a',3,'$fp_a','CI B16 verified subject A')")"
binding_b="$(admin "SELECT saas_identity.register_subject_binding('saas_b16_person_b','$tenant_b',1,'$fp_b','CI B16 verified subject B')")"
uuid "$binding_a"; uuid "$binding_b"
session_a="$(admin "SELECT saas_identity.issue_principal_session('saas_b14_person','$tenant_a',3,'$binding_a',clock_timestamp()+interval '10 minutes','CI B16 issue validated A session')")"
session_b="$(admin "SELECT saas_identity.issue_principal_session('saas_b16_person_b','$tenant_b',1,'$binding_b',clock_timestamp()+interval '10 minutes','CI B16 issue validated B session')")"
uuid "$session_a"; uuid "$session_b"
query(){ printf "SELECT saas_acl.exact_subject_session_authorized('%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::text)" "$1" "$2" "$3" "$4"; }
eq physical_a saas_b14_person "$(a 'SELECT session_user::text')"
eq physical_b saas_b16_person_b "$(b 'SELECT session_user::text')"
eq authorized_a t "$(a "$(query "$tenant_a" "$session_a" "$binding_a" "$fp_a")")"
eq authorized_b t "$(b "$(query "$tenant_b" "$session_b" "$binding_b" "$fp_b")")"
eq wrong_a_tenant f "$(a "$(query "$tenant_b" "$session_b" "$binding_b" "$fp_b")")"
eq wrong_b_tenant f "$(b "$(query "$tenant_a" "$session_a" "$binding_a" "$fp_a")")"
# Backend16.7: actual Bun.SQL physical per-principal LOGIN/PID read adapter.
# Synthetic secrets are generated in this GitHub-only PG16 process and never logged.
# Run BEFORE the revocation tests below, on exact live synthetic sessions.
SAAS_B16_PHYSICAL_CI=true \
SAAS_B16_CI_A_PASSWORD="$a_pw" \
SAAS_B16_CI_B_PASSWORD="$b_pw" \
SAAS_B16_CI_A_SUBJECT_SHA="$fp_a" \
SAAS_B16_CI_B_SUBJECT_SHA="$fp_b" \
SAAS_B16_CI_A_TENANT="$tenant_a" \
SAAS_B16_CI_B_TENANT="$tenant_b" \
SAAS_B16_CI_A_SESSION="$session_a" \
SAAS_B16_CI_B_SESSION="$session_b" \
SAAS_B16_CI_A_BINDING="$binding_a" \
SAAS_B16_CI_B_BINDING="$binding_b" \
  timeout --signal=TERM --kill-after=3s 110s \
    bun scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts \
  > /tmp/b16-bun-physical-ci.log 2>&1 ||
  { tail -n 24 /tmp/b16-bun-physical-ci.log >&2; fail; }
grep -q 'PASS Backend16.7: real Bun.SQL' /tmp/b16-bun-physical-ci.log || fail
# Rerun the SAME real PG16 two-LOGIN PID, versioned vault, revoke/abort,
# FOR SHARE cancellation, no-retry and quarantine tests on official stable.
# The original Bun 1.3.14 physical run above remains unchanged.
SAAS_B16_PHYSICAL_CI=true \
SAAS_B16_CI_A_PASSWORD="$a_pw" \
SAAS_B16_CI_B_PASSWORD="$b_pw" \
SAAS_B16_CI_A_SUBJECT_SHA="$fp_a" \
SAAS_B16_CI_B_SUBJECT_SHA="$fp_b" \
SAAS_B16_CI_A_TENANT="$tenant_a" \
SAAS_B16_CI_B_TENANT="$tenant_b" \
SAAS_B16_CI_A_SESSION="$session_a" \
SAAS_B16_CI_B_SESSION="$session_b" \
SAAS_B16_CI_A_BINDING="$binding_a" \
SAAS_B16_CI_B_BINDING="$binding_b" \
  timeout --signal=TERM --kill-after=3s 125s \
    "$SAAS_B16_STABLE_144_BIN" scripts/saas-staging/verify-backend16-bun-physical-pid-ci.ts \
  > /tmp/b16-stable144-physical-pid-ci.log 2>&1 ||
  { tail -n 24 /tmp/b16-stable144-physical-pid-ci.log >&2; fail; }
grep -Fxq 'PASS Backend16.9: staging Bun.SQL core real PG16 physical LOGIN, locked exact session, cross-tenant deny, cancel/PID death and no retry' /tmp/b16-stable144-physical-pid-ci.log || fail
grep -Fxq 'PASS Backend16.7: real Bun.SQL two distinct PG16 LOGIN backend PIDs, exact bound read, physical discard, forced cancellation, no credential spoof' /tmp/b16-stable144-physical-pid-ci.log || fail
echo 'B16_STABLE_144_PHYSICAL_VAULT_FOR_SHARE_REVOKE_PID_PASS'

# Independently verified Node24 TLS driver on the SAME disposable SQL0008
# database BEFORE the existing native Bun red security-regression probe.
# Candidate package is temporary CI only; Bun.lock is unchanged.
test "$GITHUB_ACTIONS" = true || fail
test "$SAAS_B16_CI_PG_CONTAINER" != "" || fail
test "$(node -p "process.versions.node.split('.')[0]")" = 24 || fail
SAAS_B16_LOCKED_FULL_CHAIN_CI=true \
SAAS_B16_NODEPG_PHYSICAL_CI=true \
SAAS_B16_BROKER_MTLS_CI=true \
SAAS_B16_CI_A_PASSWORD="$a_pw" \
SAAS_B16_CI_B_PASSWORD="$b_pw" \
SAAS_B16_CI_A_SUBJECT_SHA="$fp_a" \
SAAS_B16_CI_B_SUBJECT_SHA="$fp_b" \
SAAS_B16_CI_A_TENANT="$tenant_a" \
SAAS_B16_CI_B_TENANT="$tenant_b" \
SAAS_B16_CI_A_SESSION="$session_a" \
SAAS_B16_CI_B_SESSION="$session_b" \
SAAS_B16_CI_A_BINDING="$binding_a" \
SAAS_B16_CI_B_BINDING="$binding_b" \
  timeout --signal=TERM --kill-after=3s 360s \
    node scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs \
  > /tmp/b16-nodepg-exact-pg16-ci.log 2>&1 ||
  { tail -n 20 /tmp/b16-nodepg-exact-pg16-ci.log >&2; fail; }
grep -Fx 'B16_LOCKED_FULL_CHAIN_INDEPENDENT_A_PASS' /tmp/b16-nodepg-exact-pg16-ci.log || fail
grep -Fx 'B16_LOCKED_FULL_CHAIN_INDEPENDENT_B_PASS' /tmp/b16-nodepg-exact-pg16-ci.log || fail
grep -Fx 'B16_LOCKED_DUAL_INSTALL_MTLS_VAULT_PG16_EXACT_RLS_PASS' /tmp/b16-nodepg-exact-pg16-ci.log || fail
grep 'PASS Backend16 Node PG real TLS exact SQL0008 two-tenant PG16 RLS' \
 /tmp/b16-nodepg-exact-pg16-ci.log || fail
grep 'PASS Backend16 Node PG synthetic mTLS broker vault PG16 RLS full chain' \
 /tmp/b16-nodepg-exact-pg16-ci.log || fail
grep -q 'B16_NODEPG_MTLS_REVOKED_IN_FLIGHT_PREAUTH_DENY' \
 /tmp/b16-nodepg-exact-pg16-ci.log || fail
# A real authenticated PostgreSQL16 PID must be destroyed when its Node24
# client emits an asynchronous error between SQL statements. Never print
# the raw fixture log; emit only this exact proof marker after checking it.
grep -Fxq 'B16_NODEPG_ASYNC_SOCKET_ERROR_QUARANTINE_PID_DEATH_PASS' \
 /tmp/b16-nodepg-exact-pg16-ci.log || fail
echo 'PASS Backend16 Node PG async socket error quarantine physical PID death'
# Node24 loopback mTLS broker with a real OFFICIAL stable Bun HTTPS client.
# Original independent dual-install Node pg and canary acceptance are kept.
timeout --signal=TERM --kill-after=3s 95s \
  node --experimental-strip-types scripts/saas-staging/verify-backend16-official-stable-144-mtls-ci.ts \
  > /tmp/b16-stable144-mtls-ci.log 2>&1 ||
  { tail -n 20 /tmp/b16-stable144-mtls-ci.log >&2; fail; }
grep -Fxq 'B16_MTLS_BROKER_CI_BUN_CLIENT_PASS' /tmp/b16-stable144-mtls-ci.log || fail
grep -Fxq 'PASS Backend16.15 actual mutual TLS immutable-version reader' /tmp/b16-stable144-mtls-ci.log || fail
for marker in B16_MTLS_BROKER_CI_WRONG_SERVER_SAN_DENY B16_MTLS_BROKER_CI_WILDCARD_SERVER_SAN_DENY; do
  grep -Fxq "$marker" /tmp/b16-stable144-mtls-ci.log || fail
done
echo 'B16_STABLE_144_MTLS_BROKER_VERSIONED_VAULT_PASS'



# Newly isolated native verify-full Bun.SQL acceptance, using the exact
# GitHub Actions PostgreSQL service container only (never permanent SQL0008).
SAAS_B16_PHYSICAL_CI=true \
SAAS_B16_PHYSICAL_TLS_CI=true \
SAAS_B16_CI_A_PASSWORD="$a_pw" \
SAAS_B16_CI_B_PASSWORD="$b_pw" \
SAAS_B16_CI_A_SUBJECT_SHA="$fp_a" \
SAAS_B16_CI_B_SUBJECT_SHA="$fp_b" \
SAAS_B16_CI_A_TENANT="$tenant_a" \
SAAS_B16_CI_B_TENANT="$tenant_b" \
SAAS_B16_CI_A_SESSION="$session_a" \
SAAS_B16_CI_B_SESSION="$session_b" \
SAAS_B16_CI_A_BINDING="$binding_a" \
SAAS_B16_CI_B_BINDING="$binding_b" \
  timeout --signal=TERM --kill-after=3s 95s \
    "${SAAS_B16_NATIVE_BUN_BIN:?pinned native SQL TLS runtime required}" scripts/saas-staging/verify-backend16-native-pg-tls-ci.ts \
  > /tmp/b16-native-pg-tls-ci.log 2>&1 ||
  { tail -n 22 /tmp/b16-native-pg-tls-ci.log >&2; fail; }
for marker in \
 B16_NATIVE_SQL_TLS_REAL_PID_VERIFIED \
 B16_NATIVE_SQL_TLS_TWO_TENANT_RLS_PASS \
 B16_NATIVE_SQL_TLS_ALWAYS_DENY_CALLBACK_ENFORCED \
 B16_NATIVE_SQL_TLS_WRONG_ROOT_DENIED \
 B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_DENIED; do
 grep -Fx "$marker" /tmp/b16-native-pg-tls-ci.log || fail
done
grep -Fx 'PASS Backend16 native Bun.SQL TLS to real disposable PG16' \
 /tmp/b16-native-pg-tls-ci.log || fail
# Original canary physical wrong-root/wildcard/always-deny test has passed.
# Return disposable PG16 to its initial ssl=off state ONLY for the second
# independent complete stable runtime physical TLS probe.
PGOPTIONS='-c saas.staging_only=true' PGUSER=postgres \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
    -c "ALTER SYSTEM SET ssl='off'" > /tmp/b16-stable144-reset-ssl.log 2>&1 || fail
PGOPTIONS='-c saas.staging_only=true' PGUSER=postgres \
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
    -c "SELECT pg_reload_conf()" >> /tmp/b16-stable144-reset-ssl.log 2>&1 || fail
sleep 1
[[ "$(PGOPTIONS='-c saas.staging_only=true' PGUSER=postgres \
  psql -XAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c 'SHOW ssl')" == off ]] || fail
# Byte-for-byte SAME full native TLS+two-tenant vault/RLS/PID/wildcard test,
# differing only in official stable revision and CI-only stable hard stop.
SAAS_B16_PHYSICAL_CI=true \
SAAS_B16_CI_A_PASSWORD="$a_pw" \
SAAS_B16_CI_B_PASSWORD="$b_pw" \
SAAS_B16_CI_A_SUBJECT_SHA="$fp_a" \
SAAS_B16_CI_B_SUBJECT_SHA="$fp_b" \
SAAS_B16_CI_A_TENANT="$tenant_a" \
SAAS_B16_CI_B_TENANT="$tenant_b" \
SAAS_B16_CI_A_SESSION="$session_a" \
SAAS_B16_CI_B_SESSION="$session_b" \
SAAS_B16_CI_A_BINDING="$binding_a" \
SAAS_B16_CI_B_BINDING="$binding_b" \
SAAS_B16_PHYSICAL_TLS_CI=true \
  timeout --signal=TERM --kill-after=3s 125s \
    "$SAAS_B16_STABLE_144_BIN" scripts/saas-staging/verify-backend16-official-stable-144-physical-pg16-ci.ts \
  > /tmp/b16-stable144-physical-tls-ci.log 2>&1 ||
  { tail -n 22 /tmp/b16-stable144-physical-tls-ci.log >&2; fail; }
for marker in \
  B16_NATIVE_SQL_TLS_REAL_PID_VERIFIED \
  B16_NATIVE_SQL_TLS_TWO_TENANT_RLS_PASS \
  B16_NATIVE_SQL_TLS_ALWAYS_DENY_CALLBACK_ENFORCED \
  B16_NATIVE_SQL_TLS_WRONG_ROOT_DENIED \
  B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_DENIED; do
  grep -Fxq "$marker" /tmp/b16-stable144-physical-tls-ci.log || fail
done
grep -Fxq 'PASS Backend16 native Bun.SQL TLS to real disposable PG16' \
  /tmp/b16-stable144-physical-tls-ci.log || fail
echo 'B16_STABLE_144_TLS_TWO_TENANT_VAULT_RLS_PID_NEGATIVES_PASS'
echo 'B16_STABLE_144_FULL_DISPOSABLE_PG16_CANDIDATE_PASS_NOT_RELEASE_APPROVAL'
echo 'NO RELEASE AUTHORIZATION'

eq wrong_session f "$(a "$(query "$tenant_a" "$session_b" "$binding_a" "$fp_a")")"
eq wrong_binding f "$(a "$(query "$tenant_a" "$session_a" "$binding_b" "$fp_a")")"
eq wrong_digest f "$(a "$(query "$tenant_a" "$session_a" "$binding_a" "$fp_b")")"
eq missing_gate f "$(a "SET saas.staging_only=false; $(query "$tenant_a" "$session_a" "$binding_a" "$fp_a")")"
eq fake_set_role f "$(b "SET ROLE saas_runtime_reader; $(query "$tenant_a" "$session_a" "$binding_a" "$fp_a")")"
for bad_sql in \
 'SELECT * FROM saas_identity.principal_sessions' \
 'SELECT * FROM saas_identity.subject_bindings' \
 "SELECT saas_identity.revoke_subject_binding('$binding_a',1,'CI forged revoke from runtime')" \
 "INSERT INTO saas_data.tenants(tenant_key,display_name) VALUES ('ci_b16_bad','Denied')"; do
 if a "$bad_sql" > /tmp/b16-abuse-denied.log 2>&1; then fail; fi
done
# An authenticated physical A backend holds all SQL0008 FOR SHARE locks.
PGOPTIONS='-c saas.staging_only=true' PGUSER=saas_b14_person PGPASSWORD="$a_pw" \
 psql -XqAt -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -v tenant="$tenant_a" -v sess="$session_a" -v binding="$binding_a" \
 -v fp="$fp_a" > /tmp/b16-held.log 2>&1 <<'SQL' &
BEGIN ISOLATION LEVEL READ COMMITTED;
SELECT pg_backend_pid()::int;
SELECT saas_acl.exact_subject_session_authorized(
  :'tenant'::uuid, :'sess'::uuid, :'binding'::uuid, :'fp'::text);
\echo B16_EXACT_LOCK_HELD
SELECT pg_sleep(4);
COMMIT;
SQL
reader_pid=$!
held=0
for i in $(seq 1 80); do
 if grep -q B16_EXACT_LOCK_HELD /tmp/b16-held.log; then held=1; break; fi
 sleep 0.1
done
[[ "$held" == 1 ]] || { wait "$reader_pid" || true; fail; }
physical_a="$(grep -E '^[0-9]+$' /tmp/b16-held.log | head -n 1)"
physical_b="$(b 'SELECT pg_backend_pid()::int')"
[[ "$physical_a" =~ ^[0-9]+$ && "$physical_b" =~ ^[0-9]+$ &&
   "$physical_a" != "$physical_b" ]] || { wait "$reader_pid" || true; fail; }
eq live_backend 1 "$(admin "SELECT count(*) FROM pg_stat_activity WHERE pid=$physical_a AND usename='saas_b14_person'")"
eq second_login_concurrent t "$(b "$(query "$tenant_b" "$session_b" "$binding_b" "$fp_b")")"
if PGOPTIONS='-c saas.staging_only=true -c lock_timeout=150ms' PGUSER=postgres \
 psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci \
 -c "SELECT saas_identity.revoke_subject_binding('$binding_a',1,'CI B16 revoke blocks behind active read')" \
 > /tmp/b16-revoke-blocked.log 2>&1; then wait "$reader_pid" || true; fail; fi
eq no_early_revoke 1 "$(admin "SELECT binding_revision FROM saas_identity.subject_bindings WHERE binding_id='$binding_a'")"
wait "$reader_pid" || fail
eq revoke_after_reader 2 "$(admin "SELECT saas_identity.revoke_subject_binding('$binding_a',1,'CI B16 revoke after read COMMIT')")"
eq revoked_denied f "$(a "$(query "$tenant_a" "$session_a" "$binding_a" "$fp_a")")"
eq other_login_still_valid t "$(b "$(query "$tenant_b" "$session_b" "$binding_b" "$fp_b")")"
# Re-enrollment of SAME physical LOGIN does not authorize an OLD JWT session.
eq revoke_old_session 2 "$(admin "SELECT saas_identity.revoke_principal_session('$session_a',1,'CI B16 retire old bearer session')")"
binding_a2="$(admin "SELECT saas_identity.register_subject_binding('saas_b14_person','$tenant_a',3,'$fp_rotated','CI B16 enroll rotated subject A')")"
uuid "$binding_a2"
session_a2="$(admin "SELECT saas_identity.issue_principal_session('saas_b14_person','$tenant_a',3,'$binding_a2',clock_timestamp()+interval '8 minutes','CI B16 issue replacement session')")"
uuid "$session_a2"
eq old_pair_denied f "$(a "$(query "$tenant_a" "$session_a" "$binding_a" "$fp_a")")"
eq wrong_rotated_digest f "$(a "$(query "$tenant_a" "$session_a2" "$binding_a2" "$fp_a")")"
eq reissued_valid t "$(a "$(query "$tenant_a" "$session_a2" "$binding_a2" "$fp_rotated")")"
eq b_grant_revoked 2 "$(admin "SELECT saas_acl.change_principal_access('saas_b16_person_b','$tenant_b',1,'revoked','CI B16 revoke principal B')")"
eq b_revoked f "$(b "$(query "$tenant_b" "$session_b" "$binding_b" "$fp_b")")"
eq b_regrant 3 "$(admin "SELECT saas_acl.change_principal_access('saas_b16_person_b','$tenant_b',2,'reader','CI B16 regrant principal B')")"
eq old_session_stale f "$(b "$(query "$tenant_b" "$session_b" "$binding_b" "$fp_b")")"
eq eight_receipts 8 "$(admin 'SELECT count(*) FROM saas_bootstrap.schema_migrations')"
unset a_pw b_pw migrator_pw
echo 'PASS Backend16.4: real PG16 two LOGIN exact session/binding digest, FOR SHARE revoke fence, no ABA, 8 receipts'

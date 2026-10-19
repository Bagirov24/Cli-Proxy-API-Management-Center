#!/usr/bin/env bash
# Disposable GitHub PostgreSQL16 only. No SQL0008 installer is replayed.
set -euo pipefail
fail(){ echo 'Backend16 catalog drift regression STOP' >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == true && "${SAAS_B16_EPHEMERAL_CI:-}" == true ]] || fail
[[ "${PGHOST:-}" == 127.0.0.1 && "${PGPORT:-}" == 5432 &&
   "${PGUSER:-}" == postgres && "${PGDATABASE:-}" == saas_ephemeral_test ]] || fail
[[ -z "${RAILWAY_PROJECT_ID:-}" && -z "${RAILWAY_SERVICE_ID:-}" &&
   -z "${RAILWAY_ENVIRONMENT_ID:-}" && -z "${RAILWAY_ENVIRONMENT:-}" &&
   "${NODE_ENV:-}" != production ]] || fail
original="$(mktemp /tmp/b16-function-original.XXXXXX.sql)"
psql -XAt -v ON_ERROR_STOP=1 -d saas_staging_ci -c \
  "SELECT pg_catalog.pg_get_functiondef('saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)'::regprocedure)" \
  > "$original"
restore(){
  psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci -f "$original" \
    > /tmp/b16-function-restored.log 2>&1
  rm -f -- "$original"
}
trap restore EXIT
# Preserve all four legacy substrings in comments while changing behavior.
# The strict read-only postflight must reject this counterfeit installed body.
psql -X -v ON_ERROR_STOP=1 -d saas_staging_ci > /tmp/b16-function-counterfeit.log <<'SQL'
CREATE OR REPLACE FUNCTION saas_acl.exact_subject_session_authorized(
  p_tenant uuid, p_session uuid, p_binding uuid, p_subject_sha256 text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $spoof$
BEGIN
  -- s.session_id=p_session s.identity_binding_id=p_binding
  -- b.subject_fingerprint=p_subject_sha256 FOR SHARE
  RETURN true;
END
$spoof$;
SQL
if PGOPTIONS='-c saas.staging_only=true' psql -X -v ON_ERROR_STOP=1 \
  -d saas_staging_ci -v b16_expected_state=installed \
  -f scripts/saas-staging/backend16-0008-readonly-reconcile.sql \
  > /tmp/b16-counterfeit-readonly-denied.log 2>&1; then fail; fi
grep -q 'B16_READONLY_STOP_SQL0008_FUNCTION_DRIFT' /tmp/b16-counterfeit-readonly-denied.log || fail
if grep -q 'PASS_BACKEND16' /tmp/b16-counterfeit-readonly-denied.log; then fail; fi
restore
trap - EXIT
echo 'PASS_BACKEND16_COUNTERFEIT_INSTALLED_FUNCTION_DENIED'

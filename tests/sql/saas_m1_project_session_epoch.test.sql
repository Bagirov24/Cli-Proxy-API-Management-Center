\set ON_ERROR_STOP on
-- M1k independent privileged PostgreSQL16 acceptance of REAL HTTP ->
-- signed server session UUID/revision barrier and concurrent revoke order.
DO $guard$
BEGIN
  IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
     OR to_regprocedure('saas_m1_api.lock_project_session_epoch(uuid,bigint,text,text)') IS NULL
     OR to_regclass('saas_m1_private.project_session_proofs') IS NULL
     OR to_regclass('saas_m1_private.project_session_epochs') IS NULL
  THEN RAISE EXCEPTION 'M1k acceptance restricted to ephemeral PG16'; END IF;
END
$guard$;

-- PostgreSQL16 SELECT FOR SHARE is subject to UPDATE *USING* RLS as
-- well as SELECT RLS. The NOLOGIN session owner must be able to lock all
-- four private session records without gaining the ability to mutate them.
BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL ROLE saas_m1_session_owner;
SELECT COUNT(*)::TEXT AS m1k_visible_locked_sessions
FROM (
  SELECT session_id FROM saas_m1_private.project_session_epochs
  WHERE actor_id='actor-north' AND tenant_id='demo-north'
  FOR SHARE
) AS locked_sessions \gset
DO $owner_write_deny$
DECLARE blocked BOOLEAN:=FALSE;
BEGIN
  BEGIN
    UPDATE saas_m1_private.project_session_epochs
    SET revision=revision+1
    WHERE actor_id='actor-north' AND tenant_id='demo-north'
      AND status='active';
  EXCEPTION WHEN insufficient_privilege THEN
    blocked:=TRUE;
  END;
  IF NOT blocked THEN
    RAISE EXCEPTION 'M1k NOLOGIN lock owner can modify session epochs';
  END IF;
END
$owner_write_deny$;
RESET ROLE;
ROLLBACK;
SELECT saas_rls_test.assert_true(
  :'m1k_visible_locked_sessions'='4',
  'M1k FORCE RLS allows session FOR SHARE under lock-only policy'
);

SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=4 FROM saas_m1_private.project_session_epochs
       WHERE actor_id='actor-north' AND tenant_id='demo-north')
  AND (SELECT COUNT(*)=3 FROM saas_m1_private.project_session_epochs
       WHERE actor_id='actor-north' AND tenant_id='demo-north'
         AND status='revoked' AND revision=2)
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_session_epochs
       WHERE actor_id='actor-north' AND tenant_id='demo-north'
         AND status='active' AND revision=2)
  AND (SELECT COUNT(*)=5 FROM saas_m1_private.projects
       WHERE tenant_id='demo-north' AND project_id IN
         ('m1k-a-first','m1k-b-first','m1k-b-after-a-revoke',
          'm1k-b-fresh-epoch','m1k-write-first'))
  AND (SELECT COUNT(*)=5 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id LIKE 'm1k-%')
  AND (SELECT COUNT(*)=5 FROM saas_m1_private.project_attempt_bindings b
       JOIN saas_m1_private.project_write_audit_outbox a
         ON a.event_id=b.event_id
       WHERE a.tenant_id='demo-north' AND a.project_id LIKE 'm1k-%'),
  'M1k 4 distinct sessions, 3 revoked, B active rotated; 5 real HTTP signed COMMITs'
);

SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=5 FROM saas_m1_private.project_session_proofs p
       JOIN saas_m1_private.project_write_audit_outbox a
         ON a.pg_txid=p.pg_txid
       JOIN saas_m1_private.project_session_epochs s
         ON s.session_id=p.session_id
       WHERE a.tenant_id='demo-north' AND a.project_id LIKE 'm1k-%'
         AND a.actor_id='actor-north'
         AND p.actor_id=a.actor_id AND p.tenant_id=a.tenant_id
         AND s.actor_id=p.actor_id AND s.tenant_id=p.tenant_id
         AND p.session_revision BETWEEN 1 AND s.revision)
  AND (SELECT COUNT(*)=4 FROM saas_m1_private.project_session_proofs
       WHERE session_revision=1 AND actor_id='actor-north')
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_session_proofs
       WHERE session_revision=2 AND actor_id='actor-north')
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_session_proofs p
       JOIN saas_m1_private.project_write_audit_outbox a
         ON a.pg_txid=p.pg_txid
       JOIN saas_m1_private.project_session_epochs s
         ON s.session_id=p.session_id
       WHERE a.project_id='m1k-write-first' AND s.status='revoked'
         AND s.revision=p.session_revision+1)
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_session_proofs p
       JOIN saas_m1_private.project_write_audit_outbox a
         ON a.pg_txid=p.pg_txid
       JOIN saas_m1_private.project_session_epochs s
         ON s.session_id=p.session_id
       WHERE a.project_id='m1k-b-fresh-epoch'
         AND s.status='active' AND p.session_revision=2),
  'M1k 1:1 same-transaction session proof + mandatory signed audit, COMMIT before revoke'
);

SELECT saas_rls_test.assert_true(
  NOT EXISTS(SELECT 1 FROM saas_m1_private.projects
    WHERE tenant_id='demo-north' AND project_id IN
      ('m1k-unregistered','m1k-a-revoked','m1k-b-stale-epoch',
       'm1k-legacy-bypass','m1k-c-after-revoke','m1k-revoke-first',
       'm1k-signer-dead'))
  AND NOT EXISTS(SELECT 1 FROM saas_m1_private.project_write_audit_outbox
    WHERE tenant_id='demo-north' AND project_id IN
      ('m1k-unregistered','m1k-a-revoked','m1k-b-stale-epoch',
       'm1k-legacy-bypass','m1k-c-after-revoke','m1k-revoke-first',
       'm1k-signer-dead'))
  AND NOT EXISTS(
    SELECT 1 FROM saas_m1_private.project_attempt_bindings b
    JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
    WHERE a.tenant_id='demo-north' AND a.project_id LIKE 'm1k-%'
      AND a.project_id NOT IN ('m1k-a-first','m1k-b-first',
        'm1k-b-after-a-revoke','m1k-b-fresh-epoch','m1k-write-first'))
  AND (SELECT COUNT(*)=1 FROM saas_rls.memberships
       WHERE actor_id='actor-north' AND tenant_id='demo-north'
         AND status='active'),
  'Revoked, stale, unauthorized and unguarded writes leave no ghost project/audit'
);

SELECT saas_rls_test.assert_true(
  NOT has_table_privilege('saas_ci_runner',
    'saas_m1_private.project_session_epochs','SELECT')
  AND NOT has_table_privilege('saas_m1_project_executor',
    'saas_m1_private.project_session_epochs','SELECT')
  AND NOT has_table_privilege('saas_m1_project_executor',
    'saas_m1_private.project_session_proofs','INSERT')
  AND NOT has_table_privilege('saas_m1_review_operator',
    'saas_m1_private.project_session_proofs','SELECT')
  AND NOT has_table_privilege('saas_m1_session_owner',
    'saas_rls_private.scope_signers','SELECT')
  AND NOT has_function_privilege('saas_ci_runner',
    'saas_m1_api.lock_project_session_epoch(uuid,bigint,text,text)','EXECUTE')
  AND has_function_privilege('saas_m1_project_executor',
    'saas_m1_api.lock_project_session_epoch(uuid,bigint,text,text)','EXECUTE')
  AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
       WHERE oid='saas_m1_private.project_session_epochs'::regclass)
  AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
       WHERE oid='saas_m1_private.project_session_proofs'::regclass)
  AND EXISTS (SELECT 1 FROM pg_trigger
       WHERE tgname='m1_project_atomic_audit'
         AND tgrelid='saas_m1_private.projects'::regclass
         AND tgfoid='saas_m1_private.append_project_write_audit_fenced()'::regprocedure)
  AND EXISTS (SELECT 1 FROM pg_trigger
       WHERE tgname='m1_project_session_epoch_gate'
         AND tgrelid='saas_m1_private.projects'::regclass
         AND tgfoid='saas_m1_private.require_project_session_proof()'::regprocedure),
  'M1k FORCE RLS, least privilege, signed M1d and mandatory session proof remain'
);

DO $immutability$
DECLARE bad_update BOOLEAN:=FALSE;
DECLARE bad_delete BOOLEAN:=FALSE;
BEGIN
  BEGIN
    UPDATE saas_m1_private.project_session_epochs
    SET status='active', revision=revision+1
    WHERE session_id=(
      SELECT session_id FROM saas_m1_private.project_session_epochs
      WHERE actor_id='actor-north' AND status='revoked'
      ORDER BY session_id LIMIT 1);
  EXCEPTION WHEN raise_exception THEN bad_update:=TRUE;
  END;
  BEGIN
    DELETE FROM saas_m1_private.project_session_epochs
    WHERE session_id=(
      SELECT session_id FROM saas_m1_private.project_session_epochs
      WHERE actor_id='actor-north' AND status='revoked'
      ORDER BY session_id LIMIT 1);
  EXCEPTION WHEN raise_exception THEN bad_delete:=TRUE;
  END;
  IF NOT bad_update OR NOT bad_delete THEN
    RAISE EXCEPTION 'M1k accepted forbidden session resurrection or DELETE';
  END IF;
END
$immutability$;

-- SQL025 replay must never erase session revocations, reset epochs,
-- replace the existing M1d signed audit or the M1g UUID binding.
SET saas.staging_only='true';
\ir ../../staging/saas-rls/025_m1_project_session_epoch_gate_pilot.sql
SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=4 FROM saas_m1_private.project_session_epochs
       WHERE actor_id='actor-north' AND tenant_id='demo-north')
  AND (SELECT COUNT(*)=3 FROM saas_m1_private.project_session_epochs
       WHERE status='revoked' AND revision=2 AND actor_id='actor-north')
  AND (SELECT COUNT(*)=5 FROM saas_m1_private.project_session_proofs)
  AND (SELECT COUNT(*)=5 FROM saas_m1_private.project_write_audit_outbox
       WHERE tenant_id='demo-north' AND project_id LIKE 'm1k-%')
  AND EXISTS(SELECT 1 FROM pg_trigger
      WHERE tgrelid='saas_m1_private.projects'::regclass
        AND tgname='m1_project_atomic_audit'
        AND tgfoid='saas_m1_private.append_project_write_audit_fenced()'::regprocedure)
  AND EXISTS(SELECT 1 FROM pg_trigger
      WHERE tgrelid='saas_m1_private.projects'::regclass
        AND tgname='m1_project_attempt_binding'
        AND tgfoid='saas_m1_private.bind_project_attempt_to_audit()'::regprocedure)
  AND EXISTS(SELECT 1 FROM pg_trigger
      WHERE tgrelid='saas_m1_private.projects'::regclass
        AND tgname='m1_project_session_epoch_gate'
        AND tgfoid='saas_m1_private.require_project_session_proof()'::regprocedure),
  'M1k SQL025 replay preserves private revoked sessions/epochs and all 5 commits'
);
\echo 'PASS M1k: signed PG16 per-session epoch FOR SHARE, write-first/revoke-first serializes; stale/legacy deny, no audit ghost, no OIDC/production/retry'
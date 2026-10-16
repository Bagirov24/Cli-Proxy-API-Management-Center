\set ON_ERROR_STOP on
-- M1l: actual disposable loopback synthetic OIDC/JWKS A->A+B->B
-- -> signed PG16 session epoch, mandatory audit and attempt UUID.
-- Only CI superuser reads these private tables; NOT production IAM.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
    OR to_regprocedure('saas_m1_api.lock_project_session_epoch(uuid,bigint,text,text)') IS NULL
    OR to_regclass('saas_m1_private.project_session_proofs') IS NULL
    OR to_regclass('saas_m1_private.project_attempt_bindings') IS NULL
 THEN
   RAISE EXCEPTION 'M1l acceptance forbidden outside disposable PG16';
 END IF;
END
$guard$;

SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=5 FROM saas_m1_private.projects
   WHERE tenant_id='demo-north' AND project_id IN
     ('m1l-a-first','m1l-b-after-rotation','m1l-a-overlap',
      'm1l-b-live','m1l-b-recovered') AND status='active' AND version=1)
  AND (SELECT COUNT(*)=5 FROM saas_m1_private.project_write_audit_outbox
   WHERE tenant_id='demo-north' AND project_id LIKE 'm1l-%'
     AND actor_id='actor-north' AND operation='create' AND project_version=1)
  AND (SELECT COUNT(*)=5
   FROM saas_m1_private.project_attempt_bindings b
   JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
   WHERE a.tenant_id='demo-north' AND a.project_id LIKE 'm1l-%')
  AND (SELECT COUNT(*)=5
   FROM saas_m1_private.project_session_proofs p
   JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
   WHERE a.tenant_id='demo-north' AND a.project_id LIKE 'm1l-%'
     AND p.actor_id=a.actor_id AND p.tenant_id=a.tenant_id
     AND p.session_revision=1),
  'M1l 5 real HTTP→synthetic JWKS→signed PG16 writes have 5 audit, UUID, session proofs'
);

SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=2 FROM saas_m1_private.project_session_epochs s
   WHERE s.actor_id='actor-north' AND s.tenant_id='demo-north'
     AND EXISTS (
       SELECT 1 FROM saas_m1_private.project_session_proofs p
       JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
       WHERE a.project_id LIKE 'm1l-%' AND p.session_id=s.session_id))
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_session_epochs s
   WHERE s.actor_id='actor-north' AND s.tenant_id='demo-north'
     AND s.status='revoked' AND s.revision=2 AND EXISTS (
       SELECT 1 FROM saas_m1_private.project_session_proofs p
       JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
       WHERE a.project_id='m1l-a-first' AND p.session_id=s.session_id))
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_session_epochs s
   WHERE s.actor_id='actor-north' AND s.tenant_id='demo-north'
     AND s.status='active' AND s.revision=1 AND EXISTS (
       SELECT 1 FROM saas_m1_private.project_session_proofs p
       JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
       WHERE a.project_id='m1l-b-after-rotation' AND p.session_id=s.session_id)),
  'M1l retired JWT issuer key maps only to revoked A session while B stays active'
);

SELECT saas_rls_test.assert_true(
 NOT EXISTS(SELECT 1 FROM saas_m1_private.projects
 WHERE project_id IN
   ('m1l-b-before-rotation','m1l-unknown-session','m1l-race-a',
    'm1l-retired-a','m1l-b-discovery-down','m1l-b-rollback-denied',
    'm1l-a-rollback-denied','m1l-signer-dead'))
 AND NOT EXISTS(SELECT 1 FROM saas_m1_private.project_write_audit_outbox
 WHERE project_id IN
   ('m1l-b-before-rotation','m1l-unknown-session','m1l-race-a',
    'm1l-retired-a','m1l-b-discovery-down','m1l-b-rollback-denied',
    'm1l-a-rollback-denied','m1l-signer-dead'))
 AND NOT EXISTS(
   SELECT 1 FROM saas_m1_private.project_attempt_bindings b
   JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
   WHERE a.project_id IN
    ('m1l-b-before-rotation','m1l-unknown-session','m1l-race-a',
     'm1l-retired-a','m1l-b-discovery-down','m1l-b-rollback-denied',
     'm1l-a-rollback-denied','m1l-signer-dead'))
 AND (SELECT COUNT(*)=0 FROM saas_m1_private.project_session_proofs p
   LEFT JOIN saas_m1_private.project_write_audit_outbox a
     ON a.pg_txid=p.pg_txid
   WHERE a.project_id='m1l-race-a'),
 'M1l expired issuer key, unregistered token, rotated-key race and dead witness fail closed with no ghost audit'
);

SELECT saas_rls_test.assert_true(
  NOT has_table_privilege('saas_ci_runner',
    'saas_m1_private.project_session_epochs','SELECT')
  AND NOT has_table_privilege('saas_ci_runner',
    'saas_m1_private.project_session_proofs','SELECT')
  AND NOT has_table_privilege('saas_m1_project_executor',
    'saas_m1_private.project_session_epochs','UPDATE')
  AND NOT has_table_privilege('saas_m1_session_owner',
    'saas_rls_private.scope_signers','SELECT')
  AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
    WHERE oid='saas_m1_private.project_session_epochs'::regclass)
  AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
    WHERE oid='saas_m1_private.project_session_proofs'::regclass)
  AND EXISTS(SELECT 1 FROM pg_trigger
    WHERE tgrelid='saas_m1_private.projects'::regclass
      AND tgname='m1_project_atomic_audit'
      AND tgfoid='saas_m1_private.append_project_write_audit_fenced()'::regprocedure)
  AND EXISTS(SELECT 1 FROM pg_trigger
    WHERE tgrelid='saas_m1_private.projects'::regclass
      AND tgname='m1_project_session_epoch_gate'
      AND tgfoid='saas_m1_private.require_project_session_proof()'::regprocedure),
 'M1l no leaked PG key/session grants, M1d signed audit and M1k session trigger retained'
);

-- Reinstall exactly the existing CI-only SQL025 after new OIDC fixture
-- results. Reinstall may not reset private epochs or resurrect key A session.
SET saas.staging_only='true';
\ir ../../staging/saas-rls/025_m1_project_session_epoch_gate_pilot.sql
SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=5 FROM saas_m1_private.project_write_audit_outbox
    WHERE tenant_id='demo-north' AND project_id LIKE 'm1l-%')
  AND (SELECT COUNT(*)=5 FROM saas_m1_private.project_session_proofs p
    JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
    WHERE a.project_id LIKE 'm1l-%')
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_session_epochs s
    WHERE s.status='revoked' AND s.revision=2 AND EXISTS(
      SELECT 1 FROM saas_m1_private.project_session_proofs p
      JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
      WHERE a.project_id='m1l-a-first' AND p.session_id=s.session_id)),
 'M1l SQL025 replay leaves signed issuer-derived PG receipts and session revocation intact'
);
\echo 'PASS M1l: synthetic OIDC A->A+B->B rotates safely; trusted session A revoked between HTTP and PG COMMIT, 5 atomic audit proofs, no ghost writes or production'

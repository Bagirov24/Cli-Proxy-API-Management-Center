\set ON_ERROR_STOP on
-- M1q: independent privileged PG16 observation (nonce checked by JavaScript before PG16 session) AFTER actual opaque-bound HTTPS mock OAuth
-- authorization-code + PKCE S256 -> pinned JWKS -> trusted session UUID ->
-- M1h precommit signer -> signed M1k/M1d/M1c/M1g atomic COMMIT.
-- NO production OIDC/SQL019, no retry/refresh/reissue.
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test' OR current_user <> 'postgres'
     OR to_regclass('saas_m1_private.projects') IS NULL
     OR to_regclass('saas_m1_private.project_session_epochs') IS NULL
     OR to_regclass('saas_m1_private.project_session_proofs') IS NULL
     OR to_regclass('saas_m1_private.project_attempt_bindings') IS NULL
  THEN
    RAISE EXCEPTION 'M1q OAuth+PG acceptance denied outside disposable PG16';
  END IF;
END
$guard$;

SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=3 FROM saas_m1_private.projects
   WHERE tenant_id='demo-north' AND project_id IN
     ('m1q-a-first','m1q-b-first','m1q-b-after-revoke')
     AND status='active' AND version=1)
  AND (SELECT COUNT(*)=3 FROM saas_m1_private.project_write_audit_outbox
   WHERE tenant_id='demo-north' AND project_id LIKE 'm1q-%'
     AND actor_id='actor-north' AND operation='create' AND project_version=1)
  AND (SELECT COUNT(*)=3 FROM saas_m1_private.project_attempt_bindings b
   JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
   WHERE a.tenant_id='demo-north' AND a.project_id LIKE 'm1q-%')
  AND (SELECT COUNT(DISTINCT b.attempt_id)=3
   FROM saas_m1_private.project_attempt_bindings b
   JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
   WHERE a.tenant_id='demo-north' AND a.project_id LIKE 'm1q-%')
  AND (SELECT COUNT(*)=3 AND COUNT(DISTINCT p.session_id)=2
   FROM saas_m1_private.project_session_proofs p
   JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
   WHERE a.tenant_id='demo-north' AND a.project_id LIKE 'm1q-%'
     AND p.actor_id=a.actor_id AND p.tenant_id=a.tenant_id
     AND p.session_revision=1),
  'M1q three real PKCE-provisioned HTTP signed PG writes have 3 project/audit/UUID/session proofs'
);

SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=1 FROM saas_m1_private.project_session_epochs s
   JOIN saas_m1_private.project_session_proofs p ON p.session_id=s.session_id
   JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
   WHERE a.project_id='m1q-a-first' AND s.status='revoked'
     AND s.revision=2 AND s.actor_id='actor-north')
  AND (SELECT COUNT(*)=2 FROM saas_m1_private.project_session_proofs p
   JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
   JOIN saas_m1_private.project_session_epochs s ON s.session_id=p.session_id
   WHERE a.project_id IN ('m1q-b-first','m1q-b-after-revoke')
     AND s.status='active' AND s.revision=1)
  AND NOT EXISTS(SELECT 1 FROM saas_m1_private.projects
   WHERE project_id IN ('m1q-race-revoked','m1q-a-revoked',
     'm1q-signer-dead'))
  AND NOT EXISTS(SELECT 1 FROM saas_m1_private.project_write_audit_outbox
   WHERE project_id IN ('m1q-race-revoked','m1q-a-revoked',
     'm1q-signer-dead'))
  AND NOT EXISTS(SELECT 1 FROM saas_m1_private.project_attempt_bindings b
   JOIN saas_m1_private.project_write_audit_outbox a ON a.event_id=b.event_id
   WHERE a.project_id IN ('m1q-race-revoked','m1q-a-revoked',
     'm1q-signer-dead')),
  'M1q revoked one-time OAuth sessions cannot create ghost writes/audits, B stays active'
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
  'M1q synthetic code exchange does not grant public issuer or PG session privileges'
);

-- CI-only migration replay cannot reset three committed project proofs or
-- resurrect a revoked PKCE-provisioned session from a prior COMMIT.
SET saas.staging_only='true';
\ir ../../staging/saas-rls/025_m1_project_session_epoch_gate_pilot.sql
SELECT saas_rls_test.assert_true(
  (SELECT COUNT(*)=3 FROM saas_m1_private.project_write_audit_outbox
   WHERE tenant_id='demo-north' AND project_id LIKE 'm1q-%')
  AND (SELECT COUNT(*)=3 FROM saas_m1_private.project_session_proofs p
   JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
   WHERE a.tenant_id='demo-north' AND a.project_id LIKE 'm1q-%')
  AND (SELECT COUNT(*)=1 FROM saas_m1_private.project_session_epochs s
   JOIN saas_m1_private.project_session_proofs p ON p.session_id=s.session_id
   JOIN saas_m1_private.project_write_audit_outbox a ON a.pg_txid=p.pg_txid
   WHERE a.project_id='m1q-a-first' AND s.status='revoked' AND s.revision=2),
  'M1q SQL025 replay retains signed PKCE-provisioned proof and revoked session'
);
\echo 'PASS M1q: nonce-bound RS256 ID-token PKCE and context cancel, explicit rev-2 CA/SPKI HTTPS sessions, real signed PG16 3/3/3 audit/proof, revoked A/C no ghost, B active, SQL025 replay, no retry/production'

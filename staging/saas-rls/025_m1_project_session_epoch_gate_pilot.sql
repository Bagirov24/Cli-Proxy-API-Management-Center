-- M1k: synthetic SERVER-BOUND per-session epoch, real PG16 ONLY.
-- A signed actor+tenant scope is mandatory but does NOT identify a token
-- session. The CI-only server pins a verified RS256 token fingerprint to
-- a generated UUID+epoch and explicitly calls this gate BEFORE project DML.
-- This is NOT production OIDC, distributed sessions or external WORM.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_user <> 'postgres'
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR to_regprocedure('saas_m1_private.append_project_write_audit_fenced()') IS NULL
     OR to_regprocedure('saas_m1_private.bind_project_attempt_to_audit()') IS NULL
     OR to_regprocedure('saas_rls.acquire_authorized_read_barrier(text,text,text,text)') IS NULL
     OR to_regclass('saas_rls_private.actor_session_state') IS NULL
     OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_m1_project_executor'
                   AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
  THEN
    RAISE EXCEPTION 'M1k session gate forbidden outside signed disposable PG16';
  END IF;
END
$guard$;

DO $role$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_m1_session_owner') THEN
    CREATE ROLE saas_m1_session_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
  END IF;
END
$role$;
ALTER ROLE saas_m1_session_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA saas_m1_private,saas_m1_api,saas_rls
  TO saas_m1_session_owner;
GRANT USAGE ON SCHEMA saas_m1_private TO saas_rls_owner;
GRANT EXECUTE ON FUNCTION saas_rls.scope_membership_matches(TEXT,TEXT,TEXT)
  TO saas_m1_session_owner;
GRANT EXECUTE ON FUNCTION
  saas_rls.acquire_authorized_read_barrier(TEXT,TEXT,TEXT,TEXT)
  TO saas_m1_session_owner;

-- This is a synthetic DB session record, NOT an OIDC identity table.
-- None of its columns derive from raw JWT claims or HTTP session headers.
CREATE TABLE IF NOT EXISTS saas_m1_private.project_session_epochs (
  session_id UUID PRIMARY KEY,
  actor_id TEXT NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  tenant_id TEXT NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision>=1),
  status TEXT NOT NULL CHECK (status IN ('active','revoked'))
);
ALTER TABLE saas_m1_private.project_session_epochs OWNER TO saas_m1_session_owner;
REVOKE ALL ON saas_m1_private.project_session_epochs
  FROM PUBLIC,saas_ci_runner,saas_rls_reader,
       saas_m1_project_executor,saas_m1_project_owner,
       saas_m1_audit_owner,saas_m1_review_operator,saas_m1_review_owner;
ALTER TABLE saas_m1_private.project_session_epochs ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_m1_private.project_session_epochs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS m1k_session_owner_select
  ON saas_m1_private.project_session_epochs;
CREATE POLICY m1k_session_owner_select
  ON saas_m1_private.project_session_epochs
  FOR SELECT TO saas_m1_session_owner USING (true);
-- PostgreSQL16 treats SELECT ... FOR SHARE as an UPDATE-policy action.
-- FORCE RLS therefore needs explicit UPDATE USING for row visibility;
-- WITH CHECK(false) prevents the NOLOGIN lock owner from changing rows.
-- Privileged ephemeral fixture revocations remain authorized separately.
DROP POLICY IF EXISTS m1k_session_owner_share_lock
  ON saas_m1_private.project_session_epochs;
CREATE POLICY m1k_session_owner_share_lock
  ON saas_m1_private.project_session_epochs
  FOR UPDATE TO saas_m1_session_owner
  USING (true) WITH CHECK (false);

-- Exactly one authorized server session per transaction. Only a privileged
-- SECURITY DEFINER gate, not SQL executor/client/GUC, can create this row.
-- It is persisted in the SAME PG COMMIT as the project+audit+attempt,
-- hence not an independent receipt or precommit durable intent.
CREATE TABLE IF NOT EXISTS saas_m1_private.project_session_proofs (
  pg_txid TEXT PRIMARY KEY CHECK (pg_txid ~ '^[0-9]{1,19}$'),
  session_id UUID NOT NULL REFERENCES
    saas_m1_private.project_session_epochs(session_id),
  actor_id TEXT NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  tenant_id TEXT NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  session_revision BIGINT NOT NULL CHECK (session_revision>=1)
);
ALTER TABLE saas_m1_private.project_session_proofs OWNER TO saas_m1_session_owner;
REVOKE ALL ON saas_m1_private.project_session_proofs
  FROM PUBLIC,saas_ci_runner,saas_rls_reader,
       saas_m1_project_executor,saas_m1_project_owner,
       saas_m1_audit_owner,saas_m1_review_operator,saas_m1_review_owner;
ALTER TABLE saas_m1_private.project_session_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_m1_private.project_session_proofs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS m1k_session_proof_owner_insert
  ON saas_m1_private.project_session_proofs;
CREATE POLICY m1k_session_proof_owner_insert
  ON saas_m1_private.project_session_proofs
  FOR INSERT TO saas_m1_session_owner WITH CHECK (true);
DROP POLICY IF EXISTS m1k_session_proof_owner_select
  ON saas_m1_private.project_session_proofs;
CREATE POLICY m1k_session_proof_owner_select
  ON saas_m1_private.project_session_proofs
  FOR SELECT TO saas_m1_session_owner USING (true);

-- A revoked synthetic session cannot be resurrected or silently reset to
-- an older epoch by a mistaken operator fixture. Real IAM is NOT implied.
CREATE OR REPLACE FUNCTION saas_m1_private.validate_session_epoch_change()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'M1k session delete is forbidden';
  END IF;
  IF NEW.session_id IS DISTINCT FROM OLD.session_id
     OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR (OLD.status='revoked' AND NEW.status<>'revoked')
     OR (NEW IS DISTINCT FROM OLD AND NEW.revision<>OLD.revision+1)
  THEN
    RAISE EXCEPTION 'M1k session identity/epoch rollback or resurrection forbidden';
  END IF;
  RETURN NEW;
END
$fn$;
ALTER FUNCTION saas_m1_private.validate_session_epoch_change()
  OWNER TO saas_m1_session_owner;
REVOKE ALL ON FUNCTION saas_m1_private.validate_session_epoch_change()
  FROM PUBLIC,saas_ci_runner,saas_m1_project_executor,saas_rls_reader;
DROP TRIGGER IF EXISTS m1k_session_epoch_no_rollback
  ON saas_m1_private.project_session_epochs;
CREATE TRIGGER m1k_session_epoch_no_rollback
  BEFORE UPDATE OR DELETE ON saas_m1_private.project_session_epochs
  FOR EACH ROW EXECUTE FUNCTION saas_m1_private.validate_session_epoch_change();

-- A session revoke/rotation changes the *existing* tenant auth epoch,
-- cooperating with M1d's signed authorization barrier on the same tenant
-- revision row, without disclosing that row to the SQL executor.
CREATE OR REPLACE FUNCTION saas_m1_private.bump_tenant_epoch_on_session_change()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
BEGIN
  IF NEW IS DISTINCT FROM OLD THEN
    PERFORM saas_rls_private.advance_tenant_authorization_revision(NEW.tenant_id);
  END IF;
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_m1_private.bump_tenant_epoch_on_session_change()
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION
  saas_m1_private.bump_tenant_epoch_on_session_change()
  FROM PUBLIC,saas_ci_runner,saas_m1_project_executor,saas_rls_reader;
DROP TRIGGER IF EXISTS m1k_session_epoch_tenant_revision
  ON saas_m1_private.project_session_epochs;
CREATE TRIGGER m1k_session_epoch_tenant_revision
  AFTER UPDATE ON saas_m1_private.project_session_epochs
  FOR EACH ROW EXECUTE FUNCTION
    saas_m1_private.bump_tenant_epoch_on_session_change();

-- Invoke ONLY from the server's already HMAC-signed PG transaction and
-- under SET LOCAL ROLE saas_m1_project_executor. The function has one fixed
-- session UUID + expected epoch from the trusted server registry, not HTTP.
-- Locks session FOR SHARE until COMMIT/ROLLBACK, then obtains the M1d tenant
-- epoch FOR SHARE. A concurrent revoke updates BOTH rows, so either the
-- write commits first or the gate sees a revoked/newer session and denies.
CREATE OR REPLACE FUNCTION saas_m1_api.lock_project_session_epoch(
  target_session UUID, expected_revision BIGINT,
  target_tenant TEXT, target_actor TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
DECLARE
  stored_revision BIGINT;
  stored_status TEXT;
  locked_tenant_revision TEXT;
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed'
     OR current_setting('transaction_read_only') <> 'off'
     OR target_session IS NULL OR expected_revision IS NULL
     OR expected_revision<1
     OR target_tenant IS NULL OR target_tenant !~ '^[A-Za-z0-9_-]{1,64}$'
     OR target_actor IS NULL OR target_actor !~ '^[A-Za-z0-9_-]{1,128}$'
     OR current_setting('saas.scope_actor',true) IS DISTINCT FROM target_actor
     OR current_setting('saas.scope_tenant',true) IS DISTINCT FROM target_tenant
     OR NOT (saas_rls.scope_membership_matches(
       target_tenant,target_actor,'tenant-owner')
       OR saas_rls.scope_membership_matches(
       target_tenant,target_actor,'tenant-admin'))
  THEN
    RETURN FALSE;
  END IF;

  SELECT s.revision,s.status INTO stored_revision,stored_status
    FROM saas_m1_private.project_session_epochs AS s
    WHERE s.session_id=target_session
      AND s.actor_id=target_actor AND s.tenant_id=target_tenant
    FOR SHARE;
  IF stored_status IS DISTINCT FROM 'active'
     OR stored_revision IS DISTINCT FROM expected_revision THEN
    RETURN FALSE;
  END IF;

  locked_tenant_revision := COALESCE(
    saas_rls.acquire_authorized_read_barrier(
      target_tenant,target_actor,'tenant-owner','projects'),
    saas_rls.acquire_authorized_read_barrier(
      target_tenant,target_actor,'tenant-admin','projects')
  );
  IF locked_tenant_revision IS NULL
    OR locked_tenant_revision !~ '^[1-9][0-9]{0,18}$'
    OR NOT (saas_rls.scope_membership_matches(
      target_tenant,target_actor,'tenant-owner')
      OR saas_rls.scope_membership_matches(
      target_tenant,target_actor,'tenant-admin')) THEN
    RETURN FALSE;
  END IF;

  INSERT INTO saas_m1_private.project_session_proofs
    (pg_txid,session_id,actor_id,tenant_id,session_revision)
  VALUES(txid_current()::TEXT,target_session,target_actor,
         target_tenant,expected_revision);
  RETURN TRUE;
END
$fn$;
ALTER FUNCTION
  saas_m1_api.lock_project_session_epoch(UUID,BIGINT,TEXT,TEXT)
  OWNER TO saas_m1_session_owner;
REVOKE ALL ON FUNCTION
  saas_m1_api.lock_project_session_epoch(UUID,BIGINT,TEXT,TEXT)
  FROM PUBLIC,saas_ci_runner,saas_rls_reader,
       saas_m1_project_owner,saas_m1_audit_owner,saas_m1_review_operator;
GRANT EXECUTE ON FUNCTION
  saas_m1_api.lock_project_session_epoch(UUID,BIGINT,TEXT,TEXT)
  TO saas_m1_project_executor;

-- A second trigger runs AFTER M1d mandatory audit and M1g UUID binding,
-- and refuses ALL unguarded legacy project writes in this CI-only schema.
-- The proof table is written solely by SECURITY DEFINER gate, never from
-- a client-set custom GUC. Errors rollback project, audit and UUID together.
CREATE OR REPLACE FUNCTION saas_m1_private.require_project_session_proof()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
DECLARE
  signed_actor TEXT := current_setting('saas.scope_actor',true);
  proof_count BIGINT;
BEGIN
  IF signed_actor IS NULL OR signed_actor !~ '^[A-Za-z0-9_-]{1,128}$' THEN
    RAISE EXCEPTION 'M1k signed actor missing';
  END IF;
  SELECT COUNT(*) INTO proof_count
    FROM saas_m1_private.project_session_proofs p
    JOIN saas_m1_private.project_session_epochs s
      ON s.session_id=p.session_id
    WHERE p.pg_txid=txid_current()::TEXT
      AND p.actor_id=signed_actor
      AND p.tenant_id=NEW.tenant_id
      AND s.actor_id=p.actor_id AND s.tenant_id=p.tenant_id
      AND s.status='active' AND s.revision=p.session_revision;
  IF proof_count<>1 THEN
    RAISE EXCEPTION 'M1k signed project transaction lacks current locked session';
  END IF;
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_m1_private.require_project_session_proof()
  OWNER TO saas_m1_session_owner;
REVOKE ALL ON FUNCTION saas_m1_private.require_project_session_proof()
  FROM PUBLIC,saas_ci_runner,saas_rls_reader,saas_m1_project_executor;
DROP TRIGGER IF EXISTS m1_project_session_epoch_gate
  ON saas_m1_private.projects;
CREATE TRIGGER m1_project_session_epoch_gate
  AFTER INSERT OR UPDATE ON saas_m1_private.projects
  FOR EACH ROW EXECUTE FUNCTION saas_m1_private.require_project_session_proof();

DO $assert$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_m1_session_owner'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit)
     OR NOT ('m1_project_attempt_binding' < 'm1_project_session_epoch_gate')
     OR NOT EXISTS(SELECT 1 FROM pg_trigger
       WHERE tgrelid='saas_m1_private.projects'::regclass
         AND tgname='m1_project_atomic_audit'
         AND tgfoid='saas_m1_private.append_project_write_audit_fenced()'::regprocedure
         AND NOT tgisinternal)
     OR NOT EXISTS(SELECT 1 FROM pg_trigger
       WHERE tgrelid='saas_m1_private.projects'::regclass
         AND tgname='m1_project_attempt_binding'
         AND tgfoid='saas_m1_private.bind_project_attempt_to_audit()'::regprocedure
         AND NOT tgisinternal)
     OR NOT EXISTS(SELECT 1 FROM pg_trigger
       WHERE tgrelid='saas_m1_private.projects'::regclass
         AND tgname='m1_project_session_epoch_gate'
         AND tgfoid='saas_m1_private.require_project_session_proof()'::regprocedure
         AND NOT tgisinternal)
     OR NOT EXISTS(SELECT 1 FROM pg_policies
          WHERE schemaname='saas_m1_private'
            AND tablename='project_session_epochs'
            AND policyname='m1k_session_owner_share_lock'
            AND cmd='UPDATE' AND qual='true' AND with_check='false')
     OR NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
              WHERE oid='saas_m1_private.project_session_epochs'::regclass)
     OR NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
              WHERE oid='saas_m1_private.project_session_proofs'::regclass)
     OR has_table_privilege('saas_ci_runner',
         'saas_m1_private.project_session_epochs','SELECT')
     OR has_table_privilege('saas_m1_project_executor',
         'saas_m1_private.project_session_epochs','UPDATE')
     OR has_table_privilege('saas_m1_project_executor',
         'saas_m1_private.project_session_proofs','INSERT')
     OR has_table_privilege('saas_m1_review_operator',
         'saas_m1_private.project_session_proofs','SELECT')
     OR has_table_privilege('saas_m1_session_owner',
         'saas_rls_private.scope_signers','SELECT')
     OR has_schema_privilege('saas_m1_project_executor',
         'saas_m1_private','USAGE')
     OR has_function_privilege('saas_ci_runner',
         'saas_m1_api.lock_project_session_epoch(uuid,bigint,text,text)','EXECUTE')
     OR NOT has_function_privilege('saas_m1_project_executor',
         'saas_m1_api.lock_project_session_epoch(uuid,bigint,text,text)','EXECUTE')
  THEN
    RAISE EXCEPTION 'M1k least privilege/session lock/M1d audit fencing unsafe';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS M1k: signed PG16 session UUID+epoch FOR SHARE, tenant revision fence and mandatory trigger (CI-only)'
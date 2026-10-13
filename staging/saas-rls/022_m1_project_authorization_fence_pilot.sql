-- M1d: serialize cooperating project COMMIT vs tenant authorization changes.
-- DISPOSABLE PostgreSQL16 CI ONLY; never a production migration or API.
-- Reuses the EXISTING 007 FOR SHARE barrier and 004/008 epoch triggers.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_user <> 'postgres'
     OR current_setting('saas.staging_only', true) IS DISTINCT FROM 'true'
     OR to_regprocedure('saas_rls.acquire_authorized_read_barrier(text,text,text,text)') IS NULL
     OR to_regprocedure('saas_m1_private.append_project_write_audit()') IS NULL
     OR to_regclass('saas_m1_private.project_write_audit_outbox') IS NULL
     OR to_regclass('saas_rls_private.tenant_authorization_revisions') IS NULL
     OR to_regclass('saas_rls_private.actor_session_state') IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM pg_roles WHERE rolname='saas_m1_audit_owner'
       AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
  THEN
    RAISE EXCEPTION 'M1d project fence refused outside signed disposable PG16';
  END IF;
END
$guard$;

-- The M1c NOLOGIN audit owner already has saas_rls schema USAGE.
-- Grant only the existing, signed authorization BARRIER call; never the
-- private tenant epoch table, signing keys or direct project DML.
GRANT EXECUTE ON FUNCTION
  saas_rls.acquire_authorized_read_barrier(TEXT,TEXT,TEXT,TEXT)
  TO saas_m1_audit_owner;

-- A NEW trigger function, not an in-place replacement of the M1c function:
-- the earlier SQL021 replay is separately forbidden after this is installed.
-- A signed, active DB tenant/membership/session obtains FOR SHARE on the SAME
-- tenant revision row which all cooperating revoke/status writers UPDATE.
-- The lock survives to COMMIT (or ROLLBACK) of the caller transaction.
CREATE OR REPLACE FUNCTION saas_m1_private.append_project_write_audit_fenced()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  audit_operation TEXT;
  verified_actor TEXT := current_setting('saas.scope_actor', true);
  locked_revision TEXT;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'active' OR NEW.version <> 1 THEN
      RAISE EXCEPTION 'M1d invalid initial project state';
    END IF;
    audit_operation := 'create';
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR OLD.status <> 'active'
       OR NEW.version <> OLD.version + 1 THEN
      RAISE EXCEPTION 'M1d invalid project state transition';
    END IF;
    IF NEW.status = 'disabled' AND NEW.name = OLD.name THEN
      audit_operation := 'disable';
    ELSIF NEW.status = 'active' AND NEW.name IS DISTINCT FROM OLD.name THEN
      audit_operation := 'rename';
    ELSE
      RAISE EXCEPTION 'M1d unsupported project state transition';
    END IF;
  ELSE
    RAISE EXCEPTION 'M1d invalid operation';
  END IF;

  IF verified_actor IS NULL
     OR verified_actor !~ '^[A-Za-z0-9_-]{1,128}$' THEN
    RAISE EXCEPTION 'M1d invalid signed actor';
  END IF;

  -- 007 rejects non-READ-COMMITTED and validates the SIGNED transaction
  -- scope, current DB role/membership, tenant status and 008 actor state
  -- both BEFORE and AFTER any blocking FOR SHARE. No JWT/header role.
  -- PostgreSQL locks are released only when the outer transaction finishes.
  locked_revision := COALESCE(
    saas_rls.acquire_authorized_read_barrier(
      NEW.tenant_id, verified_actor, 'tenant-owner', 'projects'),
    saas_rls.acquire_authorized_read_barrier(
      NEW.tenant_id, verified_actor, 'tenant-admin', 'projects')
  );
  IF locked_revision IS NULL
     OR locked_revision !~ '^[1-9][0-9]{0,18}$'
     OR locked_revision::NUMERIC > 9223372036854775807 THEN
    RAISE EXCEPTION 'M1d signed tenant epoch fence denied';
  END IF;

  -- Mandatory write-audit is part of the SAME caller transaction. If this
  -- insert fails, the M1a function's exception subtransaction rolls back
  -- the provisional project change. There is no partial public success.
  INSERT INTO saas_m1_private.project_write_audit_outbox
    (tenant_id, project_id, project_version, operation, actor_id,
     authorization_revision, pg_txid)
  VALUES
    (NEW.tenant_id, NEW.project_id, NEW.version, audit_operation,
     verified_actor, locked_revision::BIGINT, txid_current()::TEXT);
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_m1_private.append_project_write_audit_fenced()
  OWNER TO saas_m1_audit_owner;
REVOKE ALL ON FUNCTION saas_m1_private.append_project_write_audit_fenced()
  FROM PUBLIC,saas_rls_reader,saas_ci_runner,
       saas_m1_project_owner,saas_m1_project_executor;

-- Existing app/client SQL functions are UNCHANGED. Only the private audit
-- trigger now also holds an authenticated authorization epoch lock.
DROP TRIGGER IF EXISTS m1_project_atomic_audit ON saas_m1_private.projects;
CREATE TRIGGER m1_project_atomic_audit
  AFTER INSERT OR UPDATE ON saas_m1_private.projects
  FOR EACH ROW EXECUTE FUNCTION saas_m1_private.append_project_write_audit_fenced();

DO $assert$
BEGIN
  IF NOT has_function_privilege('saas_m1_audit_owner',
       'saas_rls.acquire_authorized_read_barrier(text,text,text,text)','EXECUTE')
     OR has_function_privilege('saas_m1_project_executor',
       'saas_m1_private.append_project_write_audit_fenced()','EXECUTE')
     OR has_schema_privilege('saas_m1_project_executor',
       'saas_m1_private','USAGE')
     OR has_table_privilege('saas_m1_audit_owner',
       'saas_rls_private.tenant_authorization_revisions','SELECT')
     OR has_table_privilege('saas_m1_audit_owner',
       'saas_m1_private.projects','UPDATE')
     OR has_table_privilege('saas_m1_project_executor',
       'saas_m1_private.project_write_audit_outbox','INSERT')
     OR has_table_privilege('saas_ci_runner',
       'saas_rls_private.scope_signers','SELECT')
     OR NOT EXISTS (
       SELECT 1 FROM pg_trigger
       WHERE tgrelid='saas_m1_private.projects'::regclass
       AND tgname='m1_project_atomic_audit'
       AND tgfoid='saas_m1_private.append_project_write_audit_fenced()'::regprocedure
       AND NOT tgisinternal)
     OR NOT EXISTS (
       SELECT 1 FROM pg_class
       WHERE oid='saas_m1_private.project_write_audit_outbox'::regclass
       AND relrowsecurity AND relforcerowsecurity)
  THEN
    RAISE EXCEPTION 'M1d signed epoch lock / audit / role configuration unsafe';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS M1d: signed project-write tenant epoch FOR SHARE + same-COMMIT private audit installed (CI ONLY)'
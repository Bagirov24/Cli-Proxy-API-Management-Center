-- M1c: project mutation audit in the SAME PostgreSQL transaction.
-- STRICTLY disposable PG16 CI; this is not a migration for production.
-- No audit delivery, automatic reissue/retry, external trust or recovery.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
    OR current_user <> 'postgres'
    OR current_setting('saas.staging_only', true) IS DISTINCT FROM 'true'
    OR to_regclass('saas_m1_private.projects') IS NULL
    OR to_regprocedure('saas_rls.authorized_revision(text,text,text,text)') IS NULL
    OR to_regprocedure('saas_m1_api.create_project(text,text,text)') IS NULL
    -- Refuse accidental out-of-order replay: SQL021 would replace the
    -- M1d fenced trigger with the old non-fenced audit implementation.
    OR to_regprocedure('saas_m1_private.append_project_write_audit_fenced()') IS NOT NULL
    OR NOT EXISTS (
      SELECT 1 FROM pg_roles WHERE rolname='saas_m1_project_owner'
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
    OR NOT EXISTS (
      SELECT 1 FROM pg_roles WHERE rolname='saas_m1_project_executor'
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
  THEN
    RAISE EXCEPTION 'M1c atomic audit installation refused outside disposable PG16';
  END IF;
END
$guard$;

DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_m1_audit_owner') THEN
    CREATE ROLE saas_m1_audit_owner NOLOGIN NOINHERIT NOBYPASSRLS;
  END IF;
END
$role$;
ALTER ROLE saas_m1_audit_owner NOLOGIN NOINHERIT NOBYPASSRLS;
-- Isolated trigger owner can INSERT its own log, not write projects.
GRANT USAGE ON SCHEMA saas_m1_private TO saas_m1_audit_owner;
GRANT USAGE ON SCHEMA saas_rls TO saas_m1_audit_owner;
GRANT EXECUTE ON FUNCTION saas_rls.authorized_revision(TEXT,TEXT,TEXT,TEXT)
  TO saas_m1_audit_owner;

CREATE TABLE IF NOT EXISTS saas_m1_private.project_write_audit_outbox (
  event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  project_id TEXT NOT NULL CHECK (project_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  project_version BIGINT NOT NULL CHECK (project_version > 0),
  operation TEXT NOT NULL CHECK (operation IN ('create','rename','disable')),
  actor_id TEXT NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  authorization_revision BIGINT NOT NULL CHECK (authorization_revision > 0),
  pg_txid TEXT NOT NULL CHECK (pg_txid ~ '^[0-9]{1,19}$'),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id,project_id,project_version)
);
ALTER TABLE saas_m1_private.project_write_audit_outbox OWNER TO saas_m1_audit_owner;
REVOKE ALL ON saas_m1_private.project_write_audit_outbox
  FROM PUBLIC,saas_rls_reader,saas_ci_runner,
       saas_m1_project_owner,saas_m1_project_executor;
REVOKE ALL ON SEQUENCE saas_m1_private.project_write_audit_outbox_event_id_seq
  FROM PUBLIC,saas_rls_reader,saas_ci_runner,
       saas_m1_project_owner,saas_m1_project_executor;
ALTER TABLE saas_m1_private.project_write_audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_m1_private.project_write_audit_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS m1_audit_insert_only
  ON saas_m1_private.project_write_audit_outbox;
CREATE POLICY m1_audit_insert_only
  ON saas_m1_private.project_write_audit_outbox
  FOR INSERT TO saas_m1_audit_owner WITH CHECK (true);

-- The private log cannot be amended/deleted through SQL DML, even by its
-- NOLOGIN owner. PostgreSQL superusers/DDL can bypass this: NOT WORM.
CREATE OR REPLACE FUNCTION saas_m1_private.reject_project_audit_change()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  RAISE EXCEPTION 'M1c audit log is append only';
END
$fn$;
ALTER FUNCTION saas_m1_private.reject_project_audit_change()
  OWNER TO saas_m1_audit_owner;
REVOKE ALL ON FUNCTION saas_m1_private.reject_project_audit_change()
  FROM PUBLIC,saas_rls_reader,saas_ci_runner,
       saas_m1_project_owner,saas_m1_project_executor;
DROP TRIGGER IF EXISTS m1_outbox_append_only
  ON saas_m1_private.project_write_audit_outbox;
CREATE TRIGGER m1_outbox_append_only
  BEFORE UPDATE OR DELETE ON saas_m1_private.project_write_audit_outbox
  FOR EACH ROW EXECUTE FUNCTION saas_m1_private.reject_project_audit_change();

-- All M1a successful writes MUST write an audit row in the very SAME
-- transaction. An audit error aborts the project mutation; M1a's function
-- EXCEPTION block returns false after rolling back its own subtransaction.
-- The trigger deliberately never catches the audit failure.
CREATE OR REPLACE FUNCTION saas_m1_private.append_project_write_audit()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  audit_operation TEXT;
  verified_actor TEXT := current_setting('saas.scope_actor',true);
  verified_revision TEXT;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'active' OR NEW.version <> 1 THEN
      RAISE EXCEPTION 'M1c invalid initial project state';
    END IF;
    audit_operation := 'create';
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR OLD.status <> 'active'
       OR NEW.version <> OLD.version + 1 THEN
      RAISE EXCEPTION 'M1c invalid project transition';
    END IF;
    IF NEW.status = 'disabled' AND NEW.name = OLD.name THEN
      audit_operation := 'disable';
    ELSIF NEW.status = 'active' AND NEW.name IS DISTINCT FROM OLD.name THEN
      audit_operation := 'rename';
    ELSE
      RAISE EXCEPTION 'M1c unsupported project transition';
    END IF;
  ELSE
    RAISE EXCEPTION 'M1c unsupported project audit operation';
  END IF;

  IF verified_actor IS NULL
     OR verified_actor !~ '^[A-Za-z0-9_-]{1,128}$' THEN
    RAISE EXCEPTION 'M1c missing trusted transaction actor';
  END IF;
  -- HMAC/txid/expiry/tenant + ACTIVE tenant and exact DB membership-role
  -- are independently checked in privileged PG SQL; no client role is used.
  verified_revision := COALESCE(
    saas_rls.authorized_revision(NEW.tenant_id,verified_actor,
      'tenant-owner','projects'),
    saas_rls.authorized_revision(NEW.tenant_id,verified_actor,
      'tenant-admin','projects')
  );
  IF verified_revision IS NULL OR
     verified_revision !~ '^[1-9][0-9]{0,18}$' THEN
    RAISE EXCEPTION 'M1c signed authorization denied';
  END IF;
  INSERT INTO saas_m1_private.project_write_audit_outbox
    (tenant_id,project_id,project_version,operation,actor_id,
     authorization_revision,pg_txid)
  VALUES
    (NEW.tenant_id,NEW.project_id,NEW.version,audit_operation,verified_actor,
     verified_revision::BIGINT,txid_current()::TEXT);
  RETURN NULL; -- ignored for an AFTER row trigger
END
$fn$;
ALTER FUNCTION saas_m1_private.append_project_write_audit()
  OWNER TO saas_m1_audit_owner;
REVOKE ALL ON FUNCTION saas_m1_private.append_project_write_audit()
  FROM PUBLIC,saas_rls_reader,saas_ci_runner,
       saas_m1_project_owner,saas_m1_project_executor;
DROP TRIGGER IF EXISTS m1_project_atomic_audit
  ON saas_m1_private.projects;
CREATE TRIGGER m1_project_atomic_audit
  AFTER INSERT OR UPDATE ON saas_m1_private.projects
  FOR EACH ROW EXECUTE FUNCTION saas_m1_private.append_project_write_audit();

DO $assert$
BEGIN
  IF has_schema_privilege('saas_m1_project_executor','saas_m1_private','USAGE')
     OR has_schema_privilege('saas_ci_runner','saas_m1_private','USAGE')
     OR has_table_privilege('saas_m1_project_owner',
       'saas_m1_private.project_write_audit_outbox','INSERT')
     OR has_table_privilege('saas_m1_project_executor',
       'saas_m1_private.project_write_audit_outbox','SELECT')
     OR has_table_privilege('saas_ci_runner',
       'saas_m1_private.project_write_audit_outbox','INSERT')
     OR has_table_privilege('saas_m1_audit_owner',
       'saas_m1_private.projects','UPDATE')
     OR has_function_privilege('saas_m1_project_executor',
       'saas_m1_private.append_project_write_audit()','EXECUTE')
     OR NOT (
       SELECT relrowsecurity AND relforcerowsecurity
       FROM pg_class
       WHERE oid='saas_m1_private.project_write_audit_outbox'::regclass
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_trigger
       WHERE tgrelid='saas_m1_private.projects'::regclass
         AND tgname='m1_project_atomic_audit' AND NOT tgisinternal)
  THEN
    RAISE EXCEPTION 'M1c audit/executor least-privilege guard failed';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS M1c: trigger-owned FORCE RLS atomic project audit outbox installed in disposable PG16'
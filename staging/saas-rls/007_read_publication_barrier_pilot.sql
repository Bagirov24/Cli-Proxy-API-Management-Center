-- 2G.4d.4c: cooperative read-publication epoch lock, EPHEMERAL PG16 ONLY.
-- This is a PostgreSQL ordering experiment, not an HTTP delivery protocol.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
    OR current_user <> 'postgres'
    OR current_setting('saas.staging_only', TRUE) IS DISTINCT FROM 'true'
    OR to_regclass('saas_rls_private.tenant_authorization_revisions') IS NULL
    OR NOT EXISTS (SELECT 1 FROM pg_roles
                   WHERE rolname='saas_rls_owner' AND NOT rolsuper AND NOT rolbypassrls) THEN
    RAISE EXCEPTION 'Refusing publication barrier outside disposable CI';
  END IF;
END
$guard$;

-- A signed, current actor may take a SHARED lock on its tenant epoch.
-- All cooperating writers UPDATE the same epoch row in authorization
-- triggers, so a writer cannot COMMIT a revoke while this SQL transaction
-- remains open. Caller MUST hold the transaction to its declared
-- publication point, then COMMIT or ROLLBACK; this function alone does not
-- publish an HTTP response or guarantee network receipt.
CREATE OR REPLACE FUNCTION saas_rls.acquire_authorized_read_barrier(
  expected_tenant TEXT, expected_actor TEXT, expected_role TEXT,
  expected_collection TEXT
) RETURNS TEXT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  current_epoch TEXT;
BEGIN
  -- Force the checked-snapshot semantics relied on by the read gate.
  IF current_setting('transaction_isolation') <> 'read committed'
     OR NOT saas_rls.scope_membership_matches(
         expected_tenant, expected_actor, expected_role)
     OR NOT saas_rls.read_allowed(expected_tenant, expected_collection) THEN
    RETURN NULL;
  END IF;
  -- Writers hold an UPDATE lock on this same private epoch row until COMMIT.
  SELECT r.revision::TEXT INTO current_epoch
    FROM saas_rls_private.tenant_authorization_revisions AS r
   WHERE r.tenant_id=expected_tenant AND r.tenant_active
   FOR SHARE;
  IF current_epoch IS NULL THEN RETURN NULL; END IF;
  -- Recheck after waiting for the row lock, so a revoke committed while
  -- blocked in FOR SHARE is detected and denied, never approved from a
  -- pre-lock membership snapshot.
  IF NOT saas_rls.scope_membership_matches(
       expected_tenant, expected_actor, expected_role)
     OR NOT saas_rls.read_allowed(expected_tenant, expected_collection) THEN
    RETURN NULL;
  END IF;
  RETURN current_epoch;
END
$fn$;
ALTER FUNCTION saas_rls.acquire_authorized_read_barrier(TEXT,TEXT,TEXT,TEXT)
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.acquire_authorized_read_barrier(TEXT,TEXT,TEXT,TEXT)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.acquire_authorized_read_barrier(TEXT,TEXT,TEXT,TEXT)
  TO saas_rls_reader;

DO $assert$
BEGIN
  IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
     OR has_table_privilege('saas_rls_reader',
        'saas_rls_private.tenant_authorization_revisions','SELECT')
     OR has_table_privilege('saas_rls_reader',
        'saas_rls_private.tenant_authorization_revisions','UPDATE')
     OR NOT has_function_privilege('saas_rls_reader',
       'saas_rls.acquire_authorized_read_barrier(text,text,text,text)','EXECUTE') THEN
    RAISE EXCEPTION 'Publication barrier exposed private epoch privileges';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS: ephemeral signed FOR SHARE publication barrier installed'

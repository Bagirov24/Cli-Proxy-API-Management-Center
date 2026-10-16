-- 2G.4d.4b: signed expiry-sensitive revision attestation, ephemeral PG16 ONLY.
-- Grant expiry by time does not fire an UPDATE trigger. A deadline snapshot
-- must therefore accompany the epoch. No production migration path.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_user <> 'postgres'
     OR current_setting('saas.staging_only', TRUE) IS DISTINCT FROM 'true'
     OR to_regclass('saas_rls_private.tenant_authorization_revisions') IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_roles
                    WHERE rolname='saas_rls_owner' AND NOT rolsuper AND NOT rolbypassrls) THEN
    RAISE EXCEPTION 'Refusing time-aware revision migration outside ephemeral CI';
  END IF;
END
$guard$;

-- Same signed actor+tenant+txid and EXACT DB membership/role/collection
-- checks as 004, but return the next ACTIVE grant expiry cutoff.
-- FLOOR milliseconds denies up to 1ms early (never grants past real expiry).
-- A previously future grant disappears from MIN() as time advances,
-- without any revision increment. The server compares BOTH values.
CREATE OR REPLACE FUNCTION saas_rls.authorized_revision_state(
  expected_tenant TEXT, expected_actor TEXT, expected_role TEXT,
  expected_collection TEXT
) RETURNS TABLE(revision TEXT, not_after_ms TEXT)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT r.revision::TEXT,
    (SELECT FLOOR(EXTRACT(EPOCH FROM MIN(g.expires_at)) * 1000)::BIGINT::TEXT
       FROM saas_rls.resource_grants AS g
      WHERE g.grantee_tenant_id = expected_tenant
        AND g.status = 'active'
        AND g.expires_at > statement_timestamp()
    ) AS not_after_ms
    FROM saas_rls_private.tenant_authorization_revisions AS r
   WHERE r.tenant_id=expected_tenant AND r.tenant_active
     AND saas_rls.scope_membership_matches(
       expected_tenant, expected_actor, expected_role)
     AND saas_rls.read_allowed(expected_tenant, expected_collection)
$fn$;
ALTER FUNCTION saas_rls.authorized_revision_state(TEXT,TEXT,TEXT,TEXT)
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.authorized_revision_state(TEXT,TEXT,TEXT,TEXT)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.authorized_revision_state(TEXT,TEXT,TEXT,TEXT)
  TO saas_rls_reader;

DO $assert$
BEGIN
  IF has_table_privilege('saas_rls_reader',
       'saas_rls_private.tenant_authorization_revisions','SELECT')
     OR has_table_privilege('saas_rls_reader',
       'saas_rls.resource_grants','SELECT')
     OR has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
     OR NOT has_function_privilege('saas_rls_reader',
       'saas_rls.authorized_revision_state(text,text,text,text)','EXECUTE') THEN
    RAISE EXCEPTION 'Expiry attestation must not leak private grant details';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS: staging signed epoch + impending grant-expiry deadline attestation'

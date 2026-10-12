-- Stage 2G.4d.6a: actor-wide session kill switch, DISPOSABLE PG16 ONLY.
-- Synthetic actor registry: NOT an OIDC token/session registry or production identity.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'saas_ephemeral_test'
     OR current_user <> 'postgres'
     OR current_setting('saas.staging_only', TRUE) IS DISTINCT FROM 'true'
     OR to_regclass('saas_rls_private.tenant_authorization_revisions') IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
         AND NOT rolsuper AND NOT rolbypassrls) THEN
    RAISE EXCEPTION 'Refusing actor revocation pilot outside disposable CI';
  END IF;
END
$guard$;

-- An actor is active only while its SERVER-owned singleton synthetic
-- session is active. No per-token identity or OIDC subject is signed by 002.
CREATE TABLE IF NOT EXISTS saas_rls_private.actor_session_state (
  actor_id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0)
);
ALTER TABLE saas_rls_private.actor_session_state OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.actor_session_state FROM PUBLIC, saas_rls_reader;

-- Insert missing actors on replay; NEVER reset revoked actors to active.
INSERT INTO saas_rls_private.actor_session_state(actor_id,status,revision)
SELECT DISTINCT m.actor_id,'active',1 FROM saas_rls.memberships AS m
ON CONFLICT (actor_id) DO NOTHING;

CREATE OR REPLACE FUNCTION saas_rls_private.revise_actor_session_state()
RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  affected_actor TEXT;
  affected_tenant TEXT;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.actor_id IS DISTINCT FROM OLD.actor_id THEN
      RAISE EXCEPTION 'Actor identity relocation is forbidden';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
  END IF;
  affected_actor := CASE WHEN TG_OP='DELETE' THEN OLD.actor_id ELSE NEW.actor_id END;
  FOR affected_tenant IN
    SELECT DISTINCT tenant_id FROM saas_rls.memberships
    WHERE actor_id=affected_actor AND tenant_id IS NOT NULL
    ORDER BY tenant_id
  LOOP
    PERFORM saas_rls_private.advance_tenant_authorization_revision(affected_tenant);
  END LOOP;
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_rls_private.revise_actor_session_state()
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.revise_actor_session_state()
  FROM PUBLIC, saas_rls_reader;
DROP TRIGGER IF EXISTS saas_actor_session_authorization_revision
  ON saas_rls_private.actor_session_state;
CREATE TRIGGER saas_actor_session_authorization_revision
AFTER INSERT OR UPDATE OR DELETE ON saas_rls_private.actor_session_state
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_actor_session_state();

-- Replace gate 003 without granting SELECT on private identity/session rows.
-- Signed actor+tenant+txid is still mandatory. Actor-wide revocation is
-- checked atomically with the existing membership and exact role condition.
CREATE OR REPLACE FUNCTION saas_rls.scope_membership_matches(
  expected_tenant TEXT, expected_actor TEXT, expected_role TEXT
) RETURNS BOOLEAN
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT saas_rls_private.scope_verified()
    AND expected_tenant =
      NULLIF(current_setting('saas.scope_tenant', true), '')
    AND expected_actor =
      NULLIF(current_setting('saas.scope_actor', true), '')
    AND EXISTS (
      SELECT 1 FROM saas_rls_private.actor_session_state AS s
      WHERE s.actor_id=expected_actor AND s.status='active'
    )
    AND EXISTS (
      SELECT 1 FROM saas_rls.memberships AS m
      WHERE m.tenant_id=expected_tenant
        AND m.actor_id=expected_actor
        AND m.role=expected_role AND m.status='active'
    )
$fn$;
ALTER FUNCTION saas_rls.scope_membership_matches(TEXT,TEXT,TEXT)
  OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.scope_membership_matches(TEXT,TEXT,TEXT)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.scope_membership_matches(TEXT,TEXT,TEXT)
  TO saas_rls_reader;

DO $assert$
BEGIN
  IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
     OR has_table_privilege('saas_rls_reader',
         'saas_rls_private.actor_session_state','SELECT')
     OR has_table_privilege('saas_rls_reader',
         'saas_rls_private.actor_session_state','UPDATE')
     OR has_table_privilege('saas_ci_runner',
         'saas_rls_private.actor_session_state','SELECT')
     OR NOT has_function_privilege('saas_rls_reader',
         'saas_rls.scope_membership_matches(text,text,text)','EXECUTE') THEN
    RAISE EXCEPTION 'Actor session gate exposed private identity data';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS: actor-wide kill switch versions all tenant epochs in transaction'

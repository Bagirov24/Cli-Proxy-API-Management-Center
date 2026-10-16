-- Stage 2G.4d.6b: durable-on-COMMIT audit/outbox, EPHEMERAL PG16 ONLY.
-- NOT a delivery guarantee, public audit API or production audit sink.
BEGIN;
DO $guard$
BEGIN
  IF current_database()<>'saas_ephemeral_test'
    OR current_user<>'postgres'
    OR current_setting('saas.staging_only',TRUE) IS DISTINCT FROM 'true'
    OR to_regclass('saas_rls_private.actor_session_state') IS NULL
    OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
                   AND NOT rolsuper AND NOT rolbypassrls) THEN
    RAISE EXCEPTION 'Refusing publication audit outbox outside disposable CI';
  END IF;
END
$guard$;

CREATE TABLE IF NOT EXISTS saas_rls_private.local_publication_audit_outbox (
  event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  tenant_id TEXT NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  actor_id TEXT NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  collection TEXT NOT NULL CHECK (collection IN
    ('tenant','projects','applications','client-keys','accounts','pools','egress','routing')),
  correlation_id TEXT NOT NULL CHECK (correlation_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  authorization_revision BIGINT NOT NULL CHECK (authorization_revision>0),
  result TEXT NOT NULL DEFAULT 'allow' CHECK (result='allow'),
  UNIQUE (tenant_id,correlation_id)
);
ALTER TABLE saas_rls_private.local_publication_audit_outbox OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.local_publication_audit_outbox
  FROM PUBLIC,saas_rls_reader;
REVOKE ALL ON SEQUENCE saas_rls_private.local_publication_audit_outbox_event_id_seq
  FROM PUBLIC,saas_rls_reader;

-- An append-only staging log. A superuser can bypass DDL and may alter
-- recorded data; tamper-evidence, retention and replication remain SPEC.
CREATE OR REPLACE FUNCTION saas_rls_private.reject_local_audit_mutation()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
  RAISE EXCEPTION 'Publication audit is append only';
END
$fn$;
ALTER FUNCTION saas_rls_private.reject_local_audit_mutation()
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.reject_local_audit_mutation()
 FROM PUBLIC,saas_rls_reader;
DROP TRIGGER IF EXISTS saas_local_audit_append_only
 ON saas_rls_private.local_publication_audit_outbox;
CREATE TRIGGER saas_local_audit_append_only
BEFORE UPDATE OR DELETE ON saas_rls_private.local_publication_audit_outbox
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.reject_local_audit_mutation();

-- No raw SQL, tokens, subject, resource ID, payload or grant IDs enter the
-- outbox. A signed actor/tenant+txid, active actor-wide session, current
-- membership role and collection are REQUIRED, just like the publication
-- lock. Another FOR SHARE in the same txn is safe, not a new lease.
CREATE OR REPLACE FUNCTION saas_rls.record_signed_local_publication(
  expected_tenant TEXT, expected_actor TEXT, expected_role TEXT,
  expected_collection TEXT, server_correlation TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
DECLARE
  signed_revision TEXT;
BEGIN
  IF server_correlation IS NULL OR
     server_correlation !~ '^[A-Za-z0-9_-]{1,128}$' THEN
    RETURN FALSE;
  END IF;
  signed_revision := saas_rls.acquire_authorized_read_barrier(
    expected_tenant,expected_actor,expected_role,expected_collection);
  IF signed_revision IS NULL THEN RETURN FALSE; END IF;

  INSERT INTO saas_rls_private.local_publication_audit_outbox
    (tenant_id,actor_id,collection,correlation_id,authorization_revision)
  VALUES (expected_tenant,expected_actor,expected_collection,
          server_correlation,signed_revision::BIGINT);
  -- Duplicate correlation keys and storage failure must abort the entire
  -- publication transaction, not silently mark an event as delivered.
  RETURN TRUE;
END
$fn$;
ALTER FUNCTION saas_rls.record_signed_local_publication(TEXT,TEXT,TEXT,TEXT,TEXT)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.record_signed_local_publication(TEXT,TEXT,TEXT,TEXT,TEXT)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.record_signed_local_publication(TEXT,TEXT,TEXT,TEXT,TEXT)
 TO saas_rls_reader;

DO $assert$
BEGIN
  IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
     OR has_table_privilege('saas_rls_reader',
        'saas_rls_private.local_publication_audit_outbox','SELECT')
     OR has_table_privilege('saas_rls_reader',
        'saas_rls_private.local_publication_audit_outbox','INSERT')
     OR has_table_privilege('saas_ci_runner',
        'saas_rls_private.local_publication_audit_outbox','DELETE')
     OR NOT has_function_privilege('saas_rls_reader',
        'saas_rls.record_signed_local_publication(text,text,text,text,text)','EXECUTE') THEN
    RAISE EXCEPTION 'Signed audit outbox ACL violates least privilege';
  END IF;
END
$assert$;
COMMIT;
\echo 'PASS: signed append-only publication outbox installed in disposable PG16'

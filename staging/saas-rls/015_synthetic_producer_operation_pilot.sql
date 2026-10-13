-- 2G.4d.7f: durable producer operation identity, disposable PG16 ONLY.
-- This is an EVENT-ONLY idempotency registry, not a payload/HTTP queue.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR current_setting('saas.staging_only',TRUE) IS DISTINCT FROM 'true'
 OR to_regclass('saas_rls_private.local_publication_audit_outbox') IS NULL
 OR to_regclass('saas_rls_private.synthetic_delivery_intents') IS NULL
 OR to_regclass('saas_rls_private.synthetic_receiver_effects') IS NULL
 OR to_regprocedure('saas_rls.record_signed_local_publication(text,text,text,text,text)') IS NULL
 OR to_regprocedure('saas_rls_private.reject_local_audit_mutation()') IS NULL
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
   AND NOT rolsuper AND NOT rolbypassrls)
 THEN RAISE EXCEPTION 'Refusing producer idempotency outside disposable PG16'; END IF;
END
$guard$;

-- Globally unique random UUID, scoped to immutable authorization identity,
-- exact collection and canonical requested limit. No JWT, bearer, client
-- payload, secrets or raw SQL enter this private table.
CREATE TABLE IF NOT EXISTS saas_rls_private.synthetic_producer_operations (
 operation_id UUID PRIMARY KEY,
 event_id BIGINT NOT NULL UNIQUE REFERENCES
   saas_rls_private.local_publication_audit_outbox(event_id),
 tenant_id TEXT NOT NULL CHECK(tenant_id ~ '^[A-Za-z0-9_-]{1,64}$'),
 actor_id TEXT NOT NULL CHECK(actor_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 membership_role TEXT NOT NULL CHECK(membership_role IN
   ('tenant-owner','tenant-admin','tenant-viewer','tenant-auditor')),
 collection TEXT NOT NULL CHECK(collection IN
   ('tenant','projects','applications','client-keys','accounts','pools','egress','routing')),
 requested_limit INTEGER NOT NULL CHECK(requested_limit BETWEEN 1 AND 100),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE saas_rls_private.synthetic_producer_operations OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.synthetic_producer_operations
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
 saas_mock_delivery_worker,saas_mock_receiver;
DROP TRIGGER IF EXISTS saas_synthetic_producer_operation_immutable
 ON saas_rls_private.synthetic_producer_operations;
CREATE TRIGGER saas_synthetic_producer_operation_immutable
 BEFORE UPDATE OR DELETE ON saas_rls_private.synthetic_producer_operations
 FOR EACH ROW EXECUTE FUNCTION saas_rls_private.reject_local_audit_mutation();

-- Called ONLY in the already-signed, still-open publication transaction.
-- A missing/bad session, changed role, unauthorized collection or revoked
-- tenant denies BEFORE looking up any operation or inserting any event.
-- A transaction-scoped advisory lock serializes competing UUIDs, including
-- a cross-tenant ID collision. Hash collision can only delay, never grant.
-- READ COMMITTED rechecks the committed row AFTER waiting on the lock.
CREATE OR REPLACE FUNCTION saas_rls.record_signed_synthetic_operation(
 expected_tenant TEXT,expected_actor TEXT,expected_role TEXT,
 expected_collection TEXT,server_correlation TEXT,
 requested_operation UUID,requested_limit INTEGER
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE
 signed_revision TEXT;
 bound_tenant TEXT;
 bound_actor TEXT;
 bound_role TEXT;
 bound_collection TEXT;
 bound_limit INTEGER;
 saved_id BIGINT;
 source_id BIGINT;
BEGIN
 IF requested_operation IS NULL
    OR requested_operation::TEXT !~* '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    OR requested_limit IS NULL OR requested_limit<1 OR requested_limit>100
    OR server_correlation IS NULL
    OR server_correlation !~ '^[A-Za-z0-9_-]{1,128}$'
 THEN RETURN FALSE; END IF;
 signed_revision := saas_rls.acquire_authorized_read_barrier(
   expected_tenant,expected_actor,expected_role,expected_collection);
 IF signed_revision IS NULL THEN RETURN FALSE; END IF;

 PERFORM pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtextextended(requested_operation::TEXT,20261013));
 SELECT p.event_id,p.tenant_id,p.actor_id,p.membership_role,
   p.collection,p.requested_limit
 INTO saved_id,bound_tenant,bound_actor,bound_role,bound_collection,bound_limit
 FROM saas_rls_private.synthetic_producer_operations p
 WHERE p.operation_id=requested_operation;
 IF FOUND THEN
   -- The same UUID never creates a new audit/intent; a conflicting owner,
   -- role, collection or shape gets the same generic false as any denial.
   -- The caller MUST reauthenticate and pass the current signed DB barrier.
   RETURN bound_tenant=expected_tenant AND bound_actor=expected_actor
      AND bound_role=expected_role AND bound_collection=expected_collection
      AND bound_limit=requested_limit
      AND EXISTS(SELECT 1 FROM saas_rls_private.synthetic_delivery_intents i
                 WHERE i.event_id=saved_id);
 END IF;

 IF NOT saas_rls.record_signed_local_publication(
   expected_tenant,expected_actor,expected_role,expected_collection,
   server_correlation) THEN RETURN FALSE; END IF;
 SELECT e.event_id INTO source_id
 FROM saas_rls_private.local_publication_audit_outbox e
 WHERE e.tenant_id=expected_tenant
   AND e.actor_id=expected_actor AND e.collection=expected_collection
   AND e.correlation_id=server_correlation
   AND e.authorization_revision=signed_revision::BIGINT;
 IF source_id IS NULL THEN
   RAISE EXCEPTION 'Signed operation missing committed-intent source';
 END IF;
 INSERT INTO saas_rls_private.synthetic_producer_operations
   (operation_id,event_id,tenant_id,actor_id,membership_role,collection,
    requested_limit)
 VALUES(requested_operation,source_id,expected_tenant,expected_actor,
        expected_role,expected_collection,requested_limit);
 -- 009 audit, 013 intent and operation identity COMMIT or ROLLBACK together.
 RETURN TRUE;
END
$fn$;
ALTER FUNCTION saas_rls.record_signed_synthetic_operation(
 TEXT,TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.record_signed_synthetic_operation(
 TEXT,TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.record_signed_synthetic_operation(
 TEXT,TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) TO saas_rls_reader;

DO $assert$
BEGIN
 IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 OR has_table_privilege('saas_rls_reader',
   'saas_rls_private.synthetic_producer_operations','SELECT')
 OR has_table_privilege('saas_ci_runner',
   'saas_rls_private.synthetic_producer_operations','INSERT')
 OR has_table_privilege('saas_mock_receiver',
   'saas_rls_private.synthetic_producer_operations','SELECT')
 OR has_table_privilege('saas_mock_delivery_worker',
   'saas_rls_private.synthetic_producer_operations','UPDATE')
 OR has_function_privilege('saas_ci_runner',
   'saas_rls.record_signed_synthetic_operation(text,text,text,text,text,uuid,integer)','EXECUTE')
 OR NOT has_function_privilege('saas_rls_reader',
   'saas_rls.record_signed_synthetic_operation(text,text,text,text,text,uuid,integer)','EXECUTE')
 THEN RAISE EXCEPTION 'Producer operation idempotency exposed to untrusted SQL'; END IF;
END
$assert$;
COMMIT;
\echo 'PASS: guarded immutable producer operation -> one signed audit/intent';

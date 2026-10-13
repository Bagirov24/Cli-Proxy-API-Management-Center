-- Stage 2G.4d.7g: STAGING-ONLY signed operation issuance/recovery.
-- No transport, payload, HTTP, client secret or network side effect.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
    OR current_setting('saas.staging_only',TRUE) IS DISTINCT FROM 'true'
    OR to_regclass('saas_rls_private.synthetic_producer_operations') IS NULL
    OR to_regclass('saas_rls_private.synthetic_delivery_intents') IS NULL
    OR to_regprocedure('saas_rls.record_signed_synthetic_operation(text,text,text,text,text,uuid,integer)') IS NULL
    OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
       AND NOT rolsuper AND NOT rolbypassrls)
 THEN RAISE EXCEPTION 'Refusing producer issuance outside disposable PG16'; END IF;
END
$guard$;

-- An issued UUID is opaque and never authenticates the holder. A permanent
-- tombstone keeps globally unique UUIDs unusable after expiry; deletion /
-- reuse and production retention remain OPEN. No tokens, secrets or payloads.
CREATE TABLE IF NOT EXISTS saas_rls_private.synthetic_operation_issues (
 operation_id UUID PRIMARY KEY,
 tenant_id TEXT NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_-]{1,64}$'),
 actor_id TEXT NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 membership_role TEXT NOT NULL CHECK
   (membership_role IN ('tenant-owner','tenant-admin','tenant-viewer','tenant-auditor')),
 collection TEXT NOT NULL CHECK
   (collection IN ('tenant','projects','applications','client-keys',
                   'accounts','pools','egress','routing')),
 requested_limit INTEGER NOT NULL CHECK (requested_limit BETWEEN 1 AND 100),
 issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 issue_expires_at TIMESTAMPTZ NOT NULL,
 recovery_expires_at TIMESTAMPTZ NOT NULL,
 CONSTRAINT saas_issue_ttl CHECK (issue_expires_at>issued_at),
 CONSTRAINT saas_recovery_window CHECK (recovery_expires_at>issue_expires_at)
);
ALTER TABLE saas_rls_private.synthetic_operation_issues OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.synthetic_operation_issues
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
      saas_mock_delivery_worker,saas_mock_receiver;
DROP TRIGGER IF EXISTS saas_synthetic_operation_issue_immutable
 ON saas_rls_private.synthetic_operation_issues;
CREATE TRIGGER saas_synthetic_operation_issue_immutable
 BEFORE UPDATE OR DELETE ON saas_rls_private.synthetic_operation_issues
 FOR EACH ROW EXECUTE FUNCTION saas_rls_private.reject_local_audit_mutation();

-- Server chooses UUIDv4 + 120s in trusted Bun staging; test direct SQL may
-- request 2s so expiration can be proven without a privileged clock override.
-- Recovery window is fixed 2h, NOT a retention deletion policy.
CREATE OR REPLACE FUNCTION saas_rls.issue_signed_synthetic_operation(
 expected_tenant TEXT, expected_actor TEXT, expected_role TEXT,
 expected_collection TEXT, issued_operation UUID,
 requested_limit INTEGER, issue_ttl_seconds INTEGER
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE current_revision TEXT;
DECLARE instant TIMESTAMPTZ;
BEGIN
 IF issued_operation IS NULL
    OR issued_operation::TEXT !~
       '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    OR requested_limit IS NULL OR requested_limit NOT BETWEEN 1 AND 100
    OR issue_ttl_seconds IS NULL OR issue_ttl_seconds NOT BETWEEN 2 AND 600
 THEN RETURN FALSE; END IF;
 current_revision := saas_rls.acquire_authorized_read_barrier(
   expected_tenant, expected_actor, expected_role, expected_collection);
 IF current_revision IS NULL THEN RETURN FALSE; END IF;

 instant := clock_timestamp();
 INSERT INTO saas_rls_private.synthetic_operation_issues
   (operation_id,tenant_id,actor_id,membership_role,collection,
    requested_limit,issued_at,issue_expires_at,recovery_expires_at)
 VALUES (issued_operation,expected_tenant,expected_actor,expected_role,
         expected_collection,requested_limit,instant,
         instant + make_interval(secs => issue_ttl_seconds),
         instant + interval '2 hours');
 -- A duplicate ID (including same actor) fails without exposing owner.
 -- Higher trust boundary uses server-random UUID; no retry/upsert here.
 RETURN TRUE;
EXCEPTION WHEN unique_violation THEN
 RETURN FALSE;
END
$fn$;
ALTER FUNCTION saas_rls.issue_signed_synthetic_operation(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.issue_signed_synthetic_operation(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.issue_signed_synthetic_operation(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) TO saas_rls_reader;

-- Requires a preissued, matching, not-expired reservation for a FIRST
-- event. Once committed, replay is allowed inside the recovery window
-- even if the initial issuance deadline elapsed. No status is exposed.
CREATE OR REPLACE FUNCTION saas_rls.record_signed_reserved_operation(
 expected_tenant TEXT,expected_actor TEXT,expected_role TEXT,
 expected_collection TEXT,server_correlation TEXT,
 requested_operation UUID,requested_limit INTEGER
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE current_revision TEXT;
DECLARE issue_row saas_rls_private.synthetic_operation_issues%ROWTYPE;
DECLARE already_committed BOOLEAN;
BEGIN
 IF requested_operation IS NULL OR requested_limit IS NULL OR
    requested_limit NOT BETWEEN 1 AND 100 OR
    server_correlation IS NULL OR
    server_correlation !~ '^[A-Za-z0-9_-]{1,128}$'
 THEN RETURN FALSE; END IF;
 current_revision := saas_rls.acquire_authorized_read_barrier(
   expected_tenant,expected_actor,expected_role,expected_collection);
 IF current_revision IS NULL THEN RETURN FALSE; END IF;

 -- Same advisory namespace/salt as immutable 015. Cross-process requests
 -- serialize; no uncommitted insertion from another worker is observable.
 PERFORM pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtextextended(requested_operation::TEXT,20261013));
 SELECT * INTO issue_row
 FROM saas_rls_private.synthetic_operation_issues
 WHERE operation_id=requested_operation;
 IF NOT FOUND OR issue_row.tenant_id IS DISTINCT FROM expected_tenant
    OR issue_row.actor_id IS DISTINCT FROM expected_actor
    OR issue_row.membership_role IS DISTINCT FROM expected_role
    OR issue_row.collection IS DISTINCT FROM expected_collection
    OR issue_row.requested_limit IS DISTINCT FROM requested_limit
 THEN RETURN FALSE; END IF;

 -- Expired status window must never allow creation/replay, but the
 -- immutable key remains a tombstone for all subsequent requests.
 IF clock_timestamp()>=issue_row.recovery_expires_at THEN RETURN FALSE; END IF;
 SELECT EXISTS (
   SELECT 1 FROM saas_rls_private.synthetic_producer_operations p
   WHERE p.operation_id=requested_operation
     AND p.tenant_id=expected_tenant AND p.actor_id=expected_actor
     AND p.membership_role=expected_role AND
         p.collection=expected_collection AND
         p.requested_limit=requested_limit
 ) INTO already_committed;
 IF NOT already_committed AND clock_timestamp()>=issue_row.issue_expires_at
 THEN RETURN FALSE; END IF;
 -- 015 internally verifies signed scope and keeps one 009/013 event.
 RETURN saas_rls.record_signed_synthetic_operation(
   expected_tenant,expected_actor,expected_role,expected_collection,
   server_correlation,requested_operation,requested_limit);
END
$fn$;
ALTER FUNCTION saas_rls.record_signed_reserved_operation(
 TEXT,TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.record_signed_reserved_operation(
 TEXT,TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.record_signed_reserved_operation(
 TEXT,TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) TO saas_rls_reader;

-- READ-ONLY STATUS. Returns NULL for any unknown/conflicting or
-- unauthorized operation: uniform generic denial at the boundary.
-- No event_id, tenant_id, actor_id or worker data is returned.
CREATE OR REPLACE FUNCTION saas_rls.read_signed_synthetic_operation_status(
 expected_tenant TEXT,expected_actor TEXT,expected_role TEXT,
 expected_collection TEXT,requested_operation UUID,
 requested_limit INTEGER
) RETURNS TEXT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE issue_row saas_rls_private.synthetic_operation_issues%ROWTYPE;
DECLARE current_revision TEXT;
BEGIN
 IF requested_operation IS NULL OR requested_limit IS NULL
    OR requested_limit NOT BETWEEN 1 AND 100 THEN RETURN NULL; END IF;
 current_revision := saas_rls.acquire_authorized_read_barrier(
   expected_tenant,expected_actor,expected_role,expected_collection);
 IF current_revision IS NULL THEN RETURN NULL; END IF;
 SELECT * INTO issue_row FROM saas_rls_private.synthetic_operation_issues
 WHERE operation_id=requested_operation;
 IF NOT FOUND OR issue_row.tenant_id IS DISTINCT FROM expected_tenant
    OR issue_row.actor_id IS DISTINCT FROM expected_actor
    OR issue_row.membership_role IS DISTINCT FROM expected_role
    OR issue_row.collection IS DISTINCT FROM expected_collection
    OR issue_row.requested_limit IS DISTINCT FROM requested_limit
 THEN RETURN NULL; END IF;
 IF clock_timestamp()>=issue_row.recovery_expires_at THEN
   RETURN 'expired'; END IF;
 IF EXISTS(SELECT 1 FROM saas_rls_private.synthetic_producer_operations p
    JOIN saas_rls_private.synthetic_delivery_intents i
      ON i.event_id=p.event_id
    WHERE p.operation_id=requested_operation
      AND p.tenant_id=expected_tenant AND p.actor_id=expected_actor
      AND p.membership_role=expected_role AND
          p.collection=expected_collection AND
          p.requested_limit=requested_limit)
 THEN RETURN 'committed'; END IF;
 IF clock_timestamp()>=issue_row.issue_expires_at THEN
   RETURN 'expired'; END IF;
 RETURN 'issued';
END
$fn$;
ALTER FUNCTION saas_rls.read_signed_synthetic_operation_status(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.read_signed_synthetic_operation_status(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.read_signed_synthetic_operation_status(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) TO saas_rls_reader;

DO $assert$
BEGIN
 IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 OR has_table_privilege('saas_rls_reader',
   'saas_rls_private.synthetic_operation_issues','SELECT')
 OR has_table_privilege('saas_mock_receiver',
   'saas_rls_private.synthetic_operation_issues','SELECT')
 OR has_table_privilege('saas_mock_delivery_worker',
   'saas_rls_private.synthetic_operation_issues','UPDATE')
 OR has_table_privilege('saas_ci_runner',
   'saas_rls_private.synthetic_operation_issues','INSERT')
 OR has_function_privilege('saas_ci_runner',
   'saas_rls.issue_signed_synthetic_operation(text,text,text,text,uuid,integer,integer)','EXECUTE')
 OR has_function_privilege('saas_ci_runner',
   'saas_rls.read_signed_synthetic_operation_status(text,text,text,text,uuid,integer)','EXECUTE')
 OR NOT has_function_privilege('saas_rls_reader',
   'saas_rls.issue_signed_synthetic_operation(text,text,text,text,uuid,integer,integer)','EXECUTE')
 OR NOT has_function_privilege('saas_rls_reader',
   'saas_rls.read_signed_synthetic_operation_status(text,text,text,text,uuid,integer)','EXECUTE')
 OR NOT has_function_privilege('saas_rls_reader',
   'saas_rls.record_signed_reserved_operation(text,text,text,text,text,uuid,integer)','EXECUTE')
 THEN RAISE EXCEPTION 'Signed producer issuance/status privileges not isolated'; END IF;
END
$assert$;
COMMIT;
\echo 'PASS: guarded signed issue/recover/expire and permanent UUID tombstone'

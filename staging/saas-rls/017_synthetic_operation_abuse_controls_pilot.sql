-- Stage 2G.4d.7h: bounded synthetic operation issuance/recovery.
-- Disposable PostgreSQL16 ONLY. No tombstone deletion, purge or HTTP.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR current_setting('saas.staging_only',TRUE) IS DISTINCT FROM 'true'
 OR to_regclass('saas_rls_private.synthetic_operation_issues') IS NULL
 OR to_regclass('saas_rls_private.synthetic_producer_operations') IS NULL
 OR to_regprocedure('saas_rls.issue_signed_synthetic_operation(text,text,text,text,uuid,integer,integer)') IS NULL
 OR to_regprocedure('saas_rls.read_signed_synthetic_operation_status(text,text,text,text,uuid,integer)') IS NULL
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
   AND NOT rolsuper AND NOT rolbypassrls)
 THEN RAISE EXCEPTION 'Refusing rate-limited synthetic issuance outside disposable PG16'; END IF;
END
$guard$;

-- One bounded row per active actor/tenant/kind, NOT one row per attempt.
-- Windows reset IN-PLACE after expiry. A denied unknown-status lookup
-- commits its budget debit (see caller); otherwise 404/ROLLBACK would
-- silently erase abuse tracking. No JWT, IP, user payload or UUID is saved.
CREATE TABLE IF NOT EXISTS saas_rls_private.synthetic_operation_budgets (
 scope_kind TEXT NOT NULL CHECK(scope_kind IN ('actor','tenant')),
 tenant_id TEXT NOT NULL CHECK(tenant_id ~ '^[A-Za-z0-9_-]{1,64}$'),
 actor_id TEXT NOT NULL CHECK(actor_id='*' OR
   actor_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 action_kind TEXT NOT NULL CHECK(action_kind IN ('issue','status')),
 window_until TIMESTAMPTZ NOT NULL,
 used_count INTEGER NOT NULL CHECK(used_count BETWEEN 1 AND 64),
 PRIMARY KEY(scope_kind,tenant_id,actor_id,action_kind),
 CONSTRAINT tenant_bucket_sentinel CHECK(
   (scope_kind='tenant' AND actor_id='*')
   OR (scope_kind='actor' AND actor_id<>'*'))
);
ALTER TABLE saas_rls_private.synthetic_operation_budgets OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.synthetic_operation_budgets
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
      saas_mock_delivery_worker,saas_mock_receiver;

-- Bounded, atomic per-row UPSERT: concurrent invocations cannot exceed
-- either a principal budget or a shared tenant budget. Charge actor first;
-- even a tenant-denied status read pays one actor request, and commits.
CREATE OR REPLACE FUNCTION saas_rls_private.consume_synthetic_operation_budget(
 trusted_tenant TEXT, trusted_actor TEXT, budget_action TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE
 actor_limit INTEGER;
 tenant_limit INTEGER;
 seconds_per_window INTEGER;
 at_time TIMESTAMPTZ:=clock_timestamp();
 accepted INTEGER;
BEGIN
 IF trusted_tenant IS NULL OR trusted_actor IS NULL OR
    trusted_tenant !~ '^[A-Za-z0-9_-]{1,64}$' OR
    trusted_actor !~ '^[A-Za-z0-9_-]{1,128}$'
 THEN RETURN FALSE; END IF;
 IF budget_action='issue' THEN
   actor_limit:=4; tenant_limit:=16; seconds_per_window:=300;
 ELSIF budget_action='status' THEN
   actor_limit:=16; tenant_limit:=64; seconds_per_window:=60;
 ELSE RETURN FALSE; END IF;

 INSERT INTO saas_rls_private.synthetic_operation_budgets AS b
 (scope_kind,tenant_id,actor_id,action_kind,window_until,used_count)
 VALUES('actor',trusted_tenant,trusted_actor,budget_action,
   at_time+make_interval(secs=>seconds_per_window),1)
 ON CONFLICT(scope_kind,tenant_id,actor_id,action_kind)
 DO UPDATE SET
   window_until=CASE WHEN b.window_until<=at_time THEN
     EXCLUDED.window_until ELSE b.window_until END,
   used_count=CASE WHEN b.window_until<=at_time THEN
     1 ELSE b.used_count+1 END
 WHERE b.window_until<=at_time OR b.used_count<actor_limit
 RETURNING used_count INTO accepted;
 IF accepted IS NULL THEN RETURN FALSE; END IF;

 accepted:=NULL;
 INSERT INTO saas_rls_private.synthetic_operation_budgets AS b
 (scope_kind,tenant_id,actor_id,action_kind,window_until,used_count)
 VALUES('tenant',trusted_tenant,'*',budget_action,
   at_time+make_interval(secs=>seconds_per_window),1)
 ON CONFLICT(scope_kind,tenant_id,actor_id,action_kind)
 DO UPDATE SET
   window_until=CASE WHEN b.window_until<=at_time THEN
     EXCLUDED.window_until ELSE b.window_until END,
   used_count=CASE WHEN b.window_until<=at_time THEN
     1 ELSE b.used_count+1 END
 WHERE b.window_until<=at_time OR b.used_count<tenant_limit
 RETURNING used_count INTO accepted;
 RETURN accepted IS NOT NULL;
END
$fn$;
ALTER FUNCTION saas_rls_private.consume_synthetic_operation_budget(TEXT,TEXT,TEXT)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION
 saas_rls_private.consume_synthetic_operation_budget(TEXT,TEXT,TEXT)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
      saas_mock_delivery_worker,saas_mock_receiver;

-- This NEW fixed-template staging entrypoint wraps 016. The older 016 SQL
-- stays intact for legacy synthetic fixtures, NOT public network access.
-- Lifetime hard caps protect against endless append-only tombstone growth:
-- 48 issued UUIDs per tenant, 12 per actor/tenant in this disposable pilot.
-- Two actors from one tenant are serialized by the tenant advisory lock;
-- no check-then-insert race can overfill either cap.
CREATE OR REPLACE FUNCTION saas_rls.issue_signed_synthetic_operation_bounded(
 expected_tenant TEXT,expected_actor TEXT,expected_role TEXT,
 expected_collection TEXT,issued_operation UUID,
 requested_limit INTEGER,issue_ttl_seconds INTEGER
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE current_revision TEXT;
BEGIN
 IF issued_operation IS NULL OR requested_limit IS NULL OR
    requested_limit NOT BETWEEN 1 AND 100 OR issue_ttl_seconds IS NULL
    OR issue_ttl_seconds NOT BETWEEN 2 AND 600
 THEN RETURN FALSE; END IF;
 current_revision := saas_rls.acquire_authorized_read_barrier(
   expected_tenant,expected_actor,expected_role,expected_collection);
 IF current_revision IS NULL THEN RETURN FALSE; END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtextextended(expected_tenant,20261017));
 IF (SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues
      WHERE tenant_id=expected_tenant)>=48 OR
    (SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues
      WHERE tenant_id=expected_tenant AND actor_id=expected_actor)>=12
 THEN RETURN FALSE; END IF;
 IF NOT saas_rls_private.consume_synthetic_operation_budget(
   expected_tenant,expected_actor,'issue') THEN RETURN FALSE; END IF;
 RETURN saas_rls.issue_signed_synthetic_operation(
   expected_tenant,expected_actor,expected_role,expected_collection,
   issued_operation,requested_limit,issue_ttl_seconds);
END
$fn$;
ALTER FUNCTION saas_rls.issue_signed_synthetic_operation_bounded(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.issue_signed_synthetic_operation_bounded(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.issue_signed_synthetic_operation_bounded(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) TO saas_rls_reader;

-- Meter EVERY recognized, authenticated status request BEFORE private UUID
-- lookup, including guesses and foreign UUIDs. Return internal denial
-- sentinels instead of NULL so the trusted signed boundary can COMMIT
-- the counter and only THEN map both to the same generic 404 response.
-- NULL is reserved for a genuinely invalid signed PG authorization scope.
CREATE OR REPLACE FUNCTION saas_rls.read_signed_synthetic_operation_status_bounded(
 expected_tenant TEXT,expected_actor TEXT,expected_role TEXT,
 expected_collection TEXT,requested_operation UUID,
 requested_limit INTEGER
) RETURNS TEXT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE current_revision TEXT;
DECLARE observed_state TEXT;
BEGIN
 IF requested_operation IS NULL OR requested_limit IS NULL OR
    requested_limit NOT BETWEEN 1 AND 100 THEN RETURN NULL; END IF;
 current_revision := saas_rls.acquire_authorized_read_barrier(
   expected_tenant,expected_actor,expected_role,expected_collection);
 IF current_revision IS NULL THEN RETURN NULL; END IF;
 IF NOT saas_rls_private.consume_synthetic_operation_budget(
   expected_tenant,expected_actor,'status') THEN
   RETURN 'throttled';
 END IF;
 observed_state := saas_rls.read_signed_synthetic_operation_status(
   expected_tenant,expected_actor,expected_role,expected_collection,
   requested_operation,requested_limit);
 RETURN COALESCE(observed_state,'absent');
END
$fn$;
ALTER FUNCTION saas_rls.read_signed_synthetic_operation_status_bounded(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.read_signed_synthetic_operation_status_bounded(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.read_signed_synthetic_operation_status_bounded(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) TO saas_rls_reader;

DO $assert$
BEGIN
 IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 OR has_table_privilege('saas_rls_reader',
   'saas_rls_private.synthetic_operation_issues','DELETE')
 OR has_table_privilege('saas_rls_reader',
   'saas_rls_private.synthetic_operation_budgets','SELECT')
 OR has_table_privilege('saas_ci_runner',
   'saas_rls_private.synthetic_operation_budgets','UPDATE')
 OR has_table_privilege('saas_mock_receiver',
   'saas_rls_private.synthetic_operation_budgets','SELECT')
 OR has_function_privilege('saas_rls_reader',
   'saas_rls_private.consume_synthetic_operation_budget(text,text,text)','EXECUTE')
 OR has_function_privilege('saas_ci_runner',
   'saas_rls.issue_signed_synthetic_operation_bounded(text,text,text,text,uuid,integer,integer)','EXECUTE')
 OR has_function_privilege('saas_ci_runner',
   'saas_rls.read_signed_synthetic_operation_status_bounded(text,text,text,text,uuid,integer)','EXECUTE')
 OR NOT has_function_privilege('saas_rls_reader',
   'saas_rls.issue_signed_synthetic_operation_bounded(text,text,text,text,uuid,integer,integer)','EXECUTE')
 OR NOT has_function_privilege('saas_rls_reader',
   'saas_rls.read_signed_synthetic_operation_status_bounded(text,text,text,text,uuid,integer)','EXECUTE')
 THEN RAISE EXCEPTION 'Private synthetic operation quotas leaked to untrusted role'; END IF;
END
$assert$;
COMMIT;
\echo 'PASS: PG16 stage 017 private bounded issuer and denial-committing status quota'

-- Stage 2G.4d.7i: immutable operation retention safety + legacy SQL hard stops.
-- STRICT disposable PostgreSQL16. No archive/purge/deletion/real network.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test'
 OR current_user<>'postgres'
 OR current_setting('saas.staging_only',TRUE) IS DISTINCT FROM 'true'
 OR to_regclass('saas_rls_private.synthetic_operation_issues') IS NULL
 OR to_regclass('saas_rls_private.synthetic_producer_operations') IS NULL
 OR to_regclass('saas_rls_private.synthetic_operation_budgets') IS NULL
 OR to_regprocedure('saas_rls.issue_signed_synthetic_operation_bounded(text,text,text,text,uuid,integer,integer)') IS NULL
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
 AND NOT rolsuper AND NOT rolbypassrls)
 THEN RAISE EXCEPTION 'Refusing legacy producer hard stop outside disposable PG16'; END IF;
END
$guard$;

-- No new UUID is freed on expiry. Every 016/015 table insertion must
-- consult the SAME transaction-scoped tenant capacity lock, irrespective
-- of which public/legacy SQL function initiated it.
-- Mutable budget rows have fixed principal/action cardinality.
ALTER TABLE saas_rls_private.synthetic_operation_budgets
 DROP CONSTRAINT IF EXISTS synthetic_operation_budgets_action_kind_check;
ALTER TABLE saas_rls_private.synthetic_operation_budgets
 DROP CONSTRAINT IF EXISTS synthetic_operation_budgets_action_kinds_018;
ALTER TABLE saas_rls_private.synthetic_operation_budgets
 ADD CONSTRAINT synthetic_operation_budgets_action_kinds_018
 CHECK(action_kind IN ('issue','status','legacy_issue','legacy_status',
                      'raw_issue','producer_event'));

-- Preserve 017's in-place atomic UPSERT logic while widening its enum
-- to individual budgets for ALL successful insert paths and legacy reads.

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
 ELSIF budget_action='status' OR budget_action='legacy_status' THEN
   actor_limit:=16; tenant_limit:=64; seconds_per_window:=60;
 ELSIF budget_action='legacy_issue' THEN
   actor_limit:=8; tenant_limit:=32; seconds_per_window:=300;
 ELSIF budget_action='raw_issue' OR budget_action='producer_event' THEN
   actor_limit:=32; tenant_limit:=64; seconds_per_window:=300;
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

-- Copy the already-reviewed signed 015/016 core functions, without making
-- them callable by saas_rls_reader. 017 bounded and the legacy wrappers
-- use these PRIVATE, owner-only primitives (no recursive public chaining).

CREATE OR REPLACE FUNCTION saas_rls_private.record_signed_synthetic_operation_core(
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
ALTER FUNCTION saas_rls_private.record_signed_synthetic_operation_core(
 TEXT,TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.record_signed_synthetic_operation_core(
 TEXT,TEXT,TEXT,TEXT,TEXT,UUID,INTEGER)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
 saas_mock_delivery_worker,saas_mock_receiver;

CREATE OR REPLACE FUNCTION saas_rls_private.issue_signed_synthetic_operation_core(
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
ALTER FUNCTION saas_rls_private.issue_signed_synthetic_operation_core(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.issue_signed_synthetic_operation_core(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
 saas_mock_delivery_worker,saas_mock_receiver;

CREATE OR REPLACE FUNCTION saas_rls_private.read_signed_synthetic_operation_status_core(
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
          p.requested_limit=issue_row.requested_limit)
 THEN RETURN 'committed'; END IF;
 IF clock_timestamp()>=issue_row.issue_expires_at THEN
   RETURN 'expired'; END IF;
 RETURN 'issued';
END
$fn$;
ALTER FUNCTION saas_rls_private.read_signed_synthetic_operation_status_core(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.read_signed_synthetic_operation_status_core(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
 saas_mock_delivery_worker,saas_mock_receiver;

-- Public 017 opted-in functions now call the private 016 cores,
-- so legacy 016 wrappers can meter without recursion.

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
 RETURN saas_rls_private.issue_signed_synthetic_operation_core(
   expected_tenant,expected_actor,expected_role,expected_collection,
   issued_operation,requested_limit,issue_ttl_seconds);
END
$fn$;
ALTER FUNCTION saas_rls.issue_signed_synthetic_operation_bounded(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) OWNER TO saas_rls_owner;

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
 observed_state := saas_rls_private.read_signed_synthetic_operation_status_core(
   expected_tenant,expected_actor,expected_role,expected_collection,
   requested_operation,requested_limit);
 RETURN COALESCE(observed_state,'absent');
END
$fn$;
ALTER FUNCTION saas_rls.read_signed_synthetic_operation_status_bounded(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) OWNER TO saas_rls_owner;

-- Old 016 direct issuer cannot bypass rate limits. The legacy
-- quota is distinct from opted-in 017's stricter budget for CI
-- backwards compatibility, but every role-call is now bounded.
CREATE OR REPLACE FUNCTION saas_rls.issue_signed_synthetic_operation(
 expected_tenant TEXT,expected_actor TEXT,expected_role TEXT,
 expected_collection TEXT,issued_operation UUID,
 requested_limit INTEGER,issue_ttl_seconds INTEGER
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE authorized TEXT;
BEGIN
 IF issued_operation IS NULL OR requested_limit IS NULL
 OR requested_limit NOT BETWEEN 1 AND 100 OR issue_ttl_seconds IS NULL
 OR issue_ttl_seconds NOT BETWEEN 2 AND 600 THEN RETURN FALSE; END IF;
 authorized:=saas_rls.acquire_authorized_read_barrier(
   expected_tenant,expected_actor,expected_role,expected_collection);
 IF authorized IS NULL THEN RETURN FALSE; END IF;
 -- Make known lifetime exhaustion a stable FALSE, not a driver error.
 -- The common 018 INSERT trigger independently enforces this ceiling
 -- for all callers, including a privileged fixture that skips 017.
 PERFORM pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtextextended(expected_tenant,20261017));
 IF (SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues
     WHERE tenant_id=expected_tenant)>=48 OR
    (SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues
     WHERE tenant_id=expected_tenant AND actor_id=expected_actor)>=12
 THEN RETURN FALSE; END IF;
 IF NOT saas_rls_private.consume_synthetic_operation_budget(
   expected_tenant,expected_actor,'legacy_issue') THEN RETURN FALSE; END IF;
 RETURN saas_rls_private.issue_signed_synthetic_operation_core(
   expected_tenant,expected_actor,expected_role,expected_collection,
   issued_operation,requested_limit,issue_ttl_seconds);
END
$fn$;
ALTER FUNCTION saas_rls.issue_signed_synthetic_operation(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.issue_signed_synthetic_operation(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.issue_signed_synthetic_operation(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER,INTEGER) TO saas_rls_reader;

-- Legacy direct status is ALSO metered before lookup; unlike the
-- fixed 017 wire template it returns SQL NULL for all private
-- absent/throttled markers. With direct caller-controlled ROLLBACK
-- the debit can be erased: client raw SQL is NOT an authorized API.
CREATE OR REPLACE FUNCTION saas_rls.read_signed_synthetic_operation_status(
 expected_tenant TEXT,expected_actor TEXT,expected_role TEXT,
 expected_collection TEXT,requested_operation UUID,requested_limit INTEGER
) RETURNS TEXT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE authorized TEXT;
DECLARE state TEXT;
BEGIN
 IF requested_operation IS NULL OR requested_limit IS NULL
 OR requested_limit NOT BETWEEN 1 AND 100 THEN RETURN NULL; END IF;
 authorized:=saas_rls.acquire_authorized_read_barrier(
   expected_tenant,expected_actor,expected_role,expected_collection);
 IF authorized IS NULL THEN RETURN NULL; END IF;
 IF NOT saas_rls_private.consume_synthetic_operation_budget(
   expected_tenant,expected_actor,'legacy_status') THEN RETURN NULL; END IF;
 state:=saas_rls_private.read_signed_synthetic_operation_status_core(
   expected_tenant,expected_actor,expected_role,expected_collection,
   requested_operation,requested_limit);
 RETURN state;
END
$fn$;
ALTER FUNCTION saas_rls.read_signed_synthetic_operation_status(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.read_signed_synthetic_operation_status(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.read_signed_synthetic_operation_status(
 TEXT,TEXT,TEXT,TEXT,UUID,INTEGER) TO saas_rls_reader;

-- One SECURITY DEFINER BEFORE INSERT trigger is a common hard-stop for
-- both 015 producer commits and 016 issued IDs. Prevents direct caller
-- bypass of 017's short/lifetime caps.
-- CI admin fixture uses PostgreSQL postgres without SET ROLE to seed
-- bounded fake historical rows; a signed SET LOCAL ROLE or Bun ci_runner
-- always goes through the trigger's guard. postgres is omnipotent anyway.
CREATE OR REPLACE FUNCTION saas_rls_private.reject_synthetic_operation_overcapacity()
RETURNS TRIGGER
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE actor_cap INTEGER;
DECLARE tenant_cap INTEGER;
DECLARE budget_kind TEXT;
DECLARE lock_salt BIGINT;
BEGIN
 IF TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'Unexpected operation capacity trigger context';
 END IF;
 IF session_user='postgres'
  AND COALESCE(current_setting('role',TRUE),'none')='none'
 THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='synthetic_operation_issues' THEN
   actor_cap:=12; tenant_cap:=48; budget_kind:='raw_issue';
   lock_salt:=20261017;
 ELSIF TG_TABLE_NAME='synthetic_producer_operations' THEN
   actor_cap:=64; tenant_cap:=256; budget_kind:='producer_event';
   lock_salt:=20261018;
 ELSE
   RAISE EXCEPTION 'Unexpected producer retention table';
 END IF;

 PERFORM pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtextextended(NEW.tenant_id,lock_salt));
 IF TG_TABLE_NAME='synthetic_operation_issues' THEN
   IF (SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues
       WHERE tenant_id=NEW.tenant_id)>=tenant_cap
    OR (SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues
       WHERE tenant_id=NEW.tenant_id AND actor_id=NEW.actor_id)>=actor_cap
   THEN RAISE EXCEPTION 'Synthetic issuance lifetime limit'
        USING ERRCODE='check_violation'; END IF;
 ELSE
   IF (SELECT COUNT(*) FROM saas_rls_private.synthetic_producer_operations
       WHERE tenant_id=NEW.tenant_id)>=tenant_cap
    OR (SELECT COUNT(*) FROM saas_rls_private.synthetic_producer_operations
       WHERE tenant_id=NEW.tenant_id AND actor_id=NEW.actor_id)>=actor_cap
   THEN RAISE EXCEPTION 'Synthetic producer lifetime limit'
        USING ERRCODE='check_violation'; END IF;
 END IF;
 IF NOT saas_rls_private.consume_synthetic_operation_budget(
   NEW.tenant_id,NEW.actor_id,budget_kind) THEN
   RAISE EXCEPTION 'Synthetic producer insert budget exhausted'
     USING ERRCODE='check_violation';
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION saas_rls_private.reject_synthetic_operation_overcapacity()
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.reject_synthetic_operation_overcapacity()
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
 saas_mock_delivery_worker,saas_mock_receiver;
DROP TRIGGER IF EXISTS saas_018_issues_insert_limit
 ON saas_rls_private.synthetic_operation_issues;
CREATE TRIGGER saas_018_issues_insert_limit BEFORE INSERT
 ON saas_rls_private.synthetic_operation_issues FOR EACH ROW
 EXECUTE FUNCTION saas_rls_private.reject_synthetic_operation_overcapacity();
DROP TRIGGER IF EXISTS saas_018_producer_insert_limit
 ON saas_rls_private.synthetic_producer_operations;
CREATE TRIGGER saas_018_producer_insert_limit BEFORE INSERT
 ON saas_rls_private.synthetic_producer_operations FOR EACH ROW
 EXECUTE FUNCTION saas_rls_private.reject_synthetic_operation_overcapacity();

-- BEFORE UPDATE/DELETE already exist. TRUNCATE otherwise bypasses those
-- row triggers and would free all keys. Deny it at statement level.
DROP TRIGGER IF EXISTS saas_018_issues_no_truncate
 ON saas_rls_private.synthetic_operation_issues;
CREATE TRIGGER saas_018_issues_no_truncate BEFORE TRUNCATE
 ON saas_rls_private.synthetic_operation_issues FOR EACH STATEMENT
 EXECUTE FUNCTION saas_rls_private.reject_local_audit_mutation();
DROP TRIGGER IF EXISTS saas_018_producer_no_truncate
 ON saas_rls_private.synthetic_producer_operations;
CREATE TRIGGER saas_018_producer_no_truncate BEFORE TRUNCATE
 ON saas_rls_private.synthetic_producer_operations FOR EACH STATEMENT
 EXECUTE FUNCTION saas_rls_private.reject_local_audit_mutation();

-- PRIVATE non-destructive capacity/readiness inspection only. No UUIDs,
-- account data, event IDs, bearer claims, archive export or GC interface.
-- This is a snapshot from the SAME database, not external attestation.
CREATE OR REPLACE FUNCTION saas_rls_private.synthetic_operation_retention_health(
 inspected_tenant TEXT
) RETURNS TABLE(
 issued_total BIGINT,
 producer_total BIGINT,
 expired_issues BIGINT,
 issue_capacity_left BIGINT,
 producer_capacity_left BIGINT,
 gc_permitted BOOLEAN
)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
 SELECT
  (SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues i
    WHERE i.tenant_id=inspected_tenant),
  (SELECT COUNT(*) FROM saas_rls_private.synthetic_producer_operations p
    WHERE p.tenant_id=inspected_tenant),
  (SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues i
    WHERE i.tenant_id=inspected_tenant AND i.recovery_expires_at<=clock_timestamp()),
  GREATEST(0::BIGINT,48-(SELECT COUNT(*) FROM saas_rls_private.synthetic_operation_issues i
    WHERE i.tenant_id=inspected_tenant)),
  GREATEST(0::BIGINT,256-(SELECT COUNT(*) FROM saas_rls_private.synthetic_producer_operations p
    WHERE p.tenant_id=inspected_tenant)),
  FALSE
 WHERE inspected_tenant ~ '^[A-Za-z0-9_-]{1,64}$';
$fn$;
ALTER FUNCTION saas_rls_private.synthetic_operation_retention_health(TEXT)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION
 saas_rls_private.synthetic_operation_retention_health(TEXT)
 FROM PUBLIC,saas_rls_reader,saas_ci_runner,saas_audit_reconciler,
 saas_mock_delivery_worker,saas_mock_receiver;

DO $assert$
BEGIN
 IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 OR has_table_privilege('saas_rls_reader',
    'saas_rls_private.synthetic_operation_issues','DELETE')
 OR has_table_privilege('saas_rls_reader',
    'saas_rls_private.synthetic_producer_operations','TRUNCATE')
 OR has_function_privilege('saas_rls_reader',
    'saas_rls_private.issue_signed_synthetic_operation_core(text,text,text,text,uuid,integer,integer)','EXECUTE')
 OR has_function_privilege('saas_ci_runner',
    'saas_rls_private.read_signed_synthetic_operation_status_core(text,text,text,text,uuid,integer)','EXECUTE')
 OR has_function_privilege('saas_rls_reader',
    'saas_rls_private.synthetic_operation_retention_health(text)','EXECUTE')
 OR NOT has_function_privilege('saas_rls_reader',
    'saas_rls.issue_signed_synthetic_operation(text,text,text,text,uuid,integer,integer)','EXECUTE')
 OR NOT has_function_privilege('saas_rls_reader',
    'saas_rls.read_signed_synthetic_operation_status(text,text,text,text,uuid,integer)','EXECUTE')
 OR NOT EXISTS(SELECT 1 FROM pg_trigger
    WHERE tgrelid='saas_rls_private.synthetic_operation_issues'::regclass
    AND tgname='saas_018_issues_no_truncate' AND tgenabled='O')
 THEN RAISE EXCEPTION '018 retention hard stop or private SQL privilege missing'; END IF;
END
$assert$;
COMMIT;
echo 'PASS: 018 universal insert hard stops, metered legacy 016 SQL, immutable capacity report'

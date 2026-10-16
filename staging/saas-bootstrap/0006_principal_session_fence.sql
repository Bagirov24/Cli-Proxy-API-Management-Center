-- Backend14 / 0006: principal-bound, expiring, revocable DB session fence.
-- This is a staging-only SESSION REGISTRY, NOT a live OIDC verifier/API.
-- NO real login, bearer token, identity provider, tenant data or DB grant.
-- Session authorization relies on authenticated PostgreSQL session_user,
-- NEVER a client-supplied JWT claim / SET ROLE / writable session GUC.
-- Only reviewed one-shot non-superuser migrator after 0000..0005.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '20s';
SELECT pg_catalog.set_config('saas.b14.expected_0005', :'expected_0005_sha256', true);
SELECT pg_catalog.set_config('saas.b14.source_sha', :'migration_sha256', true);
SELECT pg_catalog.set_config('saas.b14.source_commit', :'source_commit', true);

DO $guard$
DECLARE
  attrs record;
  count_receipts integer;
  f record;
BEGIN
  IF current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR current_setting('transaction_read_only') <> 'off'
     OR pg_is_in_recovery()
     OR session_user <> 'saas_schema_migrator' THEN
    RAISE EXCEPTION 'Backend14 refused wrong PG16 migrator/database';
  END IF;
  SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
    INTO attrs FROM pg_catalog.pg_roles WHERE rolname=session_user;
  IF NOT FOUND OR attrs.rolsuper OR attrs.rolbypassrls OR attrs.rolcreaterole
     OR attrs.rolcreatedb OR attrs.rolreplication THEN
    RAISE EXCEPTION 'Backend14 refused privileged migrator';
  END IF;
  IF to_regclass('saas_bootstrap.schema_migrations') IS NULL
     OR to_regclass('saas_acl.principal_tenants') IS NULL
     OR to_regclass('saas_acl.principal_access_audit') IS NULL
     OR to_regnamespace('saas_identity') IS NOT NULL
     OR to_regprocedure('saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamp with time zone,text)') IS NOT NULL THEN
    RAISE EXCEPTION 'Backend14 missing prior objects or uncertain replay';
  END IF;
  SELECT count(*) INTO count_receipts FROM saas_bootstrap.schema_migrations;
  IF count_receipts <> 5
     OR NOT EXISTS (SELECT 1 FROM saas_bootstrap.schema_migrations
                    WHERE migration_id='0005_principal_lifecycle_revocation_fence'
                    AND source_sha256=current_setting('saas.b14.expected_0005',true))
     OR current_setting('saas.b14.expected_0005',true)
        IS DISTINCT FROM 'b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556'
     OR current_setting('saas.b14.source_sha',true) !~ '^[a-f0-9]{64}$'
     OR current_setting('saas.b14.source_commit',true) !~ '^[a-f0-9]{40}$' THEN
    RAISE EXCEPTION 'Backend14 untrusted migration ledger/digest';
  END IF;
  SELECT prosecdef,provolatile INTO f FROM pg_catalog.pg_proc
    WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure;
  IF NOT FOUND OR f.prosecdef IS DISTINCT FROM true OR f.provolatile <> 'v'
     OR (SELECT count(*) FROM pg_catalog.pg_policy
         WHERE polrelid IN ('saas_data.tenants'::regclass,
                            'saas_data.projects'::regclass)) <> 2
     OR (SELECT count(*) FROM pg_catalog.pg_class
         WHERE oid IN ('saas_data.tenants'::regclass,
                       'saas_data.projects'::regclass)
           AND relrowsecurity AND relforcerowsecurity) <> 2 THEN
    RAISE EXCEPTION 'Backend14 revoked scope fence / FORCE RLS not intact';
  END IF;
END
$guard$;

-- Entire schema stays private. No runtime principal may inspect sessions.
CREATE SCHEMA saas_identity AUTHORIZATION saas_schema_migrator;
REVOKE ALL ON SCHEMA saas_identity FROM PUBLIC;

CREATE TABLE saas_identity.principal_sessions (
  session_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  principal_name name NOT NULL,
  tenant_id uuid NOT NULL,
  grant_revision bigint NOT NULL CHECK (grant_revision > 0),
  -- Opaque operator-issued identity reference. NO user-subject/claims trusted.
  identity_binding_id uuid NOT NULL,
  session_revision bigint NOT NULL DEFAULT 1 CHECK (session_revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CONSTRAINT principal_session_acl_fk
    FOREIGN KEY (principal_name,tenant_id)
    REFERENCES saas_acl.principal_tenants(principal_name,tenant_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT session_revocation_after_creation
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
-- One unrevoked session per authenticated PostgreSQL LOGIN; no shared pool.
-- Expired records still require explicit revoke before a replacement is issued.
CREATE UNIQUE INDEX b14_single_unrevoked_login
  ON saas_identity.principal_sessions(principal_name)
  WHERE revoked_at IS NULL;
REVOKE ALL ON saas_identity.principal_sessions FROM PUBLIC;

CREATE TABLE saas_identity.session_events (
  event_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  session_id uuid NOT NULL,
  principal_name name NOT NULL,
  tenant_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('issued','revoked')),
  session_revision bigint NOT NULL CHECK (session_revision > 0),
  actor name NOT NULL,
  reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 8 AND 160),
  txid bigint NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(session_id,session_revision)
);
REVOKE ALL ON saas_identity.session_events FROM PUBLIC;

CREATE FUNCTION saas_identity.block_session_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $block$
BEGIN
  RAISE EXCEPTION 'Backend14 sessions/audit require revisioned operator command (not WORM)';
  RETURN NULL;
END
$block$;
REVOKE ALL ON FUNCTION saas_identity.block_session_mutation() FROM PUBLIC;

CREATE FUNCTION saas_identity.audit_session_transition()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $audit$
DECLARE
  reason text := current_setting('saas.b14.operator_reason',true);
  event_kind text;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'saas_schema_migrator'
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR reason IS NULL OR char_length(btrim(reason)) NOT BETWEEN 8 AND 160 THEN
    RAISE EXCEPTION 'Backend14 operator-only audit context refused';
  END IF;
  -- SECURITY DEFINER changes current_user to function owner: this is
  -- the reviewed non-LOGIN schema migrator; session_user stays postgres.
  IF TG_OP='INSERT' THEN
    IF NEW.session_revision <> 1 OR NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'Backend14 invalid session issuance';
    END IF;
    event_kind := 'issued';
  ELSIF TG_OP='UPDATE' THEN
    IF NEW.session_id IS DISTINCT FROM OLD.session_id
       OR NEW.principal_name IS DISTINCT FROM OLD.principal_name
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.grant_revision IS DISTINCT FROM OLD.grant_revision
       OR NEW.identity_binding_id IS DISTINCT FROM OLD.identity_binding_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR OLD.revoked_at IS NOT NULL
       OR NEW.revoked_at IS NULL
       OR NEW.session_revision <> OLD.session_revision+1 THEN
      RAISE EXCEPTION 'Backend14 invalid immutable session/CAS revocation';
    END IF;
    event_kind := 'revoked';
  ELSE
    RAISE EXCEPTION 'Backend14 DELETE is not a revoke';
  END IF;
  INSERT INTO saas_identity.session_events
    (session_id,principal_name,tenant_id,kind,session_revision,actor,reason,txid)
  VALUES (NEW.session_id,NEW.principal_name,NEW.tenant_id,event_kind,
          NEW.session_revision,session_user::name,reason,pg_catalog.txid_current());
  RETURN NEW;
END
$audit$;
REVOKE ALL ON FUNCTION saas_identity.audit_session_transition() FROM PUBLIC;
CREATE TRIGGER b14_session_change_audit
  BEFORE INSERT OR UPDATE ON saas_identity.principal_sessions
  FOR EACH ROW EXECUTE FUNCTION saas_identity.audit_session_transition();
CREATE TRIGGER b14_session_block_delete
  BEFORE DELETE ON saas_identity.principal_sessions
  FOR EACH ROW EXECUTE FUNCTION saas_identity.block_session_mutation();
CREATE TRIGGER b14_session_block_truncate
  BEFORE TRUNCATE ON saas_identity.principal_sessions
  FOR EACH STATEMENT EXECUTE FUNCTION saas_identity.block_session_mutation();
CREATE TRIGGER b14_events_block_changes
  BEFORE UPDATE OR DELETE ON saas_identity.session_events
  FOR EACH ROW EXECUTE FUNCTION saas_identity.block_session_mutation();
CREATE TRIGGER b14_events_block_truncate
  BEFORE TRUNCATE ON saas_identity.session_events
  FOR EACH STATEMENT EXECUTE FUNCTION saas_identity.block_session_mutation();

-- Only PostgreSQL isolated operator can issue a short-lived session.
-- The identity_binding_id is NOT proof of verified OIDC; the trusted OIDC
-- enrollment service must be built, reviewed and attached separately.
-- No application runtime has EXECUTE or even schema USAGE.
CREATE FUNCTION saas_identity.issue_principal_session(
  p_principal name, p_tenant uuid, p_expected_grant_revision bigint,
  p_identity_binding_id uuid, p_expires_at timestamptz, p_reason text)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $issue$
DECLARE
  access record;
  session_value uuid;
  current_time timestamptz := clock_timestamp();
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres'
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR p_principal IS NULL OR p_tenant IS NULL
     OR p_expected_grant_revision IS NULL OR p_expected_grant_revision < 1
     OR p_identity_binding_id IS NULL
     OR p_expires_at IS NULL OR p_expires_at <= current_time
     OR p_expires_at > current_time + interval '15 minutes'
     OR p_reason IS NULL OR char_length(btrim(p_reason)) NOT BETWEEN 8 AND 160 THEN
    RAISE EXCEPTION 'Backend14 refused untrusted or expired session request';
  END IF;
  SELECT x.access_revision,x.access_level
    INTO access FROM saas_acl.principal_tenants x
    WHERE x.principal_name=p_principal AND x.tenant_id=p_tenant
      AND x.access_revision=p_expected_grant_revision
      AND x.access_level IN ('reader','writer')
    FOR SHARE;
  IF NOT FOUND OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles r
    WHERE r.rolname=p_principal::text AND r.rolcanlogin
      AND NOT r.rolsuper AND NOT r.rolbypassrls
      AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles role ON role.oid=m.roleid
    JOIN pg_catalog.pg_roles member ON member.oid=m.member
    WHERE member.rolname=p_principal::text AND
      role.rolname=CASE access.access_level
        WHEN 'reader' THEN 'saas_runtime_reader' ELSE 'saas_runtime_writer' END
  ) THEN
    RAISE EXCEPTION 'Backend14 principal lacks approved exact tenant membership';
  END IF;
  PERFORM pg_catalog.set_config('saas.b14.operator_reason',p_reason,true);
  INSERT INTO saas_identity.principal_sessions
    (principal_name,tenant_id,grant_revision,identity_binding_id,expires_at)
  VALUES (p_principal,p_tenant,p_expected_grant_revision,p_identity_binding_id,p_expires_at)
  RETURNING session_id INTO session_value;
  RETURN session_value;
END
$issue$;
REVOKE ALL ON FUNCTION saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)
  FROM PUBLIC;

CREATE FUNCTION saas_identity.revoke_principal_session(
  p_session_id uuid, p_expected_revision bigint, p_reason text)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $revoke$
DECLARE
  new_revision bigint;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres'
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR p_session_id IS NULL OR p_expected_revision IS NULL
     OR p_expected_revision < 1
     OR p_reason IS NULL OR char_length(btrim(p_reason)) NOT BETWEEN 8 AND 160 THEN
    RAISE EXCEPTION 'Backend14 refused untrusted revoke';
  END IF;
  PERFORM pg_catalog.set_config('saas.b14.operator_reason',p_reason,true);
  UPDATE saas_identity.principal_sessions
    SET revoked_at=clock_timestamp(),session_revision=session_revision+1
    WHERE session_id=p_session_id AND session_revision=p_expected_revision
      AND revoked_at IS NULL
    RETURNING session_revision INTO new_revision;
  IF new_revision IS NULL THEN
    RAISE EXCEPTION 'Backend14 stale or already revoked session; no retry';
  END IF;
  RETURN new_revision;
END
$revoke$;
REVOKE ALL ON FUNCTION saas_identity.revoke_principal_session(uuid,bigint,text)
  FROM PUBLIC;

-- Extend the existing secure RLS predicate, keeping authenticated DB
-- session_user and ACL FOR SHARE. Explicit second FOR SHARE on the session
-- means a successful operator session revoke cannot pass an in-flight reader
-- transaction. No auth on an untrusted bearer, tenant GUC or SET ROLE.
CREATE OR REPLACE FUNCTION saas_acl.can_read_tenant(subject_tenant uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fenced$
DECLARE
  approved_revision bigint;
  active_session uuid;
BEGIN
  IF subject_tenant IS NULL
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR session_user IN ('postgres','saas_schema_migrator')
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_roles r
       WHERE r.rolname=session_user AND r.rolcanlogin
         AND NOT r.rolsuper AND NOT r.rolbypassrls
         AND NOT r.rolcreaterole AND NOT r.rolcreatedb
     ) THEN
    RETURN false;
  END IF;
  SELECT x.access_revision INTO approved_revision
    FROM saas_acl.principal_tenants x
    WHERE x.principal_name=session_user::name
      AND x.tenant_id=subject_tenant
      AND x.access_level IN ('reader','writer')
    FOR SHARE;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  SELECT s.session_id INTO active_session
    FROM saas_identity.principal_sessions s
    WHERE s.principal_name=session_user::name
      AND s.tenant_id=subject_tenant
      AND s.grant_revision=approved_revision
      AND s.revoked_at IS NULL
      AND s.expires_at>clock_timestamp()
    FOR SHARE;
  RETURN FOUND;
END
$fenced$;
REVOKE ALL ON FUNCTION saas_acl.can_read_tenant(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_acl.can_read_tenant(uuid)
  TO saas_runtime_reader,saas_runtime_writer;
REVOKE ALL ON ALL TABLES IN SCHEMA saas_identity FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA saas_identity FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE saas_schema_migrator
  IN SCHEMA saas_identity REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE saas_schema_migrator
  IN SCHEMA saas_identity REVOKE ALL ON TABLES FROM PUBLIC;

-- Atomic receipt. UNKNOWN COMMIT => manual reconciliation, not retry.
INSERT INTO saas_bootstrap.schema_migrations
  (migration_id,source_sha256,source_commit)
VALUES ('0006_principal_session_fence', :'migration_sha256', :'source_commit');
COMMIT;

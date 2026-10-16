-- Backend13 / 0005: CAS principal grant/revoke tombstones, transaction-atomic
-- non-WORM audit, and a row-lock revocation fence for READ-ONLY tenant RLS.
-- PostgreSQL16 isolated SaaS staging / disposable CI ONLY.
-- No LOGIN users, credentials, actual grants, customer data or HTTP API.
-- MUST NOT retry following an ambiguous COMMIT.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '4s';
SET LOCAL statement_timeout = '20s';

-- Substitute only SHA/commit hex outside DO dollar-quoted bodies.
SELECT pg_catalog.set_config('saas.b13.expected_0004', :'expected_0004_sha256', true);
SELECT pg_catalog.set_config('saas.b13.source_sha', :'migration_sha256', true);
SELECT pg_catalog.set_config('saas.b13.source_commit', :'source_commit', true);

DO $guard$
DECLARE
  migrator record;
  n int;
  acl_owner name;
BEGIN
  IF current_setting('server_version_num')::int NOT BETWEEN 160000 AND 169999
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR pg_is_in_recovery() OR current_setting('transaction_read_only') <> 'off'
     OR session_user <> 'saas_schema_migrator' THEN
    RAISE EXCEPTION 'Backend13 requires isolated PG16 schema migrator';
  END IF;
  SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
    INTO migrator FROM pg_catalog.pg_roles WHERE rolname=session_user;
  IF NOT FOUND OR migrator.rolsuper OR migrator.rolbypassrls
     OR migrator.rolcreaterole OR migrator.rolcreatedb OR migrator.rolreplication THEN
    RAISE EXCEPTION 'Backend13 refused privileged migrator';
  END IF;
  IF to_regclass('saas_bootstrap.schema_migrations') IS NULL
     OR to_regclass('saas_acl.principal_tenants') IS NULL
     OR to_regclass('saas_data.tenants') IS NULL
     OR to_regclass('saas_data.projects') IS NULL
     OR to_regclass('saas_acl.principal_access_audit') IS NOT NULL
     OR to_regprocedure('saas_acl.change_principal_access(name,uuid,bigint,text,text)') IS NOT NULL THEN
    RAISE EXCEPTION 'Backend13 missing baseline or attempted replay';
  END IF;
  SELECT count(*) INTO n FROM saas_bootstrap.schema_migrations;
  IF n <> 4
     OR NOT EXISTS (
       SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id='0001_ledger_only'
         AND source_sha256='7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279')
     OR NOT EXISTS (
       SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id='0002_tenant_projects_baseline'
         AND source_sha256='80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f')
     OR NOT EXISTS (
       SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id='0003_operator_runtime_roles'
         AND source_sha256='8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e')
     OR NOT EXISTS (
       SELECT 1 FROM saas_bootstrap.schema_migrations
       WHERE migration_id='0004_principal_bound_read_rls'
         AND source_sha256=current_setting('saas.b13.expected_0004',true))
     OR current_setting('saas.b13.expected_0004',true) !~ '^[a-f0-9]{64}$'
     OR current_setting('saas.b13.source_sha',true) !~ '^[a-f0-9]{64}$'
     OR current_setting('saas.b13.source_commit',true) !~ '^[a-f0-9]{40}$' THEN
    RAISE EXCEPTION 'Backend13 prior migration ledger mismatch';
  END IF;
  SELECT pg_get_userbyid(nspowner) INTO acl_owner FROM pg_catalog.pg_namespace
    WHERE nspname='saas_acl';
  IF acl_owner IS DISTINCT FROM 'saas_schema_migrator'
     OR (SELECT count(*) FROM saas_acl.principal_tenants) <> 0
     OR (SELECT count(*) FROM saas_data.tenants) <> 0
     OR (SELECT count(*) FROM saas_data.projects) <> 0
     OR (SELECT count(*) FROM pg_catalog.pg_policy
         WHERE polrelid IN ('saas_data.tenants'::regclass,
                            'saas_data.projects'::regclass)) <> 2
     OR (SELECT count(*) FROM pg_catalog.pg_class
         WHERE oid IN ('saas_data.tenants'::regclass,
                       'saas_data.projects'::regclass)
           AND relrowsecurity AND relforcerowsecurity) <> 2 THEN
    RAISE EXCEPTION 'Backend13 baseline not empty, FORCE RLS missing or ACL ownership wrong';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members
    WHERE roleid IN (SELECT oid FROM pg_catalog.pg_roles
                     WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer'))
  ) OR (SELECT count(*) FROM pg_catalog.pg_roles
        WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer')
          AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
          AND NOT rolcreaterole AND NOT rolcreatedb) <> 2 THEN
    RAISE EXCEPTION 'Backend13 runtime memberships/roles require investigation';
  END IF;
END
$guard$;

-- The principal map becomes tombstone-versioned: DELETE is NEVER an
-- acceptable revoke. A regrant must CAS against the last revoked revision.
ALTER TABLE saas_acl.principal_tenants
  ADD COLUMN access_revision bigint NOT NULL DEFAULT 1 CHECK (access_revision > 0);
ALTER TABLE saas_acl.principal_tenants
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE saas_acl.principal_tenants
  DROP CONSTRAINT principal_tenants_access_level_check;
ALTER TABLE saas_acl.principal_tenants
  ADD CONSTRAINT principal_tenants_access_level_check
  CHECK (access_level IN ('reader','writer','revoked'));
CREATE UNIQUE INDEX principal_one_active_tenant_idx
  ON saas_acl.principal_tenants(principal_name)
  WHERE access_level IN ('reader','writer');

-- Transaction-atomic, operator-only audit. NOT WORM: a PostgreSQL superuser
-- could disable triggers or rewrite the DB. No live tenant identities exist.
CREATE TABLE saas_acl.principal_access_audit (
  event_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  principal_name name NOT NULL,
  tenant_id uuid NOT NULL,
  old_access text,
  new_access text NOT NULL CHECK (new_access IN ('reader','writer','revoked')),
  revision bigint NOT NULL CHECK (revision > 0),
  operator_login name NOT NULL,
  reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 8 AND 160),
  txid bigint NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(principal_name,tenant_id,revision)
);
REVOKE ALL ON saas_acl.principal_access_audit FROM PUBLIC;
REVOKE ALL ON saas_acl.principal_access_audit
  FROM saas_runtime_reader, saas_runtime_writer;

CREATE FUNCTION saas_acl.deny_audit_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $block$
BEGIN
  RAISE EXCEPTION 'Backend13 operator audit is append-only (not WORM)';
  RETURN NULL;
END
$block$;
REVOKE ALL ON FUNCTION saas_acl.deny_audit_mutation() FROM PUBLIC;
CREATE TRIGGER b13_audit_no_update_delete
  BEFORE UPDATE OR DELETE ON saas_acl.principal_access_audit
  FOR EACH ROW EXECUTE FUNCTION saas_acl.deny_audit_mutation();
CREATE TRIGGER b13_audit_no_truncate
  BEFORE TRUNCATE ON saas_acl.principal_access_audit
  FOR EACH STATEMENT EXECUTE FUNCTION saas_acl.deny_audit_mutation();

CREATE FUNCTION saas_acl.audit_principal_transition()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $record$
DECLARE
  reason text := current_setting('saas.b13.operator_reason',true);
BEGIN
  IF session_user <> 'postgres'
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR reason IS NULL
     OR char_length(btrim(reason)) NOT BETWEEN 8 AND 160 THEN
    RAISE EXCEPTION 'Backend13 principal mutation requires reviewed operator context';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Backend13 must revoke using a revisioned tombstone';
  END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.access_revision <> 1 OR NEW.access_level='revoked' THEN
      RAISE EXCEPTION 'Backend13 invalid initial grant';
    END IF;
    INSERT INTO saas_acl.principal_access_audit
      (principal_name,tenant_id,old_access,new_access,revision,
       operator_login,reason,txid)
    VALUES (NEW.principal_name,NEW.tenant_id,NULL,NEW.access_level,1,
            session_user::name,reason,pg_catalog.txid_current());
  ELSIF TG_OP='UPDATE' THEN
    IF NEW.principal_name IS DISTINCT FROM OLD.principal_name
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.access_revision <> OLD.access_revision + 1
       OR NEW.access_level IS NOT DISTINCT FROM OLD.access_level
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'Backend13 invalid principal CAS transition';
    END IF;
    INSERT INTO saas_acl.principal_access_audit
      (principal_name,tenant_id,old_access,new_access,revision,
       operator_login,reason,txid)
    VALUES (NEW.principal_name,NEW.tenant_id,OLD.access_level,NEW.access_level,
            NEW.access_revision,session_user::name,reason,pg_catalog.txid_current());
  END IF;
  RETURN NEW;
END
$record$;
REVOKE ALL ON FUNCTION saas_acl.audit_principal_transition() FROM PUBLIC;
CREATE TRIGGER b13_principal_cas_audit
  BEFORE INSERT OR UPDATE OR DELETE ON saas_acl.principal_tenants
  FOR EACH ROW EXECUTE FUNCTION saas_acl.audit_principal_transition();
CREATE TRIGGER b13_principal_no_truncate
  BEFORE TRUNCATE ON saas_acl.principal_tenants
  FOR EACH STATEMENT EXECUTE FUNCTION saas_acl.deny_audit_mutation();

-- Staging-only operator command. SECURITY INVOKER, never grant EXECUTE to
-- tenant login or runtime template. version=0 means first-ever grant.
-- revoked rows persist and monotonic CAS prevents revoked->grant ABA.
CREATE FUNCTION saas_acl.change_principal_access(
  p_principal name, p_tenant uuid, p_expected_revision bigint,
  p_next text, p_reason text)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $change$
DECLARE
  account record;
  next_revision bigint;
  required_role text;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres'
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR current_setting('server_version_num')::int NOT BETWEEN 160000 AND 169999
     OR p_principal IS NULL OR p_tenant IS NULL
     OR p_expected_revision IS NULL OR p_expected_revision < 0
     OR p_next IS NULL OR p_next NOT IN ('reader','writer','revoked')
     OR p_reason IS NULL OR char_length(btrim(p_reason)) NOT BETWEEN 8 AND 160 THEN
    RAISE EXCEPTION 'Backend13 untrusted principal change';
  END IF;
  IF p_next <> 'revoked' THEN
    SELECT oid,rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,
           rolcreatedb,rolreplication
      INTO account FROM pg_catalog.pg_roles WHERE rolname=p_principal::text;
    IF NOT FOUND OR NOT account.rolcanlogin OR account.rolsuper
       OR account.rolbypassrls OR account.rolcreaterole
       OR account.rolcreatedb OR account.rolreplication THEN
      RAISE EXCEPTION 'Backend13 principal is not a restricted DB login';
    END IF;
    required_role := CASE p_next WHEN 'writer' THEN 'saas_runtime_writer'
                                ELSE 'saas_runtime_reader' END;
    IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_auth_members am
      JOIN pg_catalog.pg_roles r ON r.oid=am.roleid
      WHERE am.member=account.oid AND r.rolname=required_role
    ) OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_auth_members am
      WHERE am.member=account.oid
        AND am.roleid NOT IN (SELECT oid FROM pg_catalog.pg_roles
                             WHERE rolname IN ('saas_runtime_reader',
                                               'saas_runtime_writer'))
    ) THEN
      RAISE EXCEPTION 'Backend13 missing approved template or extra role membership';
    END IF;
  END IF;
  PERFORM pg_catalog.set_config('saas.b13.operator_reason',p_reason,true);
  IF p_expected_revision = 0 THEN
    IF p_next='revoked' THEN
      RAISE EXCEPTION 'Backend13 cannot revoke a never-granted principal';
    END IF;
    INSERT INTO saas_acl.principal_tenants
      (principal_name,tenant_id,access_level,access_revision)
    VALUES (p_principal,p_tenant,p_next,1)
    ON CONFLICT DO NOTHING RETURNING access_revision INTO next_revision;
  ELSE
    UPDATE saas_acl.principal_tenants
       SET access_level=p_next,access_revision=access_revision+1,
           updated_at=clock_timestamp()
     WHERE principal_name=p_principal AND tenant_id=p_tenant
       AND access_revision=p_expected_revision
       AND access_level IS DISTINCT FROM p_next
    RETURNING access_revision INTO next_revision;
  END IF;
  IF next_revision IS NULL THEN
    RAISE EXCEPTION 'Backend13 stale revision, duplicate/parallel grant or tenant conflict';
  END IF;
  RETURN next_revision;
END
$change$;
REVOKE ALL ON FUNCTION saas_acl.change_principal_access(name,uuid,bigint,text,text)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION saas_acl.change_principal_access(name,uuid,bigint,text,text)
  FROM saas_runtime_reader,saas_runtime_writer;

-- CRITICAL: VOLATILE snapshot + FOR SHARE row-lock on the ACTIVE grant.
-- Any revoke/update requires a conflicting row lock and therefore cannot
-- ACK COMMIT while a reader holds the prior grant lock in an open transaction.
-- RR/SERIALIZABLE stale reads get a serialization error after revoke, not rows.
CREATE OR REPLACE FUNCTION saas_acl.can_read_tenant(subject_tenant uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fenced$
DECLARE
  permitted uuid;
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
  SELECT x.tenant_id INTO permitted
    FROM saas_acl.principal_tenants x
   WHERE x.principal_name=session_user::name
     AND x.tenant_id=subject_tenant
     AND x.access_level IN ('reader','writer')
   FOR SHARE;
  RETURN FOUND;
END
$fenced$;
REVOKE ALL ON FUNCTION saas_acl.can_read_tenant(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_acl.can_read_tenant(uuid)
  TO saas_runtime_reader,saas_runtime_writer;

INSERT INTO saas_bootstrap.schema_migrations
  (migration_id,source_sha256,source_commit)
VALUES ('0005_principal_lifecycle_revocation_fence',
        :'migration_sha256', :'source_commit');
COMMIT;

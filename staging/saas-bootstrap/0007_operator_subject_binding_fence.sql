-- Backend15 / 0007: operator-enrolled issuer+subject fingerprint boundary.
-- Isolated PG16 staging and disposable GitHub PG16 only.
-- NOT an OIDC verifier, login provider, public API or runtime privilege grant.
-- No identities/bearers/OAuth tokens are inserted by this migration.
-- The operator MUST independently verify issuer/sub; a 64-hex digest alone
-- cannot attest a signed token or authorize a tenant.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '3s';
-- Only public source attestations: psql does not interpolate inside DO.
SELECT pg_catalog.set_config('saas.b15.expected_0006', :'expected_0006_sha256', true);
SELECT pg_catalog.set_config('saas.b15.source_sha', :'migration_sha256', true);
SELECT pg_catalog.set_config('saas.b15.source_commit', :'source_commit', true);

DO $guard$
DECLARE
  migrator record;
  n integer;
  r record;
BEGIN
  IF current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR current_setting('transaction_read_only') <> 'off'
     OR pg_is_in_recovery()
     OR session_user <> 'saas_schema_migrator' THEN
    RAISE EXCEPTION 'Backend15 refused non-staging PG16 migrator';
  END IF;
  SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
    INTO migrator FROM pg_catalog.pg_roles WHERE rolname=session_user;
  IF NOT FOUND OR migrator.rolsuper OR migrator.rolbypassrls OR
     migrator.rolcreaterole OR migrator.rolcreatedb OR migrator.rolreplication THEN
    RAISE EXCEPTION 'Backend15 refused privileged migration login';
  END IF;
  IF to_regclass('saas_bootstrap.schema_migrations') IS NULL
     OR to_regclass('saas_acl.principal_tenants') IS NULL
     OR to_regclass('saas_identity.principal_sessions') IS NULL
     OR to_regclass('saas_identity.session_events') IS NULL
     OR to_regclass('saas_identity.subject_bindings') IS NOT NULL
     OR to_regprocedure('saas_identity.register_subject_binding(name,uuid,bigint,text,text)') IS NOT NULL THEN
    RAISE EXCEPTION 'Backend15 missing schema or ambiguous replay';
  END IF;
  SELECT count(*) INTO n FROM saas_bootstrap.schema_migrations;
  IF n <> 6 OR NOT EXISTS (
      SELECT 1 FROM saas_bootstrap.schema_migrations
      WHERE migration_id='0006_principal_session_fence'
        AND source_sha256=current_setting('saas.b15.expected_0006',true))
     OR current_setting('saas.b15.expected_0006',true) IS DISTINCT FROM
        'b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505'
     OR current_setting('saas.b15.source_sha',true) !~ '^[a-f0-9]{64}$'
     OR current_setting('saas.b15.source_commit',true) !~ '^[a-f0-9]{40}$' THEN
    RAISE EXCEPTION 'Backend15 untrusted prior receipt/source hash';
  END IF;
  SELECT prosecdef,provolatile INTO r FROM pg_catalog.pg_proc
    WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure;
  IF NOT FOUND OR r.prosecdef IS DISTINCT FROM true OR r.provolatile <> 'v'
     OR (SELECT count(*) FROM pg_catalog.pg_policy
         WHERE polrelid IN ('saas_data.tenants'::regclass,
                            'saas_data.projects'::regclass)) <> 2
     OR (SELECT count(*) FROM pg_catalog.pg_class
         WHERE oid IN ('saas_data.tenants'::regclass,
                       'saas_data.projects'::regclass)
           AND relrowsecurity AND relforcerowsecurity) <> 2 THEN
    RAISE EXCEPTION 'Backend15 RLS/grant baseline unexpectedly changed';
  END IF;
  -- Historical synthetic CI sessions may exist; migration makes every one
  -- deny-all until separately operator-enrolled with its own binding ID.
END
$guard$;

-- SHA-256 of UTF-8: "saas:issuer-subject:v1" || NUL || pinned issuer
-- || NUL || verified subject. The server computes it ONLY after JWT verification.
-- The DB enforces cardinality, scope/revision, no reuse, and revocation;
-- PostgreSQL alone does NOT verify that any issuer or signature is legitimate.
CREATE TABLE saas_identity.subject_bindings (
  binding_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  principal_name name NOT NULL,
  tenant_id uuid NOT NULL,
  grant_revision bigint NOT NULL CHECK (grant_revision > 0),
  subject_fingerprint text NOT NULL UNIQUE
    CHECK (subject_fingerprint ~ '^[a-f0-9]{64}$'),
  binding_revision bigint NOT NULL DEFAULT 1 CHECK (binding_revision > 0),
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','revoked')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  FOREIGN KEY (principal_name,tenant_id)
    REFERENCES saas_acl.principal_tenants(principal_name,tenant_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT b15_revoke_marker
    CHECK ((status='active' AND revoked_at IS NULL) OR
           (status='revoked' AND revoked_at IS NOT NULL
            AND revoked_at>=created_at))
);
-- One active issuer/subject per DB login, never multiplex HTTP tenants.
CREATE UNIQUE INDEX b15_one_active_subject_per_login
  ON saas_identity.subject_bindings(principal_name)
  WHERE status='active';
-- Rebinding a revoked subject to a different principal is never automatic.
REVOKE ALL ON saas_identity.subject_bindings FROM PUBLIC;
REVOKE ALL ON saas_identity.subject_bindings
  FROM saas_runtime_reader,saas_runtime_writer;

CREATE TABLE saas_identity.subject_binding_events (
  event_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  binding_id uuid NOT NULL REFERENCES saas_identity.subject_bindings(binding_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  principal_name name NOT NULL,
  tenant_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('enrolled','revoked')),
  binding_revision bigint NOT NULL CHECK (binding_revision > 0),
  operator_login name NOT NULL,
  reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 8 AND 160),
  txid bigint NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(binding_id,binding_revision)
);
REVOKE ALL ON saas_identity.subject_binding_events FROM PUBLIC;
REVOKE ALL ON saas_identity.subject_binding_events
  FROM saas_runtime_reader,saas_runtime_writer;

-- Trigger uses private reason only as an audit annotation, NEVER AuthZ.
CREATE FUNCTION saas_identity.audit_subject_binding_transition()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $audit$
DECLARE
  reason text := current_setting('saas.b15.operator_reason',true);
  kind_value text;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'saas_schema_migrator'
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR reason IS NULL OR char_length(btrim(reason)) NOT BETWEEN 8 AND 160 THEN
    RAISE EXCEPTION 'Backend15 operator audit context refused';
  END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.binding_revision <> 1 OR NEW.status <> 'active'
       OR NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'Backend15 invalid initial binding';
    END IF;
    kind_value := 'enrolled';
  ELSIF TG_OP='UPDATE' THEN
    IF NEW.binding_id IS DISTINCT FROM OLD.binding_id
       OR NEW.principal_name IS DISTINCT FROM OLD.principal_name
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.grant_revision IS DISTINCT FROM OLD.grant_revision
       OR NEW.subject_fingerprint IS DISTINCT FROM OLD.subject_fingerprint
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.status <> 'active' OR NEW.status <> 'revoked'
       OR NEW.binding_revision <> OLD.binding_revision+1
       OR NEW.revoked_at IS NULL THEN
      RAISE EXCEPTION 'Backend15 immutable subject or CAS violation';
    END IF;
    kind_value := 'revoked';
  ELSE
    RAISE EXCEPTION 'Backend15 binding DELETE denied';
  END IF;
  INSERT INTO saas_identity.subject_binding_events
    (binding_id,principal_name,tenant_id,kind,binding_revision,
     operator_login,reason,txid)
  VALUES (NEW.binding_id,NEW.principal_name,NEW.tenant_id,kind_value,
          NEW.binding_revision,session_user::name,reason,pg_catalog.txid_current());
  RETURN NEW;
END
$audit$;
REVOKE ALL ON FUNCTION saas_identity.audit_subject_binding_transition() FROM PUBLIC;
-- AFTER row creation: the audit event has a strict FK to binding_id.
CREATE TRIGGER b15_binding_audit
  AFTER INSERT OR UPDATE ON saas_identity.subject_bindings
  FOR EACH ROW EXECUTE FUNCTION saas_identity.audit_subject_binding_transition();
CREATE TRIGGER b15_binding_no_delete
  BEFORE DELETE ON saas_identity.subject_bindings
  FOR EACH ROW EXECUTE FUNCTION saas_identity.block_session_mutation();
CREATE TRIGGER b15_binding_no_truncate
  BEFORE TRUNCATE ON saas_identity.subject_bindings
  FOR EACH STATEMENT EXECUTE FUNCTION saas_identity.block_session_mutation();
CREATE TRIGGER b15_binding_events_no_change
  BEFORE UPDATE OR DELETE ON saas_identity.subject_binding_events
  FOR EACH ROW EXECUTE FUNCTION saas_identity.block_session_mutation();
CREATE TRIGGER b15_binding_events_no_truncate
  BEFORE TRUNCATE ON saas_identity.subject_binding_events
  FOR EACH STATEMENT EXECUTE FUNCTION saas_identity.block_session_mutation();

-- Operator-only, SECURITY INVOKER. The operator is separately responsible
-- for cryptographically verifying and pinning issuer/subject before hashing.
CREATE FUNCTION saas_identity.register_subject_binding(
  p_principal name, p_tenant uuid, p_grant_revision bigint,
  p_subject_fingerprint text, p_reason text)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $register$
DECLARE
  subject_binding_id uuid;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres'
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR p_principal IS NULL OR p_tenant IS NULL
     OR p_grant_revision IS NULL OR p_grant_revision < 1
     OR p_subject_fingerprint IS NULL
     OR p_subject_fingerprint !~ '^[a-f0-9]{64}$'
     OR p_reason IS NULL OR char_length(btrim(p_reason)) NOT BETWEEN 8 AND 160 THEN
    RAISE EXCEPTION 'Backend15 untrusted identity enrollment';
  END IF;
  PERFORM 1 FROM saas_acl.principal_tenants a
    WHERE a.principal_name=p_principal AND a.tenant_id=p_tenant
      AND a.access_revision=p_grant_revision
      AND a.access_level IN ('reader','writer')
    FOR SHARE;
  IF NOT FOUND OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=p_principal::text
      AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
      AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication
  ) THEN
    RAISE EXCEPTION 'Backend15 principal/grant is not approved';
  END IF;
  PERFORM pg_catalog.set_config('saas.b15.operator_reason',p_reason,true);
  INSERT INTO saas_identity.subject_bindings
    (principal_name,tenant_id,grant_revision,subject_fingerprint)
  VALUES (p_principal,p_tenant,p_grant_revision,p_subject_fingerprint)
  RETURNING binding_id INTO subject_binding_id;
  RETURN subject_binding_id;
END
$register$;
REVOKE ALL ON FUNCTION saas_identity.register_subject_binding(name,uuid,bigint,text,text)
  FROM PUBLIC;

CREATE FUNCTION saas_identity.revoke_subject_binding(
  p_binding_id uuid, p_expected_revision bigint, p_reason text)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $revoke$
DECLARE
  result_revision bigint;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres'
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR p_binding_id IS NULL OR p_expected_revision IS NULL
     OR p_expected_revision < 1
     OR p_reason IS NULL OR char_length(btrim(p_reason)) NOT BETWEEN 8 AND 160 THEN
    RAISE EXCEPTION 'Backend15 refused untrusted binding revoke';
  END IF;
  PERFORM pg_catalog.set_config('saas.b15.operator_reason',p_reason,true);
  UPDATE saas_identity.subject_bindings
     SET status='revoked',binding_revision=binding_revision+1,
         revoked_at=clock_timestamp()
    WHERE binding_id=p_binding_id AND binding_revision=p_expected_revision
      AND status='active'
    RETURNING binding_revision INTO result_revision;
  IF result_revision IS NULL THEN
    RAISE EXCEPTION 'Backend15 stale or already revoked binding; no retry';
  END IF;
  RETURN result_revision;
END
$revoke$;
REVOKE ALL ON FUNCTION saas_identity.revoke_subject_binding(uuid,bigint,text)
  FROM PUBLIC;

-- Session issuance now requires a separately enrolled operator subject
-- binding ID and the CURRENT tenant grant revision, in addition to the
-- prior full DB-authenticated principal and role checks from 0006.
CREATE OR REPLACE FUNCTION saas_identity.issue_principal_session(
  p_principal name, p_tenant uuid, p_expected_grant_revision bigint,
  p_identity_binding_id uuid, p_expires_at timestamptz, p_reason text)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $issue$
DECLARE
  access record;
  binding_uuid uuid;
  session_value uuid;
  v_now timestamptz := clock_timestamp();
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres'
     OR current_database() NOT IN ('saas_staging','saas_staging_ci')
     OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
     OR p_principal IS NULL OR p_tenant IS NULL
     OR p_expected_grant_revision IS NULL OR p_expected_grant_revision < 1
     OR p_identity_binding_id IS NULL
     OR p_expires_at IS NULL OR p_expires_at <= v_now
     OR p_expires_at > v_now + interval '15 minutes'
     OR p_reason IS NULL OR char_length(btrim(p_reason)) NOT BETWEEN 8 AND 160 THEN
    RAISE EXCEPTION 'Backend15 refused untrusted or expired session request';
  END IF;
  SELECT x.access_revision,x.access_level INTO access
    FROM saas_acl.principal_tenants x
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
    RAISE EXCEPTION 'Backend15 principal is not an approved DB login';
  END IF;
  SELECT b.binding_id INTO binding_uuid
    FROM saas_identity.subject_bindings b
    WHERE b.binding_id=p_identity_binding_id
      AND b.principal_name=p_principal AND b.tenant_id=p_tenant
      AND b.grant_revision=p_expected_grant_revision
      AND b.status='active' AND b.revoked_at IS NULL
    FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Backend15 no active verified operator-bound identity';
  END IF;
  PERFORM pg_catalog.set_config('saas.b14.operator_reason',p_reason,true);
  INSERT INTO saas_identity.principal_sessions
    (principal_name,tenant_id,grant_revision,identity_binding_id,expires_at)
  VALUES (p_principal,p_tenant,p_expected_grant_revision,binding_uuid,p_expires_at)
  RETURNING session_id INTO session_value;
  RETURN session_value;
END
$issue$;
REVOKE ALL ON FUNCTION saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)
  FROM PUBLIC;

-- All runtime SELECTs retain FORCE RLS and DB session_user identity, then
-- acquire ACL, private session and subject binding FOR SHARE locks.
-- Binding revoke cannot acknowledge COMMIT while an in-flight reader
-- transaction holds its shared lock; later reads see revoked tombstones.
-- This does NOT revoke already delivered HTTP responses.
CREATE OR REPLACE FUNCTION saas_acl.can_read_tenant(subject_tenant uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fenced$
DECLARE
  approved_revision bigint;
  active_session uuid;
  required_binding uuid;
  verified_binding uuid;
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
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT s.session_id,s.identity_binding_id INTO active_session,required_binding
    FROM saas_identity.principal_sessions s
    WHERE s.principal_name=session_user::name
      AND s.tenant_id=subject_tenant
      AND s.grant_revision=approved_revision
      AND s.revoked_at IS NULL
      AND s.expires_at>clock_timestamp()
    FOR SHARE;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT b.binding_id INTO verified_binding
    FROM saas_identity.subject_bindings b
    WHERE b.binding_id=required_binding
      AND b.principal_name=session_user::name
      AND b.tenant_id=subject_tenant
      AND b.grant_revision=approved_revision
      AND b.status='active' AND b.revoked_at IS NULL
    FOR SHARE;
  RETURN FOUND;
END
$fenced$;
REVOKE ALL ON FUNCTION saas_acl.can_read_tenant(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_acl.can_read_tenant(uuid)
  TO saas_runtime_reader,saas_runtime_writer;
REVOKE ALL ON ALL TABLES IN SCHEMA saas_identity FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA saas_identity FROM PUBLIC;

INSERT INTO saas_bootstrap.schema_migrations
  (migration_id,source_sha256,source_commit)
VALUES ('0007_operator_subject_binding_fence', :'migration_sha256', :'source_commit');
COMMIT;

-- Backend 04: immutable token-fingerprint -> PG25 project-session link.
-- STRICTLY disposable PostgreSQL16 GitHub Actions. This is NOT production DDL.
-- Install only AFTER the complete SQL001..018,020..025 baseline and tests.
-- The existing SQL011 issuer/subject directory and SQL010 private token
-- registry are the durable identity source: never build parallel identities.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test'
    OR current_user<>'postgres'
    OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'
    OR to_regclass('saas_rls_private.issuer_subject_bindings') IS NULL
    OR to_regclass('saas_rls_private.actor_token_sessions') IS NULL
    OR to_regclass('saas_m1_private.project_session_epochs') IS NULL
    OR to_regclass('saas_m1_private.project_session_proofs') IS NULL
    OR to_regprocedure('saas_m1_api.lock_project_session_epoch(uuid,bigint,text,text)') IS NULL
    OR to_regprocedure('saas_rls_private.scope_verified()') IS NULL
    OR NOT EXISTS(SELECT 1 FROM pg_roles
       WHERE rolname='saas_m1_session_owner'
         AND NOT rolcanlogin AND NOT rolbypassrls AND NOT rolsuper)
 THEN RAISE EXCEPTION 'SQL026 requires disposable PG16 signed session baseline';
 END IF;
END $guard$;

-- Runtime is a distinct, NONLOGIN, read-only capability with no raw table
-- access, no signer/secret access and no enrol/revoke/actor write capability.
DO $roles$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_m1_identity_resolver') THEN
   CREATE ROLE saas_m1_identity_resolver NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
 END IF;
END $roles$;
ALTER ROLE saas_m1_identity_resolver NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA saas_m1_api TO saas_m1_identity_resolver,saas_issuer_provisioner;
GRANT USAGE ON SCHEMA saas_rls_private TO saas_m1_session_owner;
-- Only the NOLOGIN SECURITY DEFINER function owner reads these rows; the
-- runtime SELECT role and project executor never see raw issuer or hashes.
GRANT SELECT ON saas_rls_private.issuer_subject_bindings,
  saas_rls_private.actor_token_sessions,
  saas_rls_private.actor_session_state
  TO saas_m1_session_owner;
GRANT EXECUTE ON FUNCTION saas_rls_private.scope_verified()
  TO saas_m1_session_owner;

CREATE TABLE saas_m1_private.project_session_token_links (
  session_id UUID PRIMARY KEY REFERENCES
    saas_m1_private.project_session_epochs(session_id),
  token_fingerprint TEXT NOT NULL UNIQUE
    CHECK(token_fingerprint ~ '^[0-9a-f]{64}$')
    REFERENCES saas_rls_private.actor_token_sessions(fingerprint),
  actor_id TEXT NOT NULL CHECK(actor_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  tenant_id TEXT NOT NULL CHECK(tenant_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  issued_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp()
);
ALTER TABLE saas_m1_private.project_session_token_links OWNER TO saas_m1_session_owner;
REVOKE ALL ON saas_m1_private.project_session_token_links
 FROM PUBLIC,saas_ci_runner,saas_rls_reader,saas_m1_project_executor,
      saas_m1_identity_resolver,saas_issuer_provisioner,saas_issuer_directory_admin;
ALTER TABLE saas_m1_private.project_session_token_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE saas_m1_private.project_session_token_links FORCE ROW LEVEL SECURITY;
CREATE POLICY m1_project_token_owner_read
 ON saas_m1_private.project_session_token_links
 FOR SELECT TO saas_m1_session_owner USING(true);
CREATE POLICY m1_project_token_owner_insert
 ON saas_m1_private.project_session_token_links
 FOR INSERT TO saas_m1_session_owner WITH CHECK(true);

CREATE FUNCTION saas_m1_private.deny_project_token_rebinding()
 RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
 RAISE EXCEPTION 'SQL026 project-session token binding is immutable';
END $fn$;
ALTER FUNCTION saas_m1_private.deny_project_token_rebinding()
 OWNER TO saas_m1_session_owner;
REVOKE ALL ON FUNCTION saas_m1_private.deny_project_token_rebinding()
 FROM PUBLIC;
CREATE TRIGGER m1_project_token_never_rebind
 BEFORE UPDATE OR DELETE ON saas_m1_private.project_session_token_links
 FOR EACH ROW EXECUTE FUNCTION saas_m1_private.deny_project_token_rebinding();

-- Provisioner may link an already pinned SQL011 issuer/subject+fingerprint to
-- exactly one already-existing, active PG25 session. It cannot mint identity,
-- extend token expiry, revive revoked rows or rewrite historical links.
-- Caller MUST have cryptographically verified the access token out of band.
CREATE FUNCTION saas_m1_api.pin_project_verified_token_session(
 expected_session UUID, expected_actor TEXT, expected_tenant TEXT,
 expected_fingerprint TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE inserted INTEGER := 0;
BEGIN
 IF expected_session IS NULL OR expected_actor IS NULL
    OR expected_actor !~ '^[A-Za-z0-9_-]{1,128}$'
    OR expected_tenant IS NULL
    OR expected_tenant !~ '^[A-Za-z0-9_-]{1,64}$'
    OR expected_fingerprint IS NULL
    OR expected_fingerprint !~ '^[0-9a-f]{64}$'
 THEN RETURN FALSE; END IF;
 IF NOT EXISTS (
   SELECT 1 FROM saas_m1_private.project_session_epochs e
   WHERE e.session_id=expected_session AND e.actor_id=expected_actor
     AND e.tenant_id=expected_tenant AND e.status='active' FOR SHARE
 ) OR NOT EXISTS (
   SELECT 1 FROM saas_rls_private.actor_token_sessions t
   JOIN saas_rls_private.issuer_subject_bindings b
      ON b.issuer=t.issuer AND b.subject=t.subject AND b.actor_id=t.actor_id
   JOIN saas_rls_private.actor_session_state a ON a.actor_id=t.actor_id
   WHERE t.fingerprint=expected_fingerprint AND t.actor_id=expected_actor
     AND t.issuer IS NOT NULL AND t.subject IS NOT NULL
     AND t.status='active' AND t.expires_at>statement_timestamp()
     AND b.status='active' AND a.status='active'

 ) THEN RETURN FALSE; END IF;
 INSERT INTO saas_m1_private.project_session_token_links
   (session_id,token_fingerprint,actor_id,tenant_id)
 VALUES(expected_session,expected_fingerprint,expected_actor,expected_tenant)
 ON CONFLICT DO NOTHING;
 GET DIAGNOSTICS inserted=ROW_COUNT;
 RETURN inserted=1;
EXCEPTION WHEN check_violation OR unique_violation OR foreign_key_violation
 THEN RETURN FALSE;
END $fn$;
ALTER FUNCTION saas_m1_api.pin_project_verified_token_session(uuid,text,text,text)
 OWNER TO saas_m1_session_owner;
REVOKE ALL ON FUNCTION
 saas_m1_api.pin_project_verified_token_session(uuid,text,text,text)
 FROM PUBLIC,saas_ci_runner,saas_rls_reader,saas_m1_project_executor,
      saas_m1_identity_resolver,saas_issuer_directory_admin;
GRANT EXECUTE ON FUNCTION
 saas_m1_api.pin_project_verified_token_session(uuid,text,text,text)
 TO saas_issuer_provisioner;

-- No caller-supplied actor or role is accepted by HTTP. The server first
-- verifies issuer/signature, then this private durable directory resolves a
-- single active actor. Revoked subject/actor returns zero rows.
CREATE FUNCTION saas_m1_api.resolve_verified_subject_actor(
 verified_issuer TEXT, verified_subject TEXT
) RETURNS TABLE(actor_id TEXT)
 LANGUAGE sql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,pg_temp AS $fn$
 SELECT b.actor_id FROM saas_rls_private.issuer_subject_bindings b
 JOIN saas_rls_private.actor_session_state a ON a.actor_id=b.actor_id
 WHERE b.issuer=verified_issuer AND b.subject=verified_subject
   AND b.status='active' AND a.status='active'
   AND verified_issuer IS NOT NULL AND verified_subject IS NOT NULL
   AND char_length(verified_issuer) BETWEEN 10 AND 256
   AND char_length(verified_subject) BETWEEN 1 AND 256
 LIMIT 1
 $fn$;
ALTER FUNCTION saas_m1_api.resolve_verified_subject_actor(text,text)
 OWNER TO saas_m1_session_owner;
REVOKE ALL ON FUNCTION saas_m1_api.resolve_verified_subject_actor(text,text)
 FROM PUBLIC,saas_ci_runner,saas_m1_project_executor,saas_rls_reader,
      saas_issuer_provisioner,saas_issuer_directory_admin;
GRANT EXECUTE ON FUNCTION saas_m1_api.resolve_verified_subject_actor(text,text)
 TO saas_m1_identity_resolver;

-- One fingerprint -> one immutable session UUID. Enrolled issuer and subject
-- MUST still be active. Revision and status live in durable PG25, not RAM.
CREATE FUNCTION saas_m1_api.resolve_verified_project_session(
 expected_actor TEXT,expected_tenant TEXT,expected_fingerprint TEXT
) RETURNS TABLE(session_id UUID,session_revision BIGINT)
 LANGUAGE sql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,pg_temp AS $fn$
 SELECT e.session_id,e.revision FROM saas_m1_private.project_session_token_links l
 JOIN saas_m1_private.project_session_epochs e ON e.session_id=l.session_id
 JOIN saas_rls_private.actor_token_sessions t ON t.fingerprint=l.token_fingerprint
 JOIN saas_rls_private.issuer_subject_bindings b
   ON b.issuer=t.issuer AND b.subject=t.subject AND b.actor_id=t.actor_id
 JOIN saas_rls_private.actor_session_state a ON a.actor_id=t.actor_id
 WHERE l.token_fingerprint=expected_fingerprint
   AND l.actor_id=expected_actor AND l.tenant_id=expected_tenant
   AND e.actor_id=l.actor_id AND e.tenant_id=l.tenant_id
   AND e.status='active' AND t.actor_id=l.actor_id AND t.status='active'
   AND t.expires_at>statement_timestamp()
   AND b.status='active' AND a.status='active'
   AND expected_actor ~ '^[A-Za-z0-9_-]{1,128}$'
   AND expected_tenant ~ '^[A-Za-z0-9_-]{1,64}$'
   AND expected_fingerprint ~ '^[0-9a-f]{64}$'
 LIMIT 1
 $fn$;
ALTER FUNCTION saas_m1_api.resolve_verified_project_session(text,text,text)
 OWNER TO saas_m1_session_owner;
REVOKE ALL ON FUNCTION saas_m1_api.resolve_verified_project_session(text,text,text)
 FROM PUBLIC,saas_ci_runner,saas_m1_project_executor,saas_rls_reader,
      saas_issuer_provisioner,saas_issuer_directory_admin;
GRANT EXECUTE ON FUNCTION saas_m1_api.resolve_verified_project_session(text,text,text)
 TO saas_m1_identity_resolver;

-- PG25 session proof in SAME SQL transaction MUST additionally be tied to
-- actual server-signed SHA256 bearer fingerprint. Lock token + subject until
-- transaction completion: concurrent revocation is serialized by the\n-- existing PG25/M1d tenant authorization revision FOR SHARE lock. The\n-- SQL011 revoke trigger advances that same revision, so a later revoke\n-- cannot slip between this recheck and COMMIT.
CREATE FUNCTION saas_m1_private.require_project_token_binding()
 RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE
 fp TEXT:=NULLIF(current_setting('saas.scope_token_fingerprint',true),'');
 actor TEXT:=NULLIF(current_setting('saas.scope_actor',true),'');
 matched BOOLEAN:=FALSE;
BEGIN
 IF fp IS NULL OR fp !~ '^[0-9a-f]{64}$'
    OR actor IS NULL OR actor !~ '^[A-Za-z0-9_-]{1,128}$'
    OR NOT saas_rls_private.scope_verified() THEN
    RAISE EXCEPTION 'SQL026 missing verified token-bound write scope';
 END IF;
 SELECT TRUE INTO matched
 FROM saas_m1_private.project_session_proofs p
 JOIN saas_m1_private.project_session_token_links l ON l.session_id=p.session_id
 JOIN saas_m1_private.project_session_epochs e ON e.session_id=p.session_id
 JOIN saas_rls_private.actor_token_sessions t ON t.fingerprint=l.token_fingerprint
 JOIN saas_rls_private.issuer_subject_bindings b
  ON b.issuer=t.issuer AND b.subject=t.subject AND b.actor_id=t.actor_id
 WHERE p.pg_txid=txid_current()::TEXT
   AND p.actor_id=actor AND p.tenant_id=NEW.tenant_id
   AND l.actor_id=p.actor_id AND l.tenant_id=p.tenant_id
   AND l.token_fingerprint=fp
   AND e.actor_id=p.actor_id AND e.tenant_id=p.tenant_id
   AND e.status='active' AND e.revision=p.session_revision
   AND t.actor_id=p.actor_id AND t.status='active'
   AND t.expires_at>statement_timestamp()
   AND b.status='active'
;
 IF matched IS DISTINCT FROM TRUE THEN
   RAISE EXCEPTION 'SQL026 signed project write lacks matched active token';
 END IF;
 RETURN NULL;
END $fn$;
ALTER FUNCTION saas_m1_private.require_project_token_binding()
 OWNER TO saas_m1_session_owner;
REVOKE ALL ON FUNCTION saas_m1_private.require_project_token_binding()
 FROM PUBLIC,saas_ci_runner,saas_m1_project_executor,saas_rls_reader;
CREATE TRIGGER m1_project_token_binding_gate
 AFTER INSERT OR UPDATE ON saas_m1_private.projects
 FOR EACH ROW EXECUTE FUNCTION saas_m1_private.require_project_token_binding();

DO $assert$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_m1_identity_resolver'
   AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit)
 OR NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
    WHERE oid='saas_m1_private.project_session_token_links'::regclass)
 OR has_table_privilege('saas_m1_identity_resolver',
    'saas_m1_private.project_session_token_links','SELECT')
 OR has_table_privilege('saas_ci_runner',
    'saas_m1_private.project_session_token_links','SELECT')
 OR has_table_privilege('saas_m1_project_executor',
    'saas_m1_private.project_session_token_links','INSERT')
 OR has_function_privilege('saas_m1_identity_resolver',
    'saas_m1_api.pin_project_verified_token_session(uuid,text,text,text)','EXECUTE')
 OR has_function_privilege('saas_ci_runner',
    'saas_m1_api.resolve_verified_project_session(text,text,text)','EXECUTE')
 OR NOT has_function_privilege('saas_m1_identity_resolver',
    'saas_m1_api.resolve_verified_project_session(text,text,text)','EXECUTE')
 OR NOT EXISTS(SELECT 1 FROM pg_trigger
   WHERE tgrelid='saas_m1_private.projects'::regclass
     AND tgname='m1_project_token_binding_gate'
     AND NOT tgisinternal)
 THEN RAISE EXCEPTION 'SQL026 private identity privileges or token gate unsafe';
 END IF;
END $assert$;
COMMIT;
\echo 'PASS SQL026: durable issuer-actor/one-token-session resolution, mandatory signed token/session PG16 gate'

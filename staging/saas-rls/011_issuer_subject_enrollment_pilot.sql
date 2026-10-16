-- 2G.4d.7b: issuer/subject anchored token provisioning, DISPOSABLE PG16 ONLY.
-- The privileged provisioning service MUST verify RS256 JWT signature, issuer,
-- audience and expiry BEFORE calling these functions. PostgreSQL does NOT
-- cryptographically verify JWTs or enroll any real issuer/token by itself.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
    OR current_setting('saas.staging_only',TRUE) IS DISTINCT FROM 'true'
    OR to_regclass('saas_rls_private.actor_token_sessions') IS NULL
    OR to_regclass('saas_rls_private.token_fingerprint_tombstones') IS NULL
    OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
                 AND NOT rolsuper AND NOT rolbypassrls) THEN
   RAISE EXCEPTION 'Refusing issuer enrollment outside disposable PG16 CI';
 END IF;
END
$guard$;

-- Two separate NOLOGIN capabilities: directory bootstrap and verified-token
-- provisioning. No grant to reader, application runner or PUBLIC.
DO $roles$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_issuer_directory_admin') THEN
  CREATE ROLE saas_issuer_directory_admin NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_issuer_provisioner') THEN
  CREATE ROLE saas_issuer_provisioner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
 END IF;
END
$roles$;
GRANT USAGE ON SCHEMA saas_rls_private
 TO saas_issuer_directory_admin,saas_issuer_provisioner;

CREATE TABLE IF NOT EXISTS saas_rls_private.issuer_subject_bindings (
  issuer TEXT NOT NULL CHECK (
    char_length(issuer) BETWEEN 10 AND 256 AND
    issuer ~ '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$'),
  subject TEXT NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 256
                               AND subject !~ '[[:cntrl:]]'),
  actor_id TEXT NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  status TEXT NOT NULL CHECK (status IN ('active','revoked')),
  PRIMARY KEY (issuer,subject)
);
ALTER TABLE saas_rls_private.issuer_subject_bindings OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.issuer_subject_bindings FROM PUBLIC,
 saas_rls_reader,saas_issuer_directory_admin,saas_issuer_provisioner;

CREATE TABLE IF NOT EXISTS saas_rls_private.issuer_bound_actor_tombstones (
  actor_id TEXT PRIMARY KEY CHECK (actor_id ~ '^[A-Za-z0-9_-]{1,128}$')
);
ALTER TABLE saas_rls_private.issuer_bound_actor_tombstones OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.issuer_bound_actor_tombstones FROM PUBLIC,
 saas_rls_reader,saas_issuer_directory_admin,saas_issuer_provisioner;
INSERT INTO saas_rls_private.issuer_bound_actor_tombstones(actor_id)
  SELECT DISTINCT actor_id FROM saas_rls_private.issuer_subject_bindings
  ON CONFLICT (actor_id) DO NOTHING;

ALTER TABLE saas_rls_private.actor_token_sessions
 ADD COLUMN IF NOT EXISTS issuer TEXT;
ALTER TABLE saas_rls_private.actor_token_sessions
 ADD COLUMN IF NOT EXISTS subject TEXT;
DO $constraint$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint
                WHERE conname='actor_token_bound_subject_pair'
                 AND conrelid='saas_rls_private.actor_token_sessions'::regclass) THEN
  ALTER TABLE saas_rls_private.actor_token_sessions
   ADD CONSTRAINT actor_token_bound_subject_pair
   CHECK ((issuer IS NULL AND subject IS NULL) OR
          (issuer IS NOT NULL AND subject IS NOT NULL));
 END IF;
END
$constraint$;

-- Immutable issuer+subject -> actor ownership; subject revocation terminal.
CREATE OR REPLACE FUNCTION saas_rls_private.protect_subject_binding()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Issuer subject identity cannot be deleted'; END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.issuer IS DISTINCT FROM OLD.issuer OR
     NEW.subject IS DISTINCT FROM OLD.subject OR
     NEW.actor_id IS DISTINCT FROM OLD.actor_id OR
     (OLD.status='revoked' AND NEW.status<>'revoked') THEN
    RAISE EXCEPTION 'Issuer subject ownership and revocation are immutable';
  END IF;
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION saas_rls_private.protect_subject_binding() OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.protect_subject_binding() FROM PUBLIC;
DROP TRIGGER IF EXISTS saas_issuer_subject_protect
 ON saas_rls_private.issuer_subject_bindings;
CREATE TRIGGER saas_issuer_subject_protect BEFORE UPDATE OR DELETE
 ON saas_rls_private.issuer_subject_bindings
 FOR EACH ROW EXECUTE FUNCTION saas_rls_private.protect_subject_binding();

CREATE OR REPLACE FUNCTION saas_rls_private.revise_subject_binding()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE tenant TEXT;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 FOR tenant IN SELECT DISTINCT tenant_id FROM saas_rls.memberships
               WHERE actor_id=NEW.actor_id AND tenant_id IS NOT NULL
               ORDER BY tenant_id LOOP
  PERFORM saas_rls_private.advance_tenant_authorization_revision(tenant);
 END LOOP;
 RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_rls_private.revise_subject_binding() OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.revise_subject_binding() FROM PUBLIC;
DROP TRIGGER IF EXISTS saas_issuer_subject_epoch
 ON saas_rls_private.issuer_subject_bindings;
CREATE TRIGGER saas_issuer_subject_epoch AFTER INSERT OR UPDATE
 ON saas_rls_private.issuer_subject_bindings
 FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_subject_binding();

-- Existing 010 direct synthetic registration remains for NEVER pinned actors.
-- Once a subject is pinned for actor, any direct legacy INSERT lacks issuer
-- and is rejected, including on actor deletion/recreation.
CREATE OR REPLACE FUNCTION saas_rls_private.guard_token_issuer_binding()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
 IF TG_OP='UPDATE' AND
    (NEW.issuer IS DISTINCT FROM OLD.issuer OR
     NEW.subject IS DISTINCT FROM OLD.subject) THEN
   RAISE EXCEPTION 'Token issuer/subject ownership cannot change';
 END IF;
 IF TG_OP='INSERT' OR (TG_OP='UPDATE' AND NEW.status='active') THEN
  IF NEW.issuer IS NULL THEN
   IF EXISTS (SELECT 1 FROM saas_rls_private.issuer_bound_actor_tombstones
              WHERE actor_id=NEW.actor_id) THEN
    RAISE EXCEPTION 'Issuer-enrolled actor cannot use legacy token registry';
   END IF;
  ELSIF NOT EXISTS (
   SELECT 1 FROM saas_rls_private.issuer_subject_bindings b
    WHERE b.issuer=NEW.issuer AND b.subject=NEW.subject
      AND b.actor_id=NEW.actor_id AND b.status='active'
  ) THEN RAISE EXCEPTION 'Token issuer subject binding is not active'; END IF;
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION saas_rls_private.guard_token_issuer_binding() OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.guard_token_issuer_binding() FROM PUBLIC;
DROP TRIGGER IF EXISTS saas_token_issuer_guard
 ON saas_rls_private.actor_token_sessions;
CREATE TRIGGER saas_token_issuer_guard BEFORE INSERT OR UPDATE
 ON saas_rls_private.actor_token_sessions
 FOR EACH ROW EXECUTE FUNCTION saas_rls_private.guard_token_issuer_binding();

-- Directory admin pins identities only to existing ACTIVE actor, no
-- subject re-binding, even across transactions or an actor ID recycling.
CREATE OR REPLACE FUNCTION saas_rls_private.pin_verified_subject(
  claimed_issuer TEXT, claimed_subject TEXT, expected_actor TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE bound_actor TEXT; bound_status TEXT;
BEGIN
 IF claimed_issuer IS NULL OR claimed_subject IS NULL OR expected_actor IS NULL
    OR expected_actor !~ '^[A-Za-z0-9_-]{1,128}$' THEN RETURN FALSE; END IF;
 IF NOT EXISTS (
   SELECT 1 FROM saas_rls_private.actor_session_state s
   WHERE s.actor_id=expected_actor AND s.status='active'
   FOR SHARE
 ) THEN RETURN FALSE; END IF;
 INSERT INTO saas_rls_private.issuer_subject_bindings
   (issuer,subject,actor_id,status)
 VALUES (claimed_issuer,claimed_subject,expected_actor,'active')
 ON CONFLICT (issuer,subject) DO NOTHING;
 SELECT actor_id,status INTO bound_actor,bound_status
 FROM saas_rls_private.issuer_subject_bindings
 WHERE issuer=claimed_issuer AND subject=claimed_subject FOR SHARE;
 IF bound_actor IS DISTINCT FROM expected_actor OR bound_status<>'active' THEN
   RETURN FALSE;
 END IF;
 INSERT INTO saas_rls_private.issuer_bound_actor_tombstones(actor_id)
 VALUES(expected_actor) ON CONFLICT (actor_id) DO NOTHING;
 RETURN TRUE;
EXCEPTION WHEN check_violation THEN RETURN FALSE;
END
$fn$;
ALTER FUNCTION saas_rls_private.pin_verified_subject(TEXT,TEXT,TEXT)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.pin_verified_subject(TEXT,TEXT,TEXT)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls_private.pin_verified_subject(TEXT,TEXT,TEXT)
 TO saas_issuer_directory_admin;

CREATE OR REPLACE FUNCTION saas_rls_private.enroll_verified_token(
 claimed_issuer TEXT, claimed_subject TEXT, expected_actor TEXT,
 expected_fingerprint TEXT, expiry TIMESTAMPTZ
) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE bound_actor TEXT;
DECLARE enrolled INTEGER:=0;
BEGIN
 IF expected_fingerprint IS NULL OR
    expected_fingerprint !~ '^[0-9a-f]{64}$' OR expiry IS NULL OR
    expiry<=statement_timestamp() OR
    expiry>statement_timestamp()+INTERVAL '900 seconds' THEN RETURN FALSE; END IF;
 SELECT b.actor_id INTO bound_actor FROM saas_rls_private.issuer_subject_bindings b
 WHERE b.issuer=claimed_issuer AND b.subject=claimed_subject AND b.status='active'
 FOR SHARE;
 IF bound_actor IS DISTINCT FROM expected_actor OR bound_actor IS NULL THEN
  RETURN FALSE;
 END IF;
 IF NOT EXISTS (
   SELECT 1 FROM saas_rls_private.actor_session_state s
   WHERE s.actor_id=expected_actor AND s.status='active' FOR SHARE
 ) THEN RETURN FALSE; END IF;
 -- No reissue or extension after previous enrollment, even if deleted.
 INSERT INTO saas_rls_private.actor_token_sessions
 (fingerprint,actor_id,status,expires_at,issuer,subject)
 VALUES(expected_fingerprint,expected_actor,'active',expiry,
        claimed_issuer,claimed_subject)
 ON CONFLICT (fingerprint) DO NOTHING;
 GET DIAGNOSTICS enrolled=ROW_COUNT;
 RETURN enrolled=1;
EXCEPTION WHEN check_violation THEN RETURN FALSE;
END
$fn$;
ALTER FUNCTION saas_rls_private.enroll_verified_token(TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.enroll_verified_token(TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
 saas_rls_private.enroll_verified_token(TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ)
 TO saas_issuer_provisioner;

CREATE OR REPLACE FUNCTION saas_rls_private.revoke_verified_token(
 claimed_issuer TEXT,claimed_subject TEXT,expected_fingerprint TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE changed INTEGER:=0;
BEGIN
 IF expected_fingerprint IS NULL OR
    expected_fingerprint !~ '^[0-9a-f]{64}$' THEN RETURN FALSE; END IF;
 UPDATE saas_rls_private.actor_token_sessions s SET status='revoked'
 WHERE s.issuer=claimed_issuer AND s.subject=claimed_subject
   AND s.fingerprint=expected_fingerprint AND s.status='active'
   AND EXISTS (
     SELECT 1 FROM saas_rls_private.issuer_subject_bindings b
     WHERE b.issuer=s.issuer AND b.subject=s.subject AND b.actor_id=s.actor_id
   );
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END
$fn$;
ALTER FUNCTION saas_rls_private.revoke_verified_token(TEXT,TEXT,TEXT)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.revoke_verified_token(TEXT,TEXT,TEXT)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls_private.revoke_verified_token(TEXT,TEXT,TEXT)
 TO saas_issuer_provisioner;

CREATE OR REPLACE FUNCTION saas_rls_private.revoke_verified_subject(
 claimed_issuer TEXT,claimed_subject TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE changed INTEGER:=0;
BEGIN
 UPDATE saas_rls_private.issuer_subject_bindings b SET status='revoked'
 WHERE b.issuer=claimed_issuer AND b.subject=claimed_subject AND b.status='active';
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END
$fn$;
ALTER FUNCTION saas_rls_private.revoke_verified_subject(TEXT,TEXT)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.revoke_verified_subject(TEXT,TEXT)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls_private.revoke_verified_subject(TEXT,TEXT)
 TO saas_issuer_directory_admin;

-- Final scope auth extends 010. The HMAC, actor/token and expiry checks are
-- identical; the NEW check additionally confirms subject ownership/status.
-- A subject-level revoke invalidates active tokens without editing each row.
CREATE OR REPLACE FUNCTION saas_rls_private.scope_verified()
RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE actor_claim TEXT:=current_setting('saas.scope_actor',TRUE);
DECLARE tenant_claim TEXT:=current_setting('saas.scope_tenant',TRUE);
DECLARE txid_claim TEXT:=current_setting('saas.scope_txid',TRUE);
DECLARE expiry_claim TEXT:=current_setting('saas.scope_expiry',TRUE);
DECLARE mac_claim TEXT:=current_setting('saas.scope_mac',TRUE);
DECLARE fingerprint_claim TEXT:=NULLIF(current_setting('saas.scope_token_fingerprint',TRUE),'');
DECLARE signer_key BYTEA;
DECLARE expected_mac TEXT;
DECLARE now_epoch BIGINT;
BEGIN
 IF actor_claim IS NULL OR actor_claim !~ '^[A-Za-z0-9_-]{1,128}$'
    OR tenant_claim IS NULL OR tenant_claim !~ '^[A-Za-z0-9_-]{1,64}$'
    OR txid_claim IS NULL OR txid_claim !~ '^[0-9]{1,19}$'
    OR expiry_claim IS NULL OR expiry_claim !~ '^[0-9]{10}$'
    OR mac_claim IS NULL OR mac_claim !~ '^[0-9a-f]{64}$'
    OR txid_claim<>txid_current()::TEXT THEN RETURN FALSE; END IF;
 now_epoch:=floor(extract(epoch FROM statement_timestamp()))::BIGINT;
 IF expiry_claim::BIGINT<=now_epoch OR expiry_claim::BIGINT>now_epoch+900
 THEN RETURN FALSE; END IF;
 SELECT secret INTO signer_key FROM saas_rls_private.scope_signers
 WHERE key_id='ci-pilot';
 IF signer_key IS NULL THEN RETURN FALSE; END IF;
 IF fingerprint_claim IS NULL THEN
  IF EXISTS(SELECT 1 FROM saas_rls_private.token_bound_actor_tombstones
           WHERE actor_id=actor_claim)
     OR EXISTS(SELECT 1 FROM saas_rls_private.issuer_bound_actor_tombstones
               WHERE actor_id=actor_claim)
     OR EXISTS(SELECT 1 FROM saas_rls_private.actor_session_state s
               WHERE s.actor_id=actor_claim AND s.require_token_fingerprint)
  THEN RETURN FALSE; END IF;
  expected_mac:=encode(public.hmac(
   convert_to(concat_ws(chr(31),actor_claim,tenant_claim,
                 txid_claim,expiry_claim),'UTF8'),signer_key,'sha256'),'hex');
 ELSE
  IF fingerprint_claim !~ '^[0-9a-f]{64}$'
   OR NOT EXISTS(
    SELECT 1 FROM saas_rls_private.actor_token_sessions s
    WHERE s.fingerprint=fingerprint_claim AND s.actor_id=actor_claim
      AND s.status='active' AND s.expires_at>statement_timestamp()
      AND (
        (s.issuer IS NULL AND s.subject IS NULL AND
         NOT EXISTS (SELECT 1 FROM saas_rls_private.issuer_bound_actor_tombstones t
                     WHERE t.actor_id=s.actor_id))
        OR
        (s.issuer IS NOT NULL AND s.subject IS NOT NULL AND EXISTS (
         SELECT 1 FROM saas_rls_private.issuer_subject_bindings b
         WHERE b.issuer=s.issuer AND b.subject=s.subject
           AND b.actor_id=s.actor_id AND b.status='active'))
      )
   ) THEN RETURN FALSE; END IF;
  expected_mac:=encode(public.hmac(
   convert_to(concat_ws(chr(31),actor_claim,tenant_claim,
          txid_claim,expiry_claim,fingerprint_claim),'UTF8'),
          signer_key,'sha256'),'hex');
 END IF;
 RETURN expected_mac=mac_claim;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END
$fn$;
ALTER FUNCTION saas_rls_private.scope_verified() OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.scope_verified()
 FROM PUBLIC,saas_rls_reader,saas_issuer_directory_admin,saas_issuer_provisioner;

DO $assert$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_issuer_provisioner'
    AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='saas_issuer_directory_admin'
    AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
 OR has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
 OR has_function_privilege('saas_rls_reader',
   'saas_rls_private.enroll_verified_token(text,text,text,text,timestamptz)','EXECUTE')
 OR has_function_privilege('saas_ci_runner',
   'saas_rls_private.enroll_verified_token(text,text,text,text,timestamptz)','EXECUTE')
 OR has_function_privilege('saas_issuer_provisioner',
   'saas_rls_private.pin_verified_subject(text,text,text)','EXECUTE')
 OR has_function_privilege('saas_issuer_directory_admin',
   'saas_rls_private.enroll_verified_token(text,text,text,text,timestamptz)','EXECUTE')
 OR has_table_privilege('saas_issuer_provisioner',
   'saas_rls_private.issuer_subject_bindings','SELECT')
 OR has_table_privilege('saas_issuer_directory_admin',
   'saas_rls_private.actor_token_sessions','INSERT')
 OR has_table_privilege('saas_rls_reader',
   'saas_rls_private.issuer_subject_bindings','SELECT')
 OR NOT has_function_privilege('saas_issuer_provisioner',
   'saas_rls_private.revoke_verified_token(text,text,text)','EXECUTE')
 THEN RAISE EXCEPTION 'Issuer provisioning capability leaked or incomplete';
 END IF;
END
$assert$;
COMMIT;
\echo 'PASS: issuer/subject ownership, isolated roles, terminal revocation in PG16'

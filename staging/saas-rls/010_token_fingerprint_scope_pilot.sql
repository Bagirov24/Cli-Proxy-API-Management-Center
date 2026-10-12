-- Stage 2G.4d.7a: per-BEARER fingerprint scoped authorization, ephemeral PG16 ONLY.
-- A fingerprint is derived by the trusted server from a verified RS256 access
-- token, NOT from user-supplied jti or headers. No raw token is stored here.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
    OR current_setting('saas.staging_only',TRUE) IS DISTINCT FROM 'true'
    OR to_regclass('saas_rls_private.actor_session_state') IS NULL
    OR to_regclass('saas_rls_private.tenant_authorization_revisions') IS NULL
    OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='saas_rls_owner'
                   AND NOT rolsuper AND NOT rolbypassrls) THEN
   RAISE EXCEPTION 'Refusing token fingerprint scope outside disposable PG16 CI';
 END IF;
END
$guard$;

-- This permanent, actor-specific enrollment flag closes the legacy downgrade:
-- deleting/revoking the final token does NOT restore actor-only HMAC access.
ALTER TABLE saas_rls_private.actor_session_state
  ADD COLUMN IF NOT EXISTS require_token_fingerprint BOOLEAN NOT NULL DEFAULT FALSE;

-- Enrollment tombstone survives actor/session DELETE+recreate, including
-- deleting the final enrolled token; it is never deleted by fixture writes.
CREATE TABLE IF NOT EXISTS saas_rls_private.token_bound_actor_tombstones (
  actor_id TEXT PRIMARY KEY CHECK (actor_id ~ '^[A-Za-z0-9_-]{1,128}$')
);
ALTER TABLE saas_rls_private.token_bound_actor_tombstones OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.token_bound_actor_tombstones
 FROM PUBLIC,saas_rls_reader;
INSERT INTO saas_rls_private.token_bound_actor_tombstones(actor_id)
SELECT actor_id FROM saas_rls_private.actor_session_state
 WHERE require_token_fingerprint
ON CONFLICT (actor_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS saas_rls_private.actor_token_sessions (
  fingerprint TEXT PRIMARY KEY CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  actor_id TEXT NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  status TEXT NOT NULL CHECK (status IN ('active','revoked')),
  expires_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE saas_rls_private.actor_token_sessions OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.actor_token_sessions FROM PUBLIC,saas_rls_reader;

CREATE INDEX IF NOT EXISTS actor_token_sessions_actor_idx
  ON saas_rls_private.actor_token_sessions(actor_id);
-- Index ownership follows the private table in PostgreSQL.

CREATE OR REPLACE FUNCTION saas_rls_private.revise_actor_token_sessions()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE affected_actor TEXT;
DECLARE affected_tenant TEXT;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW.fingerprint IS DISTINCT FROM OLD.fingerprint OR
       NEW.actor_id IS DISTINCT FROM OLD.actor_id THEN
      RAISE EXCEPTION 'Moving token identity between actors is forbidden';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
  END IF;
  affected_actor := CASE WHEN TG_OP='DELETE' THEN OLD.actor_id ELSE NEW.actor_id END;
  IF TG_OP='INSERT' THEN
    -- Must already be a trusted registered actor, even in the fixture.
    UPDATE saas_rls_private.actor_session_state
       SET require_token_fingerprint=TRUE
     WHERE actor_id=affected_actor AND NOT require_token_fingerprint;
    IF NOT EXISTS (
      SELECT 1 FROM saas_rls_private.actor_session_state WHERE actor_id=affected_actor
    ) THEN
      RAISE EXCEPTION 'Unknown actor for token fingerprint enrollment';
    END IF;
    INSERT INTO saas_rls_private.token_bound_actor_tombstones(actor_id)
      VALUES (affected_actor) ON CONFLICT (actor_id) DO NOTHING;
  END IF;
  -- Scope revocation/insertion is committed with the SAME epoch updates
  -- used by the read-publication FOR SHARE lock. Over-invalidation is safe.
  FOR affected_tenant IN
    SELECT DISTINCT tenant_id FROM saas_rls.memberships
     WHERE actor_id=affected_actor AND tenant_id IS NOT NULL ORDER BY tenant_id
  LOOP
    PERFORM saas_rls_private.advance_tenant_authorization_revision(affected_tenant);
  END LOOP;
  RETURN NULL;
END
$fn$;
ALTER FUNCTION saas_rls_private.revise_actor_token_sessions() OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.revise_actor_token_sessions()
  FROM PUBLIC,saas_rls_reader;
DROP TRIGGER IF EXISTS saas_actor_token_revision ON saas_rls_private.actor_token_sessions;
CREATE TRIGGER saas_actor_token_revision
AFTER INSERT OR UPDATE OR DELETE ON saas_rls_private.actor_token_sessions
FOR EACH ROW EXECUTE FUNCTION saas_rls_private.revise_actor_token_sessions();

-- Compatible with synthetic legacy 4-field signed scope ONLY for actors
-- that have NEVER enrolled a token fingerprint. Enrolled actors require
-- a 5-field MAC, plus current private token row and expiry on EVERY gate.
-- A forged or unsigned fingerprint is NEVER accepted. The unprivileged
-- reader cannot directly read or modify actor/token registration.
CREATE OR REPLACE FUNCTION saas_rls_private.scope_verified()
RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE
  actor_claim TEXT := current_setting('saas.scope_actor',TRUE);
  tenant_claim TEXT := current_setting('saas.scope_tenant',TRUE);
  txid_claim TEXT := current_setting('saas.scope_txid',TRUE);
  expiry_claim TEXT := current_setting('saas.scope_expiry',TRUE);
  mac_claim TEXT := current_setting('saas.scope_mac',TRUE);
  fingerprint_claim TEXT := NULLIF(current_setting('saas.scope_token_fingerprint',TRUE),'');
  signer_key BYTEA;
  expected_mac TEXT;
  expires_epoch BIGINT;
  now_epoch BIGINT;
BEGIN
  IF actor_claim IS NULL OR actor_claim !~ '^[A-Za-z0-9_-]{1,128}$'
     OR tenant_claim IS NULL OR tenant_claim !~ '^[A-Za-z0-9_-]{1,64}$'
     OR txid_claim IS NULL OR txid_claim !~ '^[0-9]{1,19}$'
     OR expiry_claim IS NULL OR expiry_claim !~ '^[0-9]{10}$'
     OR mac_claim IS NULL OR mac_claim !~ '^[0-9a-f]{64}$'
     OR txid_claim <> txid_current()::TEXT THEN RETURN FALSE; END IF;
  expires_epoch := expiry_claim::BIGINT;
  now_epoch := floor(extract(epoch FROM statement_timestamp()))::BIGINT;
  IF expires_epoch<=now_epoch OR expires_epoch>now_epoch+900 THEN RETURN FALSE; END IF;
  SELECT secret INTO signer_key FROM saas_rls_private.scope_signers
    WHERE key_id='ci-pilot';
  IF signer_key IS NULL THEN RETURN FALSE; END IF;

  IF fingerprint_claim IS NULL THEN
    -- Once any token is registered, even after last token deletion, legacy
    -- actor-only MAC cannot reactivate access (permanent enrollment flag).
    IF EXISTS (
      SELECT 1 FROM saas_rls_private.token_bound_actor_tombstones t
       WHERE t.actor_id=actor_claim
    ) OR EXISTS (
      SELECT 1 FROM saas_rls_private.actor_session_state s
       WHERE s.actor_id=actor_claim AND s.require_token_fingerprint
    ) THEN RETURN FALSE; END IF;
    expected_mac := encode(public.hmac(
      convert_to(concat_ws(chr(31),actor_claim,tenant_claim,
                           txid_claim,expiry_claim),'UTF8'),
      signer_key,'sha256'),'hex');
  ELSE
    IF fingerprint_claim !~ '^[0-9a-f]{64}$' OR NOT EXISTS (
      SELECT 1 FROM saas_rls_private.actor_token_sessions s
       WHERE s.fingerprint=fingerprint_claim AND s.actor_id=actor_claim
         AND s.status='active' AND s.expires_at>statement_timestamp()
    ) THEN RETURN FALSE; END IF;
    expected_mac := encode(public.hmac(
      convert_to(concat_ws(chr(31),actor_claim,tenant_claim,
                 txid_claim,expiry_claim,fingerprint_claim),'UTF8'),
      signer_key,'sha256'),'hex');
  END IF;
  RETURN expected_mac=mac_claim;
EXCEPTION WHEN OTHERS THEN
  RETURN FALSE;
END
$fn$;
ALTER FUNCTION saas_rls_private.scope_verified() OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.scope_verified()
 FROM PUBLIC,saas_rls_reader;

-- Earliest expiry includes BOTH active grants and the signed token session.
-- The time-only token expiration has no writer trigger, so this deadline
-- is also verified by the trusted TypeScript revision-before-handoff guard.
CREATE OR REPLACE FUNCTION saas_rls.authorized_revision_state(
  expected_tenant TEXT, expected_actor TEXT, expected_role TEXT,
  expected_collection TEXT
) RETURNS TABLE(revision TEXT, not_after_ms TEXT)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $fn$
 SELECT r.revision::TEXT,
   FLOOR(EXTRACT(EPOCH FROM LEAST(
     (SELECT MIN(g.expires_at) FROM saas_rls.resource_grants g
       WHERE g.grantee_tenant_id=expected_tenant AND g.status='active'
         AND g.expires_at>statement_timestamp()),
     (SELECT MIN(s.expires_at) FROM saas_rls_private.actor_token_sessions s
       WHERE s.actor_id=expected_actor AND
         s.fingerprint=NULLIF(current_setting('saas.scope_token_fingerprint',TRUE),'')
         AND s.status='active' AND s.expires_at>statement_timestamp())
   ))*1000)::BIGINT::TEXT AS not_after_ms
 FROM saas_rls_private.tenant_authorization_revisions r
 WHERE r.tenant_id=expected_tenant AND r.tenant_active
   AND saas_rls.scope_membership_matches(expected_tenant,expected_actor,expected_role)
   AND saas_rls.read_allowed(expected_tenant,expected_collection)
$fn$;
ALTER FUNCTION saas_rls.authorized_revision_state(TEXT,TEXT,TEXT,TEXT)
 OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.authorized_revision_state(TEXT,TEXT,TEXT,TEXT)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.authorized_revision_state(TEXT,TEXT,TEXT,TEXT)
 TO saas_rls_reader;

DO $assert$
BEGIN
 IF has_schema_privilege('saas_rls_reader','saas_rls_private','USAGE')
   OR has_table_privilege('saas_rls_reader',
        'saas_rls_private.actor_token_sessions','SELECT')
   OR has_table_privilege('saas_ci_runner',
        'saas_rls_private.actor_token_sessions','INSERT')
   OR has_table_privilege('saas_rls_reader',
        'saas_rls_private.token_bound_actor_tombstones','SELECT')
   OR has_table_privilege('saas_rls_reader',
        'saas_rls_private.actor_session_state','UPDATE')
   OR has_function_privilege('saas_rls_reader',
        'saas_rls_private.scope_verified()','EXECUTE') THEN
   RAISE EXCEPTION 'Token-fingerprint private permissions violate least privilege';
 END IF;
END
$assert$;
COMMIT;
\echo 'PASS: PG16 token fingerprint HMAC binding, enrollment downgrade guard and revision expiry'

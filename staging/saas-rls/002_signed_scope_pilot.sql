-- Migration 002: signed transaction-local scope for EPHEMERAL CI ONLY.
-- This is a defence-in-depth proof, NOT OIDC authentication or production SQL.
-- Apply after 001_readonly_pilot.sql; migration is idempotent on CI fixture DB.
BEGIN;
DO $guard$
BEGIN
  IF current_setting('saas.staging_only', true) IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Refusing signed-scope migration outside explicit staging';
  END IF;
END
$guard$;

-- pgcrypto is used only by the ephemeral fixture to create/verify random HMACs.
-- No signing key or test token is committed into the repository.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS saas_rls_private AUTHORIZATION saas_rls_owner;
ALTER SCHEMA saas_rls_private OWNER TO saas_rls_owner;
REVOKE ALL ON SCHEMA saas_rls_private FROM PUBLIC;
REVOKE ALL ON SCHEMA saas_rls_private FROM saas_rls_reader;

CREATE TABLE IF NOT EXISTS saas_rls_private.scope_signers (
  key_id TEXT PRIMARY KEY,
  secret BYTEA NOT NULL CHECK (octet_length(secret) = 32)
);
ALTER TABLE saas_rls_private.scope_signers OWNER TO saas_rls_owner;
REVOKE ALL ON saas_rls_private.scope_signers FROM PUBLIC;
REVOKE ALL ON saas_rls_private.scope_signers FROM saas_rls_reader;

-- Every individual field is untrusted, including scope_txid and scope_mac.
-- The MAC authenticates their COMBINATION and txid_current() binds it to
-- the transaction. A reader can still SET these GUCs but cannot forge
-- a different actor, tenant, expiry or transaction ID without the secret.
-- Server OIDC and trusted signing remain a SEPARATE unimplemented boundary.
CREATE OR REPLACE FUNCTION saas_rls_private.scope_verified()
RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  claim_actor TEXT := current_setting('saas.scope_actor', true);
  claim_tenant TEXT := current_setting('saas.scope_tenant', true);
  claim_txid TEXT := current_setting('saas.scope_txid', true);
  claim_expiry TEXT := current_setting('saas.scope_expiry', true);
  claim_mac TEXT := current_setting('saas.scope_mac', true);
  signer_key BYTEA;
  expected_mac TEXT;
  expiry_epoch BIGINT;
  now_epoch BIGINT;
BEGIN
  IF claim_actor IS NULL OR claim_actor !~ '^[A-Za-z0-9_-]{1,128}$'
     OR claim_tenant IS NULL OR claim_tenant !~ '^[A-Za-z0-9_-]{1,64}$'
     OR claim_txid IS NULL OR claim_txid !~ '^[0-9]{1,19}$'
     OR claim_expiry IS NULL OR claim_expiry !~ '^[0-9]{10}$'
     OR claim_mac IS NULL OR claim_mac !~ '^[0-9a-f]{64}$' THEN
    RETURN FALSE;
  END IF;
  IF claim_txid <> txid_current()::TEXT THEN
    RETURN FALSE;
  END IF;
  expiry_epoch := claim_expiry::BIGINT;
  now_epoch := floor(extract(epoch FROM statement_timestamp()))::BIGINT;
  IF expiry_epoch <= now_epoch OR expiry_epoch > now_epoch + 900 THEN
    RETURN FALSE;
  END IF;
  SELECT secret INTO signer_key FROM saas_rls_private.scope_signers
  WHERE key_id = 'ci-pilot';
  IF signer_key IS NULL THEN RETURN FALSE; END IF;

  expected_mac := encode(public.hmac(
    convert_to(concat_ws(chr(31), claim_actor, claim_tenant,
                         claim_txid, claim_expiry), 'UTF8'),
    signer_key, 'sha256'
  ), 'hex');
  RETURN expected_mac = claim_mac;
EXCEPTION
  WHEN OTHERS THEN
    -- Fail closed; never reflect key, claim or upstream error in the API.
    RETURN FALSE;
END
$fn$;
ALTER FUNCTION saas_rls_private.scope_verified() OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls_private.scope_verified() FROM PUBLIC;
REVOKE ALL ON FUNCTION saas_rls_private.scope_verified() FROM saas_rls_reader;

-- Replace V1 GUC predicates with authenticated-claim lookups.
-- Volatile: scope expiry and transaction revocation must not be cached.
CREATE OR REPLACE FUNCTION saas_rls.scope_tenant()
RETURNS TEXT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF NOT saas_rls_private.scope_verified() THEN RETURN NULL; END IF;
  RETURN NULLIF(current_setting('saas.scope_tenant', true), '');
END
$fn$;

CREATE OR REPLACE FUNCTION saas_rls.read_allowed(
  target_tenant TEXT, resource_collection TEXT
) RETURNS BOOLEAN
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT saas_rls_private.scope_verified()
    AND target_tenant = NULLIF(current_setting('saas.scope_tenant', true), '')
    AND EXISTS (
      SELECT 1 FROM saas_rls.memberships AS m
      WHERE m.actor_id = NULLIF(current_setting('saas.scope_actor', true), '')
        AND m.tenant_id = target_tenant
        AND m.status = 'active'
        AND (
          m.role IN ('tenant-owner', 'tenant-admin', 'tenant-viewer')
          OR (m.role = 'tenant-auditor'
            AND resource_collection IN ('tenant', 'projects', 'applications'))
        )
    )
$fn$;

CREATE OR REPLACE FUNCTION saas_rls.resource_granted(
  resource_kind TEXT, resource_id TEXT, owner_kind TEXT, owner_tenant_id TEXT
) RETURNS BOOLEAN
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT saas_rls_private.scope_verified()
     AND CASE
       WHEN $3 = 'tenant' AND $4 = saas_rls.scope_tenant() THEN TRUE
       ELSE EXISTS (
         SELECT 1 FROM saas_rls.resource_grants AS g
         WHERE g.resource_id = $2
           AND g.resource_kind = $1
           AND g.grantee_tenant_id = saas_rls.scope_tenant()
           AND g.owner_kind = $3
           AND g.owner_tenant_id IS NOT DISTINCT FROM $4
           AND g.status = 'active'
           AND (g.expires_at IS NULL OR g.expires_at > statement_timestamp())
       )
     END
$fn$;

ALTER FUNCTION saas_rls.scope_tenant() OWNER TO saas_rls_owner;
ALTER FUNCTION saas_rls.read_allowed(TEXT, TEXT) OWNER TO saas_rls_owner;
ALTER FUNCTION saas_rls.resource_granted(TEXT, TEXT, TEXT, TEXT) OWNER TO saas_rls_owner;
REVOKE ALL ON FUNCTION saas_rls.scope_tenant() FROM PUBLIC;
REVOKE ALL ON FUNCTION saas_rls.read_allowed(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION saas_rls.resource_granted(TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saas_rls.scope_tenant() TO saas_rls_reader;
GRANT EXECUTE ON FUNCTION saas_rls.read_allowed(TEXT, TEXT) TO saas_rls_reader;
GRANT EXECUTE ON FUNCTION saas_rls.resource_granted(TEXT, TEXT, TEXT, TEXT)
  TO saas_rls_reader;

COMMIT;

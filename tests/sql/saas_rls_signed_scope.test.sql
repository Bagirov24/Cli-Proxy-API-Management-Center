\set ON_ERROR_STOP on
-- Stage 2D: adversarial checks for SIGNED TX-BOUND scope on synthetic PG16.
-- Database is disposable. No production credentials, migrations or data.
SET saas.staging_only = 'true';
\ir ../../staging/saas-rls/001_readonly_pilot.sql
\ir ../../staging/saas-rls/002_signed_scope_pilot.sql
-- Both migrations must be replayable with no policy/permission drift.
\ir ../../staging/saas-rls/001_readonly_pilot.sql
\ir ../../staging/saas-rls/002_signed_scope_pilot.sql

CREATE SCHEMA IF NOT EXISTS saas_rls_test;
CREATE OR REPLACE FUNCTION saas_rls_test.assert_true(ok BOOLEAN, message TEXT)
RETURNS VOID LANGUAGE plpgsql AS $fn$
BEGIN
  IF ok IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'Signed-scope acceptance FAILED: %', message;
  END IF;
END
$fn$;
GRANT USAGE ON SCHEMA saas_rls_test TO saas_rls_reader;
GRANT EXECUTE ON FUNCTION saas_rls_test.assert_true(BOOLEAN, TEXT) TO saas_rls_reader;

-- The key lives ONLY inside temporary PostgreSQL CI container.
INSERT INTO saas_rls_private.scope_signers(key_id, secret)
VALUES ('ci-pilot', public.gen_random_bytes(32))
ON CONFLICT (key_id) DO NOTHING;

-- Test-only privileged signer. It deliberately has NO GRANT to reader.
-- Real SaaS issuance must be behind verified server auth, never SQL client.
CREATE OR REPLACE FUNCTION saas_rls_test.issue_scope(
  actor_arg TEXT, tenant_arg TEXT, lifetime_seconds INTEGER
) RETURNS VOID
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  scoped_tx TEXT := txid_current()::TEXT;
  exp TEXT := (floor(extract(epoch FROM statement_timestamp()))::BIGINT
               + lifetime_seconds)::TEXT;
  secret_key BYTEA;
  mac TEXT;
BEGIN
  SELECT secret INTO secret_key FROM saas_rls_private.scope_signers
  WHERE key_id = 'ci-pilot';
  IF secret_key IS NULL THEN RAISE EXCEPTION 'CI key missing'; END IF;
  mac := encode(public.hmac(
    convert_to(concat_ws(chr(31), actor_arg, tenant_arg, scoped_tx, exp), 'UTF8'),
    secret_key, 'sha256'
  ), 'hex');
  PERFORM set_config('saas.scope_actor', actor_arg, TRUE);
  PERFORM set_config('saas.scope_tenant', tenant_arg, TRUE);
  PERFORM set_config('saas.scope_txid', scoped_tx, TRUE);
  PERFORM set_config('saas.scope_expiry', exp, TRUE);
  PERFORM set_config('saas.scope_mac', mac, TRUE);
END
$fn$;
REVOKE ALL ON FUNCTION saas_rls_test.issue_scope(TEXT, TEXT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION saas_rls_test.issue_scope(TEXT, TEXT, INTEGER) FROM saas_rls_reader;

SELECT saas_rls_test.assert_true(
  NOT has_schema_privilege('saas_rls_reader', 'saas_rls_private', 'USAGE') AND
  NOT has_table_privilege('saas_rls_reader', 'saas_rls_private.scope_signers', 'SELECT') AND
  NOT has_function_privilege('saas_rls_reader',
     'saas_rls_test.issue_scope(text,text,integer)', 'EXECUTE') AND
  NOT has_function_privilege('saas_rls_reader',
     'saas_rls_private.scope_verified()', 'EXECUTE'),
  'reader must not read HMAC key or invoke signer/verifier'
);

BEGIN;
INSERT INTO saas_rls.tenants(id, name, status) VALUES
  ('demo-north','North Studio','active'),
  ('demo-orbit','Orbit Lab','active'),
  ('demo-suspended','Paused','suspended');
INSERT INTO saas_rls.memberships(actor_id, tenant_id, role, status) VALUES
  ('actor-north','demo-north','tenant-admin','active'),
  ('actor-orbit','demo-orbit','tenant-viewer','active'),
  ('actor-auditor','demo-north','tenant-auditor','active'),
  ('actor-revoked','demo-north','tenant-owner','revoked'),
  ('actor-paused','demo-suspended','tenant-owner','active');
INSERT INTO saas_rls.projects(id,tenant_id,name,status) VALUES
  ('project-north','demo-north','North project','active'),
  ('project-orbit','demo-orbit','Orbit project','active'),
  ('project-paused','demo-suspended','Paused project','active');
INSERT INTO saas_rls.applications(id,tenant_id,project_id,name,status) VALUES
  ('app-north','demo-north','project-north','North app','active'),
  ('app-orbit','demo-orbit','project-orbit','Orbit app','active');
INSERT INTO saas_rls.key_bindings(id,tenant_id,application_id,key_kind,status) VALUES
  ('key-north','demo-north','app-north','cpa','active'),
  ('native-north','demo-north','app-north','core-native','active'),
  ('key-orbit','demo-orbit','app-orbit','cpa','active');
INSERT INTO saas_rls.resource_catalog
  (id,kind,owner_kind,owner_tenant_id,status) VALUES
  ('pool-north','pool','tenant','demo-north','active'),
  ('account-north','account','tenant','demo-north','active'),
  ('egress-north','egress','tenant','demo-north','active'),
  ('pool-orbit','pool','tenant','demo-orbit','active'),
  ('account-orbit','account','tenant','demo-orbit','active'),
  ('egress-orbit','egress','tenant','demo-orbit','active'),
  ('pool-platform','pool','platform',NULL,'active'),
  ('account-platform','account','platform',NULL,'active'),
  ('egress-platform','egress','platform',NULL,'active');
INSERT INTO saas_rls.resource_grants
  (id,resource_id,resource_kind,grantee_tenant_id,owner_kind,owner_tenant_id,status,expires_at)
VALUES
  ('grant-platform-pool','pool-platform','pool','demo-north','platform',NULL,'active',NULL),
  ('grant-platform-account','account-platform','account','demo-north','platform',NULL,'active',NULL),
  ('grant-platform-egress','egress-platform','egress','demo-north','platform',NULL,'active',NULL);
INSERT INTO saas_rls.resource_links(id,link_kind,from_id,to_id,status) VALUES
  ('shared-membership','pool-account','pool-platform','account-platform','active'),
  ('shared-egress','account-egress','account-platform','egress-platform','active'),
  ('foreign-link','pool-account','pool-platform','account-orbit','active');
INSERT INTO saas_rls.routing_bindings
  (id,tenant_id,application_id,key_binding_id,pool_id,
   provider_id,requested_model_id,status,egress_policy)
VALUES
  ('north-owned','demo-north','app-north','key-north','pool-north',
    'demo-provider','demo-chat','active','required'),
  ('north-shared','demo-north','app-north','key-north','pool-platform',
    'demo-provider','demo-chat','active','required'),
  ('north-foreign','demo-north','app-north','key-north','pool-orbit',
    'demo-provider','demo-chat','active','required'),
  ('north-native','demo-north','app-north','native-north','pool-north',
    'demo-provider','demo-chat','active','required'),
  ('orbit-owned','demo-orbit','app-orbit','key-orbit','pool-orbit',
    'demo-provider','demo-chat','active','required');

-- A. Even a caller who knows valid actor and tenant IDs cannot issue access
-- by setting V1 or spoofed V2 custom GUCs.
SET LOCAL ROLE saas_rls_reader;
SELECT set_config('saas.actor_id','actor-north',true);
SELECT set_config('saas.tenant_id','demo-north',true);
SELECT set_config('saas.scope_actor','actor-north',true);
SELECT set_config('saas.scope_tenant','demo-north',true);
SELECT set_config('saas.scope_txid',txid_current()::TEXT,true);
SELECT set_config('saas.scope_expiry',
   (floor(extract(epoch FROM statement_timestamp()))::BIGINT + 100)::TEXT,true);
SELECT set_config('saas.scope_mac',repeat('a',64),true);
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=0 FROM saas_rls.tenants) AND
  (SELECT count(*)=0 FROM saas_rls.projects) AND
  (SELECT count(*)=0 FROM saas_rls.resource_catalog),
  'forged GUCs and bogus MAC cannot authorize any metadata');
RESET ROLE;

-- B. Trusted ephemeral signer grants only the matching unique membership.
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=1 FROM saas_rls.tenants) AND
  (SELECT count(*)=1 FROM saas_rls.projects) AND
  (SELECT count(*)=1 FROM saas_rls.applications) AND
  (SELECT count(*)=1 FROM saas_rls.key_bindings) AND
  (SELECT count(*)=6 FROM saas_rls.resource_catalog) AND
  (SELECT count(*)=2 FROM saas_rls.resource_links) AND
  (SELECT count(*)=2 FROM saas_rls.routing_bindings),
  'valid North scope reveals own and separately granted metadata only');
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=0 FROM saas_rls.resource_catalog WHERE id LIKE '%orbit%'),
  'a signed North context must not reveal Orbit metadata');
RESET ROLE;

-- Capture only an ephemeral MAC as psql variable to simulate replay;
-- the actual random key never leaves its private PostgreSQL table.
SELECT current_setting('saas.scope_mac') AS north_mac \gset
SELECT current_setting('saas.scope_expiry') AS north_expiry \gset
SELECT current_setting('saas.scope_txid') AS north_txid \gset

-- C. Changing tenant/actor without changing MAC must fail, despite valid
-- membership for Orbit. Old V1 GUCs cannot override signed context.
SET LOCAL ROLE saas_rls_reader;
SELECT set_config('saas.scope_tenant','demo-orbit',true);
SELECT set_config('saas.scope_actor','actor-orbit',true);
SELECT set_config('saas.tenant_id','demo-orbit',true);
SELECT set_config('saas.actor_id','actor-orbit',true);
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=0 FROM saas_rls.tenants) AND
  (SELECT count(*)=0 FROM saas_rls.resource_catalog),
  'tampered signed identity and tenant cannot authorize Orbit');
RESET ROLE;
SELECT saas_rls_test.issue_scope('actor-orbit','demo-orbit',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=1 FROM saas_rls.projects) AND
  (SELECT count(*)=3 FROM saas_rls.resource_catalog) AND
  (SELECT count(*)=1 FROM saas_rls.routing_bindings),
  'fresh separately signed Orbit scope must authorize Orbit only');
RESET ROLE;

-- D. Validly signed auditor remains blocked from accounts and egress.
SELECT saas_rls_test.issue_scope('actor-auditor','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=1 FROM saas_rls.projects) AND
  (SELECT count(*)=0 FROM saas_rls.key_bindings) AND
  (SELECT count(*)=0 FROM saas_rls.resource_catalog),
  'signature alone cannot elevate auditor RBAC');
RESET ROLE;

-- E. Valid signatures cannot revive a revoked actor or suspended tenant.
SELECT saas_rls_test.issue_scope('actor-revoked','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=0 FROM saas_rls.projects), 'revoked membership must deny');
RESET ROLE;
SELECT saas_rls_test.issue_scope('actor-paused','demo-suspended',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=0 FROM saas_rls.tenants) AND
  (SELECT count(*)=0 FROM saas_rls.projects),
  'suspended tenant must deny even with a valid signature');
RESET ROLE;

-- F. Negative lifetime and edited expiry must deny; no client clock override.
SELECT saas_rls_test.issue_scope('actor-north','demo-north',-10);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true((SELECT count(*)=0 FROM saas_rls.projects),
  'expired but well-signed scope must fail');
RESET ROLE;

SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT set_config('saas.scope_expiry','9999999999',true);
SELECT saas_rls_test.assert_true((SELECT count(*)=0 FROM saas_rls.projects),
  'edited expiry cannot bypass MAC validation');
RESET ROLE;

-- G. A granted platform resource must become unavailable immediately when
-- its own grant is revoked, without affecting unrelated grants.
SELECT saas_rls_test.issue_scope('actor-north','demo-north',120);
UPDATE saas_rls.resource_grants SET status='disabled' WHERE id='grant-platform-account';
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=5 FROM saas_rls.resource_catalog) AND
  (SELECT count(*)=0 FROM saas_rls.resource_links) AND
  (SELECT count(*)=2 FROM saas_rls.routing_bindings),
  'account grant revocation hides account and both links, not independent pool');
RESET ROLE;
UPDATE saas_rls.resource_grants SET status='active' WHERE id='grant-platform-account';
UPDATE saas_rls.resource_grants
  SET expires_at='2000-01-01T00:00:00Z' WHERE id='grant-platform-pool';
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=5 FROM saas_rls.resource_catalog) AND
  (SELECT count(*)=1 FROM saas_rls.resource_links) AND
  (SELECT count(*)=1 FROM saas_rls.routing_bindings),
  'expired pool cannot leak a route or pool member reference');
RESET ROLE;
ROLLBACK;

-- H. Captured MAC is bound to the original transaction ID and cannot
-- authorize access on a fresh transaction, even with all other GUCs copied.
BEGIN;
SELECT set_config('saas.scope_actor','actor-north',true);
SELECT set_config('saas.scope_tenant','demo-north',true);
SELECT set_config('saas.scope_txid', :'north_txid',true);
SELECT set_config('saas.scope_expiry', :'north_expiry',true);
SELECT set_config('saas.scope_mac', :'north_mac',true);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=0 FROM saas_rls.projects) AND
  (SELECT count(*)=0 FROM saas_rls.resource_catalog),
  'replay of a valid MAC in another transaction must fail');
RESET ROLE;
ROLLBACK;

\echo 'PASS: signed transaction scope blocks forged GUCs, changed actor and cross-transaction replay'

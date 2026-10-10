\set ON_ERROR_STOP on
-- Stage 2E SQL proof: prepared parameters + SET LOCAL isolation on ONE CI connection.
-- Prerequisite: signed-scope pilot run in the same ephemeral PostgreSQL database.
-- NO real user IDs, credentials, Core data or production database connection.
CREATE SCHEMA IF NOT EXISTS saas_rls_test;

BEGIN;
INSERT INTO saas_rls.tenants(id,name,status) VALUES
  ('demo-north','North Studio','active'),
  ('demo-orbit','Orbit Lab','active');
INSERT INTO saas_rls.memberships(actor_id,tenant_id,role,status) VALUES
  ('actor-north','demo-north','tenant-admin','active'),
  ('actor-orbit','demo-orbit','tenant-viewer','active');
INSERT INTO saas_rls.projects(id,tenant_id,name,status) VALUES
  ('project-north','demo-north','north','active'),
  ('project-orbit','demo-orbit','orbit','active');

-- Privileged issuer is ONLY CI fixture; end users never execute this.
SELECT saas_rls_test.issue_scope('actor-north','demo-north',60);
SET LOCAL ROLE saas_rls_reader;
PREPARE safe_count (text) AS
  SELECT count(*)::integer AS visible
  FROM saas_rls.projects WHERE tenant_id=$1;

EXECUTE safe_count('demo-north') \gset
SELECT saas_rls_test.assert_true(:'visible'::integer = 1,
  'prepared query sees only authorized North rows');

-- Intentionally hostile text MUST be parsed as a bound literal, not SQL.
EXECUTE safe_count('demo-north'' OR ''1''=''1') \gset
SELECT saas_rls_test.assert_true(:'visible'::integer = 0,
  'parameter containing SQL punctuation is not executed');

EXECUTE safe_count('demo-orbit') \gset
SELECT saas_rls_test.assert_true(:'visible'::integer = 0,
  'RLS still denies Orbit even when parameter requests Orbit');

SELECT saas_rls_test.assert_true(to_regclass('saas_rls.projects') IS NOT NULL,
  'malicious parameter must not remove schema objects');
RESET ROLE;
ROLLBACK;

-- Same PostgreSQL connection, NEW transaction: SET LOCAL claims and ROLE
-- must not survive, including a previous signed token.
BEGIN;
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
  (SELECT count(*)=0 FROM saas_rls.projects),
  'transaction pool reuse without renewed signature returns zero rows');
SELECT saas_rls_test.assert_true(
  coalesce(current_setting('saas.scope_actor',true),'')='' AND
  coalesce(current_setting('saas.scope_mac',true),'')='',
  'rollback cleared signed scope claims');
RESET ROLE;
ROLLBACK;

\echo 'PASS: prepared values cannot inject SQL; SET LOCAL scope cleared on pooled connection reuse'

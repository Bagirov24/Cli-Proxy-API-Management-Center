\set ON_ERROR_STOP on
-- 2G.4d.7b: real ephemeral PG16 issuer/subject enrollment and revocation.
-- Uses two separate NOLOGIN roles; no real issuer, tokens or /data.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
 OR to_regclass('saas_rls_private.issuer_subject_bindings') IS NULL
 OR to_regclass('saas_rls_private.issuer_bound_actor_tombstones') IS NULL THEN
  RAISE EXCEPTION 'Refusing issuer session tests outside disposable PG16';
 END IF;
END
$guard$;
SELECT saas_rls_test.assert_true(
 NOT has_function_privilege('saas_rls_reader',
  'saas_rls_private.pin_verified_subject(text,text,text)','EXECUTE')
 AND NOT has_function_privilege('saas_ci_runner',
  'saas_rls_private.enroll_verified_token(text,text,text,text,timestamptz)','EXECUTE')
 AND NOT has_function_privilege('saas_issuer_provisioner',
  'saas_rls_private.pin_verified_subject(text,text,text)','EXECUTE')
 AND NOT has_function_privilege('saas_issuer_directory_admin',
  'saas_rls_private.enroll_verified_token(text,text,text,text,timestamptz)','EXECUTE')
 AND NOT has_table_privilege('saas_issuer_provisioner',
  'saas_rls_private.issuer_subject_bindings','SELECT'),
 'Bootstrap/provision/read capabilities MUST be separated');

BEGIN;
INSERT INTO saas_rls.memberships(actor_id,tenant_id,role,status) VALUES
 ('actor-issued-ci','demo-north','tenant-viewer','active'),
 ('actor-issued-other','demo-orbit','tenant-viewer','active');
INSERT INTO saas_rls_private.actor_session_state(actor_id,status)
 VALUES ('actor-issued-ci','active'),('actor-issued-other','active');

-- Only the bootstrap administrator may pin a validated issuer/subject.
SET LOCAL ROLE saas_issuer_directory_admin;
SELECT saas_rls_private.pin_verified_subject(
 'https://ci-issuer.example.test/oauth','sub-alpha','actor-issued-ci')::TEXT
 AS pinned_alpha \gset
SELECT saas_rls_private.pin_verified_subject(
 'https://ci-issuer.example.test/oauth','sub-beta','actor-issued-ci')::TEXT
 AS pinned_beta \gset
SELECT saas_rls_private.pin_verified_subject(
 'https://ci-issuer.example.test/oauth','sub-alpha','actor-issued-other')::TEXT
 AS stolen_subject \gset
SELECT saas_rls_private.pin_verified_subject(
 'https://untrusted.example.test/oauth','sub-fake','missing-actor')::TEXT
 AS unknown_actor \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'pinned_alpha'='true' AND :'pinned_beta'='true'
 AND :'stolen_subject'='false' AND :'unknown_actor'='false'
 AND (SELECT COUNT(*)=1 FROM saas_rls_private.issuer_bound_actor_tombstones
       WHERE actor_id='actor-issued-ci'),
 'Directory owner bound immutably, denied rebinding or unknown actors');

SELECT revision::TEXT AS before_enroll FROM
 saas_rls_private.tenant_authorization_revisions
 WHERE tenant_id='demo-north' \gset
-- Only the pre-pinned issuer service may enroll the EXACT verified bearer
-- digest and bounded exp (in production verification happens in TypeScript).
SET LOCAL ROLE saas_issuer_provisioner;
SELECT saas_rls_private.enroll_verified_token(
 'https://ci-issuer.example.test/oauth','sub-alpha','actor-issued-ci',
 repeat('1',64),statement_timestamp()+INTERVAL '120 seconds')::TEXT
 AS enrolled_a \gset
SELECT saas_rls_private.enroll_verified_token(
 'https://ci-issuer.example.test/oauth','sub-beta','actor-issued-ci',
 repeat('2',64),statement_timestamp()+INTERVAL '120 seconds')::TEXT
 AS enrolled_b \gset
SELECT saas_rls_private.enroll_verified_token(
 'https://ci-issuer.example.test/oauth','sub-alpha','actor-issued-other',
 repeat('3',64),statement_timestamp()+INTERVAL '120 seconds')::TEXT
 AS forged_actor \gset
SELECT saas_rls_private.enroll_verified_token(
 'https://ci-issuer.example.test/oauth','sub-unpinned','actor-issued-ci',
 repeat('4',64),statement_timestamp()+INTERVAL '120 seconds')::TEXT
 AS unpinned \gset
SELECT saas_rls_private.enroll_verified_token(
 'https://ci-issuer.example.test/oauth','sub-alpha','actor-issued-ci',
 repeat('5',64),statement_timestamp()+INTERVAL '920 seconds')::TEXT
 AS overlong \gset
SELECT saas_rls_private.enroll_verified_token(
 'https://ci-issuer.example.test/oauth','sub-alpha','actor-issued-ci',
 repeat('1',64),statement_timestamp()+INTERVAL '120 seconds')::TEXT
 AS duplicate \gset
SELECT saas_rls_private.revoke_verified_token(
 'https://ci-issuer.example.test/oauth','sub-beta',repeat('1',64))::TEXT
 AS wrong_subject_revoke \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'enrolled_a'='true' AND :'enrolled_b'='true'
 AND :'forged_actor'='false' AND :'unpinned'='false'
 AND :'overlong'='false' AND :'duplicate'='false'
 AND :'wrong_subject_revoke'='false'
 AND (SELECT revision>(:'before_enroll')::BIGINT
      FROM saas_rls_private.tenant_authorization_revisions
      WHERE tenant_id='demo-north'),
 'Pinned issuer registration succeeds; forged/duplicate/overlong denied');

SELECT saas_rls_test.issue_bound_scope(
 'actor-issued-ci','demo-north',repeat('1',64),120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.scope_tenant()='demo-north'
 AND EXISTS(SELECT 1 FROM saas_rls.projects WHERE id='north-project'),
 'Signed registered subject A may read North metadata');
RESET ROLE;

-- First issuer-controlled actor enrollment blocks old actor-only MAC and
-- legacy token rows with NULL issuer/subject, including privileged writes.
SELECT saas_rls_test.issue_scope('actor-issued-ci','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.scope_tenant() IS NULL,
 'Pinned actor cannot downgrade to four-field signed scope');
RESET ROLE;
DO $legacy_insert$
DECLARE rejected BOOLEAN:=FALSE;
BEGIN
 BEGIN
  INSERT INTO saas_rls_private.actor_token_sessions
  (fingerprint,actor_id,status,expires_at)
  VALUES(repeat('6',64),'actor-issued-ci','active',
         statement_timestamp()+INTERVAL '120 seconds');
 EXCEPTION WHEN OTHERS THEN rejected:=TRUE;
 END;
 PERFORM saas_rls_test.assert_true(rejected,
   'Direct legacy insertion must fail once issuer is pinned');
END
$legacy_insert$;

SELECT revision::TEXT AS before_a_revoke FROM
 saas_rls_private.tenant_authorization_revisions
 WHERE tenant_id='demo-north' \gset
SET LOCAL ROLE saas_issuer_provisioner;
SELECT saas_rls_private.revoke_verified_token(
 'https://ci-issuer.example.test/oauth','sub-alpha',repeat('1',64))::TEXT
 AS revoked_a \gset
SELECT saas_rls_private.revoke_verified_token(
 'https://ci-issuer.example.test/oauth','sub-alpha',repeat('1',64))::TEXT
 AS replay_revoke \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'revoked_a'='true' AND :'replay_revoke'='false'
 AND (SELECT revision=(:'before_a_revoke')::BIGINT+1
      FROM saas_rls_private.tenant_authorization_revisions
      WHERE tenant_id='demo-north'),
 'Individual revoke is terminal, second revoke no extra epoch');

SELECT saas_rls_test.issue_bound_scope(
 'actor-issued-ci','demo-north',repeat('1',64),120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.scope_tenant() IS NULL
 AND saas_rls.authorized_revision(
  'demo-north','actor-issued-ci','tenant-viewer','projects') IS NULL
 AND NOT EXISTS(SELECT 1 FROM saas_rls.projects WHERE id='north-project'),
 'Revoked token A denied even through direct signed raw RLS');
RESET ROLE;
SELECT saas_rls_test.issue_bound_scope(
 'actor-issued-ci','demo-north',repeat('2',64),120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.scope_tenant()='demo-north'
 AND EXISTS(SELECT 1 FROM saas_rls.projects WHERE id='north-project'),
 'Sibling token B for same actor continues to authorize');
RESET ROLE;

SELECT revision::TEXT AS before_subject_revoke FROM
 saas_rls_private.tenant_authorization_revisions
 WHERE tenant_id='demo-north' \gset
SET LOCAL ROLE saas_issuer_directory_admin;
SELECT saas_rls_private.revoke_verified_subject(
 'https://ci-issuer.example.test/oauth','sub-beta')::TEXT
 AS revoked_subject \gset
SELECT saas_rls_private.revoke_verified_subject(
 'https://ci-issuer.example.test/oauth','sub-beta')::TEXT
 AS replay_subject \gset
SELECT saas_rls_private.pin_verified_subject(
 'https://ci-issuer.example.test/oauth','sub-beta','actor-issued-ci')::TEXT
 AS rebind_after_revoke \gset
RESET ROLE;
SELECT saas_rls_test.assert_true(
 :'revoked_subject'='true' AND :'replay_subject'='false'
 AND :'rebind_after_revoke'='false'
 AND (SELECT revision=(:'before_subject_revoke')::BIGINT+1
      FROM saas_rls_private.tenant_authorization_revisions
      WHERE tenant_id='demo-north')
 AND (SELECT status='active'
      FROM saas_rls_private.actor_token_sessions WHERE fingerprint=repeat('2',64)),
 'Subject revoke bumps epoch without mutating each active token row');

SELECT saas_rls_test.issue_bound_scope(
 'actor-issued-ci','demo-north',repeat('2',64),120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.scope_tenant() IS NULL
 AND NOT EXISTS(SELECT 1 FROM saas_rls.projects WHERE id='north-project'),
 'Revoked SUBJECT denies still-active token B on signed raw RLS');
RESET ROLE;

DO $permanence$
DECLARE rejected_update BOOLEAN:=FALSE;
DECLARE rejected_delete BOOLEAN:=FALSE;
BEGIN
 BEGIN
  UPDATE saas_rls_private.issuer_subject_bindings SET status='active'
   WHERE issuer='https://ci-issuer.example.test/oauth' AND subject='sub-beta';
 EXCEPTION WHEN OTHERS THEN rejected_update:=TRUE;
 END;
 BEGIN
  DELETE FROM saas_rls_private.issuer_subject_bindings
   WHERE issuer='https://ci-issuer.example.test/oauth' AND subject='sub-beta';
 EXCEPTION WHEN OTHERS THEN rejected_delete:=TRUE;
 END;
 PERFORM saas_rls_test.assert_true(rejected_update AND rejected_delete,
   'Terminal subject revocation must forbid UPDATE/reactivation and DELETE');
END
$permanence$;
SELECT saas_rls_test.assert_true(
 NOT has_table_privilege('saas_ci_runner',
 'saas_rls_private.issuer_subject_bindings','SELECT')
 AND NOT has_table_privilege('saas_issuer_provisioner',
 'saas_rls_private.actor_token_sessions','SELECT')
 AND NOT has_function_privilege('saas_rls_reader',
 'saas_rls_private.revoke_verified_subject(text,text)','EXECUTE'),
 'No issuer/subject private authority exposed to reader or token provisioner');
ROLLBACK;
\echo 'PASS: issuer-pinned enrollment, per-token/subject revocation, rollback and ACL'

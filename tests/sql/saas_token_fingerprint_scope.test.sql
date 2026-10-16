\set ON_ERROR_STOP on
-- 2G.4d.7a: synthetic token fingerprints only, no real access tokens.
DO $guard$
BEGIN
 IF current_database()<>'saas_ephemeral_test' OR current_user<>'postgres'
   OR to_regclass('saas_rls_private.actor_token_sessions') IS NULL THEN
  RAISE EXCEPTION 'Refusing token-bound test outside disposable PG16';
 END IF;
END
$guard$;

-- Privileged fixture issuer; reader has neither signer nor invocation.
CREATE OR REPLACE FUNCTION saas_rls_test.issue_bound_scope(
  actor_arg TEXT,tenant_arg TEXT,fp TEXT,lifetime INTEGER
) RETURNS VOID LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE tx TEXT:=txid_current()::TEXT;
DECLARE exp TEXT:=(floor(extract(epoch from statement_timestamp()))::BIGINT+lifetime)::TEXT;
DECLARE key_bytes BYTEA;
DECLARE mac TEXT;
BEGIN
 IF fp !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'Bad fixture token'; END IF;
 SELECT secret INTO key_bytes FROM saas_rls_private.scope_signers WHERE key_id='ci-pilot';
 IF key_bytes IS NULL THEN RAISE EXCEPTION 'Missing fixture signer'; END IF;
 mac:=encode(public.hmac(
   convert_to(concat_ws(chr(31),actor_arg,tenant_arg,tx,exp,fp),'UTF8'),
   key_bytes,'sha256'),'hex');
 PERFORM set_config('saas.scope_actor',actor_arg,TRUE);
 PERFORM set_config('saas.scope_tenant',tenant_arg,TRUE);
 PERFORM set_config('saas.scope_txid',tx,TRUE);
 PERFORM set_config('saas.scope_expiry',exp,TRUE);
 PERFORM set_config('saas.scope_mac',mac,TRUE);
 PERFORM set_config('saas.scope_token_fingerprint',fp,TRUE);
END
$fn$;
REVOKE ALL ON FUNCTION saas_rls_test.issue_bound_scope(TEXT,TEXT,TEXT,INTEGER)
 FROM PUBLIC,saas_rls_reader;

BEGIN;
INSERT INTO saas_rls.memberships(actor_id,tenant_id,role,status)
 VALUES ('actor-bound-sql','demo-north','tenant-viewer','active');
INSERT INTO saas_rls_private.actor_session_state(actor_id,status)
 VALUES ('actor-bound-sql','active');
INSERT INTO saas_rls_private.actor_token_sessions(fingerprint,actor_id,status,expires_at)
 VALUES (repeat('a',64),'actor-bound-sql','active',statement_timestamp()+interval '90 seconds'),
        (repeat('b',64),'actor-bound-sql','active',statement_timestamp()+interval '90 seconds');
SELECT saas_rls_test.assert_true(
 (SELECT require_token_fingerprint FROM saas_rls_private.actor_session_state
  WHERE actor_id='actor-bound-sql'),'Enrollment flag required');

-- Even a properly issued legacy four-field MAC must be denied.
SELECT saas_rls_test.issue_scope('actor-bound-sql','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.scope_tenant() IS NULL AND
 NOT EXISTS (SELECT 1 FROM saas_rls.projects WHERE id='north-project'),
 'Enrolled actor must never downgrade to legacy MAC');
RESET ROLE;

SELECT saas_rls_test.issue_bound_scope('actor-bound-sql','demo-north',repeat('a',64),120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.scope_tenant()='demo-north',
 'Bound token A 5-field HMAC failed to authenticate');
SELECT saas_rls_test.assert_true(
 EXISTS(SELECT 1 FROM saas_rls.projects WHERE id='north-project'),
 'Bound token A valid HMAC failed to reach RLS project row');
SELECT saas_rls_test.assert_true(
 EXISTS(SELECT 1 FROM saas_rls.authorized_revision_state(
  'demo-north','actor-bound-sql','tenant-viewer','projects')
  WHERE revision ~ '^[1-9][0-9]*$' AND not_after_ms ~ '^[1-9][0-9]+$'),
 'Bound token A signed revision deadline unavailable');
SELECT set_config('saas.scope_token_fingerprint',repeat('b',64),TRUE);
SELECT saas_rls_test.assert_true(saas_rls.scope_tenant() IS NULL,
 'Substituting another enrolled fingerprint without new MAC must deny');
RESET ROLE;

SELECT revision AS epoch_before_revoke FROM
 saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north' \gset
UPDATE saas_rls_private.actor_token_sessions SET status='revoked'
 WHERE fingerprint=repeat('a',64);
DO $revoked_cannot_reactivate$
DECLARE rejected BOOLEAN:=FALSE;
BEGIN
 BEGIN
   UPDATE saas_rls_private.actor_token_sessions SET status='active'
    WHERE fingerprint=repeat('a',64);
 EXCEPTION WHEN OTHERS THEN rejected:=TRUE;
 END;
 PERFORM saas_rls_test.assert_true(rejected,
   'A previously revoked fingerprint must not change back to active');
END
$revoked_cannot_reactivate$;
SELECT saas_rls_test.assert_true(
 (SELECT revision=(:'epoch_before_revoke')::BIGINT+1
  FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'),
 'Revoking token A must bump exactly one tenant epoch');
SELECT saas_rls_test.issue_bound_scope('actor-bound-sql','demo-north',repeat('a',64),120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.scope_tenant() IS NULL AND
 saas_rls.authorized_revision('demo-north','actor-bound-sql','tenant-viewer','projects') IS NULL
 AND NOT EXISTS(SELECT 1 FROM saas_rls.projects WHERE id='north-project'),
 'Revoked A must deny even on raw signed RLS SELECT');
RESET ROLE;
SELECT saas_rls_test.issue_bound_scope('actor-bound-sql','demo-north',repeat('b',64),120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(
 saas_rls.scope_tenant()='demo-north' AND
 EXISTS(SELECT 1 FROM saas_rls.projects WHERE id='north-project'),
 'Other token B of same actor must remain authorized');
RESET ROLE;

UPDATE saas_rls_private.actor_token_sessions
 SET expires_at=statement_timestamp()+interval '850 milliseconds'
 WHERE fingerprint=repeat('b',64);
DO $ttl_no_extension$
DECLARE rejected BOOLEAN:=FALSE;
BEGIN
 BEGIN
   UPDATE saas_rls_private.actor_token_sessions
   SET expires_at=statement_timestamp()+interval '3 minutes'
   WHERE fingerprint=repeat('b',64);
 EXCEPTION WHEN OTHERS THEN rejected:=TRUE;
 END;
 PERFORM saas_rls_test.assert_true(rejected,
   'Enrolled token expiry cannot be extended by UPDATE');
END
$ttl_no_extension$;
SELECT revision AS expiry_epoch FROM
 saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north' \gset
SELECT saas_rls_test.issue_bound_scope('actor-bound-sql','demo-north',repeat('b',64),120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(saas_rls.scope_tenant()='demo-north',
 'Bound token must be active before clock-only expiry');
RESET ROLE;
SELECT pg_sleep(1.2);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(saas_rls.scope_tenant() IS NULL,
 'Clock-only token expiration denies without further UPDATE');
RESET ROLE;
SELECT saas_rls_test.assert_true(
 (SELECT revision=(:'expiry_epoch')::BIGINT
 FROM saas_rls_private.tenant_authorization_revisions WHERE tenant_id='demo-north'),
 'Clock-only token expiry must not advance raw revision');

DELETE FROM saas_rls_private.actor_token_sessions WHERE actor_id='actor-bound-sql';
DO $fingerprint_no_reuse$
DECLARE rejected BOOLEAN:=FALSE;
BEGIN
 BEGIN
   INSERT INTO saas_rls_private.actor_token_sessions
     (fingerprint,actor_id,status,expires_at)
   VALUES (repeat('a',64),'actor-bound-sql','active',
           statement_timestamp()+interval '2 minutes');
 EXCEPTION WHEN OTHERS THEN rejected:=TRUE;
 END;
 PERFORM saas_rls_test.assert_true(rejected,
  'DELETE+INSERT cannot resurrect an already used fingerprint');
END
$fingerprint_no_reuse$;
SELECT saas_rls_test.issue_scope('actor-bound-sql','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(saas_rls.scope_tenant() IS NULL,
 'Deleting last enrolled token must not restore actor-only scope');
RESET ROLE;
-- Even a privileged DELETE/re-create of the actor session state must not
-- resurrect actor-only authorization for an already enrolled actor ID.
DELETE FROM saas_rls_private.actor_session_state WHERE actor_id='actor-bound-sql';
INSERT INTO saas_rls_private.actor_session_state(actor_id,status)
 VALUES ('actor-bound-sql','active');
SELECT saas_rls_test.issue_scope('actor-bound-sql','demo-north',120);
SET LOCAL ROLE saas_rls_reader;
SELECT saas_rls_test.assert_true(saas_rls.scope_tenant() IS NULL,
 'Deleting/recreating the actor row must preserve permanent token enrollment');
RESET ROLE;
SELECT saas_rls_test.assert_true(
 (SELECT COUNT(*)=1 FROM saas_rls_private.token_bound_actor_tombstones
  WHERE actor_id='actor-bound-sql') AND
 (SELECT COUNT(*)=2 FROM saas_rls_private.token_fingerprint_tombstones
  WHERE actor_id='actor-bound-sql') AND
 NOT has_table_privilege('saas_rls_reader','saas_rls_private.actor_token_sessions','SELECT')
 AND NOT has_table_privilege('saas_ci_runner','saas_rls_private.actor_token_sessions','INSERT')
 AND NOT has_function_privilege('saas_rls_reader',
  'saas_rls_test.issue_bound_scope(text,text,text,integer)','EXECUTE'),
 'Enrollment tombstone survives actor recycling and stays private');
ROLLBACK;
\echo 'PASS: signed token A revoke, sibling B survives, expiry, no legacy downgrade'

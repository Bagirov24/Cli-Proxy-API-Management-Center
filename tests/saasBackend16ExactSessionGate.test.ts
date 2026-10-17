import {describe,expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';

const MIGRATION=readFileSync(
  new URL('../staging/saas-bootstrap/0008_exact_subject_session_gate.sql',import.meta.url),'utf8');
const ACCEPTANCE=readFileSync(
  new URL('../tests/sql/saas_backend16_exact_session_gate.test.sql',import.meta.url),'utf8');
const DRIVER=readFileSync(
  new URL('../scripts/saas-staging/verify-backend16-exact-session-pg16.sh',import.meta.url),'utf8');

describe('Backend16.4 SQL0008 exact bound session gate (NO staging writes)',()=>{
  test('one-shot SHA/PG16 staging migrator chain is pinned and never replayed',()=>{
    expect(MIGRATION).toContain("session_user <> 'saas_schema_migrator'");
    expect(MIGRATION).toContain("current_user <> 'saas_schema_migrator'");
    expect(MIGRATION).toContain("current_database() NOT IN ('saas_staging','saas_staging_ci')");
    expect(MIGRATION).toContain("current_setting('saas.staging_only',true)");
    expect(MIGRATION).toContain("pg_catalog.pg_is_in_recovery()");
    expect(MIGRATION).toContain("current_setting('transaction_read_only') <> 'off'");
    expect(MIGRATION).toContain("1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0");
    expect(MIGRATION).toContain('0007_operator_subject_binding_fence');
    expect(MIGRATION).toContain("VALUES ('0008_exact_subject_session_gate'");
    expect(MIGRATION).toContain("to_regprocedure('saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)')");
    expect(MIGRATION.trimEnd()).toMatch(/COMMIT;$/);
    expect(MIGRATION).not.toMatch(/\bCREATE OR REPLACE FUNCTION\b/);
    expect(MIGRATION).not.toMatch(/\\(?:include|i|ir)\s+.*saas-rls/i);
  });
  test('private function matches exact login, session UUID, binding UUID and subject digest',()=>{
    expect(MIGRATION).toContain('CREATE FUNCTION saas_acl.exact_subject_session_authorized');
    expect(MIGRATION).toContain('SECURITY DEFINER');
    expect(MIGRATION).toContain('SET search_path = pg_catalog, pg_temp');
    expect(MIGRATION).toContain("p_subject_sha256 !~ '^[a-f0-9]{64}$'");
    expect(MIGRATION).toContain('s.session_id=p_session');
    expect(MIGRATION).toContain('s.identity_binding_id=p_binding');
    expect(MIGRATION).toContain('b.binding_id=p_binding');
    expect(MIGRATION).toContain('b.subject_fingerprint=p_subject_sha256');
    expect(MIGRATION).toContain('s.grant_revision=grant_record.access_revision');
    expect(MIGRATION).toContain('b.grant_revision=grant_record.access_revision');
    expect(MIGRATION).toContain("s.revoked_at IS NULL");
    expect(MIGRATION).toContain("b.status='active'");
    expect(MIGRATION).toContain('session_expiry>pg_catalog.clock_timestamp()');
    expect((MIGRATION.match(/\bFOR SHARE\b/g)??[]).length).toBeGreaterThanOrEqual(3);
  });
  test('only narrow EXECUTE, no new data/role/table privilege or current-user GUC auth',()=>{
    expect(MIGRATION).toContain('REVOKE ALL ON FUNCTION');
    expect(MIGRATION).toContain('TO saas_runtime_reader,saas_runtime_writer');
    const live=MIGRATION.split('\n').filter(l=>!l.trimStart().startsWith('--')).join('\n');
    expect(live).not.toMatch(/\bCREATE\s+(?:ROLE|TABLE|DATABASE|SCHEMA)\b/i);
    expect(live).not.toMatch(/\bDROP\s+(?:ROLE|TABLE|DATABASE|SCHEMA)\b/i);
    expect(live).not.toMatch(/\bGRANT\s+(?:SELECT|INSERT|UPDATE|DELETE)\s+ON\b/i);
    expect(live).not.toMatch(/\bALTER\s+(?:ROLE|TABLE|DATABASE|POLICY)\b/i);
    expect(live).not.toMatch(/current_setting\('(tenant_id|saas\.tenant_id|saas\.principal)'/i);
    expect(live).not.toContain('SET ROLE');
  });
  test('real PG16 CI uses isolated two physical LOGINs, lock/revoke/ABA and deny replay',()=>{
    for(const marker of [
      'SAAS_B16_EPHEMERAL_CI','GITHUB_ACTIONS','127.0.0.1',
      'saas_ephemeral_test','saas_staging_ci','saas_b14_person',
      'saas_b16_person_b','B16_EXACT_LOCK_HELD','lock_timeout=150ms',
      'pg_backend_pid()::int','no_early_revoke','old_pair_denied',
      'old_session_stale','b_wrong_tenant','replay-or-db-denied',
      'PASS Backend16.4:',
    ])expect(DRIVER).toContain(marker);
    expect(DRIVER).not.toContain('postgres.railway.internal');
    expect(DRIVER).not.toContain('DATABASE_PUBLIC_URL');
    expect(DRIVER).not.toMatch(/\brailway\s+(?:up|run|redeploy)\b/);
    expect(DRIVER).not.toMatch(/\bBun\.serve\b/);
  });
  test('SQL contract proves eight receipts, definer owner and no runtime table reads',()=>{
    expect(ACCEPTANCE).toContain('saas_staging_ci');
    expect(ACCEPTANCE).toContain('n<>8');
    expect(ACCEPTANCE).toContain('applied_by');
    expect(ACCEPTANCE).toContain('saas_identity.principal_sessions');
    expect(ACCEPTANCE).toContain('saas_identity.subject_bindings');
    expect(ACCEPTANCE).toContain('saas_schema_migrator');
    expect(ACCEPTANCE).toContain('relforcerowsecurity');
    expect(ACCEPTANCE).toContain('has_function_privilege');
    expect(ACCEPTANCE).toContain('PASS Backend16.4:');
  });
});

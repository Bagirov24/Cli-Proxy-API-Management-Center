import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const FILE = new URL('../staging/saas-bootstrap/0006_principal_session_fence.sql', import.meta.url);
const PREVIOUS = new URL('../staging/saas-bootstrap/0005_principal_lifecycle_revocation_fence.sql', import.meta.url);
const SCRIPT = new URL('../scripts/saas-staging/verify-backend14-session-pg16.sh', import.meta.url);
const sql = readFileSync(FILE,'utf8');
const script = readFileSync(SCRIPT,'utf8');

describe('Backend14 private, expiring PG16 session fence',()=>{
  test('attested one-shot migration limited to isolated PG16 migrator',()=>{
    expect(createHash('sha256').update(sql).digest('hex')).toMatch(/^[0-9a-f]{64}$/);
    const oldHash=createHash('sha256').update(readFileSync(PREVIOUS)).digest('hex');
    expect(oldHash).toBe('b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556');
    expect(sql).toContain("current_database() NOT IN ('saas_staging','saas_staging_ci')");
    expect(sql).toContain("session_user <> 'saas_schema_migrator'");
    expect(sql).toContain("current_setting('saas.staging_only',true)");
    expect(sql).toContain("0005_principal_lifecycle_revocation_fence");
    expect(sql).toContain('0006_principal_session_fence');
    expect(sql).toContain(":'expected_0005_sha256'");
    expect(sql).toContain(":'migration_sha256'");
    expect(sql).toContain(":'source_commit'");
    expect(sql).toContain('BEGIN;');
    expect(sql.trimEnd()).toMatch(/COMMIT;$/);
    expect(sql).not.toMatch(/\\(?:include|i|ir)\s+[^;\n]+/i);
    expect(sql).not.toMatch(/DROP\s+(?:TABLE|ROLE|SCHEMA|DATABASE)/i);
  });
  test('DB-authenticated session user and scope revision, never arbitrary claims/GUC',()=>{
    expect(sql).toContain("session_user::name");
    expect(sql).toContain('s.grant_revision=approved_revision');
    expect(sql).toContain('s.expires_at>clock_timestamp()');
    expect(sql).toContain('s.revoked_at IS NULL');
    expect(sql).toMatch(/FROM saas_acl\.principal_tenants x[\s\S]*?FOR SHARE;/);
    expect(sql).toMatch(/FROM saas_identity\.principal_sessions s[\s\S]*?FOR SHARE;/);
    expect(sql).toContain('CREATE UNIQUE INDEX b14_single_unrevoked_login');
    expect(sql).toContain('WHERE revoked_at IS NULL');
    expect(sql).not.toMatch(/current_setting\('saas\.(?:tenant_id|actor_id|id_token|token_digest)'/i);
    expect(sql).not.toMatch(/\bGRANT\s+(?:SELECT|INSERT|UPDATE|DELETE)\s+ON\s+saas_identity/i);
  });
  test('audit is transactional and grant/session changes are CAS and operator-only',()=>{
    expect(sql).toContain('CREATE TABLE saas_identity.principal_sessions');
    expect(sql).toContain('CREATE TABLE saas_identity.session_events');
    expect(sql).toContain('session_revision=session_revision+1');
    expect(sql).toContain('x.access_revision=p_expected_grant_revision');
    expect(sql).toContain("session_user <> 'postgres' OR current_user <> 'postgres'");
    expect(sql).toContain('CREATE TRIGGER b14_session_change_audit');
    expect(sql).toContain('CREATE TRIGGER b14_events_block_changes');
    expect(sql).toContain('CREATE TRIGGER b14_session_block_truncate');
    expect(sql).toContain('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA saas_identity FROM PUBLIC');
    expect(sql).toContain('REVOKE ALL ON ALL TABLES IN SCHEMA saas_identity FROM PUBLIC');
    expect(sql).toContain("p_expires_at > v_now + interval '15 minutes'");
    expect(sql).not.toMatch(/\bCREATE\s+ROLE\b|\bALTER\s+ROLE\s+.*LOGIN\b/i);
    expect(sql).not.toMatch(/\bCREATE\s+POLICY\b/i);
  });
  test('real PostgreSQL acceptance can only run in disposable GH CI',()=>{
    expect(script).toContain('${GITHUB_ACTIONS:-}');
    expect(script).toContain('SAAS_B14_EPHEMERAL_CI');
    expect(script).toContain('PGHOST:-}');
    expect(script).toContain('PGDATABASE:-}');
    expect(script).toContain('127.0.0.1');
    expect(script).toContain('saas_staging_ci');
    expect(script).toContain('PASS Backend14: real PG16');
    expect(script).toContain('B14_READ_LOCK_HELD');
    expect(script).toContain('clock_timestamp()+interval');
    expect(script).toContain('revoke_principal_session');
    expect(script).not.toMatch(/railway\.internal|DATABASE_PUBLIC_URL|Bun\.serve/i);
  });
});

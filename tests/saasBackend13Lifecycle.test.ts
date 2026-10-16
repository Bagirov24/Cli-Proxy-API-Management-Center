import {describe,expect,test} from 'bun:test';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';

const SQL=new URL('../staging/saas-bootstrap/0005_principal_lifecycle_revocation_fence.sql',import.meta.url);
const PRIOR=new URL('../staging/saas-bootstrap/0004_principal_bound_read_rls.sql',import.meta.url);
const RUN=new URL('../scripts/saas-staging/verify-backend13-lifecycle-pg16.sh',import.meta.url);
const CONTRACT=new URL('./sql/saas_backend13_principal_lifecycle.test.sql',import.meta.url);
const sql=readFileSync(SQL,'utf8');
const bash=readFileSync(RUN,'utf8');
const contract=readFileSync(CONTRACT,'utf8');
const hash=(file:URL)=>createHash('sha256').update(readFileSync(file)).digest('hex');

describe('Backend13 PG16 tenant-access lifecycle and revocation fence',()=>{
  test('pins reviewed 0004, never pilots, and leaves migration one-shot',()=>{
    expect(hash(PRIOR)).toBe('4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980');
    expect(sql).toContain('0005_principal_lifecycle_revocation_fence');
    expect(sql).toContain("current_database() NOT IN ('saas_staging','saas_staging_ci')");
    expect(sql).toContain("current_setting('saas.staging_only',true)");
    expect(sql).toContain('source_sha256=current_setting');
    expect(sql).toContain("session_user <> 'saas_schema_migrator'");
    expect(sql).toContain(":'migration_sha256'");
    expect(sql).toContain(":'expected_0004_sha256'");
    expect(sql).toContain(":'source_commit'");
    expect(sql).toContain('BEGIN;');
    expect(sql.trimEnd().endsWith('COMMIT;')).toBe(true);
    expect(sql).not.toMatch(/^\s*\\(?:i|ir|include)\s+/m);
    expect(sql).not.toMatch(/\bCREATE\s+ROLE\b|\bALTER\s+ROLE\b|\bCREATE\s+POLICY\b/i);
    expect(sql).not.toMatch(/DATABASE_PUBLIC_URL|saas_core|api_gateway/i);
  });

  test('monotonic CAS tombstones and exactly one active tenant per login',()=>{
    expect(sql).toContain("CHECK (access_level IN ('reader','writer','revoked'))");
    expect(sql).toContain('principal_one_active_tenant_idx');
    expect(sql).toContain("WHERE access_level IN ('reader','writer')");
    expect(sql).toContain('access_revision=access_revision+1');
    expect(sql).toContain('AND access_revision=p_expected_revision');
    expect(sql).toContain('ON CONFLICT DO NOTHING');
    expect(sql).toContain("RAISE EXCEPTION 'Backend13 stale revision");
    expect(sql).toContain("RAISE EXCEPTION 'Backend13 must revoke using a revisioned tombstone'");
    expect(sql).toContain('RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER');
    expect(sql).toContain("session_user <> 'postgres' OR current_user <> 'postgres'");
    expect(sql).toContain('REVOKE ALL ON FUNCTION saas_acl.change_principal_access');
    expect(sql).toContain('FROM saas_runtime_reader,saas_runtime_writer');
  });

  test('no elevated app write access and DB login is real trusted scope',()=>{
    expect(sql).toContain('RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER');
    expect(sql).toContain('SET search_path = pg_catalog, pg_temp');
    expect(sql).toContain('x.principal_name=session_user::name');
    expect(sql).toContain('FOR SHARE;');
    expect(sql).toContain('AND x.access_level IN'); // forbid access after tombstone
    expect(sql).toContain('NOT r.rolsuper AND NOT r.rolbypassrls');
    expect(sql).not.toMatch(/\bGRANT\s+(?:INSERT|UPDATE|DELETE|TRUNCATE)\s+ON\s+saas_data/i);
    expect(sql).not.toMatch(/current_setting\('saas\.(?:tenant_id|actor_id|principal_id)'/i);
    expect(sql).not.toMatch(/Bun\.serve|createServer|\.listen\(/);
  });

  test('operator audit is atomic, protected from ordinary DML and not claimed WORM',()=>{
    expect(sql).toContain('CREATE TABLE saas_acl.principal_access_audit');
    expect(sql).toContain('pg_catalog.txid_current()');
    expect(sql).toContain('CREATE TRIGGER b13_principal_cas_audit');
    expect(sql).toContain('CREATE TRIGGER b13_audit_no_update_delete');
    expect(sql).toContain('CREATE TRIGGER b13_audit_no_truncate');
    expect(sql).toContain('CREATE TRIGGER b13_principal_no_truncate');
    expect(sql).toContain('NOT WORM');
    expect(sql).not.toContain('PG_OPERATOR_NOT_EXPECTED__');
    expect(contract).toContain('SELECT-only FORCE RLS');
  });

  test('CI-only executable refuses Railway and probes concurrent revocation',()=>{
    expect(bash).toContain("SAAS_B13_EPHEMERAL_CI:-");
    expect(bash).toContain('GITHUB_ACTIONS:-');
    expect(bash).toContain("PGHOST:-");
    expect(bash).toContain("RAILWAY_PROJECT_ID:-");
    expect(bash).toContain('saas_staging_ci');
    expect(bash).toContain('tests/sql/saas_backend13_principal_lifecycle.test.sql');
    expect(bash).toContain('LOCK_HELD');
    expect(bash).toContain('lock_timeout=150ms');
    expect(bash).toContain('audit5');
    expect(bash).toContain('no_stale_a');
    expect(bash).toContain('PASS Backend13: live PG16');
    expect(bash).not.toMatch(/DATABASE_PUBLIC_URL|railway up|railway deploy|kubectl/i);
  });
});

/**
 * Pure source-shape regression guard only. Does NOT replace real PG16 tests.
 * Prevents accidental SQL template duplication, partially spliced functions,
 * missing disposable guard and silent privilege widening during PR edits.
 */
import {readFileSync} from 'node:fs';
import {describe,expect,test} from 'bun:test';

const sql=readFileSync(new URL(
  '../staging/saas-rls/026_durable_project_token_binding_pilot.sql',
  import.meta.url,
),'utf8');
const occurrences=(pattern:RegExp)=>(sql.match(pattern)||[]).length;

describe('SQL026 only disposable PostgreSQL16, exactly one immutable bearer/session gate',()=>{
  test('single transaction and no spliced duplicated SQL after psql final marker',()=>{
    expect(occurrences(/^BEGIN;$/gm)).toBe(1);
    expect(occurrences(/^COMMIT;$/gm)).toBe(1);
    expect(occurrences(/^\\echo 'PASS SQL026:/gm)).toBe(1);
    expect(sql.trimEnd().endsWith(
      "\\echo 'PASS SQL026: one-use NOLOGIN session UUID, immutable bearer link and signed project gate'"
    )).toBe(true);
    expect(sql.includes('\\n--')).toBe(false);
    expect(sql).not.toContain('^[A-Za-z0-9_-]{1,64} The server first');
  });
  test('installs only into exact disposable GitHub PG16 with SQL011 and PG25',()=>{
    expect(sql).toContain("current_database()<>'saas_ephemeral_test'");
    expect(sql).toContain("current_user<>'postgres'");
    expect(sql).toContain("current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'");
    expect(sql).toContain("to_regclass('saas_rls_private.issuer_subject_bindings')");
    expect(sql).toContain("to_regclass('saas_m1_private.project_session_proofs')");
    expect(sql).toContain("to_regprocedure('saas_m1_api.lock_project_session_epoch(uuid,bigint,text,text)')");
    expect(sql).not.toMatch(/^\s*(DROP TABLE|TRUNCATE|DELETE FROM)\b/gim);
  });
  test('one source definition of each security-definer read, issue and trigger routine',()=>{
    for(const name of [
      'pin_project_verified_token_session',
      'issue_verified_project_session',
      'resolve_verified_subject_actor',
      'resolve_verified_project_session',
    ]){
      expect(occurrences(new RegExp(
        'CREATE FUNCTION saas_m1_api\\.'+name+'\\(', 'g'
      ))).toBe(1);
    }
    expect(occurrences(/CREATE FUNCTION saas_m1_private\.require_project_token_binding\(/g))
      .toBe(1);
    expect(occurrences(/CREATE TRIGGER m1_project_token_binding_gate/g)).toBe(1);
    expect(occurrences(/CREATE TRIGGER m1_project_token_never_rebind/g)).toBe(1);
  });
  test('mints server UUID only via NOLOGIN provisioner and immutable unique token key',()=>{
    expect(sql).toContain('minted:=gen_random_uuid()');
    expect(sql).toContain('token_fingerprint TEXT NOT NULL UNIQUE');
    expect(sql).toContain('FOR INSERT TO saas_m1_session_owner WITH CHECK(true)');
    expect(sql).toContain('ENABLE ROW LEVEL SECURITY');
    expect(sql).toContain('FORCE ROW LEVEL SECURITY');
    expect(sql).toContain(
      'GRANT EXECUTE ON FUNCTION saas_m1_api.issue_verified_project_session(text,text,text)'
    );
    expect(sql).toContain(' TO saas_issuer_provisioner;');
    expect(sql).toContain("has_table_privilege('saas_issuer_provisioner',");
    expect(sql).toContain("has_table_privilege('saas_m1_project_executor',");
    expect(sql).toContain('m1_project_token_never_rebind');
  });
  test('mandatory project trigger matches signed bearer SHA256 to SQL025 tx proof',()=>{
    expect(sql).toContain("current_setting('saas.scope_token_fingerprint',true)");
    expect(sql).toContain('saas_rls_private.scope_verified()');
    expect(sql).toContain("p.pg_txid=txid_current()::TEXT");
    expect(sql).toContain('l.token_fingerprint=fp');
    expect(sql).toContain('e.revision=p.session_revision');
    expect(sql).toContain("t.expires_at>statement_timestamp()");
    expect(sql).toContain("b.status='active'");
    expect(sql).toContain('AFTER INSERT OR UPDATE ON saas_m1_private.projects');
  });
});

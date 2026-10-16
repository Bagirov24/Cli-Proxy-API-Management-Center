import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const FOLDER=new URL('../staging/saas-bootstrap/',import.meta.url);
const ROLES=readFileSync(new URL('0003_operator_runtime_roles.sql',FOLDER),'utf8');
const POLICIES=readFileSync(new URL('0004_principal_bound_read_rls.sql',FOLDER),'utf8');
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');

describe('Backend12 isolated PostgreSQL16 role-principal read-only tenant RLS',()=>{
  test('fixed staged migrations and exact prior immutable checksums',()=>{
    expect(sha(ROLES)).toMatch(/^[a-f0-9]{64}$/);
    expect(sha(POLICIES)).toMatch(/^[a-f0-9]{64}$/);
    expect(ROLES).toContain("current_database() NOT IN ('saas_staging','saas_staging_ci')");
    expect(POLICIES).toContain("current_database() NOT IN ('saas_staging','saas_staging_ci')");
    for(const src of [ROLES,POLICIES]){
      expect(src).toContain("current_setting('saas.staging_only', true)");
      expect(src).toContain('BEGIN;');
      expect(src.trimEnd().endsWith('COMMIT;')).toBe(true);
      expect(src).not.toMatch(/\\(?:i|ir|include)\s+.*saas-rls/i);
      expect(src).not.toMatch(/\bCREATE\s+EXTENSION\b|\bDROP\s+ROLE\b/i);
      expect(src).not.toMatch(/\bALTER\s+SYSTEM\b/i);
      expect(src).not.toMatch(/postgres:\/\/|DATABASE_PUBLIC_URL|cliproxyapi-core/i);
    }
    expect(ROLES).toContain("source_sha256 = '7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279'");
    expect(ROLES).toContain("source_sha256 = '80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f'");
  });

  test('roles have no LOGIN and no inheritance, bypass, CREATEROLE or grants',()=>{
    expect(ROLES).toMatch(/CREATE ROLE saas_runtime_reader\s+NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE/);
    expect(ROLES).toMatch(/CREATE ROLE saas_runtime_writer\s+NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE/);
    expect(ROLES).not.toMatch(/\bPASSWORD\b\s*'/);
    expect(ROLES).not.toMatch(/\bGRANT\s+.*TO\s+saas_runtime/i);
  });

  test('principal-bound RLS has no caller-controlled tenant claim',()=>{
    expect(POLICIES).toContain('SECURITY DEFINER');
    expect(POLICIES).toContain('SET search_path = pg_catalog, pg_temp');
    expect(POLICIES).toContain('x.principal_name = session_user::name');
    expect(POLICIES).toContain('AND x.tenant_id = subject_tenant');
    expect(POLICIES).toContain('r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls');
    expect(POLICIES).toContain('REVOKE ALL ON FUNCTION saas_acl.can_read_tenant(uuid) FROM PUBLIC');
    expect(POLICIES).toContain('REVOKE ALL ON saas_acl.principal_tenants FROM PUBLIC');
    expect(POLICIES).not.toMatch(/current_setting\('saas\.(?:tenant_id|actor|scope)'/i);
    expect(POLICIES).not.toMatch(/\bINSERT\s+INTO\s+saas_acl\.principal_tenants\b/i);
    expect(POLICIES).not.toMatch(/\bSECURITY\s+DEFINER\b[\s\S]{0,220}\bEXECUTE\b/i);
  });

  test('only SELECT grants and policies, no runtime write path',()=>{
    expect(POLICIES).toContain('FOR SELECT TO saas_runtime_reader, saas_runtime_writer');
    expect(POLICIES).toContain('GRANT SELECT ON saas_data.tenants, saas_data.projects');
    expect(POLICIES).not.toMatch(/GRANT\s+(?:INSERT|UPDATE|DELETE|TRUNCATE|ALL)\s+ON\s+saas_data/i);
    expect(POLICIES).not.toMatch(/CREATE POLICY [^\n]*\s+FOR (?:INSERT|UPDATE|DELETE|ALL)\b/i);
    expect(POLICIES).not.toMatch(/CREATE\s+ROLE\s+.*\bLOGIN\b/i);
    expect(POLICIES).not.toMatch(/ALTER\s+ROLE\s+.*\bLOGIN\b/i);
    expect(POLICIES).toContain("VALUES ('0004_principal_bound_read_rls'");
  });
});

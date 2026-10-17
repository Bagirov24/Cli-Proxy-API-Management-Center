import {describe,expect,test} from 'bun:test';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {
  createOperatorVerifiedSubjectFingerprintGate,
} from '../src/features/saasBlueprint/controlApi/server/verifiedSubjectBinding';
import type {AccessTokenVerifier} from
  '../src/features/saasBlueprint/controlApi/server/trustedAccessToken';

const ISSUER='https://login.company-synthetic.example.net/realm';
const SUBJECT='ci_subject_A';
const NOW=1800000000;
const good:AccessTokenVerifier={
  async verifyAccessToken(token:string){
    if(token!=='signed-placeholder')return null;
    return {issuer:ISSUER,subject:SUBJECT,expiresAtSeconds:NOW+300};
  },
};
const SQL=readFileSync(
  new URL('../staging/saas-bootstrap/0007_operator_subject_binding_fence.sql',import.meta.url),'utf8'
);
const PG=readFileSync(
  new URL('../scripts/saas-staging/verify-backend15-subject-binding-pg16.sh',import.meta.url),'utf8'
);

describe('Backend15: verified-claims fingerprint preparation (not public auth)',()=>{
  test('fingerprint is reproducible and hides verified issuer/subject in output',async()=>{
    const gate=createOperatorVerifiedSubjectFingerprintGate(good,()=>NOW);
    const r=await gate.verify('signed-placeholder');
    const expected=createHash('sha256').update(
      'saas:issuer-subject:v1\0'+ISSUER+'\0'+SUBJECT,'utf8'
    ).digest('hex');
    expect(r).toEqual({fingerprint:expected,expiresAtSeconds:NOW+300});
    expect(Object.isFrozen(r)).toBe(true);
    expect(JSON.stringify(r)).not.toContain(SUBJECT);
    expect(JSON.stringify(r)).not.toContain(ISSUER);
  });
  test('unknown token, forged TTL or invalid claims refuse with no fallback',async()=>{
    expect(await createOperatorVerifiedSubjectFingerprintGate(good,()=>NOW)
      .verify('forged-token')).toBeNull();
    for(const id of [
      {issuer:'http://idp.example.net/',subject:SUBJECT,expiresAtSeconds:NOW+200},
      {issuer:'https://localhost/',subject:SUBJECT,expiresAtSeconds:NOW+200},
      {issuer:'https://login.company-synthetic.example.net/realm',subject:'a\0b',expiresAtSeconds:NOW+200},
      {issuer:ISSUER,subject:'',expiresAtSeconds:NOW+200},
      {issuer:ISSUER,subject:'bad\nsub',expiresAtSeconds:NOW+200},
      {issuer:ISSUER,subject:SUBJECT,expiresAtSeconds:NOW},
      {issuer:ISSUER,subject:SUBJECT,expiresAtSeconds:NOW+901},
      {issuer:ISSUER,subject:SUBJECT,expiresAtSeconds:undefined},
    ]){
      const verifier:AccessTokenVerifier={verifyAccessToken:async()=>id};
      const gate=createOperatorVerifiedSubjectFingerprintGate(verifier,()=>NOW);
      expect(await gate.verify('signed-placeholder')).toBeNull();
    }
    const thrown:AccessTokenVerifier={verifyAccessToken:async()=>{throw Error('private token');}};
    expect(await createOperatorVerifiedSubjectFingerprintGate(thrown,()=>NOW)
      .verify('signed-placeholder')).toBeNull();
  });
  test('fingerprint changes on issuer OR subject; token is not stored',async()=>{
    const base=(await createOperatorVerifiedSubjectFingerprintGate(good,()=>NOW)
      .verify('signed-placeholder'))!.fingerprint;
    for(const id of [
      {issuer:'https://other.company-synthetic.example.net/',subject:SUBJECT,expiresAtSeconds:NOW+300},
      {issuer:ISSUER,subject:'ci_subject_B',expiresAtSeconds:NOW+300},
    ]){
      const g=createOperatorVerifiedSubjectFingerprintGate({verifyAccessToken:async()=>id},()=>NOW);
      const f=await g.verify('signed-placeholder');
      expect(f?.fingerprint).not.toBe(base);
    }
  });
  test('fenced migration stays operator-owned, immutable and deny-all by default',()=>{
    expect(SQL).toContain("session_user <> 'saas_schema_migrator'");
    expect(SQL).toContain("current_database() NOT IN ('saas_staging','saas_staging_ci')");
    expect(SQL).toContain("current_setting('saas.staging_only',true)");
    expect(SQL).toContain('b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505');
    expect(SQL).toContain("VALUES ('0007_operator_subject_binding_fence'");
    expect(SQL).toContain("REVOKE ALL ON saas_identity.subject_bindings FROM PUBLIC");
    expect(SQL).toContain('UNIQUE INDEX b15_one_active_subject_per_login');
    expect(SQL).toContain('subject_fingerprint text NOT NULL UNIQUE');
    expect(SQL).toContain('CREATE FUNCTION saas_identity.register_subject_binding');
    expect(SQL).toContain('CREATE FUNCTION saas_identity.revoke_subject_binding');
    expect(SQL).toContain('SECURITY INVOKER');
    expect(SQL).toContain('CREATE OR REPLACE FUNCTION saas_identity.issue_principal_session');
    expect(SQL).toContain('CREATE OR REPLACE FUNCTION saas_acl.can_read_tenant');
    expect(SQL).toContain('b.grant_revision=approved_revision');
    expect(SQL).toContain("b.status='active' AND b.revoked_at IS NULL");
    expect(SQL).toContain('FOR SHARE');
    expect(SQL).toContain('AFTER INSERT OR UPDATE ON saas_identity.subject_bindings');
    expect(SQL).toContain('BEFORE TRUNCATE ON saas_identity.subject_binding_events');
    expect(SQL.trimEnd()).toMatch(/COMMIT;$/);
    expect(SQL).not.toMatch(/\bCREATE\s+ROLE\b|\bGRANT\s+(?:SELECT|INSERT|UPDATE|DELETE)\s+ON\s+saas_identity\b/i);
    expect(SQL).not.toMatch(/\\(?:include|i|ir)\s+.*saas-rls/i);
    expect(SQL).not.toMatch(/\bDROP\s+(?:ROLE|TABLE|DATABASE|SCHEMA)\b/i);
  });
  test('real PG16 CI is local-only, checks concurrency, replay and tenant spoofing',()=>{
    expect(PG).toContain('SAAS_B15_EPHEMERAL_CI');
    expect(PG).toContain('GITHUB_ACTIONS');
    expect(PG).toContain('127.0.0.1');
    expect(PG).toContain('saas_staging_ci');
    expect(PG).toContain('B15_BINDING_READ_LOCK_HELD');
    expect(PG).toContain('lock_timeout=150ms');
    expect(PG).toContain('prior_session_still_denied');
    expect(PG).toContain('denied_after_revoke');
    expect(PG).toContain('PASS Backend15:');
    expect(PG).not.toContain('DATABASE_PUBLIC_URL');
    expect(PG).not.toContain('postgres.railway.internal');
    expect(PG).not.toMatch(/Bun\.serve|railway up|railway run/);
  });
});

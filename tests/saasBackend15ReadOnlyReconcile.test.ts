import {describe,expect,test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {
  classifyBackend15Snapshot,
  type Snapshot,
  type Receipt
} from '../scripts/saas-staging/backend15-readonly-reconcile';

const previous=[
  ['0001_ledger_only','7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279'],
  ['0002_tenant_projects_baseline','80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f'],
  ['0003_operator_runtime_roles','8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e'],
  ['0004_principal_bound_read_rls','4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980'],
  ['0005_principal_lifecycle_revocation_fence','b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556'],
  ['0006_principal_session_fence','b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505']
] as const;
const b15Receipt:Receipt={
  migration_id:'0007_operator_subject_binding_fence',
  source_sha256:'1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0',
  source_commit:'6cc4a76a0b3144380ccc95f0ca1c275ae312cae3',
  applied_by:'saas_schema_migrator'
};
const b15Triggers=[
 'b15_binding_audit','b15_binding_events_no_change','b15_binding_events_no_truncate',
 'b15_binding_no_delete','b15_binding_no_truncate'
].join(',');

function fixture():Snapshot{
  return {
    metadata:{
      db:'saas_staging',login:'postgres',ver:160008,read_only:'on',
      replica:false,superuser:true,sealed:true,new_roles:0,memberships:0,safe_runtime_roles:2
    },
    receipts:previous.map(([migration_id,source_sha256])=>({
      migration_id,source_sha256,source_commit:'0'.repeat(40),
      applied_by:'saas_schema_migrator'
    })),
    baseline:{
      tenants:0,projects:0,grants:0,grant_audit:0,sessions:0,session_events:0,
      forced:2,read_policies:2,policies:2,b14_triggers:5,
      reader_data:true,writer_data:true,reader_writes:false,writer_writes:false,
      reader_identity:false,writer_identity:false,
      acl_fence:true,identity_foreign_acl:0,data_foreign_acl:0
    },
    objects:{bindings:false,events:false,enroll:false,revoke:false},
    installed:null
  };
}
function applied():Snapshot{
 const x=fixture();
 x.receipts.push({...b15Receipt});
 x.objects={bindings:true,events:true,enroll:true,revoke:true};
 x.installed={
   bindings_rows:0,events_rows:0,b15_triggers:b15Triggers,
   unique_indexes:3,revoke_constraint:1,operators:3,definers:2,
   binding_fence:true,reader_bindings:false,writer_binding_events:false,
   reader_enroll:false,writer_revoke:false
 };
 return x;
}

describe('Backend15 readonly catalog reconciliation (NO migrations, NO Railway)',()=>{
 test('classifies verified six-receipt baseline as ABSENT without write',()=>{
   expect(classifyBackend15Snapshot(fixture())).toBe('absent');
 });
 test('classifies full seven-receipt identity fence as INSTALLED',()=>{
   expect(classifyBackend15Snapshot(applied())).toBe('installed');
 });
 test('refuses replay ambiguity, missing receipts and hash mismatch',()=>{
   const x=fixture();x.receipts.pop();
   expect(classifyBackend15Snapshot(x)).toBe('stop');
   const y=applied();y.receipts[6].source_sha256='f'.repeat(64);
   expect(classifyBackend15Snapshot(y)).toBe('stop');
   const z=applied();z.receipts[6].source_commit='a'.repeat(40);
   expect(classifyBackend15Snapshot(z)).toBe('stop');
   const v=fixture();v.receipts.push({...b15Receipt});
   expect(classifyBackend15Snapshot(v)).toBe('stop');
 });
 test('refuses unknown COMMIT half-state: object exists but only six receipts',()=>{
   const x=fixture();x.objects.bindings=true;
   expect(classifyBackend15Snapshot(x)).toBe('stop');
   const y=applied();y.objects.events=false;
   expect(classifyBackend15Snapshot(y)).toBe('stop');
 });
 test('refuses unsealed migrator, wrong database, PG version, role or transaction',()=>{
   const modifications=[
     (s:Snapshot)=>{s.metadata.sealed=false;},
     (s:Snapshot)=>{s.metadata.db='saas_staging_ci';},
     (s:Snapshot)=>{s.metadata.ver=170000;},
     (s:Snapshot)=>{s.metadata.login='saas_schema_migrator';},
     (s:Snapshot)=>{s.metadata.read_only='off';},
     (s:Snapshot)=>{s.metadata.superuser=false;},
     (s:Snapshot)=>{s.metadata.replica=true;},
     (s:Snapshot)=>{s.metadata.new_roles=1;},
     (s:Snapshot)=>{s.metadata.memberships=1;},
     (s:Snapshot)=>{s.metadata.safe_runtime_roles=1;}
   ];
   for(const modify of modifications){
     const snap=fixture();modify(snap);
     expect(classifyBackend15Snapshot(snap)).toBe('stop');
   }
 });
 test('refuses data rows, privilege drift, and disabled FORCE RLS',()=>{
   const modify=[
     (s:Snapshot)=>{s.baseline.tenants=1;},
     (s:Snapshot)=>{s.baseline.projects=1;},
     (s:Snapshot)=>{s.baseline.sessions=1;},
     (s:Snapshot)=>{s.baseline.grant_audit=1;},
     (s:Snapshot)=>{s.baseline.forced=1;},
     (s:Snapshot)=>{s.baseline.policies=1;},
     (s:Snapshot)=>{s.baseline.b14_triggers=4;},
     (s:Snapshot)=>{s.baseline.reader_identity=true;},
     (s:Snapshot)=>{s.baseline.writer_identity=true;},
     (s:Snapshot)=>{s.baseline.identity_foreign_acl=1;},
     (s:Snapshot)=>{s.baseline.data_foreign_acl=1;},
     (s:Snapshot)=>{s.baseline.reader_writes=true;},
     (s:Snapshot)=>{s.baseline.writer_writes=true;},
     (s:Snapshot)=>{s.baseline.acl_fence=false;}
   ];
   for(const m of modify){const x=applied();m(x);expect(classifyBackend15Snapshot(x)).toBe('stop');}
 });
 test('refuses missing audit triggers, RLS fence, weak ACL or dirty bindings',()=>{
   const modify=[
     (s:Snapshot)=>{s.installed!.bindings_rows=1;},
     (s:Snapshot)=>{s.installed!.events_rows=1;},
     (s:Snapshot)=>{s.installed!.b15_triggers='b15_binding_audit';},
     (s:Snapshot)=>{s.installed!.unique_indexes=2;},
     (s:Snapshot)=>{s.installed!.revoke_constraint=0;},
     (s:Snapshot)=>{s.installed!.operators=2;},
     (s:Snapshot)=>{s.installed!.definers=1;},
     (s:Snapshot)=>{s.installed!.binding_fence=false;},
     (s:Snapshot)=>{s.installed!.reader_bindings=true;},
     (s:Snapshot)=>{s.installed!.writer_binding_events=true;},
     (s:Snapshot)=>{s.installed!.reader_enroll=true;},
     (s:Snapshot)=>{s.installed!.writer_revoke=true;}
   ];
   for(const m of modify){const x=applied();m(x);expect(classifyBackend15Snapshot(x)).toBe('stop');}
 });
 test('source preserves read-only transaction and non-deployment boundaries',()=>{
   const source=readFileSync(
     new URL('../scripts/saas-staging/backend15-readonly-reconcile.ts',import.meta.url),'utf8');
   const compiled=new Bun.Transpiler({loader:'ts',target:'bun'}).transformSync(source);
   expect(compiled).toContain('PASS_BACKEND15_READONLY_RECONCILE_0007_INSTALLED_SEALED_NOLOGIN');
   expect(source).toContain('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
   expect(source).toContain("default_transaction_read_only=on");
   expect(source).toContain("e.SAAS_B15_APPLY_EXPLICIT_ENABLE==='true'");
   expect(source).toContain("url.hostname!=='postgres.railway.internal'");
   expect(source).toContain("url.pathname!=='/saas_staging'");
   expect(source).toContain("RAILWAY_SERVICE_NAME!=='saas-b15-reconcile-readonly-once'");
   expect(source).toContain("BACKEND15_READONLY_RECONCILE_STOP_MANUAL_REVIEW_NEVER_REPLAY");
   expect(source).not.toMatch(/Bun\.serve|createServer|\.listen\(|setInterval|cronSchedule|DATABASE_PUBLIC_URL/);
   expect(source).not.toMatch(/await client\.query\(['"](?:ALTER|CREATE|INSERT|UPDATE|DELETE|DROP|TRUNCATE)\b/i);
 });
});

/**
 * Backend15: independently observe staging SQL0007 without ever installing it.
 *
 * Read-only reconciliation of a lost/unknown migration COMMIT:
 *  - no DDL, ALTER ROLE, credentials rotation, retry or HTTP listener;
 *  - BEGIN ... REPEATABLE READ READ ONLY, exact private Railway DB;
 *  - prints only a strictly validated state marker; no tenant/subject data.
 *
 * Never turn an "installed" marker into permission to replay SQL0007.
 * This CLI is not the installer or a replacement for human review.
 */
const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENV='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const PG_SERVICE='37f8f166-75a6-4617-b243-8e681181c16d';
const SQL_SHA='1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0';
const SOURCE_COMMIT='6cc4a76a0b3144380ccc95f0ca1c275ae312cae3';
const PREVIOUS=[
  ['0001_ledger_only','7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279'],
  ['0002_tenant_projects_baseline','80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f'],
  ['0003_operator_runtime_roles','8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e'],
  ['0004_principal_bound_read_rls','4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980'],
  ['0005_principal_lifecycle_revocation_fence','b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556'],
  ['0006_principal_session_fence','b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505'],
] as const;

export type Receipt={migration_id:string;source_sha256:string;source_commit:string;applied_by:string};
export type Metadata={
  db:string;login:string;ver:number;read_only:string;replica:boolean;superuser:boolean;
  sealed:boolean;new_roles:number;memberships:number;safe_runtime_roles:number;
};
export type Baseline={
  tenants:number;projects:number;grants:number;grant_audit:number;
  sessions:number;session_events:number;
  forced:number;read_policies:number;policies:number;b14_triggers:number;
  reader_data:boolean;writer_data:boolean;reader_writes:boolean;writer_writes:boolean;
  reader_identity:boolean;writer_identity:boolean;
  acl_fence:boolean;identity_foreign_acl:number;data_foreign_acl:number;
};
export type Objects={bindings:boolean;events:boolean;enroll:boolean;revoke:boolean};
export type Installed={
  bindings_rows:number;events_rows:number;b15_triggers:string|null;
  unique_indexes:number;revoke_constraint:number;operators:number;definers:number;
  binding_fence:boolean;reader_bindings:boolean;writer_binding_events:boolean;
  reader_enroll:boolean;writer_revoke:boolean;
};
export type Snapshot={
  metadata:Metadata; baseline:Baseline; objects:Objects;
  receipts:Receipt[]; installed?:Installed|null;
};
export type Verdict='absent'|'installed'|'stop';
const B15_TRIGGERS=[
  'b15_binding_audit','b15_binding_events_no_change',
  'b15_binding_events_no_truncate','b15_binding_no_delete','b15_binding_no_truncate'
].join(',');

/** Pure, strict and intentionally conservative: every ambiguity is STOP. */
export function classifyBackend15Snapshot(s:Snapshot):Verdict {
  const m=s.metadata,b=s.baseline,o=s.objects;
  if(!m||!b||!o||!Array.isArray(s.receipts))return 'stop';
  if(m.db!=='saas_staging'||m.login!=='postgres'||
     !Number.isInteger(m.ver)||m.ver<160000||m.ver>=170000||
     m.read_only!=='on'||m.replica!==false||m.superuser!==true||
     m.sealed!==true||m.new_roles!==0||m.memberships!==0||
     m.safe_runtime_roles!==2)return 'stop';
  if(b.tenants!==0||b.projects!==0||b.grants!==0||b.grant_audit!==0||
     b.sessions!==0||b.session_events!==0||b.forced!==2||
     b.read_policies!==2||b.policies!==2||b.b14_triggers!==5||
     b.reader_data!==true||b.writer_data!==true||
     b.reader_writes!==false||b.writer_writes!==false||
     b.reader_identity!==false||b.writer_identity!==false||
     b.acl_fence!==true||b.identity_foreign_acl!==0||
     b.data_foreign_acl!==0)return 'stop';
  if(s.receipts.length!==6 && s.receipts.length!==7)return 'stop';
  for(let i=0;i<PREVIOUS.length;i++){
    const r=s.receipts[i];
    if(!r||r.migration_id!==PREVIOUS[i][0]||
       r.source_sha256!==PREVIOUS[i][1]||
       r.applied_by!=='saas_schema_migrator')return 'stop';
  }
  if(s.receipts.length===6){
    return !o.bindings&&!o.events&&!o.enroll&&!o.revoke&&
      s.installed==null?'absent':'stop';
  }
  const r=s.receipts[6],a=s.installed;
  if(!r||r.migration_id!=='0007_operator_subject_binding_fence'||
     r.source_sha256!==SQL_SHA||r.source_commit!==SOURCE_COMMIT||
     r.applied_by!=='saas_schema_migrator'||
     !o.bindings||!o.events||!o.enroll||!o.revoke||!a)return 'stop';
  if(a.bindings_rows!==0||a.events_rows!==0||
     a.b15_triggers!==B15_TRIGGERS||a.unique_indexes!==3||
     a.revoke_constraint!==1||a.operators!==3||a.definers!==2||
     a.binding_fence!==true||a.reader_bindings!==false||
     a.writer_binding_events!==false||a.reader_enroll!==false||
     a.writer_revoke!==false)return 'stop';
  return 'installed';
}

/** Only a separate private staging CLI/one-shot operator service may run it. */
function environment():URL {
  const e=process.env;
  if(e.RAILWAY_PROJECT_ID!==PROJECT||e.RAILWAY_ENVIRONMENT_ID!==ENV||
     e.RAILWAY_ENVIRONMENT_NAME!=='staging'||
     e.RAILWAY_SERVICE_NAME!=='saas-b15-reconcile-readonly-once'||
     !/^[0-9a-f-]{36}$/.test(e.RAILWAY_SERVICE_ID||'')||
     e.RAILWAY_SERVICE_ID===PG_SERVICE||
     e.SAAS_B15_READONLY_RECONCILE_ENABLE!=='true'||
     e.SAAS_B15_APPLY_EXPLICIT_ENABLE==='true'||
     e.GITHUB_ACTIONS==='true')throw Error('reconciliation environment refused');
  const raw=e.STAGING_POSTGRES_PRIVATE_URL;
  if(!raw||raw.length<35||raw.length>1024)throw Error('DB URL refused');
  let url:URL;try{url=new URL(raw);}catch{throw Error('DB URL refused');}
  if(!['postgres:','postgresql:'].includes(url.protocol)||
     url.hostname!=='postgres.railway.internal'||url.port!=='5432'||
     url.pathname!=='/saas_staging'||decodeURIComponent(url.username)!=='postgres'||
     !url.password||url.search||url.hash)throw Error('private DB URL refused');
  return url;
}

async function collect(client:{query:(sql:string)=>Promise<{rows:any[]}>}):Promise<Snapshot>{
  const metadata=(await client.query(
    "SELECT current_database() AS db,session_user AS login,"+
    "current_setting('server_version_num')::int AS ver,"+
    "current_setting('transaction_read_only') AS read_only,"+
    "pg_is_in_recovery() AS replica,"+
    "(SELECT rolsuper FROM pg_roles WHERE rolname=session_user) AS superuser,"+
    "(SELECT NOT rolcanlogin AND rolpassword IS NULL AND NOT ("+
      "rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication) "+
      "FROM pg_authid WHERE rolname='saas_schema_migrator') AS sealed,"+
    "(SELECT count(*)::int FROM pg_roles WHERE left(rolname,5)='saas_' "+
      "AND rolname NOT IN ('saas_schema_migrator','saas_runtime_reader','saas_runtime_writer')) AS new_roles,"+
    "(SELECT count(*)::int FROM pg_authid WHERE rolname IN "+
      "('saas_runtime_reader','saas_runtime_writer') AND "+
      "NOT rolcanlogin AND NOT rolinherit AND rolpassword IS NULL "+
      "AND NOT (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)) AS safe_runtime_roles,"+
    "(SELECT count(*)::int FROM pg_auth_members WHERE roleid IN "+
      "(SELECT oid FROM pg_roles WHERE left(rolname,5)='saas_') OR member IN "+
      "(SELECT oid FROM pg_roles WHERE left(rolname,5)='saas_')) AS memberships"
  )).rows[0];
  if(!metadata||metadata.db!=='saas_staging'||metadata.login!=='postgres'||
     metadata.ver<160000||metadata.ver>=170000||metadata.read_only!=='on'||
     metadata.superuser!==true||metadata.replica!==false)throw Error('non-staging snapshot');

  const receipts=(await client.query(
    'SELECT migration_id,source_sha256,source_commit,applied_by '+
    'FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  )).rows as Receipt[];
  const baseline=(await client.query(
    "SELECT "+
    "(SELECT count(*)::int FROM saas_data.tenants) AS tenants,"+
    "(SELECT count(*)::int FROM saas_data.projects) AS projects,"+
    "(SELECT count(*)::int FROM saas_acl.principal_tenants) AS grants,"+
    "(SELECT count(*)::int FROM saas_acl.principal_access_audit) AS grant_audit,"+
    "(SELECT count(*)::int FROM saas_identity.principal_sessions) AS sessions,"+
    "(SELECT count(*)::int FROM saas_identity.session_events) AS session_events,"+
    "(SELECT count(*)::int FROM pg_class WHERE oid IN "+
      "('saas_data.tenants'::regclass,'saas_data.projects'::regclass) "+
      "AND relrowsecurity AND relforcerowsecurity) AS forced,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN "+
      "('saas_data.tenants'::regclass,'saas_data.projects'::regclass) AND polcmd='r') AS read_policies,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN "+
      "('saas_data.tenants'::regclass,'saas_data.projects'::regclass)) AS policies,"+
    "(SELECT count(*)::int FROM pg_trigger WHERE tgrelid IN "+
      "('saas_identity.principal_sessions'::regclass,'saas_identity.session_events'::regclass) "+
      "AND NOT tgisinternal AND tgenabled='O') AS b14_triggers,"+
    "has_table_privilege('saas_runtime_reader','saas_data.tenants','SELECT') "+
      "AND has_table_privilege('saas_runtime_reader','saas_data.projects','SELECT') AS reader_data,"+
    "has_table_privilege('saas_runtime_writer','saas_data.tenants','SELECT') "+
      "AND has_table_privilege('saas_runtime_writer','saas_data.projects','SELECT') AS writer_data,"+
    "has_table_privilege('saas_runtime_reader','saas_data.tenants','INSERT, UPDATE, DELETE, TRUNCATE') "+
      "OR has_table_privilege('saas_runtime_reader','saas_data.projects','INSERT, UPDATE, DELETE, TRUNCATE') AS reader_writes,"+
    "has_table_privilege('saas_runtime_writer','saas_data.tenants','INSERT, UPDATE, DELETE, TRUNCATE') "+
      "OR has_table_privilege('saas_runtime_writer','saas_data.projects','INSERT, UPDATE, DELETE, TRUNCATE') AS writer_writes,"+
    "has_schema_privilege('saas_runtime_reader','saas_identity','USAGE') AS reader_identity,"+
    "has_schema_privilege('saas_runtime_writer','saas_identity','USAGE') AS writer_identity,"+
    "(SELECT prosecdef AND provolatile='v' "+
       "AND pg_get_userbyid(proowner)='saas_schema_migrator' "+
       "FROM pg_proc WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure) AS acl_fence,"+
    "(SELECT count(*)::int FROM ("+
      "SELECT c.oid,c.relowner,c.relacl FROM pg_class c "+
        "JOIN pg_namespace n ON n.oid=c.relnamespace "+
        "WHERE n.nspname='saas_identity' AND c.relkind IN ('r','p')"+
      ") c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a "+
      "WHERE a.grantee<>c.relowner) + "+
    "(SELECT count(*)::int FROM pg_proc p "+
      "JOIN pg_namespace n ON n.oid=p.pronamespace "+
      "CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a "+
      "WHERE n.nspname='saas_identity' AND a.grantee<>p.proowner) AS identity_foreign_acl,"+
    "(SELECT count(*)::int FROM pg_class c "+
      "JOIN pg_namespace n ON n.oid=c.relnamespace "+
      "CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a "+
      "WHERE (n.nspname='saas_data' OR n.nspname='saas_acl') "+
      "AND c.relkind IN ('r','p') "+
      "AND a.grantee NOT IN (SELECT oid FROM pg_roles WHERE rolname IN "+
      "('saas_schema_migrator','saas_runtime_reader','saas_runtime_writer'))) AS data_foreign_acl"
  )).rows[0] as Baseline;
  const objects=(await client.query(
    "SELECT "+
    "(to_regclass('saas_identity.subject_bindings') IS NOT NULL) AS bindings,"+
    "(to_regclass('saas_identity.subject_binding_events') IS NOT NULL) AS events,"+
    "(to_regprocedure('saas_identity.register_subject_binding(name,uuid,bigint,text,text)') IS NOT NULL) AS enroll,"+
    "(to_regprocedure('saas_identity.revoke_subject_binding(uuid,bigint,text)') IS NOT NULL) AS revoke"
  )).rows[0] as Objects;
  if(!baseline||!objects)throw Error('missing snapshot');
  let installed:Installed|null=null;
  // Never query an object that may not exist; any half-state classifies STOP.
  if(objects.bindings&&objects.events&&objects.enroll&&objects.revoke){
    installed=(await client.query(
      "SELECT "+
      "(SELECT count(*)::int FROM saas_identity.subject_bindings) AS bindings_rows,"+
      "(SELECT count(*)::int FROM saas_identity.subject_binding_events) AS events_rows,"+
      "(SELECT string_agg(tgname,',' ORDER BY tgname) FROM pg_trigger WHERE "+
        "tgrelid IN ('saas_identity.subject_bindings'::regclass,"+
        "'saas_identity.subject_binding_events'::regclass) "+
        "AND NOT tgisinternal AND tgenabled='O') AS b15_triggers,"+
      "(SELECT count(*)::int FROM pg_index "+
        "WHERE indrelid='saas_identity.subject_bindings'::regclass AND indisunique) AS unique_indexes,"+
      "(SELECT count(*)::int FROM pg_constraint "+
        "WHERE conrelid='saas_identity.subject_bindings'::regclass "+
        "AND conname='b15_revoke_marker') AS revoke_constraint,"+
      "(SELECT count(*)::int FROM pg_proc WHERE oid IN "+
        "('saas_identity.register_subject_binding(name,uuid,bigint,text,text)'::regprocedure,"+
         "'saas_identity.revoke_subject_binding(uuid,bigint,text)'::regprocedure,"+
         "'saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)'::regprocedure) "+
        "AND NOT prosecdef AND provolatile='v' AND "+
        "pg_get_userbyid(proowner)='saas_schema_migrator') AS operators,"+
      "(SELECT count(*)::int FROM pg_proc WHERE oid IN "+
        "('saas_identity.audit_subject_binding_transition()'::regprocedure,"+
         "'saas_acl.can_read_tenant(uuid)'::regprocedure) "+
        "AND prosecdef AND provolatile='v' AND "+
        "pg_get_userbyid(proowner)='saas_schema_migrator') AS definers,"+
      "(SELECT pg_get_functiondef('saas_acl.can_read_tenant(uuid)'::regprocedure) "+
        "LIKE '%saas_identity.subject_bindings%') AS binding_fence,"+
      "has_table_privilege('saas_runtime_reader','saas_identity.subject_bindings','SELECT') AS reader_bindings,"+
      "has_table_privilege('saas_runtime_writer','saas_identity.subject_binding_events','SELECT') AS writer_binding_events,"+
      "has_function_privilege('saas_runtime_reader',"+
        "'saas_identity.register_subject_binding(name,uuid,bigint,text,text)','EXECUTE') AS reader_enroll,"+
      "has_function_privilege('saas_runtime_writer',"+
        "'saas_identity.revoke_subject_binding(uuid,bigint,text)','EXECUTE') AS writer_revoke"
    )).rows[0] as Installed;
  }
  return {metadata,receipts,baseline,objects,installed};
}

async function run():Promise<void>{
  const u=environment();
  // Runtime dependency loaded only on explicit execution; unit tests do not connect.
  const pg=(await import('pg@8.16.3')).default;
  const client=new pg.Client({
    connectionString:u.toString(),
    options:'-c default_transaction_read_only=on -c saas.staging_only=true',
    connectionTimeoutMillis:6000,query_timeout:20000,statement_timeout:15000,
    application_name:'saas-b15-readonly-reconcile'
  });
  let connected=false;
  try {
    await client.connect();connected=true;
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const verdict=classifyBackend15Snapshot(await collect(client));
    await client.query('COMMIT');
    if(verdict==='absent'){
      console.info('PASS_BACKEND15_READONLY_RECONCILE_0007_ABSENT_SEALED_NOLOGIN');
    }else if(verdict==='installed'){
      console.info('PASS_BACKEND15_READONLY_RECONCILE_0007_INSTALLED_SEALED_NOLOGIN');
    }else{
      throw Error('unexpected catalog state; manual review');
    }
  }finally{
    if(connected){try{await client.end();}catch{/* no write/retry */}}
  }
}
if(import.meta.main){
  try{await run();}
  catch{
    // Never log SQL, role password, DB URL, bearer, tenant ids or SQL errors.
    console.error('BACKEND15_READONLY_RECONCILE_STOP_MANUAL_REVIEW_NEVER_REPLAY');
    process.exitCode=1;
  }
}

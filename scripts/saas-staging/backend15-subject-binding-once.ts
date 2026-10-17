/**
 * Backend15 Phase B: one-shot, private Railway PostgreSQL16 SQL 0007 installer.
 * Only the isolated disposable SaaS staging project. No HTTP, cron or retry.
 * A failed/unknown COMMIT is operator-reconciled; this code never replays 0007.
 * Production Core/Gateway, identity provisioning and user records are out of scope.
 */
import pg from 'pg@8.16.3';

const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENV='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const DB_SERVICE='37f8f166-75a6-4617-b243-8e681181c16d';
const RUNNER='saas-b15-binding-once';
const COMMIT='6cc4a76a0b3144380ccc95f0ca1c275ae312cae3';
const SQL_FILE='0007_operator_subject_binding_fence.sql';
const SQL_SHA='1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0';
const PREVIOUS=[
  ['0001_ledger_only','7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279'],
  ['0002_tenant_projects_baseline','80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f'],
  ['0003_operator_runtime_roles','8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e'],
  ['0004_principal_bound_read_rls','4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980'],
  ['0005_principal_lifecycle_revocation_fence','b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556'],
  ['0006_principal_session_fence','b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505'],
] as const;
const STOP='BACKEND15_STOP_UNKNOWN_COMMIT_RECONCILE_NEVER_RETRY';

function refuse():never {throw new Error('Backend15 staging installer refused');}
function isHex(s:string,n:number):boolean {
  return new RegExp('^[a-f0-9]{'+n+'}$').test(s);
}
function environment():URL {
  const e=process.env;
  if(e.RAILWAY_PROJECT_ID!==PROJECT ||
     e.RAILWAY_ENVIRONMENT_ID!==ENV ||
     e.RAILWAY_ENVIRONMENT_NAME!=='staging' ||
     e.RAILWAY_SERVICE_NAME!==RUNNER ||
     !e.RAILWAY_SERVICE_ID ||
     !/^[0-9a-f-]{36}$/.test(e.RAILWAY_SERVICE_ID) ||
     e.RAILWAY_SERVICE_ID===DB_SERVICE ||
     e.SAAS_B15_APPLY_EXPLICIT_ENABLE!=='true' ||
     e.SAAS_B15_ACCEPT_DISPOSABLE_STAGING!=='true' ||
     e.GITHUB_ACTIONS==='true')refuse();
  const raw=e.STAGING_POSTGRES_PRIVATE_URL;
  if(typeof raw!=='string' || raw.length<35 || raw.length>1024)refuse();
  let u:URL;
  try {u=new URL(raw);} catch {refuse();}
  if(!['postgres:','postgresql:'].includes(u.protocol) ||
     u.hostname!=='postgres.railway.internal' ||
     u.port!=='5432' || u.pathname!=='/saas_staging' ||
     decodeURIComponent(u.username)!=='postgres' || !u.password ||
     u.search || u.hash)refuse();
  return u;
}

/** Verify immutable GitHub bytes BEFORE making ANY database connection. */
async function source():Promise<string> {
  if(!isHex(COMMIT,40)||!isHex(SQL_SHA,64))refuse();
  const url='https://raw.githubusercontent.com/Bagirov24/' +
    'Cli-Proxy-API-Management-Center/'+COMMIT+
    '/staging/saas-bootstrap/'+SQL_FILE;
  const r=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(12000)});
  if(!r.ok||r.url!==url)refuse();
  const bytes=new Uint8Array(await r.arrayBuffer());
  if(bytes.byteLength<18000||bytes.byteLength>20000)refuse();
  const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))]
    .map(x=>x.toString(16).padStart(2,'0')).join('');
  if(digest!==SQL_SHA)refuse();
  const body=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const directives=body.split('\n').filter(line=>/^\s*\\/.test(line));
  if(directives.length!==1 || directives[0].trim()!=='\\set ON_ERROR_STOP on' ||
     !body.includes('BEGIN;') || !body.trimEnd().endsWith('COMMIT;') ||
     !body.includes("VALUES ('0007_operator_subject_binding_fence'"))refuse();
  return body.replace(/^\\set ON_ERROR_STOP on\s*$/m,'');
}

/** Only a fixed set of attestation values may be substituted for psql literals. */
function bind(sql:string, values:Record<string,string>):string {
  const keys=new Set<string>();
  for(const v of Object.values(values))
    if(![40,64].includes(v.length)||!isHex(v,v.length))refuse();
  const bound=sql.replace(/:'([a-z_0-9]+)'/g,(_unused,k:string)=>{
    if(!Object.prototype.hasOwnProperty.call(values,k))refuse();
    keys.add(k);return "'"+values[k]+"'";
  });
  if(Object.keys(values).some(k=>!keys.has(k)) ||
     /:'[a-z_0-9]+'/i.test(bound) || /^\s*\\/m.test(bound))refuse();
  return bound;
}
function client(url:URL){
  return new pg.Client({
    connectionString:url.toString(),
    options:'-c saas.staging_only=true',
    connectionTimeoutMillis:6000,
    query_timeout:45000,
    statement_timeout:20000,
    application_name:'saas-backend15-one-shot-0007',
  });
}

async function preflight(admin:InstanceType<typeof pg.Client>) {
  const r=await admin.query(
    "SELECT current_database() AS db, session_user AS login,"+
    "current_setting('server_version_num')::int AS ver,"+
    "current_setting('transaction_read_only') AS read_only, pg_is_in_recovery() AS replica,"+
    "(SELECT rolsuper FROM pg_roles WHERE rolname=session_user) AS superuser,"+
    "(SELECT rolcanlogin FROM pg_roles WHERE rolname='saas_schema_migrator') AS migrator_login,"+
    "(SELECT rolpassword IS NULL FROM pg_authid WHERE rolname='saas_schema_migrator') AS migrator_no_password,"+
    "(SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication "+
      "FROM pg_roles WHERE rolname='saas_schema_migrator') AS migrator_privileged,"+
    "(SELECT count(*)::int FROM pg_roles WHERE left(rolname,5)='saas_' "+
      "AND rolname NOT IN ('saas_schema_migrator','saas_runtime_reader','saas_runtime_writer')) AS new_roles,"+
    "(SELECT count(*)::int FROM pg_auth_members WHERE roleid IN "+
      "(SELECT oid FROM pg_roles WHERE left(rolname,5)='saas_') OR member IN "+
      "(SELECT oid FROM pg_roles WHERE left(rolname,5)='saas_')) AS memberships,"+
    "(SELECT count(*)::int FROM pg_stat_activity WHERE datname=current_database() "+
      "AND pid<>pg_backend_pid() AND backend_type='client backend') AS other_connections"
  );
  const x=r.rows[0];
  if(r.rows.length!==1||x.db!=='saas_staging'||x.login!=='postgres'||
     x.ver<160000||x.ver>=170000||x.read_only!=='off'||x.replica!==false||
     x.superuser!==true||x.migrator_login!==false||
     x.migrator_no_password!==true||x.migrator_privileged!==false||
     +x.new_roles!==0||+x.memberships!==0||+x.other_connections!==0)refuse();

  const receipts=await admin.query(
    'SELECT migration_id,source_sha256,applied_by FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  );
  if(receipts.rows.length!==PREVIOUS.length ||
     !receipts.rows.every((v,i)=>v.migration_id===PREVIOUS[i][0]&&
       v.source_sha256===PREVIOUS[i][1]&&v.applied_by==='saas_schema_migrator'))refuse();

  const structure=await admin.query(
    "SELECT "+
    "(to_regclass('saas_identity.subject_bindings') IS NULL) AS no_bindings,"+
    "(to_regclass('saas_identity.subject_binding_events') IS NULL) AS no_events,"+
    "(to_regprocedure('saas_identity.register_subject_binding(name,uuid,bigint,text,text)') IS NULL) AS no_enroll,"+
    "(to_regprocedure('saas_identity.revoke_subject_binding(uuid,bigint,text)') IS NULL) AS no_revoke,"+
    "(SELECT count(*)::int FROM saas_data.tenants) AS tenants,"+
    "(SELECT count(*)::int FROM saas_data.projects) AS projects,"+
    "(SELECT count(*)::int FROM saas_acl.principal_tenants) AS grants,"+
    "(SELECT count(*)::int FROM saas_acl.principal_access_audit) AS grant_audit,"+
    "(SELECT count(*)::int FROM saas_identity.principal_sessions) AS sessions,"+
    "(SELECT count(*)::int FROM saas_identity.session_events) AS session_events,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN "+
      "('saas_data.tenants'::regclass,'saas_data.projects'::regclass) AND polcmd='r') AS read_policies,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN "+
      "('saas_data.tenants'::regclass,'saas_data.projects'::regclass)) AS policies,"+
    "(SELECT count(*)::int FROM pg_class WHERE oid IN "+
      "('saas_data.tenants'::regclass,'saas_data.projects'::regclass) "+
      "AND relrowsecurity AND relforcerowsecurity) AS forced,"+
    "(SELECT count(*)::int FROM pg_trigger WHERE tgrelid IN "+
      "('saas_identity.principal_sessions'::regclass,'saas_identity.session_events'::regclass) "+
      "AND NOT tgisinternal AND tgenabled='O') AS b14_triggers"
  );
  const s=structure.rows[0];
  if(structure.rows.length!==1||!s.no_bindings||!s.no_events||!s.no_enroll||!s.no_revoke||
     +s.tenants!==0||+s.projects!==0||+s.grants!==0||+s.grant_audit!==0||
     +s.sessions!==0||+s.session_events!==0||
     +s.read_policies!==2||+s.policies!==2||+s.forced!==2||
     +s.b14_triggers!==5)refuse();

  const perms=await admin.query(
    "SELECT "+
    "has_table_privilege('saas_runtime_reader','saas_data.tenants','SELECT') AS reader_tenants,"+
    "has_table_privilege('saas_runtime_reader','saas_data.projects','SELECT') AS reader_projects,"+
    "has_table_privilege('saas_runtime_writer','saas_data.tenants','SELECT') AS writer_tenants,"+
    "has_table_privilege('saas_runtime_writer','saas_data.projects','SELECT') AS writer_projects,"+
    "has_schema_privilege('saas_runtime_reader','saas_identity','USAGE') AS reader_identity,"+
    "has_schema_privilege('saas_runtime_writer','saas_identity','USAGE') AS writer_identity,"+
    "has_table_privilege('saas_runtime_reader','saas_identity.principal_sessions','SELECT') AS reader_sessions,"+
    "has_table_privilege('saas_runtime_writer','saas_identity.session_events','SELECT') AS writer_events,"+
    "has_function_privilege('saas_runtime_reader',"+
      "'saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)','EXECUTE') AS reader_issue,"+
    "has_table_privilege('saas_runtime_reader','saas_data.tenants','INSERT, UPDATE, DELETE, TRUNCATE') AS reader_write,"+
    "has_table_privilege('saas_runtime_writer','saas_data.projects','INSERT, UPDATE, DELETE, TRUNCATE') AS writer_write,"+
    "(SELECT count(*)::int FROM pg_class c CROSS JOIN LATERAL "+
      "aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a "+
      "WHERE c.oid IN ('saas_data.tenants'::regclass,'saas_data.projects'::regclass) "+
      "AND a.grantee NOT IN (SELECT oid FROM pg_roles WHERE rolname IN "+
      "('saas_schema_migrator','saas_runtime_reader','saas_runtime_writer'))) AS unexpected_grants"
  );
  const p=perms.rows[0];
  if(perms.rows.length!==1||!p.reader_tenants||!p.reader_projects||
     !p.writer_tenants||!p.writer_projects||
     p.reader_identity||p.writer_identity||p.reader_sessions||p.writer_events||
     p.reader_issue||p.reader_write||p.writer_write||+p.unexpected_grants!==0)refuse();

  const f=await admin.query(
    "SELECT prosecdef,provolatile,pg_get_userbyid(proowner) AS owner "+
    "FROM pg_proc WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure"
  );
  if(f.rows.length!==1||f.rows[0].prosecdef!==true||
     f.rows[0].provolatile!=='v'||f.rows[0].owner!=='saas_schema_migrator')refuse();
}

async function readBack(admin:InstanceType<typeof pg.Client>) {
  const receipts=await admin.query(
    'SELECT migration_id,source_sha256,source_commit,applied_by '+
    'FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  );
  if(receipts.rows.length!==7 ||
     !receipts.rows.slice(0,6).every((v,i)=>v.migration_id===PREVIOUS[i][0]&&
       v.source_sha256===PREVIOUS[i][1]&&v.applied_by==='saas_schema_migrator')||
     receipts.rows[6].migration_id!=='0007_operator_subject_binding_fence'||
     receipts.rows[6].source_sha256!==SQL_SHA||
     receipts.rows[6].source_commit!==COMMIT||
     receipts.rows[6].applied_by!=='saas_schema_migrator')refuse();

  const structure=await admin.query(
    "SELECT "+
    "(SELECT count(*)::int FROM saas_identity.subject_bindings) AS bindings,"+
    "(SELECT count(*)::int FROM saas_identity.subject_binding_events) AS binding_events,"+
    "(SELECT count(*)::int FROM saas_identity.principal_sessions) AS sessions,"+
    "(SELECT count(*)::int FROM saas_identity.session_events) AS session_events,"+
    "(SELECT count(*)::int FROM saas_data.tenants) AS tenants,"+
    "(SELECT count(*)::int FROM saas_data.projects) AS projects,"+
    "(SELECT count(*)::int FROM saas_acl.principal_tenants) AS grants,"+
    "(SELECT count(*)::int FROM saas_acl.principal_access_audit) AS grant_audit,"+
    "(SELECT count(*)::int FROM pg_auth_members WHERE roleid IN "+
      "(SELECT oid FROM pg_roles WHERE left(rolname,5)='saas_') OR member IN "+
      "(SELECT oid FROM pg_roles WHERE left(rolname,5)='saas_')) AS memberships,"+
    "(SELECT count(*)::int FROM pg_roles WHERE left(rolname,5)='saas_' "+
      "AND rolname NOT IN ('saas_schema_migrator','saas_runtime_reader','saas_runtime_writer')) AS new_roles,"+
    "(SELECT count(*)::int FROM pg_class WHERE oid IN "+
      "('saas_data.tenants'::regclass,'saas_data.projects'::regclass) "+
      "AND relrowsecurity AND relforcerowsecurity) AS forced,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN "+
      "('saas_data.tenants'::regclass,'saas_data.projects'::regclass) AND polcmd='r') AS policies,"+
    "(SELECT count(*)::int FROM pg_trigger WHERE tgrelid IN "+
      "('saas_identity.principal_sessions'::regclass,'saas_identity.session_events'::regclass) "+
      "AND NOT tgisinternal AND tgenabled='O') AS b14_triggers,"+
    "(SELECT string_agg(tgname,',' ORDER BY tgname) FROM pg_trigger WHERE tgrelid IN "+
      "('saas_identity.subject_bindings'::regclass,'saas_identity.subject_binding_events'::regclass) "+
      "AND NOT tgisinternal AND tgenabled='O') AS b15_triggers,"+
    "(SELECT count(*)::int FROM pg_index WHERE indrelid='saas_identity.subject_bindings'::regclass "+
      "AND indisunique) AS binding_unique_indexes,"+
    "(SELECT count(*)::int FROM pg_constraint WHERE conrelid='saas_identity.subject_bindings'::regclass "+
      "AND conname='b15_revoke_marker') AS revoke_constraint"
  );
  const s=structure.rows[0];
  const expectedTriggers=[
    'b15_binding_audit','b15_binding_events_no_change','b15_binding_events_no_truncate',
    'b15_binding_no_delete','b15_binding_no_truncate'
  ].join(',');
  if(structure.rows.length!==1||+s.bindings!==0||+s.binding_events!==0||
     +s.sessions!==0||+s.session_events!==0||+s.tenants!==0||+s.projects!==0||
     +s.grants!==0||+s.grant_audit!==0||+s.memberships!==0||+s.new_roles!==0||
     +s.forced!==2||+s.policies!==2||+s.b14_triggers!==5||
     s.b15_triggers!==expectedTriggers||+s.binding_unique_indexes!==3||
     +s.revoke_constraint!==1)refuse();

  const functions=await admin.query(
    "SELECT "+
    "(SELECT count(*)::int FROM pg_proc WHERE oid IN "+
      "('saas_identity.register_subject_binding(name,uuid,bigint,text,text)'::regprocedure,"+
       "'saas_identity.revoke_subject_binding(uuid,bigint,text)'::regprocedure,"+
       "'saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)'::regprocedure) "+
      "AND NOT prosecdef AND provolatile='v' "+
      "AND pg_get_userbyid(proowner)='saas_schema_migrator') AS operators,"+
    "(SELECT count(*)::int FROM pg_proc WHERE oid IN "+
      "('saas_identity.audit_subject_binding_transition()'::regprocedure,"+
       "'saas_acl.can_read_tenant(uuid)'::regprocedure) "+
      "AND prosecdef AND provolatile='v' "+
      "AND pg_get_userbyid(proowner)='saas_schema_migrator') AS definer_functions,"+
    "(SELECT pg_get_functiondef('saas_acl.can_read_tenant(uuid)'::regprocedure) "+
      "LIKE '%saas_identity.subject_bindings%') AS binding_fence"
  );
  const f=functions.rows[0];
  if(functions.rows.length!==1||+f.operators!==3||
     +f.definer_functions!==2||f.binding_fence!==true)refuse();

  const perms=await admin.query(
    "SELECT "+
    "has_schema_privilege('saas_runtime_reader','saas_identity','USAGE') AS reader_identity,"+
    "has_schema_privilege('saas_runtime_writer','saas_identity','USAGE') AS writer_identity,"+
    "has_table_privilege('saas_runtime_reader','saas_identity.subject_bindings','SELECT') AS reader_bindings,"+
    "has_table_privilege('saas_runtime_writer','saas_identity.subject_binding_events','SELECT') AS writer_events,"+
    "has_function_privilege('saas_runtime_reader',"+
       "'saas_identity.register_subject_binding(name,uuid,bigint,text,text)','EXECUTE') AS reader_enroll,"+
    "has_function_privilege('saas_runtime_writer',"+
       "'saas_identity.revoke_subject_binding(uuid,bigint,text)','EXECUTE') AS writer_revoke,"+
    "has_table_privilege('saas_runtime_reader','saas_data.tenants','SELECT') AS reader_tenants,"+
    "has_table_privilege('saas_runtime_writer','saas_data.projects','SELECT') AS writer_projects,"+
    "has_table_privilege('saas_runtime_reader','saas_data.tenants','INSERT, UPDATE, DELETE, TRUNCATE') AS reader_write,"+
    "has_table_privilege('saas_runtime_writer','saas_data.projects','INSERT, UPDATE, DELETE, TRUNCATE') AS writer_write,"+
    "(SELECT count(*)::int FROM pg_class c CROSS JOIN LATERAL "+
      "aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a "+
      "WHERE c.oid IN ('saas_data.tenants'::regclass,'saas_data.projects'::regclass,"+
       "'saas_identity.subject_bindings'::regclass,'saas_identity.subject_binding_events'::regclass) "+
      "AND a.grantee NOT IN (SELECT oid FROM pg_roles WHERE rolname IN "+
      "('saas_schema_migrator','saas_runtime_reader','saas_runtime_writer'))) AS unexpected_grants"
  );
  const p=perms.rows[0];
  if(perms.rows.length!==1||p.reader_identity||p.writer_identity||
     p.reader_bindings||p.writer_events||p.reader_enroll||p.writer_revoke||
     !p.reader_tenants||!p.writer_projects||p.reader_write||p.writer_write||
     +p.unexpected_grants!==0)refuse();
}

/** Always reset short-lived migrator credentials; catalog attestation is mandatory. */
async function seal(admin:InstanceType<typeof pg.Client>) {
  await admin.query('ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL');
  const r=await admin.query(
    "SELECT rolcanlogin,rolpassword IS NULL AS password_is_null, "+
    "(rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication) AS elevated "+
    "FROM pg_authid WHERE rolname='saas_schema_migrator'"
  );
  if(r.rows.length!==1||r.rows[0].rolcanlogin!==false||
     r.rows[0].password_is_null!==true||r.rows[0].elevated!==false)refuse();
}

async function run() {
  const u=environment();
  const approved=await source();
  const secret=[...crypto.getRandomValues(new Uint8Array(32))]
    .map(v=>v.toString(16).padStart(2,'0')).join('');
  if(!isHex(secret,64))refuse();
  const admin=client(u);
  const murl=new URL(u.toString());
  murl.username='saas_schema_migrator';
  murl.password=secret;
  const migrator=client(murl);
  let adminReady=false,migratorReady=false,loginMayExist=false,sealed=false;
  try {
    await admin.connect();adminReady=true;
    await preflight(admin);
    loginMayExist=true;
    const until=new Date(Date.now()+5*60*1000).toISOString();
    await admin.query("ALTER ROLE saas_schema_migrator LOGIN PASSWORD '"+secret+
      "' VALID UNTIL '"+until+"'");
    await migrator.connect();migratorReady=true;
    // One attempt. Lost COMMIT acknowledgement => manual reconciliation, NEVER retry.
    await migrator.query(bind(approved,{
      expected_0006_sha256:PREVIOUS[5][1],
      migration_sha256:SQL_SHA,
      source_commit:COMMIT,
    }));
    await readBack(admin);
    await seal(admin);sealed=true;
    console.info('PASS_BACKEND15_STAGING_PG16_0007_SUBJECT_BINDING_FORCE_RLS_NOLOGIN');
  } finally {
    if(migratorReady){try {await migrator.end();}catch{/* never retry */}}
    if(adminReady){
      if(loginMayExist&&!sealed){try {await seal(admin);}catch{/* manual reconciliation */}}
      try {await admin.end();}catch{/* never retry */ }
    }
  }
}
try {await run();}
catch {
  // Never print SQL, credentials, DB URLs, exception objects or ambiguous details.
  console.error(STOP);
  process.exitCode=1;
}

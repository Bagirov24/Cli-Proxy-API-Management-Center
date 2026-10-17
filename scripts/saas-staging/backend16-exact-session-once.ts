/**
 * Backend16.5: ONE-SHOT SQL0008 migration runner, staging PG16 ONLY.
 * No HTTP/listener/cron/retry. Must never be deployed without Railway
 * restartPolicyType=NEVER independently confirmed on its exact Function ID.
 * Unknown COMMIT = STOP, reconcile read-only: NEVER launch this code again.
 * The script is not a SaaS API, auth provider, runtime SQL reader or role bootstrap.
 */
import pg from 'pg@8.16.3';

const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENV='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const DB_SERVICE='37f8f166-75a6-4617-b243-8e681181c16d';
const RUNNER='saas-b16-0008-once';
const RUNNER_SERVICE_ID='302e9762-7451-4999-a657-f5b3624dab63';
const COMMIT='314f0962f2d955241fb5ee7a29175bddb648c130';
const SQL_FILE='0008_exact_subject_session_gate.sql';
const SQL_SHA='ef4858975fea0842ae16d1b572457641c0359fa9630f02a1d52ea972007c632b';
const PREVIOUS=[
  ['0001_ledger_only','7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279'],
  ['0002_tenant_projects_baseline','80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f'],
  ['0003_operator_runtime_roles','8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e'],
  ['0004_principal_bound_read_rls','4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980'],
  ['0005_principal_lifecycle_revocation_fence','b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556'],
  ['0006_principal_session_fence','b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505'],
  ['0007_operator_subject_binding_fence','1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0'],
] as const;
const STOP='BACKEND16_STOP_UNKNOWN_COMMIT_RECONCILE_NEVER_RETRY';
const SUCCESS='PASS_BACKEND16_STAGING_PG16_0008_EXACT_SESSION_NOLOGIN';

function refuse():never {throw Error('Backend16 SQL0008 one-shot staging refused');}
function hex(s:string,n:number):boolean {
  return new RegExp('^[a-f0-9]{'+n+'}$').test(s);
}
function environment():URL {
  const e=process.env;
  if(e.RAILWAY_PROJECT_ID!==PROJECT ||
     e.RAILWAY_ENVIRONMENT_ID!==ENV ||
     e.RAILWAY_ENVIRONMENT_NAME!=='staging' ||
     e.RAILWAY_SERVICE_NAME!==RUNNER ||
     e.RAILWAY_SERVICE_ID!==RUNNER_SERVICE_ID ||
     e.RAILWAY_SERVICE_ID===DB_SERVICE ||
     e.SAAS_B16_APPLY_EXPLICIT_ENABLE!=='true' ||
     e.SAAS_B16_ACCEPT_DISPOSABLE_STAGING!=='true' ||
     e.GITHUB_ACTIONS==='true' || e.NODE_ENV==='production')refuse();
  const raw=e.STAGING_POSTGRES_PRIVATE_URL;
  if(typeof raw!=='string'||raw.length<35||raw.length>1024)refuse();
  let url:URL;
  try {url=new URL(raw);}catch{refuse();}
  if(!['postgres:','postgresql:'].includes(url.protocol) ||
     url.hostname!=='postgres.railway.internal' ||
     url.port!=='5432' || url.pathname!=='/saas_staging' ||
     decodeURIComponent(url.username)!=='postgres' || !url.password ||
     url.search || url.hash)refuse();
  return url;
}

/** Immutable reviewed SQL bytes verified BEFORE opening any DB connection. */
async function source():Promise<string>{
  if(!hex(COMMIT,40)||!hex(SQL_SHA,64))refuse();
  const url='https://raw.githubusercontent.com/Bagirov24/' +
    'Cli-Proxy-API-Management-Center/'+COMMIT+
    '/staging/saas-bootstrap/'+SQL_FILE;
  const response=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(12000)});
  if(!response.ok||response.url!==url)refuse();
  const bytes=new Uint8Array(await response.arrayBuffer());
  if(bytes.byteLength!==9818)refuse();
  const actual=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))]
    .map(x=>x.toString(16).padStart(2,'0')).join('');
  if(actual!==SQL_SHA)refuse();
  const sql=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const directives=sql.split('\n').filter(x=>/^\s*\\/.test(x));
  if(directives.length!==1 ||
     directives[0].trim()!=='\\set ON_ERROR_STOP on' ||
     !sql.includes('BEGIN;') || !sql.trimEnd().endsWith('COMMIT;') ||
     !sql.includes("VALUES ('0008_exact_subject_session_gate'") ||
     !sql.includes("saas_acl.exact_subject_session_authorized("))refuse();
  return sql.replace(/^\\set ON_ERROR_STOP on\s*$/m,'');
}

/** Replace ONLY the exact three psql attestation keys with pinned hex literals. */
function bind(sql:string,values:Record<string,string>):string {
  if(Object.keys(values).sort().join(',')!==
     ['expected_0007_sha256','migration_sha256','source_commit'].sort().join(','))
    refuse();
  const seen=new Set<string>();
  for(const v of Object.values(values))
    if(![40,64].includes(v.length)||!hex(v,v.length))refuse();
  const result=sql.replace(/:'([a-z_0-9]+)'/g,(_all,key:string)=>{
    if(!Object.prototype.hasOwnProperty.call(values,key))refuse();
    seen.add(key);return "'"+values[key]+"'";
  });
  if(seen.size!==3 || /:'[a-z_0-9]+'/i.test(result) ||
     /^\s*\\/m.test(result))refuse();
  return result;
}
function client(url:URL){
  return new pg.Client({
    connectionString:url.toString(),
    options:'-c saas.staging_only=true',
    connectionTimeoutMillis:6000,
    query_timeout:45000,
    statement_timeout:20000,
    application_name:'saas-backend16-one-shot-0008',
  });
}
type PgClient=InstanceType<typeof pg.Client>;
function expectedReceipt(x:any,i:number){
  return x.migration_id===PREVIOUS[i][0] &&
    x.source_sha256===PREVIOUS[i][1] &&
    x.applied_by===(i===2?'postgres':'saas_schema_migrator');
}
async function receipts(admin:PgClient,post:boolean){
  const r=await admin.query(
    'SELECT migration_id,source_sha256,source_commit,applied_by '+
    'FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  );
  if(r.rows.length!==(post?8:7) ||
     !r.rows.slice(0,7).every(expectedReceipt))refuse();
  if(post){
    const x=r.rows[7];
    if(x.migration_id!=='0008_exact_subject_session_gate' ||
       x.source_sha256!==SQL_SHA || x.source_commit!==COMMIT ||
       x.applied_by!=='saas_schema_migrator')refuse();
  }
}
async function catalog(admin:PgClient,post:boolean){
  const q=await admin.query(
    "SELECT "+
      "(SELECT count(*)::int FROM saas_data.tenants) AS tenants,"+
      "(SELECT count(*)::int FROM saas_data.projects) AS projects,"+
      "(SELECT count(*)::int FROM saas_acl.principal_tenants) AS grants,"+
      "(SELECT count(*)::int FROM saas_acl.principal_access_audit) AS grant_audit,"+
      "(SELECT count(*)::int FROM saas_identity.principal_sessions) AS sessions,"+
      "(SELECT count(*)::int FROM saas_identity.session_events) AS session_events,"+
      "(SELECT count(*)::int FROM saas_identity.subject_bindings) AS bindings,"+
      "(SELECT count(*)::int FROM saas_identity.subject_binding_events) AS binding_events,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_auth_members WHERE roleid IN "+
        "(SELECT oid FROM pg_catalog.pg_roles WHERE left(rolname,5)='saas_') OR member IN "+
        "(SELECT oid FROM pg_catalog.pg_roles WHERE left(rolname,5)='saas_')) AS memberships,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_roles WHERE left(rolname,5)='saas_' "+
        "AND rolname NOT IN ('saas_schema_migrator','saas_runtime_reader','saas_runtime_writer')) AS new_roles,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_class WHERE oid IN "+
        "('saas_data.tenants'::regclass,'saas_data.projects'::regclass) "+
        "AND relrowsecurity AND relforcerowsecurity) AS forced,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_policy WHERE polrelid IN "+
        "('saas_data.tenants'::regclass,'saas_data.projects'::regclass) AND polcmd='r') AS policies,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_policy WHERE polrelid IN "+
        "('saas_data.tenants'::regclass,'saas_data.projects'::regclass)) AS all_policies,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_trigger WHERE tgrelid IN "+
        "('saas_identity.principal_sessions'::regclass,'saas_identity.session_events'::regclass) "+
        "AND NOT tgisinternal AND tgenabled='O') AS b14_triggers,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_trigger WHERE tgrelid IN "+
        "('saas_identity.subject_bindings'::regclass,'saas_identity.subject_binding_events'::regclass) "+
        "AND NOT tgisinternal AND tgenabled='O') AS b15_triggers,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_index WHERE indrelid="+
        "'saas_identity.subject_bindings'::regclass AND indisunique) AS binding_unique_indexes,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_constraint WHERE conrelid="+
        "'saas_identity.subject_bindings'::regclass AND conname='b15_revoke_marker') AS revoke_constraint,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_proc WHERE oid IN "+
        "('saas_identity.audit_subject_binding_transition()'::regprocedure,"+
        "'saas_acl.can_read_tenant(uuid)'::regprocedure) "+
        "AND prosecdef AND provolatile='v' AND "+
        "pg_catalog.pg_get_userbyid(proowner)='saas_schema_migrator') AS original_definers,"+
      "(SELECT pg_catalog.pg_get_functiondef('saas_acl.can_read_tenant(uuid)'::regprocedure) "+
        "LIKE '%saas_identity.subject_bindings%') AS original_binding_fence,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_proc WHERE oid IN "+
        "('saas_identity.register_subject_binding(name,uuid,bigint,text,text)'::regprocedure,"+
        "'saas_identity.revoke_subject_binding(uuid,bigint,text)'::regprocedure,"+
        "'saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)'::regprocedure) "+
        "AND NOT prosecdef AND provolatile='v' AND "+
        "pg_catalog.pg_get_userbyid(proowner)='saas_schema_migrator') AS operator_functions"
  );
  const x=q.rows[0];
  if(q.rows.length!==1 ||
     +x.tenants!==0||+x.projects!==0||+x.grants!==0||+x.grant_audit!==0||
     +x.sessions!==0||+x.session_events!==0||
     +x.bindings!==0||+x.binding_events!==0||
     +x.memberships!==0||+x.new_roles!==0||
     +x.forced!==2||+x.policies!==2||+x.all_policies!==2||
     +x.b14_triggers!==5||+x.b15_triggers!==5||
     +x.binding_unique_indexes!==3||+x.revoke_constraint!==1||
     +x.original_definers!==2||x.original_binding_fence!==true||
     +x.operator_functions!==3)refuse();

  const f=await admin.query(
    "SELECT to_regprocedure("+
    "'saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)') "+
    "IS NOT NULL AS exists"
  );
  if(f.rows.length!==1||f.rows[0].exists!==post)refuse();

  const perms=await admin.query(
    "SELECT "+
      "pg_catalog.has_schema_privilege('saas_runtime_reader','saas_identity','USAGE') AS reader_private_schema,"+
      "pg_catalog.has_schema_privilege('saas_runtime_writer','saas_identity','USAGE') AS writer_private_schema,"+
      "pg_catalog.has_table_privilege('saas_runtime_reader','saas_identity.principal_sessions','SELECT') AS reader_sessions,"+
      "pg_catalog.has_table_privilege('saas_runtime_writer','saas_identity.subject_bindings','SELECT') AS writer_bindings,"+
      "pg_catalog.has_table_privilege('saas_runtime_reader','saas_identity.subject_binding_events','SELECT') AS reader_events,"+
      "pg_catalog.has_table_privilege('saas_runtime_writer','saas_identity.subject_binding_events','SELECT') AS writer_events,"+
      "pg_catalog.has_table_privilege('saas_runtime_reader','saas_data.tenants','SELECT') AS reader_tenants,"+
      "pg_catalog.has_table_privilege('saas_runtime_writer','saas_data.projects','SELECT') AS writer_projects,"+
      "pg_catalog.has_table_privilege('saas_runtime_reader','saas_data.tenants','INSERT, UPDATE, DELETE, TRUNCATE') AS reader_write,"+
      "pg_catalog.has_table_privilege('saas_runtime_writer','saas_data.projects','INSERT, UPDATE, DELETE, TRUNCATE') AS writer_write"
  );
  const p=perms.rows[0];
  if(perms.rows.length!==1||p.reader_private_schema||p.writer_private_schema||
     p.reader_sessions||p.writer_bindings||p.reader_events||p.writer_events||
     !p.reader_tenants||!p.writer_projects||p.reader_write||p.writer_write)
    refuse();
  if(post){
    const f2=await admin.query(
      "SELECT p.prosecdef,p.provolatile,pg_catalog.pg_get_userbyid(p.proowner) AS owner,"+
        "p.proconfig,"+
        "pg_catalog.has_function_privilege('saas_runtime_reader',p.oid,'EXECUTE') AS reader_execute,"+
        "pg_catalog.has_function_privilege('saas_runtime_writer',p.oid,'EXECUTE') AS writer_execute,"+
        "(SELECT count(*)::int FROM pg_catalog.aclexplode(p.proacl) a "+
          "WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute,"+
        "(SELECT count(*)::int FROM pg_catalog.aclexplode(p.proacl) a "+
          "WHERE a.grantee NOT IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN "+
          "('saas_schema_migrator','saas_runtime_reader','saas_runtime_writer'))) AS unexpected_grantees,"+
        "(pg_catalog.pg_get_functiondef(p.oid) LIKE '%FOR SHARE%') AS share_locks,"+
        "(pg_catalog.pg_get_functiondef(p.oid) LIKE '%s.session_id = p_session%') AS exact_session,"+
        "(pg_catalog.pg_get_functiondef(p.oid) LIKE '%b.subject_fingerprint = p_subject_sha256%') AS exact_subject "+
      "FROM pg_catalog.pg_proc p WHERE p.oid="+
        "'saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)'::regprocedure"
    );
    const y=f2.rows[0];
    if(f2.rows.length!==1||y.prosecdef!==true||y.provolatile!=='v'||
       y.owner!=='saas_schema_migrator'||
       !Array.isArray(y.proconfig)||
       !y.proconfig.includes('search_path=pg_catalog, pg_temp')||
       y.reader_execute!==true||y.writer_execute!==true||
       +y.public_execute!==0||+y.unexpected_grantees!==0||
       y.share_locks!==true||y.exact_session!==true||y.exact_subject!==true)
      refuse();
  }
}
async function preflight(admin:PgClient){
  const r=await admin.query(
    "SELECT current_database() AS db, session_user AS login,"+
    "current_setting('server_version_num')::int AS ver,"+
    "current_setting('transaction_read_only') AS read_only,"+
    "pg_catalog.pg_is_in_recovery() AS replica,"+
    "(SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=session_user) AS superuser,"+
    "(SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname='saas_schema_migrator') AS migrator_login,"+
    "(SELECT rolpassword IS NULL FROM pg_catalog.pg_authid WHERE rolname='saas_schema_migrator') AS migrator_no_password,"+
    "(SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication "+
      "FROM pg_catalog.pg_roles WHERE rolname='saas_schema_migrator') AS migrator_privileged,"+
    "(SELECT count(*)::int FROM pg_catalog.pg_stat_activity WHERE datname=current_database() "+
      "AND pid<>pg_catalog.pg_backend_pid() AND backend_type='client backend') AS other_connections"
  );
  const x=r.rows[0];
  if(r.rows.length!==1||x.db!=='saas_staging'||x.login!=='postgres'||
     x.ver<160000||x.ver>=170000||x.read_only!=='off'||x.replica!==false||
     x.superuser!==true||x.migrator_login!==false||
     x.migrator_no_password!==true||x.migrator_privileged!==false||
     +x.other_connections!==0)refuse();
  await receipts(admin,false);
  await catalog(admin,false);
}
async function readBack(admin:PgClient){
  await receipts(admin,true);
  await catalog(admin,true);
}
async function seal(admin:PgClient){
  await admin.query('ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL');
  const r=await admin.query(
    "SELECT rolcanlogin,rolpassword IS NULL AS password_is_null,"+
    "(rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication) AS elevated "+
    "FROM pg_catalog.pg_authid WHERE rolname='saas_schema_migrator'"
  );
  if(r.rows.length!==1||r.rows[0].rolcanlogin!==false||
     r.rows[0].password_is_null!==true||r.rows[0].elevated!==false)refuse();
}

async function run(){
  const uri=environment();
  const sql=await source();
  const secret=[...crypto.getRandomValues(new Uint8Array(32))]
    .map(x=>x.toString(16).padStart(2,'0')).join('');
  if(!hex(secret,64))refuse();
  const admin=client(uri);
  const murl=new URL(uri.toString());
  murl.username='saas_schema_migrator';
  murl.password=secret;
  const migrator=client(murl);
  let adminReady=false,migratorReady=false,loginMayExist=false,sealed=false;
  try{
    await admin.connect();adminReady=true;
    await preflight(admin);
    // Only a preflight-positive sealed role may be temporarily unsealed.
    loginMayExist=true;
    const until=new Date(Date.now()+5*60*1000).toISOString();
    await admin.query("ALTER ROLE saas_schema_migrator LOGIN PASSWORD '"+secret+
      "' VALID UNTIL '"+until+"'");
    await migrator.connect();migratorReady=true;
    // Exactly ONE transaction submission. Unknown COMMIT or missing ACK:
    // NO repeat, NO replay, best-effort seal then manual reconciliation.
    await migrator.query(bind(sql,{
      expected_0007_sha256:PREVIOUS[6][1],
      migration_sha256:SQL_SHA,
      source_commit:COMMIT,
    }));
    await readBack(admin);
    await seal(admin);sealed=true;
    console.info(SUCCESS);
  }finally{
    if(migratorReady){try{await migrator.end();}catch{/* NO retry */}}
    if(adminReady){
      if(loginMayExist&&!sealed){try{await seal(admin);}catch{/* MANUAL seal */}}
      try{await admin.end();}catch{/* NO retry */}
    }
  }
}
try{await run();}
catch{
  // Never leak SQL, credentials, URL, subject, stack, pg_catalog or error data.
  console.error(STOP);
  process.exitCode=1;
}

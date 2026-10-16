/**
 * Backend14 one-shot PRIVATE Railway staging PG16 session-fence installer.
 * Reviewed migration 0006 only, no HTTP listener, cron, retries, app login,
 * user records, public DB route, Core/Gateway access or customer credentials.
 * Operator accepted loss of disposable SaaS staging data only.
 */
import pg from 'pg@8.16.3';

const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENV='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const COMMIT='e040f3994106a467e4bf42c1f21b18ca70ed4da2';
const SQL_FILE='0006_principal_session_fence.sql';
const SQL_SHA='b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505';
const PREVIOUS=[
  ['0001_ledger_only','7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279'],
  ['0002_tenant_projects_baseline','80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f'],
  ['0003_operator_runtime_roles','8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e'],
  ['0004_principal_bound_read_rls','4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980'],
  ['0005_principal_lifecycle_revocation_fence','b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556'],
] as const;
const STOP='BACKEND14_STOP_UNKNOWN_COMMIT_RECONCILE_NEVER_RETRY';

function refuse():never {throw new Error('Backend14 private staging migration refused');}
function isHex(s:string,n:number){return new RegExp('^[a-f0-9]{'+n+'}$').test(s);}

function environment():URL {
  const e=process.env;
  if(e.RAILWAY_PROJECT_ID!==PROJECT ||
     e.RAILWAY_ENVIRONMENT_ID!==ENV ||
     e.RAILWAY_ENVIRONMENT_NAME!=='staging' ||
     e.RAILWAY_SERVICE_NAME!=='saas-b14-session-once' ||
     e.SAAS_B14_APPLY_EXPLICIT_ENABLE!=='true' ||
     e.SAAS_B14_ACCEPT_STAGING_LOSS!=='true' ||
     e.GITHUB_ACTIONS==='true')refuse();
  const raw=e.STAGING_POSTGRES_PRIVATE_URL;
  if(typeof raw!=='string'||raw.length<35||raw.length>1024)refuse();
  let u:URL;
  try{u=new URL(raw);}catch{refuse();}
  if(!['postgres:','postgresql:'].includes(u.protocol)||
     u.hostname!=='postgres.railway.internal'||
     u.port!=='5432'||u.pathname!=='/saas_staging'||
     decodeURIComponent(u.username)!=='postgres'||!u.password||
     u.search||u.hash)refuse();
  return u;
}

async function source():Promise<string> {
  if(!isHex(COMMIT,40)||!isHex(SQL_SHA,64))refuse();
  const url='https://raw.githubusercontent.com/Bagirov24/' +
    'Cli-Proxy-API-Management-Center/'+COMMIT+
    '/staging/saas-bootstrap/'+SQL_FILE;
  const r=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(12000)});
  if(!r.ok||r.url!==url)refuse();
  const bytes=new Uint8Array(await r.arrayBuffer());
  if(bytes.byteLength<12000||bytes.byteLength>19000)refuse();
  const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))]
    .map(x=>x.toString(16).padStart(2,'0')).join('');
  if(digest!==SQL_SHA)refuse();
  const body=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const directives=body.split('\n').filter(line=>/^\s*\\/.test(line));
  if(directives.length!==1||directives[0].trim()!=='\\set ON_ERROR_STOP on'||
     !body.includes('BEGIN;')||!body.trimEnd().endsWith('COMMIT;'))refuse();
  return body.replace(/^\\set ON_ERROR_STOP on\s*$/m,'');
}

function bind(sql:string,values:Record<string,string>):string {
  const keys=new Set<string>();
  for(const v of Object.values(values))
    if(![40,64].includes(v.length)||!isHex(v,v.length))refuse();
  const bound=sql.replace(/:'([a-z_0-9]+)'/g,(_unused,k:string)=>{
    if(!Object.prototype.hasOwnProperty.call(values,k))refuse();
    keys.add(k);return "'"+values[k]+"'";
  });
  if(Object.keys(values).some(k=>!keys.has(k))||
     /:'[a-z_0-9]+'/i.test(bound)||/^\s*\\/m.test(bound))refuse();
  return bound;
}
function client(url:URL){
  return new pg.Client({
    connectionString:url.toString(),
    options:'-c saas.staging_only=true',
    connectionTimeoutMillis:6000,
    query_timeout:25000,
    statement_timeout:20000,
    application_name:'saas-backend14-one-shot-0006',
  });
}

async function preflight(admin:InstanceType<typeof pg.Client>) {
  const r=await admin.query(
    "SELECT current_database() AS db, session_user AS login,"+
    "current_setting('server_version_num')::int AS ver,"+
    "(SELECT rolsuper FROM pg_roles WHERE rolname=session_user) AS superuser,"+
    "(SELECT rolcanlogin FROM pg_roles WHERE rolname='saas_schema_migrator') AS migrator_login,"+
    "(SELECT rolpassword IS NULL FROM pg_authid WHERE rolname='saas_schema_migrator') AS migrator_no_password,"+
    "(SELECT count(*)::int FROM pg_namespace WHERE nspname='saas_identity') AS identity_schemas,"+
    "(SELECT count(*)::int FROM pg_auth_members WHERE roleid IN ("+
      "SELECT oid FROM pg_roles WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer'))) AS memberships"
  );
  const x=r.rows[0];
  if(r.rows.length!==1||x.db!=='saas_staging'||x.login!=='postgres'||
     x.ver<160000||x.ver>=170000||x.superuser!==true||
     x.migrator_login!==false||x.migrator_no_password!==true||
     +x.identity_schemas!==0||+x.memberships!==0)refuse();
  const receipts=await admin.query(
    'SELECT migration_id,source_sha256 FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  );
  if(receipts.rows.length!==5||
     !receipts.rows.every((v,i)=>v.migration_id===PREVIOUS[i][0]&&
                              v.source_sha256===PREVIOUS[i][1]))refuse();
  const prior=await admin.query(
    "SELECT prosecdef,provolatile,pg_get_userbyid(proowner) AS owner FROM pg_proc "+
    "WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure"
  );
  if(prior.rows.length!==1||prior.rows[0].prosecdef!==true||
     prior.rows[0].provolatile!=='v'||prior.rows[0].owner!=='saas_schema_migrator')
    refuse();
  const safety=await admin.query(
    "SELECT (SELECT count(*)::int FROM saas_data.tenants) AS tenants,"+
    "(SELECT count(*)::int FROM saas_data.projects) AS projects,"+
    "(SELECT count(*)::int FROM saas_acl.principal_tenants) AS grants,"+
    "(SELECT count(*)::int FROM saas_acl.principal_access_audit) AS grant_audit,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN ("+
      "'saas_data.tenants'::regclass,'saas_data.projects'::regclass)) AS policies,"+
    "(SELECT count(*)::int FROM pg_class WHERE oid IN ("+
      "'saas_data.tenants'::regclass,'saas_data.projects'::regclass) "+
      "AND relrowsecurity AND relforcerowsecurity) AS force"
  );
  const z=safety.rows[0];
  if(safety.rows.length!==1||+z.tenants!==0||+z.projects!==0||
     +z.grants!==0||+z.grant_audit!==0||+z.policies!==2||+z.force!==2)refuse();
}

async function readBack(admin:InstanceType<typeof pg.Client>) {
  const receipts=await admin.query(
    'SELECT migration_id,source_sha256,source_commit,applied_by '+
    'FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  );
  if(receipts.rows.length!==6||
     !receipts.rows.slice(0,5).every((v,i)=>v.migration_id===PREVIOUS[i][0]&&
       v.source_sha256===PREVIOUS[i][1])||
     receipts.rows[5].migration_id!=='0006_principal_session_fence'||
     receipts.rows[5].source_sha256!==SQL_SHA||
     receipts.rows[5].source_commit!==COMMIT||
     receipts.rows[5].applied_by!=='saas_schema_migrator')refuse();
  const schema=await admin.query(
    "SELECT (SELECT count(*)::int FROM saas_identity.principal_sessions) AS sessions,"+
    "(SELECT count(*)::int FROM saas_identity.session_events) AS events,"+
    "(SELECT count(*)::int FROM saas_data.tenants) AS tenants,"+
    "(SELECT count(*)::int FROM saas_data.projects) AS projects,"+
    "(SELECT count(*)::int FROM saas_acl.principal_tenants) AS grants,"+
    "(SELECT count(*)::int FROM pg_auth_members WHERE roleid IN ("+
      "SELECT oid FROM pg_roles WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer'))) AS memberships,"+
    "(SELECT count(*)::int FROM pg_trigger WHERE tgrelid IN ("+
      "'saas_identity.principal_sessions'::regclass,'saas_identity.session_events'::regclass) "+
      "AND NOT tgisinternal AND tgenabled='O') AS session_triggers,"+
    "(SELECT count(*)::int FROM pg_class WHERE oid IN ("+
      "'saas_data.tenants'::regclass,'saas_data.projects'::regclass) "+
      "AND relrowsecurity AND relforcerowsecurity) AS force,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN ("+
      "'saas_data.tenants'::regclass,'saas_data.projects'::regclass) AND polcmd='r') AS reads,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN ("+
      "'saas_data.tenants'::regclass,'saas_data.projects'::regclass)) AS policies,"+
    "has_schema_privilege('saas_runtime_reader','saas_identity','USAGE') AS reader_identity_usage,"+
    "has_schema_privilege('saas_runtime_writer','saas_identity','USAGE') AS writer_identity_usage,"+
    "has_function_privilege('saas_runtime_reader',"+
      "'saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)','EXECUTE') AS reader_issue,"+
    "has_table_privilege('saas_runtime_reader','saas_identity.principal_sessions','SELECT') AS reader_read"
  );
  const x=schema.rows[0];
  if(schema.rows.length!==1||+x.sessions!==0||+x.events!==0||
     +x.tenants!==0||+x.projects!==0||+x.grants!==0||+x.memberships!==0||
     +x.session_triggers!==5||+x.force!==2||+x.reads!==2||+x.policies!==2||
     x.reader_identity_usage!==false||x.writer_identity_usage!==false||
     x.reader_issue!==false||x.reader_read!==false)refuse();
  const f=await admin.query(
    "SELECT prosecdef,provolatile,pg_get_userbyid(proowner) AS owner "+
    "FROM pg_proc WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure"
  );
  if(f.rows.length!==1||f.rows[0].prosecdef!==true||
     f.rows[0].provolatile!=='v'||f.rows[0].owner!=='saas_schema_migrator')refuse();
  const operatorFns=await admin.query(
    "SELECT count(*)::int AS n FROM pg_proc WHERE oid IN ("+
      "'saas_identity.issue_principal_session(name,uuid,bigint,uuid,timestamptz,text)'::regprocedure,"+
      "'saas_identity.revoke_principal_session(uuid,bigint,text)'::regprocedure) "+
      "AND NOT prosecdef AND provolatile='v'"
  );
  if(operatorFns.rows.length!==1||+operatorFns.rows[0].n!==2)refuse();
}

async function seal(admin:InstanceType<typeof pg.Client>){
  await admin.query('ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL');
  const r=await admin.query(
    "SELECT rolcanlogin,rolpassword IS NULL AS password_is_null FROM pg_authid "+
    "WHERE rolname='saas_schema_migrator'"
  );
  if(r.rows.length!==1||r.rows[0].rolcanlogin!==false||
     r.rows[0].password_is_null!==true)refuse();
}

async function run() {
  const u=environment();
  const approved=await source(); // verify immutable bytes BEFORE DB contact
  const secret=[...crypto.getRandomValues(new Uint8Array(32))]
    .map(v=>v.toString(16).padStart(2,'0')).join('');
  if(!isHex(secret,64))refuse();
  const admin=client(u);
  const murl=new URL(u.toString());murl.username='saas_schema_migrator';
  murl.password=secret;
  const migrator=client(murl);
  let adminReady=false,migratorReady=false,loginMayExist=false,sealed=false;
  try{
    await admin.connect();adminReady=true;
    await preflight(admin);
    loginMayExist=true;
    const until=new Date(Date.now()+5*60*1000).toISOString();
    await admin.query("ALTER ROLE saas_schema_migrator LOGIN PASSWORD '"+
      secret+"' VALID UNTIL '"+until+"'");
    await migrator.connect();migratorReady=true;
    await migrator.query(bind(approved,{
      expected_0005_sha256:PREVIOUS[4][1],
      migration_sha256:SQL_SHA,source_commit:COMMIT,
    }));
    // A lost COMMIT acknowledgement requires manual reconciliation, not retry.
    await readBack(admin);
    await seal(admin);sealed=true;
    console.info('PASS_BACKEND14_STAGING_PG16_0006_PRIVATE_SESSIONS_FORCE_RLS_NOLOGIN');
  }finally{
    if(migratorReady){try{await migrator.end();}catch{/* no retry */}}
    if(adminReady){
      // Narrow best-effort containment of temporary migrator LOGIN only.
      // Even on UNKNOWN COMMIT, never rerun 0006 or create another runner.
      if(loginMayExist&&!sealed){try{await seal(admin);}catch{/* operator reconcile */}}
      try{await admin.end();}catch{/* no retry */}
    }
  }
}
try{await run();}
catch{
  // No SQL contents, error objects, credentials, hashes or hosts in logs.
  console.error(STOP);
  process.exitCode=1;
}

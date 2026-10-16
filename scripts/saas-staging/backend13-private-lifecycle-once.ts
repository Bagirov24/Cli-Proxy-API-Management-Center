/**
 * Backend13: PRIVATE one-shot Railway PG16 installation of audited CAS
 * grant/revoke tombstones + VOLATILE/FOR SHARE read revocation fence.
 *
 * No HTTP routes/listeners, cron, runtime LOGIN, tenant data, retry, public
 * database proxy, Core/Gateway connectivity or non-staging environment.
 * Only disposable test staging (explicit user no-backup risk acceptance).
 */
import pg from 'pg@8.16.3';

const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENV='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const COMMIT='d9a5a151cd86ff458882032ed2c62fd947a92f07';
const SQL_FILE='0005_principal_lifecycle_revocation_fence.sql';
const SQL_SHA='b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556';
const PREVIOUS=[
  ['0001_ledger_only','7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279'],
  ['0002_tenant_projects_baseline','80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f'],
  ['0003_operator_runtime_roles','8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e'],
  ['0004_principal_bound_read_rls','4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980'],
] as const;
const STOP='BACKEND13_STOP_UNKNOWN_COMMIT_MANUALLY_RECONCILE_NO_RETRY';
function refuse():never{throw new Error('Backend13 isolated staging operator preflight refused');}
function isHex(s:string,n:number){return new RegExp('^[a-f0-9]{'+n+'}$').test(s);}

function environment():URL{
  const e=process.env;
  if(e.RAILWAY_PROJECT_ID!==PROJECT || e.RAILWAY_ENVIRONMENT_ID!==ENV ||
     e.RAILWAY_ENVIRONMENT_NAME!=='staging' ||
     e.RAILWAY_SERVICE_NAME!=='saas-b13-lifecycle-once' ||
     e.SAAS_B13_APPLY_EXPLICIT_ENABLE!=='true' ||
     e.SAAS_B13_ACCEPT_STAGING_LOSS!=='true' ||
     e.GITHUB_ACTIONS==='true')refuse();
  const raw=e.STAGING_POSTGRES_PRIVATE_URL;
  if(typeof raw!=='string'||raw.length<35||raw.length>1024)refuse();
  let url:URL;
  try{url=new URL(raw);}catch{refuse();}
  if(!['postgres:','postgresql:'].includes(url.protocol) ||
     url.hostname!=='postgres.railway.internal' || url.port!=='5432' ||
     url.pathname!=='/saas_staging' ||
     decodeURIComponent(url.username)!=='postgres' || !url.password ||
     url.search || url.hash)refuse();
  return url;
}

async function approvedSql():Promise<string>{
  if(!isHex(SQL_SHA,64)||!isHex(COMMIT,40))refuse();
  const url='https://raw.githubusercontent.com/Bagirov24/' +
    'Cli-Proxy-API-Management-Center/'+COMMIT+
    '/staging/saas-bootstrap/'+SQL_FILE;
  const r=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(12000)});
  if(!r.ok||r.url!==url)refuse();
  const bytes=new Uint8Array(await r.arrayBuffer());
  if(bytes.byteLength<12000||bytes.byteLength>20000)refuse();
  const dig=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))]
    .map(x=>x.toString(16).padStart(2,'0')).join('');
  if(dig!==SQL_SHA)refuse();
  const raw=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const meta=raw.split('\n').filter(line=>/^\s*\\/.test(line));
  if(meta.length!==1||meta[0].trim()!=='\\set ON_ERROR_STOP on'||
     !raw.includes('BEGIN;')||!raw.trimEnd().endsWith('COMMIT;'))refuse();
  return raw.replace(/^\\set ON_ERROR_STOP on\s*$/m,'');
}
function bind(sql:string,values:Record<string,string>):string{
  const seen=new Set<string>();
  for(const v of Object.values(values))
    if(![40,64].includes(v.length)||!isHex(v,v.length))refuse();
  const bound=sql.replace(/:'([a-z_0-9]+)'/g,(_m,key:string)=>{
    if(!Object.prototype.hasOwnProperty.call(values,key))refuse();
    seen.add(key);return "'"+values[key]+"'";
  });
  if(Object.keys(values).some(k=>!seen.has(k)) ||
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
    application_name:'saas-backend13-migration-once',
  });
}

async function before(admin:InstanceType<typeof pg.Client>){
  const q=await admin.query(
    "SELECT current_database() AS db,session_user AS login,"+
    "current_setting('server_version_num')::int AS ver,"+
    "(SELECT rolsuper FROM pg_roles WHERE rolname=session_user) AS superuser,"+
    "(SELECT rolcanlogin FROM pg_roles WHERE rolname='saas_schema_migrator') AS mig_login,"+
    "(SELECT rolpassword FROM pg_authid WHERE rolname='saas_schema_migrator') AS mig_password,"+
    "(SELECT count(*)::int FROM pg_auth_members WHERE roleid IN ("+
    "SELECT oid FROM pg_roles WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer'))) AS memberships,"+
    "(SELECT count(*)::int FROM pg_namespace WHERE nspname='saas_acl') AS acl"
  );
  const x=q.rows[0];
  if(q.rows.length!==1||x.db!=='saas_staging'||x.login!=='postgres'||
     x.ver<160000||x.ver>=170000||x.superuser!==true||
     x.mig_login!==false||x.mig_password!==null||+x.memberships!==0||+x.acl!==1)refuse();
  const receipt=await admin.query(
    'SELECT migration_id,source_sha256 FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  );
  if(receipt.rows.length!==4||
     !receipt.rows.every((r,i)=>r.migration_id===PREVIOUS[i][0]&&r.source_sha256===PREVIOUS[i][1]))refuse();
  const previousFunc=await admin.query(
    "SELECT prosecdef,provolatile,pg_get_userbyid(proowner) AS owner FROM pg_proc "+
    "WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure"
  );
  if(previousFunc.rows.length!==1||previousFunc.rows[0].prosecdef!==true||
     previousFunc.rows[0].provolatile!=='s'||
     previousFunc.rows[0].owner!=='saas_schema_migrator')refuse();
  const data=await admin.query(
    'SELECT (SELECT count(*)::int FROM saas_data.tenants) AS tenants,'+
    '(SELECT count(*)::int FROM saas_data.projects) AS projects,'+
    '(SELECT count(*)::int FROM saas_acl.principal_tenants) AS grants,'+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN ("+
    "'saas_data.tenants'::regclass,'saas_data.projects'::regclass)) AS policies,"+
    "(SELECT count(*)::int FROM pg_class WHERE oid IN ("+
    "'saas_data.tenants'::regclass,'saas_data.projects'::regclass) "+
    "AND relrowsecurity AND relforcerowsecurity) AS force"
  );
  const z=data.rows[0];
  if(data.rows.length!==1||+z.tenants!==0||+z.projects!==0||+z.grants!==0||
     +z.policies!==2||+z.force!==2)refuse();
  const extras=await admin.query(
    "SELECT to_regclass('saas_acl.principal_access_audit') IS NOT NULL AS audit_exists,"+
    "to_regprocedure('saas_acl.change_principal_access(name,uuid,bigint,text,text)') IS NOT NULL AS fn_exists"
  );
  if(extras.rows.length!==1||extras.rows[0].audit_exists||
     extras.rows[0].fn_exists)refuse();
}

async function after(admin:InstanceType<typeof pg.Client>){
  const receipts=await admin.query(
    'SELECT migration_id,source_sha256,source_commit,applied_by '+
    'FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  );
  if(receipts.rows.length!==5||
     !receipts.rows.slice(0,4).every((r,i)=>r.migration_id===PREVIOUS[i][0]&&
        r.source_sha256===PREVIOUS[i][1])||
     receipts.rows[4].migration_id!=='0005_principal_lifecycle_revocation_fence'||
     receipts.rows[4].source_sha256!==SQL_SHA||
     receipts.rows[4].source_commit!==COMMIT||
     receipts.rows[4].applied_by!=='saas_schema_migrator')refuse();
  const f=await admin.query(
    "SELECT prosecdef,provolatile,pg_get_userbyid(proowner) AS owner "+
    "FROM pg_proc WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure"
  );
  if(f.rows.length!==1||f.rows[0].prosecdef!==true||
     f.rows[0].provolatile!=='v'||f.rows[0].owner!=='saas_schema_migrator')refuse();
  const changes=await admin.query(
    "SELECT prosecdef,provolatile FROM pg_proc "+
    "WHERE oid='saas_acl.change_principal_access(name,uuid,bigint,text,text)'::regprocedure"
  );
  if(changes.rows.length!==1||changes.rows[0].prosecdef!==false||
     changes.rows[0].provolatile!=='v')refuse();
  const safety=await admin.query(
    "SELECT (SELECT count(*)::int FROM saas_data.tenants) AS tenants,"+
    "(SELECT count(*)::int FROM saas_data.projects) AS projects,"+
    "(SELECT count(*)::int FROM saas_acl.principal_tenants) AS grants,"+
    "(SELECT count(*)::int FROM saas_acl.principal_access_audit) AS audit,"+
    "(SELECT count(*)::int FROM pg_trigger WHERE tgrelid='saas_acl.principal_tenants'::regclass "+
    "AND NOT tgisinternal AND tgenabled IN ('O','A')) AS map_triggers,"+
    "(SELECT count(*)::int FROM pg_trigger WHERE tgrelid='saas_acl.principal_access_audit'::regclass "+
    "AND NOT tgisinternal AND tgenabled IN ('O','A')) AS audit_triggers,"+
    "(SELECT count(*)::int FROM pg_class WHERE oid IN ("+
    "'saas_data.tenants'::regclass,'saas_data.projects'::regclass) "+
    "AND relrowsecurity AND relforcerowsecurity) AS force,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN ("+
    "'saas_data.tenants'::regclass,'saas_data.projects'::regclass) "+
    "AND polcmd='r') AS read_policies,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN ("+
    "'saas_data.tenants'::regclass,'saas_data.projects'::regclass)) AS all_policies,"+
    "(SELECT count(*)::int FROM pg_auth_members WHERE roleid IN ("+
    "SELECT oid FROM pg_roles WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer'))) AS memberships,"+
    "has_function_privilege('saas_runtime_reader',"+
    "'saas_acl.change_principal_access(name,uuid,bigint,text,text)','EXECUTE') AS reader_operator,"+
    "has_function_privilege('saas_runtime_writer',"+
    "'saas_acl.change_principal_access(name,uuid,bigint,text,text)','EXECUTE') AS writer_operator,"+
    "has_table_privilege('saas_runtime_reader',"+
    "'saas_acl.principal_access_audit','SELECT') AS audit_read"
  );
  const s=safety.rows[0];
  if(safety.rows.length!==1||+s.tenants!==0||+s.projects!==0||
     +s.grants!==0||+s.audit!==0||+s.map_triggers!==2||
     +s.audit_triggers!==2||+s.force!==2||+s.read_policies!==2||
     +s.all_policies!==2||+s.memberships!==0||
     s.reader_operator!==false||s.writer_operator!==false||s.audit_read!==false)refuse();
}

async function seal(admin:InstanceType<typeof pg.Client>){
  await admin.query('ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL');
  const x=await admin.query(
    "SELECT rolcanlogin,rolpassword FROM pg_authid WHERE rolname='saas_schema_migrator'"
  );
  if(x.rows.length!==1||x.rows[0].rolcanlogin!==false||
     x.rows[0].rolpassword!==null)refuse();
}

async function run(){
  const url=environment();
  const sql=await approvedSql(); // network + SHA check before DB contact
  const secret=[...crypto.getRandomValues(new Uint8Array(32))]
    .map(b=>b.toString(16).padStart(2,'0')).join('');
  if(!isHex(secret,64))refuse();
  const admin=client(url);
  const migUrl=new URL(url.toString());
  migUrl.username='saas_schema_migrator';migUrl.password=secret;
  const migrator=client(migUrl);
  let adminOpen=false,migratorOpen=false,loginMayExist=false,sealed=false;
  try {
    await admin.connect();adminOpen=true;
    await before(admin);
    loginMayExist=true;
    const until=new Date(Date.now()+5*60*1000).toISOString();
    await admin.query("ALTER ROLE saas_schema_migrator LOGIN PASSWORD '"+
      secret+"' VALID UNTIL '"+until+"'");
    await migrator.connect();migratorOpen=true;
    await migrator.query(bind(sql,{
      expected_0004_sha256:PREVIOUS[3][1],
      migration_sha256:SQL_SHA,source_commit:COMMIT,
    }));
    // The COMMIT must be acknowledged. UNKNOWN = STOP, not a replay.
    await after(admin);
    await seal(admin);sealed=true;
    console.info('PASS_BACKEND13_STAGING_PG16_0005_CAS_AUDIT_FENCE_NOLOGIN');
  } finally {
    if(migratorOpen){try{await migrator.end();}catch{/* STOP, no retry */}}
    if(adminOpen){
      // Narrow containment if COMMIT or readback became uncertain.
      // Never repeat/reissue 0005; revoke temporary LOGIN only.
      if(loginMayExist&&!sealed){try{await seal(admin);}catch{/* operator reconcile */}}
      try{await admin.end();}catch{/* do not retry */}
    }
  }
}

try{await run();}
catch {
  console.error(STOP); // No secret, SQL, driver stack, URL or token.
  process.exitCode=1;
}

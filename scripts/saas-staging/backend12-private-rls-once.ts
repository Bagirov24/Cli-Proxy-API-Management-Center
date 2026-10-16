/**
 * Backend12 private one-shot PG16 role-bound tenant READ RLS installer.
 * Staging-only; no HTTP listener, login provisioning, app data or retry.
 * Operator accepted loss of disposable STAGING data, not production data.
 */
import pg from 'pg@8.16.3';

const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENV='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const PINNED_COMMIT='8b06c308d2fe52abb17b44fa09451db0994d3850';
const FILES=[
  ['0003_operator_runtime_roles.sql','8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e'],
  ['0004_principal_bound_read_rls.sql','4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980'],
] as const;
const PRIOR1='7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279';
const PRIOR2='80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f';
const STOP='BACKEND12_STOP_UNKNOWN_COMMIT_RECONCILE_NO_RETRY';

function deny(): never {throw new Error('Isolated Backend12 one-shot refused');}
function hex(v:string,n:number){return new RegExp('^[a-f0-9]{'+n+'}$').test(v);}

function environment(): URL {
  const e=process.env;
  if(e.RAILWAY_PROJECT_ID!==PROJECT || e.RAILWAY_ENVIRONMENT_ID!==ENV ||
     e.RAILWAY_ENVIRONMENT_NAME!=='staging' ||
     e.RAILWAY_SERVICE_NAME!=='saas-b12-rls-once' ||
     e.SAAS_B12_APPLY_EXPLICIT_ENABLE!=='true' ||
     e.SAAS_B12_ACCEPT_NO_BACKUP!=='true' ||
     e.GITHUB_ACTIONS==='true')deny();
  const raw=e.STAGING_POSTGRES_PRIVATE_URL;
  if(typeof raw!=='string'||raw.length>1024||raw.length<35)deny();
  let url:URL;
  try{url=new URL(raw);}catch{deny();}
  if(!['postgres:','postgresql:'].includes(url.protocol) ||
     url.hostname!=='postgres.railway.internal' ||
     url.port!=='5432' || url.pathname!=='/saas_staging' ||
     decodeURIComponent(url.username)!=='postgres' || !url.password ||
     url.search || url.hash)deny();
  return url;
}

async function checkedSource(name:string, hash:string) {
  if(!FILES.some(([n,h])=>n===name&&h===hash))deny();
  const url='https://raw.githubusercontent.com/Bagirov24/' +
    'Cli-Proxy-API-Management-Center/'+PINNED_COMMIT+
    '/staging/saas-bootstrap/'+name;
  const r=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(12000)});
  if(!r.ok || r.url!==url)deny();
  const bytes=new Uint8Array(await r.arrayBuffer());
  if(bytes.byteLength<2500||bytes.byteLength>10500)deny();
  const actual=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))]
    .map(v=>v.toString(16).padStart(2,'0')).join('');
  if(actual!==hash)deny();
  const sql=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const meta=sql.split('\n').filter(l=>/^\s*\\/.test(l));
  if(meta.length!==1||meta[0].trim()!=='\\set ON_ERROR_STOP on'||
     !sql.includes('BEGIN;')||!sql.trimEnd().endsWith('COMMIT;'))deny();
  return sql.replace(/^\\set ON_ERROR_STOP on\s*$/m,'');
}

function bind(sql:string, values:Record<string,string>){
  const keys=new Set<string>();
  for(const v of Object.values(values)){
    if(![40,64].includes(v.length)||!hex(v,v.length))deny();
  }
  const bound=sql.replace(/:'([a-z_0-9]+)'/g,(_match,key:string)=>{
    if(!Object.prototype.hasOwnProperty.call(values,key))deny();
    keys.add(key);return "'"+values[key]+"'";
  });
  if(Object.keys(values).some(k=>!keys.has(k))||
     /:'[a-z_0-9]+'/i.test(bound)||/^\s*\\/m.test(bound))deny();
  return bound;
}

function makeClient(url:URL){
  return new pg.Client({
    connectionString:url.toString(),
    options:'-c saas.staging_only=true',
    connectionTimeoutMillis:6000,
    query_timeout:25000,
    statement_timeout:20000,
    application_name:'saas-backend12-migration-once',
  });
}

async function preflight(admin:InstanceType<typeof pg.Client>){
  const q=await admin.query(
    "SELECT current_database() AS db,session_user AS login,"+
    "current_setting('server_version_num')::int AS version,"+
    "(SELECT rolsuper FROM pg_roles WHERE rolname=session_user) AS superuser,"+
    "(SELECT rolcanlogin FROM pg_roles WHERE rolname='saas_schema_migrator') AS mig_login,"+
    "(SELECT count(*)::int FROM pg_roles WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer')) AS roles,"+
    "(SELECT count(*)::int FROM pg_namespace WHERE nspname='saas_acl') AS acl,"+
    "(SELECT count(*)::int FROM pg_policy WHERE polrelid IN ("+
    "'saas_data.tenants'::regclass,'saas_data.projects'::regclass)) AS policies"
  );
  const x=q.rows[0];
  if(q.rows.length!==1||x.db!=='saas_staging'||x.login!=='postgres'||
     x.version<160000||x.version>=170000||x.superuser!==true||
     x.mig_login!==false||+x.roles!==0||+x.acl!==0||+x.policies!==0)deny();
  const ledger=await admin.query(
    'SELECT migration_id,source_sha256 FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  );
  if(ledger.rows.length!==2||
     ledger.rows[0].migration_id!=='0001_ledger_only' ||
     ledger.rows[0].source_sha256!==PRIOR1 ||
     ledger.rows[1].migration_id!=='0002_tenant_projects_baseline' ||
     ledger.rows[1].source_sha256!==PRIOR2)deny();
  const catalog=await admin.query(
    "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid IN ("+
    "'saas_data.tenants'::regclass,'saas_data.projects'::regclass)"
  );
  if(catalog.rows.length!==2||
     !catalog.rows.every(r=>r.relrowsecurity&&r.relforcerowsecurity))deny();
  const data=await admin.query(
    'SELECT (SELECT count(*)::int FROM saas_data.tenants) AS t,'+
    '(SELECT count(*)::int FROM saas_data.projects) AS p'
  );
  if(data.rows.length!==1||+data.rows[0].t!==0||+data.rows[0].p!==0)deny();
}

async function verify(admin:InstanceType<typeof pg.Client>){
  const receipts=await admin.query(
    'SELECT migration_id,source_sha256,source_commit,applied_by '+
    'FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  );
  if(receipts.rows.length!==4 ||
     receipts.rows[0].migration_id!=='0001_ledger_only' ||
     receipts.rows[0].source_sha256!==PRIOR1 ||
     receipts.rows[1].migration_id!=='0002_tenant_projects_baseline' ||
     receipts.rows[1].source_sha256!==PRIOR2 ||
     receipts.rows[2].migration_id!=='0003_operator_runtime_roles' ||
     receipts.rows[2].source_sha256!==FILES[0][1] ||
     receipts.rows[2].source_commit!==PINNED_COMMIT ||
     receipts.rows[2].applied_by!=='postgres' ||
     receipts.rows[3].migration_id!=='0004_principal_bound_read_rls' ||
     receipts.rows[3].source_sha256!==FILES[1][1] ||
     receipts.rows[3].source_commit!==PINNED_COMMIT ||
     receipts.rows[3].applied_by!=='saas_schema_migrator')deny();
  const roles=await admin.query(
    "SELECT count(*)::int AS n FROM pg_roles WHERE rolname IN ("+
    "'saas_runtime_reader','saas_runtime_writer') AND NOT rolcanlogin "+
    'AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit AND NOT rolcreaterole'
  );
  if(+roles.rows[0]?.n!==2)deny();
  const grants=await admin.query(
    "SELECT has_table_privilege('saas_runtime_reader','saas_data.projects','INSERT') AS reader_write,"+
    "has_table_privilege('saas_runtime_writer','saas_data.projects','INSERT') AS writer_write,"+
    "has_table_privilege('saas_runtime_reader','saas_acl.principal_tenants','SELECT') AS private_map_read,"+
    "(SELECT count(*)::int FROM pg_auth_members WHERE roleid IN ("+
    "SELECT oid FROM pg_roles WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer'))) AS memberships"
  );
  const g=grants.rows[0];
  if(grants.rows.length!==1||g.reader_write!==false||g.writer_write!==false||
     g.private_map_read!==false||+g.memberships!==0)deny();
  const policies=await admin.query(
    "SELECT c.relrowsecurity,c.relforcerowsecurity,p.polcmd,"+
    "(SELECT count(*)::int FROM pg_policy p2 WHERE p2.polrelid=c.oid) AS n "+
    'FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace '+
    'JOIN pg_policy p ON p.polrelid=c.oid '+
    "WHERE ns.nspname='saas_data' AND c.relname IN ('tenants','projects')"
  );
  if(policies.rows.length!==2 || !policies.rows.every(r=>
    r.relrowsecurity===true && r.relforcerowsecurity===true &&
    r.polcmd==='r' && +r.n===1))deny();
  const definer=await admin.query(
    "SELECT prosecdef,provolatile FROM pg_proc "+
    "WHERE oid='saas_acl.can_read_tenant(uuid)'::regprocedure"
  );
  if(definer.rows.length!==1||definer.rows[0].prosecdef!==true||
     definer.rows[0].provolatile!=='s')deny();
  const counts=await admin.query(
    'SELECT (SELECT count(*)::int FROM saas_acl.principal_tenants) AS grants,'+
    '(SELECT count(*)::int FROM saas_data.tenants) AS tenants,'+
    '(SELECT count(*)::int FROM saas_data.projects) AS projects'
  );
  if(counts.rows.length!==1 || +counts.rows[0].grants!==0 ||
     +counts.rows[0].tenants!==0 || +counts.rows[0].projects!==0)deny();
}

async function seal(admin:InstanceType<typeof pg.Client>){
  await admin.query('ALTER ROLE saas_schema_migrator NOLOGIN PASSWORD NULL');
  const q=await admin.query(
    "SELECT r.rolcanlogin,a.rolpassword FROM pg_roles r "+
    "JOIN pg_authid a ON a.oid=r.oid WHERE r.rolname='saas_schema_migrator'"
  );
  if(q.rows.length!==1 || q.rows[0].rolcanlogin!==false ||
     q.rows[0].rolpassword!==null)deny();
}

async function run(){
  const adminUrl=environment();
  const [roleSql,policySql]=await Promise.all(FILES.map(
    ([name,digest])=>checkedSource(name,digest)
  ));
  const secret=[...crypto.getRandomValues(new Uint8Array(32))]
    .map(v=>v.toString(16).padStart(2,'0')).join('');
  if(!hex(secret,64))deny();
  const admin=makeClient(adminUrl);
  const userUrl=new URL(adminUrl.toString());
  userUrl.username='saas_schema_migrator';userUrl.password=secret;
  const migrator=makeClient(userUrl);
  let adminReady=false,temporaryLoginMayExist=false,migratorReady=false,sealed=false;
  try{
    await admin.connect();adminReady=true;
    await preflight(admin);
    // Each operation is ONE-SHOT. An ambiguous ACK is UNKNOWN, not replayed.
    await admin.query(bind(roleSql,{
      migration_sha256:FILES[0][1],source_commit:PINNED_COMMIT
    }));
    // Time-limited random credential: NOLOGIN is restored after read-back.
    const expiration=new Date(Date.now()+5*60*1000).toISOString();
    temporaryLoginMayExist=true;
    await admin.query(
      "ALTER ROLE saas_schema_migrator LOGIN PASSWORD '"+secret+
      "' VALID UNTIL '"+expiration+"'"
    );
    await migrator.connect();migratorReady=true;
    await migrator.query(bind(policySql,{
      expected_0003_sha256:FILES[0][1],
      migration_sha256:FILES[1][1],source_commit:PINNED_COMMIT
    }));
    await verify(admin);
    await seal(admin);sealed=true;
    console.info('PASS_BACKEND12_STAGING_READ_ONLY_ROLE_RLS_0003_0004_NOLOGIN');
  } finally {
    if(migratorReady){try{await migrator.end();}catch{/* never retry */}}
    if(adminReady){
      if(temporaryLoginMayExist&&!sealed){
        // Containment, NOT retry/reissue of any migration.
        // If this fails, temporary random login also expires in 5min.
        try{await seal(admin);}catch{/* manual reconciliation required */}
      }
      try{await admin.end();}catch{/* never retry */}
    }
  }
}
try{await run();}
catch{
  // No server errors, SQL, passwords, hostnames, or tokens in public logs.
  console.error(STOP);
  process.exitCode=1;
}

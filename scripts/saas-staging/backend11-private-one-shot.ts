/**
 * Backend11. One-shot private Railway Function: NEVER a public HTTP handler.
 * Applies REVIEWED PG16 staging 0000 -> 0001 -> 0002, NO retry on uncertainty.
 * The user accepts loss of disposable staging data; NOT production ready.
 */
import pg from 'pg@8.16.3';

const PROJECT = 'a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENVIRONMENT = 'b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const COMMIT = '7b2158009b742b47e12fd738c34ae430662803cf';
const ROLE = 'saas_schema_migrator';
const FILES = [
  ['0000_operator_migrator_role.sql', '08047267af4750206d6963b058d2766b4f4f2ea16bb60e90209070aa65a4aab3'],
  ['0001_ledger_only.sql', '7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279'],
  ['0002_tenant_projects_baseline.sql', '80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f'],
] as const;

const FAIL = 'BACKEND11_STOP_UNKNOWN_STATE_RECONCILE_NO_RETRY';

function refuse(): never { throw new Error('Backend11 refused'); }
function hex(value: string, n: number) {
  return new RegExp('^[a-f0-9]{' + n + '}$').test(value);
}

function validateEnvironment(): URL {
  const e = process.env;
  if (e.RAILWAY_PROJECT_ID !== PROJECT ||
      e.RAILWAY_ENVIRONMENT_ID !== ENVIRONMENT ||
      e.RAILWAY_ENVIRONMENT_NAME !== 'staging' ||
      e.RAILWAY_SERVICE_NAME !== 'saas-bootstrap-once' ||
      e.SAAS_BOOTSTRAP_EXPLICIT_ENABLE !== 'true' ||
      e.SAAS_BOOTSTRAP_OPERATOR_ACCEPT_LOSS !== 'true' ||
      e.GITHUB_ACTIONS === 'true') refuse();
  const raw = e.STAGING_POSTGRES_PRIVATE_URL;
  if (!raw || raw.length > 1024) refuse();
  let url: URL;
  try { url = new URL(raw); } catch { refuse(); }
  if (!['postgres:', 'postgresql:'].includes(url.protocol) ||
      url.hostname !== 'postgres.railway.internal' ||
      url.port !== '5432' || url.pathname !== '/saas_staging' ||
      decodeURIComponent(url.username) !== 'postgres' ||
      !url.password || url.search || url.hash) refuse();
  return url;
}

async function checkedSource(name: string, digest: string): Promise<string> {
  if (!FILES.some(([n,h]) => n === name && h === digest)) refuse();
  const url = 'https://raw.githubusercontent.com/Bagirov24/' +
    'Cli-Proxy-API-Management-Center/' + COMMIT +
    '/staging/saas-bootstrap/' + name;
  const r = await fetch(url, {redirect:'error', signal:AbortSignal.timeout(12000)});
  if (!r.ok || r.url !== url) refuse();
  const bytes = new Uint8Array(await r.arrayBuffer());
  if (bytes.length < 2500 || bytes.length > 9500) refuse();
  const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))]
    .map(v=>v.toString(16).padStart(2,'0')).join('');
  if (hash !== digest) refuse();
  const sql = new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const meta = sql.split('\n').filter(line=>/^\s*\\/.test(line));
  if (meta.length !== 1 || meta[0].trim() !== '\\set ON_ERROR_STOP on' ||
      !sql.includes('BEGIN;') || !sql.trimEnd().endsWith('COMMIT;')) refuse();
  return sql.replace(/^\\set ON_ERROR_STOP on\s*$/m,'');
}

function bind(sql: string, variables: Record<string,string>): string {
  for (const value of Object.values(variables))
    if (![40,64].includes(value.length) || !hex(value,value.length)) refuse();
  const seen = new Set<string>();
  const out = sql.replace(/:'([a-z_0-9]+)'/g, (_match,key: string) => {
    if (!Object.prototype.hasOwnProperty.call(variables,key)) refuse();
    seen.add(key);
    return "'" + variables[key] + "'";
  });
  if (Object.keys(variables).some(key=>!seen.has(key)) ||
      /:'[a-z_0-9]+'/i.test(out) || /^\s*\\/m.test(out)) refuse();
  return out;
}

function client(url: URL) {
  return new pg.Client({
    connectionString: url.toString(),
    connectionTimeoutMillis: 6000,
    options: '-c saas.staging_only=true',
    query_timeout: 25000,
    statement_timeout: 20000,
    application_name: 'saas-backend11-once',
  });
}

async function blank(admin: InstanceType<typeof pg.Client>) {
  const x = await admin.query(
    'SELECT current_database() AS db, session_user AS login, ' +
    "current_setting('server_version_num')::int AS ver, " +
    '(SELECT rolsuper FROM pg_roles WHERE rolname=session_user) AS superuser, ' +
    "(SELECT COUNT(*)::int FROM pg_roles WHERE rolname='saas_schema_migrator') AS roles, " +
    "(SELECT COUNT(*)::int FROM pg_namespace WHERE nspname IN (" +
    "'saas_bootstrap','saas_data','saas_rls','saas_rls_private'," +
    "'saas_m1_private','saas_m1_api')) AS schemas"
  );
  const r = x.rows[0];
  if (x.rows.length !== 1 || r.db !== 'saas_staging' ||
      r.login !== 'postgres' || r.ver < 160000 || r.ver >= 170000 ||
      r.superuser !== true || +r.roles !== 0 || +r.schemas !== 0) refuse();
}

async function verify(admin: InstanceType<typeof pg.Client>) {
  const receipt = await admin.query(
    'SELECT migration_id,source_sha256,source_commit,applied_by ' +
    'FROM saas_bootstrap.schema_migrations ORDER BY migration_id'
  );
  if (receipt.rows.length !== 2 ||
      receipt.rows[0].migration_id !== '0001_ledger_only' ||
      receipt.rows[1].migration_id !== '0002_tenant_projects_baseline' ||
      receipt.rows[0].source_sha256 !== FILES[1][1] ||
      receipt.rows[1].source_sha256 !== FILES[2][1] ||
      !receipt.rows.every(r=>r.source_commit===COMMIT && r.applied_by===ROLE))
    refuse();
  const catalog = await admin.query(
    'SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, ' +
    'pg_get_userbyid(c.relowner) AS owner, ' +
    '(SELECT count(*)::int FROM pg_policy p WHERE p.polrelid=c.oid) AS policies ' +
    'FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace ' +
    "WHERE n.nspname='saas_data' AND c.relname IN ('tenants','projects')"
  );
  if (catalog.rows.length !== 2 ||
      !catalog.rows.every(r=>r.relrowsecurity===true &&
        r.relforcerowsecurity===true && r.owner===ROLE && +r.policies===0))
    refuse();
  const counts = await admin.query(
    'SELECT (SELECT count(*)::int FROM saas_data.tenants) AS tenants, ' +
    '(SELECT count(*)::int FROM saas_data.projects) AS projects, ' +
    "(SELECT count(*)::int FROM pg_namespace WHERE nspname IN (" +
    "'saas_rls','saas_m1_private','saas_m1_api')) AS pilot"
  );
  const row = counts.rows[0];
  if (counts.rows.length !== 1 || +row.tenants!==0 ||
      +row.projects!==0 || +row.pilot!==0) refuse();
}

async function run() {
  const url = validateEnvironment();
  const [zero,one,two] = await Promise.all(FILES.map(
    ([name,digest])=>checkedSource(name,digest)
  ));
  const secret = [...crypto.getRandomValues(new Uint8Array(32))]
    .map(x=>x.toString(16).padStart(2,'0')).join('');
  if (!hex(secret,64)) refuse();
  const admin=client(url);
  const roleUrl = new URL(url.toString());
  roleUrl.username=ROLE;
  roleUrl.password=secret;
  const migrator=client(roleUrl);
  let adminOpen=false, roleOpen=false;
  try {
    await admin.connect(); adminOpen=true;
    await blank(admin);
    await admin.query(bind(zero,{migration_password:secret}));
    await migrator.connect(); roleOpen=true;
    await migrator.query(bind(one,{
      bootstrap_sha256:FILES[1][1], source_commit:COMMIT
    }));
    await migrator.query(bind(two,{
      expected_0001_sha256:FILES[1][1],
      migration_sha256:FILES[2][1],source_commit:COMMIT
    }));
    await verify(admin);
    // Seal the transient LOGIN without storing the secret anywhere.
    await admin.query('ALTER ROLE saas_schema_migrator NOLOGIN');
    const check=await admin.query(
      "SELECT rolcanlogin FROM pg_roles WHERE rolname='saas_schema_migrator'"
    );
    if (check.rows.length!==1 || check.rows[0].rolcanlogin!==false) refuse();
    console.info('PASS_BACKEND11_STAGING_PG16_0000_0001_0002_FORCE_RLS_NOLOGIN');
  } finally {
    if (roleOpen) {try {await migrator.end();} catch {/* do not retry */}}
    if (adminOpen) {
      // On UNKNOWN COMMIT, NEVER issue another SQL statement or replay.
      // Operator must reconcile role, schema and receipts independently.
      try {await admin.end();} catch {/* no retry */}
    }
  }
}

try { await run(); }
catch {
  // No DB diagnostic, password, stack trace, SQL content or URL in logs.
  console.error(FAIL);
  process.exitCode=1;
}

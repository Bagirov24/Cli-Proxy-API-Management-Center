/**
 * Backend16.16: Railway staging SQL0008 INSTALLED postflight, no migration.
 * Runs the unmodified DO block of the immutable Backend16.8 read-only SQL.
 * Exact operator expectation is INSTALLED: eight receipts + exact SQL0008 gate.
 * No WRITE transaction, DDL, migration, HTTP listener, cron, public DB, retry.
 * NO positive marker if the DB is partially migrated, busy, drifted or unreadable.
 * Source: 0df48301c16e29a23c5df56d5ed456cb03b8ec13
 * DO block audited against scripts/saas-staging/backend16-0008-readonly-reconcile.sql.
 * This is NOT authorization to run SQL0008 or to retry an UNKNOWN COMMIT.
 */
import {SQL} from 'bun';
import {
  backend16IsApprovedStagingPgTlsTrust,
  type Backend16StagingPgTlsTrust,
} from '../../src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts';
const PROJECT='a9703851-6eb1-406c-bb15-7d3a89359fb7';
const ENV='b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b';
const SERVICE='saas-b16-0008-readonly-preflight';
const SERVICE_ID='ff2df1d3-3bca-483c-bc2a-0edea01dd3f1';
const EXPECTED='installed';
const MARKER='PASS_BACKEND16_SQL0008_READONLY_INSTALLED_SEALED';
// Only pre-reviewed constant failure codes may appear in logs. Never raw SQL,
// error objects, credentials, connection URL, or server-provided free text.
const ALLOWED_CATALOG_STOP_MARKERS=new Set(["B16_READONLY_STOP_B14_TRIGGERS","B16_READONLY_STOP_B15_TRIGGERS","B16_READONLY_STOP_BINDING_CATALOG","B16_READONLY_STOP_CONCURRENT_STAGING_CLIENT","B16_READONLY_STOP_CONTEXT","B16_READONLY_STOP_FORCE_RLS","B16_READONLY_STOP_MIGRATOR_NOT_SEALED","B16_READONLY_STOP_NONEMPTY_OR_ROLE_DRIFT","B16_READONLY_STOP_PARTIAL_SQL0008","B16_READONLY_STOP_PREVIOUS_RECEIPTS","B16_READONLY_STOP_RECEIPT_COUNT","B16_READONLY_STOP_RUNTIME_PRIVILEGES","B16_READONLY_STOP_SQL0007_PROVENANCE","B16_READONLY_STOP_SQL0008_FUNCTION_DRIFT","B16_READONLY_STOP_SQL0008_PROVENANCE","B16_READONLY_STOP_TEMPLATE_ROLES","B16_READONLY_STOP_UNEXPECTED_TABLE_GRANTS"]);
const RECONCILE_DO_SQL="DO $b16_readonly$\nDECLARE\n  wanted text := current_setting('saas.b16.reconcile_expected',true);\n  staging boolean := (current_database()='saas_staging');\n  n integer;\n  migrator_role record;\n  f record;\nBEGIN\n  IF wanted NOT IN ('absent','installed')\n     OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999\n     OR current_database() NOT IN ('saas_staging','saas_staging_ci')\n     OR current_setting('saas.staging_only',true) IS DISTINCT FROM 'true'\n     OR current_setting('transaction_read_only') <> 'on'\n     OR session_user <> 'postgres' OR current_user <> 'postgres'\n     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles\n                     WHERE rolname='postgres' AND rolsuper AND rolcanlogin)\n     OR pg_catalog.pg_is_in_recovery()\n  THEN RAISE EXCEPTION 'B16_READONLY_STOP_CONTEXT'; END IF;\n\n  SELECT count(*)::int INTO n\n    FROM pg_catalog.pg_stat_activity\n   WHERE datname=current_database()\n     AND pid<>pg_catalog.pg_backend_pid() AND backend_type='client backend';\n  IF staging AND n<>0 THEN\n    RAISE EXCEPTION 'B16_READONLY_STOP_CONCURRENT_STAGING_CLIENT';\n  END IF;\n\n  SELECT r.rolcanlogin AS login, a.rolpassword IS NULL AS no_password,\n         r.rolsuper OR r.rolbypassrls OR r.rolcreaterole\n          OR r.rolcreatedb OR r.rolreplication AS privileged\n    INTO migrator_role\n    FROM pg_catalog.pg_roles r\n    JOIN pg_catalog.pg_authid a ON a.oid=r.oid\n   WHERE r.rolname='saas_schema_migrator';\n  IF NOT FOUND OR migrator_role.login IS DISTINCT FROM false\n     OR migrator_role.no_password IS DISTINCT FROM true\n     OR migrator_role.privileged IS DISTINCT FROM false THEN\n    RAISE EXCEPTION 'B16_READONLY_STOP_MIGRATOR_NOT_SEALED';\n  END IF;\n\n  SELECT count(*)::int INTO n\n    FROM pg_catalog.pg_roles\n   WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer')\n     AND NOT rolcanlogin AND NOT rolinherit\n     AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole\n     AND NOT rolcreatedb AND NOT rolreplication;\n  IF n<>2 THEN RAISE EXCEPTION 'B16_READONLY_STOP_TEMPLATE_ROLES'; END IF;\n\n  IF (SELECT count(*)::int FROM saas_bootstrap.schema_migrations)\n     <> (CASE WHEN wanted='absent' THEN 7 ELSE 8 END)\n  THEN RAISE EXCEPTION 'B16_READONLY_STOP_RECEIPT_COUNT'; END IF;\n\n  WITH expected(id,sha,author) AS (\n    VALUES\n      ('0001_ledger_only','7ee1feb3316f87b18be2d79d51fbbaeb9d8354dc200c8785b991300ee1c51279','saas_schema_migrator'),\n      ('0002_tenant_projects_baseline','80acdac5c7a97257bb8819d752baf52acd091d21ca28a433d448f5a9cb1c129f','saas_schema_migrator'),\n      ('0003_operator_runtime_roles','8bd26bb1e798e1196f64546a0bfd554cfe46c6a5cd9d4414d369bc1cbf98124e','postgres'),\n      ('0004_principal_bound_read_rls','4084aba0f461ac1e0da4faf00d630485ba86953d7e63648df8d5468c8ec21980','saas_schema_migrator'),\n      ('0005_principal_lifecycle_revocation_fence','b37eb4d07125766be98f69b93cb6a5f4ee16298d09e0ab4c118c63c2ba7d2556','saas_schema_migrator'),\n      ('0006_principal_session_fence','b811c33822be02ad515d3ff2678ca7a58cfe7e90dff34c138ce6ace9468a0505','saas_schema_migrator'),\n      ('0007_operator_subject_binding_fence','1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0','saas_schema_migrator')\n  )\n  SELECT count(*)::int INTO n\n    FROM expected e\n    FULL JOIN saas_bootstrap.schema_migrations m ON m.migration_id=e.id\n   WHERE (m.migration_id IS NULL OR e.id IS NULL)\n     OR m.source_sha256 IS DISTINCT FROM e.sha\n     OR m.applied_by IS DISTINCT FROM e.author;\n  -- An INSTALLED state has one additional, independently validated SQL0008\n  -- receipt, so the FULL JOIN mismatch count is exactly one in that state.\n  IF n<>(CASE WHEN wanted='absent' THEN 0 ELSE 1 END) THEN\n    RAISE EXCEPTION 'B16_READONLY_STOP_PREVIOUS_RECEIPTS';\n  END IF;\n\n  IF NOT EXISTS (\n      SELECT 1 FROM saas_bootstrap.schema_migrations\n       WHERE migration_id='0007_operator_subject_binding_fence'\n         AND source_sha256='1fa9bf930e0977e11e7e920a6daa69265f8863e90b85e190bfecea3b5249e6f0'\n         AND (NOT staging OR source_commit='6cc4a76a0b3144380ccc95f0ca1c275ae312cae3')\n         AND source_commit ~ '^[a-f0-9]{40}$'\n  ) THEN RAISE EXCEPTION 'B16_READONLY_STOP_SQL0007_PROVENANCE'; END IF;\n\n  IF wanted='installed' AND NOT EXISTS (\n      SELECT 1 FROM saas_bootstrap.schema_migrations\n       WHERE migration_id='0008_exact_subject_session_gate'\n         AND source_sha256='ef4858975fea0842ae16d1b572457641c0359fa9630f02a1d52ea972007c632b'\n         AND applied_by='saas_schema_migrator'\n         AND (NOT staging OR source_commit='314f0962f2d955241fb5ee7a29175bddb648c130')\n         AND source_commit ~ '^[a-f0-9]{40}$'\n  ) THEN RAISE EXCEPTION 'B16_READONLY_STOP_SQL0008_PROVENANCE'; END IF;\n\n  SELECT count(*)::int INTO n FROM pg_catalog.pg_class\n   WHERE oid IN ('saas_data.tenants'::regclass,\n                 'saas_data.projects'::regclass)\n     AND relrowsecurity AND relforcerowsecurity;\n  IF n<>2 OR\n    (SELECT count(*)::int FROM pg_catalog.pg_policy\n      WHERE polrelid IN ('saas_data.tenants'::regclass,\n                         'saas_data.projects'::regclass))<>2 OR\n    (SELECT count(*)::int FROM pg_catalog.pg_policy\n      WHERE polrelid IN ('saas_data.tenants'::regclass,\n                         'saas_data.projects'::regclass) AND polcmd='r')<>2\n  THEN RAISE EXCEPTION 'B16_READONLY_STOP_FORCE_RLS'; END IF;\n\n  SELECT count(*)::int INTO n\n    FROM pg_catalog.pg_trigger\n   WHERE tgrelid IN ('saas_identity.principal_sessions'::regclass,\n                     'saas_identity.session_events'::regclass)\n     AND NOT tgisinternal AND tgenabled='O';\n  IF n<>5 THEN RAISE EXCEPTION 'B16_READONLY_STOP_B14_TRIGGERS'; END IF;\n  SELECT count(*)::int INTO n\n    FROM pg_catalog.pg_trigger\n   WHERE tgrelid IN ('saas_identity.subject_bindings'::regclass,\n                     'saas_identity.subject_binding_events'::regclass)\n     AND NOT tgisinternal AND tgenabled='O';\n  IF n<>5 THEN RAISE EXCEPTION 'B16_READONLY_STOP_B15_TRIGGERS'; END IF;\n\n  IF (SELECT count(*)::int FROM pg_catalog.pg_index\n       WHERE indrelid='saas_identity.subject_bindings'::regclass\n         AND indisunique)<>3\n     OR (SELECT count(*)::int FROM pg_catalog.pg_constraint\n       WHERE conrelid='saas_identity.subject_bindings'::regclass\n         AND conname='b15_revoke_marker')<>1\n  THEN RAISE EXCEPTION 'B16_READONLY_STOP_BINDING_CATALOG'; END IF;\n\n  IF EXISTS (\n     SELECT 1 FROM pg_catalog.pg_roles\n      WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer')\n        AND pg_catalog.has_schema_privilege(rolname,'saas_identity','USAGE')\n  ) OR EXISTS (\n     SELECT 1 FROM pg_catalog.pg_roles\n      WHERE rolname IN ('saas_runtime_reader','saas_runtime_writer')\n        AND (pg_catalog.has_table_privilege(\n                rolname,'saas_identity.principal_sessions','SELECT')\n          OR pg_catalog.has_table_privilege(\n                rolname,'saas_identity.subject_bindings','SELECT')\n          OR pg_catalog.has_table_privilege(\n                rolname,'saas_identity.subject_binding_events','SELECT')\n          OR pg_catalog.has_table_privilege(\n                rolname,'saas_data.tenants','INSERT, UPDATE, DELETE, TRUNCATE')\n          OR pg_catalog.has_table_privilege(\n                rolname,'saas_data.projects','INSERT, UPDATE, DELETE, TRUNCATE'))\n  ) THEN RAISE EXCEPTION 'B16_READONLY_STOP_RUNTIME_PRIVILEGES'; END IF;\n\n  SELECT count(*)::int INTO n\n    FROM pg_catalog.pg_class c\n    CROSS JOIN LATERAL pg_catalog.aclexplode(\n      coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl\n   WHERE c.oid IN (\n     'saas_data.tenants'::regclass,'saas_data.projects'::regclass,\n     'saas_acl.principal_tenants'::regclass,\n     'saas_acl.principal_access_audit'::regclass,\n     'saas_identity.principal_sessions'::regclass,\n     'saas_identity.session_events'::regclass,\n     'saas_identity.subject_bindings'::regclass,\n     'saas_identity.subject_binding_events'::regclass)\n     AND acl.grantee NOT IN (\n       SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN\n        ('saas_schema_migrator','saas_runtime_reader','saas_runtime_writer'));\n  IF n<>0 THEN RAISE EXCEPTION 'B16_READONLY_STOP_UNEXPECTED_TABLE_GRANTS'; END IF;\n\n  IF staging THEN\n    IF EXISTS (\n      SELECT 1 FROM pg_catalog.pg_roles WHERE left(rolname,5)='saas_'\n        AND rolname NOT IN ('saas_schema_migrator',\n                            'saas_runtime_reader','saas_runtime_writer')\n    ) OR EXISTS (\n      SELECT 1 FROM pg_catalog.pg_auth_members\n       WHERE roleid IN (SELECT oid FROM pg_catalog.pg_roles\n                         WHERE left(rolname,5)='saas_')\n          OR member IN (SELECT oid FROM pg_catalog.pg_roles\n                         WHERE left(rolname,5)='saas_')\n    ) OR\n       (SELECT count(*) FROM saas_data.tenants)<>0 OR\n       (SELECT count(*) FROM saas_data.projects)<>0 OR\n       (SELECT count(*) FROM saas_acl.principal_tenants)<>0 OR\n       (SELECT count(*) FROM saas_acl.principal_access_audit)<>0 OR\n       (SELECT count(*) FROM saas_identity.principal_sessions)<>0 OR\n       (SELECT count(*) FROM saas_identity.session_events)<>0 OR\n       (SELECT count(*) FROM saas_identity.subject_bindings)<>0 OR\n       (SELECT count(*) FROM saas_identity.subject_binding_events)<>0\n    THEN RAISE EXCEPTION 'B16_READONLY_STOP_NONEMPTY_OR_ROLE_DRIFT'; END IF;\n  END IF;\n\n  IF wanted='absent' THEN\n    IF to_regprocedure(\n      'saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)')\n      IS NOT NULL THEN\n      RAISE EXCEPTION 'B16_READONLY_STOP_PARTIAL_SQL0008';\n    END IF;\n  ELSE\n    SELECT p.prosecdef,p.provolatile,p.prorettype,\n           pg_catalog.pg_get_userbyid(p.proowner) AS owner_name,\n           p.proconfig,p.proargnames,\n           (SELECT lanname FROM pg_catalog.pg_language WHERE oid=p.prolang) AS language_name,\n           pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex') AS body_sha256,\n           pg_catalog.has_function_privilege(\n             'saas_runtime_reader',p.oid,'EXECUTE') AS reader_execute,\n           pg_catalog.has_function_privilege(\n             'saas_runtime_writer',p.oid,'EXECUTE') AS writer_execute,\n           (SELECT count(*)::int FROM pg_catalog.aclexplode(\n               coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a\n             WHERE a.grantee NOT IN (\n               SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN (\n                 'saas_schema_migrator','saas_runtime_reader',\n                 'saas_runtime_writer'))) AS foreign_grants,\n           pg_catalog.pg_get_functiondef(p.oid) AS definition\n      INTO f\n      FROM pg_catalog.pg_proc p\n     WHERE p.oid=to_regprocedure(\n       'saas_acl.exact_subject_session_authorized(uuid,uuid,uuid,text)');\n    IF NOT FOUND OR f.prosecdef IS DISTINCT FROM true\n       OR f.provolatile IS DISTINCT FROM 'v'\n       OR f.prorettype IS DISTINCT FROM 'boolean'::regtype\n       OR f.owner_name IS DISTINCT FROM 'saas_schema_migrator'\n       OR f.proconfig IS NULL\n       OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']\n       OR f.proargnames IS DISTINCT FROM ARRAY['p_tenant','p_session','p_binding','p_subject_sha256']\n       OR f.language_name IS DISTINCT FROM 'plpgsql'\n       OR f.body_sha256 IS DISTINCT FROM '158e303247b82187dc081212a10eb90f1295cf40f8874e353fef377a14ac753e'\n       OR f.reader_execute IS DISTINCT FROM true\n       OR f.writer_execute IS DISTINCT FROM true\n       OR f.foreign_grants<>0\n       OR f.definition NOT LIKE '%s.session_id=p_session%'\n       OR f.definition NOT LIKE '%s.identity_binding_id=p_binding%'\n       OR f.definition NOT LIKE '%b.subject_fingerprint=p_subject_sha256%'\n       OR f.definition NOT LIKE '%FOR SHARE%'\n    THEN RAISE EXCEPTION 'B16_READONLY_STOP_SQL0008_FUNCTION_DRIFT'; END IF;\n  END IF;\nEND\n$b16_readonly$;";
function stop():never{
  // Exit without Bun's source excerpt/stack; never expose embedded SQL or URL.
  console.error('B16_READONLY_PREFLIGHT_STOP_NO_DATABASE_WRITES');
  process.exit(1);
}
/** A separately reviewed operator wrapper must supply the branded CA policy. */
export async function runBackend16RailwayReadOnlyPostflight(
  tlsTrust?:Backend16StagingPgTlsTrust,
):Promise<void>{
const e=Bun.env;
if(e.RAILWAY_PROJECT_ID!==PROJECT||e.RAILWAY_ENVIRONMENT_ID!==ENV||
   e.RAILWAY_ENVIRONMENT_NAME!=='staging'||e.RAILWAY_SERVICE_NAME!==SERVICE||
   e.RAILWAY_SERVICE_ID!==SERVICE_ID||e.GITHUB_ACTIONS==='true'||
   e.NODE_TLS_REJECT_UNAUTHORIZED==='0')stop();
// Absence of explicit operator enablement must be a silent NO-DB terminal
// path, not a crashing Railway restart loop. Never print secret values.
if(e.SAAS_B16_READONLY_PREFLIGHT_EXPLICIT_ENABLE!=='true'||
   !e.STAGING_POSTGRES_PRIVATE_URL){
  console.info('B16_READONLY_PREFLIGHT_DISABLED_NO_DATABASE');
  process.exit(0);
}
let uri:URL;
try{uri=new URL(e.STAGING_POSTGRES_PRIVATE_URL!)}catch{stop()}
if(!['postgres:','postgresql:'].includes(uri.protocol)||
   uri.hostname!=='postgres.railway.internal'||
   uri.port!=='5432'||uri.pathname!=='/saas_staging'||
   decodeURIComponent(uri.username)!=='postgres'||
   !uri.password||uri.search||uri.hash)stop();
// Private DNS and encryption alone do not authenticate PostgreSQL. Refuse
// before reading the password or constructing SQL unless a separate operator
// policy supplied a current branded CA. No CA is discovered or auto-approved.
if(!backend16IsApprovedStagingPgTlsTrust(tlsTrust)){
  console.error('B16_READONLY_POSTFLIGHT_BLOCKED_OPERATOR_TLS_APPROVAL_REQUIRED');
  return;
}
let password:string;
try{password=decodeURIComponent(uri.password)}catch{stop()}
const pool=new SQL({adapter:'postgres',hostname:'postgres.railway.internal',
  port:5432,database:'saas_staging',username:'postgres',password,
  tls:tlsTrust,max:1,connectionTimeout:4,idleTimeout:0,prepare:false});
let connection:Awaited<ReturnType<typeof pool.reserve>>|undefined;
type Phase='RESERVE'|'BEGIN'|'SCOPED'|'CATALOG'|'COMMIT'|'CLOSE';
let phase:Phase='RESERVE';
let transaction=false,commitSent=false,closed=false,failed=false;
let failurePhase:Phase|null=null;
let catalogStopCode:string|null=null;
try{
  connection=await pool.reserve({signal:AbortSignal.timeout(8000)});
  phase='BEGIN';
  await connection.unsafe('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY',[]).execute();
  transaction=true;
  phase='SCOPED';
  await connection.unsafe('SET LOCAL search_path = pg_catalog, pg_temp',[]).execute();
  await connection.unsafe("SET LOCAL statement_timeout = '15000ms'",[]).execute();
  await connection.unsafe("SET LOCAL lock_timeout = '3000ms'",[]).execute();
  // Match the audited psql operator invocation's
  // PGOPTIONS='-c saas.staging_only=true'. A LOCAL, immutable scope tag,
  // never a database role, tenant claim, grant, schema mutation or proof.
  // Private host+DB+Railway IDs and catalog guards are separately pinned.
  await connection.unsafe("SELECT pg_catalog.set_config('saas.staging_only','true',true)",[]).execute();
  await connection.unsafe("SELECT pg_catalog.set_config('saas.b16.reconcile_expected','installed',true)",[]).execute();
  phase='CATALOG';
  await connection.unsafe(RECONCILE_DO_SQL,[]).execute();
  commitSent=true;
  phase='COMMIT';
  await connection.unsafe('COMMIT',[]).execute();
}catch(error){
  failed=true;
  failurePhase=phase; // closed enum ONLY, never record raw error or connection URL
  if(phase==='CATALOG'&&error instanceof Error){
    const candidate=error.message.match(/B16_READONLY_STOP_[A-Z0-9_]+/)?.[0];
    if(candidate&&ALLOWED_CATALOG_STOP_MARKERS.has(candidate))
      catalogStopCode=candidate;
  }
  if(transaction&&!commitSent&&connection){
    try{await connection.unsafe('ROLLBACK',[]).execute()}catch{/* read-only only */}
  }
}finally{
  try{
    connection?.release();
    await pool.close({timeout:0});
    closed=true;
  }catch{
    failed=true;
    failurePhase='CLOSE';
  }
}
// Negative/uncertain observations MUST terminate without a Railway crash
// restart and without ever producing the positive verification marker.
if(failed||!closed||EXPECTED!=='installed'){
  console.error('B16_READONLY_PREFLIGHT_STOP_PHASE_'+
    (failurePhase??'CLOSE')+'_REASON_'+
    (catalogStopCode??'UNSPECIFIED')+'_NO_DATABASE_WRITES');
  process.exit(0);
}
console.info(MARKER);
}
// The standalone Function has no approved CA policy. Keep it blocked until
// an independent operator reviews a concrete wrapper; never infer trust.
if(import.meta.main)await runBackend16RailwayReadOnlyPostflight();

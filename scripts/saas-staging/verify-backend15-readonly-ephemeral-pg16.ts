/**
 * Disposable GitHub Actions PostgreSQL16 end-to-end contract for the real
 * Backend15 read-only catalog collector. NEVER targets a Railway resource.
 *
 * The shell workflow constructs the isolated saas_staging database with
 * reviewed SQL0000..0006 (absent) and SQL0007 (installed), independently.
 * Here we only read the resulting catalog in REPEATABLE READ READ ONLY mode.
 */
import pg from 'pg';
import {classifyBackend15Snapshot,collect,type Verdict} from './backend15-readonly-reconcile';

const REFUSE='BACKEND15_EPHEMERAL_READONLY_RECONCILE_FAIL_CLOSED';
let phase='environment';
async function run() {
  const e=process.env;
  if(e.GITHUB_ACTIONS!=='true'||e.SAAS_B15_RECONCILE_EPHEMERAL_CI!=='true'||
     e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||e.PGUSER!=='postgres'||
     e.PGDATABASE!=='saas_staging'||!e.PGPASSWORD||
     e.NODE_ENV==='production'||e.RAILWAY_PROJECT_ID||
     e.RAILWAY_ENVIRONMENT_ID||e.RAILWAY_SERVICE_ID||
     !['absent','installed'].includes(e.SAAS_B15_RECONCILE_EXPECTED||'')) {
    throw Error('refused non-ephemeral contract');
  }
  const desired=e.SAAS_B15_RECONCILE_EXPECTED as Verdict;
  const client=new pg.Client({
    host:'127.0.0.1',port:5432,database:'saas_staging',user:'postgres',
    password:e.PGPASSWORD,ssl:false,
    options:'-c default_transaction_read_only=on -c saas.staging_only=true',
    statement_timeout:15000,query_timeout:20000,connectionTimeoutMillis:5000,
    application_name:'saas-backend15-ci-readonly-catalog',
  });
  let connected=false;
  try {
    phase='connection';
    await client.connect();connected=true;
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    phase='catalog_readonly_query';
    const state=await collect(client);
    phase='catalog_classification';
    const verdict=classifyBackend15Snapshot(state);
    if(verdict!==desired){
      // Only synthetic numeric/boolean CI counters; no subjects, SQL or secrets.
      console.error('BACKEND15_EPHEMERAL_CATALOG_MISMATCH '+JSON.stringify({
        verdict,receipts:state.receipts.length,metadata:{
          sealed:state.metadata.sealed,ver:state.metadata.ver,
          safe_runtime_roles:state.metadata.safe_runtime_roles,
          new_roles:state.metadata.new_roles,memberships:state.metadata.memberships,
          read_only:state.metadata.read_only
        },baseline:state.baseline,objects:state.objects
      }));
    }
    await client.query('COMMIT');
    if(verdict!==desired)throw Error('readonly catalog state mismatch');
    if(verdict==='absent')
      console.info('PASS_BACKEND15_EPHEMERAL_PG16_READONLY_0007_ABSENT');
    if(verdict==='installed')
      console.info('PASS_BACKEND15_EPHEMERAL_PG16_READONLY_0007_INSTALLED');
  }finally {
    if(connected)try{await client.end()}catch{/* never change or retry */}
  }
}
try{await run()}
catch (error) {
  // Do not print SQL, database connection strings, credentials or role metadata.
  const maybeCode=(error as {code?:unknown})?.code;
  const sqlState=typeof maybeCode==='string' && /^[0-9A-Z]{5}$/.test(maybeCode)
    ?maybeCode:'none';
  console.error(REFUSE+'_'+phase+'_'+sqlState);
  process.exitCode=1;
}

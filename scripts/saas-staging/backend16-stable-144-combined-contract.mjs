/** Strict CI-only process boundary; never a production credential resolver. */
export const COMBINED_REVISION='38afee6c84fcf48c0edb2466aa4b27d287a59c30';
export const COMBINED_STEPS=Object.freeze([
  'stats','stats','wrong-version','stats','expired','stats',
  'deferred','wait','release','stats','pass','stats','done',
]);
export const COMBINED_MARKERS=Object.freeze([
  'B16_STABLE_144_COMBINED_MTLS_TWO_TENANT_TLS_RLS_PID_PASS',
  'B16_STABLE_144_COMBINED_WRONG_VERSION_EXPIRED_PREAUTH_DENY',
  'B16_STABLE_144_COMBINED_REVOKED_IN_FLIGHT_PREAUTH_DENY',
  'B16_STABLE_144_COMBINED_LOCK_ABORT_PID_DEATH_QUARANTINE_PASS',
  'B16_STABLE_144_COMBINED_WRONG_PG_ROOT_DENIED',
  'B16_STABLE_144_COMBINED_12_FRESH_BROKER_READS_PASS',
  'B16_STABLE_144_COMBINED_BLOCKED_RELEASE',
]);
const denied=()=>{throw Error('Backend16 stable combined CI refused');};
const HEX=/^[a-f0-9]{64}$/;
const SHA=/^[a-f0-9]{40}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export function assertCombinedEnvironment(e,major,checkout){
  if(!e||major!==24||e.CI!=='true'||e.GITHUB_ACTIONS!=='true'||
     e.GITHUB_EVENT_NAME!=='pull_request'||
     e.GITHUB_REPOSITORY!=='Bagirov24/Cli-Proxy-API-Management-Center'||
     e.RUNNER_OS!=='Linux'||e.RUNNER_ARCH!=='X64'||
     !SHA.test(e.B16_PR_HEAD_SHA??'')||checkout!==e.B16_PR_HEAD_SHA||
     !SHA.test(e.GITHUB_SHA??'')||
     e.SAAS_B16_EPHEMERAL_CI!=='true'||
     e.SAAS_B16_STABLE_144_FULL_PG16_CI!=='true'||
     e.SAAS_B16_STABLE_144_COMBINED_CI!=='true'||
     e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||e.PGUSER!=='postgres'||
     e.PGDATABASE!=='saas_ephemeral_test'||e.PGPASSWORD!=='ci_ephemeral_test_only'||
     e.NODE_ENV==='production'||e.NODE_TLS_REJECT_UNAUTHORIZED==='0'||e.DATABASE_URL||
     Object.keys(e).some(k=>k.startsWith('RAILWAY_')&&e[k])||
     !/^\/tmp\/b16-official-stable-144-ci-[A-Za-z0-9]{6}\/bun$/.test(e.SAAS_B16_STABLE_144_BIN??'')||
     !HEX.test(e.SAAS_B16_CI_PG_CONTAINER??''))denied();
  for(const k of ['A','B']){
    if(!HEX.test(e['SAAS_B16_CI_'+k+'_PASSWORD']??'')||
       !HEX.test(e['SAAS_B16_CI_'+k+'_SUBJECT_SHA']??''))denied();
    for(const field of ['TENANT','SESSION','BINDING'])
      if(!UUID.test(e['SAAS_B16_CI_'+k+'_'+field]??''))denied();
  }
  return true;
}
export function combinedChildEnvironment(e){
  // Deliberately no principal passwords, NODE_OPTIONS or inherited arbitrary secrets.
  const keys=['PATH','CI','GITHUB_ACTIONS','PGHOST','PGPORT','PGUSER','PGDATABASE',
    'PGPASSWORD','SAAS_B16_CI_PG_CONTAINER','SAAS_B16_EPHEMERAL_CI',
    'SAAS_B16_STABLE_144_FULL_PG16_CI','SAAS_B16_STABLE_144_COMBINED_CI'];
  for(const k of ['A','B'])for(const field of ['SUBJECT_SHA','TENANT','SESSION','BINDING'])
    keys.push('SAAS_B16_CI_'+k+'_'+field);
  const output=Object.fromEntries(keys.filter(k=>typeof e[k]==='string').map(k=>[k,e[k]]));
  return Object.freeze({...output,SAAS_B16_PHYSICAL_CI:'true',
    SAAS_B16_PHYSICAL_TLS_CI:'true',SAAS_B16_BROKER_MTLS_CI:'true'});
}
export function parseCombinedCommand(line,index){
  if(typeof line!=='string'||line.length>160||!Number.isInteger(index)||
     index<0||index>=COMBINED_STEPS.length)denied();
  let value;
  try{value=JSON.parse(line);}catch{denied();}
  if(!value||Array.isArray(value)||Object.keys(value).join(',')!=='id,op'||
     value.id!==index+1||value.op!==COMBINED_STEPS[index]||
     JSON.stringify(value)!==line)denied();
  return Object.freeze(value);
}
export function assertCombinedBrokerReceipt(calls,received){
  if(calls!==12||!Array.isArray(received)||received.length!==12)denied();
  const counts={saas_b14_person:0,saas_b16_person_b:0};
  for(const x of received){
    if(!x||Object.keys(x).sort().join(',')!=='pgLogin,secretId,version')denied();
    const letter=x.pgLogin==='saas_b14_person'?'a':
      x.pgLogin==='saas_b16_person_b'?'b':null;
    if(!letter||x.secretId!=='b16-stg-pg-'+letter.repeat(20)||
       x.version!==letter.repeat(32))denied();
    counts[x.pgLogin]++;
  }
  if(counts.saas_b14_person!==8||counts.saas_b16_person_b!==4)denied();
  return true;
}

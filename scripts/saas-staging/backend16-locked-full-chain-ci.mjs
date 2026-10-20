/** CI-only composition of the existing #81 E2E with the #86 verified installs. */
import {spawnSync} from 'node:child_process';
import {realpathSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {enforceBackend16GenuineLockCiEnvironment} from './verify-backend16-nodepg-real-lock-ci.mjs';

export const FULL_CHAIN_MARKERS=Object.freeze([
  'B16_NODEPG_COMBINED_MTLS_VERSIONED_TLS_RLS_PASS',
  'B16_NODEPG_EXACT_TWO_TENANT_TLS_RLS_PASS',
  'B16_NODEPG_MTLS_WRONG_VERSION_AND_EXPIRED_PREAUTH_DENY',
  'B16_NODEPG_MTLS_REVOKED_IN_FLIGHT_PREAUTH_DENY',
  'B16_NODEPG_EXACT_PHYSICAL_SSL_PID_DISCARD_PASS',
  'B16_NODEPG_ASYNC_SOCKET_ERROR_QUARANTINE_PID_DEATH_PASS',
  'B16_NODEPG_EXACT_WRONG_CA_PREAUTH_DENY',
  'B16_NODEPG_EXACT_CA_VALID_WILDCARD_PREAUTH_DENY',
  'B16_NODEPG_EXACT_LOCK_ABORT_PID_DEATH_PASS',
  'PASS Backend16 Node PG real TLS exact SQL0008 two-tenant PG16 RLS',
  'PASS Backend16 Node PG synthetic mTLS broker vault PG16 RLS full chain',
]);
function refuse(){throw new Error('Backend16 locked full chain CI refused');}
export function enforceLockedFullChainEnvironment(e,nodeMajor){
  enforceBackend16GenuineLockCiEnvironment(e,nodeMajor);
  if(e.SAAS_B16_LOCKED_FULL_CHAIN_CI!=='true'||
     e.SAAS_B16_EPHEMERAL_CI!=='true'||
     e.SAAS_B16_NODEPG_PHYSICAL_CI!=='true'||e.SAAS_B16_BROKER_MTLS_CI!=='true'||
     e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||e.PGUSER!=='postgres'||
     e.PGDATABASE!=='saas_ephemeral_test'||e.PGPASSWORD!=='ci_ephemeral_test_only'||
     !/^[a-f0-9]{64}$/.test(e.SAAS_B16_CI_PG_CONTAINER??''))refuse();
}
export function verifyFullChainResult(result){
  if(result.error||result.signal||result.status!==0||typeof result.stdout!=='string')refuse();
  const lines=result.stdout.split(/\r?\n/);
  if(!FULL_CHAIN_MARKERS.every(marker=>lines.filter(line=>line===marker).length===1))refuse();
  return FULL_CHAIN_MARKERS;
}
export function runLockedFullChainCi(dirs){
  enforceLockedFullChainEnvironment(process.env,Number(process.versions.node.split('.')[0]));
  if(!Array.isArray(dirs)||dirs.length!==2||dirs[0]===dirs[1])refuse();
  const canonical=dirs.map(dir=>realpathSync(dir));
  if(canonical.some((dir,i)=>dir!==dirs[i]||
      !/^\/tmp\/b16-nodepg-dual-lock-ci-[a-zA-Z0-9]+\/independent-[ab]$/.test(dir))||
     dirname(canonical[0])!==dirname(canonical[1])||
     !canonical[0].endsWith('/independent-a')||!canonical[1].endsWith('/independent-b'))refuse();
  const script=fileURLToPath(new URL('./verify-backend16-nodepg-exact-pg16-ci.ts',import.meta.url));
  for(const [index,dir] of canonical.entries()){
    const result=spawnSync(process.execPath,['--experimental-strip-types',script],{
      cwd:join(dirname(script),'../..'),
      env:{...process.env,SAAS_B16_VERIFIED_NODEPG_DIR:dir},
      encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:110_000,maxBuffer:1_000_000,
    });
    // Never forward raw output/errors that might contain generated passwords.
    for(const marker of verifyFullChainResult(result))console.info(marker);
    console.info('B16_LOCKED_FULL_CHAIN_INDEPENDENT_'+(index===0?'A':'B')+'_PASS');
  }
  console.info('B16_LOCKED_DUAL_INSTALL_MTLS_VAULT_PG16_EXACT_RLS_PASS');
}

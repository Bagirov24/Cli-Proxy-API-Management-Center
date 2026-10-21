/**
 * Backend16 — independent Node pg TLS identity fixture on TWO verified npm
 * graph installations. CI-only: reuse the genuine dual-lock supply-chain
 * gate; never introduce a separate, floating npm install or broker/RLS path.
 */
import {spawnSync} from 'node:child_process';
import {enforceBackend16GenuineLockCiEnvironment}
  from './verify-backend16-nodepg-real-lock-ci.mjs';

const REFUSED='Backend16 dual-locked NodePG peer TLS CI refused';
export const REQUIRED_LOCKED_NODEPG_PEER_MARKERS=Object.freeze([
  'B16_NODEPG_AUTHENTICATED_SSL_AND_EXACT_SAN_PASS',
  'B16_NODEPG_PHYSICAL_PID_DISCARD_PASS',
  'B16_NODEPG_FORCED_CALLBACK_DENIED',
  'B16_NODEPG_WRONG_CA_DENIED',
  'B16_NODEPG_WILDCARD_SAN_DENIED',
  'B16_NODEPG_WRONG_SAN_DENIED',
  'B16_NODEPG_CN_ONLY_DENIED',
  'PASS Backend16 Node24 pg authenticated PostgreSQL peer verification',
]);
const CONTAINER=/^[0-9a-f]{64}$/;
const DIRECTORY=/^(\/tmp\/b16-nodepg-dual-lock-ci-[a-zA-Z0-9]+)\/independent-([ab])$/;
const refuse=()=>{throw Error(REFUSED);};

export function enforceLockedNodePgPeerCiEnvironment(e,nodeMajor){
  enforceBackend16GenuineLockCiEnvironment(e,nodeMajor);
  if(e.SAAS_B16_LOCKED_NODEPG_PEER_CI!=='true'||
     e.SAAS_B16_NODEPG_PEER_CI!=='true'||
     e.PGHOST!=='127.0.0.1'||e.PGPORT!=='5432'||
     e.PGUSER!=='postgres'||e.PGDATABASE!=='saas_ephemeral_test'||
     e.PGPASSWORD!=='ci_ephemeral_test_only'||
     !CONTAINER.test(e.SAAS_B16_CI_PG_CONTAINER??'')||
     e.SAAS_B16_VERIFIED_NODEPG_DIR!==undefined||
     e.SAAS_B16_LOCKED_PG16_CI!==undefined||
     e.SAAS_B16_LOCKED_FULL_CHAIN_CI!==undefined)refuse();
}

export function verifyLockedNodePgPeerResult(result){
  if(!result||result.error||result.signal||result.status!==0||
     typeof result.stdout!=='string'||result.stdout.length>128_000)refuse();
  const lines=result.stdout.split(/\r?\n/);
  for(const marker of REQUIRED_LOCKED_NODEPG_PEER_MARKERS){
    if(lines.filter(line=>line===marker).length!==1)refuse();
  }
  return REQUIRED_LOCKED_NODEPG_PEER_MARKERS;
}

export function runLockedNodePgPeerCi(dirs){
  enforceLockedNodePgPeerCiEnvironment(
    process.env,Number(process.versions.node.split('.')[0]),
  );
  if(!Array.isArray(dirs)||dirs.length!==2||dirs[0]===dirs[1])refuse();
  const a=typeof dirs[0]==='string'?DIRECTORY.exec(dirs[0]):null;
  const b=typeof dirs[1]==='string'?DIRECTORY.exec(dirs[1]):null;
  if(!a||!b||a[1]!==b[1]||a[2]!=='a'||b[2]!=='b')refuse();
  for(const [index,dir] of dirs.entries()){
    const result=spawnSync(process.execPath,[
      '--experimental-strip-types',
      'scripts/saas-staging/verify-backend16-nodepg-peer-ci.ts',
    ],{
      env:{...process.env,SAAS_B16_VERIFIED_NODEPG_DIR:dir},
      encoding:'utf8',stdio:['ignore','pipe','pipe'],
      timeout:120_000,maxBuffer:512*1024,
    });
    // Never replay raw TLS/tool output or errors: the fixture controls
    // stdout markers; provider output may accidentally carry secret material.
    for(const marker of verifyLockedNodePgPeerResult(result)){
      console.info('B16_LOCKED_NODEPG_PEER_'+(index===0?'A':'B')+
        '_'+marker+'_VERIFIED');
    }
    console.info('B16_LOCKED_NODEPG_PEER_INDEPENDENT_'+
      (index===0?'A':'B')+'_PASS');
  }
  console.info('B16_LOCKED_NODEPG_PEER_DUAL_LOCK_TLS_PASS');
}

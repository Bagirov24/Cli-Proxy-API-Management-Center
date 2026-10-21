/**
 * Backend16 CI-ONLY proof of the same installed Node pg byte tree on TWO
 * separate GitHub-hosted Linux jobs. Each job independently executes the
 * existing dual-lock / dual-npm-ci verifier. No signed package provenance,
 * production runtime approval or live infrastructure authorization.
 */
import {spawnSync} from 'node:child_process';
import {appendFileSync} from 'node:fs';
import {isAbsolute,resolve,sep} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {
  OBSERVED_NODEPG_GRAPH,enforceBackend16GenuineLockCiEnvironment,
} from './verify-backend16-nodepg-real-lock-ci.mjs';

const DENIED='Backend16 NodePG cross-runner CI refused';
const refuse=()=>{throw new Error(DENIED);};
const HEX40=/^[0-9a-f]{40}$/;
const HEX64=/^[0-9a-f]{64}$/;
const OUTPUT_MARKERS=Object.freeze([
  'B16_REAL_LOCK_CI_RESOLUTION_START',
  'B16_REAL_LOCK_CI_OBSERVED_GRAPH_MATCH_PASS',
  'B16_REAL_LOCK_CI_INDEPENDENT_RESOLUTIONS_MATCH_PASS',
  'B16_NODEPG_FROZEN_TREE_INDEPENDENT_MATCH_PASS',
  'B16_REAL_LOCK_CI_FROZEN_INSTALL_PASS',
]);

export function parseBackend16NodePgIndependentGateOutput(stdout){
  if(typeof stdout!=='string'||stdout.length>64_000)refuse();
  const lines=stdout.split(/\r?\n/);
  for(const marker of OUTPUT_MARKERS)
    if(lines.filter(line=>line===marker).length!==1)refuse();
  const installed=lines.filter(line=>
    line.startsWith('B16_NODEPG_FROZEN_TREE_SHA256='));
  if(installed.length!==1)refuse();
  const tree=installed[0].slice('B16_NODEPG_FROZEN_TREE_SHA256='.length);
  if(!HEX64.test(tree))refuse();
  // Reordered or recycled markers must not produce a valid receipt.
  const ordered=[...OUTPUT_MARKERS.slice(0,4),
    'B16_NODEPG_FROZEN_TREE_SHA256='+tree,
    OUTPUT_MARKERS[4]];
  let previous=-1;
  for(const line of ordered){
    const index=lines.findIndex(candidate=>candidate===line);
    if(index<=previous)refuse();
    previous=index;
  }
  const end='PASS Backend16 Node24 independently resolved pg lock twice: '+
    OBSERVED_NODEPG_GRAPH.packageCount+' packages; canonical_sha256='+
    OBSERVED_NODEPG_GRAPH.sha256+
    '; two frozen installs; NO RELEASE AUTHORIZATION';
  if(lines.filter(line=>line===end).length!==1||
     lines.findIndex(line=>line===end)<=previous)refuse();
  return Object.freeze({
    tree,graph:OBSERVED_NODEPG_GRAPH.sha256,
  });
}

export function enforceBackend16NodePgCrossRunnerEnvironment(e,major,mode){
  enforceBackend16GenuineLockCiEnvironment(e,major);
  if(!e||!['record','compare'].includes(mode)||
     e.GITHUB_EVENT_NAME!=='pull_request'||
     e.RUNNER_OS!=='Linux'||e.RUNNER_ARCH!=='X64'||
     !HEX40.test(e.GITHUB_SHA??'')||
     !HEX40.test(e.B16_PR_HEAD_SHA??'')||
     e.SAAS_B16_LOCKED_NODEPG_PEER_CI!==undefined||
     e.SAAS_B16_LOCKED_PG16_CI!==undefined||
     e.SAAS_B16_LOCKED_FULL_CHAIN_CI!==undefined||
     e.SAAS_B16_VERIFIED_NODEPG_DIR!==undefined)refuse();
  if(mode==='record'){
    if(!['A','B'].includes(e.B16_CROSS_RUNNER_SLOT)||
       typeof e.RUNNER_TEMP!=='string'||!isAbsolute(e.RUNNER_TEMP)||
       typeof e.GITHUB_OUTPUT!=='string'||!isAbsolute(e.GITHUB_OUTPUT)||
       !e.GITHUB_OUTPUT.startsWith(e.RUNNER_TEMP+sep))
      refuse();
  }else if(e.B16_CROSS_RUNNER_SLOT!==undefined){
    // Comparison never generates a third npm lock or writes step outputs.
    // GITHUB_OUTPUT exists in every Actions step, including this one.
    refuse();
  }
}

export function assertMatchingBackend16NodePgCrossRunnerProofs(a,b,head,checkout){
  const keys=['slot','head','checkout','graph','tree'];
  const valid=x=>x&&typeof x==='object'&&!Array.isArray(x)&&
    Object.keys(x).sort().join(',')===keys.slice().sort().join(',')&&
    ['A','B'].includes(x.slot)&&HEX40.test(x.head)&&
    HEX40.test(x.checkout)&&HEX64.test(x.graph)&&HEX64.test(x.tree)&&
    x.graph===OBSERVED_NODEPG_GRAPH.sha256;
  if(!valid(a)||!valid(b)||a===b||a.slot!=='A'||b.slot!=='B'||
     !HEX40.test(head??'')||!HEX40.test(checkout??'')||
     a.head!==head||b.head!==head||
     a.checkout!==checkout||b.checkout!==checkout||
     a.graph!==b.graph||a.tree!==b.tree)refuse();
  return 'B16_NODEPG_CROSS_RUNNER_FROZEN_BYTES_MATCH_PASS';
}

function checkoutSha(){
  const result=spawnSync('git',['rev-parse','HEAD'],{
    cwd:fileURLToPath(new URL('../../',import.meta.url)),
    encoding:'utf8',stdio:['ignore','pipe','pipe'],
    timeout:5_000,maxBuffer:4_096,
  });
  if(result.error||result.signal||result.status!==0||
     typeof result.stdout!=='string'||!HEX40.test(result.stdout.trim()))
    refuse();
  return result.stdout.trim();
}
function runGate(){
  const script=fileURLToPath(
    new URL('./verify-backend16-nodepg-real-lock-ci.mjs',import.meta.url));
  const child=spawnSync(process.execPath,[script],{
    cwd:resolve(fileURLToPath(new URL('../../',import.meta.url))),
    env:{
      PATH:process.env.PATH||'/usr/local/bin:/usr/bin:/bin',
      GITHUB_ACTIONS:'true',CI:'true',LANG:'C',
    },
    encoding:'utf8',stdio:['ignore','pipe','pipe'],
    timeout:270_000,maxBuffer:128_000,
  });
  if(child.error||child.signal||child.status!==0||
     child.stderr!==''||typeof child.stdout!=='string')refuse();
  return parseBackend16NodePgIndependentGateOutput(child.stdout);
}

function record(){
  const e=process.env;
  enforceBackend16NodePgCrossRunnerEnvironment(
    e,Number(process.versions.node.split('.')[0]),'record');
  const actual=checkoutSha();
  if(actual!==e.GITHUB_SHA)refuse();
  const proof=runGate();
  const fields={
    slot:e.B16_CROSS_RUNNER_SLOT,
    head:e.B16_PR_HEAD_SHA,
    checkout:actual,
    graph:proof.graph,
    tree:proof.tree,
  };
  // GitHub owns this per-step output file; values are validated ASCII only.
  // The private npm logs, paths, tarballs, locks and credentials never escape.
  appendFileSync(e.GITHUB_OUTPUT,
    Object.entries(fields).map(([k,v])=>k+'='+v+'\n').join(''),
    {encoding:'utf8',flag:'a'});
  console.info('B16_NODEPG_CROSS_RUNNER_'+fields.slot+'_DUAL_INSTALL_PASS');
}
function compare(){
  const e=process.env;
  enforceBackend16NodePgCrossRunnerEnvironment(
    e,Number(process.versions.node.split('.')[0]),'compare');
  const actual=checkoutSha();
  if(actual!==e.GITHUB_SHA)refuse();
  const proof=prefix=>({
    slot:e[prefix+'SLOT'],
    head:e[prefix+'HEAD'],
    checkout:e[prefix+'CHECKOUT'],
    graph:e[prefix+'GRAPH'],
    tree:e[prefix+'TREE'],
  });
  const marker=assertMatchingBackend16NodePgCrossRunnerProofs(
    proof('B16_PROOF_A_'),proof('B16_PROOF_B_'),
    e.B16_PR_HEAD_SHA,actual,
  );
  console.info(marker);
  console.info('B16_NODEPG_CROSS_RUNNER_TREE_SHA256='+
    e.B16_PROOF_A_TREE);
  console.info('NO RELEASE AUTHORIZATION');
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{
    if(process.argv.length!==3)refuse();
    if(process.argv[2]==='record')record();
    else if(process.argv[2]==='compare')compare();
    else refuse();
  }catch{
    console.error('STOP Backend16 NodePG cross-runner CI refused; NO RELEASE AUTHORIZATION');
    process.exitCode=1;
  }
}

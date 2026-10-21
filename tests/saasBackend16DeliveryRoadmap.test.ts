import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {BACKEND16_REQUIRED_STAGING_GATES}
  from '../src/features/saasBlueprint/controlApi/server/backend16ReleaseEvidenceGate.ts';

const read=(path:string)=>readFileSync(new URL(path,import.meta.url),'utf8');
const roadmap=read('../docs/saas/BACKEND_16_DELIVERY_ROADMAP.ru.md');
const index=read('../docs/saas/PRODUCTION_READINESS_GATES_V1.ru.md');
const releaseGate=read('../src/features/saasBlueprint/controlApi/server/backend16ReleaseEvidenceGate.ts');
const physical=read('../src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts');
const graph=read('../scripts/saas-staging/verify-backend16-nodepg-real-lock-ci.mjs');
const tick=String.fromCharCode(96);

test('live release roadmap has exactly all ten signed gates in verifier order',()=>{
  const start='<!-- BEGIN BACKEND16 LIVE GATE LEDGER -->';
  const end='<!-- END BACKEND16 LIVE GATE LEDGER -->';
  assert.equal(roadmap.split(start).length,2);
  assert.equal(roadmap.split(end).length,2);
  const section=roadmap.split(start)[1].split(end)[0];
  const rows=section.split('\n')
    .filter(line=>line.startsWith('| '+tick))
    .map(line=>line.split('|').slice(1,-1).map(col=>
      col.trim().replaceAll(tick,'')));
  assert.equal(rows.length,10,'release gates must not be silently omitted');
  assert.ok(rows.every(row=>row.length===5));
  assert.deepEqual(rows.map(row=>row[0]),[...BACKEND16_REQUIRED_STAGING_GATES]);
  assert.equal(new Set(rows.map(row=>row[0])).size,rows.length);
  const expected=[
    ['db-operator','1h','P6'],
    ['operations-reviewer','24h','P9'],
    ['security-reviewer','1h','P3'],
    ['security-reviewer','1h','P4'],
    ['security-reviewer','1h','P5'],
    ['security-reviewer','1h','P8'],
    ['runtime-reviewer','1h','P10'],
    ['runtime-reviewer','30m','P11'],
    ['security-reviewer','30m','P12'],
    ['operations-reviewer','30m','P12'],
  ];
  assert.deepEqual(rows.map(row=>row.slice(1,4)),expected);
  for(const row of rows){
    assert.equal(row[4],'LIVE_UNVERIFIED',
      'source-only documentation cannot grant real operator approvals');
    assert.ok(roadmap.includes('### '+row[3]+'.'),
      'gate must point to an explicit implementation stage: '+row[0]);
  }
});

test('full delivery stage sequence stays visible and discoverable',()=>{
  const stages=[...roadmap.matchAll(/^### P([0-9]+)\./gm)]
    .map(match=>Number(match[1]));
  assert.deepEqual(stages,Array.from({length:14},(_,i)=>i));
  assert.ok(index.includes('BACKEND_16_DELIVERY_ROADMAP.ru.md'));
  assert.ok(roadmap.includes('P0 → P1 → P2'));
  assert.ok(roadmap.includes('BLOCKED_RELEASE'));
  assert.ok(roadmap.includes('protected:false'));
  assert.ok(roadmap.includes('READY_FOR_INDEPENDENT_REVIEW'));
  assert.ok(releaseGate.includes("result:'BLOCKED'"));
  assert.ok(releaseGate.includes('productionAuthorized:false'));
});

test('roadmap cannot silently reset frozen supply-chain or native TLS hard stop',()=>{
  const sha='b5e2aa1735babcbca40748c0983a73c36c57488f96d857fd4087ae4e7a5341fa';
  assert.ok(graph.includes("sha256:'"+sha+"'"));
  assert.ok(roadmap.includes(sha));
  const frontend=JSON.parse(read('../package.json'));
  assert.equal(frontend.packageManager,'bun@1.3.14');
  assert.ok(roadmap.includes('bun@1.3.14'));
  assert.ok(physical.includes(
    'const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;'));
  assert.ok(roadmap.includes('NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false'));
  assert.ok(roadmap.includes('SQL0008'));
});

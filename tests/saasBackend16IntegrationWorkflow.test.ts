import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {parse} from 'yaml';

test('combined Backend16 workflow preserves independent security test coverage',()=>{
  const workflow=parse(readFileSync(new URL(
    '../.github/workflows/saas-backend16-private-read-contract.yml',import.meta.url),
  'utf8'),{uniqueKeys:true});
  const steps=workflow.jobs['private-read-contract'].steps as Array<{run?:string}>;
  const commands=steps.map(step=>step.run??'').join('\n');
  for(const file of [
    'saasBackend16PrivateTenantProjectRead',
    'saasBackend16PinnedSessionAuthenticator',
    'saasBackend16PhysicalPgAdmission',
    'saasBackend16ExactSessionGate',
    'saasBackend16ExactSessionSqlRead',
    'saasBackend16CiBunPhysicalPgPool',
    'saasBackend16StagingBunPhysicalPgPool',
    'saasBackend16StagingPgTlsTrust',
    'saasBackend16TlsPeerProbe',
    'saasBackend16ReleaseEvidenceGate',
    'saasBackend16StagingVersionedPrincipalVault',
    'saasBackend16PrivateMtlsVersionedSecretReader',
    'saasBackend16Sql0008ReadOnlyReconcile',
  ])assert.ok(commands.includes(`tests/${file}.test.ts`),file);
  for(const runner of [
    'verify-backend16-mtls-secret-broker-ci.ts',
    'verify-backend16-verified-private-pg-tls-ci.ts',
    'verify-backend16-bun-tls-client-ci.ts',
  ])assert.ok(commands.includes(runner),runner);
  assert.equal(workflow.permissions.contents,'read');
});

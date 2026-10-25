/** CI-only transport library; deliberately no server bootstrap or listener. */
import * as exactRead from './src/backend16ExactSessionSqlRead.ts';
import * as admission from './src/backend16PhysicalPgAdmission.ts';
import * as secretReader from './src/backend16PrivateMtlsVersionedSecretReader.ts';
import * as privateRead from './src/backend16PrivateTenantProjectRead.ts';
import * as physicalPool from './src/backend16StagingBunPhysicalPgPool.ts';
import * as tlsTrust from './src/backend16StagingPgTlsTrust.ts';
import * as vault from './src/backend16StagingVersionedPrincipalVault.ts';

export const transport = Object.freeze({
  exactRead, admission, secretReader, privateRead, physicalPool, tlsTrust, vault,
});
export const releaseState = 'BLOCKED_RELEASE' as const;

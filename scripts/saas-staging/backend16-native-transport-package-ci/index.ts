/** CI-only library entry. The reviewed source tree is copied here, never imported from frontend. */
export * as exactSqlRead from './src/features/saasBlueprint/controlApi/server/backend16ExactSessionSqlRead.ts';
export * as physicalAdmission from './src/features/saasBlueprint/controlApi/server/backend16PhysicalPgAdmission.ts';
export * as secretReader from './src/features/saasBlueprint/controlApi/server/backend16PrivateMtlsVersionedSecretReader.ts';
export * as privateRead from './src/features/saasBlueprint/controlApi/server/backend16PrivateTenantProjectRead.ts';
export * as physicalPool from './src/features/saasBlueprint/controlApi/server/backend16StagingBunPhysicalPgPool.ts';
export * as tlsTrust from './src/features/saasBlueprint/controlApi/server/backend16StagingPgTlsTrust.ts';
export * as versionedVault from './src/features/saasBlueprint/controlApi/server/backend16StagingVersionedPrincipalVault.ts';
export const releaseState = 'BLOCKED_RELEASE';
export const serverArtifactBuilt = false;
export const stableRuntimeApproved = false;
export const stagingAuthorized = false;
export const productionAuthorized = false;

import type { BlueprintSnapshot, Owner } from '../domain';
import { publicEgressLabel } from '../egressValidation';
import { authorizeTenantRead, mayViewTenantResource } from './authorization';
import {
  SAAS_CONTROL_API_VERSION,
  type ControlActor,
  type ControlCollection,
  type ControlReadError,
  type ControlReadResult,
  type ControlResource,
  type ResourceOwnership,
} from './contracts';

const HIDDEN: ControlReadError = {
  ok: false,
  status: 404,
  error: { code: 'NOT_FOUND', message: 'Resource unavailable' },
};
const DENIED: ControlReadError = {
  ok: false,
  status: 403,
  error: { code: 'FORBIDDEN', message: 'Permission denied' },
};
const TENANT_OFF: ControlReadError = {
  ok: false,
  status: 403,
  error: { code: 'TENANT_UNAVAILABLE', message: 'Resource unavailable' },
};
const UNAVAILABLE: ControlReadError = {
  ok: false,
  status: 503,
  error: { code: 'SOURCE_UNAVAILABLE', message: 'Service unavailable' },
};

/**
 * Tenant index: only active, unambiguous, session-authorized memberships
 * appear. Never enumerate all tenants based on a client-provided tenant ID.
 */
export function listAccessibleTenants(
  snapshot: BlueprintSnapshot,
  actor: ControlActor
): readonly Extract<ControlResource, { kind: 'tenant' }>[] {
  if (snapshot.schemaVersion !== 1 || !actor?.id?.trim()) return [];
  return snapshot.tenants
    .filter((tenant) => tenant.status === 'active')
    .flatMap((tenant) => {
      const auth = authorizeTenantRead(actor, tenant.id, 'tenant');
      return auth.allowed ? [{
        kind: 'tenant' as const,
        id: tenant.id,
        name: tenant.name,
        status: 'active' as const,
        role: auth.membership.role,
      }] : [];
    });
}

/** Only the whitelisted, independently granted metadata is projected. */
function ownerView(
  snapshot: BlueprintSnapshot,
  owner: Owner,
  tenantId: string
): ResourceOwnership {
  return {
    kind: owner.kind,
    tenantName: owner.kind === 'tenant'
      ? snapshot.tenants.find((entry) => entry.id === owner.tenantId)?.name ?? null
      : null,
    access: owner.kind === 'tenant' && owner.tenantId === tenantId
      ? 'owned' : 'explicit-grant',
  };
}

/**
 * Pure simulation of future GET /control-api/v1/tenants/{tenantId}/metadata/{collection}.
 * Does not connect to Core, read auth files, enforce traffic, authorize OAuth,
 * create sessions or claim a network health check. Actor is a trusted fixture,
 * NOT something the future endpoint may accept from a client request body.
 */
export function readSyntheticTenantCollection(
  snapshot: BlueprintSnapshot,
  actor: ControlActor,
  tenantId: string,
  collection: ControlCollection,
  nowMs: number
): ControlReadResult {
  // Unknown path segments are not a role probe; reject them with generic 404.
  const knownCollections: readonly ControlCollection[] = [
    'tenant', 'projects', 'applications', 'client-keys',
    'accounts', 'pools', 'egress', 'routing',
  ];
  if (!knownCollections.includes(collection)) return HIDDEN;
  const auth = authorizeTenantRead(actor, tenantId, collection);
  if (!auth.allowed) return auth.reason === 'not-found' ? HIDDEN : DENIED;
  if (snapshot.schemaVersion !== 1 || !Number.isFinite(nowMs)) return UNAVAILABLE;
  const tenant = snapshot.tenants.find((entry) => entry.id === tenantId);
  if (!tenant) return HIDDEN;
  if (tenant.status !== 'active') return TENANT_OFF;

  const projects = snapshot.projects.filter((item) => item.tenantId === tenantId);
  const projectIds = new Set(projects.map((item) => item.id));
  const applications = snapshot.applications.filter((item) =>
    item.tenantId === tenantId && projectIds.has(item.projectId));
  const applicationIds = new Set(applications.map((item) => item.id));
  // Expose CPA binding references only: never native Core keys or secret strings.
  const keys = snapshot.keyBindings.filter((item) =>
    item.tenantId === tenantId && item.kind === 'cpa' && applicationIds.has(item.applicationId));
  const keyIds = new Set(keys.map((item) => item.id));

  const accounts = snapshot.providerAccounts.filter((item) =>
    mayViewTenantResource(snapshot, tenantId, 'account', item.id, item.owner, nowMs));
  const accountIds = new Set(accounts.map((item) => item.id));
  const pools = snapshot.accountPools.filter((item) =>
    mayViewTenantResource(snapshot, tenantId, 'pool', item.id, item.owner, nowMs));
  const poolIds = new Set(pools.map((item) => item.id));
  const egress = snapshot.egressProfiles.filter((item) =>
    mayViewTenantResource(snapshot, tenantId, 'egress', item.id, item.owner, nowMs));
  const egressIds = new Set(egress.map((item) => item.id));

  let data: readonly ControlResource[];
  switch (collection) {
    case 'tenant':
      data = [{ kind: 'tenant', id: tenant.id, name: tenant.name, status: 'active',
        role: auth.membership.role }];
      break;
    case 'projects':
      data = projects.map((item) => ({
        kind: 'project', id: item.id, name: item.name, status: item.status, tenantId: item.tenantId,
      }));
      break;
    case 'applications':
      data = applications.map((item) => ({
        kind: 'application', id: item.id, name: item.name, status: item.status,
        projectId: item.projectId,
      }));
      break;
    case 'client-keys':
      data = keys.map((item) => ({
        kind: 'client-key', id: item.id, status: item.status,
        applicationId: item.applicationId, keyType: 'cpa',
      }));
      break;
    case 'accounts':
      data = accounts.map((item) => ({
        kind: 'account', id: item.id, owner: ownerView(snapshot, item.owner, tenantId),
        providerId: item.providerId, authMode: item.authMode,
        authorizationStatus: item.authorizationStatus, status: item.status,
        allowedModelIds: [...item.allowedModelIds],
        egressProfileId: egressIds.has(item.egressProfileId) ? item.egressProfileId : null,
      }));
      break;
    case 'pools':
      data = pools.map((item) => ({
        kind: 'pool', id: item.id, owner: ownerView(snapshot, item.owner, tenantId),
        providerId: item.providerId, status: item.status,
        accountIds: item.accountIds.filter((id) => accountIds.has(id)),
      }));
      break;
    case 'egress':
      data = egress.map((item) => ({
        kind: 'egress', id: item.id, owner: ownerView(snapshot, item.owner, tenantId),
        name: item.name, routeKind: item.kind, status: item.status, health: item.health,
        publicEndpoint: publicEgressLabel(item),
      }));
      break;
    case 'routing':
      data = snapshot.routingBindings
        .filter((item) => item.tenantId === tenantId &&
          applicationIds.has(item.applicationId) && keyIds.has(item.keyBindingId))
        .map((item) => ({
          kind: 'routing', id: item.id, applicationId: item.applicationId,
          keyBindingId: item.keyBindingId,
          poolId: poolIds.has(item.poolId) ? item.poolId : null,
          providerId: item.providerId, requestedModelId: item.requestedModelId,
          status: item.status, egressPolicy: item.egressPolicy,
        }));
      break;
    default:
      // JS/HTTP callers can supply arbitrary collection strings despite types.
      return HIDDEN;
  }

  return {
    ok: true,
    status: 200,
    apiVersion: SAAS_CONTROL_API_VERSION,
    source: 'synthetic-simulation',
    tenantId,
    collection,
    data,
  };
}

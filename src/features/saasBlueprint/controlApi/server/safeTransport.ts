import type {
  ControlActor, ControlCollection, ControlReadResult, ControlResource,
  ControlSource, ResourceOwnership, TenantRole,
} from '../contracts';
import { authorizeTenantRead } from '../authorization';

/**
 * Runtime allowlist at the HTTP boundary: never JSON.stringify a Core adapter
 * object directly, even if its TypeScript declaration looks safe.
 */
const RESOURCE_KIND: Readonly<Record<ControlCollection, ControlResource['kind']>> = {
  tenant: 'tenant', projects: 'project', applications: 'application',
  'client-keys': 'client-key', accounts: 'account', pools: 'pool',
  egress: 'egress', routing: 'routing',
};

type ObjectRecord = Record<string, unknown>;

function record(value: unknown): ObjectRecord | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as ObjectRecord : null;
}

function id(value: unknown): string | null {
  return typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$/.test(value)
    ? value : null;
}

function label(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 256) return null;
  // Avoid control bytes without a no-control-regex lint exception.
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return null;
  }
  return value;
}

function variant<const T extends readonly string[]>(
  value: unknown, allowed: T
): T[number] | null {
  return typeof value === 'string' && allowed.includes(value) ? value as T[number] : null;
}

function owner(raw: unknown): ResourceOwnership | null {
  const value = record(raw);
  if (!value) return null;
  const kind = variant(value.kind, ['tenant', 'platform'] as const);
  const access = variant(value.access, ['owned', 'explicit-grant'] as const);
  const tenantName = value.tenantName === null ? null : label(value.tenantName);
  if (!kind || !access || (value.tenantName !== null && tenantName === null) ||
      (kind === 'platform' && tenantName !== null)) return null;
  return { kind, access, tenantName };
}

function idArray(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length > 200) return null;
  const result = value.map(id);
  return result.every((entry): entry is string => entry !== null) ? result : null;
}

/** Return null for invalid schema, never pass through unknown properties. */
function resource(raw: unknown, collection: ControlCollection): ControlResource | null {
  const value = record(raw);
  if (!value || value.kind !== RESOURCE_KIND[collection]) return null;
  const ref = id(value.id);
  if (!ref) return null;

  switch (collection) {
    case 'tenant': {
      const name = label(value.name);
      const role = variant(value.role,
        ['tenant-owner', 'tenant-admin', 'tenant-viewer', 'tenant-auditor'] as const);
      return name !== null && role && value.status === 'active'
        ? { kind: 'tenant', id: ref, name, status: 'active', role } : null;
    }
    case 'projects': {
      const name = label(value.name);
      const tenantId = id(value.tenantId);
      const status = variant(value.status, ['active', 'disabled'] as const);
      return name !== null && tenantId && status
        ? { kind: 'project', id: ref, name, tenantId, status } : null;
    }
    case 'applications': {
      const name = label(value.name);
      const projectId = id(value.projectId);
      const status = variant(value.status, ['active', 'disabled'] as const);
      return name !== null && projectId && status
        ? { kind: 'application', id: ref, name, projectId, status } : null;
    }
    case 'client-keys': {
      const applicationId = id(value.applicationId);
      const status = variant(value.status, ['active', 'disabled'] as const);
      return applicationId && status && value.keyType === 'cpa'
        ? { kind: 'client-key', id: ref, applicationId, status, keyType: 'cpa' } : null;
    }
    case 'accounts': {
      const accountOwner = owner(value.owner);
      const providerId = id(value.providerId);
      const authMode = variant(value.authMode,
        ['provider-api-key', 'provider-oauth', 'workload-identity'] as const);
      const authorizationStatus = variant(value.authorizationStatus,
        ['approved', 'unverified', 'blocked'] as const);
      const status = variant(value.status,
        ['active', 'disabled', 'reauth-required', 'blocked'] as const);
      const allowedModelIds = idArray(value.allowedModelIds);
      const egressProfileId = value.egressProfileId === null ? null : id(value.egressProfileId);
      if (!accountOwner || !providerId || !authMode || !authorizationStatus ||
          !status || !allowedModelIds ||
          (value.egressProfileId !== null && egressProfileId === null)) return null;
      return {
        kind: 'account', id: ref, owner: accountOwner, providerId, authMode,
        authorizationStatus, status, allowedModelIds, egressProfileId,
      };
    }
    case 'pools': {
      const poolOwner = owner(value.owner);
      const providerId = id(value.providerId);
      const status = variant(value.status, ['active', 'disabled'] as const);
      const accountIds = idArray(value.accountIds);
      return poolOwner && providerId && status && accountIds
        ? { kind: 'pool', id: ref, owner: poolOwner, providerId, status, accountIds }
        : null;
    }
    case 'egress': {
      const egressOwner = owner(value.owner);
      const name = label(value.name);
      const routeKind = variant(value.routeKind,
        ['http', 'https', 'socks5', 'socks5h', 'direct', 'vpn-connector'] as const);
      const status = variant(value.status, ['active', 'disabled'] as const);
      const health = variant(value.health,
        ['healthy', 'degraded', 'offline', 'unknown'] as const);
      const publicEndpoint = label(value.publicEndpoint);
      // Opaque labels from upstream may contain credentials; deny unsafe forms.
      if (!egressOwner || name === null || !routeKind || !status || !health ||
          publicEndpoint === null || publicEndpoint.includes('@') ||
          publicEndpoint.includes('://') || publicEndpoint.includes('\\')) return null;
      return { kind: 'egress', id: ref, owner: egressOwner, name, routeKind,
        status, health, publicEndpoint };
    }
    case 'routing': {
      const applicationId = id(value.applicationId);
      const keyBindingId = id(value.keyBindingId);
      const poolId = value.poolId === null ? null : id(value.poolId);
      const providerId = id(value.providerId);
      const requestedModelId = id(value.requestedModelId);
      const status = variant(value.status, ['active', 'disabled'] as const);
      const egressPolicy = variant(value.egressPolicy,
        ['required', 'direct-explicit'] as const);
      if (!applicationId || !keyBindingId || !providerId || !requestedModelId ||
          !status || !egressPolicy || (value.poolId !== null && !poolId)) return null;
      return { kind: 'routing', id: ref, applicationId, keyBindingId,
        poolId, providerId, requestedModelId, status, egressPolicy };
    }
  }
  return null;
}

/** All upstream errors are mapped to static codes/messages. */
export function cleanReadResult(
  raw: unknown, source: ControlSource, tenantId: string,
  collection: ControlCollection, expectedRole: TenantRole
): ControlReadResult | null {
  const value = record(raw);
  if (!value) return null;
  if (value.ok === false) {
    const failure = record(value.error);
    switch (failure?.code) {
      case 'NOT_FOUND':
        return value.status === 404 ? { ok: false, status: 404,
          error: { code: 'NOT_FOUND', message: 'Resource unavailable' } } : null;
      case 'FORBIDDEN':
        return value.status === 403 ? { ok: false, status: 403,
          error: { code: 'FORBIDDEN', message: 'Permission denied' } } : null;
      case 'TENANT_UNAVAILABLE':
        return value.status === 403 ? { ok: false, status: 403,
          error: { code: 'TENANT_UNAVAILABLE', message: 'Resource unavailable' } } : null;
      case 'SOURCE_UNAVAILABLE':
        return value.status === 503 ? { ok: false, status: 503,
          error: { code: 'SOURCE_UNAVAILABLE', message: 'Service unavailable' } } : null;
      default:
        return null;
    }
  }

  if (value.ok !== true || value.status !== 200 || value.apiVersion !== 1 ||
      value.source !== source || value.tenantId !== tenantId ||
      value.collection !== collection || !Array.isArray(value.data) ||
      value.data.length > 200) return null;

  const entries: ControlResource[] = [];
  const seen = new Set<string>();
  for (const candidate of value.data) {
    const safe = resource(candidate, collection);
    if (!safe || seen.has(safe.id)) return null;
    if (safe.kind === 'project' && safe.tenantId !== tenantId) return null;
    if (safe.kind === 'tenant' && (safe.id !== tenantId || safe.role !== expectedRole)) return null;
    seen.add(safe.id);
    entries.push(safe);
  }
  return { ok: true, status: 200, apiVersion: 1, source, tenantId, collection, data: entries };
}

/** Tenant index must be checked against server-side memberships again. */
export function cleanTenantIndex(
  raw: unknown, actor: ControlActor
): readonly Extract<ControlResource, { kind: 'tenant' }>[] | null {
  if (!Array.isArray(raw) || raw.length > 200) return null;
  const safe: Extract<ControlResource, { kind: 'tenant' }>[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    const tenant = resource(item, 'tenant');
    if (!tenant || tenant.kind !== 'tenant' || seen.has(tenant.id)) return null;
    const auth = authorizeTenantRead(actor, tenant.id, 'tenant');
    if (!auth.allowed || auth.membership.role !== tenant.role) return null;
    seen.add(tenant.id);
    safe.push(tenant);
  }
  return safe;
}

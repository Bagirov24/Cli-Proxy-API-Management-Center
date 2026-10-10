import type { AccessGrant, BlueprintSnapshot, Owner } from '../domain';
import type { ControlActor, ControlCollection, TenantMembership, TenantRole } from './contracts';

/**
 * RBAC evaluation prototype. There is NO session verification here.
 * A future server MUST construct ControlActor from verified credentials.
 * Unknown roles and duplicate/disabled memberships deny by default.
 */
const READ_CAPABILITIES: Readonly<Record<TenantRole, readonly ControlCollection[]>> = {
  'tenant-owner': ['tenant', 'projects', 'applications', 'client-keys', 'accounts', 'pools', 'egress', 'routing'],
  'tenant-admin': ['tenant', 'projects', 'applications', 'client-keys', 'accounts', 'pools', 'egress', 'routing'],
  'tenant-viewer': ['tenant', 'projects', 'applications', 'client-keys', 'accounts', 'pools', 'egress', 'routing'],
  'tenant-auditor': ['tenant', 'projects', 'applications'],
};

export type ReadAuthorization =
  | { readonly allowed: true; readonly membership: TenantMembership }
  | { readonly allowed: false; readonly reason: 'not-found' | 'forbidden' };

export function authorizeTenantRead(
  actor: ControlActor,
  tenantId: string,
  collection: ControlCollection
): ReadAuthorization {
  if (!actor?.id?.trim() || !tenantId?.trim() || !Array.isArray(actor.memberships)) {
    return { allowed: false, reason: 'not-found' };
  }
  const matching = actor.memberships.filter((entry) => entry.tenantId === tenantId);
  // Ambiguous memberships must never elevate rights by choosing the first match.
  if (matching.length !== 1 || matching[0].status !== 'active') {
    return { allowed: false, reason: 'not-found' };
  }
  const capabilities = READ_CAPABILITIES[matching[0].role];
  if (!capabilities || !capabilities.includes(collection)) {
    return { allowed: false, reason: 'forbidden' };
  }
  return { allowed: true, membership: matching[0] };
}

/** The tenant owning a resource needs no grant; every other tenant needs one. */
function sameOwner(expected: Owner, grant: AccessGrant): boolean {
  return expected.kind === grant.owner.kind &&
    (expected.kind === 'platform' ||
      (grant.owner.kind === 'tenant' && grant.owner.tenantId === expected.tenantId));
}

/**
 * Do not reuse RBAC permissions as sharing grants. Each pool, account and
 * egress profile is independently granted, with a matching owner + expiry.
 * Passing an invalid clock must not extend cross-tenant access.
 */
export function mayViewTenantResource(
  snapshot: BlueprintSnapshot,
  tenantId: string,
  resourceKind: AccessGrant['resourceKind'],
  resourceId: string,
  owner: Owner,
  nowMs: number
): boolean {
  if (owner.kind === 'tenant' && owner.tenantId === tenantId) return true;
  if (!Number.isFinite(nowMs)) return false;
  return snapshot.accessGrants.some((grant) =>
    grant.resourceKind === resourceKind &&
    grant.resourceId === resourceId &&
    grant.granteeTenantId === tenantId &&
    grant.status === 'active' &&
    sameOwner(owner, grant) &&
    (grant.expiresAt === undefined || (
      Number.isFinite(Date.parse(grant.expiresAt)) &&
      Date.parse(grant.expiresAt) > nowMs
    )));
}

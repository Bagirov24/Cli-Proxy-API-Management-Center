/**
 * SaaS Control API v1 — SPEC / SYNTHETIC CONTRACT ONLY.
 *
 * No HTTP listener, sessions, databases, credential handling or Core adapter
 * are implemented. Real actors MUST be derived from a server-verified session.
 */
export const SAAS_CONTROL_API_VERSION = 1 as const;

export type TenantRole =
  | 'tenant-owner'
  | 'tenant-admin'
  | 'tenant-viewer'
  | 'tenant-auditor';

export type ControlCollection =
  | 'tenant'
  | 'projects'
  | 'applications'
  | 'client-keys'
  | 'accounts'
  | 'pools'
  | 'egress'
  | 'routing';

export interface TenantMembership {
  readonly tenantId: string;
  readonly role: TenantRole;
  readonly status: 'active' | 'revoked';
}

/** This identity must be issued by a trusted SaaS authentication boundary. */
export interface ControlActor {
  readonly id: string;
  readonly memberships: readonly TenantMembership[];
}

export interface ResourceOwnership {
  readonly kind: 'tenant' | 'platform';
  /** Human-readable owner; may be a different tenant only with a specific grant. */
  readonly tenantName: string | null;
  readonly access: 'owned' | 'explicit-grant';
}

export type ControlResource =
  | {
    readonly kind: 'tenant';
    readonly id: string;
    readonly name: string;
    readonly status: 'active';
    readonly role: TenantRole;
  }
  | {
    readonly kind: 'project';
    readonly id: string;
    readonly name: string;
    readonly status: 'active' | 'disabled';
    readonly tenantId: string;
  }
  | {
    readonly kind: 'application';
    readonly id: string;
    readonly name: string;
    readonly status: 'active' | 'disabled';
    readonly projectId: string;
  }
  | {
    readonly kind: 'client-key';
    /** Binding reference ONLY, never the CPA secret or native Core key. */
    readonly id: string;
    readonly applicationId: string;
    readonly status: 'active' | 'disabled';
    readonly keyType: 'cpa';
  }
  | {
    readonly kind: 'account';
    readonly id: string;
    readonly owner: ResourceOwnership;
    readonly providerId: string;
    readonly authMode: 'provider-api-key' | 'provider-oauth' | 'workload-identity';
    readonly authorizationStatus: 'approved' | 'unverified' | 'blocked';
    readonly status: 'active' | 'disabled' | 'reauth-required' | 'blocked';
    readonly allowedModelIds: readonly string[];
    /** Null means absent or inaccessible; do not reveal forbidden references. */
    readonly egressProfileId: string | null;
  }
  | {
    readonly kind: 'pool';
    readonly id: string;
    readonly owner: ResourceOwnership;
    readonly providerId: string;
    readonly status: 'active' | 'disabled';
    /** Individually visible accounts only; pool grant is not account grant. */
    readonly accountIds: readonly string[];
  }
  | {
    readonly kind: 'egress';
    readonly id: string;
    readonly owner: ResourceOwnership;
    readonly name: string;
    readonly routeKind: 'http' | 'https' | 'socks5' | 'socks5h' | 'direct' | 'vpn-connector';
    readonly status: 'active' | 'disabled';
    readonly health: 'healthy' | 'degraded' | 'offline' | 'unknown';
    /** Sanitized host/port label; never VPN configs, userinfo, credentials or IP attestations. */
    readonly publicEndpoint: string;
  }
  | {
    readonly kind: 'routing';
    readonly id: string;
    readonly applicationId: string;
    readonly keyBindingId: string;
    /** Null if the tenant lacks a separate grant on this pool. */
    readonly poolId: string | null;
    readonly providerId: string;
    readonly requestedModelId: string;
    readonly status: 'active' | 'disabled';
    readonly egressPolicy: 'required' | 'direct-explicit';
  };

export type ControlSource = 'synthetic-simulation' | 'core-metadata-readonly';

export interface ControlReadSuccess {
  readonly ok: true;
  readonly status: 200;
  readonly apiVersion: typeof SAAS_CONTROL_API_VERSION;
  readonly source: ControlSource;
  readonly tenantId: string;
  readonly collection: ControlCollection;
  readonly data: readonly ControlResource[];
}

export interface ControlReadError {
  readonly ok: false;
  readonly status: 403 | 404 | 503;
  readonly error: {
    readonly code: 'NOT_FOUND' | 'FORBIDDEN' | 'TENANT_UNAVAILABLE' | 'SOURCE_UNAVAILABLE';
    /** Must not include actor, tenant or foreign resource identifiers. */
    readonly message: 'Resource unavailable' | 'Permission denied' | 'Service unavailable';
  };
}
export type ControlReadResult = ControlReadSuccess | ControlReadError;

/** Future server integration boundary: deliberately without an implementation. */
export interface AuthorizedReadScope {
  readonly actorId: string;
  readonly tenantId: string;
  readonly role: TenantRole;
  /** Server-generated correlation ID; never raw request text. */
  readonly correlationId: string;
}

export interface ReadOnlyTenantMetadataAdapter {
  readonly source: 'core-metadata-readonly';
  /**
   * Server creates an authorized scope AFTER verifying identity and tenant
   * membership. Implementation must scope its DB query BEFORE fetching data.
   * Fail closed on unsupported Core metadata; do not return a full Core config.
   */
  readCollection(
    scope: AuthorizedReadScope,
    collection: ControlCollection,
    options: { readonly signal?: AbortSignal }
  ): Promise<ControlReadResult>;
}

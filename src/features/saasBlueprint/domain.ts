/**
 * SaaS Blueprint v1 — design-time contracts, NOT connected to CLIProxyAPI Core.
 * No secrets, tokens, raw credential files, proxy passwords or network I/O live here.
 * Interfaces are intentionally transport- and UI-independent.
 */
export const SAAS_BLUEPRINT_SCHEMA_VERSION = 1 as const;

export type Identifier = string;
export type Owner = { readonly kind: 'tenant'; readonly tenantId: Identifier } | { readonly kind: 'platform' };
export type RecordStatus = 'active' | 'disabled';
export type Health = 'healthy' | 'degraded' | 'offline' | 'unknown';

export interface Tenant {
  readonly id: Identifier;
  readonly name: string;
  readonly status: RecordStatus | 'suspended';
  /** Direct internet access is denied by default; also requires explicit binding consent. */
  readonly allowDirectEgress: boolean;
}

export interface Project {
  readonly id: Identifier;
  readonly tenantId: Identifier;
  readonly name: string;
  readonly status: RecordStatus;
}

export interface Application {
  readonly id: Identifier;
  readonly tenantId: Identifier;
  readonly projectId: Identifier;
  readonly name: string;
  readonly status: RecordStatus;
}

/** Only a reference; the CPA plaintext key is returned once by CPA and is never stored here. */
export interface ClientKeyBinding {
  readonly id: Identifier;
  readonly tenantId: Identifier;
  readonly applicationId: Identifier;
  readonly kind: 'cpa' | 'core-native';
  readonly status: RecordStatus;
}

export type AccountAuthMode = 'provider-api-key' | 'provider-oauth' | 'workload-identity';

/** The real credential and its vault handle remain backend-only. */
export interface ProviderAccount {
  readonly id: Identifier;
  readonly owner: Owner;
  readonly providerId: Identifier;
  readonly authMode: AccountAuthMode;
  readonly status: 'active' | 'disabled' | 'reauth-required' | 'blocked';
  readonly allowedModelIds: readonly Identifier[];
  /** Required: each selected account has an explicit outbound route. */
  readonly egressProfileId: Identifier;
}

export interface AccountPool {
  readonly id: Identifier;
  readonly owner: Owner;
  readonly providerId: Identifier;
  readonly status: RecordStatus;
  readonly accountIds: readonly Identifier[];
}

export type EgressKind = 'http' | 'https' | 'socks5' | 'socks5h' | 'direct' | 'vpn-connector';
export interface ProxyEndpoint {
  /** Host and port only: never put proxy credentials into the URL. */
  readonly hostname: string;
  readonly port: number;
}

export interface EgressProfile {
  readonly id: Identifier;
  readonly owner: Owner;
  readonly name: string;
  readonly kind: EgressKind;
  readonly status: RecordStatus;
  readonly health: Health;
  readonly endpoint?: ProxyEndpoint;
  /** Identifier of an independently provisioned, verified VPN connector. */
  readonly connectorId?: Identifier;
}

export interface AccessGrant {
  readonly id: Identifier;
  readonly resourceKind: 'pool' | 'account' | 'egress';
  readonly resourceId: Identifier;
  readonly owner: Owner;
  readonly granteeTenantId: Identifier;
  readonly status: RecordStatus;
  /** Optional ISO timestamp. Invalid timestamps are NOT treated as valid grants. */
  readonly expiresAt?: string;
}

export interface RoutingBinding {
  readonly id: Identifier;
  readonly tenantId: Identifier;
  readonly applicationId: Identifier;
  readonly keyBindingId: Identifier;
  readonly poolId: Identifier;
  readonly providerId: Identifier;
  readonly requestedModelId: Identifier;
  readonly status: RecordStatus;
  /** "required" never falls back to direct; "direct-explicit" needs tenant opt-in too. */
  readonly egressPolicy: 'required' | 'direct-explicit';
}

export interface BlueprintSnapshot {
  readonly schemaVersion: typeof SAAS_BLUEPRINT_SCHEMA_VERSION;
  readonly tenants: readonly Tenant[];
  readonly projects: readonly Project[];
  readonly applications: readonly Application[];
  readonly keyBindings: readonly ClientKeyBinding[];
  readonly providerAccounts: readonly ProviderAccount[];
  readonly accountPools: readonly AccountPool[];
  readonly egressProfiles: readonly EgressProfile[];
  readonly accessGrants: readonly AccessGrant[];
  readonly routingBindings: readonly RoutingBinding[];
}

/**
 * Internal-only selection result from a trustworthy scheduler. The external caller
 * must never be allowed to choose tenant/account/egress via untrusted headers.
 */
export interface RouteRequest {
  readonly tenantId: Identifier;
  readonly applicationId: Identifier;
  readonly keyBindingId: Identifier;
  readonly requestedModelId: Identifier;
  readonly selectedAccountId: Identifier;
}

export interface RuntimeCapabilities {
  /** Allow-listed, health-checked connectors deployed OUTSIDE of Core. Empty by default. */
  readonly verifiedVpnConnectorIds: readonly Identifier[];
}

import type { PolicyStage, RouteDecision } from './resolveRoute';

/** Explains a SIMULATED policy decision, never claims to describe live Core traffic. */
export interface SafeDecisionPreview {
  readonly mode: 'synthetic-simulation';
  readonly allowed: boolean;
  readonly reasonCode: string | null;
  readonly steps: readonly {
    readonly stage: PolicyStage;
    readonly state: 'passed' | 'blocked' | 'not-reached';
  }[];
  readonly selectedRoute: {
    readonly providerId: string;
    readonly modelId: string;
    readonly accountReference: string;
    readonly egressReference: string;
  } | null;
}

const stages: readonly PolicyStage[] = [
  'configuration',
  'tenant',
  'application',
  'client-key',
  'routing',
  'account-pool',
  'provider-account',
  'egress',
];

/**
 * Deliberate allow-list of fields. Source records, key material, OAuth tokens,
 * proxy URLs, VPN config and request/response payloads must NEVER be included.
 */
export function safeDecisionPreview(decision: RouteDecision): SafeDecisionPreview {
  const stopAt = stages.indexOf(decision.stage);
  return {
    mode: 'synthetic-simulation',
    allowed: decision.allowed,
    reasonCode: decision.allowed ? null : decision.reason,
    steps: stages.map((stage, index) => ({
      stage,
      state: decision.allowed || index < stopAt
        ? 'passed'
        : index === stopAt
          ? 'blocked'
          : 'not-reached',
    })),
    selectedRoute: decision.allowed
      ? {
          providerId: decision.providerId,
          modelId: decision.modelId,
          accountReference: decision.providerAccountId,
          egressReference: decision.egressProfileId,
        }
      : null,
  };
}

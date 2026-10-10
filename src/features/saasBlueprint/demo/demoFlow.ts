import type { PolicyStage } from '../resolveRoute';
import type { SafeDecisionPreview } from '../safeDecisionPreview';

/** A visual explanation of SYNTHETIC decisions, never observed request traffic. */
export type DemoFlowNode = 'client' | 'gateway' | 'policy' | 'pool' | 'account' | 'egress' | 'provider';
export type DemoFlowState = 'passed' | 'blocked' | 'not-reached' | 'illustrative';

export interface DemoFlowStep {
  readonly id: DemoFlowNode;
  readonly state: DemoFlowState;
}

function groupState(preview: SafeDecisionPreview, stages: readonly PolicyStage[]): DemoFlowState {
  const states = stages.map((stage) => preview.steps.find((step) => step.stage === stage)?.state);
  if (states.includes('blocked')) return 'blocked';
  if (states.every((state) => state === 'passed')) return 'passed';
  return 'not-reached';
}

/**
 * Gateway and provider never become "passed": the resolver cannot prove a
 * network connection. A denied request cannot even reach the provider node.
 */
export function buildDemoFlow(preview: SafeDecisionPreview): readonly DemoFlowStep[] {
  return [
    { id: 'client', state: groupState(preview, ['tenant', 'application']) },
    { id: 'gateway', state: 'illustrative' },
    { id: 'policy', state: groupState(preview, ['configuration', 'client-key', 'routing']) },
    { id: 'pool', state: groupState(preview, ['account-pool']) },
    { id: 'account', state: groupState(preview, ['provider-account']) },
    { id: 'egress', state: groupState(preview, ['egress']) },
    { id: 'provider', state: preview.allowed ? 'illustrative' : 'not-reached' },
  ];
}

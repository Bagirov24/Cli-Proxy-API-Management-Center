import type { ControlCollection } from '../contracts';

/**
 * Stage 2G.3 — isolated synchronous audit contract, never production logging.
 *
 * No tokens, request headers, SQL strings, credentials, provider account IDs,
 * resource IDs, prompts, responses or arbitrary metadata are accepted.
 * An async/durable sink is intentionally NOT supported yet: audit writes must
 * not introduce another await after the final authorization check.
 */
export type SecurityAuditResult = 'allow' | 'deny' | 'error';
export type SecurityAuditReason =
  | 'read-allowed'
  | 'invalid-request'
  | 'unauthenticated'
  | 'tenant-hidden'
  | 'role-forbidden'
  | 'authorization-changed'
  | 'request-cancelled'
  | 'source-unavailable';

export interface SecurityAuditDecision {
  readonly correlationId: string;
  /** Set only after trusted issuer+subject mapping, NEVER from JWT claims. */
  readonly actorId: string | null;
  /** A tenant proven accessible server-side; never raw requested tenant. */
  readonly tenantId: string | null;
  readonly collection: ControlCollection | null;
  readonly result: SecurityAuditResult;
  readonly reason: SecurityAuditReason;
}

export interface SecurityAuditEvent {
  readonly version: 1;
  readonly occurredAt: string;
  readonly source: 'trusted-sql-read-boundary';
  readonly classification: 'synthetic' | 'staging';
  readonly operation: 'saas.metadata.read';
  readonly correlationId: string;
  readonly actorId: string | null;
  readonly tenantId: string | null;
  readonly collection: ControlCollection | null;
  readonly result: SecurityAuditResult;
  readonly reason: SecurityAuditReason;
}

/** Sink must finish synchronously; no console or network default. */
export interface SecurityAuditSink {
  write(event: Readonly<SecurityAuditEvent>): void;
}
export interface SecurityAuditRecorder {
  record(decision: SecurityAuditDecision): void;
}

const COLLECTIONS: readonly ControlCollection[] = [
  'tenant', 'projects', 'applications', 'client-keys',
  'accounts', 'pools', 'egress', 'routing',
];
const ALLOWED_REASONS: Readonly<Record<SecurityAuditResult, readonly SecurityAuditReason[]>> = {
  allow: ['read-allowed'],
  deny: ['invalid-request', 'unauthenticated', 'tenant-hidden',
    'role-forbidden', 'authorization-changed'],
  error: ['request-cancelled', 'source-unavailable'],
};
const CORRELATION = /^[A-Za-z0-9_-]{1,128}$/;
const ACTOR = /^[A-Za-z0-9_-]{1,128}$/;
const TENANT = /^[A-Za-z0-9_-]{1,64}$/;

export function createSecurityAuditRecorder(
  sink: SecurityAuditSink,
  options: {
    readonly classification: 'synthetic' | 'staging';
    readonly nowMs?: () => number;
  }
): SecurityAuditRecorder {
  if (!sink || typeof sink.write !== 'function' ||
      !['synthetic', 'staging'].includes(options?.classification)) {
    throw new Error('Invalid security audit configuration');
  }
  const nowMs = options.nowMs ?? (() => Date.now());
  return {
    record(decision) {
      if (!decision || typeof decision !== 'object' ||
          !CORRELATION.test(decision.correlationId) ||
          (decision.actorId !== null && !ACTOR.test(decision.actorId)) ||
          (decision.tenantId !== null && !TENANT.test(decision.tenantId)) ||
          (decision.collection !== null && !COLLECTIONS.includes(decision.collection)) ||
          !Object.prototype.hasOwnProperty.call(ALLOWED_REASONS, decision.result) ||
          !ALLOWED_REASONS[decision.result].includes(decision.reason) ||
          (decision.result === 'allow' && (!decision.actorId ||
            !decision.tenantId || !decision.collection))) {
        throw new Error('Invalid security audit decision');
      }
      const time = nowMs();
      if (!Number.isSafeInteger(time) || time < 1_577_836_800_000 ||
          time > 4_102_444_800_000) {
        throw new Error('Invalid security audit clock');
      }
      // Build every property by name: runtime callers may smuggle extra
      // fields through TypeScript casts, but they can never reach the sink.
      // Denied/failed operations carry no tenant ID, so foreign tenant IDs
      // cannot be leaked by an unsafe caller or malicious request.
      const event: SecurityAuditEvent = Object.freeze({
        version: 1,
        occurredAt: new Date(time).toISOString(),
        source: 'trusted-sql-read-boundary',
        classification: options.classification,
        operation: 'saas.metadata.read',
        correlationId: decision.correlationId,
        actorId: decision.actorId,
        tenantId: decision.result === 'allow' ? decision.tenantId : null,
        collection: decision.collection,
        result: decision.result,
        reason: decision.reason,
      });
      const written: unknown = sink.write(event);
      // A promise returned by a misconfigured sink breaks the synchronous
      // post-AuthZ contract. Reject; do not claim that an async write worked.
      if (written !== undefined) {
        throw new Error('Asynchronous security audit sink is unsupported');
      }
    },
  };
}

/** Bounded and isolated; test fixture ONLY, never persistent audit storage. */
export function createSyntheticAuditBuffer(capacity = 64): SecurityAuditSink & {
  readonly snapshot: () => readonly Readonly<SecurityAuditEvent>[];
} {
  if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 1000) {
    throw new Error('Invalid synthetic audit buffer size');
  }
  const events: SecurityAuditEvent[] = [];
  return {
    write(event) {
      // Even a direct call to this buffer must not serialize unknown keys.
      events.push(Object.freeze({
        version: event.version, occurredAt: event.occurredAt,
        source: event.source, classification: event.classification,
        operation: event.operation, correlationId: event.correlationId,
        actorId: event.actorId, tenantId: event.tenantId,
        collection: event.collection, result: event.result, reason: event.reason,
      }));
      if (events.length > capacity) events.shift();
    },
    snapshot() {
      return Object.freeze(events.map(event => Object.freeze({ ...event })));
    },
  };
}

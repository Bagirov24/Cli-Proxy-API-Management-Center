import { describe, expect, test } from 'bun:test';
import {
  createSecurityAuditRecorder, createSyntheticAuditBuffer,
  type SecurityAuditDecision, type SecurityAuditSink,
} from '../src/features/saasBlueprint/controlApi/server/securityAudit';

const clock = () => 1_800_000_000_000;
const allowed: SecurityAuditDecision = {
  correlationId: 'server-event-2g3',
  actorId: 'actor-north',
  tenantId: 'demo-north',
  collection: 'projects',
  result: 'allow',
  reason: 'read-allowed',
};

function fixture(capacity = 64) {
  const sink = createSyntheticAuditBuffer(capacity);
  const recorder = createSecurityAuditRecorder(sink, {
    classification: 'synthetic', nowMs: clock,
  });
  return { sink, recorder };
}

describe('Stage 2G.3 — server-owned redacted decision audit (synthetic only)', () => {
  test('emits only fixed, versioned, UTC metadata with server provenance', () => {
    const h = fixture();
    h.recorder.record(allowed);
    expect(h.sink.snapshot()).toEqual([{
      version: 1,
      occurredAt: '2027-01-15T08:00:00.000Z',
      source: 'trusted-sql-read-boundary',
      classification: 'synthetic',
      operation: 'saas.metadata.read',
      correlationId: 'server-event-2g3',
      actorId: 'actor-north',
      tenantId: 'demo-north',
      collection: 'projects',
      result: 'allow',
      reason: 'read-allowed',
    }]);
    expect(Object.keys(h.sink.snapshot()[0]).sort()).toEqual([
      'actorId', 'classification', 'collection', 'correlationId',
      'occurredAt', 'operation', 'reason', 'result',
      'source', 'tenantId', 'version',
    ]);
  });

  test('unrecognized fields, credentials and prompts cannot enter audit records', () => {
    const h = fixture();
    const raw = {
      ...allowed, authorization: 'Bearer SYNTHETIC_BEARER_SECRET',
      apiKey: 'sk-SYNTHETIC_KEY', oauthRefreshToken: 'refresh-secret',
      proxyCredentials: 'socks5://user:pass@secret.example:1080',
      prompt: 'PRIVATE_AI_PROMPT', response: 'PRIVATE_AI_RESPONSE',
      foreignResourceId: 'orbit-secret-account',
      metadata: { password: 'SYNTHETIC_PASSWORD' },
    };
    h.recorder.record(raw);
    const output = JSON.stringify(h.sink.snapshot());
    for (const value of [
      'SYNTHETIC_BEARER_SECRET', 'SYNTHETIC_KEY', 'refresh-secret',
      'socks5://', 'PRIVATE_AI_PROMPT', 'PRIVATE_AI_RESPONSE',
      'orbit-secret-account', 'SYNTHETIC_PASSWORD',
    ]) expect(output).not.toContain(value);
    expect(Object.keys(h.sink.snapshot()[0]).length).toBe(11);
  });

  test('foreign requested tenant is always absent from deny and error events', () => {
    const h = fixture();
    h.recorder.record({
      ...allowed, tenantId: 'demo-orbit',
      result: 'deny', reason: 'tenant-hidden',
    });
    h.recorder.record({
      ...allowed, tenantId: 'demo-orbit',
      result: 'error', reason: 'source-unavailable',
    });
    expect(h.sink.snapshot().map(item => item.tenantId)).toEqual([null, null]);
    expect(JSON.stringify(h.sink.snapshot())).not.toContain('demo-orbit');
  });

  test('invalid enums, identifiers, timestamps, and inconsistent reasons fail closed', () => {
    const h = fixture();
    const invalid: readonly SecurityAuditDecision[] = [
      { ...allowed, correlationId: 'Bearer leaked-secret' },
      { ...allowed, actorId: 'actor\nnot-safe' },
      { ...allowed, tenantId: 'tenant@example.test' },
      { ...allowed, collection: '__proto__' as SecurityAuditDecision['collection'] },
      { ...allowed, result: 'allow', reason: 'tenant-hidden' },
      { ...allowed, result: 'deny', reason: 'read-allowed' },
      { ...allowed, result: 'error', reason: 'unauthenticated' },
      { ...allowed, result: 'allow', tenantId: null },
      { ...allowed, result: 'allow', actorId: null },
      { ...allowed, result: 'allow', collection: null },
    ];
    for (const item of invalid) expect(() => h.recorder.record(item)).toThrow();
    expect(h.sink.snapshot()).toEqual([]);

    const invalidClock = createSecurityAuditRecorder(h.sink, {
      classification: 'synthetic', nowMs: () => Number.NaN,
    });
    expect(() => invalidClock.record(allowed)).toThrow('Invalid security audit clock');
    expect(h.sink.snapshot()).toEqual([]);
  });

  test('fixed-capacity synthetic sink drops oldest events and clones snapshots', () => {
    const h = fixture(2);
    h.recorder.record({ ...allowed, correlationId: 'a' });
    const early = h.sink.snapshot();
    h.recorder.record({ ...allowed, correlationId: 'b' });
    h.recorder.record({ ...allowed, correlationId: 'c' });
    expect(h.sink.snapshot().map(event => event.correlationId)).toEqual(['b', 'c']);
    expect(early.map(event => event.correlationId)).toEqual(['a']);
    expect(Object.isFrozen(h.sink.snapshot())).toBe(true);
    expect(Object.isFrozen(h.sink.snapshot()[0])).toBe(true);
    expect(() => createSyntheticAuditBuffer(0)).toThrow();
    expect(() => createSyntheticAuditBuffer(1001)).toThrow();
  });

  test('even direct sink writes drop unknown fields', () => {
    const sink = createSyntheticAuditBuffer();
    const unsafe = {
      version: 1 as const, occurredAt: '2027-01-15T08:00:00.000Z',
      source: 'trusted-sql-read-boundary' as const,
      classification: 'synthetic' as const,
      operation: 'saas.metadata.read' as const,
      correlationId: 'server-event-2g3',
      actorId: 'actor-north', tenantId: 'demo-north',
      collection: 'projects' as const,
      result: 'allow' as const, reason: 'read-allowed' as const,
      authorization: 'Bearer SHOULD_NOT_APPEAR',
    };
    sink.write(unsafe);
    expect(JSON.stringify(sink.snapshot())).not.toContain('SHOULD_NOT_APPEAR');
    expect(Object.keys(sink.snapshot()[0]).length).toBe(11);
  });

  test('rejects async sinks rather than pretending an audit write succeeded', () => {
    const asyncSink = {
      write: (() => Promise.resolve()) as SecurityAuditSink['write'],
    };
    const audit = createSecurityAuditRecorder(asyncSink, {
      classification: 'synthetic', nowMs: clock,
    });
    expect(() => audit.record(allowed)).toThrow('Asynchronous security audit sink');
  });

  test('a sink exception is visible only as a failure to its trusted caller', () => {
    const sink: SecurityAuditSink = {
      write() { throw new Error('SYNTHETIC_SECRET_WILL_NOT_BE_LOGGED'); },
    };
    const audit = createSecurityAuditRecorder(sink, {
      classification: 'synthetic', nowMs: clock,
    });
    expect(() => audit.record(allowed)).toThrow();
    // The boundary catches this and returns generic 503. This module
    // deliberately never writes to console, disk, stdout or HTTP.
  });
});

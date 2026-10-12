import { beforeAll, describe, expect, test } from 'bun:test';
import { createPinnedAccessTokenVerifier } from
  '../src/features/saasBlueprint/controlApi/server/trustedAccessToken';
import {
  createTrustedIssuerSessionProvisioner,
  type VerifiedIssuerTokenBinding,
} from '../src/features/saasBlueprint/controlApi/server/issuerSessionProvisioning';

const issuer = 'https://ci-issuer.example.test/oauth';
const audience = 'saas-control-api';
const now = 1_800_000_000;
let rsa: CryptoKeyPair;

function b64(raw: Uint8Array): string {
  return btoa(String.fromCharCode(...raw)).replace(/\+/g, '-')
    .replace(/\//g, '_').replace(/=+$/g, '');
}
async function jwt(
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {}
): Promise<string> {
  const encode = (input: unknown) =>
    b64(new TextEncoder().encode(JSON.stringify(input)));
  const first = encode({ typ: 'at+jwt', alg: 'RS256', kid: 'ci-issuer', ...header });
  const second = encode({
    iss: issuer, sub: 'sub-ci', aud: audience,
    iat: now - 15, exp: now + 120, ...claims,
  });
  const signature = new Uint8Array(await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', rsa.privateKey,
    new TextEncoder().encode(first + '.' + second)
  ));
  return first + '.' + second + '.' + b64(signature);
}
function tokens() {
  return createPinnedAccessTokenVerifier({
    issuer, audience, publicKeys: new Map([['ci-issuer', rsa.publicKey]]),
    nowSeconds: () => now,
  });
}
function harness(options: {
  readonly onLookup?: (index: number) => string | null;
  readonly rejectWriter?: boolean;
} = {}) {
  const enrolled: VerifiedIssuerTokenBinding[] = [];
  const revoked: VerifiedIssuerTokenBinding[] = [];
  let checks = 0;
  const instance = createTrustedIssuerSessionProvisioner({
    tokens: tokens(),
    actorDirectory: {
      async resolveActorId(identity) {
        expect(identity.issuer).toBe(issuer);
        expect(identity.subject).toBe('sub-ci');
        checks += 1;
        return options.onLookup?.(checks) ?? 'actor-bound-ci';
      },
    },
    writer: {
      async enrollVerifiedToken(input) {
        if (options.rejectWriter) throw new Error('FAKE_DB_SECRET_MUST_NOT_LEAK');
        enrolled.push(input);
        return true;
      },
      async revokeVerifiedToken(input) {
        if (options.rejectWriter) throw new Error('FAKE_DB_SECRET_MUST_NOT_LEAK');
        revoked.push(input);
        return true;
      },
    },
    nowSeconds: () => now,
  });
  return { instance, enrolled, revoked, get checks() { return checks; } };
}

beforeAll(async () => {
  rsa = await crypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  }, true, ['sign', 'verify']) as CryptoKeyPair;
});

describe('2G.4d.7b — issuer-controlled session provisioning (synthetic)', () => {
  test('records only verified issuer/subject actor and exact JWT fingerprint', async () => {
    const h = harness();
    const bearer = await jwt({
      jti: 'MALICIOUS_CLIENT_JTI', actorId: 'forged-owner',
      tenantId: 'demo-orbit', role: 'tenant-owner',
    });
    expect(await h.instance.enrollBearer(bearer)).toBe(true);
    const sha = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', new TextEncoder().encode(bearer)
    ));
    const expected = Array.from(sha, b => b.toString(16).padStart(2, '0')).join('');
    expect(h.enrolled).toHaveLength(1);
    expect(h.enrolled[0]).toEqual({
      issuer, subject: 'sub-ci', actorId: 'actor-bound-ci',
      fingerprint: expected, expiresAtSeconds: now + 120,
    });
    expect(Object.isFrozen(h.enrolled[0])).toBe(true);
    expect(h.checks).toBe(2);
    const serialized = JSON.stringify(h.enrolled);
    expect(serialized).not.toContain(bearer);
    expect(serialized).not.toContain('MALICIOUS_CLIENT_JTI');
    expect(serialized).not.toContain('tenant-owner');
    expect(serialized).not.toContain('forged-owner');
  });

  test('two verified tokens for one actor have independent fingerprints', async () => {
    const h = harness();
    expect(await h.instance.enrollBearer(await jwt({ jti: 'A' }))).toBe(true);
    expect(await h.instance.enrollBearer(await jwt({ jti: 'B' }))).toBe(true);
    expect(h.enrolled[0].actorId).toBe(h.enrolled[1].actorId);
    expect(h.enrolled[0].fingerprint).not.toBe(h.enrolled[1].fingerprint);
    expect(h.enrolled.every(x => /^[0-9a-f]{64}$/.test(x.fingerprint))).toBe(true);
  });

  test('revoke sends the same trusted issuer, subject and fingerprint', async () => {
    const h = harness();
    const bearer = await jwt();
    expect(await h.instance.revokeBearer(bearer)).toBe(true);
    expect(h.revoked).toHaveLength(1);
    expect(h.enrolled).toHaveLength(0);
    expect(h.revoked[0]).toEqual({
      issuer, subject: 'sub-ci', actorId: 'actor-bound-ci',
      fingerprint: expect.stringMatching(/^[0-9a-f]{64}$/),
      expiresAtSeconds: now + 120,
    });
  });

  test('unsigned, expired, wrong audience and ID tokens never contact writer', async () => {
    const h = harness();
    const signed = await jwt();
    const parts = signed.split('.');
    parts[2] = (parts[2].startsWith('A') ? 'B' : 'A') + parts[2].slice(1);
    const bad = [
      'not-jwt', parts.join('.'),
      await jwt({ iss: 'https://evil.example.test' }),
      await jwt({ aud: 'wrong-audience' }),
      await jwt({ exp: now - 1 }),
      await jwt({ sub: 'different-subject' }),
      await jwt({}, { typ: 'JWT' }),
    ];
    for (const item of bad) {
      expect(await h.instance.enrollBearer(item)).toBe(false);
      expect(await h.instance.revokeBearer(item)).toBe(false);
    }
    expect(h.enrolled).toHaveLength(0);
    expect(h.revoked).toHaveLength(0);
  });

  test('directory drift across awaits fails closed before writer', async () => {
    const h = harness({
      onLookup: count => count === 1 ? 'actor-bound-ci' : 'other-actor',
    });
    expect(await h.instance.enrollBearer(await jwt())).toBe(false);
    expect(h.enrolled).toHaveLength(0);
    expect(h.checks).toBe(2);
  });

  test('invalid or missing trusted expiry and writer failure deny generically', async () => {
    const calls: unknown[] = [];
    const withoutVerifiedExpiry = createTrustedIssuerSessionProvisioner({
      tokens: { async verifyAccessToken() {
        return { issuer, subject: 'sub-ci' };
      } },
      actorDirectory: { async resolveActorId() { return 'actor-bound-ci'; } },
      writer: {
        async enrollVerifiedToken(input) { calls.push(input); return true; },
        async revokeVerifiedToken(input) { calls.push(input); return true; },
      },
      nowSeconds: () => now,
    });
    expect(await withoutVerifiedExpiry.enrollBearer('any')).toBe(false);
    expect(await withoutVerifiedExpiry.revokeBearer('any')).toBe(false);
    expect(calls).toHaveLength(0);
    const h = harness({ rejectWriter: true });
    expect(await h.instance.enrollBearer(await jwt())).toBe(false);
    expect(await h.instance.revokeBearer(await jwt())).toBe(false);
    expect(h.enrolled).toHaveLength(0);
    expect(h.revoked).toHaveLength(0);
  });

  test('rejects mutable untrusted issuer and missing provisioning capabilities', () => {
    expect(() => createTrustedIssuerSessionProvisioner({
      tokens: tokens(),
      actorDirectory: { async resolveActorId() { return 'actor-bound-ci'; } },
      writer: {} as never,
    })).toThrow();
  });
});

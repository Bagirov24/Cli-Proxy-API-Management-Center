import { beforeAll, describe, expect, test } from 'bun:test';
import {
  createPinnedAccessTokenVerifier, createVerifiedSubjectSessionBridge,
} from '../src/features/saasBlueprint/controlApi/server/trustedAccessToken';

const issuer = 'https://issuer.example.test/oauth';
const audience = 'saas-control-api';
const now = 1_800_000_000;
let keys: CryptoKeyPair;

function base64url(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function jwt(
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {}
): Promise<string> {
  const h = base64url(new TextEncoder().encode(JSON.stringify({
    typ: 'at+jwt', alg: 'RS256', kid: 'ci-key', ...header,
  })));
  const p = base64url(new TextEncoder().encode(JSON.stringify({
    iss: issuer, aud: audience, sub: 'sub-north',
    iat: now - 40, exp: now + 120, ...claims,
  })));
  const signed = new TextEncoder().encode(h + '.' + p);
  const signature = new Uint8Array(await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', keys.privateKey, signed
  ));
  return h + '.' + p + '.' + base64url(signature);
}

function verifier() {
  return createPinnedAccessTokenVerifier({
    issuer, audience,
    publicKeys: new Map([['ci-key', keys.publicKey]]),
    nowSeconds: () => now,
  });
}

beforeAll(async () => {
  keys = await crypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
  }, true, ['sign', 'verify']) as CryptoKeyPair;
});

describe('pinned JWT identity verification (synthetic ephemeral public key)', () => {
  test('requires a correctly signed API access token', async () => {
    expect(await verifier().verifyAccessToken(await jwt())).toEqual({
      issuer, subject: 'sub-north',
    });
    expect(await verifier().verifyAccessToken('invalid')).toBeNull();
    expect(await verifier().verifyAccessToken((await jwt()) + '.extra')).toBeNull();
  });

  test('rejects mismatched issuer, audience, expiry, missing subject and future nbf', async () => {
    const rejected = [
      { iss: 'https://other.example.test/oauth' },
      { aud: 'other-audience' },
      { exp: now },
      { exp: now + 5000 },
      { iat: now + 40 },
      { nbf: now + 50 },
      { sub: null },
      { sub: '' },
      { sub: 'line\nbreak' },
    ];
    for (const claims of rejected) {
      expect(await verifier().verifyAccessToken(await jwt(claims))).toBeNull();
    }
    expect(await verifier().verifyAccessToken(await jwt({
      aud: [audience, 'another'], azp: audience,
    }))).not.toBeNull();
  });

  test('rejects unsupported token headers and unknown signing keys', async () => {
    const headers = [
      { alg: 'none' }, { typ: 'JWT' }, { kid: 'other-key' },
      { jku: 'https://example.test/keys' }, { crit: ['b64'] },
    ];
    for (const header of headers) {
      expect(await verifier().verifyAccessToken(await jwt({}, header))).toBeNull();
    }
    const original = (await jwt()).split('.');
    const altered = original[0] + '.' + original[1] + '.' +
      (original[2].startsWith('A') ? 'B' : 'A') + original[2].slice(1);
    expect(await verifier().verifyAccessToken(altered)).toBeNull();
  });

  test('issuer + subject resolve actor via trusted directory, not JWT role claims', async () => {
    const directory = new Map([[issuer + ':sub-north', 'actor-north']]);
    const session = createVerifiedSubjectSessionBridge(verifier(), {
      async resolveActorId(id) {
        return directory.get(id.issuer + ':' + id.subject) ?? null;
      },
    });
    const withExtraClaims = await jwt({
      actorId: 'not-an-authoritative-actor', role: 'tenant-owner', tenantId: 'demo-orbit',
    });
    expect(await session.verify(withExtraClaims)).toEqual({ actorId: 'actor-north' });
    directory.clear();
    expect(await session.verify(withExtraClaims)).toBeNull();
  });

  test('does not initialize from insecure issuer or missing pinned keys', () => {
    expect(() => createPinnedAccessTokenVerifier({
      issuer: 'http://issuer.example.test', audience,
      publicKeys: new Map([['ci-key', keys.publicKey]]),
    })).toThrow();
    expect(() => createPinnedAccessTokenVerifier({
      issuer, audience, publicKeys: new Map(),
    })).toThrow();
  });
});

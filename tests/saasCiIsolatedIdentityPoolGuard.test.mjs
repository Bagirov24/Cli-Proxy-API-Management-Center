import {describe, expect, test} from 'bun:test';
import {
  createCiIsolatedIdentityPool,
} from '../scripts/saas-staging/ci-isolated-identity-pool.mjs';

describe('Backend07 CI-only physical identity driver deployment guard', () => {
  test('cannot construct when explicit ephemeral PostgreSQL16 flag is absent', () => {
    expect(process.env.SAAS_ISOLATED_IDENTITY_DISCARD_CI)
      .not.toBe('true');
    expect(() => createCiIsolatedIdentityPool({
      password: 'a'.repeat(48),
    })).toThrow('restricted to disposable PostgreSQL16 CI');
  });
  test('missing credentials and unconstrained connection overrides are refused', () => {
    expect(() => createCiIsolatedIdentityPool({
      password: '',
    })).toThrow('restricted to disposable PostgreSQL16 CI');
    expect(() => createCiIsolatedIdentityPool({
      password: 'a'.repeat(48),
      username: 'postgres',
    })).toThrow('restricted to disposable PostgreSQL16 CI');
  });
});

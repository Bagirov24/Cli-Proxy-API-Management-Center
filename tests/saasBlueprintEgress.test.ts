import { describe, expect, test } from 'bun:test';
import type { EgressProfile } from '../src/features/saasBlueprint/domain';
import {
  publicEgressLabel,
  validateEgressProfileShape,
  validateProxyEndpoint,
} from '../src/features/saasBlueprint/egressValidation';

const proxy: EgressProfile = {
  id: 'egress-a',
  name: 'Provider proxy',
  owner: { kind: 'tenant', tenantId: 'tenant-a' },
  kind: 'socks5h',
  status: 'active',
  health: 'healthy',
  endpoint: { hostname: 'proxy.vendor.net', port: 1080 },
};

describe('SaaS Blueprint egress endpoint safety (no outbound connections)', () => {
  test('accepts declared public-looking proxy hosts, with runtime DNS enforcement required', () => {
    expect(validateEgressProfileShape(proxy)).toBeNull();
    expect(validateProxyEndpoint({ hostname: '8.8.8.8', port: 443 })).toBeNull();
    expect(publicEgressLabel(proxy)).toBe('SOCKS5H · proxy.vendor.net:1080');
  });

  test.each([
    'localhost',
    'localhost.',
    'anything.localhost',
    'proxy.local',
    'metadata.google.internal',
    'proxy.internal',
    'mybox.lan',
    'proxy.corp',
    'proxy.test',
    'proxy.invalid',
    'proxy.example',
    '100.100.100.200',
    '169.254.169.254',
    '127.0.0.1',
    '0.0.0.0',
    '10.0.0.1',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.10',
    '100.64.0.1',
    '100.127.255.255',
    '192.0.2.1',
    '198.51.100.1',
    '203.0.113.1',
    '198.18.0.1',
    '224.0.0.1',
    '255.255.255.255',
    '0127.0.0.1',
    '008.008.008.008',
  ])('rejects a private, special or ambiguous host: %s', (hostname) => {
    expect(validateProxyEndpoint({ hostname, port: 8080 })).not.toBeNull();
  });

  test.each([
    '',
    '127.1',
    '2130706433',
    '0x7f000001',
    '[::1]',
    '::ffff:127.0.0.1',
    'fd00::1',
    'http://proxy.vendor.net',
    'user:pass@proxy.vendor.net',
    'user@proxy.vendor.net',
    'proxy.vendor.net/path',
    'proxy.vendor.net?x=1',
    'proxy vendor.net',
    'proxy.vendor.net:1080',
    'proxy.vendor.net#fragment',
  ])('rejects URI-like, ambiguous or credential-bearing hostname: %s', (hostname) => {
    expect(validateProxyEndpoint({ hostname, port: 8080 })).not.toBeNull();
  });

  test.each([0, -1, 65536, 3.14, NaN, Infinity])('rejects invalid port: %s', (port) => {
    expect(validateProxyEndpoint({ hostname: 'proxy.vendor.net', port })).toBe('port-invalid');
  });

  test('requires an endpoint for proxies, forbids it for direct and VPN', () => {
    expect(validateEgressProfileShape({
      ...proxy, endpoint: undefined,
    })).toBe('endpoint-missing');

    expect(validateEgressProfileShape({
      ...proxy, kind: 'direct',
    })).toBe('endpoint-unexpected');

    expect(validateEgressProfileShape({
      ...proxy, kind: 'direct', endpoint: undefined,
    })).toBeNull();

    expect(validateEgressProfileShape({
      ...proxy, kind: 'vpn-connector', endpoint: undefined,
    })).toBe('connector-id-missing');

    expect(validateEgressProfileShape({
      ...proxy, kind: 'vpn-connector', endpoint: undefined, connectorId: 'vpn-verified',
    })).toBeNull();
  });

  test('VPN connectors do not accept user-controlled URLs or proxy credentials', () => {
    expect(validateEgressProfileShape({
      ...proxy,
      kind: 'vpn-connector',
      connectorId: 'https://login:password@vpn.example.net',
      endpoint: undefined,
    })).toBe('connector-id-missing');
    expect(publicEgressLabel({
      ...proxy, kind: 'vpn-connector', endpoint: undefined, connectorId: 'vpn-safe',
    })).toBe('VPN connector');
  });

  test('invalid proxy label never reproduces embedded credentials', () => {
    const label = publicEgressLabel({
      ...proxy, endpoint: { hostname: 'user:SECRET@proxy.vendor.net', port: 1080 },
    });
    expect(label).toBe('Invalid proxy endpoint');
    expect(label).not.toContain('SECRET');
  });
});

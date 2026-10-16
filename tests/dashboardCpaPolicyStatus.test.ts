import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { summarizeCpaPolicy } from '../src/features/dashboard/cpaPolicyStatus';
import type { PluginListEntry, PluginListResponse } from '../src/types/plugin';

const plugin = (overrides: Partial<PluginListEntry> = {}): PluginListEntry => ({
  id: 'cpa-key-policy',
  path: '/CLIProxyAPI/plugins/linux/amd64/cpa-key-policy.so',
  configured: true,
  registered: true,
  enabled: true,
  effectiveEnabled: true,
  supportsOAuth: false,
  logo: '',
  configFields: [],
  menus: [{ path: '/v0/resource/plugins/cpa-key-policy/index.html', menu: 'Keys', description: '' }],
  metadata: {
    name: 'CPA Key Policy',
    version: '0.5.1',
    author: '',
    githubRepository: '',
    logo: '',
    configFields: [],
  },
  ...overrides,
});

const listing = (plugins: PluginListEntry[], pluginsEnabled = true): PluginListResponse => ({
  pluginsEnabled,
  pluginsDir: '/CLIProxyAPI/plugins',
  plugins,
});

describe('Dashboard CPA Key Policy read-only status', () => {
  test('displays an enabled plugin and uses the first valid backend menu', () => {
    const result = summarizeCpaPolicy(
      listing([plugin({ menus: [
        { path: '   ', menu: 'Empty', description: '' },
        { path: '/v0/resource/plugins/cpa-key-policy/index.html', menu: 'Keys', description: '' },
      ] })])
    );
    expect(result).toEqual({
      state: 'enabled',
      version: '0.5.1',
      route: '/plugin-pages/cpa-key-policy/1',
    });
  });

  test('uses the exact CPA plugin ID, not a similarly named plugin', () => {
    expect(summarizeCpaPolicy(listing([plugin({ id: 'cpa-key-policy-alt' })]))).toEqual({
      state: 'missing',
      version: null,
      route: null,
    });
  });

  test.each([
    [true, false, true],
    [true, true, false],
    [false, true, true],
  ])('does not link to disabled plugin: global=%s, enabled=%s, effective=%s',
    (global, enabled, effectiveEnabled) => {
      const result = summarizeCpaPolicy(
        listing([plugin({ enabled, effectiveEnabled })], global)
      );
      expect(result.state).toBe('disabled');
      expect(result.route).toBeNull();
    }
  );

  test('does not fabricate a navigation target for an enabled plugin without menu', () => {
    expect(summarizeCpaPolicy(listing([plugin({ menus: [], metadata: null })]))).toEqual({
      state: 'enabled',
      version: null,
      route: null,
    });
  });

  test('does not confuse a missing plugin with a healthy plugin', () => {
    expect(summarizeCpaPolicy(listing([])).state).toBe('missing');
  });

  test('ignores stale async responses when switching Management API connections', () => {
    const hook = readFileSync(
      new URL('../src/features/dashboard/hooks/useCpaPolicyStatus.ts', import.meta.url),
      'utf8'
    );
    expect(hook).toContain('let cancelled = false;');
    expect(hook.match(/if \(!cancelled\)/g)).toHaveLength(2);
    expect(hook).toContain('cancelled = true;');
    expect(hook).toContain('[apiBase, connected, revision, supportsPlugin]');
    expect(hook).toContain('loaded?.apiBase === apiBase && loaded.revision === revision');
  });
});

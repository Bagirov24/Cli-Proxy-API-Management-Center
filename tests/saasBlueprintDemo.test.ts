import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import {
  DEMO_SNAPSHOT,
  DEMO_SCENARIOS,
  getTenantScenarios,
  runDemoScenario,
  selectTenantDemoView,
  type DemoScenarioId,
} from '../src/features/saasBlueprint/demo/demoData';
import { getSaasDemoCopy } from '../src/features/saasBlueprint/demo/demoCopy';
import { buildDemoFlow } from '../src/features/saasBlueprint/demo/demoFlow';
import { getSaasDemoNavigation } from '../src/features/saasBlueprint/demo/demoNavigation';

const fixtureIds = DEMO_SNAPSHOT.tenants.map((tenant) => tenant.id);

describe('SaaS Blueprint UI fixture isolation', () => {
  test('all tenant selectors return only owned or explicitly granted account and egress metadata', () => {
    const north = selectTenantDemoView(DEMO_SNAPSHOT, 'demo-north');
    const orbit = selectTenantDemoView(DEMO_SNAPSHOT, 'demo-orbit');
    if (!north || !orbit) throw new Error('Static tenant is missing');

    expect(north.accounts.map((a) => a.id).sort()).toEqual(
      ['account-north', 'account-north-oauth', 'account-platform']);
    expect(north.egress.map((a) => a.id).sort()).toEqual(
      ['direct-north', 'proxy-north', 'proxy-north-down', 'proxy-platform']);
    expect(north.applications.map((a) => a.id)).toEqual(['app-north']);
    expect(north.keys.map((k) => k.id)).toEqual(['key-north']);
    expect(north.pools.map((p) => p.id).sort()).toEqual(['pool-north', 'pool-platform']);

    expect(orbit.accounts.map((a) => a.id).sort()).toEqual(
      ['account-orbit', 'account-orbit-vpn']);
    expect(orbit.egress.map((a) => a.id).sort()).toEqual(['proxy-orbit', 'vpn-orbit']);
    expect(orbit.applications.map((a) => a.id)).toEqual(['app-orbit']);
    expect(orbit.keys.map((k) => k.id)).toEqual(['key-orbit']);
    expect(orbit.pools.map((p) => p.id)).toEqual(['pool-orbit']);
    expect(selectTenantDemoView(DEMO_SNAPSHOT, 'not-a-tenant')).toBeNull();
  });

  test('removing the individual platform grant hides account without changing foreign data', () => {
    const restricted = {
      ...DEMO_SNAPSHOT,
      accessGrants: DEMO_SNAPSHOT.accessGrants.filter((grant) => grant.resourceId !== 'account-platform'),
    };
    expect(selectTenantDemoView(restricted, 'demo-north')?.accounts.map((a) => a.id))
      .not.toContain('account-platform');
  });

  test('expiry and disabled grants do not leak shared account metadata', () => {
    for (const broken of [
      { status: 'disabled' as const },
      { expiresAt: '2026-10-09T12:00:00Z' },
      { expiresAt: 'invalid-date' },
    ]) {
      const restricted = {
        ...DEMO_SNAPSHOT,
        accessGrants: DEMO_SNAPSHOT.accessGrants.map((grant) =>
          grant.resourceId === 'account-platform' ? { ...grant, ...broken } : grant),
      };
      expect(selectTenantDemoView(restricted, 'demo-north')?.accounts.map((a) => a.id))
        .not.toContain('account-platform');
    }
  });

  test('scenario options are tenant-scoped and selection cannot preview a different tenant', () => {
    expect(fixtureIds).toEqual(['demo-north', 'demo-orbit']);
    const north = getTenantScenarios('demo-north');
    const orbit = getTenantScenarios('demo-orbit');
    expect(north).toHaveLength(7);
    expect(orbit).toHaveLength(2);
    expect(north.every((item) => item.tenantId === 'demo-north')).toBe(true);
    expect(orbit.every((item) => item.tenantId === 'demo-orbit')).toBe(true);
    expect(north.map((item) => item.id)).not.toContain('orbit-vpn');
  });

  const expectedDecisions: readonly [DemoScenarioId, boolean, string | null][] = [
    ['north-owned', true, null],
    ['north-shared', true, null],
    ['north-foreign-account', false, 'account-not-in-pool'],
    ['north-foreign-egress', false, 'egress-forbidden'],
    ['north-offline', false, 'egress-unavailable'],
    ['north-direct', false, 'egress-direct-forbidden'],
    ['north-unapproved', false, 'account-auth-unapproved'],
    ['orbit-owned', true, null],
    ['orbit-vpn', false, 'egress-unavailable'],
  ];

  test.each(expectedDecisions)('scenario %s: allowed=%s and denial reason %s', (id, allowed, reason) => {
    const run = runDemoScenario(id);
    expect(run.decision.allowed).toBe(allowed);
    expect(run.preview.reasonCode).toBe(reason);
    expect(run.preview.mode).toBe('synthetic-simulation');
    expect(run.preview.steps).toHaveLength(8);
    if (allowed) {
      expect(run.preview.selectedRoute).not.toBeNull();
    } else {
      expect(run.preview.selectedRoute).toBeNull();
      expect(run.preview.steps.some((step) => step.state === 'blocked')).toBe(true);
    }
  });

  test('seven-stage flow is policy-driven while network stages are always schematic', () => {
    const allowed = buildDemoFlow(runDemoScenario('north-owned').preview);
    expect(allowed.map((node) => node.id)).toEqual([
      'client', 'gateway', 'policy', 'pool', 'account', 'egress', 'provider',
    ]);
    expect(allowed.map((node) => node.state)).toEqual([
      'passed', 'illustrative', 'passed', 'passed', 'passed', 'passed', 'illustrative',
    ]);

    for (const scenario of DEMO_SCENARIOS) {
      const run = runDemoScenario(scenario.id);
      const flow = buildDemoFlow(run.preview);
      expect(flow).toHaveLength(7);
      expect(flow.find((node) => node.id === 'gateway')?.state).toBe('illustrative');
      expect(flow.find((node) => node.id === 'provider')?.state)
        .toBe(run.decision.allowed ? 'illustrative' : 'not-reached');
      expect(flow.filter((node) => node.state === 'blocked')).toHaveLength(
        run.decision.allowed ? 0 : 1);
    }
    expect(buildDemoFlow(runDemoScenario('north-offline').preview)
      .find((node) => node.id === 'egress')?.state).toBe('blocked');
    expect(buildDemoFlow(runDemoScenario('north-foreign-account').preview)
      .find((node) => node.id === 'account')?.state).toBe('blocked');
  });

  test('flow context redacts foreign account and egress even for denied scenarios', () => {
    const shared = runDemoScenario('north-shared').context;
    expect(shared.accountReference).toBe('account-platform');
    expect(shared.accountOwnerKind).toBe('platform');
    expect(shared.accountAccess).toBe('shared');
    expect(shared.egressAccess).toBe('shared');
    expect(shared.poolReference).toBe('pool-platform');

    const foreignAccount = runDemoScenario('north-foreign-account').context;
    expect(foreignAccount.accountReference).toBeNull();
    expect(foreignAccount.accountOwnerKind).toBeNull();
    expect(foreignAccount.egressName).toBeNull();

    const foreignEgress = runDemoScenario('north-foreign-egress').context;
    expect(foreignEgress.accountReference).toBe('account-north');
    expect(foreignEgress.egressName).toBeNull();
    expect(foreignEgress.egressOwnerKind).toBeNull();

    const north = DEMO_SCENARIOS.filter((scenario) => scenario.tenantId === 'demo-north');
    for (const scenario of north) {
      const context = runDemoScenario(scenario.id).context;
      expect(JSON.stringify(context)).not.toMatch(/account-orbit|proxy-orbit|Orbit Lab/);
    }
    const orbit = DEMO_SCENARIOS.filter((scenario) => scenario.tenantId === 'demo-orbit');
    for (const scenario of orbit) {
      const context = runDemoScenario(scenario.id).context;
      expect(JSON.stringify(context)).not.toMatch(/account-north|proxy-north|North Studio/);
    }
  });

  test('every scenario has RU/EN human-readable labels and future next actions', () => {
    const ru = getSaasDemoCopy('ru');
    const en = getSaasDemoCopy('en');
    expect(getSaasDemoCopy('zh-CN')).toEqual(en);
    for (const language of ['ru', 'en', 'zh-CN']) {
      const copy = getSaasDemoCopy(language);
      expect(getSaasDemoNavigation(language)).toEqual({
        navGroup: copy.navGroup, navItem: copy.navItem, demoBadge: copy.demoBadge,
      });
    }
    for (const scenario of DEMO_SCENARIOS) {
      expect(ru.scenarios[scenario.id].length).toBeGreaterThan(8);
      expect(en.scenarios[scenario.id].length).toBeGreaterThan(8);
      const run = runDemoScenario(scenario.id);
      if (!run.decision.allowed) {
        for (const copy of [ru, en]) {
          expect(copy.reasons[run.decision.reason].title.length).toBeGreaterThan(7);
          expect(copy.reasons[run.decision.reason].next.length).toBeGreaterThan(10);
        }
      }
    }
    for (const copy of [ru, en]) {
      expect(Object.keys(copy.stages)).toHaveLength(8);
      expect(Object.keys(copy.flowNodes)).toHaveLength(7);
      expect(Object.keys(copy.flowStates)).toHaveLength(4);
      expect(copy.flowSource.length).toBeGreaterThan(30);
      expect(Object.keys(copy.reasons)).toHaveLength(22);
      expect(copy.wizardSteps).toHaveLength(4);
      expect(copy.demoWarning.toLowerCase()).toMatch(/макет|mockup/);
    }
  });

  test('fixture and safe preview contain no raw tokens, authorization headers, or passwords', () => {
    const serialized = JSON.stringify({
      fixtures: DEMO_SNAPSHOT,
      simulations: DEMO_SCENARIOS.map((scenario) => {
        const run = runDemoScenario(scenario.id);
        return { preview: run.preview, context: run.context, flow: buildDemoFlow(run.preview) };
      }),
    });
    expect(serialized).not.toMatch(/sk-ant-|sk-proj-|cpa_[a-z0-9]+|Bearer\s/i);
    expect(serialized).not.toMatch(/access_token|refresh_token|proxyPassword|authorization_header/i);
    expect(serialized).not.toContain('://user:');
  });
});

describe('SaaS opt-in UI and no-live-API safeguards', () => {
  const read = (path: string) =>
    readFileSync(new URL(path, import.meta.url), 'utf8');

  test('route and navigation are BOTH gated by a default-off build flag', () => {
    const flag = read('../src/features/saasBlueprint/demo/featureFlag.ts');
    const routes = read('../src/router/MainRoutes.tsx');
    const layout = read('../src/components/layout/MainLayout.tsx');
    const app = read('../src/App.tsx');
    const vite = read('../vite.config.ts');
    expect(vite).toContain("process.env.VITE_ENABLE_SAAS_BLUEPRINT_DEMO === 'true'");
    expect(vite).toContain('SaasDemoRouteDisabled.tsx');
    expect(flag).toContain('__SAAS_BLUEPRINT_DEMO_ENABLED__');
    expect(routes).toContain('...(SAAS_BLUEPRINT_DEMO_ENABLED');
    expect(routes).toContain("path: '/saas-demo'");
    expect(layout).toContain('...(SAAS_BLUEPRINT_DEMO_ENABLED');
    expect(layout).toContain("path: '/saas-demo'");
    expect(app).toContain('import.meta.env.DEV && SAAS_BLUEPRINT_DEMO_ENABLED');
    expect(app).toContain("path: '/saas-demo-preview'");
  });

  test('demo page never imports operational API clients or sends network requests', () => {
    const page = read('../src/features/saasBlueprint/demo/SaasBlueprintDemoPage.tsx');
    const fixture = read('../src/features/saasBlueprint/demo/demoData.ts');
    for (const source of [page, fixture]) {
      expect(source).not.toMatch(/from\s+['"]@\/services/);
      expect(source).not.toContain('fetch(');
      expect(source).not.toContain('axios');
      expect(source).not.toContain('localStorage');
      expect(source).not.toContain('sessionStorage');
    }
    expect(page).toContain('aria-selected={activeTab === tab}');
    expect(page).toContain("event.key === 'ArrowRight'");
    expect(page).toContain("event.key === 'ArrowDown'");
    expect(page).toContain("event.key === 'ArrowUp'");
    expect(page).toContain("const isMobileGrid = window.matchMedia('(max-width: 740px)').matches");
    expect(page).toContain('aria-live="polite"');
    expect(page).toContain('role="note"');
    expect(page).toContain('buildDemoFlow(preview)');
    expect(page).toContain('aria-pressed={inspected.id === node.id}');
    expect(page).toContain('setSelectedNode(null)');
    expect(page).toContain('flowDetails[inspected.id]');
    expect(page).toContain('ownerLabel(account.owner, copy)');
    expect(page).toContain('ownerLabel(profile.owner, copy)');
    expect(page).toContain('role="region"');
    expect(page).toContain('data-saas-demo-root');
    expect(page).toContain('label={copy.referenceLabel}');

    expect(page).not.toMatch(/onClick=\{.*create(Real|Account|Key|Proxy)/i);
  });

  test('the demo stylesheet honors focus, mobile layout and reduced motion', () => {
    const scss = read('../src/features/saasBlueprint/demo/SaasBlueprintDemoPage.module.scss');
    expect(scss).toContain(':focus-visible');
    expect(scss).toContain('max-width: 740px');
    expect(scss).toContain('max-width: 410px');
    expect(scss).toContain('prefers-reduced-motion: reduce');
    expect(scss).toContain('.flowList');
    expect(scss).toContain('.flowNodeSelected');
    expect(scss).toContain('.flowNodeBlocked');
    const browserTest = read('./browser/saas_demo_browser.py');
    const browserWorkflow = read('../.github/workflows/saas-blueprint-browser-ci.yml');
    expect(browserTest).toContain('audit_accessibility');
    expect(browserTest).toContain('wcag22aa');
    expect(browserTest).toContain('reflow-200pct-ru-light');
    expect(browserWorkflow).toContain('axe-core@4.10.3');
    expect(browserWorkflow).not.toMatch(/railway (up|deploy)|deploy to production/i);
  });
});

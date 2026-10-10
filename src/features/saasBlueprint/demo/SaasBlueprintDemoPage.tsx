import { useId, useMemo, useState, type KeyboardEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { getSaasDemoCopy, type DemoCopy } from './demoCopy';
import {
  DEMO_SNAPSHOT,
  getTenantScenarios,
  runDemoScenario,
  selectTenantDemoView,
  type DemoScenarioId,
  type TenantDemoView,
} from './demoData';
import { publicEgressLabel } from '../egressValidation';
import type { EgressProfile, ProviderAccount } from '../domain';
import styles from './SaasBlueprintDemoPage.module.scss';

type DemoTab = 'clients' | 'accounts' | 'egress' | 'routing';
const TABS: readonly DemoTab[] = ['clients', 'accounts', 'egress', 'routing'];
const DOCS_URL = 'https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/blob/feature/saas-blueprint-tenant-egress-20261010/docs/saas/UX_UI.ru.md';

function matches(search: string, ...candidates: string[]) {
  if (!search) return true;
  return candidates.some((candidate) => candidate.toLowerCase().includes(search));
}

function ResourceCard({
  title, eyebrow, children, trailing,
}: {
  title: string;
  eyebrow: string;
  children: ReactNode;
  trailing?: ReactNode;
}) {
  return (
    <article className={styles.resourceCard}>
      <div className={styles.cardTop}>
        <div className={styles.cardHeading}>
          <span className={styles.cardEyebrow}>{eyebrow}</span>
          <h3 className={styles.cardTitle}>{title}</h3>
        </div>
        {trailing}
      </div>
      <div className={styles.cardBody}>{children}</div>
    </article>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div className={styles.detail}><dt>{label}</dt><dd>{value}</dd></div>;
}

function EmptyState({ copy }: { copy: DemoCopy }) {
  return <p className={styles.emptyState} role="status">{copy.emptyState}</p>;
}

function SectionIntro({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className={styles.sectionIntro}>
      <h2>{title}</h2>
      {hint && <p>{hint}</p>}
    </div>
  );
}

function ClientPanel({ view, copy, query }: {
  view: TenantDemoView;
  copy: DemoCopy;
  query: string;
}) {
  const projects = view.projects.filter((project) =>
    matches(query, project.name, project.id));
  const apps = view.applications.filter((app) =>
    matches(query, app.name, app.id));
  const visible = projects.length + apps.length;

  return (
    <section className={styles.panelContent}>
      <SectionIntro title={copy.tabs.clients} hint={copy.tenantHelp} />
      <p className={styles.count}>{copy.resultCount}: {visible}</p>
      {visible === 0 ? <EmptyState copy={copy} /> : (
        <div className={styles.resourceGrid}>
          {projects.map((project) => (
            <ResourceCard key={project.id} eyebrow={copy.project} title={project.name}>
              <dl className={styles.details}>
                <Detail label={copy.owner} value={view.tenant.name} />
                <Detail label="Reference" value={project.id} />
              </dl>
            </ResourceCard>
          ))}
          {apps.map((app) => (
            <ResourceCard key={app.id} eyebrow={copy.application} title={app.name}>
              <dl className={styles.details}>
                <Detail label={copy.project} value={view.projects.find((p) => p.id === app.projectId)?.name || '—'} />
                <Detail label={copy.accessKind} value={view.keys.find((key) => key.applicationId === app.id)?.id || '—'} />
              </dl>
            </ResourceCard>
          ))}
        </div>
      )}
    </section>
  );
}

function AccountCard({ account, view, copy }: {
  account: ProviderAccount;
  view: TenantDemoView;
  copy: DemoCopy;
}) {
  const granted = account.owner.kind === 'platform' ||
    (account.owner.kind === 'tenant' && account.owner.tenantId !== view.tenant.id);
  const egress = view.egress.find((profile) => profile.id === account.egressProfileId);
  const label = account.authorizationStatus === 'approved'
    ? copy.accountStatus[account.status] : copy.approval[account.authorizationStatus];

  return (
    <ResourceCard eyebrow={copy.accountLabel} title={account.id}
      trailing={<span className={[
        styles.statusPill,
        account.authorizationStatus === 'approved' ? styles.statusNeutral : styles.statusWarn,
      ].join(' ')}>{label}</span>}>
      <dl className={styles.details}>
        <Detail label={copy.owner} value={granted ? copy.shared : copy.selfOwned} />
        <Detail label={copy.authLabel} value={copy.authMode[account.authMode]} />
        <Detail label={copy.authorization} value={copy.approval[account.authorizationStatus]} />
        <Detail label={copy.modelLabel} value={account.allowedModelIds.join(', ')} />
        <Detail label={copy.egressLabel} value={egress?.name || copy.noConnection} />
      </dl>
    </ResourceCard>
  );
}

function AccountWizard({ copy }: { copy: DemoCopy }) {
  const [step, setStep] = useState(0);
  const selected = copy.wizardSteps[step];

  return (
    <section className={styles.wizard} aria-label={copy.wizardTitle}>
      <div className={styles.wizardHeading}>
        <div>
          <h3>{copy.wizardTitle}</h3>
          <p>{copy.wizardDescription}</p>
        </div>
        <span className={styles.stepCounter}>{copy.wizardStep} {step + 1}/{copy.wizardSteps.length}</span>
      </div>
      <ol className={styles.wizardSteps} aria-label={copy.wizardTitle}>
        {copy.wizardSteps.map((entry, index) => (
          <li key={entry.title}>
            <button type="button"
              className={[styles.wizardDot, index === step ? styles.wizardDotActive : ''].join(' ')}
              onClick={() => setStep(index)}
              aria-current={index === step ? 'step' : undefined}
              aria-label={[copy.wizardStep, index + 1, entry.title].join(' ')}
            >{index + 1}</button>
          </li>
        ))}
      </ol>
      <div className={styles.wizardContent} aria-live="polite">
        <strong>{selected.title}</strong>
        <p>{selected.description}</p>
      </div>
      <div className={styles.wizardActions}>
        <button className={styles.subtleButton} type="button"
          onClick={() => setStep((old) => old - 1)} disabled={step === 0}>
          {copy.wizardBack}
        </button>
        <button className={styles.primaryButton} type="button"
          onClick={() => setStep((old) => old + 1 < copy.wizardSteps.length ? old + 1 : 0)}>
          {step + 1 === copy.wizardSteps.length ? copy.wizardRestart : copy.wizardNext}
        </button>
      </div>
    </section>
  );
}

function AccountsPanel({ view, copy, query }: {
  view: TenantDemoView;
  copy: DemoCopy;
  query: string;
}) {
  const visible = view.accounts.filter((account) =>
    matches(query, account.id, account.providerId, copy.authMode[account.authMode]));
  return (
    <div className={styles.panelContent}>
      <SectionIntro title={copy.tabs.accounts} hint={copy.accountReadonly} />
      <p className={styles.count}>{copy.resultCount}: {visible.length}</p>
      {visible.length === 0 ? <EmptyState copy={copy} /> : (
        <div className={styles.resourceGrid}>
          {visible.map((account) => <AccountCard key={account.id} account={account} view={view} copy={copy} />)}
        </div>
      )}
      <AccountWizard key={view.tenant.id} copy={copy} />
    </div>
  );
}

function EgressCard({ profile, view, copy }: {
  profile: EgressProfile;
  view: TenantDemoView;
  copy: DemoCopy;
}) {
  const granted = profile.owner.kind === 'platform' ||
    (profile.owner.kind === 'tenant' && profile.owner.tenantId !== view.tenant.id);
  const stateClass = profile.health === 'offline' ? styles.statusError :
    profile.health === 'healthy' ? styles.statusNeutral : styles.statusWarn;
  return (
    <ResourceCard title={profile.name} eyebrow={copy.egressLabel}
      trailing={<span className={[styles.statusPill, stateClass].join(' ')}>{copy.health[profile.health]}</span>}>
      <dl className={styles.details}>
        <Detail label={copy.owner} value={granted ? copy.shared : copy.selfOwned} />
        <Detail label={copy.profileLabel} value={profile.kind.toUpperCase()} />
        <Detail label={copy.endpointLabel} value={profile.kind === 'vpn-connector'
          ? copy.noConnection : publicEgressLabel(profile)} />
        <Detail label={copy.healthLabel} value={copy.health[profile.health]} />
      </dl>
      <p className={styles.microNote}>{copy.noTestedIp}</p>
    </ResourceCard>
  );
}

function EgressPanel({ view, copy, query }: {
  view: TenantDemoView;
  copy: DemoCopy;
  query: string;
}) {
  const visible = view.egress.filter((profile) =>
    matches(query, profile.id, profile.name, profile.kind));
  return (
    <section className={styles.panelContent}>
      <SectionIntro title={copy.tabs.egress} hint={copy.egressReadonly} />
      <p className={styles.count}>{copy.resultCount}: {visible.length}</p>
      {visible.length === 0 ? <EmptyState copy={copy} /> : (
        <div className={styles.resourceGrid}>
          {visible.map((profile) => <EgressCard key={profile.id} profile={profile} view={view} copy={copy} />)}
        </div>
      )}
    </section>
  );
}

function RoutePanel({ tenantId, copy }: {
  tenantId: string;
  copy: DemoCopy;
}) {
  const candidates = getTenantScenarios(tenantId);
  const [requestedScenario, setRequestedScenario] = useState<DemoScenarioId>(
    tenantId === 'demo-north' ? 'north-owned' : 'orbit-owned');
  const currentId = candidates.some((candidate) => candidate.id === requestedScenario)
    ? requestedScenario : candidates[0].id;
  const { decision, preview } = runDemoScenario(currentId);
  const reason = decision.allowed ? null : copy.reasons[decision.reason];

  return (
    <section className={styles.panelContent}>
      <SectionIntro title={copy.tabs.routing} hint={copy.routeDisclaimer} />
      <div className={styles.scenarioForm}>
        <label htmlFor="saas-demo-scenario">{copy.scenarioLabel}</label>
        <select id="saas-demo-scenario" value={currentId}
          onChange={(event) => setRequestedScenario(event.target.value as DemoScenarioId)}>
          {candidates.map((scenario) => (
            <option key={scenario.id} value={scenario.id}>{copy.scenarios[scenario.id]}</option>
          ))}
        </select>
      </div>
      <div className={styles.decision} role="status" aria-live="polite">
        <div className={styles.decisionHeader}>
          <div>
            <span className={styles.cardEyebrow}>{copy.decisionTitle}</span>
            <h3>{decision.allowed ? copy.decisionAllow : copy.decisionDeny}</h3>
          </div>
          <span className={[
            styles.decisionSymbol, decision.allowed ? styles.decisionYes : styles.decisionNo,
          ].join(' ')} aria-hidden="true">{decision.allowed ? '✓' : '×'}</span>
        </div>
        {reason ? (
          <div className={styles.explanation}>
            <strong>{copy.denialWhy}</strong><p>{reason.title}</p>
            <strong>{copy.nextAction}</strong><p>{reason.next}</p>
          </div>
        ) : (
          <dl className={styles.decisionDetails}>
            <Detail label={copy.resolvedAccount} value={preview.selectedRoute?.accountReference || '—'} />
            <Detail label={copy.selectedEgress} value={preview.selectedRoute?.egressReference || '—'} />
          </dl>
        )}
      </div>
      <div className={styles.timeline}>
        <h3>{copy.timelineTitle}</h3>
        <ol className={styles.timelineList}>
          {preview.steps.map((stage, index) => (
            <li key={stage.stage} className={styles.timelineRow}>
              <span className={[
                styles.timelineBullet,
                stage.state === 'passed' ? styles.timelinePassed :
                  stage.state === 'blocked' ? styles.timelineBlocked : styles.timelinePending,
              ].join(' ')} aria-hidden="true">
                {stage.state === 'passed' ? '✓' : stage.state === 'blocked' ? '×' : index + 1}
              </span>
              <span className={styles.timelineName}>{copy.stages[stage.stage]}</span>
              <span className={styles.timelineState}>
                {stage.state === 'passed' ? copy.stagePassed :
                  stage.state === 'blocked' ? copy.stageBlocked : copy.stagePending}
              </span>
            </li>
          ))}
        </ol>
      </div>
      <p className={styles.microNote}>{copy.routeDisclaimer}</p>
    </section>
  );
}

export function SaasBlueprintDemoPage() {
  const { i18n } = useTranslation();
  const copy = getSaasDemoCopy(i18n.language);
  const tabId = useId();
  const [tenantId, setTenantId] = useState(DEMO_SNAPSHOT.tenants[0].id);
  const [activeTab, setActiveTab] = useState<DemoTab>('clients');
  const [search, setSearch] = useState('');
  const view = useMemo(() => selectTenantDemoView(DEMO_SNAPSHOT, tenantId), [tenantId]);
  if (!view) return null;
  const normalizedSearch = search.trim().toLowerCase();

  const setTenant = (next: string) => {
    if (!DEMO_SNAPSHOT.tenants.some((tenant) => tenant.id === next)) return;
    setTenantId(next);
    setActiveTab('clients');
    setSearch('');
  };

  const switchTab = (next: DemoTab) => {
    setActiveTab(next);
    setSearch('');
  };

  const handleTabKeyDown = (event: KeyboardEvent<HTMLButtonElement>, tab: DemoTab) => {
    const position = TABS.indexOf(tab);
    let next: number;
    if (event.key === 'ArrowRight') next = (position + 1) % TABS.length;
    else if (event.key === 'ArrowLeft') next = (position + TABS.length - 1) % TABS.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = TABS.length - 1;
    else return;
    event.preventDefault();
    const selected = TABS[next];
    switchTab(selected);
    document.getElementById(tabId + '-' + selected)?.focus();
  };

  return (
    <div className={styles.page}>
      <header className={styles.hero}>
        <div className={styles.heroLeft}>
          <span className={styles.eyebrow}>{copy.eyebrow}</span>
          <h1>{copy.title}</h1>
          <p>{copy.subtitle}</p>
          <div className={styles.heroBadges}>
            <span className={styles.demoBadge}>{copy.demoBadge}</span>
            <span className={styles.secondaryBadge}>{copy.draftStatus}</span>
          </div>
        </div>
        <div className={styles.heroGraphic} aria-hidden="true">
          <div className={styles.graphicNode}>TENANT</div>
          <div className={styles.graphicLink} />
          <div className={styles.graphicNode}>POLICY</div>
          <div className={styles.graphicLink} />
          <div className={styles.graphicNode}>EGRESS</div>
        </div>
      </header>

      <p className={styles.safetyNotice} role="note">
        <span className={styles.safetyIcon} aria-hidden="true">ⓘ</span>
        {copy.demoWarning}
      </p>

      <div className={styles.tenantToolbar}>
        <div className={styles.tenantContext}>
          <span className={styles.toolbarLabel}>{copy.viewAs}</span>
          <span className={styles.tenantName}>{view.tenant.name}</span>
          <span className={styles.toolbarHint}>{copy.tenantHelp}</span>
        </div>
        <div className={styles.tenantSelect}>
          <label htmlFor="saas-demo-tenant">{copy.tenantLabel}</label>
          <select id="saas-demo-tenant" value={tenantId}
            onChange={(event) => setTenant(event.target.value)}>
            {DEMO_SNAPSHOT.tenants.map((tenant) => (
              <option key={tenant.id} value={tenant.id}>{tenant.name}</option>
            ))}
          </select>
        </div>
      </div>

      <section className={styles.metrics} aria-label={copy.listHeader}>
        {([
          ['projects', view.projects.length],
          ['applications', view.applications.length],
          ['accounts', view.accounts.length],
          ['egress', view.egress.length],
        ] as const).map(([name, count]) => (
          <div key={name} className={styles.metric}>
            <span>{copy.metrics[name]}</span>
            <strong>{count}</strong>
            <small>{copy.demoBadge}</small>
          </div>
        ))}
      </section>

      <div className={styles.workspace}>
        <div className={styles.tabs} role="tablist" aria-label={copy.navGroup}>
          {TABS.map((tab) => (
            <button key={tab} id={tabId + '-' + tab} type="button" role="tab"
              aria-controls={tabId + '-panel'} aria-selected={activeTab === tab}
              tabIndex={activeTab === tab ? 0 : -1}
              className={[styles.tab, activeTab === tab ? styles.tabActive : ''].join(' ')}
              onClick={() => switchTab(tab)}
              onKeyDown={(event) => handleTabKeyDown(event, tab)}>
              {copy.tabs[tab]}
            </button>
          ))}
        </div>
        <div className={styles.workspaceBody}>
          {activeTab !== 'routing' && (
            <div className={styles.searchField}>
              <label htmlFor="saas-demo-search">{copy.searchLabel}</label>
              <input id="saas-demo-search" type="search" value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder={copy.searchPlaceholder} />
            </div>
          )}
          <div id={tabId + '-panel'} role="tabpanel" tabIndex={0}
            aria-labelledby={tabId + '-' + activeTab}>
            {activeTab === 'clients' && <ClientPanel copy={copy} view={view} query={normalizedSearch} />}
            {activeTab === 'accounts' && <AccountsPanel copy={copy} view={view} query={normalizedSearch} />}
            {activeTab === 'egress' && <EgressPanel copy={copy} view={view} query={normalizedSearch} />}
            {activeTab === 'routing' && <RoutePanel key={tenantId} tenantId={tenantId} copy={copy} />}
          </div>
        </div>
      </div>
      <footer className={styles.footer}>
        <span>{copy.draftStatus}</span>
        <a href={DOCS_URL} target="_blank" rel="noopener noreferrer">{copy.readDocs} ↗</a>
      </footer>
    </div>
  );
}

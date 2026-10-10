import type { AccountAuthMode, Health, ProviderAccount } from '../domain';
import type { DenialReason, PolicyStage } from '../resolveRoute';
import type { DemoScenarioId } from './demoData';
import type { DemoFlowNode, DemoFlowState } from './demoFlow';

interface ReasonCopy {
  readonly title: string;
  readonly next: string;
}

export interface DemoCopy {
  readonly navGroup: string;
  readonly navItem: string;
  readonly eyebrow: string;
  readonly title: string;
  readonly subtitle: string;
  readonly demoBadge: string;
  readonly demoWarning: string;
  readonly draftStatus: string;
  readonly tenantLabel: string;
  readonly tenantHelp: string;
  readonly viewAs: string;
  readonly tabs: {
    readonly clients: string;
    readonly accounts: string;
    readonly egress: string;
    readonly routing: string;
  };
  readonly metrics: {
    readonly projects: string;
    readonly applications: string;
    readonly accounts: string;
    readonly egress: string;
  };
  readonly listHeader: string;
  readonly searchLabel: string;
  readonly searchPlaceholder: string;
  readonly resultCount: string;
  readonly emptyState: string;
  readonly project: string;
  readonly application: string;
  readonly accessKind: string;
  readonly owner: string;
  readonly referenceLabel: string;
  readonly selfOwned: string;
  readonly shared: string;
  readonly platformOwner: string;
  readonly accessScope: string;
  readonly accountLabel: string;
  readonly authLabel: string;
  readonly authorization: string;
  readonly egressLabel: string;
  readonly modelLabel: string;
  readonly providerLabel: string;
  readonly profileLabel: string;
  readonly healthLabel: string;
  readonly endpointLabel: string;
  readonly noEndpoint: string;
  readonly accountReadonly: string;
  readonly egressReadonly: string;
  readonly noConnection: string;
  readonly noTestedIp: string;
  readonly wizardTitle: string;
  readonly wizardDescription: string;
  readonly wizardStep: string;
  readonly wizardBack: string;
  readonly wizardNext: string;
  readonly wizardRestart: string;
  readonly wizardSteps: readonly { readonly title: string; readonly description: string }[];
  readonly scenarioLabel: string;
  readonly decisionTitle: string;
  readonly decisionAllow: string;
  readonly decisionDeny: string;
  readonly denialWhy: string;
  readonly nextAction: string;
  readonly timelineTitle: string;
  readonly flowTitle: string;
  readonly flowHint: string;
  readonly flowInspector: string;
  readonly flowUnknown: string;
  readonly flowSchematic: string;
  readonly flowSource: string;
  readonly flowNodes: Readonly<Record<DemoFlowNode, string>>;
  readonly flowStates: Readonly<Record<DemoFlowState, string>>;
  readonly stagePassed: string;
  readonly stageBlocked: string;
  readonly stagePending: string;
  readonly resolvedAccount: string;
  readonly selectedEgress: string;
  readonly routeDisclaimer: string;
  readonly readDocs: string;
  readonly health: Readonly<Record<Health, string>>;
  readonly accountStatus: Readonly<Record<ProviderAccount['status'], string>>;
  readonly approval: Readonly<Record<ProviderAccount['authorizationStatus'], string>>;
  readonly authMode: Readonly<Record<AccountAuthMode, string>>;
  readonly stages: Readonly<Record<PolicyStage, string>>;
  readonly reasons: Readonly<Record<DenialReason, ReasonCopy>>;
  readonly scenarios: Readonly<Record<DemoScenarioId, string>>;
}

const ru: DemoCopy = {
  navGroup: 'SaaS · прототип',
  navItem: 'Клиенты и подключения',
  eyebrow: 'BLUEPRINT B / UX DEMO',
  title: 'Клиенты, аккаунты и подключения',
  subtitle: 'Будущая единая панель SaaS — сначала понятная модель доступа, затем реальные интеграции.',
  demoBadge: 'Синтетические данные',
  demoWarning: 'Это интерактивный макет. Никаких запросов в Core, VPN, CPA, Railway или к провайдерам не выполняется.',
  draftStatus: 'Не подключено к production',
  tenantLabel: 'Просмотр от имени клиента',
  tenantHelp: 'Переключение показывает только доступные выбранному клиенту демонстрационные объекты.',
  viewAs: 'Выбранный клиент',
  tabs: {
    clients: 'Клиенты и проекты',
    accounts: 'Аккаунты и BYOK/BYOA',
    egress: 'Сеть и подключения',
    routing: 'Схема запроса',
  },
  metrics: {
    projects: 'Проекты',
    applications: 'Приложения',
    accounts: 'Доступные аккаунты',
    egress: 'Сетевые подключения',
  },
  listHeader: 'Доступные ресурсы',
  searchLabel: 'Поиск в списке',
  searchPlaceholder: 'Название, тип или идентификатор',
  resultCount: 'Показано',
  emptyState: 'По этому запросу ничего не найдено. Очистите поиск или переключите клиента.',
  project: 'Проект',
  application: 'Приложение',
  accessKind: 'CPA-ключ',
  owner: 'Владелец',
  referenceLabel: 'Идентификатор',
  selfOwned: 'Собственный ресурс',
  shared: 'Доступ по отдельному разрешению',
  platformOwner: 'Платформа',
  accessScope: 'Права доступа',
  accountLabel: 'Аккаунт провайдера',
  authLabel: 'Авторизация',
  authorization: 'Разрешение на использование',
  egressLabel: 'Исходящий маршрут',
  modelLabel: 'Разрешённые модели',
  providerLabel: 'Провайдер',
  profileLabel: 'Тип подключения',
  healthLabel: 'Состояние (демо)',
  endpointLabel: 'Адрес без секретов',
  noEndpoint: 'Нет адреса',
  accountReadonly: 'Изменение и подключение реальных учётных записей появятся после внедрения защищённого SaaS API.',
  egressReadonly: 'Сетевые проверки и фактический исходящий IP пока не выполняются. Статусы ниже только демонстрационные.',
  noConnection: 'Не подключено',
  noTestedIp: 'Исходящий IP ещё не подтверждён',
  wizardTitle: 'Как будет подключаться учётная запись',
  wizardDescription: 'Просмотр будущего мастера без формы ввода ключей и без сохранения.',
  wizardStep: 'Шаг',
  wizardBack: 'Назад',
  wizardNext: 'Далее',
  wizardRestart: 'Сначала',
  wizardSteps: [
    { title: 'Выбери клиента и проект', description: 'Владелец ресурса назначается до ввода учётных данных.' },
    { title: 'Выбери BYOK или разрешённый BYOA', description: 'Для API-ключа — защищённое хранилище; OAuth доступен только в поддерживаемом провайдером режиме.' },
    { title: 'Выбери исходящий маршрут', description: 'Обязательный прокси/VPN должен быть подтверждён. При ошибке трафик не уходит напрямую.' },
    { title: 'Проверь связи перед сохранением', description: 'Клиент → приложение → CPA-ключ → аккаунт → прокси. Применение появится лишь после backend-проверок.' },
  ],
  scenarioLabel: 'Сценарий симуляции',
  decisionTitle: 'Решение политики',
  decisionAllow: 'Разрешено в симуляции',
  decisionDeny: 'Отклонено в симуляции',
  denialWhy: 'Почему получено это решение',
  nextAction: 'Что делать',
  timelineTitle: 'Этапы проверки',
  flowTitle: 'Интерактивная схема запроса',
  flowHint: 'Выберите узел, чтобы увидеть безопасные сведения. Это симуляция правил, а не реальные сетевые запросы.',
  flowInspector: 'Выбранный этап',
  flowUnknown: 'Недоступно или нет разрешения',
  flowSchematic: 'Узел показан для объяснения архитектуры. Нет реального сетевого соединения.',
  flowSource: 'Источник: синтетическая фикстура от 10.10.2026. Gateway и AI-провайдер не вызываются.',
  flowNodes: {
    client: 'Клиент / приложение',
    gateway: 'API Gateway',
    policy: 'CPA Key Policy',
    pool: 'Пул аккаунтов',
    account: 'AI-аккаунт',
    egress: 'Прокси / VPN',
    provider: 'AI-провайдер',
  },
  flowStates: {
    passed: 'Правило пройдено',
    blocked: 'Заблокировано здесь',
    'not-reached': 'Не достигнуто',
    illustrative: 'Только схема',
  },
  stagePassed: 'Пройдено',
  stageBlocked: 'Заблокировано',
  stagePending: 'Не выполнялось',
  resolvedAccount: 'Выбранный аккаунт (reference)',
  selectedEgress: 'Исходящий профиль (reference)',
  routeDisclaimer: 'Результат отражает только чистую модель правил. Он НЕ подтверждает реальную маршрутизацию, VPN, IP или работоспособность OAuth.',
  readDocs: 'Требования к безопасности и UX/UI на GitHub',
  health: { healthy: 'Условно доступен', degraded: 'Деградирует', offline: 'Недоступен', unknown: 'Не проверен' },
  accountStatus: { active: 'Активен в макете', disabled: 'Отключён', 'reauth-required': 'Требуется вход', blocked: 'Заблокирован' },
  approval: { approved: 'Режим разрешён в макете', unverified: 'Режим не подтверждён', blocked: 'Использование запрещено' },
  authMode: { 'provider-api-key': 'BYOK · API-ключ', 'provider-oauth': 'BYOA · OAuth', 'workload-identity': 'Workload identity' },
  stages: {
    configuration: 'Конфигурация',
    tenant: 'Клиент',
    application: 'Проект и приложение',
    'client-key': 'CPA-ключ',
    routing: 'Правило маршрута',
    'account-pool': 'Пул аккаунтов',
    'provider-account': 'Аккаунт и модель',
    egress: 'Исходящее подключение',
  },
  reasons: {
    'unsupported-schema': { title: 'Несовместимая версия модели', next: 'Проверьте контракт версии перед интеграцией.' },
    'invalid-clock': { title: 'Неверное время проверки', next: 'Проверьте доверенный источник времени.' },
    'tenant-unavailable': { title: 'Клиент отключён или отсутствует', next: 'Проверьте статус клиента.' },
    'application-unavailable': { title: 'Приложение недоступно', next: 'Проверьте статус приложения.' },
    'project-unavailable': { title: 'Проект недоступен', next: 'Проверьте принадлежность проекта.' },
    'client-key-unavailable': { title: 'CPA-ключ не найден или отключён', next: 'Проверьте привязку ключа к приложению.' },
    'core-native-key-forbidden': { title: 'Нативный ключ Core не допускается в SaaS', next: 'Для клиентов нужен отдельный CPA-ключ.' },
    'route-not-found': { title: 'Для модели не найден маршрут', next: 'Проверьте разрешённые модели и правила.' },
    'route-ambiguous': { title: 'Конфликт маршрутов', next: 'Оставьте одно однозначное правило.' },
    'pool-unavailable': { title: 'Группа аккаунтов недоступна', next: 'Проверьте статус группы.' },
    'pool-forbidden': { title: 'Нет доступа к группе аккаунтов', next: 'Проверьте владельца и отдельное разрешение.' },
    'account-unavailable': { title: 'Аккаунт недоступен', next: 'Проверьте состояние аккаунта.' },
    'account-not-in-pool': { title: 'Аккаунт не состоит в разрешённой группе', next: 'Проверьте выбор аккаунта планировщиком.' },
    'account-forbidden': { title: 'Нет доступа к учётной записи', next: 'Нужно явное разрешение владельца.' },
    'account-auth-unapproved': { title: 'Способ авторизации не подтверждён', next: 'Используйте поддерживаемый провайдером способ подключения.' },
    'provider-mismatch': { title: 'Провайдер не соответствует маршруту', next: 'Проверьте модель, группу и провайдера.' },
    'model-forbidden': { title: 'Модель не разрешена аккаунту', next: 'Выберите разрешённую модель.' },
    'egress-unavailable': { title: 'Обязательное подключение недоступно', next: 'Проверьте здоровье прокси/VPN. Прямой обход запрещён.' },
    'egress-forbidden': { title: 'Нет доступа к исходящему маршруту', next: 'Выберите собственный профиль или запросите отдельное разрешение.' },
    'egress-invalid': { title: 'Адрес подключения не прошёл проверку', next: 'Проверьте безопасный адрес и сетевые ограничения.' },
    'egress-direct-forbidden': { title: 'Прямое соединение запрещено', next: 'Настройте обязательный разрешённый прокси.' },
    'vpn-connector-unverified': { title: 'VPN-коннектор не подтверждён', next: 'Проверьте выделенный коннектор до использования.' },
  },
  scenarios: {
    'north-owned': 'Свой аккаунт + свой SOCKS5',
    'north-shared': 'Явное совместное использование платформенных ресурсов',
    'north-foreign-account': 'Попытка обращения к аккаунту другого клиента',
    'north-foreign-egress': 'Попытка выхода через прокси другого клиента',
    'north-offline': 'Обязательный прокси отключился',
    'north-direct': 'Попытка прямого соединения без разрешения',
    'north-unapproved': 'OAuth-режим ещё не подтверждён',
    'orbit-owned': 'Свой аккаунт + разрешённый HTTPS',
    'orbit-vpn': 'VPN-коннектор пока не готов',
  },
};

const en: DemoCopy = {
  navGroup: 'SaaS · prototype',
  navItem: 'Clients & connections',
  eyebrow: 'BLUEPRINT B / UX DEMO',
  title: 'Clients, accounts & connections',
  subtitle: 'A future unified SaaS workspace: start with understandable access rules, then real integrations.',
  demoBadge: 'Synthetic data',
  demoWarning: 'This is an interactive mockup. It makes no requests to Core, CPA, VPN, Railway or any provider.',
  draftStatus: 'Not connected to production',
  tenantLabel: 'Preview as tenant',
  tenantHelp: 'Switching tenants shows only synthetic resources accessible to that tenant.',
  viewAs: 'Selected tenant',
  tabs: { clients: 'Clients & projects', accounts: 'Accounts & BYOK/BYOA', egress: 'Network connections', routing: 'Request path' },
  metrics: { projects: 'Projects', applications: 'Applications', accounts: 'Available accounts', egress: 'Network connections' },
  listHeader: 'Accessible resources',
  searchLabel: 'Search this list',
  searchPlaceholder: 'Name, type or ID',
  resultCount: 'Showing',
  emptyState: 'No matching resources. Clear your search or change tenant.',
  project: 'Project',
  application: 'Application',
  accessKind: 'CPA key',
  owner: 'Owner',
  referenceLabel: 'Reference',
  selfOwned: 'Owned resource',
  shared: 'Explicitly shared',
  platformOwner: 'Platform',
  accessScope: 'Access',
  accountLabel: 'Provider account',
  authLabel: 'Authentication',
  authorization: 'Authorization status',
  egressLabel: 'Outbound route',
  modelLabel: 'Allowed models',
  providerLabel: 'Provider',
  profileLabel: 'Connection type',
  healthLabel: 'Status (synthetic)',
  endpointLabel: 'Address without secrets',
  noEndpoint: 'No endpoint',
  accountReadonly: 'Connecting and editing real accounts will become available only after a secured SaaS API exists.',
  egressReadonly: 'No network checks or actual egress IP lookups are performed. All statuses are synthetic.',
  noConnection: 'Not connected',
  noTestedIp: 'Outbound IP not verified',
  wizardTitle: 'How connecting an account will work',
  wizardDescription: 'Explore the future wizard without entering secrets or saving anything.',
  wizardStep: 'Step',
  wizardBack: 'Back',
  wizardNext: 'Next',
  wizardRestart: 'Restart',
  wizardSteps: [
    { title: 'Choose a tenant and project', description: 'Assign ownership before asking for any credentials.' },
    { title: 'Choose BYOK or approved BYOA', description: 'API keys belong in a vault. OAuth is available only for provider-approved use cases.' },
    { title: 'Select an outbound route', description: 'A mandatory proxy/VPN must be verified. Errors never silently fall back to direct.' },
    { title: 'Review the relationships', description: 'Tenant → app → CPA key → account → proxy. Saving requires future backend enforcement.' },
  ],
  scenarioLabel: 'Simulation scenario',
  decisionTitle: 'Policy decision',
  decisionAllow: 'Allowed in simulation',
  decisionDeny: 'Denied in simulation',
  denialWhy: 'Why this decision was made',
  nextAction: 'Next step',
  timelineTitle: 'Validation stages',
  flowTitle: 'Interactive request path',
  flowHint: 'Select a stage to inspect non-secret references. This models policy decisions, not real network traffic.',
  flowInspector: 'Selected stage',
  flowUnknown: 'Unavailable or not permitted',
  flowSchematic: 'This node explains the architecture. No live network connection is made.',
  flowSource: 'Source: synthetic fixture dated 2026-10-10. No Gateway or AI provider requests are sent.',
  flowNodes: {
    client: 'Client / application',
    gateway: 'API Gateway',
    policy: 'CPA Key Policy',
    pool: 'Account pool',
    account: 'AI account',
    egress: 'Proxy / VPN',
    provider: 'AI provider',
  },
  flowStates: {
    passed: 'Rule passed',
    blocked: 'Blocked here',
    'not-reached': 'Not reached',
    illustrative: 'Schematic only',
  },
  stagePassed: 'Passed',
  stageBlocked: 'Blocked',
  stagePending: 'Not reached',
  resolvedAccount: 'Selected account (reference)',
  selectedEgress: 'Egress profile (reference)',
  routeDisclaimer: 'The result only reflects a pure rules model. It does NOT prove live routing, VPN, outbound IP or OAuth health.',
  readDocs: 'Read security and UX/UI requirements on GitHub',
  health: { healthy: 'Assumed healthy', degraded: 'Degraded', offline: 'Offline', unknown: 'Not verified' },
  accountStatus: { active: 'Active in fixture', disabled: 'Disabled', 'reauth-required': 'Sign-in required', blocked: 'Blocked' },
  approval: { approved: 'Approved in fixture', unverified: 'Not approved', blocked: 'Use prohibited' },
  authMode: { 'provider-api-key': 'BYOK · API key', 'provider-oauth': 'BYOA · OAuth', 'workload-identity': 'Workload identity' },
  stages: {
    configuration: 'Configuration',
    tenant: 'Tenant',
    application: 'Project & application',
    'client-key': 'CPA key',
    routing: 'Routing policy',
    'account-pool': 'Account pool',
    'provider-account': 'Account & model',
    egress: 'Outbound connection',
  },
  reasons: {
    'unsupported-schema': { title: 'Unsupported schema version', next: 'Review the integration contract.' },
    'invalid-clock': { title: 'Invalid evaluation clock', next: 'Check the trusted time source.' },
    'tenant-unavailable': { title: 'Tenant unavailable', next: 'Check tenant status.' },
    'application-unavailable': { title: 'Application unavailable', next: 'Check application status.' },
    'project-unavailable': { title: 'Project unavailable', next: 'Check project ownership.' },
    'client-key-unavailable': { title: 'CPA key unavailable', next: 'Review its application binding.' },
    'core-native-key-forbidden': { title: 'Native Core key forbidden for SaaS', next: 'Issue a dedicated CPA client key.' },
    'route-not-found': { title: 'No route for this model', next: 'Review models and bindings.' },
    'route-ambiguous': { title: 'Ambiguous route rules', next: 'Keep one unambiguous active rule.' },
    'pool-unavailable': { title: 'Account pool unavailable', next: 'Review pool status.' },
    'pool-forbidden': { title: 'Account pool access denied', next: 'Request a separate explicit grant.' },
    'account-unavailable': { title: 'Account unavailable', next: 'Review account state.' },
    'account-not-in-pool': { title: 'Account is not in the permitted pool', next: 'Review the scheduler selection.' },
    'account-forbidden': { title: 'Account access denied', next: 'An explicit owner grant is required.' },
    'account-auth-unapproved': { title: 'Authentication method not approved', next: 'Use a provider-supported connection method.' },
    'provider-mismatch': { title: 'Provider does not match the route', next: 'Review provider, account pool and model.' },
    'model-forbidden': { title: 'Model not allowed', next: 'Choose a permitted model.' },
    'egress-unavailable': { title: 'Mandatory outbound connection unavailable', next: 'Check proxy/VPN health. No direct fallback.' },
    'egress-forbidden': { title: 'Egress profile access denied', next: 'Use your own connection or request a grant.' },
    'egress-invalid': { title: 'Unsafe connection endpoint', next: 'Fix endpoint and verify network restrictions.' },
    'egress-direct-forbidden': { title: 'Direct connection forbidden', next: 'Configure a mandatory approved proxy.' },
    'vpn-connector-unverified': { title: 'VPN connector not verified', next: 'Verify the dedicated connector before use.' },
  },
  scenarios: {
    'north-owned': 'Own account + own SOCKS5',
    'north-shared': 'Explicit grant for shared platform resources',
    'north-foreign-account': 'Attempt to use another tenant account',
    'north-foreign-egress': 'Attempt to use another tenant proxy',
    'north-offline': 'Mandatory proxy goes offline',
    'north-direct': 'Unapproved direct connection',
    'north-unapproved': 'OAuth integration not approved',
    'orbit-owned': 'Own account + approved HTTPS',
    'orbit-vpn': 'VPN connector is not ready',
  },
};

/** Other configured locale codes deliberately fall back to English for this isolated demo. */
export function getSaasDemoCopy(language: string): DemoCopy {
  return language.toLowerCase().startsWith('ru') ? ru : en;
}

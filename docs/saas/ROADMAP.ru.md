# SaaS Blueprint B — поэтапная реализация и контроль качества

**Важно:** ни один пункт ниже сам по себе не даёт согласия на изменение
Railway production, клиентов, OAuth или прокси. Каждый этап — самостоятельный
PR с тестами, возможностью отката и указанием версии Core/CPA.

## Состояния работ

- `SPEC` — только документация и контракты;
- `SIMULATED` — тестируемое поведение на синтетических данных;
- `STAGING` — изолированная среда, синтетические аккаунты, сетевые тесты;
- `VERIFIED` — проверено в заданном окружении с логами и артефактами;
- `RELEASED` — опубликовано после отдельного согласования и rollout.

Не использовать `VERIFIED` или `RELEASED` на основании одних unit tests.

## Этап 0 — Blueprint и прототип policy resolver

**Сейчас:** `SPEC / SIMULATED`, отдельная GitHub-ветка.

- [x] Versioned TypeScript contracts без API-токенов и сетевых вызовов.
- [x] Типы Tenant, Project, Application, CPA binding, Account/Pool, Egress, Grant, Route.
- [x] Чистый decision resolver (allow/deny + стабильные коды причин).
- [x] Egress syntax/SSRF precheck, default deny для private IP.
- [x] Safe preview с только разрешёнными полями.
- [x] Документы: Architecture, UX/UI, Roadmap, Decisions.
- [x] GitHub Actions CI: 1 659 тестов, 0 ошибок, ESLint, TypeScript и Vite build — SUCCESS ([run 38071132757](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38071132757), проверен SHA c0137c2459a14239ff687331874f7326f2f9ac26).
- [ ] Отдельное архитектурное ревью реального CPA scheduler/API contract.

Критерий: `bun run verify` зелёный; доменная модель не связана с Core,
а demo Router импортирует **только opt-in read-only UI** с синтетическими
данными. Нет изменения Core/Gateway, OAuth или `/data`.

## Этап 1 — Read-only SaaS UI

**Статус:** `SIMULATED` для UX-макета, `SPEC` для реального SaaS API.

- [x] Read-only интерактивный **демо** экран на синтетических данных.
- [x] RU/EN microcopy **всех** denial reasons (остальные локали временно English).
- [x] Router добавляет SaaS-раздел **только за feature flag**; в DEV есть standalone preview.
- [x] Списки из изолированных demo fixture selectors (без credentials/API).
- [x] Понятные empty/blocked/unknown состояния, mobile и клавиатурные вкладки;
      локальный error boundary для отказа страницы.
- [x] Unit regression tests demo: tenant-switch scopes, scenarios и no-network UI.
- [ ] Реальный **read-only SaaS API adapter**, серверная фильтрация и AuthZ.
- [ ] Live loading/stale/error/no-permission состояния + проверка изоляции кэша.
- [ ] Browser UI/a11y и screenshot regression tests на staging.
- [ ] Зафиксировать результаты пользовательского UX-ревью до подключения backend.
- [x] Backend API не меняется, live write/connect кнопок нет.

Гейт: UI показывает источник и время данных; переключение tenant не
показывает чужой state. Нет работающих изменений маршрутизации.

## Этап 2 — SaaS Control backend и безопасность

**Статус:** `SPEC`.

- [ ] Выбрать backend, схему PostgreSQL, миграции, индексы, RLS + tenant AuthZ.
- [ ] Отдельный tenant-scoped SSO/login, роли admin/owner/viewer.
- [ ] Реализовать Vault abstraction: key wrapping, rotation, audit, service identities.
- [ ] Получить официальный provider capabilities/approved auth modes registry.
- [ ] Версионированные `/v1/tenants`, `/v1/accounts`, `/v1/egress` API,
      server-side validation, error taxonomy, idempotency/ETag, pagination.
- [ ] Изоляция кэша и запросов; deny by default; журнал действий и grants.
- [ ] Staging без продакшен-ключей и OAuth.

Гейт: penetration testing tenant breakout, отсутствие чужих данных в API,
RBAC+RLS double enforcement, backup+restore dry run.

## Этап 3 — Проверяемый egress + BYOK

**Статус:** `SPEC`.

- [ ] Сеть: каталог HTTP/HTTPS/SOCKS5(H) профилей, операторский allow-list.
- [ ] DNS A/AAAA validation + network firewall + запрет CGNAT/private/metadata,
      DNS rebinding, SSRF через redirects/IPv6, credential exfiltration.
- [ ] Runtime connector обеспечивает fail-closed при proxy down, including
      retries, SSE, WebSocket и OAuth token refresh.
- [ ] Проверить фактически выбранную учётную запись **после** Core scheduler;
      никакого fallback на соседнего tenant или direct.
- [ ] BYOK: только собственный API ключ клиента в Vault, модельный allow-list.
- [ ] Тесты IP egress, reconnect, timeouts, 407, DNS failure, rate-limit.
- [ ] Определить, достаточна ли общая Core-инстанция; иначе выделенный Core.

Гейт: доказанная network-level изоляция; не один лишь allow от JS resolver.
Проверки без доступа к production токенам. Публичный Gateway не должен
передавать management endpoints.

## Этап 4 — BYOA и поддерживаемая авторизация

**Статус:** `SPEC`.

- [ ] Таблица provider/method/allowed_use + подтверждение действующих правил.
- [ ] Встроить системный OAuth/PKCE redirect там, где официально разрешено;
      без антидетекта/подмены браузера и обхода провайдерских блокировок.
- [ ] Refresh/revoke/401/403/429 + cooling + manual reconnect + audit.
- [ ] Не передавать подписные OAuth-токены третьим лицам; разграничить ownership.
- [ ] Интеграционные тесты подключения с аккаунтом, специально разрешённым
      для сценария, в staging.

Гейт: документированное разрешение провайдера и возможность отзыва токена.

## Этап 5 — Analytics, стоимость и Request Trace

**Статус:** `SPEC`.

- [ ] Подписанные события в безопасной схеме, masked references и provenance.
- [ ] Корреляция request_id → CPA policy → verified account → verified egress.
- [ ] Postgres retention, idempotency key, audit, aggregate + cost pricing version.
- [ ] Учитывать input/output/cache/reasoning, если реально доступны.
- [ ] Отделять estimated cost от invoiced/actual; не выдумывать цены/usage.
- [ ] UX timeline + replay, ограниченная анимация, reduced-motion.
- [ ] Проверить нагрузку без блокирования AI inference при сбоях аналитики.

Гейт: воспроизводимость расчётов, правильное tenant scope,
полная очистка/анонимизация по retention.

## Этап 6 — VPN Connector как опция

**Статус:** `SPEC`.

- [ ] Оценить Railway VM/network ограничения WireGuard/Tailscale/tunless egress.
- [ ] Реализовать отдельный connector (не исполнять VPN в Core и не смешивать
      Core secret volume с VPN secret store).
- [ ] Определить fixed exit IP, сеть и port, DNS/IPv6 поведение, health.
- [ ] Connector identity attestation, rotated secrets, egress route verification.
- [ ] Ротация конфигурации без потери критичных сессий; audit.
- [ ] Fail-closed тест при остановке VPN и отказах DNS, без direct fallback.
- [ ] Допустить только правомерные способы сетевого доступа; не обход
      блокировок провайдеров или региональных/лицензионных ограничений.

Гейт: demo environment и security review; feature flag остаётся OFF в production.

## Постоянные ворота для каждого релиза

- Отдельный PR, отдельный commit и lockfile-free change при отсутствии
  необходимости в зависимости.
- `bun run verify` зелёный; TypeScript строгий, unit tests + integration tests
  под соответствующий этап.
- API contract version и migrations; при breaking change — backward
  compatibility plan + automatic rollback.
- Нет ключей/tokens/паролей в Git, client UI, error messages и логах.
- Contract tests совместимости с конкретным CLIProxyAPI v8.0.23 и CPA v0.5.1
  до изменения pinned SHA Core.
- Gateway/Core/Management Center выпускаются отдельно; релиз статического
  `management.html` не повод для обновления Core.
- Production трафик, /data, OAuth и API ключи — неизменяемы во время Blueprint.
  Любые runtime изменения только после отдельного разрешения и backup.
- UX: понятно owner/status/route, mobile, keyboard, a11y, RU+EN, ошибок
  достаточно для восстановления без раскрытия посторонних ресурсов.
- Observability: trace reason code, version, tenant-scoped correlation,
  audit с redaction; владельцу ясно, где симуляция, а где реальные данные.

## Матрица рисков

| Риск | Минимальная защита | Что проверять |
| --- | --- | --- |
| Tenant A использует аккаунт B | owner + grant + post-scheduler enforcement | mismatch tests |
| Неисправный proxy ведёт напрямую | обязательный egress + firewall fail-closed | proxy down / reconnect |
| DNS hostname ведёт на metadata IP | strict DNS policy + firewall | A/AAAA/rebinding tests |
| OAuth или proxy-secret в trace | whitelist-only serialization + Vault | no-secrets tests |
| Подписка провайдера используется против правил | approved auth modes registry | provider review |
| UI показывает старый tenant | request invalidation, no cross-tenant cache | race tests |
| Usage посчитан дважды | idempotent event ledger | retry/dedup tests |
| Финансы выглядят точными без данных | provenance + estimated/actual separation | pricing tests |
| Случайный UI merge провоцирует live release | draft PR и отдельный release gate | GitHub workflow rules |

## Минимальная последовательность первого рабочего прототипа

1. Сохранить эти требования и CI в отдельной ветке (текущий шаг).
2. Проверить API Core и CPA plugins: откуда берутся account/egress метаданные
   без чтения секретов; отдельное ADR по точке enforcement.
3. Спроектировать wireframe и read-only mock UI под `/saas` за feature flag.
4. Спроектировать SaaS API/Vault/DB, только после этого обеспечить реальный
   account/egress enforcement на стенде.

## Текущая поправка к этапу 1 (SIMULATED)

- [x] Встроенная семиузловая схема request path поверх существующего policy resolver, с отдельной маркировкой Gateway и AI Provider как схематичных узлов.
- [x] Добавлен статический regression test на обязательные подписи симуляции.
- [x] Browser smoke в Chromium 1440/820/390/320 px RU/EN light/dark с PNG; tenant-safe inspector и reduced motion проверены.
- [ ] Полная ручная UX/a11y проверка и WCAG-аудит на staging. Анимация — только объясняющая и необязательная.
- [x] **SPEC/SIMULATED:** версии и DTO Control API v1, actor/tenant/membership RBAC, независимые grants, синтетические read-only contract tests.
- [ ] **STAGING/PROPOSED:** серверная AuthZ, HTTP endpoints, PostgreSQL/RLS, SSO, реальный read-only Core metadata adapter. Production не изменять.

## Итерация 2 — результат и оставшийся гейт

- [x] `SIMULATED`: интерактивные 7 узлов request flow с понятными RU/EN статусами, состояниями, инспектором и точкой отказа.
- [x] `SIMULATED`: инспектор строится из tenant-visible проекции контекста. Чужие account/egress references не раскрываются, в том числе при DENY.
- [x] `SIMULATED`: владелец и право `owned/shared` отдельно в account и network cards, модель и провайдер в доступных метаданных.
- [x] CSS focus-visible, keyboard button activation, responsive 7/4/2/1, reduced-motion без сетевой «анимации».
- [x] Автоматический Chromium browser QA RU/EN, light/dark, desktop/tablet/mobile и скриншоты: [SUCCESS #38075528744](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38075528744).
- [x] Сетка 2×2 на mobile, все вкладки в пределах viewport, ArrowUp/Down для клавиатуры.
- [ ] Ручная UX-приёмка, полный WCAG-аудит, screen reader и staging проверки с отказами сервиса.
- [x] SaaS Control API v1 **контракты и тестируемый pure AuthZ/DTO-прототип**: SPEC/SIMULATED, не сервер.
- [ ] SaaS Control API **HTTP backend**, SSO, RLS, Core adapter, реальный trace и enforcement: PROPOSED/STAGING, не реализованы.

## Этап 1, браузерные ворота (SIMULATED)

- [x] GitHub Actions устанавливает Playwright/Chromium изолированно и запускает Vite только с синтетикой.
- [x] 4 конфигурации, 20 скриншотов (overview/accounts/network/deny/allow flow), JSON-результаты, no-external-HTTP проверка.
- [x] Tenant isolation при смене tenant, восстановление поиска, табы с клавиатуры, демонстрационный BYOK/BYOA wizard, mobile overflow и reduced-motion.
- [ ] Согласовать скриншоты с пользователем; до этого не считать UX окончательно принятым.
- [ ] Полный WCAG и end-to-end staging — отдельно, без реальных production токенов/CPA/VPN.

## Этап 1 — дополнительный гейт доступности, итерация 4

- [x] 5 Chromium конфигураций, в т.ч. 640 CSS px для эквивалентной reflow
      ширины 200% масштабирования; 25 PNG и 30 JSON axe-core WCAG A/AA.
- [x] Автоматически обнаружен дефект dark hover `2,58:1`; исправлен и
      покрыт отдельным `accounts-hover` аудитом.
- [x] Полный `bun run verify`, opt-in build и браузерный smoke успешны на
      commit `473a1f66d112079fd20689de5af6ce93a574faeb`.
- [ ] Провести ручную проверку `color-contrast: incomplete` (5 повторяющихся
      элементов), увеличение браузера, скринридеры и а11y UX-приёмку.
- [ ] Backend API/AuthZ/RBAC/read-only adapter и настоящие метрики/трейсы
      остаются `SPEC / PROPOSED`; не переходить к production без согласия.

## Этап 2A — Control API read-only contracts (SPEC/SIMULATED)

- [x] `controlApi/contracts.ts`: версия 1, allow-listed resource DTO,
      generic 403/404/503 response и интерфейс будущего backend adapter.
- [x] `controlApi/authorization.ts`: активное уникальное membership,
      deny при revoked/duplicated, роли owner/admin/viewer/auditor.
- [x] Отдельная authorisation owner+grant для pool/account/egress с
      проверкой grantee, владельца, expiry и состояния.
- [x] `controlApi/readOnlyProjection.ts`: tenant-scoped поля;
      redaction чужих account/egress/pool references и отказ от core-native
      key bindings; source только synthetic-simulation.
- [x] `tests/saasControlApiV1.test.ts`: контрактные unit тесты на
      межклиентскую изоляцию, owner/grant, ошибки, безопасную сериализацию.
- [x] Спецификации
      [CONTROL_API_V1](CONTROL_API_V1.ru.md),
      [AUTHZ_RBAC_V1](AUTHZ_RBAC_V1.ru.md),
      [CORE_METADATA_ADAPTER_V1](CORE_METADATA_ADAPTER_V1.ru.md).
- [ ] Реальная trusted SaaS-сессия и AuthZ middleware; не принимать
      actorId/tenantId из пользовательских заголовков.
- [ ] Реальная БД, RLS, audit, vault, server-side read adapter к Core,
      staged contract tests и cancellation при tenant-switch.
- [ ] Manual security review и интеграционные проверки с Core/CPA на
      отдельном staging, без любых реальных production credentials.


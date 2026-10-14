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

## Этап 2B — изолированная HTTP граница (SIMULATED / LOCAL-ONLY)

- [x] `createControlHttpHandler`: только GET tenant index и
      tenant-scoped metadata коллекции; никакие write routes не созданы.
- [x] Opaque 256-битные **синтетические** сессии, TTL/revoke/hash-at-rest;
      нет endpoints создания токенов или реального SSO.
- [x] Серверный actor directory, RBAC до metadata reader и повторная
      проверка membership/session после async fetch.
- [x] Strict runtime DTO allowlist, static 401/403/404/405/503,
      отсутствие CORS, no-store и серверный correlation ID.
- [x] `syntheticBackend` и `scripts/saas-control-local.mjs`:
      ручной opt-in, 127.0.0.1:18551, отказ запуска в production/Railway.
- [x] HTTP/security tests: spoofed headers, revoked/expired token,
      duplicate membership, independent grants, invalid upstream
      source/schema, aborted/stale responses и синтетический loopback TCP.
- [ ] Настоящие OIDC/SSO и server-side session store с rotation,
      CSRF policy (если cookie auth), revocation across replicas.
- [ ] PostgreSQL + RLS, audit ledger, idempotent migrations,
      resource pagination/rate limits и tenant-aware cache.
- [ ] Проверенный Core/CPA read-only metadata adapter на изолированном
      staging; contract tests с официальным API и fail-closed errors.
- [ ] Подключение React UI к server data после отдельной security/UX
      приёмки. Не менять Core production и не объединять Draft PR.

## Этап 2C — PostgreSQL/RLS staging-only pilot (SQL VERIFIED)

- [x] `staging/saas-rls/001_readonly_pilot.sql`: идемпотентный
      SQL-пилот, NOLOGIN/NOBYPASSRLS роли, FORCE RLS на семи таблицах.
- [x] Закрытые `memberships/resource_grants`: read роль не может
      читать их напрямую или менять metadata, только SELECT через RLS.
- [x] Точные scope/RBAC/owner/grant/expiry проверки, отсутствие
      неявного наследования pool→account и account→egress.
- [x] SQL тесты: North/Orbit isolation, auditor, revoked/suspended,
      wrong-owner/expired/disabled grants, native Core-key deny,
      tenant switch без membership, migration replay.
- [x] GitHub Actions изолированно поднимает временный PostgreSQL 16;
      никаких Railway/production database connections.
- [ ] **Staging backend integration:** реальный PostgreSQL datastore,
      issuer-verified actor, защищённый transaction scope, transaction pool
      reset, параметризованные запросы и SQL injection threat tests.
- [ ] Полный доменный DDL, реальные grants migration/rollback,
      RLS with policy fuzzing, audit, indexes, performance и backup/restore.
- [ ] Разрешённый Core/CPA read-only metadata adapter, нормализация
      неразрешённых routing pool references и UI integration.
- [ ] Перепроверить все security/UX gates перед переносом на staging;
      production и `custom-no-apikey-fun` не менять.

**Не путать пилот с реализацией SaaS БД:** реальная база/RLS, OIDC,
cache invalidation и серверная интеграция остаются **PROPOSED**.

## Этап 2D — подписанный scoped SQL + контракты (CI VERIFIED)

- [x] Ephemeral PG16: миграция `002_signed_scope_pilot.sql` поверх 001,
      HMAC-SHA256 для actor/tenant/transaction ID/expiry, приватный
      случайный ключ и запрет его чтения read ролью.
- [x] Adversarial SQL: попытки подмены старых/новых GUC, чужого actor,
      tenant, expiry и replay подписи из другой транзакции — DENY.
- [x] Проверки RBAC, revoked membership, suspended tenant, grants
      account/pool/egress и hiding of forbidden routing references.
- [x] Pure `readSyntheticTenantCollection`, API DTO и runtime transport:
      полностью скрывают route при отсутствии отдельного pool grant.
- [x] Read-only backend остаётся изолированным от Core,
      Railway production и настоящих credentials.
- [ ] Настоящий issuer-verified OIDC, backend-owned transaction scope,
      protection from arbitrary SQL, тесты SQL injection и очистка
      connection pool после каждого запроса.
- [ ] Вынесенная staging БД/миграции, полный аудит RLS,
      key rotation, query performance и отдельная проверка security.
- [ ] Реальный разрешённый Core read-only metadata adapter,
      contract mapping, UX states/telemetry и неизменное fail-closed
      для AI/egress data-plane.

## Этап 2E — identity + SQL read boundary (test-only)

- [x] `trustedAccessToken.ts`: pinned RS256 access-token verify,
      обязательные issuer/audience/sub/exp/iat, `typ=at+jwt`,
      deny для неподходящих `alg/kid/jku/typ` и подозрительного срока.
- [x] server-held mapping issuer+subject → actorId; tenant/role из
      JWT и client headers не могут стать источником авторизации.
- [x] `signedSqlBoundary.ts`: фиксированные SQL SELECT по
      `ControlCollection`, значения tenant/limit только как параметры,
      HMAC scope по transaction ID и `SET LOCAL ROLE`.
- [x] Abort/rollback, discard на failure, runtime whitelist
      полученных metadata columns и generic failure без DB секретов.
- [x] Unit-тесты RS256 с синтетическими ephemeral keys и
      SQL boundary на fake pool; PostgreSQL CI тест
      `PREPARE/EXECUTE`, опасных значений-параметров и
      rollback/SET LOCAL сброса на одном соединении.
- [ ] Реальный OIDC/SSO/JWKS lifecycle и безопасный session/revocation
      store; production токены в этом этапе не создаются.
- [ ] Реальный PostgreSQL driver, non-superuser pool, query cancellation,
      concurrency/reuse, key rotation, audit, SQL fuzz/pentest.
- [ ] Серверный staged integration тест OIDC → AuthZ → SQL/RLS
      → DTO; Core/CPA read-only adapter и traffic enforcement отдельно.
- [ ] UX интеграция со staging с явным read provenance и
      ошибками/ожиданием, после security review и отдельных согласований.

## Этап 2F — ephemeral PostgreSQL driver acceptance

- [x] **Код:** Bun.SQL wrapper, `reserve`/bound parameters/COMMIT/
      ROLLBACK, exact SELECT templates, cancellation/discard, без
      изменений production dependency graph.
- [x] **Код:** одноразовые SQL fixtures и отдельная NOINHERIT/
      NOBYPASSRLS login роль `saas_ci_runner` вместо superuser.
- [x] **Тест-план:** параллельные North/Orbit reads, отдельные
      platform grants, CPA-only bindings, роль auditor, deny при
      отсутствии membership, GUC reset на повторном соединении.
- [x] **VERIFIED в ephemeral CI:** настоящий Bun.SQL успешно
      выполнил 12 параллельных tenant reads, RLS grants, cleanup
      GUC/role между транзакциями и fail-closed pool shutdown.
      [Workflow #38086896433](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38086896433).
      Это не production драйвер и не доступ к Core.
- [ ] **PROPOSED:** реальный SSO/OIDC, DB driver service, production
      TLS/pool, signer key rotation/revocation, audit и нагрузочные
      проверки до staging deployment.
- [ ] **PROPOSED:** официальный Core/CPA metadata adapter,
      backpressure, trace, egress enforcement, billing.


## Этап 2G.1 — SQL pool lifecycle hardening

- [x] В изолированном SQL boundary введён синхронный quarantine-hook,
  ограниченные deadlines acquire/query/sign, отдельный cleanup timeout
  и отбрасывание поздно полученного соединения.
- [x] Synthetic adversarial tests: бесконечный SELECT, зависшие
  ROLLBACK/release, поздний reserve, success/reuse без карантина.
- [x] Подтверждённый 4/4 CI SHA 2G.1: `4f83d3d93671679777bcc39a0fcc9c960e2a7b0d`.
- [ ] Production-grade atomic connection discard, independent cancel,
  tested pool retry/recovery after network split: **PROPOSED**.

Важно: quarantine-hook закрывает *весь* одноразовый тестовый pool,
но не доказывает готовность SQL transport к production.

## Этап 2G.1b — native Bun.SQL fault experiments

- [x] Добавлен изолированный протокол испытаний реальных Bun.SQL
  `reserve({ signal })`, `Query.cancel()`, `statement_timeout`,
  подтверждённого `ROLLBACK`, `SQL.close()` и создания нового пула.
- [x] Результат 2G.1b подтверждён 4/4 GitHub Actions на
  `0b0f7223189a46d3fd79ad486d2e89a4590487ba`:
  [CI](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38261137470),
  [PG16](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38261137458),
  [Demo](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38261137532),
  [Browser](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38261137479).
  **VERIFIED только тесты и fail-closed quarantine; НЕ bounded native cancel**.
- [x] При первом native CI после отмены `reserve({signal})` повторное
  чтение из **того же** Bun-пула закончилось отказом, поэтому такой пул
  нельзя считать безопасно восстановленным; тест исправлен на quarantine
  и запуск tenant reads только из новой инстанции.
  [Failed probe #38259910402](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38259910402).
- [x] В отдельном PG16 CI Bun native `Query.cancel()` при
  выполняющемся `pg_sleep` **не завершился за 2,5 секунды**:
  [failed probe #38260251602](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38260251602).
  Это отрицательный результат относительно bounded cancel, не PASS.
  В обновлённом тесте исход классифицируется явно, блокируются
  новые выдачи из старого pool; требуется его физический shutdown.
- [ ] Atomic physical `discard(connection)` для Bun 1.3.14 —
  **НЕ подтверждён**. Нельзя использовать `reserved.release()` для
  возврата повреждённого соединения в действующий multi-tenant pool.
- [ ] Протестированный в изоляции альтернативный driver с гарантированным
  удалением отдельной connection, cancellation и network-failure recovery.
  Кандидат: `pg.Pool` с документированным `client.release(true)` —
  только **PROPOSED**, ещё не подключён.

**Уточнение 2G.1:** четыре workflow предыдущего инкремента
на `4f83d3d93671679777bcc39a0fcc9c960e2a7b0d` завершились SUCCESS:
[CI](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38088983986),
[PostgreSQL](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38088984062),
[Demo](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38088983972),
[Browser](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38088983952).

### Негативный результат native Bun.SQL

[PG16 CI #38260730407](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38260730407):
`Query.cancel()` вернул error отмены лишь за 3002 мс (лимит
2,5 секунды). Сам таймаут ожидания `reserve({signal})` не может
считаться успехом native abort, поэтому новый probe явно
отличает driver rejection от собственного deadline. Для любого
сомнительного исхода **fail-closed quarantine и replacement**, не
reuse повреждённого пула.

## Этап 2G.2 — Trusted Identity → AuthZ → signed SQL (server-only)

- [x] Добавлен отдельно от React/HTTP `trustedSqlReadBoundary.ts`
  на существующих pinned RS256 verifier, issuer+subject directory,
  current membership/RBAC и signedSqlBoundary (никаких production keys).
- [x] Вторичная проверка token, actor mapping, membership и роли
  после асинхронного SQL: fail-closed при изменениях доступа и abort.
- [x] Синтетические adversarial unit tests: North/Orbit,
  spoofed headers/JWT claims, чужой issuer/audience/kid,
  ID-token, отозванный actor, duplicate membership, auditor deny,
  SQL-like tenant values, DB failure, race revocation и stale abort.
- [x] Подтверждено 4/4 GitHub Actions для кода SHA
  `2ceb5727faf60efb7eabf90557470c14c5d0f2b1`:
  [CI](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480676)
  (1 745 тестов, 0 fail, lint/tsc/build),
  [PG16](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480684),
  [Demo](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480798),
  [Chromium](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480692).
  Статус VERIFIED относится к isolated contracts и synthetic tests,
  НЕ к real OIDC → SQL integration.
- [ ] **PROPOSED:** настоящий JWT→actor-store→PostgreSQL wire-protocol
  end-to-end acceptance (2G.4), реальный OIDC issuer,
  session replay/revocation across replicas, production pool/physical
  connection discard, Core metadata source и публичный SaaS API.

См. [TRUSTED_SQL_READ_BOUNDARY_V1.ru.md](TRUSTED_SQL_READ_BOUNDARY_V1.ru.md).

## Этап 2G.3 — Security Audit Contract / server-only

- [x] Типизированные события с version, UTC timestamp, correlation ID,
  operation, source, classification, actor/tenant context,
  результатом allow/deny/error и enum reason.
- [x] Sink принимает **только фиксированную allowlist** атрибутов.
  Ни JWT/API/OAuth keys, Authorization headers, prompts, SQL, secrets,
  proxy URI, ни произвольные metadata/foreign object IDs не копируются.
- [x] В `trustedSqlReadBoundary` audit-порт обязателен. Для
  отказанных/ошибочных чтений tenant ID принудительно null.
  Сбой sink → generic 503 без SQL rows, не silent success.
- [x] Только синхронный in-memory sink, без await после финальной
  проверки AuthZ. Отдельная async/durable модель требует review.
- [x] Synthetic adversarial tests: Allow/Deny/Error, IDOR, wrong JWT,
  revocation mid-SQL, cancellation, sink exception, malicious
  metadata/credentials, schema/reason enforcement, bounded buffer.
- [x] 4/4 GitHub Actions SUCCESS на проверенном кодовом SHA
  `1ea71978abd6abc33263fe460754d7f9dbdd1053`:
  [Main CI #38265951045](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265951045)
  (1758 tests, 0 fail, lint/TS/Vite),
  [PG16 #38265950944](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265950944),
  [Demo #38265950961](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265950961),
  [Browser #38265951009](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265951009).
  **VERIFIED только synthetic audit contract; НЕ persistent ledger**.
- [ ] 2G.4 — настоящий synthetic JWT→PostgreSQL wire protocol→RLS→audit
  end-to-end, отдельные consistency/revocation races.
- [ ] Persistent audit, tamper-evident store, ACL, retention,
  multi-replica consistency и real Core/SSO — **PROPOSED**.

См. [SECURITY_AUDIT_V1.ru.md](SECURITY_AUDIT_V1.ru.md).

## Этап 2G.4a — synthetic JWT + actual PG16 signed RLS + audit

- [x] Отдельный CI-only `verify-trusted-pg-e2e.mjs` на существующих
  JWT, RBAC, signed SQL, sanitization и synchronous audit modules.
- [x] Синтетический pinned RS256 token→server-held mapping,
  signed scope HMAC from disposable DB и настоящий non-superuser
  `saas_ci_runner` PostgreSQL wire-protocol.
- [x] Дополнительный SQL fixture после 2F теста:
  Orbit Pool-grant без Account/Egress, North Account-grant без Egress,
  истёкший Egress-grant. Нет изменений production migrations.
- [x] Adversarial проверки 8 concurrent North/Orbit, forged
  JWT role/tenant/actor, foreign issuer/kid/audience, ID-token,
  SQL-like input, auditor deny, revoke mapping/role after COMMIT,
  audit failure, cancellation/pool quarantine.
- [x] 4/4 GitHub Actions SUCCESS для кода SHA
  `73066e254e5db2bdd6abeb479c75cae648fc9624`:
  [Main CI #38269435023](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269435023)
  (1758 unit tests, 0 fail, lint/TS/Vite),
  [PG16 actual E2E #38269435054](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269435054),
  [Demo #38269434999](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269434999),
  [Chromium #38269435126](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269435126).
  VERIFIED реальная RLS интеграция с **synthetic** JWT/actor/audit,
  НЕ production auth, durable audit или network enforcement.
- [ ] **PROPOSED:** trusted tenant-state gate (suspended tenant
  должен давать явный Deny, не 200 empty), consistent actor-state
  snapshot across replicas/DB, real OIDC/JTI revocation, real
  backend SQL physical discard and network-failure recovery.
- [ ] Полный public HTTP/ControlResource DTO, durable audit
  ledger, data-plane enforcement и Railway production — NOT IMPLEMENTED.

Подробности: [E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md](E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md).

## Этап 2G.4b — authoritative tenant/membership gate в PostgreSQL

- [x] Staging-only миграция `003_explicit_read_gate_pilot.sql`:
  HMAC-verified actor+tenant и приватный active membership/exact role
  подтверждаются BOOLEAN security-definer, не чтением таблицы reader.
- [x] Fixed `SCOPED_READ_GATE_SQL` подтверждает active tenant через
  FORCE RLS и capability collection. Запуск до и после metadata SELECT
  в одной подписанной transaction, SQL значения параметризованы.
- [x] Fail-closed преобразование DB Deny в generic 404 и redacted
  `authorization-changed` audit, никаких чужих IDs; malformed gate,
  SQL timeout и rollback failure продолжают вызывать quarantine.
- [x] Adversarial unit и actual PostgreSQL CI probes: suspended tenant,
  revoked DB membership, role mismatch, deny-after-SELECT, healthy
  rollback/reuse, malformed SQL gate.
- [x] 4/4 GitHub Actions SUCCESS для кода SHA
  `12a3b5ba2c9e32786773e369eb1b80195b75e4d8`:
  [Main CI #38272959097](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959097)
  (1763 tests, 0 failures, lint/TS/Vite),
  [PG16 E2E #38272959201](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959201),
  [Demo #38272959212](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959212),
  [Browser #38272959125](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959125).
  **VERIFIED staging read gate; НЕ atomic post-COMMIT revocation**.
- [ ] PROPOSED: атомарная revocation consistency между actor directory
  и DB после второго gate/COMMIT, production OIDC, физический
  connection discard, durable audit, public API/data plane.

Детали: [TENANT_DB_AUTHZ_GATE_V1.ru.md](TENANT_DB_AUTHZ_GATE_V1.ru.md).

## Этап 2G.4c — post-COMMIT signed DB revalidation

- [x] Сервер фиксирует verified tenant/collection/limit/access-token/signal
  до await; caller не может изменить второй SQL scope через мутируемый
  request object.
- [x] Две signed PostgreSQL read-only транзакции для той же коллекции,
  каждая с independent RLS/gates, txid и HMAC; сравнение только
  санитизированных и упорядоченных метаданных.
- [x] Fail-closed 404 + tenantless audit при post-COMMIT revoke tenant,
  membership, grant или несовпадающем row set. Driver/signer/timeout
  failures по-прежнему 503/quarantine без скрытых Allow.
- [x] Adversarial unit и ephemeral PG16 tests: отозванный tenant,
  membership и Account grant между транзакциями, stale response,
  мутируемые request fields и cancel второй транзакции.
- [x] 4/4 GitHub Actions SUCCESS для кодового SHA
  `6b47e92d2884d238b036e6539382cc4ed7a3383f`:
  [Main CI #38275287907](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287907)
  (1 767 unit tests, 0 fail, lint/TypeScript/Vite),
  [actual PG16 E2E #38275287696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287696),
  [Demo #38275287915](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287915),
  [Chromium #38275287939](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287939).
  VERIFIED только synthetic/ephemeral post-COMMIT RLS revalidation.
- [ ] **PROPOSED:** действительно согласованный versioned
  authorization state и revocation barrier после второго COMMIT,
  robust production physical connection discard, real OIDC,
  durable audit/HTTP/Data Plane. Двойное чтение не заменяет эти
  требования и не рекомендовано в качестве production SLA.

См. [POST_COMMIT_REVALIDATION_V1.ru.md](POST_COMMIT_REVALIDATION_V1.ru.md).


## Этап 2G.4d — opt-in server-owned authorization revision guard

- [x] Изолированный типизированный server-side revision port, canonical
  PostgreSQL BIGINT-text range; значения из клиентского запроса/JWT не
  являются авторитетными.
- [x] Опциональное включение guard в существующий trusted signed SQL
  boundary: capture после RBAC и compare после двух COMMIT, повторной
  JWT/actor/membership проверки; mismatch 404, unavailable/abort 503.
- [x] Синтетические adversarial tests: in-SQL revision drift,
  post-first-COMMIT drift, change before final Allow, forged revision,
  malformed/missing storage, fail-closed и safe connection reuse.
- [ ] **VERIFIED** на новом SHA только после GitHub Actions. Уже
  завершённые CI 2G.4c не являются проверкой нового кода.
- [ ] **SPEC:** authoritative transactional revision writes/reader backed
  by ephemeral PG, grant invalidation across affected tenants,
  multiple backend instances and concurrent writer tests.
- [ ] **PROPOSED:** explicit revocation linearization point/response
  policy; the post-final-check race remains unsolved.

No 004 migration yet: no authoritative write path is present to enforce
atomic revision increments. See
[AUTHORIZATION_REVISION_CONTRACT_V1.ru.md](AUTHORIZATION_REVISION_CONTRACT_V1.ru.md).


## Этап 2G.4d.2 — server-owned epoch в одноразовой PostgreSQL 16

- [x] Staging-only `004` private BIGINT epoch c tenant tombstone и
  инкрементом в **той же транзакции**, что изменение status,
  membership/role, Pool/Account/Egress grant или resource catalog.
- [x] Фиксированный signed SQL `authorized_revision` с no-access для
  reader к private таблицам, строгой проверкой current actor/role и
  tenant/collection scope.
- [x] Добавлены SQL acceptance и отдельные concurrent `psql` writer /
  read tests: rollback atomicity, shared-resource fan-out, отсутствие
  lost bump, изоляция North/Orbit.
- [x] **VERIFIED** synthetic baseline + disposable PG16 на кодовом SHA
  `6ea4546a6953d10baa42f7dcdc6ec5495f9f9517`:
  [CI #38284819714](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819714)
  (1 777 tests PASS, 0 fail, lint/TS/Vite),
  [PG16 #38284819774](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819774)
  (signed epoch, rollback, concurrent writer lock/no lost bump),
  [Demo #38284819723](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819723),
  [Browser #38284819716](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819716).
  Это не verification production revocation linearizability.
- [x] Staging-only signed PostgreSQL revision adapter реализован и
  VERIFIED в следующем этапе 2G.4d.3.
- [ ] **SPEC:** production native driver physical discard,
  expiry-time invalidation, policy coverage и multi-instance
  transaction/crash/deadlock QA.
- [ ] **PROPOSED:** linearizable response/revocation completion barrier.

См. [TRANSACTIONAL_AUTHORIZATION_REVISIONS_V1.ru.md](TRANSACTIONAL_AUTHORIZATION_REVISIONS_V1.ru.md).


## Этап 2G.4d.3 — signed PG revision source для trusted SQL

- [x] Типизированный server-only revision port расширен до trusted
  actor/tenant/**role**/correlation/collection. User JWT/request
  revision/role не используются для issuance.
- [x] Тот же signed SQL executor теперь выполняет fixed
  `authorized_revision` с HMAC-txid, двойным DB gate,
  timeout/cancellation и pool quarantine.
- [x] Отдельный `createSignedPgAuthorizationRevisionSource` внедрён в
  isolated E2E non-superuser driver. Unit tests для malformed/NULL/
  cross-tenant SQL, SQL failure, cancel и clean ROLLBACK.
- [x] Реальный ephemeral PG16 E2E проверяет изменения grant, tenant,
  membership после второго metadata COMMIT перед final Allow; старые
  LIMITed rows не выдаются.
- [x] **VERIFIED** на SHA `94f8d7a14c24573ff5397fbe1349e0d89fa7c91f`: [Main CI #38286207826](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38286207826)
  (1 785 unit tests PASS, 0 fail, lint/tsc/Vite), [PostgreSQL #38286208002](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38286208002)
  (реальный non-superuser SQL и после второго metadata COMMIT
  tenant/member/Account grant revocation), [Demo #38286208055](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38286208055), [Chromium #38286207825](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38286207825)
  — 4/4 SUCCESS.
- [ ] **SPEC:** production multi-instance driver/credential lifecycle,
  link/routing/expiry revision coverage, actor persistence, transactional
  session revocation and correctness across concurrent HTTP delivery.
- [ ] **PROPOSED:** формально упорядоченный revocation/response barrier.

Подробнее: [SIGNED_REVISION_READER_V1.ru.md](SIGNED_REVISION_READER_V1.ru.md).

## Этап 2G.4d.4a — metadata + links revision coverage

- [x] `005` (ephemeral-only) добавляет триггеры epoch для projects,
  applications, key_bindings, routing_bindings, resource_links.
- [x] Shared resource link invalidates всех затронутых владельцев и
  grantee tenants, в том числе независимо выданных Pool/Account.
- [x] SQL adversarial tests: no-op UPDATE, UPDATE/INSERT/DELETE, tenant
  fan-out, rollback atomicity и cross-tenant signed scope.
- [x] **VERIFIED** на `9458db06a86cb0d355937292ce135a89f1926f96` ([PG16 #38287715026](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38287715026), Main CI, Demo, Browser — 4/4 SUCCESS).
- [x] Time-only expiry закрыт следующим отдельным staging-этапом 2G.4d.4b;
  это не production clock authority.
- [ ] **SPEC:** multi-instance/crash/deadlock, deadlock/crash
  retry tests, multi-instance correctness.
- [ ] **PROPOSED:** atomic read/revoke/response completion barrier.

См. [AUTHORIZATION_REVISION_COVERAGE_V1.ru.md](AUTHORIZATION_REVISION_COVERAGE_V1.ru.md).

## Этап 2G.4d.4b — grant expiry без write-event

- [x] Private signed `authorized_revision_state` возвращает epoch и
  раннюю будущую границу expiration, не раскрывая grants.
- [x] Trusted TS boundary валидирует и сравнивает оба значения,
  проверяет серверные часы перед Allow; expiry → generic 404,
  malformed SQL → generic 503/quarantine.
- [x] Synthetic + real ephemeral PostgreSQL E2E: expiration по времени
  при одинаковых LIMITed metadata rows и неизменном raw tenant epoch.
- [x] **VERIFIED** на `f0a35b8433e057fae466974e744f48523243ef62` ([PG16 #38288157880](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288157880), Main CI 1 792 tests PASS,
  Demo и Browser — 4/4 SUCCESS).
- [ ] **SPEC/PROPOSED:** revocation/response linearization,
  clock-skew/multi-instance policies и production driver.

## Этап 2G.4d.4c — deterministic read/revoke ordering pilot

- [x] `007` signed `FOR SHARE` lock на tenant epoch с DB recheck
  после получения lock, без доступа reader к private таблицам.
- [x] Real independent psql sessions: writer revoke COMMIT ждёт
  release read-publication transaction, третий observer не видит
  незафиксированное изменение и North/Orbit изолированы.
- [x] SQL denial tests: unsigned, cross-tenant, role mismatch,
  paused tenant, audit-only forbidden collection.
- [x] **VERIFIED** на `9696e280cfee9c6ecd8475fd48afd10113632060` ([PG16 #38288803851](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288803851), Main CI 1 792 tests PASS,
  Demo и Chromium — 4/4 SUCCESS); доказана задержка revoke COMMIT
  и recovery после termination reader backend, но не HTTP delivery.
- [ ] **SPEC:** управляемый bounded publication/transport lifecycle,
  cancellation/crash recovery, persistence and multi-instance tests.
- [ ] **PROPOSED:** production decision that defines the HTTP
  revocation completion point, backpressure and acceptable in-flight reads.

## Выполнение полного SaaS Blueprint (Definition of Done)

- [ ] Реальный server-side identity/session/OIDC, safe token replay/rotation,
  account directory и issuer/JWK management.
- [ ] Формальный revocation completion API + bounded publication lifecycle,
  транспортные cancel/crash/backpressure tests и доказанный порядок ответа.
- [ ] Production SQL connection eviction, multi-instance transactions,
  retry/deadlock tests, backup/recovery/migration rollback.
- [ ] Durable redacted/tamper-evident audit и retention.
- [ ] Tenant-scoped management APIs, vault, BYOK/BYOA approved flows,
  proper CPA/Gateway isolation and client-side backend authorization.
- [ ] Network egress firewall/SSRF/DNS/IPv6/proxy/VPN enforcement;
  per-request trace, usage and billing correctness.
- [ ] Consent/approval for separately scoped production rollout, canary,
  operational SLOs/monitoring and security acceptance.

Текущие стадии 2G.4d.4a/b/c verified только в disposable CI;
это НЕ green light для release. См.
[PRODUCTION_READINESS_GATES_V1.ru.md](PRODUCTION_READINESS_GATES_V1.ru.md).

## Этап 2G.4d.5a — bounded publication callback

- [x] Signed server-only PostgreSQL publication primitive shares HMAC,
  txid, DB gates, SQL quarantine and deadline with metadata path.
- [x] `FOR SHARE` plus server-owned epoch/expiry comparison before
  prepare, second DB gate and expiry check before sync local handoff.
- [x] Synthetic adversarial tests for replay, foreign tenant, unsafe
  SQL, clock expiry, cancellation, hung prepare and malformed results.
- [x] Real PG16 E2E: writer revoke waits for local handoff, stale
  epoch cannot republish and neighboring tenant remains isolated.
- [x] VERIFIED: `02f5db4dddeabddf099ae9d98d49c13421d759a8` —
  [main CI #38290101997](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38290101997)
  (1 802 PASS, 0 FAIL), [PG16 #38290101971](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38290101971),
  [Demo #38290101951](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38290101951),
  [Browser #38290101996](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38290101996).
- [ ] **SPEC**: verified actor/session identity and durable audit must be
  tied to the same high-level publication flow, not separately replayed.
- [ ] **SPEC**: a real bounded HTTP transport/cancel/crash contract and
  independently proven DB per-connection destruction/reuse correctness.
- [ ] **PROPOSED**: production completion semantics and release approvals.

См. [BOUNDED_PUBLICATION_HANDOFF_V1.ru.md](BOUNDED_PUBLICATION_HANDOFF_V1.ru.md).

## Этап 2G.4d.5b — единый staging trusted publication entrypoint

- [x] Новый `createTrustedSqlPublishedBoundary` принимает только
  client token/tenant/collection/limit/signal, сам выводит trusted
  actor/RBAC/signed baseline и не отдаёт SQL rows в receipt.
- [x] Последовательная JWT/actor/session revalidation внутри
  PostgreSQL `FOR SHARE` lease до и после private stage.
- [x] Синхронный обязательный audit gate под DB lock перед локальным
  `commit()`: отказ аудита или SQL не публикует bytes.
- [x] Synthetic tests (в том числе forged tenant/role, пропажа
  directory и membership во время stage, audit failure, cancellation).
- [x] Actual PG16 E2E from synthetic JWT through non-superuser
  signed revocation check to receipt-only handoff.
- [x] **VERIFIED** SHA `71688ebe6d17a0139a2363609f807ce49640e8be`:
  [CI #38291187218](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38291187218)
  1 809 PASS, 0 FAIL; [PG16 #38291187422](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38291187422),
  Demo, Chromium — 4/4 SUCCESS.
- [ ] **SPEC:** actor/session revocation must be transactionally
  invalidated within PostgreSQL epoch; durable audit outbox.
- [ ] **SPEC:** transport adapter with proven nonthrowing bounded
  publication, crash/retry/backpressure and per-socket discard semantics.
- [ ] **PROPOSED:** public SaaS control API and production approvals.

См. [TRUSTED_PUBLICATION_LIFECYCLE_V1.ru.md](TRUSTED_PUBLICATION_LIFECYCLE_V1.ru.md).

## 2G.4d.6a — авторитетный actor-wide session gate

- [x] Guarded PG16 migration 008: private actor session active/revoked
  state, signed membership gate и tenant epoch fanout trigger.
- [x] SQL тесты revocation, rollback, affected tenants и отсутствие
  private SELECT/UPDATE для saas_ci_runner.
- [x] Real PG16 after-second-COMMIT actor session kill-switch E2E.
- [x] **VERIFIED** SHA `2df528fa665a4702003fbf834e75e25e815e1025`:
  [PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787), [CI #38292965756](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965756), Demo, Chromium — 4/4 SUCCESS.
- [ ] **SPEC:** subject/token-scoped signed session identity, OIDC
  discovery/JWK rotation, persisted session/logout/replay controls.
- [ ] **SPEC:** durable audit/outbox under signed PG publication lease.

## 2G.4d.6b — signed audit outbox при локальной публикации

- [x] Migration 009: private append-only outbox и SECURITY DEFINER
  signed-authorized record function (no direct read/write reader grants).
- [x] PostgreSQL SQL tests: forged tenant, wrong role, revoked actor,
  duplicate correlation, atomic ROLLBACK and persistent COMMIT record.
- [x] TypeScript opt-in signed outbox write inside the publication
  lease, after last DB gate, before synchronous audit/local handoff.
- [x] Real non-superuser PG16 E2E: receipt-only publish creates exactly
  one persisted minimal private event, foreign tenant creates none.
- [x] **VERIFIED** on SHA `2df528fa665a4702003fbf834e75e25e815e1025`:
  [PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787), [CI #38292965756](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965756) (1 815 PASS), Demo and Chromium — 4/4 SUCCESS.
- [ ] **SPEC:** tamper-evident durable audit replication/retention,
  guarantee for callback failure/commit uncertainty and real HTTP.

## 2G.4d.6 final verified checkpoint (raw RLS + actor logout + outbox)

- [x] **VERIFIED** final code SHA `bd96d7a038378fa30524914362013ebf06fd420f` — [Main CI #38293380784](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380784),
  [PG16 #38293380854](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380854), [Demo #38293380672](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380672), [Chromium #38293380657](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380657): 4/4 SUCCESS.
- [x] Даже raw signed `saas_rls.projects` RLS SELECT после
  actor-wide revoke не видит строк; `scope_tenant()` возвращает NULL,
  `read_allowed()` — FALSE.
- [x] Independent PG processes: actor logout COMMIT ждёт завершения
  signed `FOR SHARE` publisher, после чего старый actor denied.
- [x] Minimal signed allow audit outbox durable after COMMIT; no
  direct SELECT/INSERT/DELETE для `saas_ci_runner`, rollback атомарен.
- [ ] **SPEC:** per-token/session identifier signed with actor/tenant/txid
  and integrated with a production issuer/subject directory.
- [ ] **SPEC:** tamper-evident external durable audit, atomic HTTP
  delivery state, crash/backpressure recovery and physical driver discard.
- [ ] **PROPOSED:** real SaaS endpoints, Vault/BYOK, CPA/Gateway,
  egress enforcement, billing and release/security approvals.

## 2G.4d.7a — verified token fingerprint authorization

- [x] Verified JWT bearer SHA-256 bound to 5-field HMAC and scoped
  signed SQL transaction; no client-supplied jti/session/actor/role.
- [x] Private PG16 token registry, token/actor check, clock expiry,
  tenant epoch invalidation on per-token write.
- [x] Permanent tombstone blocks downgrade after deleting tokens or
  recycling actor ID; legacy scope for never-enrolled fixture only.
- [x] PG16 signed A revoke / B continues / raw RLS deny / expiry /
  rollback; independent reader/writer/observer COMMIT ordering.
- [x] **VERIFIED** code SHA `772a29be5b855f31e65e28b30144adddbe776bb1`
  — [Main 1 822 PASS](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991853),
  [PG16](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991811),
  Demo, Chromium — 4/4 SUCCESS.
- [ ] **SPEC:** OIDC-backed session enrollment/revocation API with
  durable issuer/subject directory and mandatory strict rollout.
- [ ] **SPEC:** monotonic migration execution, multi-process failover,
  physical connection discard, token-specific audit correlation.
- [ ] **SPEC/PROPOSED:** crash-safe bounded HTTP/outbox delivery,
  tamper-evident audit, Vault, CPA/Gateway, egress and billing.

## 2G.4d.7b — issuer/subject anchored session lifecycle

- [x] Guarded migration 011: immutable issuer+subject/actor directory,
  permanent issuer-bound tombstone, isolated NOLOGIN bootstrap/provisioner
  function capabilities and signed RLS subject-status revalidation.
- [x] Server-only verified RS256 bearer provisioning port uses verified
  token expiry, exact signed JWT SHA-256, double-checks actor directory,
  never trusts `jti`/actor/role claims or logs bearer.
- [x] SQL + real PG16 non-superuser E2E: A revoke, B continues; then
  subject revoke denies B with token row still individually active;
  immutable identity/ACLs, rollback and no forged audit Allow.
- [x] Multi-process PG16 signed read/publication FOR SHARE vs
  issuer-subject revoke COMMIT; unchanged epoch until earlier COMMIT.
- [x] **VERIFIED** code SHA `cade8751232b8deff40143c1ed31a8ac800194a1`: [Main CI #38300085289](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085289) (1 829 PASS),
  [PostgreSQL16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282), [Demo #38300085311](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085311), [Chromium #38300085300](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085300) — 4/4 SUCCESS.
- [ ] **SPEC:** issuer-controlled production enrollment/logout/rotation,
  secure provisioning credentials, session ownership across instances.
- [ ] **SPEC:** production monotonic migration registry and tested
  failover/rollback; never replay 010 after 011.
- [ ] **SPEC:** token/subject-specific tamper-evident audit/outbox
  reconciliation and reliable HTTP acknowledgement delivery.
- [ ] **PROPOSED:** Vault/CPA/Gateway, enforced network egress,
  billing and production security/release approval.

## 2G.4d.7c — fenced recovery of committed LOCAL audit (ephemeral only)

- [x] Migration 012: private one-row-per-committed-event reconciliation
  state, append-only attempts history, least-privileged NOLOGIN role.
- [x] Bounded `FOR UPDATE SKIP LOCKED` claim, lease expiry reclaim,
  monotonic generation and random UUID fencing to deny stale ACKs.
- [x] Atomic `reconciled_local` commit, terminal idempotence,
  cancellation/ROLLBACK and migration replay preservation.
- [x] Physical PG worker crash before claim COMMIT and retry after
  committed lease expiry, with second concurrent worker.
- [x] Real non-superuser signed Bun.SQL publication E2E confirms
  committed event can be observed without SQL rows or lease in receipt.
- [x] **VERIFIED** code SHA `1aeeb218a68ca7f0c8094d51551802205b60f224`: [Main #38302392363](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392363)
  (1 829 PASS), [PG16 #38302392290](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392290), [Demo #38302392314](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392314), [Chromium #38302392437](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392437), 4/4 SUCCESS.
- [ ] **SPEC:** external HTTP transport/client ACK protocol, idempotent
  remote delivery, safe recovery when local handoff happened but
  PostgreSQL COMMIT failed, dead letters and backpressure.
- [ ] **SPEC:** tamper-evident replicated audit, worker credentials,
  retention/SLO, physical driver discard, multi-instance failover and
  monotonic production migration system.
- [ ] **PROPOSED:** real OIDC/Vault/CPA/Gateway/egress/billing/public API
  and independently approved production release.

## 2G.4d.7d — durable synthetic intent / mock ACK (staging only)

- [x] Guarded migration 013 creates immutable intent with UUID
  idempotency key in SAME transaction as signed audit Allow;
  rollback removes both, replay preserves historic/terminal state.
- [x] No mock dispatch until separate `reconciled_local` observation
  commits; worker has NOLOGIN EXECUTE-only private capabilities.
- [x] 1–16 bounded claims, 1–30s lease, `SKIP LOCKED`, immutable key,
  generation/UUID fences, ACK rollback and terminal `mock_acked`.
- [x] Three attempts then `retry_exhausted` with no false ACK.
- [x] Independent physical PostgreSQL workers: forced backend crash
  before claim COMMIT rolls back; after committed lease expiry
  replay retains immutable key and denies stale acknowledgements.
- [x] Real trusted Bun.SQL staging publication → COMMIT → local
  observation → synthetic in-memory receiver: lost ACK, same key,
  one receiver effect, no secrets/rows in public receipt.
- [x] **VERIFIED** code SHA `6b0bf3189c544cce21ccdfbaf58b7b2f72ba3214`: [Main CI #38304607776](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607776) (1 829 PASS/0 FAIL),
  [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719), [Demo #38304607709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607709), [Chromium #38304607769](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607769); 4/4 SUCCESS.
- [ ] **SPEC:** real HTTP/client transport ACK, persisted per-recipient
  idempotency, payload protection, crash-safe COMMIT/delivery protocol,
  real remote retry/dead letters/backpressure and worker identity.
- [ ] **SPEC:** tamper-evident external audit, physical driver discard,
  multi-process durable failover/monitoring, monotonic migration runner.
- [ ] **PROPOSED:** production OIDC/Vault/CPA/Gateway/network egress,
  billing/public API and separately approved production release.

- [x] **Negative E2E verified**: synthetic local effect before signed
  PostgreSQL ROLLBACK persists while 009 audit/013 intent disappear.
  This proves the old synchronous handoff gap remains OPEN;
  [PG16 #38305618718](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38305618718).

- [x] **2G.4d.7d durable synthetic receiver (014), VERIFIED PG16**:
  receiver-local atomic effect/receipt, retry deduplication after process
  restart, guarded NOLOGIN API, sender receipt/fence ACK and migration replay;
  [PG16 #38307286153](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38307286153) on `a8eabe5`.
- [ ] **STILL SPEC/PROPOSED:** external receiver authorization,
  durable remote payload, real transport/ACK, pre-COMMIT handoff fix,
  unknown-outcome operations and production release gate.

## 2G.4d.7e — Synthetic committed-intent-only boundary

- [x] **IMPLEMENTED:** отдельный staging-only server entrypoint,
  zero pre-COMMIT synthetic handoff, committed 009 audit/013 intent,
  downstream 012/013/014 worker.
- [x] **TEST CODE:** реальные PG16 injected pre-COMMIT ROLLBACK
  и потеря COMMIT reply после успешного PostgreSQL COMMIT;
  независимое восстановление committed intent.
- [ ] **SPEC:** durable producer operation ID for unknown outcome,
  request retry dedup, payload queue, revocation-at-dispatch.
- [ ] **PROPOSED:** externally authenticated transport/ACK,
  production control plane/release.

**VERIFIED on code commit `fa895296a6ce4062687d0ad0af77f26114d4ef03`:** [PG16 #38309259713](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259713), [Main CI #38309259929](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259929), [Demo #38309259856](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259856), [Chromium #38309259696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259696) — all 4 SUCCESS. The final documentation commit requires its own independent Actions results; code verification does not imply production readiness.


## 2G.4d.7f — producer idempotency after unknown COMMIT

- [x] **IMPLEMENTED:** guarded PG16 015 immutable operation UUID
  mapping signed outbox+intent; tenant/actor/role/collection/limit
  binding; the isolated staging event-only port opts in
- [x] **TEST ADDED:** SQL rollback/replay/IDOR/conflict, physical
  advisory-lock contention, Bun committed-response-loss retry
- [ ] **SPEC:** public producer operation ID issuance, durable
  authenticated client retry/status protocol, payload canonical
  digest and operation retention, abuse budgets
- [ ] **PROPOSED:** external delivery ACK and production deployment

**CODE VERIFIED** on SHA `ca2503f2e22d30e64c32490c6f46bb7dd73b6dc1`:
[Main CI #38351833547](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833547),
[PostgreSQL16 #38351833550](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833550),
[Demo #38351833546](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833546),
[Chromium #38351833571](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833571) — **4/4 SUCCESS**.
The documentation commit must be checked independently on its own SHA.


## 2G.4d.7g — server-issued operation and signed recovery

- [x] **IMPLEMENTED (staging-only):** guarded 016 signed UUID issuance;
  immutable issue/actor/tenant/role/collection/limit binding;
  issued/committed/expired signed status-only recovery; no pre-COMMIT
  receiver callback or audit+intent during issuance
- [x] **TESTED BY CI:** real PG16 status/TTL, delayed/duplicate replay,
  rolled-back reserved commit, unknown successful COMMIT, strict IDOR,
  private ACL, tombstone/migration replay; legacy 015 concurrency retained
- [ ] **SPEC:** authenticated public issue/status API, client UUID
  persistence and retries, quotas, safe tombstone archiving/retention,
  payload hash/durability, external delivery semantics
- [ ] **PROPOSED:** transport, external attested ACK and release approvals

**CODE VERIFIED on `0d9214b8b41deb1ab97a43f71bb76bdf9d661a7d`:**
[Main CI #38354372696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372696),
[ephemeral PostgreSQL16 #38354372709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372709),
[Demo #38354372683](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372683),
[Chromium #38354372700](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372700) — **4/4 SUCCESS**.
The final documentation SHA requires its own independent CI; this does not authorize production delivery.


## 2G.4d.7h — permanent tombstones and scoped anti-abuse budgets

- [x] **IMPLEMENTED in 017**: no tombstone GC/reuse; immutable 016
  entries with actor/tenant lifetime caps 12/48 and signed issuer
  short-window ceilings 4/16 IDs per 5 minutes
- [x] **IMPLEMENTED**: signed metered status 16/64 lookups per minute;
  status unknown/foreign probes persist counters on 404 after COMMIT;
  bounded counter rows reset in place, not per-attempt logs
- [x] **VERIFIED by ephemeral PG16/Bun**: tenant/actor separation,
  denial parity, immutable tombstones, migration replay and
  physical session race for last status slot
- [ ] **SPEC**: safe archival/non-reuse proof, capacity relief once
  lifetime caps reached, global edge rate limits, per-plan policy,
  secure retention and user-facing exhaustion handling
- [ ] **PROPOSED**: public producer API and actual remote delivery


**CODE VERIFIED on SHA `64d93a034face985d07aa990085d56678e441715`:**
[Main CI #38356159803](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159803),
[PostgreSQL16 #38356159812](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159812),
[Demo #38356159923](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159923),
[Chromium #38356159948](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159948)
all SUCCESS. The final documentation commit requires independent Actions on its own SHA.


## Stage 2G.4d.7i — SQL-backed retention floor, no archive

- [x] **IMPLEMENTED:** 018 BEFORE INSERT common per-tenant
  advisory-lock lifetime capacity checks for issued 016 UUIDs
  and 015 producer-event identities; separate raw-insert budgets
- [x] **IMPLEMENTED:** private capacity snapshot `gc_permitted=false`;
  BEFORE TRUNCATE denial; private core functions and metered
  legacy 016 issued/read facades (8/32 issues per 5min, 16/64
  status per minute)
- [x] **TEST ADDED:** no event on quota-induced SQL ROLLBACK,
  exact replay under exhausted new-insert limit, legacy
  status debit, cap refusal, protected TRUNCATE, 018-last replay
- [ ] **SPEC:** verifiable remote non-reuse record, atomic safe archive
  cutover, authenticated external witness and DDL-privileged
  tamper-evidence, restored capacity/plan economics
- [ ] **SPEC:** legacy direct SQL caller-controlled ROLLBACK rate
  bypass; 009 callback/request bursts, global edge policy,
  public HTTP and real payload/delivery/ACK


## Stage 2G.4d.7j — detached witness / restore rejection

- [x] **IMPLEMENTED CI-only:** two-process offline Ed25519
  canonical UUID commitment witness, sequence/previous signed chain,
  external-to-PostgreSQL pinned checkpoint digest during one job
- [x] **TESTED:** actual PG16 uncommitted invisibility, separate
  committed INSERT, killed backend ROLLBACK, simulated restored
  older projection rejection, signed-head replay, fork, tampered
  manifest/signature, wrong key, torn bundle
- [x] **SAFE DEFAULT:** no GC/archive/copy/export, no UUID reuse,
  existing SQL 015–018 unchanged, `gcPermitted=false` invariant
- [ ] **SPEC:** independently controlled persistent signing key and
  trust head across hosts, atomic external witness protocol,
  real PITR/backup restore and failover, non-reuse after compacted
  archives, key rotation, legal retention and capacity relief
- [ ] **PROPOSED:** production deployment/security release approval

**CODE VERIFIED on `66019cd7602d256148562eafd304e9712a2d907b`:** [Main CI #38363925445](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925445), [ephemeral PostgreSQL16 #38363925442](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925442), [Demo #38363925450](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925450), [Chromium #38363925440](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925440) all SUCCESS. Final docs SHA needs its own Actions. No production release claim.


## Stage 2G.4d.7k — persisted local trust head + actual PG restore

- [x] **IMPLEMENTED CI only:** signed checkpoint sequence/history,
  fsync+rename head and separate pinned anchor, full chain checks
  across fresh offline OS verifier processes
- [x] **VERIFIED:** actual `pg_dump` old/current full backups,
  separate real `pg_restore` scratch databases, old restored
  signed UUID missing → DENY, current exact restored set → PASS
- [x] **VERIFIED:** new PostgreSQL COMMIT without signed
  successor → DENY; witness SIGKILL before atomic rename →
  fail closed; stale head/torn anchor → DENY
- [x] **NOT PERMITTED:** no tombstone deletion, GC, archive move,
  UUID reuse, cap reset, production or merge
- [ ] **SPEC:** independently durable, rollback-resistant external
  pinned root across hosts/runners; atomic PG-commit/witness
  settlement, true WAL/PITR and failover, key rotation and
  cross-instance non-reuse enforcement on every issuance

**CODE VERIFIED at `9af3b8d5b29ebceb6a433468c650f01be913a148`:** [Main CI #38367994239](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994239), [ephemeral PG16 #38367994247](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994247), [Demo #38367994191](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994191), [Chromium #38367994196](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994196) — **4/4 SUCCESS**. The final documentation HEAD must pass its own CI; no archive/GC/deployment authorization.


## Stage 2G.4d.7l — offline head quorum and commit-gap fail-closed

- [x] **IMPLEMENTED (disposable CI only):** two separate signed
  head histories, two offline verification processes and independent
  *local* fsynced append-only-convention high-water journal;
  all three must agree on latest signed sequence and UUID set
- [x] **TESTED:** real PG16 COMMIT-to-witness gap DENY; one
  replica advanced DENY; both advanced without journal DENY;
  complete seq2/seq3 PASS; double replica rollback, lost/torn
  journal, SIGKILL before journal lock release all DENY
- [x] **Explicit negative acceptance:** rewind both replicas
  AND local journal plus matching old projection may PASS;
  this shows why there is no external rollback-resistant root
- [ ] **SPEC:** independently administered durable append-only
  high-water, key custody, external monotonic anti-rollback,
  atomic/fenced producer COMMIT+witness settlement, authenticated
  live DB projection and real PITR/failover
- [ ] **NOT ALLOWED:** tombstone GC/deletion/reuse, capacity reclaim,
  production deployment, public issue/status or external sender


## Stage 2G.4d.7m — unknown PG COMMIT / offline witness reconciliation

- [x] **IMPLEMENTED CI-only:** strict offline proof gate binding
  expected hashed operation to a previously signed baseline and
  exactly one later UUID, plus direct successor and 7l high-water
- [x] **TEST ADDED:** actual PG backend kill before COMMIT gives
  ROLLBACK/UNKNOWN and DENY; kill after COMMIT gives committed
  UUID but still DENY until both signed heads and journal publish
- [x] **ADVERSARIAL:** wrong candidate/hash/registry, unexpected
  extra UUID, stale projection, forged baseline and partial
  witness publication DENY; 009/013 untouched and GC=false
- [ ] **SPEC:** actual independently durable off-host witness and
  authenticated cross-host trust root, competing writer fencing,
  atomic PG→external settlement, verified live issuer rules
- [ ] **SPEC:** real partitions/WAL/PITR, full production recovery,
  durable operation payload/ACK, safe archive/non-reuse and GC


## Stage 2G.4d.7n — witness process and idempotent IPC ACK recovery

- [x] **IMPLEMENTED CI-only:** separate long-lived Unix-socket
  Ed25519 signer, signed request-id receipt, per-checkpoint
  exclusive/fsynced append and atomically published head
- [x] **TESTED:** real PG COMMIT while signer is offline DENY;
  signer restart/pinned public key; lost ACK after durable head
  resumes exact same signed receipt by idempotent request ID
- [x] **ADVERSARIAL:** stale/forked head, changed request payload,
  zero-delta append, concurrent writers racing one head,
  crash before head publication leaves orphan and startup DENY
- [ ] **SPEC:** independent durable off-host signer/trust
  domain, authenticated DB projection, real network partition,
  tenant/actor binding, atomic/fenced COMMIT-to-witness settlement,
  PITR/failover/keeper recovery and safe production operation
- [ ] **NOT AUTHORIZED:** tombstone deletion/reuse, GC, capacity
  reset, public producer endpoints and production deployment


## Stage 2G.4d.7o — least-privilege source-backed witness proof

- [x] **CI-only implemented:** dedicated PostgreSQL role with
  column SELECT on issued/producer `operation_id` only,
  one REPEATABLE READ READ ONLY transaction, a separate
  ephemeral Ed25519 projector signature binding nonce,
  fixed source database and signed witness predecessor
- [x] **ADVERSARIAL:** real post-COMMIT UUID changes accepted
  only with fresh attestation and direct signed successor;
  forged client array, wrong key, replayed challenge,
  stale pinned head and revoked SELECT all DENY
- [x] **NON-DESTRUCTIVE:** zero new 009/013 audit/intent from
  witness, previous SQL 015–018 unchanged, GC always false
- [ ] **SPEC:** actual attestor and witness split across host,
  independent durable replay-resistant nonce/head state,
  authenticated database identity and issuer grant for
  real paths; strict proof enforcement on every IPC append
- [ ] **SPEC:** fenced PG COMMIT→external witness atomic
  settlement, WAL/PITR/failover, partition resilience,
  remote delivery ACK, safe archive/non-reuse/GC approval


## Stage 2G.4d.7p — source-attested IPC witness append

- [x] **IMPLEMENTED staging only:** pinned Ed25519 projector trust root,
  daemon-owned challenge nonce, `append-pg` verification prior to
  witness signature; opt-in mode refuses client-only `append`
- [x] **TEST COVERAGE:** real PG16 read-only projection after COMMIT,
  modified proof/request ID/replayed challenge/stale head DENY,
  concurrent publishers, ACK-loss idempotent restart, unavailable
  projector, revoked SELECT and tampered disk evidence DENY
- [x] **CODE VERIFIED:** 4/4 GitHub Actions SUCCESS on \`7bbfc07d\`; final docs HEAD requires separate 4/4 verification
- [ ] **PRODUCTION BLOCKERS:** independent off-host attestor/witness,
  durable anti-rollback trust root and nonces, signed issuer authority,
  fenced/atomic PG settlement, WAL/PITR/failover/partition recovery,
  authenticated delivery ACK, safe retention/GC sign-off
- [ ] **NOT AUTHORIZED:** production API/deployment, UUID reuse,
  tombstone removal, migration 019 or lifetime-cap reset


## Stage 2G.4d.7q — signed local high-water publication gate

- [x] **IMPLEMENTED CI-only:** второй Unix-socket процесс с отдельной
  Ed25519 подписью, pinned mutual public keys, fsynced append-only
  journal и signed status/advance receipts
- [x] **TESTED:** witness ACK только после подтверждённого
  high-water; отдельный PostgreSQL16 projector; lost ACK idempotency,
  witness-only/journal-only rollback, crash before journal advance и
  journal orphan before head publication DENY
- [x] **LIMITATION REPRODUCED:** совместный rollback и потеря external
  pin не детектируются — обе службы работают на одном CI runner
- [ ] **PRODUCTION BLOCKERS:** настоящий off-host durable trusted head,
  source/issuer authorization, атомарный или fenced PostgreSQL COMMIT,
  WAL/PITR/failover/partition recovery, independent key custody,
  remote authenticated ACK, retention/GC/security signoff
- [ ] **NOT PERMITTED:** production release/deployment, merge,
  migration 019, UUID delete/reuse, retention lifetime-cap reset


## Stage 2G.4d.7r — UNKNOWN outcome proof without reissue

- [x] **IMPLEMENTED CI-only:** offline verifier принимает signed
  PG projector attestation, direct witness signed checkpoint,
  signed separate local high-water receipt и untrusted prepared UUID
  **commitment**, но не SQL credentials/raw UUID/actor/tenant/payload
- [x] **ADVERSARIAL:** физическое отключение PostgreSQL backend
  ДО/ПОСЛЕ COMMIT, signed source-only identity, lost IPC ACK и
  signature/head/predecessor/nonce/candidate replay/tamper DENY,
  crash/rollback/multiple COMMIT paths
- [x] **ALWAYS DENY ACTION:** snapshot observation НЕ даёт
  `authorizationGranted`, `retryPermitted`,
  `reissuePermitted`, `deliveryPermitted` и `gcPermitted`
- [ ] **PRODUCTION SPEC:** независимый durable off-host source/witness,
  WAL proof, atomic/fenced COMMIT→witness,
  unknown/out-of-sync journal reconciliation, trusted revocation,
  issuer auth, partition/PITR/failover and remote ACK
- [ ] **NOT ALLOWED:** migration 019, production deployment,
  outbound delivery, UUID deletion/reuse or retention-cap/GC reset

- [x] **CODE VERIFIED:** 4/4 Actions SUCCESS на SHA `602398c8`; финальный documentation SHA проверяется отдельно


## Stage 2G.4d.7s — manual-only signed reviewer pin

- [x] **IMPLEMENTED in disposable CI:** третий, отдельно подписанный
  reviewer head с previous-pin digest, отдельным Ed25519 key и
  `pin`/`inspect` CLI; no SQL credentials, network or production
- [x] **ADVERSARIAL TEST DESIGN:** real PG COMMIT and signed 7r
  evidence, lost ACK, dual-local rollback against preserved pin,
  unsigned local advance, witness/journal split/orphan, forgery,
  key swap, gaps and concurrent exclusive pin writes
- [x] **CI VERIFIED CODE SHA `7f1496fd`:** 4/4 SUCCESS,
  включая реальный PG16, старые 7l–7r и новый 7s reviewer proof
- [x] **EXPECTED FAIL-CLOSED:** все статусы — только ручной
  разбор, не approval: запрет reissue/retry/repair/delivery/GC
- [ ] **PRODUCTION BLOCKER:** оператор/ключ и WORM/trusted pin
  **в независимом trust domain**, signed current PG COMMIT,
  cross-system atomic settlement, PITR/failover/partition,
  issuer actor authorization, durable recipient ACK и
  security/retention/legal review
- [ ] **NOT ALLOWED:** deployment, merge, SQL 019, UUID
  delete/reuse, automatic recovery, quota/retention/GC reset


## Stage 2G.4d.7t — genuine off-host authority contract (SPEC)

- [x] **STAGING CONTRACT:** pinned external authority/logId/epoch,
  challenge-bound signed receipt, direct predecessor, immutable
  synthetic revision, independently supplied minimum and
  witness+journal digest verification
- [x] **ADVERSARIAL CI:** physical PG16 COMMIT/crash/lost ACK plus
  simulated external authority; rollback/replay/fork, key/epoch/
  nonce substitution, local split and gap DENY/manual-only
- [x] **CODE VERIFIED:** 4/4 GitHub Actions SUCCESS on `264df12e`; docs HEAD independently rechecked
- [ ] **REMOTE DEPLOYMENT NOT DONE:** separate operator/service,
  off-runner signing key/HSM, verified WORM monotonic log,
  authenticated append transport, retained off-host minimum,
  equivocation detection and independent drill
- [ ] **PRODUCTION BLOCKED:** atomic/fenced PG COMMIT,
  PITR/failover/partition recovery, issuer authorization,
  durable payload/recipient ACK and security/retention approval
- [ ] **NOT AUTHORIZED:** production issuer, merge/deploy,
  SQL 019, UUID delete/reuse, auto-repair/retry, cap reset/GC


## Stage 2G.4d.7u — operator onboarding / DR evidence quarantine

- [x] **STAGING-ONLY:** signed governance policy и distinct
  `security`/`operations` Ed25519 approvals on exact dossier,
  logId/epoch/nonce/retained minimum; isolated offline verifier
- [x] **ADVERSARIAL:** signed local rollback/split/fork/lag,
  external equivocation, forged journal, key/policy/role swap,
  incomplete quorum, changed request/replay DENY
- [x] **CODE VERIFIED:** 4/4 GitHub Actions SUCCESS on `89c4560e`; 7l–7t and new 7u pass
- [x] **LIMITATION:** exact signed replay is still accepted
  without an independent durable nonce ledger; CI keys co-located
- [ ] **REQUIRED REAL:** independent off-host WORM and operator
  custody, identity+revocation/mTLS, governance of epoch/key rotation,
  production monitoring and independently tested incident runbook
- [ ] **REQUIRED SETTLEMENT:** fenced PG COMMIT/WAL/PITR,
  durable authenticated recipient ACK, actor-scoped issuer auth,
  privacy/security/retention release approval
- [ ] **NOT AUTHORIZED:** deployment/merge, SQL 019, UUID
  issue/retry/reuse/delete, auto-recovery, archive or GC


## Stage 2G.4d.7v — executable mTLS authority transport

- [x] **CI ONLY:** HTTPS/TLS1.3 on `127.0.0.1`, mTLS plus
  pinned client and server SPKI, signed witness/journal direct
  append with separate Ed25519 authority receipt
- [x] **CODE VERIFIED:** 4/4 GitHub Actions SUCCESS on SHA `99461022`; full historical suite and 7v pass
- [x] **FAIL-CLOSED:** fsync before ACK, lost-ACK replay of identical
  receipt, stale expected/fork and nonce rebind DENY; tampered/torn
  journal, substituted key and denied publisher credentials
- [ ] **REAL OFF-HOST:** independent operator, HSM/WORM,
  monotonic counter/nonce ledger, CA rotation/revocation, remote
  client minimum custody, partition/failover/DR and quorum
- [ ] **PRODUCTION SETTLEMENT:** atomic/fenced PG COMMIT+WAL,
  issuer actor auth, recipient ACK, privacy/security/retention
- [ ] **NO RELEASE:** no deploy, merge, 019, UUID reissue/reuse/
  delete, repair, archive, delivery or GC


## Stage 2G.4d.7w — remote Railway staging verified, independent root remains OPEN

- [x] Remote synthetic-only `saas-highwater-staging-only` deployment `885ee1a7`, private 512 MB volume, no public route, no PG/issuer
- [x] `ba8503a5` source, 4/4 GitHub Actions; same-admin isolated sandbox project
- [x] Smoke `d3e4ee3d` `SUCCESS` following human Railway Dashboard 2FA
- [x] Actual private TLS1.3/mTLS pinned SPKI head; client without certificate DENY
- [x] Retained signed high-water revision 1 verified by Node Crypto + WebCrypto against operator-audited public SPKI
- [x] Real 2 competing signed revision-2 publishers: exactly one 200, one 409; signed head equals winning reply
- [ ] **UNTESTED REMOTELY:** identical nonce/lost-ACK recovery, high-water restart/restore, torn record, rollback/partition/failover, external monotonic minimum, cert rotation
- [ ] **INDEPENDENT ROOT:** separate operator/workspace, HSM/KMS/WORM and revocation/governance with anti-rollback
- [ ] **PRODUCTION BLOCKED:** fenced PG COMMIT/WAL/PITR, issuer/actor auth, authenticated recipient ACK, privacy/security/retention; no merge, SQL 019, UUID retry/reissue/repair/GC


## Stage 2G.4d.7w — operator 2FA setup / approval runbook

- [x] Задокументированы официальные Railway Account Security
  TOTP, recovery codes и passkey настройки без раскрытия секретов
- [x] Задокументированы workspace Pro+ `Require 2FA`, interactive
  Dashboard `Staged Changes → Details → Deploy`, 2FA и Windows SSH
- [x] Зафиксированы operator-evidence checks: sandbox-only scope,
  exact diff, deploy SUCCESS + concrete PASS logs; no API 2FA bypass
- [ ] **ACCOUNT/WORKSPACE MFA STATE:** проверяется владельцем вручную,
  нельзя утверждать `enabled` через Railway OAuth connector
- [ ] **NOT TRUST-ROOT:** отдельная workspace/operator, independently
  retained minimum, WORM/HSM and release sign-off остаются OPEN
[Railway 2FA operator runbook](RAILWAY_2FA_OPERATOR_RUNBOOK.ru.md).


## Stage 2G.4d.7x — expiry / retained high-water

- [x] Remote **stateless smoke client ONLY** restarted in same Railway sandbox;
  authenticated signed external head revision 2 under existing pinned root,
  both Node/WebCrypto valid, mTLS unauthenticated client DENY; authority untouched
- [x] Separate GitHub CI guard + read-only synthetic PKI and signed journal audit:
  SHA256 policy/authority pin, exact nonce and predecessor, valid certificate
  chain, 48h expiry warning, retained minimum, torn/tampered-row/rollback-floor DENY
- [ ] **SERVER RESTART** with 512 MB volume — requires **explicit operator
  permission**; don't use redeploy/other mutations to bypass
- [ ] **TEST TLS PKI EXPIRES 2026-10-15 13:33 UTC**: rotate to **separate
  staging logId/keys/volume** after signer/governance review, OR decommission;
  never overwrite old signed marker/journal
- [ ] **REAL EXTERNAL TRUST** independently operated root/WORM/HSM,
  retained minimum, partition/PITR and fenced PG settlement, issuer/ACK;
  production, UUID reissue/retry/GC still BLOCKED
[7x operations and certificate expiry runbook](RAILWAY_HIGHWATER_AUDIT_7X.ru.md).

## Stage 2G.4d.7y — owner-approved remote authority restart

- [x] **OWNER CONSENT:** in-place only `saas-highwater-staging-only`,
  existing 512MB private volume retained; no redeploy or config changes
- [x] **REAL SERVER RESTART:** `2026-10-13T19:42:56Z READY ... head 2`
  after volume mount; startup policy marker and signed chain validated
- [x] **FRESH REMOTE CRYPTO:** new smoke startup `19:43:29Z`
  Ed25519 Node+WebCrypto true on rev2, mTLS pinned SPKI PASS,
  missing-client-cert DENY, no new append
- [x] Both Railway sandbox services Online, 0 staged changes;
  `gcPermitted=false`, Draft PR still OPEN
- [ ] **NOT YET VERIFIED REMOTELY:** actual lost ACK after fsync
  with same nonce retry, SIGKILL during append, torn record, independent
  retained minimum, cross-host restore/partition/failover, WORM/HSM
- [ ] **TEST PKI:** expires 2026-10-15 13:33 UTC; preserve existing
  signed log and plan separate synthetic logId/keys/volume, or retire
- [ ] **PRODUCTION BLOCKED:** independent admin, fenced PG COMMIT/WAL,
  tenant actor issuer, authenticated recipient ACK, security/legal
[Detailed audit and expiry plan](RAILWAY_HIGHWATER_AUDIT_7X.ru.md).


## Stage M0 — safe-to-review merge foundation, not SaaS launch

- [x] Default-off Vite alias and route isolation; ordinary build with
  accidental `VITE_ENABLE_SAAS_BLUEPRINT_DEMO=true` fails CLOSED
- [x] Synthetic PR-preview explicitly gated by GitHub
  `pull_request` + dedicated `SAAS_BLUEPRINT_SYNTHETIC_CI_BUILD`
  flag, no deploy/release; local dev mode remains opt-in
- [x] Automated three-way CI proof: denied unsafe opt-in,
  fixture-free default bundle, accepted isolated synthetic preview
- [ ] Full code-owner + security review of all PR changes
- [ ] Production release pipeline check: no demo env flag/artifact
- [ ] Latest HEAD 4/4 CI and explicit permission to remove Draft/merge
- [ ] M1 live SSO/Control CRUD/PG/Core; M2 runtime tenant/egress;
  M3 independent settlement; M4 ops/security — separate PRs
[M0 merge readiness checklist](MERGE_READINESS_M0.ru.md).


## Stage M1b — signed native PG16 command transaction (STACKED DRAFT / CI-only)

- [x] Новый отдельный M1b branch от HEAD M1a Draft PR №4, без merge M0/M1a.
- [x] Guarded disposable PG16 SQL role, Bun.SQL private write harness, verified synthetic RS256 access token → issuer/subject actor → tenant RBAC → signed transaction HMAC → fixed M1a project functions.
- [x] Скрипт и GitHub Actions SQL E2E test добавлены; фактический результат CI на финальном SHA — проверять отдельно.
- [ ] Подтвердить 4/4 GitHub Actions SUCCESS на окончательном M1b SHA, including SQL16 E2E logs.
- [ ] Durable atomic write-audit outbox / epoch fence / UNKNOWN COMMIT reconciliation without reissue.
- [ ] Independent physical connection discard/timeout/cancel and partition tests, trusted durable sessions, security review before any real API.

Этап не подключён к production, публичному HTTP, Core/Gateway, Railway,
CPA keys и SQL019. [M1b acceptance and limitations](M1B_SIGNED_PG_DRIVER_E2E.ru.md).


## Stage M1c — transactional project audit outbox (STACKED DRAFT / CI-only)

- [x] Изолированная ветка от точного M1b HEAD, SQL 021 с disposable PG16 guard, NOLOGIN audit owner, FORCE RLS, signed scope и trigger-owned audit в той же транзакции.
- [x] В GitHub workflow включены legacy M1a SQL tests, signed native M1b Bun.SQL E2E и новые adversarial audit/rollback/conflict/replay SQL проверки.
- [ ] Подтвердить 4/4 GitHub Actions SUCCESS на итоговом M1c SHA (а не только родительском PR).
- [ ] Durable independent audit/WORM, serialized tenant revocation across post-COMMIT, idempotency and manual UNKNOWN COMMIT settlement — все отдельные задачи.

Без public API, реальных ключей, production PostgreSQL и Railway. SQL 019 запрещена.
[M1c acceptance checklist](M1C_PROJECT_ATOMIC_AUDIT_PG16.ru.md).


## Stage M1d — tenant revocation / project COMMIT fence (STACKED DRAFT / PG16 CI-only)

- [x] Новая отдельная ветка от зафиксированного HEAD M1c Draft PR №6.
- [x] Staging-only SQL022: mandatory M1c project audit + signed existing 007 tenant epoch FOR SHARE; shared lock держится до транзакционного COMMIT и конфликтует с 004/008 revoke/status epoch UPDATE.
- [x] Реальные concurrency fixtures: write-before-revoke, revoke-before-write, tenant-suspend-before-write; RLS и audit fail-closed; out-of-order replay SQL021 запрещён.
- [x] Verified 4/4 GitHub Actions SUCCESS на финальном M1d HEAD `34e2b118` (including PostgreSQL16 race harness / SQL022 replay); это CI, не release approval.
- [ ] Дальше: durable issuer/session fencing, independent audit/WORM, UNKNOWN COMMIT operator-led resolution, physical connection quarantine and security/code-owner review.

Не открывает HTTP/API, production PostgreSQL, Core/CPA/Railway, SQL019 или retry/reissue/GC.
[M1d contract and limitations](M1D_PROJECT_AUTHORIZATION_FENCE_PG16.ru.md).


## Stage M1e — real disconnected PG16 transaction before COMMIT (STACKED DRAFT / CI-only)

- [x] Read-only checked parent Draft PR №7 at HEAD `34e2b118` with 4/4 GitHub Actions SUCCESS.
- [x] Added opt-in M1e hook in unmounted Bun.SQL M1b CI driver and fixed PG16 negative acceptance SQL; no production driver/code changes.
- [x] Actual physical backend termination and AbortSignal after M1c audit mutation but before COMMIT; generic 503, whole CI pool quarantine, PID must disappear, no second reservation/automatic retry.
- [x] Baseline M1b committed lost ACK remains independently assertable as 1 project + 1 audit.
- [x] Verified 4/4 GitHub Actions SUCCESS on M1e HEAD `738e0e19`; real PG16 log confirms physical loss, abort, quarantine and the committed-lost-ACK control.
- [ ] Independent partitioned-connection discard and production pool, durable operator-led UNKNOWN COMMIT settlement, token-bound sessions, third-party WORM — BLOCKED.

Railway sandbox old mTLS service was independently observed redeployed on an inert no-listener start command, its persistent volume retained. This is platform evidence, not an active 8443 network probe. No Railway write in M1e.
[M1e acceptance and limits](M1E_PG_PHYSICAL_DISCONNECT_CI.ru.md).


## Stage M1f — operator-gated read-only UNKNOWN COMMIT local evidence (STACKED DRAFT / CI-only)

- [x] Verified parent M1e Draft PR №8 `738e0e19` has 4/4 GitHub Actions SUCCESS; no parent merge or source mutation.
- [x] New guarded SQL023 (NOLOGIN owner/operator, FORCE RLS SELECT) with READ COMMITTED READ ONLY local project+audit version-chain review.
- [x] Negative SQL acceptance added: missing/in-flight evidence is inconclusive, mismatched actor/operation/version forces STOP; regular M1 roles cannot SELECT or EXECUTE.
- [x] Confirmed 4/4 GitHub Actions SUCCESS on M1f HEAD `ad0cc9f4`, including real PG16 SQL023 acceptance and replay.
- [ ] Immutable per-request operation ID, independent WORM, manual human signoff, real network partition during COMMIT and production-grade physical pool discard remain BLOCKED.

No HTTP/SaaS server integration or OAuth/CPA/keys, no automatic retry,
production/Railway/SQL019 or delivery/GC. [M1f evidence and limits](M1F_UNKNOWN_COMMIT_OPERATOR_LOCAL_EVIDENCE.ru.md).


## Stage M1g — attempt UUID → same-COMMIT signed audit (STACKED DRAFT / disposable PG16)

- [x] Base exact M1f Draft PR №9 `ad0cc9f4` has 4/4 GitHub Actions SUCCESS; no parent merge or deploy.
- [x] New guarded staging SQL024 (NOLOGIN attempt owner, FORCE RLS, immutable UUIDv4 PK → unique M1c/M1d audit event FK); keeps existing M1d signed trigger untouched.
- [x] CI-only Bun wrapper mints per-write UUIDv4 before signed write; tests committed UUID reuse, legacy missing stamp, CAS/disable, lost ACK after real PG COMMIT and NOLOGIN read-only attempt review.
- [x] Verified M1g HEAD `2f96c60` 4/4 GitHub Actions SUCCESS including disposable PG16 SQL024 and adversarial acceptance.
- [ ] Future: independent pre-COMMIT operation intent, cryptographic attempt provenance bound to actor/tenant/version, durable external WORM/human adjudication, network partition during COMMIT — BLOCKED.

No real HTTP/API, Railway change, production PostgreSQL/SQL019, automatic retry/reissue/delivery/GC.
[M1g contract](M1G_ATTEMPT_UUID_BOUND_PROJECT_AUDIT_PG16.ru.md).


## M1h — local fsync + Ed25519 PRE-COMMIT intent (STACKED DRAFT / CI-only)

- [x] Parent M1g PR №10 HEAD `2f96c60`, 4/4 SUCCESS, still Draft/unmerged.
- [x] Separate GitHub disposable Node signer has no SQL credentials; fsync-only local intent and chained Ed25519 proof precede actual M1g signed PG write.
- [x] New adversarial CI harness contrasts lost ACK post-COMMIT 1/1/1 vs physically terminated backend pre-COMMIT 0/0/0, denies signer crash, duplicate intent, tampering, truncated expected high-water and replacement key.
- [x] Verified final M1h HEAD `1f2a172b` Main/PG16/Demo/Chromium 4/4 SUCCESS.
- [ ] Off-host anchored durable high-water, independent WORM/DBA, real network partition DURING COMMIT, manual authenticated recovery, live OIDC and release/merge review are STILL BLOCKED.

CI-local fsync is NOT off-host durability, third-party receipt or a safe retry key.
[M1h review](M1H_PRECOMMIT_SIGNED_INTENT_CI.ru.md).


## M1i — guarded project HTTP write adapter (STACKED DRAFT / CI-only)

- [x] Parent M1h PR №11 HEAD `1f2a172b`, all 4 GitHub Actions SUCCESS; no merge/deploy.
- [x] Add strictly opt-in/unmounted loopback POST/PATCH/DELETE project Request/Response boundary, bounded JSON, exact CAS DTO, CORS/cookie/attempt/role header denial and sealed response.
- [x] CI-only real pinned RS256 access tokens, trusted issuer/subject directory and synthetic private writer; live Bun.serve only on loopback in isolated GitHub check.
- [x] Confirmed 4/4 GitHub Actions SUCCESS on M1i HEAD `7b1d668f`, including explicit synthetic HTTP 7/7 PASS and PG16 regressions.
- [ ] Real OIDC/session issuer, signed PG16 writer through HTTP, independent WORM, tenant/API server deployment, production migrations and failure-tolerant release remain BLOCKED.

Merge only by explicit code-owner/security/operator approval; no production, SQL019, Railway, CPA keys, retry or GC.
[M1i notes](M1I_UNMOUNTED_PROJECT_WRITE_HTTP_CI.ru.md).


## M1j — actual loopback HTTP→signed PG16 with M1h precommit witness (STACKED DRAFT / disposable CI)

- [x] Parent M1i Draft PR №12 HEAD `7b1d668f` has Main/PG16/Demo/Chromium 4/4 SUCCESS.
- [x] Reuse unmounted M1i fixed Request/Response handler, pinned synthetic RS256 trusted directory, M1a actor/tenant checks, signed M1d PostgreSQL16, M1c audit, M1g UUID binding and M1h fsynced precommit Ed25519 signer on one ephemeral runner.
- [x] Real HTTP + PG16 adversarial tests: create/CAS rename/disable, forged bearer/actor/headers denied, revoked current PG membership, COMMIT lost ACK 503 with 1/1/1, physical pre-COMMIT disconnect 503 with 0/0/0, dead witness with 0 reservations; independent SQL acceptance.
- [x] Verified 4/4 SUCCESS on M1j exact HEAD `90d0c72c`, including explicit Bun E2E and independent PG16 SQL `PASS M1j` logs.
- [ ] Off-host independent WORM/high-water, real OIDC/session issuer, production signed PG pool and network partition DURING COMMIT, real deployed API/CPA/tenant provisioning and release review still BLOCKED.

No merge/Ready/deploy/SQL019, Railway signer/journal/volume change or automatic retry.
[M1j verification and limits](M1J_REAL_HTTP_SIGNED_PG16_INTEGRATION_CI.ru.md).


## M1k — synthetic per-session epoch + signed PG16 revoke/COMMIT ordering (STACKED DRAFT / CI-only)

- [x] Verified parent M1j Draft PR №13 HEAD `90d0c72c` has 4/4 GitHub Actions SUCCESS, remains unmerged.
- [x] Guarded SQL025: no-login FORCE-RLS server session UUID/revision and transaction-bound proof, current session SELECT FOR SHARE before M1d tenant epoch fence, mandatory post-audit write trigger, no legacy bypass.
- [x] Server-side pinned RS256 token SHA256 fingerprint bound to UUID/epoch in separate CI process context; multiple sessions one actor, token/session revocation, rotate stale epoch and signed HTTP write-first/revoke-first PostgreSQL lock races.
- [x] Independent SQL025 acceptance: no ghost project/audit, least privileges, distinct session revision in M1c/M1g audit transaction, denied resurrect/delete, idempotent SQL025 replay.
- [x] Verified exact M1k HEAD `288792c5` all 4 GitHub Actions SUCCESS with separate HTTP/Bun.SQL + independent SQL `PASS M1k` acceptance.
- [ ] Production OIDC, true token/session binding, multi-replica revocation, off-host WORM/high-water, network partitions DURING COMMIT, production pool and migration remain BLOCKED.

No live public endpoint, Ready/merge/deploy, SQL019, Railway mutation or retry/GC.
[M1k contract](M1K_SESSION_EPOCH_REVOCATION_PG16_CI.ru.md).


## M1l — synthetic OIDC discovery/JWKS key rotation → signed PG16 session (STACKED DRAFT / CI-only)

- [x] Parent M1k Draft PR №14 HEAD `288792c5` verified 4/4 SUCCESS with adversarial PostgreSQL16 revocation lock ordering.
- [x] Bounded loopback mock OIDC metadata/JWKS parser: pinned HTTPS issuer string, exact metadata/JWKS URI, RSA 2048/4096 RS256 public keys only; monotonic A→A+B→B, retired kid rollback and invalid-refresh quarantine.
- [x] Add a separate opt-in M1l GitHub unit step and post-M1k disposable PG16 invocation: real HTTP JWT → trusted token fingerprint/session UUID → M1h fsync → M1k session lock and mandatory signed M1c/M1d/M1g audit.
- [x] Add race of already-verified HTTP A token vs issuer A retirement and committed DB session A revoke BEFORE PG reservation: 404 and 0/0/0; B remains usable; independent SQL acceptance checks 5 successful PG COMMITs + 1 rolled-back attempt.
- [x] Verified exact M1l HEAD `c141b3a8`, 4/4 SUCCESS with opt-in JWKS tests and dual real PG16 `PASS M1l` plus M1a–M1k regressions.
- [ ] Real OIDC/SSO, refresh-token/session revocation lifecycle, key trust on TLS, distributed IAM, external WORM, production pooling, network partition DURING COMMIT, CPA/tenant onboarding, review/merge/deploy are NOT implemented.

CI mock is not a production login provider or a general JWKS client. [M1l review](M1L_SYNTHETIC_OIDC_JWKS_ROTATION_SESSION_PG16_CI.ru.md).


## M1m — synthetic one-shot OAuth code+PKCE S256 → signed PG16 sessions (STACKED DRAFT / CI-only)

- [x] Parent M1l PR №15 HEAD `c141b3a8` verified 4/4 SUCCESS with real mock OIDC/JWKS and signed PG16 session revocation.
- [x] Explicit CI-only synthetic OAuth client and local issuer: state + S256 PKCE, fixed client ID/redirect/issuer, one-time authorization code, bounded token response; callback/error always consume private state before token exchange.
- [x] Real pinned JWKS RS256 access token issuer+subject → trusted actor → private server-issued PG16 UUID/epoch after successful mock code exchange; no JWT role/sid impersonation.
- [x] Separate post-M1l PG16 acceptance: 3 independently authorized mock logins A/B/C, real HTTP→M1h fsync→M1k session fence/M1c audit/M1g UUID; revoke C in-flight before PG and A afterward, B unaffected; independent SQL checks 3/3/3 and no ghost rows.
- [x] Verified exact M1m HEAD `20637f4b` all 4 GitHub Actions SUCCESS; PKCE 10/10 PASS plus dual independent real PG16 `PASS M1m`.
- [ ] Real IdP HTTPS/PKCE browser callback, token/session refresh/rotation, distributed state, off-host WORM, production pool/DB, network partition DURING COMMIT, CPA/onboarding and codeowner/security approval still BLOCKED.

No public login, merge/Ready/deploy, SQL019, Railway mutation or automated retry/reissue/GC.
[M1m review](M1M_SYNTHETIC_PKCE_AUTH_CODE_SESSION_PG16_CI.ru.md).


## M1n — opt-in pinned HTTPS mock IdP → signed PG16 session (STACKED DRAFT / CI-only)

- [x] Parent M1m Draft PR №16 HEAD `20637f4b` verified 4/4 SUCCESS; OAuth code/state PKCE session proof 3/3/3 and revocation fail-closed.
- [x] Generate isolated one-day CA + valid and invalid leaf certificates only in disposable GitHub runner `/tmp`, no permanent/private secret commit or Railway keys.
- [x] Enforce literal `https://127.0.0.1:<port>`, CA chain, SAN localhost, exact SHA256 SPKI on every HTTPS handshake, reject DNS/SSRF/downgrade/redirect/response oversize/cookie and malicious JWKS metadata.
- [x] Reuse one-shot M1m PKCE S256/state, but send IdP authorization/code/JWKS over verified HTTPS; dedicated negative TLS tests and eighth post-M1m real PG16 invocation with M1h+M1k+M1c/M1g signed audit.
- [ ] Verify all 4 GitHub Actions on exact M1n SHA including 100% opt-in HTTPS unit tests, native E2E `PASS M1n` and independent SQL `PASS M1n` without M1a–M1m regressions.
- [ ] External trusted HTTPS IdP/real consent+callback/PKCE cookie, token refresh/logout, distributed durable session store, independent off-host WORM, during-COMMIT network partitions, release approval, CPA/onboarding remain BLOCKED.

No merge, Ready, deploy, SQL019, Railway signer/volume/cert rotation, live CPA keys or auto retries. [M1n gates](M1N_PINNED_HTTPS_IDP_PKCE_SESSION_PG16_CI.ru.md).

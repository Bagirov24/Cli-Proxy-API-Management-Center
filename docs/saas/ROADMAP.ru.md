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
- [ ] **VERIFIED** после GitHub Actions на точном SHA.
- [ ] **SPEC:** time-only expiry без SQL writer trigger, deadlock/crash
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
- [ ] **VERIFIED** только после точного GitHub CI SHA.
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
- [ ] **VERIFIED** после exact-SHA GitHub Actions.
- [ ] **SPEC:** управляемый bounded publication/transport lifecycle,
  cancellation/crash recovery, persistence and multi-instance tests.
- [ ] **PROPOSED:** production decision that defines the HTTP
  revocation completion point, backpressure and acceptable in-flight reads.

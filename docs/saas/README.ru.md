# SaaS Blueprint B — индекс проектного прототипа (RU)

> **Статус: ПРОЕКТ / НЕ ПОДКЛЮЧЁН К PRODUCTION.** Здесь нет работающей
> многоклиентности, VPN, BYOA или дополнительного механизма доступа.
> Файлы в `src/features/saasBlueprint/` содержат TS-контракты и симулятор
> на синтетических данных. Демонстрационная страница подключается в Router
> **только по явному feature flag**. Core, Gateway, ключи и реальная сеть
> ей недоступны.

## Зачем существует этот каталог

Сохранить архитектуру будущего единого SaaS-продукта так, чтобы её можно было
развивать без повторного исследования требований и случайного изменения
критичного production. Первые функции: **Tenant/Project/Application**, **BYOK/BYOA**
(только одобренные провайдером способы), **Account Pool**, **Egress Profile**,
**явный доступ к общим ресурсам**, **безопасная трассировка**.

## Навигация по документам

| Документ | Что в нём закреплено |
| --- | --- |
| [ARCHITECTURE.ru.md](ARCHITECTURE.ru.md) | Контуры Core/Gateway/SaaS, доменная модель, инварианты и границы доверия |
| [UX_UI.ru.md](UX_UI.ru.md) | Навигация, экраны, понятные статусы, мастера подключения, доступность и ошибки |
| [ROADMAP.ru.md](ROADMAP.ru.md) | Очерёдность разработки, CI-проверки, критерии готовности, откат |
| [DECISIONS.ru.md](DECISIONS.ru.md) | Архитектурные решения, открытые вопросы и реестр будущих задач |
| [CONTROL_API_V1.ru.md](CONTROL_API_V1.ru.md) | Read-only HTTP SPEC, DTO, ошибки и модель происхождения |
| [AUTHZ_RBAC_V1.ru.md](AUTHZ_RBAC_V1.ru.md) | Роли, membership и независимые grants для pool/account/egress |
| [CORE_METADATA_ADAPTER_V1.ru.md](CORE_METADATA_ADAPTER_V1.ru.md) | Интерфейс staging-only read metadata без раскрытия Core Management API |
| [LOCAL_CONTROL_HTTP_V1.ru.md](LOCAL_CONTROL_HTTP_V1.ru.md) | Local-only HTTP слой и проверка короткоживущих синтетических сессий |
| [STAGING_POSTGRES_RLS_V1.ru.md](STAGING_POSTGRES_RLS_V1.ru.md) | PostgreSQL 16 RLS pilot, временная база CI и доказательства изоляции |
| [SIGNED_SCOPE_RLS_V1.ru.md](SIGNED_SCOPE_RLS_V1.ru.md) | Временный HMAC-контекст транзакции и adversarial SQL-тесты |
| [IDENTITY_SQL_BOUNDARY_V1.ru.md](IDENTITY_SQL_BOUNDARY_V1.ru.md) | Этап 2E: закреплённые JWT access-token ключи, SQL read boundary и проверки SQL injection |
| [BUN_SQL_DRIVER_PILOT.ru.md](BUN_SQL_DRIVER_PILOT.ru.md) | Этап 2F: Bun PostgreSQL native SQL на временной базе, конкуренция и повторное использование соединений |
| [TRUSTED_SQL_READ_BOUNDARY_V1.ru.md](TRUSTED_SQL_READ_BOUNDARY_V1.ru.md) | 2G.2: pinned JWT → actor directory → RBAC → signed SQL + RLS → safe metadata rows, без HTTP/live |

## Что добавлено в код

| Файл | Назначение |
| --- | --- |
| `src/features/saasBlueprint/domain.ts` | Версионированные типы, отдельно от UI/API/секретов |
| `src/features/saasBlueprint/egressValidation.ts` | Статическая проверка структуры подключения и опасных адресов |
| `src/features/saasBlueprint/resolveRoute.ts` | Чистый имитатор fail-closed решения, без сетевых вызовов |
| `src/features/saasBlueprint/safeDecisionPreview.ts` | Безопасные этапы UX-пояснения без паролей и OAuth-токенов |
| `tests/saasBlueprintRouting.test.ts` | Клиентская изоляция, grants, CPA-only, deny-by-default, direct/VPN |
| `tests/saasBlueprintEgress.test.ts` | Приватные/служебные адреса, URL credentials, схемы и статусы |
| `src/features/saasBlueprint/demo/` | Read-only интерфейс, вымышленные tenants, RU/EN тексты, feature flag |
| `tests/saasBlueprintDemo.test.ts` | Проверки разграничения demo-ресурсов, сценариев и UI-безопасности |
| `src/features/saasBlueprint/controlApi/` | **SPEC/SIMULATED:** DTO, RBAC и whitelist-only tenant projection, не HTTP backend |
| `tests/saasControlApiV1.test.ts` | Чистые contract tests: роли, членство, grants, no-secret, no-IDOR |

Локально: `bun test tests/saasBlueprintRouting.test.ts tests/saasBlueprintEgress.test.ts`,
или полный `bun run verify`. При изменениях нужен PR CI и актуализация документов.

## Как посмотреть UX/UI-прототип

**По умолчанию макет скрыт**: обычные `bun run build` и GitHub
release pipeline НЕ включают его в навигацию. Не требуется Core или
действительный OAuth-аккаунт, если открыть специальный локальный маршрут.

В копии **этой feature-ветки**:

```bash
bun install --frozen-lockfile
VITE_ENABLE_SAAS_BLUEPRINT_DEMO=true bun run dev
```

Открыть: **http://localhost:5173/#/saas-demo-preview** (если Vite выбрал
другой порт, использовать его адрес). Эта страница доступна только при
`import.meta.env.DEV` и флаге; работает вне login shell, только на синтетике.
Под PowerShell: `$env:VITE_ENABLE_SAAS_BLUEPRINT_DEMO='true'; bun run dev`.

Внутри уже авторизованного Management Center при том же флаге виден пункт
`SaaS · прототип → Клиенты и подключения` и путь `/#/saas-demo`.

В прототипе: переключение tenant, изолированные списки проектов, аккаунтов
и прокси, обзор поддерживаемых BYOK/BYOA статусов, 4 шага будущего мастера,
симуляции allow/deny и наглядный маршрут. Кнопок отправки секретов,
подключения VPN или сохранения настроек **нет**.

Языки RU/EN; остальные локали временно получают English вместо отсутствующих
переводов. Настоящий клиентский SaaS API/SSO понадобится отдельным этапом.
Никакие demo-статусы нельзя использовать как мониторинг production.
## Факт vs проект

**Сейчас в CLIProxyAPI Core v8.0.23:**
- общий исходящий прокси `requests.proxy-url` (`http`, `https`, `socks5`, `socks5h`);
- индивидуальный `proxy_url` в файле провайдерских учётных данных;
- настройки `proxy-url` для ряда групп API-key upstream;
- режим `direct` / `none` для явного обхода глобального прокси;
- рабочие плагин CPA Key Policy и API Gateway (разработаны отдельно от Blueprint).

Источники текущего API:
- https://github.com/router-for-me/CLIProxyAPI/blob/v8.0.23/config.example.yaml
- https://github.com/router-for-me/CLIProxyAPI/blob/v8.0.23/internal/runtime/executor/helps/proxy_helpers.go
- https://github.com/router-for-me/CLIProxyAPI/blob/v8.0.23/sdk/auth/filestore.go
- https://github.com/origin652/cpa-plugin-key-policy/blob/c041a48bb5e3c3ab44b24d05fa2a27c77c55caf5/README.md

**Пока отсутствует:** надёжный tenant-aware scheduler, enforceable network egress
между разными владельцами, отдельный SaaS AuthZ, секретное хранилище SaaS,
VPN Connector, полноценный billing ledger, live trace pipeline.

## Правила внесения изменений

1. Никаких реальных API/OAuth/CPA ключей, паролей прокси, токенов или дампов `/data`
   в Git, тесты, клиентский JS и CI-логи.
2. Любое изменение модели обновляет `SAAS_BLUEPRINT_SCHEMA_VERSION` либо
   документирует полностью обратную совместимость; API/DB контракты версионируются
   отдельно до подключения к production.
3. Новые возможности — отдельные модули и адаптеры, не скрытые побочные действия
   компонентов React. UI **никогда не является слоем enforcement**.
4. Каждый denial reason должен иметь RU+EN сообщение, доступное объяснение
   и регрессионный тест, прежде чем появится в пользовательском интерфейсе.
5. Любой новый upstream-провайдер: capabilities + правомерный способ авторизации
   + владельцы аккаунтов + собственные тесты. Не выдавать неподдерживаемый OAuth
   за доступный SaaS-доступ.
6. В реальном runtime обязательны network-layer fail-closed, SSRF/DNS проверка,
   запрет случайного direct, проверка фактически выбранного Core аккаунта после
   планировщика, а также проверка refresh/SSE/WebSocket.
7. Работа с Core, Gateway, Railway, `/data`, схемой OAuth и публикация
   `management.html` — отдельные согласованные релизы. PR из этой ветки
   **не сливать** в `custom-no-apikey-fun` до готовности к публикации.

## Уровень гарантий

Симулятор policy evaluator проверяет *консистентность метаданных*, но НЕ
контролирует реальную сеть, выбор аккаунтов Core, DNS-резолвер, IPv6 или
правила провайдера. Положительный результат `resolveSaasRoute` **не является**
разрешением отправлять реальный запрос, пока backend enforcement отсутствует.

## Уточнение прототипа: request path (SIMULATED)

Вкладка «Схема запроса» теперь показывает семь логических точек: Client/Application → API Gateway → CPA Key Policy → Account Pool → Account → Proxy/VPN → AI Provider. Gateway и провайдер помечены «Только схема»: ни одно реальное соединение не создаётся. Восьмиэтапная проверка policy resolver остаётся отдельной, более подробной диагностикой. Настоящие network trace, токены, стоимость и задержки отсутствуют.

## UX-итерация 2 (SIMULATED, не backend)

- Семь узлов request flow стали **выбираемыми**: выбор этапа открывает инспектор безопасных ссылок, владельца ресурса и типа разрешения; при отказе показывает причину и следующий шаг.
- Все детали выбранного аккаунта, пула и egress проецируются через `selectTenantDemoView`. Сценарии чужого аккаунта/прокси возвращают нейтральное «Недоступно или нет разрешения», а не имя чужого ресурса.
- Аккаунты и сетевые профили теперь раздельно показывают **владельца** и **доступ: собственный / явно предоставленный**.
- Данные остаются синтетическими; даже `ALLOW` не означает реального запроса к Gateway или AI-провайдеру. Автоматический browser smoke с Chromium выполнен в CI; полная ручная a11y/UX-приёмка на staging остаётся открытой.

## Реальная браузерная проверка изолированного макета (10.10.2026)

- `tests/browser/saas_demo_browser.py` проверяет живой React-макет через Chromium/Playwright: смену клиента, изоляцию отображаемых ресурсов, поиск, 4 шага мастера, сценарии Allow/Deny, клавиатуру, статусы и запрет внешних HTTP-запросов.
- Workflow: `.github/workflows/saas-blueprint-browser-ci.yml`. Запускается только на изменениях SaaS UI/браузерного теста в PR и по ручному `workflow_dispatch`; **не разворачивает приложение**. Python Playwright устанавливается временно в runner, без изменений `bun.lock`.
- Проверенные конфигурации: desktop 1440 px RU/light; tablet 820 px EN/dark; mobile 390 px RU/dark/reduced motion; small mobile 320 px EN/light/reduced motion.
- [Успешный Browser QA и 20 скриншотов](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38075528744) — артефакт `saas-blueprint-browser-qa` (хранение 7 дней).
- Это **browser smoke и реальные снимки синтетики**, но не полный WCAG-аудит, не staging с backend и не проверка network enforcement.

Запуск локально после `VITE_ENABLE_SAAS_BLUEPRINT_DEMO=true bun run dev`:

```bash
python -m pip install playwright==1.55.0
python -m playwright install chromium
npm install --prefix /tmp/saas-axe --no-save --no-package-lock --ignore-scripts axe-core@4.10.3
# На Windows установите axe-core в подходящий каталог и задайте SAAS_AXE_SCRIPT
python tests/browser/saas_demo_browser.py
```

Публичный Core Management API не требуется; настоящие учётные данные не вводить.

## UX-итерация 4 — автоматический WCAG A/AA smoke (SIMULATED)

В Chromium добавлены **5 конфигураций** (1440 RU/light, 820 EN/dark,
390 RU/dark/reduced motion, 320 EN/light/reduced motion, 640 RU/light/reflow).
Ширина 640 CSS px моделирует reflow при увеличении 1280 px рабочего окна
до 200%; это **не замена тестированию реального браузерного zoom**.

Проверяется каждый из шести экранных состояний (clients, accounts,
accounts-hover, network, denied flow, allowed flow): всего **30 axe-core
WCAG A/AA аудитов** с JSON-отчётами и **25 PNG**. Проверки выполняются
только на synthetic Vite preview, а скрипт axe-core@4.10.3 устанавливается
временным инструментом CI, без включения в production bundle.
[Успешный Chromium + axe CI #38078136183](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38078136183):
0 автоматических нарушений; 5/5 браузерных сценариев PASS.

В первоначальном запуске выявлен реальный дефект: контраст текста кнопки
мастера в состоянии hover и тёмной теме составлял **2,58:1**. Состояние
исправлено, теперь в аудите нарушений не фиксируется.

**Ограничение:** все 30 сканов имеют `color-contrast` в секции
`incomplete` для повторяющихся элементов с градиентом/фоновыми изображениями.
Это не означает автоматическую проверку их контраста. Нужны ручной
contrast audit, скринридеры, реальное 200/400% увеличение, 400% reflow,
крупный текст и UX-приёмка. Backend/AuthZ/network enforcement по-прежнему
`SPEC / PROPOSED`, публикация production запрещена.

## Этап 2 / SPEC — контракт SaaS Control API v1

Зафиксированы [версионированный read-only контракт](CONTROL_API_V1.ru.md),
[матрица AuthZ/RBAC](AUTHZ_RBAC_V1.ru.md) и
[порт read-only metadata adapter](CORE_METADATA_ADAPTER_V1.ru.md).
В TypeScript добавлены только чистые `controlApi` модули и тесты на
синтетическом `BlueprintSnapshot`. Доступ к tenant требует единственного
активного membership, доступ к каждому общему пулу/аккаунту/egress —
**отдельного grant**. Ответ строится из allow-listed DTO:
без credentials, неизвестных исходных полей и чужих идентификаторов.

**Статус: SPEC для HTTP/AuthZ/backend adapter; SIMULATED для функций и тестов.**
Нет сервера, SaaS login, write endpoints, базы данных, сетевых вызовов и
реального data-plane enforcement. UI пока не подключён к Control API.
Никакой новый endpoint не опубликован.

## Этап 2B — локальный read-only HTTP Control API (SIMULATED)

После контракта Control API v1 реализована **отдельная серверная
граница для тестов**, не подключённая к UI или production:
`server/syntheticSessions.ts`, `httpHandler.ts`, `syntheticBackend.ts`,
`safeTransport.ts`. Локальный bootstrap `scripts/saas-control-local.mjs`
начинает слушать только `127.0.0.1:18551` при явном флаге
`SAAS_CONTROL_SYNTHETIC_SERVER=true`; запуск запрещён в Railway/
production. Реальные API ключи не нужны и не создаются.

Реализованы проверяемые краткоживущие **синтетические** opaque sessions,
server-held actor/membership, RBAC before/after reader, проверка grants,
generic deny/no-CORS/no-cache, строгий whitelist DTO и loopback
интеграционные тесты. Никаких Core Management endpoint, Gateway,
OAuth, VPN, /data или credentials. Это **не** готовый SSO или серверная
PostgreSQL AuthZ. Документация запуска:
[LOCAL_CONTROL_HTTP_V1.ru.md](LOCAL_CONTROL_HTTP_V1.ru.md).

Обычный `management.html` не импортирует этот код; default-off
feature flag остаётся прежним. Следующие серверные шаги требуют
изолированного staging, OIDC provider, tenant RLS, audit и read-only Core
metadata source contract.

## Этап 2C — staging-only PostgreSQL RLS pilot (VERIFIED в ephemeral CI)

Создана автономная SQL-миграция
`staging/saas-rls/001_readonly_pilot.sql`, тест
`tests/sql/saas_rls_v1.test.sql` и отдельный workflow с временным
PostgreSQL 16. Реально проверяются tenant-scoping, активное membership
и RBAC, независимые grants на пул/аккаунт/egress, RLS на семи таблицах,
отзыв прав, невозможность читать приватные grants/actor memberships из
read role, скрытие Core-native bindings и отсутствующих pool links.

**Это не развернутый SaaS backend:** только фиктивная база CI, без
Core/CPA, Docker/Railway deployment, реального SSO и secrets.
Session GUC `saas.actor_id` / `saas.tenant_id` — исключительно
контекст, заданный доверенным тестом. Он **может быть подменён SQL
клиентом** и не должен рассматриваться как аутентификация. Для реального
backend нужны OIDC, защищённый scope, параметризованные SQL, изоляция
соединений в пуле, полный threat model и staging acceptance.
Подробнее: [STAGING_POSTGRES_RLS_V1.ru.md](STAGING_POSTGRES_RLS_V1.ru.md).

## Этап 2D — signed scope и единая политика routing (staging CI)

Новая миграция `staging/saas-rls/002_signed_scope_pilot.sql`
дополняет 001: для запросов к синтетической PostgreSQL базе требуется
HMAC-подпись пары actor/tenant, срока действия и идентификатора
**текущей транзакции**. Закрытый ключ создаётся случайно только в
ephemeral CI, read-only роль не может получить его или вызвать
привилегированную тестовую функцию выдачи подписи.

Дополнительно тестируется подмена GUC, actor и tenant, изменение срока,
повтор подписи в новой транзакции и отзыв grants. На уровне
Control API read-only DTO маршруты с недоступным Pool
**исключаются полностью** — так же, как их скрывает PostgreSQL RLS.
`Account.egressProfileId` может оставаться `null`, если Egress скрыт.

Это **не настоящий SaaS SSO**: подпись выдаётся только привилегированной
тестовой функцией; авторизация пользователя, защищённый backend
transaction scope, SQL injection review и интеграция Core ещё
не реализованы. Ни React, ни Gateway/production не обращаются к базе.
Подробности: [SIGNED_SCOPE_RLS_V1.ru.md](SIGNED_SCOPE_RLS_V1.ru.md).

## Этап 2E — identity verification + SQL read boundary (SIMULATED/STAGING)

Новые `controlApi/server/trustedAccessToken.ts` и
`signedSqlBoundary.ts` — изолированные backend-порты, не подключённые
к React, Core, Gateway или Railway. Первый проверяет pinned RS256
`at+jwt` (issuer/audience/kid/signature/expiry), а затем через
server-held mapping связывает issuer+subject с внутренним actorId.
Ни JWT-роль, ни tenant из токена не дают права сами по себе.
Второй выполняет **фиксированные параметризованные SELECT** внутри
отдельной транзакции, подписывает SQL scope, назначает `SET LOCAL ROLE`,
завершает COMMIT либо ROLLBACK с discard повреждённого соединения.
Без PostgreSQL драйвера и реальной DB-интеграции.

Добавлены unit/security tests с эфемерными RSA/HMAC ключами и
`tests/sql/saas_scoped_queries.test.sql` с реальным PostgreSQL 16
только в GitHub Actions. Проверяются spoofed claims, подписи,
SQL-подобные параметры, RLS и отсутствие переноса signed-scope
на следующий запрос по тому же соединению.

**PROPOSED:** реальный OIDC issuer, JWKS rotation/revocation,
полноценный tenant DB, connection-pool driver, access audit,
разрешённый metadata adapter Core и все live traffic функции.
См. [IDENTITY_SQL_BOUNDARY_V1.ru.md](IDENTITY_SQL_BOUNDARY_V1.ru.md).

## Этап 2F — native PostgreSQL driver integration (EPHEMERAL CI)

Без изменения архитектуры B добавлен отдельный **staging-only**
`scripts/saas-staging/verify-bun-postgres.mjs`. Он вызывает уже
изолированный `readSignedScopedMetadata` через настоящий Bun.SQL
(`reserve`, фиксированный SELECT, bound values, transaction-local
scope, commit/rollback и release/discard). Скрипт не импортируется
в React и запускается только внутри GitHub Actions с явным CI guard.

Временная база имеет login-роль `saas_ci_runner` без SUPERUSER,
BYPASSRLS, прямого доступа к memberships/grants/private HMAC key
и без write привилегий. Используются только вымышленные North/Orbit.
Обычная сборка без SaaS флага не увеличивается.

**Не развёрнут реальный SaaS database backend.** OIDC/login,
независимая выдача signing scope, production DB pool/TLS,
audit ledger, реальный Core metadata adapter и enforcement —
`SPEC/PROPOSED`. До успешного финального GitHub Actions нельзя
помечать интеграционный driver acceptance как VERIFIED.
См. [BUN_SQL_DRIVER_PILOT.ru.md](BUN_SQL_DRIVER_PILOT.ru.md).


## Этап 2G.1 — SQL cancellation / pool quarantine (контракт)

В `signedSqlBoundary.ts` введены backend-owned wall-clock deadline,
AbortSignal на каждый SQL-вызов и ограниченное ожидание ROLLBACK/release.
При недостоверном исходе вызова pool синхронно переводится в карантин
перед cleanup: соединение нельзя снова отдавать другому tenant.
Тесты с зависающими SQL, rollback/release и поздним acquire используют
только синтетический driver. Это **контракт/CI acceptance**, НЕ готовый
production-pool: встроенный Bun.SQL 1.3.14 пока не доказал независимый
atomic physical discard, bounded network disconnect и корректность
повторного использования после отмены. См. [BUN_SQL_DRIVER_PILOT.ru.md](BUN_SQL_DRIVER_PILOT.ru.md).

## Этап 2G.1b — native Bun SQL fault probes (VERIFIED: ephemeral CI only)

Добавлен строго изолированный раздел в `scripts/saas-staging/verify-bun-postgres.mjs`.
В GitHub Actions на *временном* PG16 запускаются:
- негативная проверка `reserve({signal})` при исчерпанном `max=1`:
  отдельно классифицируется *native* abort и срабатывание нашего
  probe timeout; в обоих случаях требуется карантин старого пула;
  North/Orbit RLS-чтение только через **новый** пул;
- серверный `statement_timeout` в транзакции, состояние failed
  transaction, подтверждённый `ROLLBACK` и очистка `SET LOCAL`;
- negative capability probe `Bun.Query.cancel()` во время `pg_sleep`:
  если SQL не завершился cancellation error в пределах deadline,
  **не считать отмену работоспособной**; обязательный карантин
  пула без его повторной выдачи клиенту;
- новая **независимая** `SQL`-инстанция после остановки тестовых pools
  с North/Orbit isolation.

Проверка `pg_sleep` выполняется только в защищённом CI-тесте, не входит
в SQL allowlist и не открывает пользователю произвольный SQL. Нельзя
интерпретировать восстановление **нового** пула как успешный recycle
повреждённого connection. См. [BUN_SQL_DRIVER_PILOT.ru.md](BUN_SQL_DRIVER_PILOT.ru.md).

**Результат 2G.1b:** проверено на [PostgreSQL CI #38261137458](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38261137458).
В Bun 1.3.14 native `reserve({signal})` не подтвердил отмену за 1253 мс,
а `Query.cancel()` вернул ошибку отмены только через 3001 мс
(проверяемый лимит 2500 мс). Это отрицательные результаты по срокам
отмены, а не готовый production-драйвер. Подтверждён безопасный отказ
и изоляция с **новым** пулом. Остальные три workflow этого SHA —
[CI](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38261137470),
[Demo](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38261137532),
[Browser](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38261137479) — SUCCESS.

## Этап 2G.2 — server-only trusted identity → SQL scope

Добавлен изолированный `trustedSqlReadBoundary.ts`: принимает
**проверенный через pinned RSA API access-token** только через
существующий verifier, определяет actor по server-held
issuer+subject mapping и читает актуальные memberships до SQL.
Самостоятельно создаёт scope, вызывает fixed parameterized SQL с
HMAC/transaction-local role и проверяет actor/token/RBAC повторно
после асинхронного чтения. Отозванные membership или actor mapping,
смена роли и AbortSignal не возвращают stale rows.

Строгие generic 401/403/404/503, secret-free ответы и SQL field
allowlist. **Статус: IMPLEMENTED contract / VERIFIED synthetic unit tests**
([CI #38263480676](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480676)
на SHA `2ceb5727faf60efb7eabf90557470c14c5d0f2b1`).
Этот порт не является HTTP API, OIDC/SSO или production backend;
реальная E2E PostgreSQL интеграция JWT→AuthZ→SQL остаётся PROPOSED.
Подробнее: [TRUSTED_SQL_READ_BOUNDARY_V1.ru.md](TRUSTED_SQL_READ_BOUNDARY_V1.ru.md).

## Этап 2G.3 — server-side security audit (SYNTHETIC)

Добавлен server-only [Security Audit Contract v1](SECURITY_AUDIT_V1.ru.md):
события `allow/deny/error` с серверным correlationId,
результатом и фиксированным reason code. Только validated actor ID
и Allow tenant; для Deny/Error `tenantId=null`, чтобы audit sink
не стал каналом утечки чужих resource identifiers. События
**не содержат** токенов OAuth/API key, secret URL, SQL/параметров,
prompts, AI responses или произвольного metadata payload.

Новый `securityAudit.ts` подключён к изолированному
`trustedSqlReadBoundary.ts`: запись выполняется синхронно после
последней AuthZ-проверки; ошибка sink **блокирует выдачу
ранее прочитанных SQL metadata с generic 503**. Для unit-тестов
существует только ограниченный по размеру synthetic in-memory buffer.
Это **не** production audit ledger и не HTTP endpoint; durable
event storage, retention и tamper resistance остаются PROPOSED.

**2G.3 CI:** synthetic audit unit tests и интеграция с trusted SQL
boundary подтверждены на `1ea71978abd6abc33263fe460754d7f9dbdd1053`:
[CI #38265951045](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265951045)
(1758 tests PASS / 0 FAIL),
[PG16 #38265950944](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265950944),
[Demo #38265950961](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265950961),
[Chromium #38265951009](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265951009):
**4/4 SUCCESS**. Никакой live DB audit или token replay protection
этими проверками не подтверждены.

## Этап 2G.4a — настоящий PostgreSQL в общей цепочке (CI-gated)

Добавлен staging-only [E2E PostgreSQL Security Acceptance](E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md).
Отдельный GitHub Actions script связывает синтетический pinned RS256
JWT, server-held identity/role, signed transaction scope, **реальный**
non-superuser Bun.SQL → PostgreSQL 16.6 FORCE RLS → allowlisted SQL
metadata → post-read authorization → redacted synchronous audit.

В одноразовой SQL-фикстуре проверяются **независимые** platform
grants: Pool без Account, Account без Egress, просроченный Egress
grant, а также отсутствие Core-native CPA routing. Negative checks
включают unknown issuer/kid/audience/ID-token, чужой tenant,
SQL-like input, server actor revocation после DB COMMIT, отказ
audit и stale cancellation.

**Статус:** IMPLEMENTED CI acceptance, **VERIFIED только после
фактического SUCCESS Actions**. Это не production SaaS API,
не реальный OIDC, не durable audit и не единая транзакция
между in-memory actor-directory и PostgreSQL. См. ограничения
в отдельном E2E документе.

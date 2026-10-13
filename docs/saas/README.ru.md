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

**Статус: IMPLEMENTED / VERIFIED в ephemeral GitHub Actions на
`73066e254e5db2bdd6abeb479c75cae648fc9624`**:
[PG16 actual E2E #38269435054](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269435054)
и [Main CI #38269435023](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269435023)
(1758 unit tests, 0 fail), [Demo #38269434999](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269434999),
[Browser #38269435126](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269435126).
Это лишь synthetic JWT/actor + настоящий PG16, не production backend. Это не production SaaS API,
не реальный OIDC, не durable audit и не единая транзакция
между in-memory actor-directory и PostgreSQL. См. ограничения
в отдельном E2E документе.

## Этап 2G.4b — явный DB-side AuthZ Deny (CI PENDING)

[DB tenant/membership read gate](TENANT_DB_AUTHZ_GATE_V1.ru.md) добавляет
в изолированный signed SQL boundary проверку статуса tenant, текущего
membership и **точного совпадения** server-authorized role с
PostgreSQL. Отрицательный результат до/после SELECT выдаёт generic
**404**, а не `200 []`; аудируется `authorization-changed` с
`tenantId:null`. Подтверждённый ROLLBACK позволяет продолжить работу
изолированного пула; неизвестное состояние connection → quarantine.

Дополнительная миграция `003_explicit_read_gate_pilot.sql` имеет guard
только для временной `saas_ephemeral_test` и запускается CI-отдельно,
без пути к Railway. Проверяются suspended tenant, DB-revoked actor,
stale server role, RLS и повторное использование исправного пула.
**Статус: IMPLEMENTED / VERIFIED для staging PG16 на
`12a3b5ba2c9e32786773e369eb1b80195b75e4d8`**
([CI #38272959097](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959097),
[PG16 #38272959201](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959201),
[Demo #38272959212](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959212),
[Browser #38272959125](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959125)); механизм не
устраняет атомарную race window после SQL/COMMIT и не является
production OIDC, real accounts либо сетевым enforcement.

## Этап 2G.4c — повторная signed RLS проверка после COMMIT

Добавлена [post-COMMIT read-only revalidation](POST_COMMIT_REVALIDATION_V1.ru.md).
После первого signed PostgreSQL SELECT/COMMIT тот же доверенный actor
повторно читает **ту же коллекцию и LIMIT** через новую signed
transaction с новым `txid`. Изменение DB tenant status, membership,
роли или конкретных resource grants между транзакциями вызывает
generic 404, а ранние rows не возвращаются; SQL/pool errors остаются
generic 503. Аудит не раскрывает tenant/resource IDs при Deny.

Unit и CI-only real PG16 tests моделируют отзыв прав/Account grant
**после** COMMIT. **VERIFIED** в
[PG16 E2E #38275287696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287696)
и [Main CI #38275287907](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287907)
(1 767 tests PASS, 0 fail),
[Demo #38275287915](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287915),
[Browser #38275287939](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287939).
Код SHA `6b47e92d2884d238b036e6539382cc4ed7a3383f`. Эта проверка
**не** обеспечивает атомарность отзыва после второго COMMIT,
не заменяет production OIDC/driver/audit и не подключает HTTP/Core.


## Этап 2G.4d — server-owned authorization revision (opt-in guard)

Добавлен [Authorization Revision Contract v1](AUTHORIZATION_REVISION_CONTRACT_V1.ru.md):
новый server-only `authorizationRevision.ts`, опционально подключаемый к
существующему trusted SQL boundary через `revisions`. После trusted
identity/RBAC он фиксирует валидную server-owned ревизию, а после
двух signed SQL транзакций и post-read RBAC повторно читает её.
Изменение → generic 404 и tenantless audit; недоступность,
неканоническое значение и cancellation → generic 503. Ревизия из JWT
или request игнорируется. Тесты `tests/saasTrustedSqlReadBoundary.test.ts`
моделируют изменение во время SELECT, после первого COMMIT и перед
финальным Allow.

**Статус: IMPLEMENTED / SYNTHETIC pending verification on this SHA.**
В отсутствие `revisions` старый путь 2G.4c не изменяется; настоящего
authoritative storage/writer и atomic revision bump пока нет. Новая
PostgreSQL миграция намеренно не добавлена. Временная PostgreSQL CI
проверяет прежний signed RLS E2E как regression, а не новую
линейризуемость; window после последнего revision check остаётся.


## Этап 2G.4d.2 — атомарное изменение tenant revision (ephemeral PG16)

Добавлен отдельный [staging SQL revision pilot](TRANSACTIONAL_AUTHORIZATION_REVISIONS_V1.ru.md):
`004_tenant_authorization_revisions_pilot.sql` поддерживает закрытые
tenant epoch с транзакционными триггерами для tenant status, membership,
роли, независимых Pool/Account/Egress grants и общих ресурсов. Через
signed scope предоставляется только `authorized_revision` без доступа
к private epochs. SQL-фикстуры проверяют rollback, 404-equivalent DB
denial, cross-tenant isolation, drift между двумя транзакциями и
раздельный Pool/Account/Egress; две отдельные PostgreSQL writer-сессии
проверяют блокировку общего epoch, отсутствие dirty read и lost update.

**Статус: IMPLEMENTED / VERIFIED для ephemeral PG16.** [Main CI #38284819714](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819714)
(1 777 Bun tests PASS, 0 fail, ESLint, TypeScript, default-off Vite 3 305.72 KB),
[PG16 #38284819774](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819774)
(signed tenant/member/grant/catalog epoch, rollback, cross-session lock/no lost increments),
[Demo #38284819723](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819723)
и [Chromium #38284819716](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819716)
— **4/4 SUCCESS** для кодового SHA `6ea4546a6953d10baa42f7dcdc6ec5495f9f9517`.
Исторически это был PostgreSQL storage/writer proof; в последующем
2G.4d.3 TypeScript `ServerAuthorizationRevisionSource` подключён
к нему только в disposable staging E2E. TTL expiry по времени и
гонка между final check и ответом остаются SPEC. Нет новых HTTP endpoints,
production DB, Railway, Core, Gateway или изменений UI.


## Этап 2G.4d.3 — real PG16 revision source в trusted read path

[Signed revision reader](SIGNED_REVISION_READER_V1.ru.md) подключает
`createSignedPgAuthorizationRevisionSource` к server-only
`trustedSqlReadBoundary`, используя тот же non-superuser signed
transaction executor, HMAC/txid, DB gates и quarantine, что метаданные.
Обе metadata транзакции остаются; начальная и итоговая ревизии
теперь читаются через signed SQL `authorized_revision`. В ephemeral
PG16 E2E проверяется реальный revoke после **второго** metadata COMMIT,
который обнаруживается даже при одинаковом LIMITed read set.
Нет новых HTTP endpoints и production data-plane.

**Статус: IMPLEMENTED / VERIFIED** только для synthetic + ephemeral
PostgreSQL16. [Main CI #38286207826](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38286207826) (1 785 Bun tests PASS, 0 fail, ESLint, TypeScript, Vite),
[PostgreSQL #38286208002](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38286208002) (real signed PG16 revision source, after-second-COMMIT tenant/member/grant revoke and epoch regression),
[Demo #38286208055](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38286208055) и [Chromium #38286207825](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38286207825) — **4/4 SUCCESS** на кодовом SHA `94f8d7a14c24573ff5397fbe1349e0d89fa7c91f`.
Этап не устраняет race после последнего COMMIT и не является
production credential/access/session enforcement.

## Этап 2G.4d.4a — DB authorization epoch coverage

[Revision coverage](AUTHORIZATION_REVISION_COVERAGE_V1.ru.md)
расширяет staging-only миграции PostgreSQL16: `005` транзакционно
повышает tenant revision при изменениях projects, applications,
CPA key bindings, routing bindings и resource links. Изменение shared
Pool→Account связи инвалидирует оба затронутых tenants; ROLLBACK
откатывает и метаданные, и epoch. Защита остаётся в disposable PG16,
без нового public API или Core/Gateway.

**IMPLEMENTED / VERIFIED** в ephemeral PostgreSQL на SHA `9458db06a86cb0d355937292ce135a89f1926f96`:
[PG16 #38287715026](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38287715026), [CI #38287714993](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38287714993),
[Demo #38287714981](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38287714981),
[Browser #38287715064](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38287715064)
— 4/4 SUCCESS. Истечение grants только от хода времени,
финальный revocation/response barrier и production driver остаются
отдельными задачами.

## Этап 2G.4d.4b — expiry без SQL write

[Signed grant-expiry guard](AUTHORIZATION_EXPIRY_GUARD_V1.ru.md)
закрывает окно, в котором grant истекает по времени, но PostgreSQL
триггеры не повышают revision. Миграция 006 подписанно возвращает
ближайшую deadline активного гранта; server-only guard сравнивает
epoch и deadline и fail-closed при переходе через неё. Добавлены
реальные ephemeral PG16 tests с неизменным SQL epoch и
проверками no-secret/no-IDOR.

**IMPLEMENTED / VERIFIED** на SHA `f0a35b8433e057fae466974e744f48523243ef62`: [PG16 #38288157880](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288157880),
[CI #38288157690](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288157690)
(1 792 tests PASS, 0 fail),
[Demo #38288157863](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288157863),
[Browser #38288157720](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288157720)
— 4/4 SUCCESS; production revocation/HTTP barrier
по-прежнему не доказан.

## Этап 2G.4d.4c — cooperative SQL publication barrier

[Publication barrier proof](PUBLICATION_BARRIER_PILOT_V1.ru.md)
добавляет одноразовый PostgreSQL `007`: signed read transaction
может удерживать `FOR SHARE` private tenant epoch до объявленного
момента публикации, а параллельный writer grant/revoke ждёт завершения
этой транзакции. Проверяется через независимые реальные sessions и
третьего наблюдателя.

**IMPLEMENTED / VERIFIED** для кооперативного PG16 barrier, SHA `9696e280cfee9c6ecd8475fd48afd10113632060`:
[PG16 #38288803851](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288803851) (normal reader COMMIT and forced reader-backend termination),
[CI #38288803787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288803787)
(1 792 tests PASS), [Demo #38288803789](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288803789),
[Browser #38288803822](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288803822)
— 4/4 SUCCESS. Это не HTTP response-send механизм:
функция не внедрена в live read handler, а сетевые доставки и
slow-client/crash semantics остаются SPEC.

## Где проходит граница «полностью реализовано»

См. [Production readiness gates](PRODUCTION_READINESS_GATES_V1.ru.md):
staging PostgreSQL authorization contract пока **не равен**
готовому SaaS, OIDC, сетевому enforcement, billing или durable audit.
Эта feature-ветка не выдаёт новые production endpoints и не меняет
Core/Gateway/Railway. Отдельные approvals, security review и
production-hardening необходимы до любых live credentials.

## Этап 2G.4d.5a — bounded local publication handoff

[Контракт staging-публикации](BOUNDED_PUBLICATION_HANDOFF_V1.ru.md)
добавляет server-only примитив `withSignedScopedPublicationBarrier`.
Он использует существующую подписанную транзакцию и PostgreSQL
`FOR SHARE`, сверяет server-owned epoch и expiry, выполняет асинхронную
*закрытую* подготовку с timeout/cancellation, затем допускает только
синхронную локальную передачу данных до освобождения lock.

**IMPLEMENTED / VERIFIED** на кодовом SHA
`02f5db4dddeabddf099ae9d98d49c13421d759a8`,
[CI #38290101997](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38290101997)
(1 802 PASS), [PG16 #38290101971](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38290101971)
и Demo/Chromium — 4/4 SUCCESS. Публичных HTTP endpoints нет:
remote delivery, audit/outbox, crashes и production credentials остаются
отдельными блокерами.

## Этап 2G.4d.5b — JWT/RBAC + audit + receipt-only publication

[Trusted publication lifecycle](TRUSTED_PUBLICATION_LIFECYCLE_V1.ru.md)
объединяет в одном server-only staging entrypoint
`createTrustedSqlPublishedBoundary` проверенный synthetic JWT/actor,
RBAC, две подписанные metadata транзакции, server revision/expiry,
signed PostgreSQL `FOR SHARE`, дополнительный identity recheck и
обязательный синхронный audit **до** локальной передачи. Внешний
вызов получает только `published:true` + correlationId без SQL rows.

**IMPLEMENTED / VERIFIED** на кодовом SHA `71688ebe6d17a0139a2363609f807ce49640e8be`:
[CI #38291187218](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38291187218)
(1 809 tests PASS, 0 fail),
[PG16 #38291187422](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38291187422),
[Demo #38291187093](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38291187093),
[Chromium #38291187313](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38291187313)
— 4/4 SUCCESS. Не является публичным HTTP endpoint; in-memory
actor store, durable audit, remote receipt и production driver
остаются открытыми security gates.

## 2G.4d.6a — database actor-wide kill switch

[Actor/session epoch pilot](AUTHORITATIVE_ACTOR_REVOCATION_V1.ru.md)
добавляет закрытое состояние активной синтетической actor-сессии в
disposable PG16. Отзыв меняет тот же tenant revision, который
проверяет signed metadata и publication. Для actor, состоящего
в нескольких tenants, инвалидация охватывает все memberships.

**IMPLEMENTED / VERIFIED** в disposable PG16 на SHA
`2df528fa665a4702003fbf834e75e25e815e1025`, [PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787),
[CI #38292965756](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965756), [Demo #38292965740](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965740), [Chromium #38292965795](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965795) — 4/4 SUCCESS. Это не per-token OIDC session
revocation: исходная HMAC scope пока подписывает actor+tenant, а не
идентификатор отдельной сессии.

## 2G.4d.6b — подписанный durable-on-COMMIT audit/outbox

[Private publication audit outbox](SIGNED_PUBLICATION_OUTBOX_V1.ru.md)
в migration 009 записывает только actor/tenant/collection/correlation/
epoch без SQL rows, prompts, secrets и grant IDs. INSERT возможен
исключительно через signed scope и текущую активную PostgreSQL
actor/member role. Событие сохраняется после успешного SQL COMMIT
и удаляется при ROLLBACK всей транзакции.

**IMPLEMENTED / VERIFIED** в disposable PG16:
[PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787), [CI #38292965756](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965756) (1 815 Bun PASS, 0 FAIL), Demo/Chromium
SUCCESS. Транзакционная запись не доказывает
фактическую доставку remote HTTP bytes и не создаёт production
tamper-evident audit service.

## Stage 2G.4d.6 — итоговая staging-верификация

[Main CI #38293380784](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380784) (1 815 tests PASS, 0 FAIL; ESLint, tsc, Vite),
[PG16 #38293380854](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380854) (actor kill-switch, raw signed RLS, outbox transaction, rollback,
signed publication/revoker ordering and crash recovery), [Demo #38293380672](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380672),
[Chromium #38293380657](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380657) — **4/4 SUCCESS** на SHA `bd96d7a038378fa30524914362013ebf06fd420f`.

Важное усиление migration 008: после отзыва actor даже ранее
подписанный scope не может получить строки **непосредственно из RLS**,
потому что `scope_tenant()` и `read_allowed()` проверяют закрытое
active actor state независимо от TypeScript boundary.

Signed audit/outbox в migration 009 сохраняет минимальное redacted
событие после COMMIT, не превращая его в remote-delivery receipt.
Публичных SaaS endpoints, production OIDC и live-network changes нет.

## 2G.4d.7a — per-token revocation, без actor-wide logout

[Token fingerprint authority](TOKEN_FINGERPRINT_REVOCATION_V1.ru.md):
только opt-in server-only scope подписывает SHA-256 полного ранее
проверенного access token. В закрытой PG16 token registry можно
отозвать A, сохранив B того же actor; все writes транзакционно
инвалидируют tenant epoch. Постоянная tombstone запрещает downgrade
к actor-only HMAC даже после actor ID recycling.

**IMPLEMENTED / VERIFIED** (disposable CI, 4/4 SUCCESS на code SHA
`772a29be5b855f31e65e28b30144adddbe776bb1`):
[Main CI](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991853) —
1 822 PASS, 0 FAIL;
[real PG16](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991811),
[Demo](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991833),
[Chromium](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38296991887).
Не является production OIDC/session manager или HTTP receipt.

## 2G.4d.7b — закрытый issuer/subject session provisioning (staging)

[Issuer Session Enrollment](ISSUER_SESSION_ENROLLMENT_V1.ru.md)
добавляет неизменяемый trusted `issuer+subject→actor` в disposable
PG16 и раздельные NOLOGIN-роли для bootstrap личности и регистрации
подписанного JWT fingerprint. Отзыв subject транзакционно меняет
tenant epoch и запрещает даже ранее активные токены через signed RLS.

**IMPLEMENTED / VERIFIED** только synthetic/ephemeral на code SHA
`cade8751232b8deff40143c1ed31a8ac800194a1`: [Main CI #38300085289](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085289) (1 829 PASS / 0 FAIL), [PostgreSQL16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282), [Demo #38300085311](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085311),
[Chromium #38300085300](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085300) — **4/4 SUCCESS**. Это не production OIDC, не реальный
session manager и не HTTP delivery protocol.

## 2G.4d.7c — восстановление локального audit/outbox после сбоев

[Committed Local Audit Reconciliation](LOCAL_AUDIT_RECONCILIATION_V1.ru.md)
добавляет staging-only PostgreSQL механизм после signed audit COMMIT:
закрытая NOLOGIN роль, атомарный claim со `SKIP LOCKED`, короткая
lease, fencing UUID+generation, re-claim после crash и terminal
`reconciled_local` со вторым append-only журналом. Реальный Bun.SQL
E2E проверяет receipt-only publish → COMMIT → local audit observation;
два PG процесса подтверждают rollback незакоммиченного claim при
завершении backend, затем re-claim и защиту от stale ACK.

**IMPLEMENTED / VERIFIED** только ephemeral PG16:
[Main #38302392363](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392363) (1,829 Bun PASS, 0 FAIL; ESLint/TypeScript/Vite),
[PG16 #38302392290](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392290) (real Bun.SQL signed publication, PG16 crash/concurrency, rollback,
lease reclaim/fencing), [Demo #38302392314](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392314), [Chromium #38302392437](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392437) — **4/4 SUCCESS** on code SHA
`1aeeb218a68ca7f0c8094d51551802205b60f224`.

`reconciled_local` не является подтверждением доставки HTTP и не
устраняет gap «локальный handoff до неуспешного SQL COMMIT».

## 2G.4d.7d — synthetic delivery intent и mock ACK

[Post-COMMIT Synthetic Delivery](SYNTHETIC_POST_COMMIT_DELIVERY_V1.ru.md)
расширяет disposable PG16 audit: отдельный immutable intent создаётся
в той же транзакции, что signed Allow. Mock worker получает event ID,
постоянный UUID idempotency key, lease generation и fencing token
только после `reconciled_local`. При потере mock ACK повторная попытка
использует тот же key: тестовый in-memory receiver не применяет эффект
повторно. Три неуспешных попытки переводят событие в
`retry_exhausted`, а не «доставлено».

**IMPLEMENTED / VERIFIED** только synthetic: [Main CI #38304607776](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607776) (1,829 PASS / 0 FAIL, ESLint, TypeScript, Vite), [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719), [Demo #38304607709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607709), [Chromium #38304607769](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607769) — **4/4 SUCCESS** on code SHA `6b0bf3189c544cce21ccdfbaf58b7b2f72ba3214`.

**НЕ HTTP:** никакой payload не передаётся; mock ACK не доказывает
удалённого получения, а local handoff до failed COMMIT по-прежнему
является непреодолённым production-блокером.

## Follow-up 2G.4d.7d: durable LOCAL synthetic receiver

**IMPLEMENTED / VERIFIED (staging only):** migration 014 adds a private
transactional receiver effect/receipt ledger. Repeated synthetic claims
with the same immutable key reuse the first committed receipt; they do
not re-apply the local test effect. [PG16 #38307286153](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38307286153) on SHA `a8eabe5ecc0ccbd42437bb73c6ee58286166c86d`.
See [receiver proof](SYNTHETIC_POST_COMMIT_DELIVERY_V1.ru.md).
**NOT** real HTTP or client exactly-once delivery.

## 2G.4d.7e — отдельный event-only post-COMMIT протокол

**IMPLEMENTED, staging only:** новый
`syntheticCommittedIntent.ts` не принимает local handoff callback
и передаёт worker только ранее закоммиченный 009/013 intent,
без пользовательских SQL rows, JWT или response payload.
При неизвестном ответе `COMMIT` возвращается 503, а не ложная
гарантия отсутствия события. См.
[контракт 2G.4d.7e](COMMITTED_INTENT_ONLY_V1.ru.md).
Старый synchronous pre-COMMIT handoff остаётся production blocker.

**VERIFIED on code commit `fa895296a6ce4062687d0ad0af77f26114d4ef03`:** [PG16 #38309259713](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259713), [Main CI #38309259929](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259929), [Demo #38309259856](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259856), [Chromium #38309259696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259696) — all 4 SUCCESS. The final documentation commit requires its own independent Actions results; code verification does not imply production readiness.


## 2G.4d.7f — Producer operation UUID и recovery после unknown COMMIT

**IMPLEMENTED (synthetic staging only):** новая guarded миграция 015
привязывает один UUIDv4 операции к уже подписанному 009 Allow +
013 immutable intent в ОДНОЙ PostgreSQL-транзакции. Повтор с тем
же UUID, tenant/actor/role/collection/limit проверяет актуальные
права и использует исходное событие, не записывая второй Allow.
Неправильная роль/tenant/параметры дают generic Deny.

При успешном COMMIT и потерянном ответе клиент по-прежнему получает
503 (не доказательство ROLLBACK). Только явный повтор с тем же UUID
в staging восстановит первый event без новой доставки. Реальный
HTTP, remote ACK, durable payload и реальная политика producer
idempotency вне этого пилота.
См. [полный контракт](PRODUCER_OPERATION_IDEMPOTENCY_V1.ru.md).

**CODE VERIFIED** on SHA `ca2503f2e22d30e64c32490c6f46bb7dd73b6dc1`:
[Main CI #38351833547](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833547),
[PostgreSQL16 #38351833550](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833550),
[Demo #38351833546](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833546),
[Chromium #38351833571](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833571) — **4/4 SUCCESS**.
The documentation commit must be checked independently on its own SHA.


## Stage 2G.4d.7g — выдача UUID и bounded recovery (STAGING)

**IMPLEMENTED:** guarded миграция 016 выдаёт случайный UUIDv4
только через подписанный SQL после проверки actor/tenant/role/RBAC.
Выдача не создаёт 009 audit и 013 intent. Отдельный reserved-only
event path создаёт intent лишь при действующем issued key.
Read-only recovery показывает только `issued`, `committed`,
`expired`; никакого event ID, клиента, payload или HTTP ACK.

DB срок первого использования — не более 120 секунд; signed recovery
допускается до двух часов от выдачи. После expiry идентификатор остаётся
неудаляемым tombstone и не используется повторно. Старый 015-режим
не изменён и по-прежнему допускает unissued UUID в synthetic-тестах.
[Подробный контракт](PRODUCER_OPERATION_ISSUANCE_RECOVERY_V1.ru.md).

**CODE VERIFIED on `0d9214b8b41deb1ab97a43f71bb76bdf9d661a7d`:**
[Main CI #38354372696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372696),
[ephemeral PostgreSQL16 #38354372709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372709),
[Demo #38354372683](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372683),
[Chromium #38354372700](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38354372700) — **4/4 SUCCESS**.
The final documentation SHA requires its own independent CI; this does not authorize production delivery.


## Stage 2G.4d.7h — bounded issuance/status, no tombstone GC

**IMPLEMENTED / CODE VERIFIED (staging only):** guarded 017
installs signed, per-actor/tenant issuance limits (4/16 UUID in 5 minutes)
and status limits (16/64 requests in 1 minute). The issuer also refuses
new IDs when there are 12 immutable issue tombstones for an actor/tenant
or 48 for a tenant overall. Expired UUIDs remain permanent and cannot
be reissued; this is deliberately a fail-closed lifetime ceiling, **not**
a production archival or safe deletion policy.

Unknown/foreign status probes debit the requesting authenticated
principal's private PostgreSQL budget *before* ID lookup. The fixed
staging status boundary commits the debit and still returns identical
generic 404 for absent/throttled status, without leaking the UUID's
existence or event/receiver information. Older direct 016/015 SQL
fixtures are unchanged, so **not every legacy path is globally
throttled**. See [the 017 contract](TOMBSTONE_RETENTION_ABUSE_GATES_V1.ru.md).


**CODE VERIFIED on SHA `64d93a034face985d07aa990085d56678e441715`:**
[Main CI #38356159803](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159803),
[PostgreSQL16 #38356159812](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159812),
[Demo #38356159923](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159923),
[Chromium #38356159948](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38356159948)
all SUCCESS. The final documentation commit requires independent Actions on its own SHA.


## Stage 2G.4d.7i — общий PostgreSQL hard stop, без удаления UUID

**IMPLEMENTED (staging only):** миграция 018 ставит BEFORE INSERT
проверки на обе immutable таблицы 015/016: даже прямой вызов старых
signed SQL функций не может бесконтрольно накапливать новые UUID.
Выдача: пожизненные лимиты 12 actor / 48 tenant; события producer:
64 actor / 256 tenant. Успешные INSERT также ограничены 32
actor / 64 tenant за 5 минут (раздельные бюджеты).

018 добавляет BEFORE TRUNCATE запрет, отдельный private snapshot
заполненности с `gc_permitted=false` и ограниченные legacy facades
для прямых вызовов 016. Архивирования, удаления и повторной выдачи
UUID НЕТ. Переигрывание старых 015–017 SQL миграций может
перезаписать функции, поэтому CI заново применяет 018 последним
и проверяет wrappers. Глобальную защиту всех legacy/009
публикаций этот этап **не заявляет**.
[Полный контракт](SYNTHETIC_TOMBSTONE_RETENTION_V1.ru.md).


## Stage 2G.4d.7j — независимый CI witness, но НЕ архив / GC

**CODE VERIFIED (strictly ephemeral):** две новые Node/Bun-independent
`scripts/saas-staging/archive-witness-*.mjs` демонстрируют
Ed25519-подписанный hash-only snapshot UUID, цепочку seq+previous,
offline pinning последнего checkpoint и отказ при неполном restore.
Свидетельский процесс НЕ получает PostgreSQL credentials.
Сценарии: реальный PG16 pre-COMMIT invisibility, COMMIT,
pg_terminate_backend → ROLLBACK, старый/подменённый snapshot,
чужой public key, torn file и forked checkpoint. Никакого
UUID удаления, экспорта реальных IDs или новой миграции 019.
Это только proof-only CI: ephemeral witness и pinned head не
долговечны, GC всегда запрещён. Подробнее:
[7j witness protocol](SYNTHETIC_ARCHIVE_WITNESS_PROOF_V1.ru.md).

**CODE VERIFIED on `66019cd7602d256148562eafd304e9712a2d907b`:** [Main CI #38363925445](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925445), [ephemeral PostgreSQL16 #38363925442](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925442), [Demo #38363925450](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925450), [Chromium #38363925440](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38363925440) all SUCCESS. Final docs SHA needs its own Actions. No production release claim.


## Stage 2G.4d.7k — реальный PG16 backup/restore, head переживает restart процесса

**IMPLEMENTED / CODE VERIFIED (CI ONLY):** `archive-witness-head-store.mjs`
записывает подписанную историю и pinned head через fsync + atomic
rename; новый OS-процесс заново сверяет Ed25519 signatures, всю
цепочку и отдельный файл trust anchor. Второй новый сценарий
использует полноценные **pg_dump / pg_restore**: старый backup
восстанавливается в отдельную scratch-базу и **DENY** при потере
закоммиченного UUID; свежий backup проходит. Состояние с SIGKILL
до rename отклоняется. Любая дополнительная, ещё не подписанная
запись тоже не проходит строгий restore gate.

Ключ, witness head и pinned anchor остаются только на **одном
временном CI-runner**. Это не внешняя долговечная свидетельская
служба, не физический PITR, не атомарный PG→witness COMMIT и
не безопасный GC. `gcPermitted=false` неизменно; SQL 015–018
и production не изменены.
[Полный контракт 7k](SYNTHETIC_WITNESS_RESTORE_PROOF_V1.ru.md).

**CODE VERIFIED at `9af3b8d5b29ebceb6a433468c650f01be913a148`:** [Main CI #38367994239](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994239), [ephemeral PG16 #38367994247](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994247), [Demo #38367994191](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994191), [Chromium #38367994196](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38367994196) — **4/4 SUCCESS**. The final documentation HEAD must pass its own CI; no archive/GC/deployment authorization.


## Stage 2G.4d.7l — three local witness compartments (CI only)

**IMPLEMENTED only for ephemeral PG16:** two distinct offline
Ed25519-verified witness replicas and a separately fsynced, sequential
high-water journal. A real PG COMMIT made before its signed successor
is DENIED; incomplete publication of one/both witness replicas or
missing high-water pin also DENIES. Rollback of both signed replicas
is detectable while the independent-to-replicas local high-water
retains the newer head. A journal crash after fsync leaves a lock
and DENIES on fresh verifier process.

The test explicitly demonstrates the **remaining vulnerability**:
rolling back all three job-local histories together can recreate an
old consistent view. All copies and the signer still share one CI host,
not a durable independently administered witness. No migration 019,
GC, archive removal, real traffic or endpoint. Read
[stage 7l contract](SYNTHETIC_WITNESS_HIGHWATER_GAP_V1.ru.md).


## Stage 2G.4d.7m — signed UNKNOWN-COMMIT settlement (CI-only)

New disposable PG16 tests terminate one connection **before COMMIT**
and another **after real COMMIT** but before the caller sees a
reliable reply. The offline verification requires the exact expected
single UUID commitment AND a signed direct-successor checkpoint on
both witness histories plus the third high-water journal. A missing
UUID, unauthorized extra UUID, incorrect candidate, lagging witness
or partial publication DENIES instead of granting a retry, issuing
another UUID or releasing a network event.

This is LOCAL observation only. Witness files and temporary Ed25519
key reside on ONE runner, candidate is not signed actor approval,
there is no atomic PG→external witness protocol or production
identity/failover guarantee. No archive/GC/UUID reuse.
[7m contract](SYNTHETIC_UNKNOWN_COMMIT_SETTLEMENT_V1.ru.md).


## Stage 2G.4d.7n — отдельный Unix-socket witness (CI only)

Новый синтетический PostgreSQL16 CI запускает долгоживущий
Node witness process с Unix-сокетом, собственным временным
Ed25519 ключом, fsynced checkpoint/head и подписанным
receipt для каждого request ID. Реальный PG COMMIT до
обновления witness даёт DENY; потеря IPC ACK **после**
фиксации head восстанавливает ТОТ ЖЕ receipt после restart,
а не выпускает другой UUID. Конкурентные stale writers,
подмена request ID, незаписанный UUID и orphaned checkpoint
после SIGKILL блокируются.

Signer НЕ получает PG credentials, но signer и client всё
ещё находятся на одном GitHub runner и в одном OS trust
domain; PostgreSQL projection приходит от клиента и не
подтверждается независимым источником. Никакого external
durable witness, production, GC, архива, реальной delivery.
[Контракт 7n](SYNTHETIC_IPC_WITNESS_LOST_ACK_V1.ru.md).


## Stage 2G.4d.7o — read-only signed PG16 snapshot (CI only)

**IMPLEMENTED as disposable proof:** отдельный PG16 projector с
ограниченным правом SELECT только `operation_id` самостоятельно
считывает оба immutable UUID реестра в REPEATABLE READ READ ONLY
transaction, подписывает canonical SHA-256 commitments и свежий
challenge nonce своим Ed25519 ключом. Offline verifier проверяет
этот сертификат и точное соответствие отдельному signed witness
checkpoint. Реальный COMMIT без нового свидетельства, подменённый
клиентский snapshot, чужой ключ, старый nonce и отозванный SELECT
получают DENY.

**Важно:** ключи, projector и trusted challenge находятся на
ОДНОМ CI runner. Это **не** независимый durable root, истинный
PG COMMIT certificate или атомарное external settlement; 7n
IPC append остаётся test-only и НЕ использует этот gate.
Никаких GC/архива/UUID reuse/production.
[Детальный контракт 7o](SYNTHETIC_PG_PROJECTION_ATTESTATION_V1.ru.md).


## Stage 2G.4d.7p — signed PostgreSQL witness append (CI only)

**IMPLEMENTED / staging proof:** 7p добавляет отдельный opt-in
`challenge-pg` → `append-pg` к Unix-socket witness.
Публичный ключ PostgreSQL projector закрепляется при запуске;
проверка nonce, request ID, predecessor, source, signature и точного
projection digest выполняется **в witness перед подписанием**.
В этом режиме клиентский `append` запрещён; старый 7n
`append` остаётся только в отдельном тестовом режиме.
Тот же signed receipt восстанавливается после потерянного IPC ACK;
подделка proof, stale/replay, fork и отсутствие projector DENY.

**NOT PRODUCTION:** один CI runner, без off-host durability,
PG→witness atomic settlement, issuer authorization, external ACK,
архива/GC. Всегда `gcPermitted=false`.
[Контракт 7p](SYNTHETIC_PG_ATTESTED_IPC_APPEND_V1.ru.md).


## Stage 2G.4d.7q — локальный high-water fence для защищённого IPC witness

**IMPLEMENTED (CI proof only):** отдельный локальный Node journal со
своим Ed25519 ключом подписывает monotonic witness head после проверки
witness подписи/предшественника. В опциональном режиме защищённый
`append-pg` возвращает положительный ACK только после local fsync и
подтверждённого signed journal high-water. Откат одной стороны,
недоступный journal, несовпадающие heads, подмена pinned key и crash
посреди публикации приводят к DENY / запрету автоматического replay.

Оба процесса всё ещё на **одном GitHub runner**, а не в независимых
административных trust domains. Нет atomic PG COMMIT, off-host WORM,
production issuer/delivery, архива, UUID reuse или GC.
`gcPermitted=false`.
[Детальный контракт 7q](SYNTHETIC_IPC_HIGHWATER_FENCE_V1.ru.md).


## Stage 2G.4d.7r — read-only UNKNOWN outcome observation (CI only)

**IMPLEMENTED staging proof, NOT a recovery/reissue API:** новый offline
`archive-witness-unknown-observer.mjs` не получает PG credentials,
не выпускает UUID и проверяет три pinned Ed25519 signatures: PostgreSQL
source snapshot, Unix witness checkpoint и separate local journal receipt.
Для заранее подготовленного commitment различает `NOT_OBSERVED_IN_ONE_SNAPSHOT_UNKNOWN`,
`PG_SNAPSHOT_ONLY_UNWITNESSED` и
`DUAL_LOCAL_SIGNED_IDENTITY_OBSERVED`, но **ВСЕ** статусы всегда
возвращают `authorizationGranted=false`, `reissuePermitted=false`,
`retryPermitted=false`, `deliveryPermitted=false`,
`gcPermitted=false`.

Физические PG16 pre/post-COMMIT loss, lost witness ACK, signature replay,
rollback, fork и multi-COMMIT drift проверяются в отдельном 7r CI шаге;
предыдущие 7l–7q не заменяются. Одного локального CI runner недостаточно
для off-host durability/atomicity, реального production issuer,
outbound ACK, retention или GC.
[7r технический контракт](SYNTHETIC_UNKNOWN_OUTCOME_OBSERVATION_V1.ru.md).


## Stage 2G.4d.7s — simulated reviewer pin and manual-only high-water disputes

**CI-only:** новый offline `archive-witness-manual-review-pin.mjs`
с отдельным *синтетическим* reviewer Ed25519 ключом подписывает
неубывающий head только после проверки signed witness + local
high-water. `inspect` выявляет частичный split, локальный head
позади отдельно сохранённого reviewer pin, конфликт digest либо
неподписанный reviewer advance. Даже при совпадении подписей
требуется ручной анализ; `repairPermitted=false`,
`reissuePermitted=false`, `deliveryPermitted=false`,
`gcPermitted=false`.

**Важно:** reviewer/key/pin и оба signer на **одном runner**,
настоящего независимого off-host/WORM/реального operator approval
нет. Совместный rollback с потерянным reviewer pin остаётся
необнаружимым; никаких production, UUID reuse, archive или GC.
[Контракт 7s](SYNTHETIC_MANUAL_REVIEW_PIN_V1.ru.md).


## Stage 2G.4d.7t — independent off-host high-water SPEC, signed wire conformance

**SPEC only for actual off-host authority:** описаны независимые
оператор/key custody, authenticated compare-and-append, WORM/
монотонный trusted minimum, anti-replay, crash/partition manual
runbooks. **Никакой внешней службы, отдельного хоста, HSM или WORM
в 7t не развёрнуто.**

**IMPLEMENTED CI-only:** offline verifier подписанного
`saas-synthetic-offhost-highwater-receipt-v1` с pinned
authority/witness/journal keys, nonce, epoch, direct predecessor,
journal digest и независимо supplied retained minimum.
Физические PG16 и signed 7p–7s сценарии вновь проверяются на
отдельных UUID fixtures; mock external signer остаётся на
ОДНОМ CI runner. Результат всегда `manualReviewRequired=true`
и `actualOffHostCustodyVerified=false`,
`reissuePermitted=false`, `deliveryPermitted=false`,
`repairPermitted=false`, `gcPermitted=false`.
[7t контракт](SYNTHETIC_OFFHOST_HIGHWATER_CONTRACT_V1.ru.md).


## Stage 2G.4d.7u — operator onboarding + manual DR quarantine (CI-only)

**SPEC:** независимые governance и две реальные operator роли, ключи,
ревокация, WORM external minimum, durable anti-replay и отдельная
проверка PITR/partition/failover перед настоящим release.
**CI IMPLEMENTED:** offline Ed25519 policy + 2-of-2 role signatures
на неизменный incident dossier, signed 7t receipt и retained minimum;
тесты rollback/split/lag/fork и replay. Все роли на **ОДНОМ**
runner, поэтому ни human approval, ни off-host custody, ни DR
не считаются достигнутыми. Даже matched evidence остаётся quarantine;
`authorityToResume=false`, `reissuePermitted=false`,
`repairPermitted=false`, `deliveryPermitted=false`,
`gcPermitted=false`.
[7u контракт](SYNTHETIC_OPERATOR_DR_QUARANTINE_V1.ru.md).

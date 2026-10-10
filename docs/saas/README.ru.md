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
python tests/browser/saas_demo_browser.py
```

Публичный Core Management API не требуется; настоящие учётные данные не вводить.

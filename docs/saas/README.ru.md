# SaaS Blueprint B — индекс проектного прототипа (RU)

> **Статус: ПРОЕКТ / НЕ ПОДКЛЮЧЁН К PRODUCTION.** Здесь нет работающей
> многоклиентности, VPN, BYOA или дополнительного механизма доступа.
> Файлы в `src/features/saasBlueprint/` — чистые TS-контракты и симулятор
> решений на синтетических данных; в Router, Core и Gateway они не импортируются.

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

Локально: `bun test tests/saasBlueprintRouting.test.ts tests/saasBlueprintEgress.test.ts`,
или полный `bun run verify`. При изменениях нужен PR CI и актуализация документов.

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

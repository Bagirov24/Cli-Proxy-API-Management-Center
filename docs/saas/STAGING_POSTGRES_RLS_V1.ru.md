# SaaS Control — PostgreSQL RLS pilot v1 (изолированный CI)

**Статус: VERIFIED только в ephemeral PostgreSQL CI, backend интеграция — SPEC.**

Это экспериментальный, **staging-only SQL contract**, а не миграция рабочей
системы. Прототип проверяет базовые принципы tenant isolation в PostgreSQL
16 на фиктивных North Studio, Orbit Lab, платформенных ресурсах и
read-only actor roles. Ни один модуль SQL здесь не импортирует реальный
Core, Gateway, OAuth, Railway и не взаимодействует с /data.

## Что создано

- `staging/saas-rls/001_readonly_pilot.sql` — повторно применяемая
  миграция в изолированной схеме `saas_rls` (в том числе explicit opt-in
  `SET saas.staging_only = 'true'`). Роли `saas_rls_owner` и
  `saas_rls_reader` не имеют LOGIN или BYPASSRLS.
- `tenants`, `projects`, `applications`, `key_bindings`,
  `resource_catalog`, `resource_links`, `routing_bindings` —
  таблицы чтения с **ENABLE и FORCE ROW LEVEL SECURITY**.
- `memberships`, `resource_grants` — приватные таблицы авторизации,
  недоступные read role даже для SELECT.
- `read_allowed` проверяет server-provided actor + tenant scope,
  status active и роль. `resource_granted` проверяет совпадение
  конкретного ресурса, вида, владельца, получателя, status и
  `expires_at > statement_timestamp()` по часам БД.
- Ссылки `pool→account` и `account→egress` доступны только когда
  **оба** объекта доступны независимо. Route, содержащий чужой либо
  недоступный pool, скрывается целиком; Core-native bindings не видны.
- Все exposed таблицы доступны роли только через SELECT. Никаких
  write-прав, API keys, raw proxy URI, OAuth files и prompts в схеме нет.

## Acceptance и воспроизводимость

Запускать только на **отдельном локальном или CI PostgreSQL**, никогда не
на Railway production:

```bash
# Подключение только к СВОЕЙ временной тестовой базе postgres.
# psql откроет локальную SQL миграцию, повторит её и выполнит фикстуры.
psql -X -v ON_ERROR_STOP=1 -f tests/sql/saas_rls_v1.test.sql
```

GitHub workflow `.github/workflows/saas-staging-rls-ci.yml` создаёт
**эпизодический** PostgreSQL 16 service, не использует Railway environment,
секреты GitHub/production или внешний DB endpoint. Тест выполняет:

- migration replay; роли NOLOGIN/NOBYPASSRLS, запрет reader INSERT/UPDATE/
  DELETE и чтения memberships/grants;
- default deny без session context, tenant switch без membership;
- North/Orbit: свои проекты, приложения, CPA key references и ресурсы;
- платформенные Pool, Account, Egress **только по независимым grants**;
- отсутствие чужих account/egress references и ссылок на непрозрачные
  ресурсы, отсутствие доступа к native Core key;
- роль auditor только для tenant/projects/applications;
- revoked membership, suspended tenant, disabled/wrong-owner/expired grant;
- моментальное скрытие ссылок при отзыве account/pool/egress grants.

Прошедший этот тест PostgreSQL RLS **не означает** готовый SaaS
backend — ниже обязательные границы доверия.

## Критическое ограничение: session GUC — НЕ аутентификация

Функции читают `current_setting('saas.actor_id')` и
`current_setting('saas.tenant_id')`, чтобы моделировать контекст
**уже проверенной** SaaS-сессии. PostgreSQL custom GUC доступны для
изменения пользователю SQL-соединения. Поэтому эти два значения
**нельзя считать защищёнными от SQL-инъекции или недоверенного
SQL-клиента**. RLS здесь — defence in depth, а не единственный
authentication boundary. Допуск произвольного SQL под reader ролью
разрушает это допущение.

На следующем этапе нужны проверенная OIDC/SSO-сессия, серверный
подписанный/валидационный контекст транзакции либо иной механизм
защищённого назначения scope, параметризованные запросы, pool
connection hygiene (`SET LOCAL` в транзакции и сброс на release),
ограниченный endpoint surface и отдельные adversarial/SQL injection
проверки. Без этого **запрещено** давать reader роль внешним
приложениям, подключать браузер непосредственно к БД или размещать
pilot в production.

## Согласованный read-only RoutingBinding (этап 2D)

SQL RLS скрывает всю строку маршрута, если pool недоступен.
С этапа 2D `readSyntheticTenantCollection` тоже **полностью исключает**
этот route вместо `poolId: null`. HTTP transport отвергает
некорректный частичный route. При этом Account.egressProfileId
может быть null и Pool.accountIds фильтруются независимо;
база не хранит секреты и не является полной доменной схемой.

Не реализованы: реальный API adapter, SSO, secrets/Vault, tenant-aware
cache, полноценные миграции и backup/restore, audit trail, pagination,
настоящие network traces/billing, encryption/rotation, enforcement
CPA scheduler и VPN. Всё это остаётся **PROPOSED/STAGING**.

См. [CONTROL_API_V1.ru.md](CONTROL_API_V1.ru.md),
[AUTHZ_RBAC_V1.ru.md](AUTHZ_RBAC_V1.ru.md),
[LOCAL_CONTROL_HTTP_V1.ru.md](LOCAL_CONTROL_HTTP_V1.ru.md).

## Миграция 002 (подписанный тестовый контекст)

Описание выше относится к исходной миграции **001**. GitHub Actions
дополнительно последовательно применяет `002_signed_scope_pilot.sql`,
затем проверяет подмену произвольных session GUC, срока жизни,
actor/tenant и повтор подписи за пределами транзакции.
В 002 чтение прежних `saas.actor_id`/`saas.tenant_id`
больше не предоставляет права без HMAC подлинного scope.
Привилегированный тестовый issuer не подключён к production.

Важно: защита только в глубину. OIDC, параметризованные запросы,
connection pool и запрет произвольного SQL обязательны до staging.
См. [SIGNED_SCOPE_RLS_V1.ru.md](SIGNED_SCOPE_RLS_V1.ru.md).

## Этап 2E — дополнительный SQL-injection и pool-reuse smoke

`tests/sql/saas_scoped_queries.test.sql` запускается на **том же**
ephemeral GitHub Actions PostgreSQL 16 после миграций 001 и 002.
`PREPARE/EXECUTE` получает SQL-подобный tenant ID как
параметр и возвращает ноль записей, а отдельный BEGIN после
ROLLBACK не видит signed-scope claims предыдущей транзакции.
Это smoke для статических prepared SQL, не доказательство
защиты от всех классов SQL injection и concurrency в будущем драйвере.
[IDENTITY_SQL_BOUNDARY_V1.ru.md](IDENTITY_SQL_BOUNDARY_V1.ru.md).


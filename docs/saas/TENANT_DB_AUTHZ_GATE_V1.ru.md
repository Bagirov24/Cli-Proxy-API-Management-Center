# SaaS Blueprint B — Stage 2G.4b: подписанная проверка статуса tenant и membership

**Статус: IMPLEMENTED / VERIFIED только в ephemeral PG16 CI на кодовом
SHA `12a3b5ba2c9e32786773e369eb1b80195b75e4d8`.** Не является production
authentication, OIDC, публичным HTTP API или готовым backend. Все тестовые
данные и миграции относятся только к disposable PostgreSQL 16 в GitHub
Actions и отдельным синтетическим JWT/actor-store. Railway, CLIProxyAPI
Core/Gateway и действующие credentials не используются.

## Обнаруженный недостаток 2G.4a

`saas_rls` уже скрывал строки suspended tenants и revoked membership
через FORCE RLS, но API мог ошибочно вернуть `200` с пустым массивом.
Пустой разрешённый результат и отказ авторизации не равнозначны.
Второй разрыв: ранее подписанный actor/tenant scope не проверял, что
**роль membership в БД** совпадает с разрешённой сервером ролью.
Актуальный статус PostgreSQL должен быть отдельным fail-closed gate,
не только следствием отсутствия видимых строк.

## Реализация 2G.4b

- `staging/saas-rls/003_explicit_read_gate_pilot.sql`: третья миграция
  только для одноразовой `saas_ephemeral_test`, с guard
  `saas.staging_only=true`, `current_user=postgres` и запретом
  доступа reader к memberships, grants и HMAC ключам.
  Функция `saas_rls.scope_membership_matches` — `SECURITY DEFINER`,
  возвращает **только boolean** и требует подлинный HMAC SQL scope,
  того же actor+tenant, текущий `active` membership и точное
  совпадение role. Функция не возвращает private resource IDs.
- `SCOPED_READ_GATE_SQL` — фиксированный, параметризованный SELECT.
  Он требует доступную через RLS **активную запись tenant**, совпадение
  actor/tenant/role в приватной таблице через secure definer и
  действующую `saas_rls.read_allowed(..., collection)` capability.
  Никакой произвольный SQL/роль/tenant из клиента не принимается.
- `readSignedScopedMetadata` выполняет gate дважды **в той же
  подписанной READ COMMITTED transaction**: сразу после `SET LOCAL ROLE
  saas_rls_reader` и после metadata SELECT, до COMMIT. На отрицательный
  ответ `false` — `ROLLBACK`, строки отбрасываются и выдаётся только
  типизированный `ScopedSqlAuthorizationDenied` без PG/tenant details.
  При *подтверждённом* ROLLBACK исправная connection может быть
  возвращена в тестовый pool; при ошибке ROLLBACK/unknown query outcome
  остаётся синхронный quarantine/whole-pool discard.
- `trustedSqlReadBoundary` преобразует только этот доверенный
  `ScopedSqlAuthorizationDenied` в generic **404 NOT_FOUND** и
  server-side audit `authorization-changed`, всегда `tenantId:null`.
  Неизвестные SQL ошибки остаются generic **503**, не маскируются как
  Deny и не раскрывают внутренние данные.

Важно: SQL role parameter выводится из проверенной server-side
membership, **не** из JWT claims/HTTP headers. Подписанный контекст
связывает actor, tenant, expiry и transaction ID; RBAC аудитора
контролируется и сервером, и PostgreSQL.

## Проверки 2G.4b

Unit-тесты покрывают DENY до SELECT, DENY после SELECT с
отбрасыванием уже прочитанных строк, malformed boolean gate,
подтверждённый ROLLBACK без pool poisoning и безопасный 404/audit.
Новые staging PostgreSQL проверки используют НАСТОЯЩУЮ БД, но
аккаунты остаются синтетическими:

| Сценарий | Безопасный результат |
| --- | --- |
| Активные North/Orbit с совпадающей ролью | 200 Allow, только собственные строки |
| Suspended `demo-paused` при active server membership | **404**, без rows и tenant ID |
| Revoked `actor-db-revoked` в PostgreSQL, active в server memory | **404**, без rows |
| Действующий auditor в DB, но stale `tenant-admin` на server | **404**, без privilege elevation |
| Чужой tenant/JWT role spoofing | **404** до SQL |
| Запрос с malformed/небулевым SQL authz result | **503**, quarantine |
| DB gate denies после SELECT (unit controlled race) | **404**, `ROLLBACK`, без rows |
| Последующий корректный запрос после подтверждённого ROLLBACK | Allow, без наследования контекста |

Проверка с настоящим PG исполняется под `saas_ci_runner` (NOINHERIT,
NOBYPASSRLS), а миграция — отдельно через одноразовый CI superuser
и guarded staging flag. SQL-модуль не использует `postgres` login для
metadata reads и не видит signing secret в БД.

## Оставшиеся ограничения — SPEC / PROPOSED

- Двойная проверка в READ COMMITTED существенно сокращает race
  window, но **не обеспечивает атомарность** с внешним actor-directory
  и не исключает изменение membership/tenant status сразу ПОСЛЕ
  второй проверки или COMMIT. Для production требуется согласованная
  модель авторизации, revision/snapshot, блокировки либо надёжная
  стратегия отзыва с формально определённой гарантией.
- Actor-store и RSA issuer синтетические; live OIDC, JTI/replay
  revocation, tenant membership across replicas НЕ внедрены.
- Bun.SQL 1.3.14 не гарантирует индивидуального physical
  discard и быстрый network cancel. Whole-pool quarantine остаётся
  изолированной CI стратегией, не production transport.
- Подписанный SQL scope и строки PostgreSQL — metadata projection,
  **не полный ControlResource DTO**, не public HTTP и не enforcement
  реального AI-трафика.
- Audit — redacted in-memory staging events; durability, ACL,
  retention, tamper evidence НЕ реализованы.
- Никакие миграции не имеют автоматического пути к Railway
  production, а Core/native keys и VPN/proxy не затрагиваются.

См. [E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md](E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md),
[TRUSTED_SQL_READ_BOUNDARY_V1.ru.md](TRUSTED_SQL_READ_BOUNDARY_V1.ru.md),
[BUN_SQL_DRIVER_PILOT.ru.md](BUN_SQL_DRIVER_PILOT.ru.md)
и [SECURITY_AUDIT_V1.ru.md](SECURITY_AUDIT_V1.ru.md).

## Подтверждение GitHub Actions

На SHA `12a3b5ba2c9e32786773e369eb1b80195b75e4d8` 4/4 SUCCESS:

- [Основной CI #38272959097](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959097):
  **1 763 Bun unit-теста PASS / 0 FAIL**, ESLint, TypeScript,
  Vite default-off **3 305,72 KB**.
- [Ephemeral PG16 #38272959201](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959201):
  **SUCCESS**. В логах подтверждены `PASS: staging-only signed membership
  role read gate installed` и `PASS: suspended tenant, DB-revoked member
  and stale role deny 404 before output`. E2E PG16 — отдельный workflow,
  **не входит в 1 763 unit-теста**.
- [SaaS Demo #38272959212](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959212):
  **SUCCESS**, opt-in HTML **3 386,51 KB**.
- [Chromium QA #38272959125](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959125):
  **SUCCESS**, synthetic browser QA.

Первый кодовый SHA `bd25b0c` дал **1 763 passing unit-теста и
успешный PG16**, но основной CI отклонил нарушение ESLint
`preserve-caught-error`. Исправлено в `12a3b5b`: никакая исходная
SQL exception не прикрепляется к `Error.cause` и не протекает
через публичное сообщение. Полный повторный CI прошёл успешно.

**VERIFIED только staging DB-authoritative gate**, не атомарная
гарантия отзыва прав между SQL/actor-store, не физический discard,
не real OIDC и не deployment.

## Дополнение 2G.4c — after-COMMIT read-set validation

2G.4b использовал два signed gates до/после SELECT в одной
транзакции. В 2G.4c **после первого COMMIT** весь allowlisted
read повторяется во второй signed transaction; отозванный в
промежутке tenant/membership/grant или изменившиеся видимые
Account/Pool/Egress rows возвращают generic 404 вместо stale data.
Это диагностический security-hardening в CI, **не** атомарный
revision-barrier. Подробнее:
[POST_COMMIT_REVALIDATION_V1.ru.md](POST_COMMIT_REVALIDATION_V1.ru.md).

**2G.4c VERIFIED:** независимая signed READ COMMITTED transaction
после первого COMMIT повторно проверяет те же gates и resource
row set. На [PG16 #38275287696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287696)
изолированный fixture writer отозвал tenant, membership и Account
grant после первого COMMIT; прочитанные строки не были выданы.
Это не гарантия сериализации после второго COMMIT:
[POST_COMMIT_REVALIDATION_V1.ru.md](POST_COMMIT_REVALIDATION_V1.ru.md).

# Stage 2G.4a — End-to-end Trusted Identity → PostgreSQL RLS → Audit

> **Статус: IMPLEMENTED / VERIFIED в ephemeral PostgreSQL CI
на кодовом SHA `73066e254e5db2bdd6abeb479c75cae648fc9624`.** Интеграционный тест выполняется
> только в GitHub Actions на одноразовой PostgreSQL 16.6 и Bun 1.3.14.
> **STAGING ONLY:** нет production credentials, публичного HTTP,
> настоящего OIDC, CLIProxyAPI Core/Gateway или SaaS deployment.

## Что теперь действительно объединено

Новый отдельный executable acceptance:

- `scripts/saas-staging/verify-trusted-pg-e2e.mjs`.
- `tests/sql/saas_e2e_grants_fixture.test.sql` (строго временный
  PostgreSQL, запуск ПОСЛЕ существующего 2F native driver acceptance).
- Шаг в `.github/workflows/saas-staging-rls-ci.yml`.

Цепочка проверки **в одном запросе**:

1. Синтетический **RS256 JWT**, сгенерированный в памяти текущего CI
   процесса, `typ=at+jwt`, заранее прикреплённый issuer/audience/key.
2. Trusted `issuer + sub → actorId` через **server-held synthetic map**.
   Никакие JWT actor/role/tenant claims не определяют права.
3. Актуальное in-memory membership/RBAC на стороне isolated server
   boundary, собственный correlationId.
4. SQL scope выдаётся через `createPinnedHmacScopeIssuer`. HMAC ключ
   берётся **только из disposable PG16 fixture**, через защищённый
   CI bootstrap, не публикуется и не читается SQL reader ролью.
5. Встроенный **реальный** `Bun.SQL` PostgreSQL wire connection под
   логином `saas_ci_runner` (NOINHERIT, NOBYPASSRLS, без доступа к
   приватным membership/grant/signer таблицам). Все SQL строки
   фиксированы на сервере, значения только параметрами `$1/$2`.
6. Реальная транзакция: `BEGIN`, `txid_current()`, signed GUCs,
   `SET LOCAL ROLE saas_rls_reader`, fixed SELECT, PostgreSQL
   `ENABLE/FORCE RLS`, sanitation allowlist и `COMMIT`.
7. Повторная проверка JWT/subject mapping и membership/RBAC **после**
   COMMIT. Revocation during async SQL скрывает уже полученный результат.
8. Синхронное audit событие с 11 разрешёнными полями и безопасным
   reason. Deny/Error не содержат чужого tenant ID. Сбой sink →
   generic 503 без rows.

Не задействованы реальные accounts, CPA native keys, VPN/Proxy или
Data Plane. События аудита существуют исключительно в памяти
CI-процесса; не публикуются в stdout, API, Core или production store.

## Положительные и отрицательные проверки

| Сценарий | Критерий |
| --- | --- |
| North → North projects; Orbit → Orbit projects | Только собственные строки, Allow audit и соответствующий tenant |
| 8 конкурентных North/Orbit signed reads | Без пересечения строк и без повреждения SQL pool |
| North grants: Account без Egress | `shared-account` виден, `shared-egress` скрыт |
| Orbit grants: Pool без Account | `shared-pool` виден, `shared-account` скрыт |
| Orbit expired Egress grant | `shared-egress` скрыт |
| CPA-native key bindings | Native Core key не попадает в SQL routing output |
| North → Orbit, Orbit → North | 404 до подключения к DB, audit Deny с `tenantId=null` |
| Auditor → Accounts | 403 до подключения к DB |
| Wrong JWT issuer/audience/kid, ID-token, unknown subject | 401 до SQL |
| Forged JWT role/actor/tenant, SQL-like tenant | Не дают доступ, не выполняют пользовательский SQL |
| Membership revocation или trusted actor mapping revoked ПОСЛЕ COMMIT | No stale rows, generic 404/401, безопасный audit |
| Audit sink exception после DB query | Generic 503, без уже прочитанных metadata |
| AbortSignal на завершении COMMIT | Generic 503 без rows; pool quarantined, никакого reuse |

**Разделение прав проверяется настоящим PostgreSQL**, а не
только картинками демо: отдельный SQL fixture для Orbit выдаёт
`shared-pool` без Account/Egress grant, а North убирает grant
на `shared-egress`, оставляя `shared-account`. Изменения
производятся в одноразовой БД **после** ранее действовавшего 2F
test suite, чтобы не переписать исторические ожидания драйвера.

Все тестовые SQL statements доступны **только** CI runner; запросы
пользователя не передаются в `SQL.unsafe`. Запуск скрипта блокируется
вне `GITHUB_ACTIONS=true` и `SAAS_EPHEMERAL_E2E_CI=true`, вне точных
`PGHOST=127.0.0.1`, `PGPORT=5432`, `PGDATABASE=saas_ephemeral_test`
и при обнаружении Railway environment. Внешний процесс
ограничен `timeout --kill-after`. Это эксплуатационная страховка
и **не** доказательство индивидуального физического
`discard(connection)` в Bun.

## Что НЕ доказано даже после успешного CI

- Issuer и JWT RS256 — **SIMULATED**, ключи одноразовые; настоящий
  OIDC/SSO issuer, JWK rotation, revocation, replay/JTI не подключены.
- Actor directory и memberships — **SIMULATED in-memory**. Тест
  отзывает их после настоящего PostgreSQL COMMIT, но не доказывает
  атомарного согласования membership между двумя хранилищами.
- PostgreSQL RLS — реальный и защищённый подписанным scope,
  однако отсутствие строк для suspended tenant пока не имеет
  отдельного fail-closed domain status (200 empty vs 403/404).
  Потребуется backend-owned tenant-state gate и связанная snapshot
  семантика до production.
- SQL row allowlist — **metadata projection**, не полные
  `ControlResource` DTO. Публичный HTTP serializer и live Core
  metadata adapter не подключены.
- Audit — **in-memory SYNTHETIC/STAGING event**, без durable
  delivery, retention, tamper evidence и multi-replica guarantees.
- Bun.SQL 1.3.14 не получил доказанный individual physical discard
  и bounded cancel; 2G.1b обнаружил ограничения. CI adapter
  карантинирует **весь** pool и не допускает next tenant reuse.
- Нет настоящего Core, CPA Key Policy, Data Plane, SDK, клиентов,
  реальных аккаунтов/credentials/egress, маршрутизации AI.

Следующий инкремент: атомарная проверка snapshot/tenant activity
между DB и actor directory, тесты физического SQL discard и
устойчивости к сетевым отказам отдельного будущего backend.
Не объединять staging contract с production, пока не доказаны
эти свойства и не проведён отдельный security review.

См. [SECURITY_AUDIT_V1.ru.md](SECURITY_AUDIT_V1.ru.md),
[TRUSTED_SQL_READ_BOUNDARY_V1.ru.md](TRUSTED_SQL_READ_BOUNDARY_V1.ru.md),
[BUN_SQL_DRIVER_PILOT.ru.md](BUN_SQL_DRIVER_PILOT.ru.md),
[ROADMAP.ru.md](ROADMAP.ru.md).

## Подтверждённая проверка GitHub Actions (2G.4a)

На кодовом SHA `73066e254e5db2bdd6abeb479c75cae648fc9624`:

- [PG16 + настоящая JWT→RLS→Audit цепочка #38269435054](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269435054):
  **SUCCESS**. Логи подтвердили `PASS: stage 2G.4a synthetic JWT
  through real ephemeral PG16 signed RLS + redacted audit`.
  Проверены независимые Pool/Account/Egress grants, IDOR/invalid JWT,
  post-COMMIT revocation, failed audit и cancellation/quarantine.
- [Основной CI #38269435023](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269435023):
  **SUCCESS** — 1758 Bun unit-тестов / 0 ошибок, ESLint,
  TypeScript, Vite. Default-off HTML **3 305,72 KB**, unchanged.
  **Эти 1758 unit-тестов НЕ включают SQL E2E probe** — он выполнен
  отдельно внутри PostgreSQL workflow.
- [Opt-in demo #38269434999](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269434999):
  **SUCCESS**, HTML **3 386,51 KB**, unchanged.
- [Chromium QA #38269435126](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269435126):
  **SUCCESS**, синтетический browser QA.

**VERIFIED** только интеграция синтетического access-token и actor
mapping с настоящим PG16 RLS и redacted in-memory audit на временной БД.
Эти проверки НЕ подтверждают production OIDC, согласование
membership в разных хранилищах, durable audit, индивидуальный
physical discard Bun.SQL или настоящий Gateway/Core data-plane.

## 2G.4b — дополнение: active tenant и точная роль в БД

В E2E сценарий добавлены: suspended `demo-paused` при active server
membership, revoked `actor-db-revoked` в PostgreSQL при active
server actor snapshot, stale server `tenant-admin` против реальной
DB `tenant-auditor`. Два fixed SQL read gates до/после metadata
SELECT возвращают explicit generic 404 вместо `200 []` без раскрытия
tenant/resource IDs. Полный протокол и ограничения consistency:
[TENANT_DB_AUTHZ_GATE_V1.ru.md](TENANT_DB_AUTHZ_GATE_V1.ru.md).
**VERIFIED в staging-only PG16 #38272959201**
([Actions](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959201),
кодовый SHA `12a3b5ba2c9e32786773e369eb1b80195b75e4d8`),
не production tenant/session coherence.

## 2G.4c — отдельная signed transaction после COMMIT

Синтетический JWT → настоящий PG16 RLS E2E расширен
проверкой новой signed transaction после первого COMMIT.
Специальный **CI-only** `psql` mutator с фиксированными UPDATE
приостанавливает tenant, отзывает membership либо отключает
`grant-account` сразу после первого COMMIT. Повторный
SQL gate и read-set сравнение должны выдать generic 404,
без первоначальных rows и чужих resource IDs. Никакой
production admin SQL/HTTP endpoint не добавлен. Описание:
[POST_COMMIT_REVALIDATION_V1.ru.md](POST_COMMIT_REVALIDATION_V1.ru.md).
Статус этого инкремента до GitHub CI — IMPLEMENTED / NOT VERIFIED.

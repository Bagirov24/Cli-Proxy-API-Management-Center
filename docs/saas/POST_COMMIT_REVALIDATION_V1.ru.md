# SaaS Blueprint B — Stage 2G.4c: post-COMMIT signed RLS revalidation

**Статус: IMPLEMENTED / VERIFIED только в synthetic unit + ephemeral PG16 E2E на
кодовом SHA `6b47e92d2884d238b036e6539382cc4ed7a3383f`.** Не production
backend, не реальный OIDC, не атомарный механизм отзыва полномочий.
Все SQL reads идут через проверенный signed-scope boundary и
non-superuser `saas_ci_runner` к одноразовой PostgreSQL 16.6.

## Проблема после 2G.4b

Два signed DB gates **в одной** READ COMMITTED транзакции
проверяли tenant status, membership и роль до и после SELECT.
Однако сразу **после COMMIT** другой администратор мог:

- приостановить tenant;
- отозвать membership в приватной таблице PostgreSQL;
- отключить конкретный grant на Pool, Account или Egress.

Серверный synthetic actor directory мог остаться с прежней
membership, а полученный набор строк — устареть. Одна проверка
JWT/membership в RAM после SQL не выявляет DB-only отзыв.
Задача 2G.4c — fail-closed выявлять такие изменения в новой
подписанной PostgreSQL transaction **перед выдачей результата**,
не обещая невозможной без согласования хранилищ линейризуемости.

## Реализованный контракт

`trustedSqlReadBoundary.ts` сохраняет server-verified tenant,
collection, limit, access-token и AbortSignal в локальных
неизменяемых ссылках до первых асинхронных операций. Далее:

1. Проверка pinned synthetic `at+jwt`,
   `issuer+sub → trusted actor` и current RBAC как в 2G.4b.
2. Первый `readSignedScopedMetadata`: настоящее PostgreSQL RLS,
   два gate, фиксированный SELECT, field sanitation, COMMIT.
3. **Второй** `readSignedScopedMetadata` с тем же actor/tenant/role,
   collection и limit, но **новым** PostgreSQL txid и HMAC scope.
   Он проверяет current tenant status, membership/role, RLS и
   видимость конкретных Account/Pool/Egress grants. Произвольного SQL,
   raw client role, готовых provider secrets или живого AI-трафика нет.
4. Сервер сравнивает два полностью очищенных и упорядоченных
   результата. Любое отличие в строках/полях или длине, в том числе
   отозванный Account grant, вызывает generic **404 NOT_FOUND**.
   Старые metadata rows не выдаются. Redacted audit:
   `authorization-changed`, `tenantId:null`.
5. Если второй gate возвращает отказ, он транслируется в такой же
   generic **404**. При ошибке SQL/connection/timeout/несовместимом
   ответе — generic **503** и безопасный quarantine/cleanup;
   никакой silent allow или rollback error masking.
6. Только после успешной второй DB транзакции повторно проверяются
   та же JWT, trusted actor mapping, member/role. Audit sink
   остаётся синхронным, обязательным и secret-free.

Это дорогой **двойной read-эксперимент**, не предложенный как
финальная production реализация. Текущая область — только
изолированный metadata control plane. Она не делает данные
immutable, не блокирует конкурентных writers и не гарантирует,
что отзыв не произойдёт ПОСЛЕ повторной проверки.

## Проверяемые угрозы

| Сценарий | Staging ожидание |
| --- | --- |
| Active North/Orbit, неизменные grants | Allow 200, идентичные списки двух SQL transactions |
| Suspended tenant *после первого COMMIT* | Второй gate Deny, 404, без rows/tenant в ответе |
| Revoke DB membership *после первого COMMIT* | Второй gate Deny, 404 |
| Disable shared Account grant *после первого COMMIT* | Второй SELECT видит другой набор, 404 без shared Account ID |
| Изменение collection/tenant/limit объекта request во время await | Сохранённый verified scope, тот же SELECT/params в обеих транзакциях |
| Abort во второй SQL transaction | Generic 503, quarantine, никаких stale rows |
| Успешный Confirmed ROLLBACK на Deny | Отдельное чистое подключение для следующего tenant |
| Malformed SQL, недоступный signer/sink | 503, ни SQL errors, ни ключи не логируются |

`tests/saasTrustedSqlReadBoundary.test.ts` проверяет эти
свойства на synthetic fake pool. Новые real PostgreSQL probes в
`scripts/saas-staging/verify-trusted-pg-e2e.mjs` используют
**только CI-fixture admin writer**: заранее фиксированные UPDATE
`saas_rls.tenants`, `saas_rls.memberships` и `saas_rls.resource_grants`
в одноразовой DB через отдельный `psql` process **после первого
COMMIT**, перед второй signed transaction. Reader SQL остаётся
non-superuser и имеет только allowlisted SELECT. Writer не является
частью SaaS backend, не принимает клиентские SQL и не имеет пути
к Railway. Тестовые изменения возвращаются к исходному статусу.

## Security limitations / что остаётся SPEC

- **Гарантии атомарного отказа нет.** Между вторым COMMIT, повторной
  проверкой actor, audit sink и моментом доставки HTTP ответа
  конкурентный writer может снова отозвать право. Для production
  необходим авторитетный revision/snapshot, протокол invalidation
  либо серилизованная модель с доказуемым порядком revocation.
  Выбор механизма ещё **PROPOSED**.
- Double SELECT сам по себе не доказывает consistent snapshot
  для изменяющейся схемы, рекурсивных ссылок или pagination.
  Для списка с LIMIT возможно вытеснение строк; расхождение
  детектируется и трактуется как Deny, но отсутствие отличий
  не доказывает неизменности всей таблицы.
- Actor directory, JWT issuer, ключи — только SYNTHETIC. Не подключены
  live OIDC, JTI replay, SSO session revocation, DB-backed owner store.
- Bun.SQL 1.3.14 имеет нерешённый individual physical discard;
  quarantining whole-pool — только CI hardening.
- Metadata rows не являются полными `ControlResource` DTO; HTTP
  endpoint, durable audit, CPA Core, Gateway и AI data-plane
  enforcement не внедрены.
- Двойная транзакция увеличивает latency и нагрузку; это
  staging security acceptance, не производственный SLA.

Связанные спецификации:
[TENANT_DB_AUTHZ_GATE_V1.ru.md](TENANT_DB_AUTHZ_GATE_V1.ru.md),
[E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md](E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md),
[SECURITY_AUDIT_V1.ru.md](SECURITY_AUDIT_V1.ru.md) и
[ROADMAP.ru.md](ROADMAP.ru.md).

## GitHub Actions — подтверждённый результат 2G.4c

Кодовый SHA `6b47e92d2884d238b036e6539382cc4ed7a3383f`:

- [CI #38275287907](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287907):
  **SUCCESS, 1 767 Bun unit-тестов, 0 fail, ESLint, TypeScript, Vite**.
  Default-off HTML: **3 305,72 KB**, без прироста.
- [PostgreSQL #38275287696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287696):
  **SUCCESS** на настоящем disposable PG16; логи содержат
  `PASS: after-COMMIT real PG16 tenant/member/grant revocation returns
  404 and hides old rows`. В этих tests привилегированный SQL используется
  только fixture writer после первого COMMIT; читатель остаётся
  `saas_ci_runner` без private SELECT/credentials.
- [Opt-in SaaS Demo #38275287915](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287915):
  **SUCCESS**, **3 386,51 KB**, unchanged.
- [Chromium QA #38275287939](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287939):
  **SUCCESS**, synthetic browser QA.

Первый CI на SHA `e72ff2d` подтвердил 1 767 passing unit-тестов
и PostgreSQL E2E, но остановился на ESLint `prefer-const` в
synthetic request-mutation test. Это исправлено в
`6b47e92`, затем полный CI был запущен повторно и успешно завершён.

**VERIFIED** относится лишь к bounded/staging post-COMMIT detection,
не к atomic revocation после второй транзакции, real OIDC, production
SQL-driver lifecycle, durable audit или реальной сетевой маршрутизации.

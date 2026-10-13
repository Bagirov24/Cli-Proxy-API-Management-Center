# M1b — CI-only сквозной Auth → signed PostgreSQL16 project write

**Статус: STACKED DRAFT / NOT PRODUCTION / NO MERGE AUTHORIZATION.**
Новая M1b ветка от HEAD [M1a PR #4](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/4);
новый PR имеет базой feature-ветку PR #4, а M1a — Draft PR #3.

## Реально выполняемый CI-only вертикальный срез

1. Скрипт `scripts/saas-staging/verify-m1-project-pg-e2e.mjs` запускается
   **только в GitHub Actions с флагом** `SAAS_EPHEMERAL_M1_PG_CI=true`
   на точно заданном `127.0.0.1:5432/saas_ephemeral_test`, без URL
   от клиента и без production/Railway. Применён временный `saas_ci_runner`
   с новым случайным паролем в CI job.
2. RSA-2048 создаётся в памяти. Реальный RS256 access token (`typ=at+jwt`)
   проверяется существующим pinned verifier (issuer, audience, exp/iat, sub,
   kid, подпись). Нет OIDC discovery или внешнего issuer.
3. Серверные синтетические issuer+subject→actor и membership проходят
   через существующий `createM1ProjectCommandBoundary`. Клиентские
   `actorId`, `tenantId` и role из JWT не дают прав.
4. CI adapter получает одну зарезервированную Bun.SQL connection,
   выполняет `BEGIN`, `txid_current()`, signing actor/tenant/txid/expiry
   случайным job-local HMAC, пять `SET LOCAL` GUC, `SET LOCAL ROLE`
   только `saas_m1_project_executor`, затем одну из фиксированных
   параметризованных SQL-функций M1a. Signed-scope / active tenant /
   current membership / role повторно проверяются на стороне реальной PG16.
5. Зафиксированный COMMIT — success. Deny/stale CAS возвращает false только
   после подтверждённого ROLLBACK. Неопределённая операция/COMMIT — generic
   503, синхронный карантин **всего disposable pool**, никакого retry.
6. SQL `tests/sql/saas_m1_pg_driver_role.test.sql` даёт временному runner
   право SET ROLE **только после** исходных M1a SQL acceptance; не даёт
   прямого SELECT/INSERT/UPDATE/DELETE приватной таблицы или ключей signer.

## Негативные и функциональные проверки

- Verified synthetic admin create → duplicate denial → sanitized get →
  rename CAS → stale version deny → soft-disable → no reactivation.
- Viewer/auditor, cross-tenant, wrong audience, поддельные JWT actor/role
  не проходят server-side authorisation.
- При DB membership revocation, несмотря на всё ещё активный server
  snapshot, реальная PostgreSQL signed function отказывает записи.
- Тестовый adapter намеренно теряет локальный ACK *после фактического
  PostgreSQL COMMIT*. Caller получает 503, pool карантинируется, никакого
  автоматического повторения; новая здоровая signed read-транзакция видит
  уже закоммиченный project. Это **НЕ exactly-once** и НЕ recovery.
- Никакого listener, реального frontend или Core/CPA/AI routing,
  OAuth credentials, API tokens клиентов, egress, Railway или production DB.

## Ограничения и hard stops

**Проверка показывает лишь безопасность ограниченного CI-пилота**, а
не готовый SaaS API. Adapter существует только в `scripts/saas-staging/`,
не подключается к runtime. Не решены OIDC/SSO, dynamic JWKS/rotation,
durable sessions, cross-replica revocation, release-ready physical discard,
network partitions, cancellation у повреждённого драйвера, атомарная
tenant authorization fencing, durable write audit outbox, retention,
idempotency при UNKNOWN COMMIT, real control API или Core integration.

SQL 020 остаётся staging-only. SQL 019 не применять. CI 4/4 на
конечном HEAD требует отдельной проверки и явного одобрения перед merge.
`gcPermitted=false`; никаких production deployments, UUID/CPA key mint,
retry/reissue/repair/delivery/archive/GC, изменений Railway signer/journal,
volume или API endpoints.

**Дальше:** независимый transactional audit/outbox + точная семантика
UNKNOWN COMMIT; физический discard/cancel/partition proof на отдельном
driver; после review — private HTTP только с настоящими server sessions.

У существующих синтетических Railway mTLS сертификатов документирован
срок истечения **15 октября 2026, 13:33 UTC**. Этот PR их не заменяет.
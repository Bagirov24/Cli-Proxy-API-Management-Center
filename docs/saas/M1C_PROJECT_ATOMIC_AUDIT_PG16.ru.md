# M1c — атомарный PostgreSQL16 audit/outbox для изменений проектов

**Статус: STACKED DRAFT / CI-ONLY / NOT PRODUCTION.**
Новая ветка M1c создаётся от HEAD [M1b PR №5](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/5);
M1b сам находится поверх Draft PR №4, затем Draft PR №3.
До отдельного code/security review и прямого разрешения владельца никакой merge/deploy недопустим.

## Реализуемая ограниченная модель

Новый staging-only SQL 021 `staging/saas-rls/021_m1_project_atomic_audit_pilot.sql`
исполняется **только** на disposable `saas_ephemeral_test` от `postgres` с явным
`saas.staging_only=true`. Не применять его к production PostgreSQL.
Миграция 019 по-прежнему запрещена.

- `saas_m1_private.project_write_audit_outbox` — отдельная приватная таблица
  с `ENABLE + FORCE ROW LEVEL SECURITY`, `UNIQUE(tenant_id,project_id,project_version)`,
  DB txid, авторизованной actor ID, revision, типом операции и timestamp.
  **Нет** project name, bearer, JWT, секретов, SQL-текстов, тела ответа,
  credential, provider key и tenant API endpoint.
- Audit function `saas_m1_private.append_project_write_audit` вызывается
  триггером `AFTER INSERT OR UPDATE` над существующими M1a project rows.
  Триггер обслуживает только `create` / `rename` / `disable`, строго
  проверяет переход версии и текущую PostgreSQL signed authorization revision.
- `saas_m1_audit_owner` — отдельный `NOLOGIN/NOINHERIT/NOBYPASSRLS` владелец
  таблицы и `SECURITY DEFINER` trigger. M1 project owner и non-superuser
  executor не получают прав INSERT/SELECT/UPDATE/DELETE на outbox.
  `saas_ci_runner` и `saas_rls_reader` не видят приватную таблицу.
- При ошибке записи в audit/outbox триггер **выдаёт исключение**; M1a функция
  перехватывает ошибку и возвращает deny, её PL/pgSQL subtransaction
  откатывает provisional project write. Это не независимый audit sink,
  а единая commit/rollback граница для проекта и приватной audit строки.
- UPDATE и DELETE записей аудита заблокированы специальным триггером.
  SQL 021 можно переиграть на disposable fixture без очистки существующих
  rows и версий. Суперпользователь / DDL / snapshot rollback **обходят**
  этот контроль: это НЕ tamper-evident WORM, независимый high-water или DR.

## Adversarial acceptance

Workflow `.github/workflows/saas-staging-rls-ci.yml` запускает M1a SQL acceptance
без изменений, выдаёт временному runner только право SET ROLE executor,
устанавливает SQL 021, запускает существующий **реальный Bun.SQL M1b E2E**,
после чего проверяет `tests/sql/saas_m1_project_atomic_audit.test.sql`.

Проверяются:

1. Настоящий M1b pinned RS256 → trusted actor → подписанный PG16 transaction
   выдаёт **ровно три** audit events для проекта после create/rename/disable.
   Неудачный CAS, duplicate, revoked membership, чужой tenant, viewer и auditor
   не добавляют audit events.
2. При тестовом lost COMMIT ACK после **фактического PG COMMIT** server
   возвращает 503 и карантинирует весь disposable pool, но другой PG
   observer видит **один** committed audit и проект. Ни автоматического
   retry, ни восстановления с неизвестным результатом M1c не добавляет.
3. PostgreSQL `ROLLBACK` удаляет **и** provisional project, **и** audit event.
4. Принудительный UNIQUE collision в private outbox (привилегированный
   тестовый fault injection) запрещает project INSERT — **не существует
   committed проекта без обязательного аудита**; fixture полностью откатывается.
5. Права NOLOGIN/NOINHERIT, append-only SQL UPDATE/DELETE denial, отсутствие
   secret-bearing columns, повторная установка SQL 021 без потери событий.

**ВАЖНО:** записи, сделанные в M1a **до установки** триггера M1c,
не получают задним числом audit events. Это ожидаемо для одноразового
пилота, но неприменимо к production schema без плана миграции и backfill.

## Чего этот этап НЕ доказывает

- Истинное exactly-once, восстановление UNKNOWN COMMIT, idempotency keys,
  проверку конфликтующих операций между разными репликами, session replay/jti.
  CAS только отбрасывает stale versions; повторный вызов API после 503
  **не выполняется**.
- Atomic tenant revocation fence сквозь issuer-store и PG, сериализацию
  изменений авторизации после COMMIT, стабильность token-bound sessions.
- Независимый и неизменяемый audit ledger, WORM/HSM, outbox delivery
  worker, recipient ACK, retention, физическую невозможность отката
  общим PostgreSQL администратором.
- Production SQL pool/discard/timeout/network partition, real OIDC/SSO,
  public SaaS HTTP CRUD, Core/CPA, реальные provider accounts или keys.

## Дальше

M1d — разработать *только после отдельной проверки*: серверные
authorization epochs и commit fencing, durable operation uncertainty record,
без автоматического retry/repair/delivery; отдельно проверить безопасный
physical connection discard и bounded cancellation.

**Hard stops:** no merge/Ready/deploy, no Railway changes, SQL019,
production DB, UUID/CPA issuance, retry/reissue/reuse/delete, archive/GC.
`gcPermitted=false`. Старые синтетические Railway TLS certificates истекают
**15.10.2026 13:33 UTC**; здесь они не меняются.
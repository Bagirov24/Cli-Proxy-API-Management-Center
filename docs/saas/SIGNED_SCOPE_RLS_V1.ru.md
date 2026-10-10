# SaaS Control / PostgreSQL RLS — подписанный контекст транзакции v1

**Статус: VERIFIED только в ephemeral PostgreSQL 16 GitHub Actions.**
Это security-прототип, а не настроенный OIDC, production tenancy или
безопасный SQL endpoint.

## Почему понадобился этап 2D

SQL-пилот 2C использовал пользовательские PostgreSQL GUC
`saas.actor_id` и `saas.tenant_id`. Эти значения разрешено изменять
любому пользователю своей SQL-сессии. Поэтому они **не могут
удостоверять личность** и без дополнительной защиты допускают
имперсонацию в случае выполнения произвольного SQL.

Добавлена вторая, отдельная миграция:

`staging/saas-rls/002_signed_scope_pilot.sql`

Миграция 001 остаётся базовой; 002 в тестовом сценарии применяется
**после** 001. Внутри ephemeral PostgreSQL создаётся закрытая
`saas_rls_private.scope_signers` с 256-битным случайным HMAC-ключом.
Ключ генерируется **во время теста**, в GitHub не хранится и не
передаётся в приложение. Роль `saas_rls_reader` не имеет
`USAGE` на private schema, `SELECT` на ключе и `EXECUTE` на тестовой
функции подписания.

## Модель тестовой подписи

В доверенной транзакции создаётся набор:

- actor ID и tenant ID, которые будущий backend обязан получить
  только из **проверенной SaaS-сессии**;
- PostgreSQL transaction ID из `txid_current()`;
- UTC expiry в Unix seconds с максимальным окном 15 минут;
- MAC = HMAC-SHA256 над последовательностью этих четырёх полей.

Подписанный набор хранится в **transaction-local** GUC:
`saas.scope_actor`, `saas.scope_tenant`, `saas.scope_txid`,
`saas.scope_expiry`, `saas.scope_mac`. SQL-функция
`saas_rls_private.scope_verified()` проверяет формат, срок, совпадение
transaction ID и MAC с закрытым ключом. Все RLS-предикаты
`scope_tenant()`, `read_allowed()` и `resource_granted()` из
миграции 001 переопределены так, чтобы отказывать при неверной подписи.
Старые `saas.actor_id` / `saas.tenant_id` более не принимаются.

Для тестов **только под superuser** в
`tests/sql/saas_rls_signed_scope.test.sql` создана вспомогательная
`saas_rls_test.issue_scope()`. Она не выдана read роли и не
предназначена для развертывания с пользовательским SQL-доступом.

## Что именно проверено в CI

- Без MAC и при поддельных старых/новых GUC — **0 доступных строк**.
- При корректно подписанном North actor — только его tenant,
  собственные и отдельно разрешённые ресурсы.
- Подмена `scope_actor` или `scope_tenant` при старом MAC блокируется.
- Только заново подписанный Orbit actor видит собственные записи.
- Роль auditor, отозванная membership, suspended tenant и истёкшая
  подпись не повышают доступ.
- Подмена expiry без пересоздания MAC блокируется.
- Подпись **из другой транзакции** не открывает записи даже при
  копировании всех пяти полей.
- Отзыв grant на аккаунт немедленно скрывает его и обе связи;
  истечение grant на пул скрывает routing references.
- Миграции 001 и 002 воспроизводимо применяются дважды в тестовой БД.
- Старый contract-тест этапа 2C продолжает проходить отдельно до
  установки миграции 002.

Workflow: `.github/workflows/saas-staging-rls-ci.yml`.
Запуск проходит только на GitHub-hosted **временном** PostgreSQL 16.
Для проверки используется `psql -v ON_ERROR_STOP=1`, без Railway,
Core, OAuth, реальных учётных данных и deploy.

## Что всё ещё НЕ гарантируется

**Это не готовая система authentication/authorization.**
Недоверенный пользователь, которому позволен произвольный SQL
в рамках **своего** валидно подписанного scope, по-прежнему опасен:
он может свободно читать всё, что разрешает этот scope, либо
использовать другие доступные ему SQL-возможности. Поэтому:

1. **Нельзя** выдавать клиентам SQL-доступ к `saas_rls_reader`.
2. Источник actor/tenant и доверенная процедура подписания требуют
   отдельного защищённого server-side OIDC/session-порта, проверенного
   issuer/audience/expiration и ревокации.
3. Необходимы параметризованные, типизированные SQL-запросы,
   ограниченный набор backend действий, review SQL injection,
   отдельные read-credentials и гарантированная очистка connection pool.
4. Подпись доступна для повторного использования **в рамках исходной
   транзакции**; она не предотвращает злоупотребления на уже
   скомпрометированном соединении/транзакции. Привязка к txid в этом
   пилоте также создаёт накладные расходы на назначение transaction ID.
5. Нужны threat model, настоящая ротация ключей, защита от side-channel,
   управление временем/TTL, RLS performance, миграции rollback/replay
   и отдельный security review.
6. SQL-пилот не подключён к локальному HTTP-обработчику,
   UI, Core или Railway и не управляет реальными AI-запросами.

## Согласование маршрутов

Слой `readSyntheticTenantCollection` приведён к PostgreSQL RLS:
**если у клиента нет отдельного grant на pool, правило маршрутизации
целиком не возвращается**. Для доступных правил `poolId` всегда string;
частичный rule с `poolId: null` больше не является контрактом.
`safeTransport.ts` отвергает подобный некорректный ответ адаптера.
При этом Account.egressProfileId по-прежнему может быть null, а
Pool.accountIds фильтруются по независимым account grants.

В демонстрационной request-flow визуализации можно отдельно показывать
нейтральную причину DENY; это **не** означает раскрытие чужого pool ID в
tenant-scoped metadata API.

**Следующий гейт:** дизайн настоящего issuer-verified OIDC-порта,
защищённого backend-owned transaction scope, connection-pool lifecycle
и SQL-injection тестов только на staging, с отдельным согласованием
до любой production интеграции.

## Этап 2E — новый signer/query port, без боевых ключей

`createPinnedHmacScopeIssuer` в TypeScript формирует MAC
в том же формате (разделитель ASCII 31), что и SQL 002.
`readSignedScopedMetadata` получает transaction ID от БД,
назначает подписанные transaction-local GUC и снижает роль до
`saas_rls_reader` перед строго параметризованным SELECT.
Это **только тестируемый порт**: ключ берётся из injected
fixture, реальной его ротации/синхронизации с БД не существует.
No driver, no real OIDC, no production DB. SQL CI отдельно
проверяет hostile `PREPARE` параметр и cleanup того же соединения.
[IDENTITY_SQL_BOUNDARY_V1.ru.md](IDENTITY_SQL_BOUNDARY_V1.ru.md).

## Этап 2F — синтетический HMAC передаётся реальному DB-драйверу в CI

Временный CI superuser отдельно извлекает ephemeral HMAC fixture
из закрытой PostgreSQL таблицы, кратковременно передаёт test driver
процессу и не публикует значение в логах. Сам read-only
`saas_ci_runner` **не может** читать эту таблицу.
`readSignedScopedMetadata` подписывает txid, RLS перепроверяет
MAC в DB. Для production такой механизм передачи секрета неприемлем
без отдельного signer service, key rotation и security review.


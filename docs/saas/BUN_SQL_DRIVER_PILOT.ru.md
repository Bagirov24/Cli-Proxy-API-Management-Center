# Этап 2F — Bun PostgreSQL driver + tenant RLS acceptance (RU)

**Статус: VERIFIED на ephemeral PostgreSQL 16 в GitHub Actions
[#38086896433](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38086896433);
реальный SaaS backend — PROPOSED.** Bun.SQL здесь выполняет
действительные SELECT через PostgreSQL wire protocol, но только
с вымышленными fixtures. Нет deployable endpoint или Core metadata adapter.

## Реализованный изолированный стенд

- `scripts/saas-staging/verify-bun-postgres.mjs`: интеграционный
  тест поверх встроенного в Bun 1.3.14 PostgreSQL-драйвера
  (`SQL.reserve()`, `unsafe(sql, boundValues)`, `cancel()`,
  `release()/close()`). Этот скрипт **не импортируется** в React
  или Management Center и **не создаёт HTTP endpoint**.
- `tests/sql/saas_driver_fixture.test.sql`: временная login-роль
  `saas_ci_runner` с NOINHERIT/NOBYPASSRLS, без привилегий
  суперпользователя, записи и прямого чтения private signing key,
  memberships/grants. Роль может `SET LOCAL ROLE saas_rls_reader`
  только внутри scoped read transaction.
- Фикстуры: North Studio, Orbit Lab, приостановленный tenant,
  собственные проекты, приложения, CPA bindings, пулы/аккаунты/
  egress и платформенный Account/Pool/Egress с **тремя**
  самостоятельными grants.
- GitHub Actions `saas-staging-rls-ci.yml` применяет SQL 001/002,
  запускает SQL acceptance, создаёт временные фикстуры, а затем
  проверяет Bun-драйвер. PostgreSQL слушает только loopback runner.
- Runtime guard скрипта требует GitHub Actions +
  `SAAS_EPHEMERAL_DRIVER_CI=true`, запрещает production/Railway.
  Тестовый PostgreSQL host/database/user **жёстко закреплены**:
  `127.0.0.1:5432 / saas_ephemeral_test / saas_ci_runner`.
  Не принимает `DATABASE_URL` для перенаправления на другую базу.
- Роль `saas_ci_runner` получает **случайный временный пароль**
  длиной 48 hex-символов, создаваемый заново в каждом GitHub Actions
  job. В GitHub/repo не сохраняется рабочий пароль этой роли.
- 256-битный HMAC key существует только в ephemeral SQL fixture
  `saas_rls_private.scope_signers` и кратковременно передаётся
  отдельному test driver процессу. Ни в репозитории, ни в логах CI
  не публикуется; **никаких Railway secrets** не используется.

## Границы транзакции

На каждый запрос:

1. Зарезервировать соединение (при отмене ожидания — отказ).
2. `BEGIN` и реальный `txid_current()`.
3. Вычислить HMAC actor/tenant/txid/expiry с синтетическим ключом.
4. Установить пять полей через `set_config(..., true)`
   (`SET LOCAL`), затем `SET LOCAL ROLE saas_rls_reader`.
5. Выполнить **один exact-allowlisted SELECT**, только с
   PostgreSQL placeholders для tenant/limit.
6. Whitelist DTO, `COMMIT`, `release`; при ошибке/отмене
   `ROLLBACK` и запрет повторного использования повреждённого
   соединения.
7. Отказать без выдачи исходного SQL, credential values или текста
   внутренних исключений.

В Bun 1.3.14 `ReservedSQL.release()` не имеет аргумента
`discard`. При тестировании выявлено, что сочетание
`ReservedSQL.close({timeout:0})` и последующего
`SQL.close()` зависает при shutdown. Поэтому при отказе
**помечается непригодным и закрывается ВЕСЬ staging-pool**, а
последующие `connect()` на нём запрещены. Это fail-closed обходное
решение только для одноразового теста, не production-конструкция.
Необходим driver с документированным атомарным
`discard(connection)`, проверкой аварийного закрытия и
isolated-pool failover.

## Проверки на реальном драйвере (ephemeral)

- Одновременные read-only запросы от двух разных tenants; в выдаче
  North не встречаются Orbit projects/accounts и наоборот.
- Самостоятельные grants на платформенные ресурсы; Orbit их не видит.
- Роль auditor без прав на accounts; tenant без membership не виден;
  suspended tenant не раскрывает проекты.
- Нативный Core binding типа `core-native` не возвращается
  ни при разрешённом tenant.
- Переключение North→Orbit с повторным использованием DB connection
  не переносит `SET LOCAL ROLE`, actor GUC или MAC.
- Отказ при неправильной роли, отмене и query timeout-policy;
  закрытие всего staging-pool при discard вместо скрытого reuse.
- SQL injection smoke, deny for ungranted pool-routing, а также
  подписанный HMAC и запрет replay проверяются отдельными SQL-сценариями.

**Проверено:** GitHub Actions #38086896433 завершился `SUCCESS`.
12 конкурентных read-only запросов, pool-reuse, deny без членства,
CPA-only bindings и shutdown после discard отработали на настоящем
PostgreSQL 16 с Bun.SQL. Это не доказывает готовность к
production-нагрузке, OAuth/SSO или успешный Core metadata adapter.

## Что пока только SPEC/PROPOSED

- Реальный OIDC/SSO issuer, token/JWKS refresh, trusted actor directory,
  session revocation, production audit/RBAC и security testing.
- Реальный backend identity → SQL transaction signer; защищённое
  хранение и ротация HMAC, не тестовый случайный fixture.
- Высокая нагрузка, ограничения statement/query deadlines,
  отказоустойчивый production pool, pgBouncer/TLS/mTLS и
  rollback при сетевом разрыве.
- Production SQL migration tool, восстановление/backup, pagination,
  cursor consistency, costs/billing, error budgets.
- Core/CPA metadata bridge, VPN/proxy fail-closed enforcement и UI
  real-data integration.

Следующий небольшой этап — прочный staging adapter поверх
**разрешённого** read-only metadata source с полноценной серверной
AuthZ/revocation и тестами отсутствия IDOR; не подключать
production без отдельного согласия.

Документы:
[IDENTITY_SQL_BOUNDARY_V1.ru.md](IDENTITY_SQL_BOUNDARY_V1.ru.md),
[STAGING_POSTGRES_RLS_V1.ru.md](STAGING_POSTGRES_RLS_V1.ru.md),
[SIGNED_SCOPE_RLS_V1.ru.md](SIGNED_SCOPE_RLS_V1.ru.md).

## Этап 2G.1 — ограниченная отмена (CONTRACT, не production driver)

SQL boundary больше не полагается на бесконечное ожидание cleanup:
срок выполнения запроса по умолчанию 15 секунд, срок одного cleanup
по умолчанию 1 секунда; оба значения задаёт только backend.
AbortSignal прокидывается в SQL-port на каждый запрос. По таймауту
выполняющегося statement результат отбрасывается, пул синхронно
карантинируется до cleanup. **Promise timeout не останавливает
физический SQL:** если драйвер игнорирует cancel, нельзя отправлять
ROLLBACK параллельно незавершённому statement. Поэтому в этой ситуации
ROLLBACK пропускается, соединение отбрасывается, весь CI-pool
блокируется для новых резервирований. Поздно выданное соединение
также подлежит discard.

Bun native SQL 1.3.14 не предоставляет подтверждённый в этом пилоте
atomic `discard(connection)`; сценарии реальных сетевых потерь,
зависаний socket shutdown, recovery и reuse после cancel остаются
**PROPOSED**, несмотря на synthetic adversarial regression tests.
Production адаптер обязан подтвердить quarantine и своевременное
физическое закрытие транспортного соединения отдельно.

## Дополнение 2G.1b — native отмена и controlled pool replacement

**Испытание staging-only, итоговый статус определяется по CI на
конкретном commit.** Для первого bounded security инкремента добавлены
adversarial unit-тесты (2G.1) и fault-probes Bun.SQL 1.3.14 с настоящим
ephemeral PG16 (2G.1b).

Протокол новых native проверок:
1. `max=1`, одна reserved connection занята; ожидание второго
   `reserve({signal})` отменяется. Старый pool переводится в карантин:
   дальнейшие tenant reads на нём не разрешены; другой tenant допускается
   только на *новом* pool c новой подписанной транзакцией и RLS.
2. `BEGIN` + **server-side** `SET LOCAL statement_timeout` +
   `SELECT pg_sleep(2)`: запрет продолжать aborted transaction до
   подтверждённого `ROLLBACK`; проверка role/GUC reset.
3. `Query.cancel()` во время выполняющегося SQL в отдельном пуле:
   дождаться реальной PostgreSQL/Bun cancellation error, не принять
   один только истёкший JS timer как доказательство отмены. После
   эксперимента весь pool закрывается.
4. Создаётся совершенно новый pool, выполняются независимые
   North/Orbit signed RLS reads. Старый quarantined pool не
   разблокируется.
5. Для тестовых шагов установлены индивидуальные deadline и внешний
   GitHub Actions `timeout --kill-after`. **Это проверка timeout
   процесса, а не гарантированное физическое отключение сокета
   в произвольной неисправной библиотеке.**

### Сравнение возможных драйверов (выбор production НЕ сделан)

| Вариант | Подтверждённый интерфейс | Неразрешённый риск |
| --- | --- | --- |
| Bun.SQL 1.3.14 | `reserve({signal})`, `Query.cancel()`, `ReservedSQL.release()`, `SQL.close({timeout})` | `release()` возвращает connection; атомарный **individual discard не подтверждён**; наблюдалось зависание `ReservedSQL.close()` + закрытие пула |
| node-postgres (`pg.Pool`) | Документированный `client.release(true)` удаляет отдельный client, вместо его возврата | Отдельно проверить query cancellation, pool starvation, TLS/network split, async `end()` и фактический multi-tenant RLS reset |
| Postgres.js | `reserve().release()` и `sql.end({timeout})` | Нужен проверенный per-client forced discard; само завершение всего pool не заменяет независимого delete |

Документация интерфейсов:
- [Bun ReservedSQL](https://bun.com/reference/bun/ReservedSQL).
- [node-postgres pooling](https://node-postgres.com/apis/pool).
- [Postgres.js README](https://github.com/porsager/postgres#connection-pooling).

**Решение:** не подключать новый SQL-драйвер и не выдавать Bun
native close/cancel за production-гарантии до независимого
adversarial acceptance, включая отключение network и отказ rollback.
Любой fail-closed quarantine блокирует дальнейшие выдачи из
повреждённого pool; восстановление только через отдельно созданный
pool при доказанной очистке/уничтожении старого.

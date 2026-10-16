# M1e — реальный PostgreSQL16 backend loss, отмена запроса и карантин CI-пула

**Статус: STACKED DRAFT / CI ONLY / NOT PRODUCTION.** Новый M1e PR основан
на ещё не смерженном [M1d PR №7](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/7),
далее PR №6 → №5 → №4 → №3. Никого из них не мержить и не превращать
в Ready без отдельного code/security/operator review.

## Угроза и узкая область эксперимента

В M1b уже доказан **симулированный lost ACK ПОСЛЕ подтверждённого реального
PostgreSQL COMMIT**: вызывающий порт отдаёт generic 503, попыток повторной
записи нет, а новая транзакция находит одну запись. В M1c аудиторский outbox
пишется в тот же PostgreSQL COMMIT, M1d сериализует подписанную запись
с изменением tenant authorization revision.

В M1e дополнительно проверяется **физическая потеря соединения ДО COMMIT**
и **AbortSignal ПОСЛЕ успешной mutation+audit, но ДО COMMIT**. Эти исходы
имеют разную физическую судьбу транзакции; ошибка 503 **не является
доказательством отсутствия или наличия COMMIT**, поэтому никакой
автоматический retry, reissue или exactly-once не вводится.

В существующем, **не импортируемом в runtime**, скрипте
`scripts/saas-staging/verify-m1-project-pg-e2e.mjs` добавлен отдельный
необязательный `beforeCommit` fault-hook. Он вызывается только после
реальной signed-scope SQL-функции create и её обязательного M1c audit
INSERT, но до попытки `COMMIT`; он получает фактический
`pg_backend_pid()` с зарезервированной Bun.SQL connection.
Хук и проверки запускаются только при
`GITHUB_ACTIONS=true` + `SAAS_EPHEMERAL_M1_PG_CI=true` +
`SAAS_EPHEMERAL_M1E_DISCONNECT_CI=true` в точно заданной
`127.0.0.1:5432/saas_ephemeral_test` с синтетическим actor и
случайным CI-only signing key. Тестовый DB password не копируется
в новые файлы/логи. Production-адаптера или публичного HTTP нет.

## Набор отрицательных испытаний

1. **Физически убитый backend до COMMIT.** Privileged *другая*
   fixture connection вызывает `pg_terminate_backend(pid)` по
   целочисленному PID из фактической Bun.SQL сессии и подтверждает
   `terminated`. Порт отдаёт sanitized 503, пул синхронно
   помечен `poisoned`, подтверждённых COMMIT = 0. Повторное
   обращение к **этому же** объекту writer получает 503 без второй
   резервации/попытки записи. Проверяется отсутствие PostgreSQL PID.
   Отдельная подписанная READ и привилегированная SQL-проверка
   подтверждают **0 project / 0 audit** после потери backend.
2. **Отмена непосредственно до COMMIT.** AbortSignal меняется
   только в CI fault-hook, уже после успешного DB INSERT и private
   audit. Порт возвращает 503, весь CI-only pool карантинируется,
   старый PG backend обязан исчезнуть, другая операция через
   этот pool не получает резервации. Наблюдатель подтверждает
   **0 project / 0 audit**.
3. **Уже закоммиченная транзакция, локальный ACK потерян.**
   Сохранённый M1b сценарий возвращает 503, но fresh signed observer
   и independent PostgreSQL fixture видят **1 project + 1 audit**
   без повторов. Принципиально запрещено трактовать 503 как
   `never committed`.
4. `tests/sql/saas_m1_physical_disconnect.test.sql` отдельно
   подтверждает 0/0 для обеих сбойных операций и 1/1 для
   подтверждённого COMMIT, отсутствие привилегий runner на audit
   или signer keys, FORCE RLS. Остальные M1a–M1d SQL и Bun
   regression tests остаются обязательными.

## Точный статус гарантий

- **Это НЕ физический discard одной повреждённой connection
  в production-пуле.** `db.close({timeout:0})` изолирует **весь**
  disposable pool, в CI проверено исчезновение конкретных PG PIDs,
  но нет доказательства при сетевой partition, разных драйверах,
  leak после падения самого процесса или работе нескольких реплик.
- Нет успешной атомарной записи внешней durable recovery intent,
  реестра idempotency, операторской процедуры подтверждения
  UNKNOWN COMMIT на независимом корне или независимого WORM/HSM.
- Test hook вызывается в JavaScript между mutation и COMMIT.
  Тест не создаёт реальный сетевой разрыв **во время** COMMIT;
  неконтролируемая потеря ACK по обе стороны COMMIT остаётся
  потенциально неопределённой. Автоматическая повторная
  выдача/продолжение запрещена.
- Поскольку M1e запускается в том же workflow после M1c,
  но до установки 007/008/022 M1d, сам physical-loss сценарий
  подтверждает атомарность **M1c** аудита и fail-closed M1b
  adapter. M1d race/fence доказывается отдельными более
  поздними PG16 тестами в том же job, **не в fault-hook M1e**.
- Нет реального OIDC/SSO, token/session revocation,
  human-signoff процесса, public SaaS CRUD endpoint, Core/CPA,
  продуктивной PostgreSQL schema, Archive или GC.

## Railway TLS — отдельная срочная задача

Срок тестовой CA/server/client PKI по
[Railway high-water audit 7x](RAILWAY_HIGHWATER_AUDIT_7X.ru.md):
**15 октября 2026 года, 13:33 UTC**.

В Railway `cpa-gateway-sandbox/sandbox` обнаружено, что подготовленная
в прошлой сессии **неизменяющая том** замена `Start Command`
`saas-highwater-staging-only` уже применена: deployment
`a5e9ccdc-b9ae-4392-945a-6d65b8c2c284` имеет статус
`SUCCESS`, старый deployment `REMOVED`, запуск нового процесса
пишет `RETIRED_MTLS_SANDBOX_NO_LISTENER`, а retained volume
`synthetic-highwater-only` остаётся подключён.
Это **read-only observation** платформы, не сетевой probe 8443
и не независимый журнал. Новая M1e ветка Railway не меняет.

## Постоянные запреты

No merge/Ready/deploy; SQL 019 запрещён, staging SQL 020–022
не применять вне disposable GitHub PostgreSQL16. Никаких операций
с production, Railway signer/journal/volume, настоящими
credentials, provision/create UUID, retry/reissue/repair/reuse/delete,
delivery/archive/GC. `gcPermitted=false`.

Следующий этап требует независимого manual reconciliation UNKNOWN
COMMIT и ревизии драйвера на network partition/physical discard в
изолированном контуре, затем отдельного security review.
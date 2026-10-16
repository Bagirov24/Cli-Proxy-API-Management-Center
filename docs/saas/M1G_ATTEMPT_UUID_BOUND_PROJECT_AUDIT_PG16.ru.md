# M1g — серверный UUID попытки, привязанный к project COMMIT и audit (PG16 CI-only)

**СТАТУС: STACKED DRAFT / CI ONLY / НЕ PRODUCTION / НЕ AUTHORIZED RETRY.**
M1g ответвлён от проверенного Draft [M1f PR №9](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/9),
далее от PR №8 → №7 → №6 → №5 → №4 → №3. Не мержить, не переводить в Ready и не деплоить.

## Цель ограниченного M1g

M1f позволяет supervised NOLOGIN оператору READ ONLY сопоставить локальный
проект и полную цепочку M1c/M1d audit, но не позволяет доказать,
какая **конкретно** исходная попытка его записала. В M1g появляется
**локальная привязка UUIDv4 конкретной тестовой попытки** к обязательному
project audit event. UUID выбирается доверенным *CI server wrapper* ещё
до вызова database writer; он не берётся из JWT, HTTP, заголовка или
данных клиента. Драйвер ставит UUID как SET LOCAL custom GUC только
на зарезервированной signed PostgreSQL транзакции.

Новая миграция `staging/saas-rls/024_m1_attempt_bound_project_audit_pilot.sql`
исполняется **только** от `postgres` на одноразовой
`127.0.0.1:5432/saas_ephemeral_test`, с
`saas.staging_only=true`, после всех M1a–M1f тестов. Никакой
production migration или изменения SQL019.

- `saas_m1_private.project_attempt_bindings`:
  `attempt_id UUID PRIMARY KEY`, `event_id BIGINT NOT NULL UNIQUE
  REFERENCES project_write_audit_outbox`, `recorded_at`. Нет
  project name, tenant credential, response body, raw SQL,
  JWT, реального actor token или signer. Обязательная пара
  project+audit живёт в том же PG transaction и том же DB trust domain.
- FORCE RLS, отдельный `saas_m1_attempt_owner`
  (`NOLOGIN/NOINHERIT/NOBYPASSRLS`), INSERT-only policy,
  SQL append-only UPDATE/DELETE rejection; приложение,
  обычный writer и CI runner не получают прямой доступ к таблице.
- Дополнительный **AFTER ROW** `m1_project_attempt_binding` идёт после
  существующего **M1d** `m1_project_atomic_audit` по имени триггера.
  Он требует корректную UUIDv4 (текущая транзакция), ту же actor ID,
  audit event версии и `txid_current`. Успешная запись привязки,
  project mutation и ранее обязательный audit участвуют в одном
  COMMIT. Отсутствие UUID, повтор ранее закоммиченного UUID,
  несовпадение актёра/версии/audit => исключение и rollback
  provisional DML M1a SQL-function. Никакого автоматического повтора.
- Старые M1a SQL create/rename/disable после включения SQL024
  **fail closed**, если не штампован серверный UUID. Это
  CI-only эксперимент, а **не** безусловно совместимая production
  миграция. В старом M1c/M1d SQL нет backfill; существующие
  тестовые проекты из M1b остаются без задней привязки.

## Повторное расследование в M1f NOLOGIN reviewer

`saas_m1_review.inspect_project_attempt(tenant,project,attempt_uuid,
operation,version,actor)` запускается только в
**READ COMMITTED READ ONLY** транзакции NOLOGIN operator. Его
SECURITY DEFINER owner получает SELECT под FORCE RLS с отдельной
policy. Operator получает только EXECUTE; не получает table SELECT,
INSERT/UPDATE/DELETE, signer, credentials или самостоятельный SQL
writer. Дополнительно вызывается существующая M1f проверка полной
version-chain project+audit.

| Код | Значение | Правило |
| --- | --- | --- |
| `LOCAL_ATTEMPT_PAIR_OBSERVED` | Видна согласованная локальная попытка UUID → audit event → project и вся audit история | Только входные данные ручного расследования. Это **не** независимое attestation |
| `NO_LOCAL_ATTEMPT_EVIDENCE` | В текущей snapshot нет ни этого UUID, ни названного project/audit | **STOP**, отсутствие доказательства не доказывает отсутствие COMMIT |
| `INCONSISTENT_STOP` | UUID привязан к другой операции, actor, версии, проекту, либо есть project/audit без требуемой попытки | **STOP**, не исправлять и не переиздавать |

Положительный результат удостоверяет только согласованность данных
**того же PostgreSQL**. У суперпользователя/DDL/backup rollback есть
власть над обоими источниками. Ключ сервера и UUID не фиксируются
в независимом WORM/HSM. Важно: переданный через GUC UUID
**не является криптографически attested** PostgreSQL:
custom GUC теоретически устанавливается обладателем доступа
к SQL session. Серверность UUID — контракт проверенного тестового
wrapper, **не** production security primitive.

### Что именно испытывает GitHub disposable PostgreSQL16

Скрипт `scripts/saas-staging/verify-m1-project-pg-e2e.mjs` запускается
**вторым** CI-only процессом после SQL024 и с флагом
`SAAS_EPHEMERAL_M1G_ATTEMPT_CI=true`. Он генерирует новую
синтетическую пару pinned RSA/RS256 и использует прежний server-side
issuer/subject → actor, RBAC, scope-HMAC и фиксированные
Bun.SQL templates с подготовленным `crypto.randomUUID()`.
В отличие от прежнего M1b E2E, выполняются новые проектные ID
`m1g-first`, `m1g-lost-ack`.

Сценарии:

1. create → rename CAS → soft disable: **3 разных** UUID,
   3 обязательных audit events, версии 1–3 и один terminal project.
2. Атака повторного использования уже committed UUID для нового
   project: fail closed, 0 нового project / 0 audit. Не доказано
   предотвращение *дозаписи* после несостоявшегося COMMIT:
   не существует независимого precommit durable intent.
3. Старый signed writer без UUID запрещён при SQL024:
   0 project и 0 audit; обратная совместимость не обещана.
4. COMMIT действительно случился, но локальный ACK потерян:
   caller видит 503 + quarantined pool, но один project,
   один audit и один UUID→event row persisted в PostgreSQL.
   **Никакой** повторной записи, идемпотентного replay или
   production-safe reconciliation.
5. SQL `tests/sql/saas_m1_attempt_bound_audit.test.sql`
   проверяет 1:1 local UUID/event привязку, полную версию,
   wrong actor/project/op/version, отсутствие UUID при
   существующем project как STOP, nonmatching UUID на пустом
   project как inconclusive, READ WRITE/REPEATABLE READ deny,
   FORCE RLS/ACL и запрет UPDATE/DELETE binding rows.
   Повторная SQL024 сохраняет записи и M1d fenced trigger.
6. Предыдущие M1b–M1f E2E и adversarial проверки остаются
   обязательными в том же disposable GitHub workflow.

## Чего M1g НЕ делает

- Не записывает attempt UUID до начала операции в независимый
  durable intent store. Сбой CI server process до COMMIT может
  потерять UUID. PostgreSQL однажды видит его только как signed
  transaction custom GUC; токен попытки не был подписан отдельно.
- Не доказывает exactly-once, настоящую идемпотентность,
  безопасный retry после 503, causality внешнего запроса,
  межрепличную сериализацию или rollout/backfill существующих
  production данных. Даже 0 записей может быть временной
  snapshot или rollback под контролем общего DB root.
- Не создаёт independent WORM, HSM, external timestamp,
  delivery/ACK, HTTP route, production SQL pool, физический
  discard одного соединения при partition в момент COMMIT.
- Не затрагивает Railway, старый подписанный journal,
  signer, volume, Core/CPA/OAuth, UUID key issuance,
  mutation release или customer data.

## Срочное отдельно: Railway TLS

Проверено read-only, что `cpa-gateway-sandbox/sandbox`
`saas-highwater-staging-only` уже использует inert no-listener
Start Command; новый deployment `SUCCESS`, старый `REMOVED`,
retained volume `synthetic-highwater-only` по-прежнему
подключён к `/staging-highwater`. Это подтверждение
конфигурации Railway, **не** независимый TCP-negative probe
8443. Срок тестовой PKI: **15 октября 2026, 13:33 UTC**.
M1g никаких Railway действий не выполняет.

## Следующий hard gate

Durable *before-write* independent operation-intent root,
подписанный attempt/actor/tenant/operation/version контекст,
связанный с атомарным SQL и реальным issuer session, операторское
решение UNKNOWN COMMIT с независимой цепочкой WORM,
network partition during COMMIT и external trust-domain approval —
**всё ещё не выполнено**. Отсутствие этих гарантий блокирует
production и merge без review.

**Постоянные запреты:** no Ready/merge/deploy, no SQL019,
no production PostgreSQL/Railway signer/journal/volume change,
no Core/CPA key mint/reissue/retry/repair/reuse/delete,
no delivery/archive/GC. `gcPermitted=false`.
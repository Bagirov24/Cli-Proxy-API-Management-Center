# M1h — подписанное PRE-COMMIT намерение для project write (CI-only)

**Статус: STACKED DRAFT / НЕ PRODUCTION / NO RETRY.** Новый M1h PR
ставится поверх незамерженного [M1g PR №10](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/10),
далее цепочка Draft PR №9→№8→№7→№6→№5→№4→№3.

## Что фактически реализовано

После уже пройденного M1g signed RS256 → trusted actor →
PostgreSQL fixed-function write с mandatory audit и UUIDv4 попытки,
M1h добавляет *только внутри disposable GitHub PG16 job* второй
локальный Node-процесс. Он не получает PG credentials, signing scope
key, Railway vars, JWT или приложение. Своим случайным ephemeral
Ed25519 ключом подписывает цепочку фиксированных записей вида
`{attemptId, actorId, tenantId, projectId, operation, expectedVersion}`.

Процесс создаёт файл внутри `/tmp`, добавляет intent record,
`fsync` файла и **только после этого** выдаёт signed receipt.
CI Bun.SQL wrapper не имеет права начинать project write до receipt.
Запись includes monotonic sequence, previous SHA256 digest, body digest
и Ed25519 signature; дублирование UUID отказывается без append.

Никакие SQL 019/025, runtime route или доступ клиента к witness
не добавляются. В PostgreSQL остаётся M1g UUID→обязательный audit
из **того же PG COMMIT**. Новое доказательство связывается с
проектом только **посредством UUID, actor, tenant, project и операции**,
сверяемых между journal и local PG read-only observer. PostgreSQL
не проверяет внешнюю Ed25519 подпись и НЕ подписывает саму попытку.

## Adversarial acceptance в disposable CI

1. **Потерян ACK ПОСЛЕ реального COMMIT:** до write отдельный
   signer успешно fsync и подпись намерения; caller видит `503`,
   новый PG observer видит `1 project / 1 audit / 1 M1g UUID binding`.
   Пул карантинируется, автоматического retry нет.
2. **Убитый физический backend ДО COMMIT:** намерение уже
   независимо от PG fsync'd, но PG observer видит `0/0/0`.
   Ответ `503`, PID исчез, пул карантинируется.
   Запись о попытке остаётся, но **НЕ даёт права повторить**.
3. **Signer недоступен:** после остановки child-process wrapper
   возвращает `503` **без резервации PG connection** и без проекта.
4. **Подмена подписанной записи, обрезание high-water,
   смена публичного ключа** — отдельный offline verifier без PG
   credentials обязан отказаться. Дублирование UUID в witness
   также запрещено.
5. [M1g SQL024](M1G_ATTEMPT_UUID_BOUND_PROJECT_AUDIT_PG16.ru.md)
   и M1a–M1f регрессии запускаются в том же disposable job.

## Три принципиальные границы

- **Не off-host и не independent WORM:** оба процесса и файловый
  журнал находятся на одном CI runner и одном OS trust domain.
  Даже если приватный ключ только у ребёнка, родитель/админ может
  удалить журнал, изменить pin, переиграть snapshot. Ephemeral
  key и `expectedCount` живут только в памяти CI процесса.
  Без независимого долговечного high-water нельзя надёжно
  обнаружить rollback всей машины/проекта.
- **Не exactly-once:** наличие PRE-COMMIT intent при отсутствии
  local PG rows не доказывает, что COMMIT никогда не будет или
  что сетевое подтверждение не потеряно. Драйвер не делает
  retry, repair, mint или recovery. Между fsync и COMMIT возможна
  неопределённость.
- **Не production integration:** нет durable issuer/session ID,
  настоящего OIDC, физических pool discard при network partition,
  внешнего signer, сессий ревокации между репликами,
  самостоятельного HTTP CRUD/CPA/BYOA/Egress, DR/WORM,
  операторских подписей, независимого ACK или production release.

## Условия для code merge vs SaaS release

Для **слияния CI-only Draft цепочки** потребуется отдельный codeowner
и security review, подтверждённые 4/4 GitHub checks на каждом
проверяемом HEAD, закреплённый default-off/disposable-only scope,
план последовательных merge PR №3→№10→M1h и письменное разрешение
владельца. Полноценный SaaS **не активируется** от merge.

Для **production SaaS** дополнительно нужны реальный серверный
auth/tenant/RBAC CRUD, штатные миграции и backfill, строгие
API/egress/CPA controls, независимое durable precommit receipt
с внешним trust root/WORM + manual UNKNOWN COMMIT dispute,
проверенный OIDC/session revocation, failure injection на
network partition during COMMIT, key/volume rotation,
observability, операционное DR и отдельный release approval.

## Railway TLS

Ранее read-only подтверждено, что test
`cpa-gateway-sandbox/sandbox/saas-highwater-staging-only`
работает под inert no-listener Start Command; статус deployment
`SUCCESS`, старый mTLS deployment `REMOVED`, volume
`synthetic-highwater-only` остаётся смонтирован на
`/staging-highwater`. Документированный test PKI expiry:
**2026-10-15 13:33 UTC**. Независимый отрицательный TCP probe
8443 не проведён, и M1h никакой Railway write не делает.

**Hard stops:** все PR остаются Draft; не мержить/не Ready/не deploy
без explicit review и approval. SQL019, production DB,
Railway signer/journal/volume, реальные CPA/OAuth keys,
automatic retry/reissue/reuse/repair/GC/delivery/archive запрещены.
`gcPermitted=false`.

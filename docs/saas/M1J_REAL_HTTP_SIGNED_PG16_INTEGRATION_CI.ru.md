# M1j — реальный loopback HTTP → подписанный PostgreSQL16 COMMIT (CI-only)

**STACKED DRAFT / НЕ PRODUCTION / БЕЗ АВТОПОВТОРОВ.**
База: [M1i Draft PR №12](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/12)
(предыдущий HEAD `7b1d668f` имел 4/4 SUCCESS), далее цепочка PR
№11 → №10 → … → №3. Все остаются Draft и не смержены.

## Что соединено

M1i содержал настоящий, но НЕ смонтированный HTTP Request/Response
адаптер, который тестировался с mock writer. M1j **не добавляет
production маршрута**: только после всех M1b–M1h регрессий одноразовый
CI-процесс запускает `Bun.serve` на `127.0.0.1` и эфемерном порту `0`.
Один тестовый запрос проходит полный путь:

1. HTTP `POST/PATCH/DELETE` с ограниченным JSON, строгим путем,
   отсутствием CORS/cookie/клиентского actor/attempt ID.
2. Реально подписанный синтетический RS256 `at+jwt`; pinned
   issuer, audience, kid, exp/iat; trusted серверный
   `issuer/subject → actor`, активная tenant membership и роль,
   повторная проверка до записи.
3. СЕРВЕРНЫЙ UUIDv4 каждой допущенной попытки; отдельный Node
   Ed25519 witness БЕЗ PG-пароля/SQL signing key подписывает
   actor, tenant, project, operation, expectedVersion, UUID, записывает
   hash-chain в локальный CI файл и вызывает `fsync` **ДО** PG write;
   при отсутствии receipt DB connection не резервируется.
4. Реальный Bun.SQL pool `max:1`, не-superuser `saas_ci_runner`,
   HMAC-подписанный tx-scoped actor/tenant/txid/expiry/mac,
   PostgreSQL `SET LOCAL ROLE saas_m1_project_executor`, только
   allowlisted SQL function. FORCE RLS и текущая membership/tenant
   auth проверяются **внутри самой транзакции**, M1d ревокация
   сериализуется, private M1c audit и M1g UUID→audit event
   записываются в том же PostgreSQL COMMIT.
5. HTTP возвращает только фиксированные `201/200/401/404/503`,
   server correlation ID, `no-store`, `nosniff`, no CORS/cookie,
   без PostgreSQL данных/SQL ошибок/actor токена/tenant name.
   Ни одно `503` не вызывает retry, reissue или success.

Никаких миграций SQL025/SQL019, production deps, публичного
listener, реального пользователя/токена, CPA/Core/VPN или Railway.

## Адверсариальные тесты

Запуск `scripts/saas-staging/verify-m1j-http-signed-pg.mjs`
происходит **в четвёртом отдельном** вызове существующего
`verify-m1-project-pg-e2e.mjs` при явно выставленных
`SAAS_EPHEMERAL_M1_PG_CI/M1G_ATTEMPT_CI/M1_HTTP_CI/
M1J_HTTP_PG_CI=true`, после SQL024, полного M1g replay и M1h.
Все слои проверяются на **настоящих localhost HTTP и PG16
соединениях**, не mock writer.

| Исход | HTTP | Физическое состояние PostgreSQL16 |
| --- | --- | --- |
| create → CAS rename → disable | 201 → 200 → 200 | 1 проект, версия 3, 3 аудита, 3 уникальные UUID binding |
| Заведомо неверная аудитория JWT, viewer/auditor, подмена actor, Idempotency-Key, extra DTO | 401 или 404 | 0 DB reservations/0 intents до проверки |
| Rename terminal disabled project | 404 | Signed precommit intent есть; нового COMMIT и UUID binding нет |
| Реальная DB membership revoked при неизменном TS actor | 404 | Signed precommit intent есть; 0 project/audit/binding; membership восстановлено в disposable fixture |
| ACK потерян **после реального COMMIT** | 503 | 1 project / 1 audit / 1 UUID binding, пул карантинирован, ACK count 0 |
| Другая PG fixture убила зарезервированный backend **до COMMIT** | 503 | 0/0/0, PID исчез, карантин pool, signed intent пережил rollback |
| Witness остановлен | 503 | **0 новых DB reservations** и 0 project/audit |

После остановки witness отдельный no-PG-credential offline
verifier подтверждает **ровно семь** signed/fsynced precommit
записей, порядок, SHA256 chain, Ed25519 подписанный payload.
Отдельная SQL-проверка
`tests/sql/saas_m1_http_signed_pg_e2e.test.sql`
независимо подтверждает 3/3/3, committed lost ACK 1/1/1,
denied/physical loss 0/0/0, текущую membership,
M1d trigger и отсутствие новых grants на signer/audit.

Защитные тесты M1a–M1i **сохраняются**. Обычный frontend
`bun test/lint/build` проверяет default-off; M1i CI-only
HTTP контракт остаётся отдельным тестом. CI-only реальный
путь запускается в disposable GitHub PostgreSQL16 job,
и завершение этого шага не является deployment.

## Чего НЕ доказано — merge/release gate

- Нет настоящего OIDC discovery/refresh/session revocation,
  issuer trust/rotation и authenticator/tenant provisioning
  для реальных пользователей.
- Ed25519 precommit witness и PG16 запущены на **одном
  GitHub runner/OS trust domain**; ключ, файл и high-water
  не защищены внешним WORM/HSM. DBA/admin может сдвинуть
  оба источника, а UUID в PG хранится в custom GUC,
  НЕ криптографически привязанном к JWT.
- Убийство backend выполнено **до**, а не в середине COMMIT.
  Production pool physical discard, сетевые partition во время
  COMMIT, несколько реплик и bounded manual UNKNOWN COMMIT
  reconciliation с внешней доверенной квитанцией — НЕ доказаны.
  **Нет exactly-once и безопасного auto-retry.**
- Сервис не может принимать реальные внешние запросы:
  нет production listener, изолированного backend deployment,
  production PostgreSQL migration/backfill, egress, CPA/BYOA,
  tenant onboarding, quota/billing, observability/DR.
- Для CI-only **merge** цепочки необходимо независимое
  code-owner + security review, проверка точного final HEAD,
  отсутствие production import, последовательность PR и
  письменное разрешение. Даже разрешённый merge
  **не включает SaaS в production**.

## Railway — отдельный контроль

Ранее read-only наблюдением установлено: sandbox staged TLS сервис
`cpa-gateway-sandbox/sandbox/saas-highwater-staging-only` уже
использует no-listener deployment `SUCCESS`, старое развёртывание
`REMOVED`, retained volume `synthetic-highwater-only` сохранён
на `/staging-highwater`. Тестовая PKI истекает
**15 октября 2026, 13:33 UTC**. Независимого отрицательного
TCP8443 probe пока нет. M1j не изменяет Railway.

**Hard stops:** все PR Draft / Not merged; SQL019 запрещён;
никаких production/Railway signer/journal/volume изменений,
CPA/Core/OAuth ключей, выдачи/reissue/retry/repair/delivery/GC.
`gcPermitted=false`.

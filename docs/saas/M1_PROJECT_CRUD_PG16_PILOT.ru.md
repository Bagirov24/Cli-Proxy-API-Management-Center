# M1a — изолированный PostgreSQL16 CRUD проектов tenant (не production)

**Статус:** STACKED DRAFT PR / CI-ONLY. База — ветка открытого
Draft PR #3 \`feature/saas-blueprint-tenant-egress-20261010\`,
а НЕ \`custom-no-apikey-fun\`. Новый M1a нельзя мержить отдельно
перед его базовым PR; он не открывает живой SaaS API.

## Реализованный вертикальный срез

- \`create_project(tenant, id, name)\` — только tenant-owner/admin,
  новый локальный проект, \`version=1\`, отсутствие дубликатов.
- \`get_project(tenant, id)\` — только при подписанном transaction scope,
  active tenant/membership; owner/admin/viewer/auditor могут читать
  **ограниченные** поля \`project_id, name, status, version\`.
  Чужой tenant возвращает пустой результат без существования ресурса.
- \`rename_project(tenant, id, name, expected_version)\` —
  только owner/admin, status=active; CAS version, атомарное
  увеличение \`version\`, устаревшая версия получает \`false\`.
- \`disable_project(tenant, id, expected_version)\` —
  логическое отключение (версия увеличивается); повтор, rename
  после disable или физическое DELETE **невозможны**.

Временный SQL пилот \`staging/saas-rls/020_m1_project_metadata_pilot.sql\`
создаёт отдельно от существующего read-only SaaS schema:
\`saas_m1_private.projects\` и \`saas_m1_api\`. Обязательные
\`ENABLE/FORCE ROW LEVEL SECURITY\`, изолированный \`NOLOGIN\` owner,
отдельный \`NOLOGIN\` executor с правами **только EXECUTE** четырёх
закреплённых функций, без доступа к приватным таблицам,
signer keys, SQL UPDATE/DELETE напрямую. DDL строго проверяет
\`current_database()='saas_ephemeral_test'\`,
\`current_user='postgres'\`, \`saas.staging_only=true\`
и установленный signed-scope revision gate. Это предотвращение
случайного запуска, а **не механизм защиты production-DB**.

**SQL авторизация:** сервер должен передавать лишь подписанный
HMAC-SHA256 \`actor, tenant, txid, expiry\` от привилегированного
компонента, затем выполнить функцию в одной транзакции.
Сами функции вызывают ранее реализованную
\`saas_rls.authorized_revision(...)\`, которая снова проверяет
подпись, совпадение actor, роль из БД, действующий membership
и состояние tenant из server-owned revision table.
Роль или claims из клиента и JWT **не могут** повышать полномочия.
SQL guard работает только в disposable CI с отдельным случайным
test signer key. Нет реального issuer/token directory подключённого
к PG mutation backend.

**TypeScript порт:**
\`src/features/saasBlueprint/controlApi/server/m1ProjectCommandBoundary.ts\`
использует существующий \`AccessTokenVerifier\` и доверенный
\`issuer+subject → actorId\` directory; отбрасывает чужие
tenant role/actor headers, дважды проверяет актуальное membership
до исполнения server-only writer, валидирует имя/ID/version и
возвращает унифицированные результаты без токенов и SQL ошибок.
Дополнительная fail-closed проверка: результат server-side actor lookup обязан иметь ровно тот же `actor.id`, который разрешён доверенным issuer/subject directory; подмена даже на admin другого actor блокирует writer (401). Это закреплено негативным Bun-тестом.

Порт **НЕ подключён** к HTTP router, Railway, Core/Gateway,
production PostgreSQL и не знает секретов или signer key.
Его \`M1ProjectTransactionalWriter\` пока только интерфейс:
адаптер обязан атомарно проверять подписанный scope и текущую
роль **в PostgreSQL**, выполнять CAS и аудит внутри транзакции,
не использовать прямой пользовательский SQL.
Между чистой TypeScript границей и PostgreSQL тестами **ещё нет
сетевого или реального driver adapter**, и это нельзя называть
production-ready CRUD.

## Тесты и запреты

\`tests/sql/saas_m1_project_metadata.test.sql\` выполняется внутри
существующего эпизодического GitHub Actions PostgreSQL16 workflow:
реальный PostgreSQL проверяет create/get/rename/disable, replay
guard, транзакционный ROLLBACK, оптимистическую конкуренцию,
запрет direct table DML/signing keys, unsigned/forged MAC,
expired MAC, wrong tenant, viewer/auditor writes, revoked actor,
suspended tenant, неверные идентификаторы/имя и невозможность
reactivation/delete.

\`tests/saasM1ProjectCommandBoundary.test.ts\` проверяет
server-verified identity port через **синтетический** issuer mock,
server actor/role, cross-tenant, запрет поддельных клиентских
claims, revocation между асинхронными проверками, strict inputs,
AbortSignal, скрытие ошибок и отсутствие автоматического retry.

**Не заявляется проверенным:** живой OIDC discovery/JWKS/rotation,
tenant CRUD provisioning, реальный network backend/HTTP handler,
production database/pool, полноценный write-audit outbox,
двухфазный DB fencing под параллельным revoke,
идемпотентное восстановление неизвестного COMMIT, billing,
Core/CPA bindings, HTTP/SOCKS5/VPN, Vault/BYOA,
external independently owned WORM/high-water, receipt ACK,
SQL019, миграции production, согласование security release.

## Следующий этап M1b

1. Доверенный OIDC issuer/JWKS rotation и durable session/revocation
   store с actor/tenant admin UI (отдельное решение оператора).
2. Подтверждённый safe PG16 connection-pool adapter с
   transaction-scoped signer, блокировкой авторизации и
   atomic audit outbox; устранение UNKNOWN COMMIT/retry опасности.
3. Только после этих шагов — staging-only guarded private HTTP CRUD,
   реальные интеграционные тесты на отдельной базе и security review.
4. Позже — Core metadata adapter, tenant runtime routing/egress,
   секреты, delivery ACK и независимый high-water.

**Запреты сохраняются:** не мержить без review и отдельного
разрешения, не менять production или Railway services,
не применять миграцию 019, не выдавать/повторять UUID,
не включать retry/reissue/repair/delivery/archive/GC.
\`gcPermitted=false\`, \`authorizationGranted=false\`.
Тестовые Railway mTLS сертификаты текущего Stage 7w/7y
истекают **2026-10-15 13:33 UTC**; этот M1a PR их не ротирует.

# M1k — синтетическая per-session ревокация внутри реальной signed PG16 transaction

**СТАТУС: STACKED DRAFT / DISPOSABLE CI ONLY / NOT PRODUCTION / NO RETRY.**

База — [M1j Draft PR №13](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/13), точный исходный HEAD `90d0c72c` имел 4/4 SUCCESS. Цепочка Draft PR №3–13 не смержена. M1k не изменяет runtime API, SQL019, production БД, OIDC, CPA/Core или Railway.

## Проблема и узкий контракт

Существующий `008_actor_session_epoch_pilot.sql` уже реализует **отзыв всего актёра** и bump tenant epoch. M1j проверяет signed HTTP→PG16 и текущую membership DB, но ничего не знает о двух одновременных **отдельных сессиях одного actor**. M1k не заменяет actor-wide kill switch или M1d tenant/membership revoke. Он добавляет отдельно от них disposable CI pilot **на одну серверную сессию**.

В CI server process четыре synthetic RS256 bearer `at+jwt` подписаны временным тестовым ключом. Каждый токен имеет собственную подпись и SHA256 fingerprint, ассоциированный ТОЛЬКО в памяти доверенного CI server registry с новым серверным UUIDv4, `actorId`, `tenantId`, `sessionRevision`. Никакие `sid/sessionId/actorId/role/tenantId/jti` из JWT claims, HTTP заголовков или JSON не являются источником прав. Директория issuer/subject→actor остаётся серверной. `AsyncLocalStorage` изолирует выбранную сервером запись сессии для отдельного HTTP request; двойная RS256 verification и сравнение identity+revision перед write обязательны.

**Это НЕ OIDC session management**: нет real issuer, refresh/logout, JWT-bound signing root, production durable session registry, распределённых реплик или возможности оператора менять session. CI registry и signed PG proof находятся на одном runner.

## SQL025 (строго disposable PostgreSQL16)

Новая **отдельная** `staging/saas-rls/025_m1_project_session_epoch_gate_pilot.sql`:

- Guard: только `postgres` на `saas_ephemeral_test`, при `saas.staging_only=true`, с существующими M1d mandatory audit fence, M1g UUID binding и подписанным actor/tenant scope.
- `saas_m1_private.project_session_epochs`: серверный UUID, фиксированный actor/tenant, `revision >= 1`, `active/revoked`. NOLOGIN/NOINHERIT/NOBYPASSRLS `saas_m1_session_owner`, FORCE RLS, запрет DELETE, actor/tenant/UUID relocation, epoch rollback и возврата `revoked`→`active`. Privileged fixture может только отозвать с bump revision или повысить epoch активной сессии.
- `saas_m1_private.project_session_proofs`: уникальный PG txid → signed server session UUID/actor/tenant/revision, добавляется ТОЛЬКО SECURITY DEFINER функцией в той же транзакции и не является durable external intent. RLS FORCE, никаких SELECT/INSERT grants у обычного SQL runner/executor/reviewer.
- `saas_m1_api.lock_project_session_epoch(UUID, revision, tenant, actor)` вызывается только внутри уже HMAC-signed PG16 scope, после `SET LOCAL ROLE saas_m1_project_executor` и **до DML**. Сначала сверяет cryptographically signed actor/tenant через имеющуюся `scope_membership_matches`, затем берёт `SELECT ... FOR SHARE` на запись точной session UUID/epoch. Проверяет `active` и текущую версию и получает существующий **M1d tenant revision FOR SHARE** до COMMIT/ROLLBACK. Перед успешной записью создаёт закрытый transaction proof. Если revocation COMMIT предшествовал lock, функция возвращает FALSE и writer отказывает; если запись уже держит lock, revoke не может завершиться до COMMIT.
- Дополнительный AFTER ROW `m1_project_session_epoch_gate` проверяет DB proof после существующих M1d audit trigger и M1g UUID→event trigger. Он не заменяет старые триггеры, но **не допускает обходного старого writer** без вызова защищённой функции (rollback provisional project+audit+UUID). Повторная SQL025 не сбрасывает сессии.
- UPDATE session state на synthetic PG superuser fixture вызывает bump *существующей* tenant revision, поэтому остальные M1d reader/barrier продолжают сериализоваться. Публичная роль не получает таблицы, HMAC signer, session revoker API или дополнительные grants.

**Ограничение:** scope HMAC всё ещё удостоверяет actor/tenant/txid, но НЕ подписывает токен сессии или session UUID. Привязка конкретного bearer fingerprint к UUID обеспечивается кодом доверенного **CI** server adapter, а не доказанным production token-binding или неизменяемым внешним реестром. Скомпрометированный privileged writer/session root остаётся вне модели.

## Физические adversarial tests

Отдельный 5-й CI процесс ПОСЛЕ M1a–M1j regression и установки SQL025 запускается из `verify-m1-project-pg-e2e.mjs` с явными flags `SAAS_EPHEMERAL_M1K_SESSION_CI=true` и `SAAS_EPHEMERAL_M1_HTTP_CI=true`. `verify-m1k-session-epoch-ci.mjs` использует настоящий `127.0.0.1` HTTP listener (Bun port 0), M1i Request/Response, pinned synthetic RS256, actor lookup и M1h NO-PG-credentials local Ed25519/fsync precommit witness. Основной signed native Bun.SQL driver использует `sessionGuard:true`. Никаких реальных tenant/PGA/CPA данных.

1. Две одновременно действительные RS256 сессии A/B с **одним actor и tenant**, но разными серверными session UUID. HTTP A и B → 201; неподписанный/незарегистрированный bearer → 401 без witness/PG.
2. Реальный PG revoke только A: подписанный токен A и устаревший TypeScript actor ещё выглядят корректно, но HTTP→signed PG возвращает 404 и **0 project/0 audit/0 UUID**, сессия B продолжает работать.
3. Повышение `revision` у активной B без изменения роли: прежний серверный epoch=1 → 404 и ноль записей, обновление доверенного CI registry на epoch=2 → 201.
4. Старый signed native writer с M1g UUID, но **без** session proof пытается записать проект → 0/0/0. У M1k нет невидимого обхода SQL025 через старую API функцию.
5. **Write-first**: реальный HTTP C успешно пишет project+audit, в `beforeCommit` держит обе `FOR SHARE` блокировки; независимый privileged PG revoker обязан реально ждать `wait_event_type='Lock'`, затем запись COMMIT 201 и **1/1/1**, только после этого revoke COMMIT. Дальнейший HTTP C → 404.
6. **Revoke-first**: privileged PG transaction меняет D status/epoch и держит lock до COMMIT. Вторая настоящая HTTP→signed PG16 transaction обязана физически ждать этот lock и после revoke COMMIT вернуть 404, **0/0/0**.
7. Подписанные локальные precommit intents (включая физически отвергнутые попытки) проверяются отдельным no-PG verifier; недоступный signer → 503 **до резервации** SQL и 0 project/audit. Отказ никогда не вызывает retry.
8. Независимый `tests/sql/saas_m1_project_session_epoch.test.sql` проверяет совпадение PG txid session proofs с M1c/M1g audit, только пять committed project events, четыре synthetic session states, отказ восстановления revoked и удаления сессии, ACL/FORCE RLS, SQL025 replay без сброса epoch.

## Merge и release

**CI-only code merge:** только после 4/4 GitHub Actions на exact M1k SHA, отдельного code-owner/security review, проверки default-off, неизменности родительских PR, последовательного merge, операторского письменного approval. Ни один PR автоматически не переводится в Ready.

**Production SaaS:** всё ещё нужны настоящий OIDC/JWKS rotation, отдельный постоянный issuer session store и распределённый отзыв, подписанное token-bound доказательство identity/session в БД, production pool/disconnect/partition during COMMIT, независимый off-host WORM+durable high-water/manual adjudication, реальное HTTP backend deployment, CPA/BYOA/egress/quota/billing, миграции/backfill, observability/DR и release/security approval. Ни `503`, ни session revocation race сами по себе не дают exactly-once/retry.

## Railway TLS / постоянные hard stops

Ранее read-only наблюдением подтверждены: тестовый
`cpa-gateway-sandbox/sandbox/saas-highwater-staging-only` имеет новый
`SUCCESS` no-listener deployment, старый mTLS deployment `REMOVED`,
постоянный том `synthetic-highwater-only` сохранён на `/staging-highwater`.
Отдельного активного TCP-negative probe 8443 **не было**. Срок
тестовой PKI — **15 октября 2026, 13:33 UTC**. M1k Railway не изменяет.

Не делать merge/Ready/deploy/SQL019 или production PostgreSQL операции
без explicit approval. Не трогать Railway signer/journal/volume, Core/CPA,
OIDC secrets, реальные ключи, issuance/reissue/retry/repair/delivery/GC.
`gcPermitted=false`.

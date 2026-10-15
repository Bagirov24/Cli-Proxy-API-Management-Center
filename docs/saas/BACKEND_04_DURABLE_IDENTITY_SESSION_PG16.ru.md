# Backend 04 — постоянная привязка issuer/subject и bearer→session в PostgreSQL16

**15 октября 2026. Статус: изолированная реализация и disposable GitHub PostgreSQL16 CI. Не production migration/deploy.**

Stacked from [operator-curated JWKS Draft #26](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/26), точный parent HEAD `48d69bdd9c4565d6fd078f4e1ae3efe31a7db1cd`. SQL026 не заменяет SQL011 и SQL025, а соединяет их на стороне **самой базы**.

## Что нового

- `staging/saas-rls/026_durable_project_token_binding_pilot.sql` допускает установку **только** в disposable GitHub PG16 `saas_ephemeral_test` администратором с `saas.staging_only=true`, строго после 011, 025. Никаких автоматических production migrations, SQL019, Core, CPA или Railway.
- Уже существующие PRIVATE PostgreSQL таблицы SQL011 `issuer_subject_bindings`, SQL010 `actor_token_sessions`, SQL008 `actor_session_state` остаются первичным source of truth. Новая `saas_m1_private.project_session_token_links` хранит **один неизменяемый fingerprint на один session UUID**, с уникальностью обеих сторон и запретом UPDATE/DELETE. FORCE RLS, только отдельный NOLOGIN owner видит сырые строки; новая NOLOGIN `saas_m1_identity_resolver` не имеет к ним SELECT, INSERT, UPDATE или доступа к signer secrets.
- `saas_m1_api.resolve_verified_subject_actor(issuer,subject)` и `resolve_verified_project_session(actor,tenant,sha256Bearer)` — ограниченные `SECURITY DEFINER` функции, возвращающие **только** активный actor либо `session UUID/revision`. Никаких ролей, токенов, ключей, raw SQL или OAuth claims. Функции доступны исключительно выделенной runtime read capability, не SQL executor/client.
- `saas_m1_api.pin_project_verified_token_session` доступен **только отдельной ранее существовавшей** verified-issuer provisioner capability и только после проверки активного issuer/subject, token hash, истечения токена, actor state и PG25 session. Только одна регистрация; no bind replay, no subject reassignment/revival.
- Новый mandatory `AFTER INSERT/UPDATE` project trigger `m1_project_token_binding_gate`: проверяет **реальный подписанный** HMAC fingerprint текущей транзакции, PG25 session proof того же txid, link той же пары actor/tenant и активный SQL011 subject+fingerprint с unexpired токеном. Несовпадение прекращает запись и обязательный audit/attempt по одной транзакции. Для конкурирующего revoke используется существующий PG25/M1d `FOR SHARE` tenant authorization revision fence; SQL011 revoke обновляет именно этот epoch. Публикация 503 после неизвестного COMMIT не превращается в повтор записи.
- `pgDurableIdentitySessionAuthority.ts` — серверный приватный TypeScript адаптер `directory` + `sessions` к уже готовому API. Он выполняет **только фиксированные параметризованные SELECT**, транзакцию `BEGIN READ ONLY`, `SET LOCAL ROLE saas_m1_identity_resolver`, строгий DTO и no-rows→deny. При непонятном DB ответе или ошибке sync quarantine→connection discard, без SQL-текста и без ретрая. Бэкенд сначала независимо проверяет issuer/signature/typ/aud/exp из PR #26, **не** берёт actor, role, tenant или fingerprint из header/клиентских claims.

## Acceptance

`tests/saasPgDurableIdentitySessionAuthority.test.ts`: fixed SQL, no caller-provided actor claims, malformed rows, unknown COMMIT, pool poison, failed release/abort. Новый **13-й disposable DB acceptance** после всех M1a–M1q+backend-02 regression и signed witness tests:

1. SQL026 устанавливается только под privileged disposable pg16 и проверяет role grants/FORCE RLS, нет доступа raw identity/token data у runtime.
2. GitHub CI создаёт отдельный ephemeral `saas_identity_ci` DB login с random password; у него нет возможностей выдавать identity или писать проекты. RSA ключ/короткий JWT генерируется **в CI**; используется **настоящий** `createOperatorPinnedOidcAccessVerifier`, не synthetic identity bypass.
3. Только authenticated verified issuer/subject сопоставляется с durable actor; отдельный SHA-256 проверенного bearer соответствует ровно одному PG25 session UUID+epoch. Чужой actor/tenant/fingerprint не получает сессию.
4. Настоящий signed PG16 SQL write с нужными token, session, actor, tenant создаёт project+mandatory audit+attempt+PG25 proof в одном COMMIT. Подмена fingerprint при сохранении чужого UUID — отклонение SQL026 trigger, ничего не записывается.
5. PostgreSQL SQL011 revoke того же fingerprint при всё ещё криптографически действующем JWT приводит к no-session, signed PG16 no-write, no-ghost project/audit; revoke subject приводит к no-actor. Никакого возобновления revoked через повторную enrol.
6. Все прежние SQL001–025 сценарии проходят **до** SQL026 и не ослабляются.

## Production остаётся отдельным гейтом

Это **persistent database design tested on ephemeral PostgreSQL16**, а не развёрнутая production база. Production требует независимо утверждённых миграций и прав (SQL026 *нельзя* применять к живой базе), реальных IAM/OIDC provisioning и tenant memberships, операционного секрет-хранилища, устойчивой внешней выдачи/revoke сессий и идемпотентного workflow без автоматического retry после uncertain COMMIT, production-grade pool quarantine, off-host signed WORM и backup/recovery. Выделить приватный SaaS staging в Railway с **новой** PostgreSQL, без Core/Gateway/`/data`; доказать E2E и независимый security/codeowner review, потом canary/rollback.

HTTP read/write handlers всё ещё **не смонтированы** на production Gateway. Отдельное разрешение пользователя на доведение до production не отменяет технические fail-closed проверки и невозможность считать CI-ключ настоящим IdP. Нет live credentials, Railway changes, direct custom branch push, GitHub Release mutation или GC.

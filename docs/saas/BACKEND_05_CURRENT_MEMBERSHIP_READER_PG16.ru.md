# Backend 05 — непривилегированное текущее членство actor в tenant

**16 октября 2026.** Изолированный GitHub PR, исключительно одноразовая PostgreSQL16 в CI. **Не** production migration, не mounted SaaS API и не доказательство полной готовности к production.

## Закрываемый дефект интеграции

Backend 04 уже проверял RSA-подписанный JWT через доверенный JWKS, issuer/subject→actor через SQL026 и fingerprint→PG25 session через ограниченный `saas_identity_ci` DB-login. Однако реальный HTTP→PG16 E2E до сих пор использовал `postgres` superuser для `actors.lookup` — прямое чтение `saas_rls.memberships`. Это не подходящий runtime credential.

**SQL027** `staging/saas-rls/027_current_actor_membership_projection_pilot.sql` добавляет только `saas_m1_api.resolve_current_actor_memberships(expected_actor)`. Тело функции работает как NOLOGIN `saas_rls_owner`, но `EXECUTE` доступен только NOLOGIN `saas_m1_identity_resolver`, которую отдельный NOINHERIT login может выбрать через `SET LOCAL ROLE`. Роль чтения **не** имеет сырого SELECT на membership/actor state/revision и не получает INSERT, UPDATE, credentials или signer. CREATE на схеме выдаётся владельцу функции лишь внутри одноразовой транзакции миграции и отзывается до COMMIT.

- Проекция читает только `saas_rls.memberships` для **серверного** actor ID и только `status='active'`.
- Tenant обязан иметь `tenant_authorization_revisions.tenant_active=TRUE`; actor — `actor_session_state.status='active'`. Эти состояния поддерживаются триггерами старых SQL004/008.
- Разрешены только четыре роли `tenant-owner/admin/viewer/auditor`; никаких ролей и ID из JWT или HTTP-заголовков.
- Привилегированная SQL-функция возвращает максимум 33 строки; TypeScript **отказывает всему запросу**, если активных memberships более 32. Частичный список запрещён.
- `pgDurableIdentitySessionAuthority(pool).actors.lookup(actorId,signal)` выполняет отдельную `BEGIN READ ONLY` + `SET LOCAL ROLE` + параметризованный SELECT + `COMMIT`, возвращает только замороженные `ControlActor.memberships`. Null/отсутствие активных членств = deny, некорректные строки, повторённый tenant, ошибка базы, unknown ACK и physical release = fail closed, синхронный карантин пула и запрет повторной выдачи.
- Драйвер PostgreSQL и внешняя система IAM не выбираются HTTP-клиентом; полная проверка access token выполняется перед этим lookup. Текущий RBAC в памяти **не** заменяет обязательный PostgreSQL CAS / signed tenant revision lock непосредственно при записи.

## Acceptance

1. `bun:test` `tests/saasPgCurrentMembershipReader.test.ts` проверяет bounded result, неподписанные строки, duplicate/overflow, extra roles/status/fields, no-row, abort, unknown COMMIT и отказ release/connection без утечки деталей.
2. Только после всех старых PostgreSQL16 SQL001–026 и прежних E2E устанавливается SQL027, с защитой exact `saas_ephemeral_test`/PostgreSQL16/`postgres`/`saas.staging_only=true`. Проверяются `has_function_privilege` и **отсутствие** прямых прав на raw membership/tenant epoch у SQL role и фактического non-superuser login.
3. Backend04 HTTPS-origin `POST`→pinned RS256→SQL026 actor/session→новый SQL027 `actors.lookup`→fsynced witness→signed PG16 сохраняет ранее проверенный project/audit/attempt/session commit, A/B независимые bearer, 503 после реального COMMIT без retry.
4. После SQL `UPDATE memberships.status='revoked'`, всё ещё валидный JWT B и активный PG25 bearer session **не** дают HTTP запись: 401/0 новых fsync-intents. Другая роль `tenant-viewer` в tenant со статусом `suspended` исчезает из выдачи, без объявления нового tenant публичным.
5. Все пять workflow (Main CI, реальная одноразовая PostgreSQL16, read-only Management release guard, Demo Build, Chromium) должны быть **SUCCESS на одном точном SHA**. Исходные пройденные тесты `main` не заменяют этот gate.

## Границы production

SQL027 является **только ephemeral proof**, **не** утверждённой миграцией для постоянного Railway PostgreSQL. Не реализованы production физический discard Bun.SQL/pg pool, внешний IdP provisioning/deprovisioning, особый аварийный actor kill switch, независимый off-host WORM, защищённое IAM membership administration, многорепликовый lifecycle и проверенные rollback/restore процедуры. Лимит в 32 memberships — явное решение для данного пилота, не продуктовый потолок навсегда. HTTP handlers остаются несмонтированными; нет новых сервисов, публичных доменов, production secrets, Railway deploy или изменений веток `custom-no-apikey-fun`/`api-gateway`/тома `/data`.

Следующий отдельный этап: физически проверяемый driver с реальным уничтожением соединения после неизвестного исхода и staging с **отдельной** управляемой PostgreSQL, а затем независимая codeowner/security/ops приёмка.

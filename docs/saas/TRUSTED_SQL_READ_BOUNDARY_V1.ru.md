# Этап 2G.2 — Trusted Identity → AuthZ → Signed SQL Boundary (RU)

> **Статус: IMPLEMENTED contract / VERIFIED на синтетических unit-тестах**
> после [GitHub CI #38263480676](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480676)
> для SHA `2ceb5727faf60efb7eabf90557470c14c5d0f2b1`;
> JWT/actor-store/fake SQL-port всё ещё SIMULATED.
> Это **НЕ production authentication, не OIDC и не HTTP endpoint**.

## Цель

Соединить существующие проверяемые backend-порты Blueprint B **без**
изменений React, Core, CPA/Gateway, Railway, OAuth, ключей и живых сетевых
маршрутов. Новый модуль:

`src/features/saasBlueprint/controlApi/server/trustedSqlReadBoundary.ts`.

Поток из доверенных серверных зависимостей:

1. На вход поступает API access-token, запрошенные tenant/collection и
   server-side AbortSignal (никаких client-supplied actor/role/GUC).
2. Существующий `trustedAccessToken.ts` проверяет **pinned RS256**,
   `typ=at+jwt`, HTTPS issuer, audience, сроки, sub и kid.
   **ID-token не принимается.**
3. `createVerifiedSubjectSessionBridge` находит internal actor ID
   исключительно по **issuer + subject** через серверный directory.
   Claims `actorId`, `role`, `tenantId`, заголовки и client-supplied
   membership игнорируются.
4. Серверный `actors.lookup` читает актуальный actor/membership.
   `authorizeTenantRead` требует единственное active membership и
   разрешённую для роли коллекцию. Чужой tenant — generic **404**,
   auditor → accounts — **403**, неизвестный actor — **401**.
5. Только после AuthZ создаётся `AuthorizedReadScope` с
   **server-generated correlationId**. `signedSqlBoundary.ts`
   резервирует connection и выполняет один fixed SELECT с `$1/$2`:
   `BEGIN` → transaction ID → HMAC actor/tenant/txid/expiry →
   пять `set_config(..., true)` → `SET LOCAL ROLE` →
   PostgreSQL RLS → SQL whitelist row sanitation → `COMMIT`.
6. После **асинхронного** SQL повторяются token signature/time,
   issuer/subject mapping, actor lookup, полный snapshot memberships и
   tenant RBAC/role. При отзыве прав, смене роли, tenant или actor
   успешная выдача блокируется. При `AbortSignal` — **503 без rows**.
7. Ответ — **только внутренние SQL metadata rows**
   `source: 'staging-signed-rls'`. Это НЕ `ControlResource` и НЕ
   production `ControlReadResult`; текущие тестовые SQL-таблицы не
   имеют всех полей для публичного аккаунта/пула/egress DTO.

### Почему отдельный server-only порт, а не публичный endpoint

Исходный opt-in `createControlHttpHandler` и синтетический UI
не связаны с SQL. Было бы опасно выдать неполные SQL-таблицы за полный
проверенный `core-metadata-readonly` DTO, добавить новый endpoint или
интегрировать JWT с реальной системой авторизации без review. Поэтому
новый порт существует **только в TypeScript**, тестируемым контрактом
для будущего backend. Он не импортируется в React, Router, SaaS demo
или production `management.html`.

## Негативная security-приёмка

`tests/saasTrustedSqlReadBoundary.test.ts` генерирует свежий
**синтетический RSA keypair** и отдельный HMAC ключ в памяти тестов.
Отдельный fake ScopedSqlPool имитирует RLS-проекцию, а не является
wire-protocol PostgreSQL.

- North → North и Orbit → Orbit: разрешены, scope подписан
  server-side; SQL выполняется только через fixed parameter templates.
- North → Orbit / Orbit → North: **404, SQL не вызывается**, без
  чужих resource ID в ответе.
- Auditor → Accounts: **403**. Revoked/duplicate/missing
  membership: **404**.
- Wrong audience/issuer/kid, ID-token, unknown subject, `alg=none`:
  **401**, до выдачи DB connection.
- Поддельные JWT `role/tenantId/actorId` и дополнительные
  client-like headers не дают новых прав.
- Отзыв actor mapping или membership / изменение роли во время
  SELECT: повторная проверка отбрасывает уже прочитанные строки.
- `AbortSignal` во время SQL: **503**, никакого stale response,
  SQL boundary помечает pool как quarantined.
- Ошибка SQL и secret-looking debug text: только generic **503**.
- Вредоносная tenant-строка, неизвестная collection, неверный
  `limit`: отклоняются до SQL; неизвестные столбцы удаляются
  по existing SQL allowlist.

**Ограничения acceptance:** unit tests не подтверждают реальную
согласованность server actor-store и PostgreSQL RLS при конкурентном
отзыве membership. Отдельные PG16 tests 2C–2G.1b покрывают
signed GUC/RLS, но пока **не запускают JWT→AuthZ→SQL полный
pipeline через настоящий драйвер**.

## Открытые риски и следующие шаги

- **JWT replay:** действительный access-token может использоваться
  повторно в пределах TTL. При удалении server-side mapping такой
  token отклоняется на следующих чтениях; настоящие session binding,
  blacklist/jti, key rotation, logout/revocation across replicas и
  официальный OIDC issuer — **SPEC / PROPOSED**.
- Смена tenant на клиенте должна **отменять** предыдущие запросы:
  AbortSignal не может магически узнать о переключении UI, если
  его не передать от доверенной серверной границы.
- PostgreSQL snapshot может не видеть одновременно изменившиеся
  memberships без повторной проверки в той же БД/согласованном
  storage. Текущий actor-store и fake pool — **SIMULATED**.
- Подтверждение физического удаления повреждённой connection и
  сроков cancellation Bun.SQL 1.3.14 **отсутствует**. См.
  [BUN_SQL_DRIVER_PILOT.ru.md](BUN_SQL_DRIVER_PILOT.ru.md).
- Сторонние клиенты **не** получают произвольный SQL, signer service,
  signed GUC, native Core API key или доступ к production.
- 2G.3 добавил обязательный server-side audit contract с redacted
  Allow/Deny/Error и fail-closed поведением при ошибке sink.
  См. [SECURITY_AUDIT_V1.ru.md](SECURITY_AUDIT_V1.ru.md).
  2G.4 — end-to-end ephemeral PG acceptance, затем согласованная
  архитектура live SaaS identity/data plane и безопасного storage.

Другие спецификации:
[IDENTITY_SQL_BOUNDARY_V1.ru.md](IDENTITY_SQL_BOUNDARY_V1.ru.md),
[AUTHZ_RBAC_V1.ru.md](AUTHZ_RBAC_V1.ru.md),
[STAGING_POSTGRES_RLS_V1.ru.md](STAGING_POSTGRES_RLS_V1.ru.md).

## Фактическая проверка 2G.2

На commit `2ceb5727faf60efb7eabf90557470c14c5d0f2b1`:

- [Основной CI #38263480676](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480676):
  **SUCCESS**; 1 745 Bun тестов, 0 ошибок, ESLint, TypeScript
  и default-off Vite build; `dist/index.html` **3 305,72 KB**,
  неизменно относительно 2G.1b.
- [Ephemeral PG16 #38263480684](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480684):
  **SUCCESS** для существующего signed RLS/native-driver CI.
  **Не** является E2E исполнением нового JWT pipeline в PostgreSQL.
- [Demo #38263480798](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480798):
  **SUCCESS**, opt-in HTML **3 386,51 KB**.
- [Browser QA #38263480692](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480692):
  **SUCCESS**, синтетический SaaS UI.

Первый CI SHA `16e1529` имел **2 ESLint prefer-const ошибки**
после успешных 1 745 unit-тестов. Они исправлены в
`2ceb572`, затем выполнен полный повторный CI.

## Интеграция с аудитом (2G.3 — SIMULATED)

Успешная финальная проверка AuthZ заканчивается вызовом
обязательного синхронного `SecurityAuditRecorder` c `read-allowed`.
Отказ для чужого tenant — `tenant-hidden`, для auditor —
`role-forbidden`, для изменившегося actor/membership —
`authorization-changed` или `unauthenticated`. При отмене —
`request-cancelled`, ошибке SQL — `source-unavailable`.
У каждого Deny/Error audit event **tenantId=null**.
Если sink недоступен, даже уже прочитанные rows не возвращаются:
только generic 503. Версия, источник, `classification: synthetic`,
timestamp и разрешённые поля описаны в
[SECURITY_AUDIT_V1.ru.md](SECURITY_AUDIT_V1.ru.md).

**Этап 2G.3 проверен:** [CI #38265951045](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265951045)
подтвердил обязательный синхронный audit adapter, безопасные
allow/deny/error events, отсутствие чужих tenant IDs и generic
503 при сбое audit sink. Только synthetic fake SQL-port и
in-memory audit, не реальный backend ledger. Полный протокол:
[SECURITY_AUDIT_V1.ru.md](SECURITY_AUDIT_V1.ru.md).

## 2G.4a — реальный wire-protocol E2E для staging

Проверяемое взаимодействие pinned synthetic JWT, server-held actor,
signed SQL transaction, PostgreSQL RLS и synchronous audit запущено
на настоящем disposable PG16 через native Bun.SQL, а не fake port.
Новый скрипт и acceptance matrix документированы в
[E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md](E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md).
Это **не** production OIDC, durable actor-store или public HTTP/DTO.

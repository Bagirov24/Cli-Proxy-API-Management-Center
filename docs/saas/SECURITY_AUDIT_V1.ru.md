# 2G.3 — Security Audit Contract v1 (STAGING / SYNTHETIC)

**Статус: IMPLEMENTED / VERIFIED в synthetic CI на SHA
`1ea71978abd6abc33263fe460754d7f9dbdd1053`;
реальный audit backend, OIDC и PostgreSQL E2E — PROPOSED.** Никакого production sink, long-term ledger, Railway
deployment, real OAuth/API keys, сетевых маршрутов или публичных
HTTP endpoints. Работа выполняется только в feature-ветке Blueprint B.

## Граница доверия

Audit — **серверное решение** после identity → AuthZ → signed SQL.
Клиент не может задать actor ID, роль, tenant, correlation ID, источник
или код причины; запросы с непроверенными tenant IDs никогда
не приводят к записи этого tenant ID в журнал.

Временный контракт находится в
\`src/features/saasBlueprint/controlApi/server/securityAudit.ts\`.
Интеграция с isolated \`trustedSqlReadBoundary.ts\`:

1. Проверить pinned JWT + issuer/subject → server actor → membership/RBAC.
2. При **Allow** выполнить подписанный SQL и окончательно повторно
   проверить JWT/actor/member/role, затем синхронно записать событие.
3. При **Deny/Error** записать только безопасный reason, result,
   event/correlation metadata, **tenantId=null**. ActorId допускается
   только после серверного resolve/lookup, иначе null.
4. Если запись бросает исключение или используется неподдерживаемый
   async sink, вернуть generic **503** — не раскрывать успешные
   SQL rows при недостоверном статусе аудита.
5. Код и результаты ошибки SQL, signer, JWT, pool или sink не
   включаются в audit event или HTTP/body.
6. Все события создаются серверным \`createSecurityAuditRecorder\` с
   pinned \`classification: synthetic | staging\`. В данном этапе
   интегрирован **только synthetic in-memory sink**. Нельзя
   принимать classification из client JWT или HTTP headers.

### Поля фиксированной allowlist (ровно 11)

| Поле | Содержание |
| --- | --- |
| \`version\` | Константа \`1\` |
| \`occurredAt\` | ISO 8601 UTC, только backend clock |
| \`source\` | \`trusted-sql-read-boundary\` |
| \`classification\` | \`synthetic\` или \`staging\`, доверенная конфигурация |
| \`operation\` | Константа \`saas.metadata.read\` |
| \`correlationId\` | Server-generated ID, ограниченный формат |
| \`actorId\` | Server-resolved actor ID либо null |
| \`tenantId\` | **Только Allow** после AuthZ; иначе null |
| \`collection\` | Allowlisted read-only collection либо null |
| \`result\` | \`allow\` / \`deny\` / \`error\` |
| \`reason\` | Серверный enum, согласованный с result |

Причины: \`read-allowed\`, \`invalid-request\`,
\`unauthenticated\`, \`tenant-hidden\`, \`role-forbidden\`,
\`authorization-changed\`, \`request-cancelled\`,
\`source-unavailable\`. Недопустимые пары (например,
result=allow + reason=tenant-hidden) вызывают отказ.

**Запрещены без исключений:** сырые Authorization headers, access/
refresh/ID tokens, raw API keys, OAuth files, secret/private HMAC,
database passwords, proxy/VPN credentials, полные secret URI,
prompt/response contents, user-supplied metadata, SQL text/parameters,
внутренние driver errors, чужие resource IDs и произвольные
строки стека. Даже если JS caller добавит поля к объекту, аудит
копирует только одиннадцать описанных выше атрибутов.

### Synthetic sink

\`createSyntheticAuditBuffer(capacity)\` хранит от 1 до 1000
последних событий (по умолчанию 64), только в памяти тестового
процесса. Выдаёт копии frozen snapshots, не пишет в stdout,
console, DB, сетевой endpoint или production storage. Snapshot
не является API tenant data; нельзя добавлять его в UI/HTTP
response. При переполнении удаляется старейшая запись — это
**не** долговечный audit ledger.

Синхронный контракт намеренно не делает \`await\` после финального
RBAC. Он **не** доказывает гарантированную доставку события на
диск, точно однократную запись, multi-replica consistency или
production audit integrity. Реальный async audit backend потребует
отдельной архитектуры (outbox, durable store, retry, retention,
access-controlled investigation, key management, regulatory review).
Нельзя заменить его скрытым \`console.log\` или игнорировать
ошибку sink.

## Security acceptance в тестах

- \`tests/saasSecurityAuditContract.test.ts\`: фиксированный schema,
  server clock, enums, invalid values, forbidden extras, synthetic
  bearer/refresh/API keys, proxy URI, private prompt/response,
  hidden foreign tenant, bounded buffer/immutability, sink exception,
  async sink refusal.
- \`tests/saasTrustedSqlReadBoundary.test.ts\`: audit Allow North,
  404 for North→Orbit without logging foreign tenant,
  401 for wrong-audience token, mid-SQL membership revocation
  logged as safe deny, tenant-switch AbortSignal as error,
  and fail-closed 503 when sink fails even if SQL completed.

**Важно:** JWT/Signed SQL + audit acceptance пока выполнена через
синтетический actor directory и fake SQL-port. Существующие
PostgreSQL 16 RLS CI тесты не являются этим единым E2E потоком.
Нельзя объявлять SQL-пул, настоящий Core metadata adapter или
OIDC готовыми по результатам synthetic audit unit tests.

## Следующие инкременты

- 2G.4: временная PostgreSQL 16 с полноценным synthetic
  JWT→server membership→signed SQL→RLS→sanitation→audit, включая
  конкурентный отзыв прав и non-leakage.
- Отдельная security-приёмка реального audit ledger с политикой
  хранения, ACL, ротацией, tamper detection, rate limits и
  fail-closed operation; persistent store пока **PROPOSED**.
- Production реализация SQL connection lifecycle, live OIDC,
  Core/CPA read-only metadata integration и data-plane enforcement
  требуют отдельных согласований.

См. [TRUSTED_SQL_READ_BOUNDARY_V1.ru.md](TRUSTED_SQL_READ_BOUNDARY_V1.ru.md),
[ROADMAP.ru.md](ROADMAP.ru.md),
[BUN_SQL_DRIVER_PILOT.ru.md](BUN_SQL_DRIVER_PILOT.ru.md).

## Подтверждённый CI — инкремент 2G.3

Код проверен на SHA `1ea71978abd6abc33263fe460754d7f9dbdd1053`:

- [Main CI #38265951045](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265951045):
  **SUCCESS**, **1758 тестов / 0 ошибок**, ESLint, TypeScript,
  default-off Vite; обычная сборка `3 305,72 KB` (без прироста).
- [Ephemeral PostgreSQL #38265950944](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265950944):
  **SUCCESS**, существующие SQL/RLS/driver acceptance. **Это не**
  запись audit в PostgreSQL и не E2E тест JWT→RLS→audit.
- [Opt-in SaaS demo #38265950961](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265950961):
  **SUCCESS**, `3 386,51 KB`, unchanged.
- [Chromium synthetic browser QA #38265951009](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265951009):
  **SUCCESS**.

Тестируемая функциональность — **строго синтетический security audit
contract**, а не production persistent ledger. Нет внешних вызовов
поставщиков AI, записи в `/data`, Railway deployment и real credentials.

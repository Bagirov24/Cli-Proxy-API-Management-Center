# Read-only адаптер Core metadata v1 — порт и границы (RU)

**Статус: SPEC ONLY.** Здесь **нет реализованного backend adapter**,
сетевого клиента, чтения Railway volume, обращения к production Core,
CPA Key Policy или подключения к новым credential files. Контракт нужен,
чтобы будущая реализация не изменила модульный монолит B и не создала
публичный Core Management API.

## 1. Назначение порта

TypeScript интерфейс ReadOnlyTenantMetadataAdapter в
src/features/saasBlueprint/controlApi/contracts.ts — граница между
доверенным SaaS Control backend и источником metadata. Не использовать
его в React и не импортировать Core SDK в браузер.

Операция readCollection принимает AuthorizedReadScope:
actorId, tenantId, роль и серверный correlationId. Этот scope создаётся
**только backend** после проверки сеанса, tenant membership и RBAC.
TypeScript-типы **не заменяют** runtime-проверки и не подтверждают
идентичность пользователя.

Адаптер должен обеспечивать:

1. Предварительно проверенный tenant scope, не результат фильтрации
   общесистемного snapshot на клиенте.
2. Отдельные grants на pool/account/egress, включая owner/status/expiry;
   server-side scoped queries и RLS.
3. Удаление неизвестных полей DTO и полную redaction секретов.
4. Явный source = core-metadata-readonly только после успешного
   authenticated fetch; invalid или stale source = SOURCE_UNAVAILABLE,
   **не** отображать поддельный healthy/live статус.
5. AbortSignal, deadline, bounded pagination, rate limits, audit и
   cancellation/tenant-switch invalidation.
6. Отсутствие любых операций записи, OAuth-сессий, probe, reconnect,
   VPN config и выполнения AI-запросов в этом API.

## 2. Источник и допустимые поля

Сначала установить на **изолированном staging** документированный
источник каждого поля. Если его нет в закреплённом Core API, не
читать /data/auths вручную ради заполнения UI. Отсутствие подтверждённых
метаданных — «unknown», а не вымышленное значение.

| Поле UI | Потенциальный источник | Политика |
| --- | --- | --- |
| Tenant/Project/Application | будущая SaaS DB metadata | Только scoped по tenant |
| CPA Key Binding reference | официальный/документированный CPA metadata API или SaaS mapping | Только непрозрачный ID; secret не выдавать |
| Provider account status/auth mode | разрешённая metadata view Core/CPA, после проверки контракта версии | Никаких OAuth token, refresh token и raw auth file |
| Account pool/member IDs | SaaS mapping, отдельно авторизованные grants | Не раскрывать чужих account IDs |
| Egress profile type/status | SaaS registry или metadata view | Sanitized label, не proxy password или private VPN config |
| Verified outgoing IP/health | отдельная будущая staging service | Пока unknown; не проверять сеть из макета |
| Route decision, actual account selected | instrumentation после CPA scheduler | Пока SPEC, не считать resolver настоящим enforcement |
| Cost/tokens/latency | подписанный future usage ledger | Не смешивать estimate с live invoice |

## 3. Физические границы сети

- SaaS read adapter находится на backend/staging, не внутри публичного
  inference Gateway и не в production management.html.
- Core Management API должен остаться приватным; отдельные сервисные
  identity, allow-listed network ingress и least-privilege read-only
  credentials, когда будет отдельное разрешение на интеграцию.
- Не переиспользовать operator API key в SaaS user session. Нельзя
  передавать Management auth, OAuth files, CPA plaintext ключи или
  секреты прокси пользователям. Не использовать production Railway
  secret env или volume /data при проектировании.
- Если read-only metadata interface upstream недоступен, возвращать
  SOURCE_UNAVAILABLE без silent fallback на парсинг файлов или
  импорта конфигурации целиком.

## 4. Контракт отказов и гонок

При AbortSignal.aborted прекратить работу, не добавлять устаревший
result в UI store. Cache key должен включать actorId/tenantId/role,
grant revision и источник metadata; отзыв membership/grant обязан
инвалидировать старые ответы. Совпадение actorId не освобождает от
повторной tenant-проверки.

События аудита: correlationId, actorId, tenantId, action, resourceKind,
resultCode, timestamp, источник metadata. Исключить из audit logs
payload, request body, bearer tokens, Vault handles, upstream proxy URI
userinfo/password, тексты ошибок из raw Core.

Серверный timeout/read-source error = 503 generic, не ALLOW и не
fallback на прямой сетевой запрос. Никакой read-only adapter не может
самостоятельно изменить выбор Core account или маршрут egress.

## 5. Первые staging acceptance gates (пока НЕ выполнялись)

- Contract tests на точные поля выбранного metadata source под
  закреплённую версию CLIProxyAPI v8.0.23 и CPA Key Policy v0.5.1.
- Unauthorized tenant/IDOR/role denial и подтверждение RLS на уровне БД,
  не только TypeScript проектора.
- Тест отзыва каждой из трёх grants и invalid expiresAt.
- Нет секретов в успешных ответах, exceptions, logs, cache и traces.
- Cancel/race при 10 быстрых tenant-switch; нет stale cross-tenant UI.
- Отказ source/timeout/network partition возвращает generic 503,
  не переключает runtime на другой Core или direct egress.
- Убедиться, что нет write endpoints, VPN routes, OAuth exchanges
  и изменения Railway production.

До этих гейтов интерфейс использует только вымышленные DEMO_SNAPSHOT
и обязателен badge «SIMULATED». См.
[CONTROL_API_V1.ru.md](CONTROL_API_V1.ru.md),
[AUTHZ_RBAC_V1.ru.md](AUTHZ_RBAC_V1.ru.md).

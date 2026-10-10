# SaaS Control API v1 — контракт read-only (RU)

**Статус: SPEC + SIMULATED.** Это договорённость о будущем серверном API и
тестируемая чистая TypeScript-проекция данных, **не работающий HTTP endpoint**.
Ни одна функция из этого модуля не подключена к production, Core, Gateway,
Railway, OAuth или UI-маршрутизации. Применение политики к живому трафику
по-прежнему отсутствует.

## Задачи и границы

- Сохранить архитектуру B (модульный монолит), но разделить SaaS Control
  API и существующие Core Management API и AI inference Gateway.
- Начать с безопасного tenant-scoped metadata read, без изменения OAuth,
  выдачи credentials, маршрутизации, VPN, BYOK/BYOA, grants или бюджетов.
- Не возвращать чужие идентификаторы, ключи, токены, заголовки,
  пользовательские промпты, credentials или содержимое Core config.
- Для внешнего доступа требовать отдельную SaaS-сессию; CPA client key
  не является правом на Control API. tenantId из URL **не авторизует** доступ.

## Предлагаемая схема HTTP (пока SPEC)

| Метод / путь | Данные | Статус |
| --- | --- | --- |
| GET /control-api/v1/tenants | Активные организации только из memberships подтверждённого actor | SPEC |
| GET /control-api/v1/tenants/{tenantId}/metadata/tenant | Название, состояние и роль пользователя | SPEC |
| GET /control-api/v1/tenants/{tenantId}/metadata/projects | Принадлежащие организации проекты | SPEC |
| GET /control-api/v1/tenants/{tenantId}/metadata/applications | Приложения, связанные с доступными проектами | SPEC |
| GET /control-api/v1/tenants/{tenantId}/metadata/client-keys | Только CPA binding reference и статус, не plaintext | SPEC |
| GET /control-api/v1/tenants/{tenantId}/metadata/accounts | Собственные/явно разрешённые аккаунты, метод авторизации и состояния | SPEC |
| GET /control-api/v1/tenants/{tenantId}/metadata/pools | Собственные/разрешённые пулы, только отдельно доступные account IDs | SPEC |
| GET /control-api/v1/tenants/{tenantId}/metadata/egress | Собственные/разрешённые egress, только валидированные публичные host:port labels | SPEC |
| GET /control-api/v1/tenants/{tenantId}/metadata/routing | Правила своего приложения; непрозрачные или недоступные pool IDs = null | SPEC |

Никаких POST/PATCH/PUT/DELETE, preview живых запросов, health probes,
OAuth callbacks, raw Core credentials или реального enforcement на этом этапе.
Нельзя проксировать Core Management API наружу под этим URL.

## Ответы (вычисляются только локально на синтетике)

Успех: HTTP 200, пометка происхождения, только allow-listed поля.
При активной SaaS-интеграции source должен быть явно другим и проверенным,
не менять source на основании желания UI.

~~~json
{
  "ok": true,
  "status": 200,
  "apiVersion": 1,
  "source": "synthetic-simulation",
  "tenantId": "demo-north",
  "collection": "accounts",
  "data": [{
    "kind": "account",
    "id": "account-north",
    "owner": {"kind": "tenant", "tenantName": "North Studio", "access": "owned"},
    "providerId": "demo-provider",
    "authMode": "provider-api-key",
    "authorizationStatus": "approved",
    "status": "active",
    "allowedModelIds": ["demo-chat"],
    "egressProfileId": "proxy-north"
  }]
}
~~~

Отказ:

| Status / code | Когда | Внешнее сообщение |
| --- | --- | --- |
| 404 / NOT_FOUND | Нет активного membership, не существует tenant, чужой ресурс, неверная категория | Resource unavailable |
| 403 / FORBIDDEN | Есть membership, но не хватает RBAC capability | Permission denied |
| 403 / TENANT_UNAVAILABLE | Tenant подтверждён, но приостановлен | Resource unavailable |
| 503 / SOURCE_UNAVAILABLE | Неизвестная schema version или недостоверные временные данные; будущий adapter fail-closed | Service unavailable |

Ни в response body, ни в трассировке ошибки не раскрывать foreign tenant ID,
название аккаунта, egress hostname или исходный запрос. 401 и session expiry
реализует будущий authentication layer, **не** эта чистая модель.

## Политика представления данных

- Tenant/project/application scoped by ownership; orphaned связи не выдавать.
- ClientKeyBinding: только идентификатор CPA-привязки, никогда сам секрет.
- AccountPool, ProviderAccount и EgressProfile имеют **независимые**
  server-verified grants. Grant на пул не открывает аккаунты внутри.
- Account.egressProfileId становится null, если egress невидим клиенту.
  Pool.accountIds фильтруются по отдельным правам на каждый аккаунт.
  Routing.poolId скрывается, если пул недоступен.
- Не копировать неизвестные поля из исходных объектов через object spread.
  Все DTO собирать через список разрешённых свойств.
- source = synthetic-simulation для pure fixture. Значение
  core-metadata-readonly зарезервировано для будущего staging adapter, но
  сейчас **не может** быть получено без отдельной реализации.

## Подготовка к реальному backend (не выполнено)

1. Сервер создаёт actor из подтверждённой SaaS-сессии (cookie + CSRF для
   browser-client или подходящий OIDC flow). Клиентский header actorId/
   tenantId не является доказательством прав.
2. Перед выполнением любого DB/adapter запроса проверяет membership,
   status, RBAC capability, deadline и tenant state; для чужих ресурсов
   возвращает одинаковый 404. Гранты проверяются отдельно и по владельцу.
3. На уровне SQL задаёт tenant-scoped WHERE + foreign-grants join + RLS,
   обрабатывает отмену AbortSignal и разрывы tenant-switch; cache keys
   включают tenant+actor+role+grants-version, с отзывом при изменениях.
4. В v1 добавляет bounded pagination, stable sort, rate limits и
   correlation IDs, список allowed fields и серверную redaction. Ни одного
   произвольного filter/sort SQL от клиента.
5. Проверяет совместимость с закреплённым Core и CPA **только на staging**,
   без production management credentials; источник фактических account/pool
   metadata надо исследовать отдельно.
6. Отдельно проектирует mutations, idempotency, optimistic concurrency,
   audit, Vault и rollout. Этот SPEC не даёт права публиковать API.

## Исходный код и тесты

- src/features/saasBlueprint/controlApi/contracts.ts — версии, DTO, ошибки,
  типы actor/role и интерфейс будущего read-only adapter.
- src/features/saasBlueprint/controlApi/authorization.ts — чистое RBAC +
  проверка независимого grant (синтетическая модель).
- src/features/saasBlueprint/controlApi/readOnlyProjection.ts — fail-closed
  projection синтетического BlueprintSnapshot в tenant-scoped DTO.
- tests/saasControlApiV1.test.ts — unit/contract проверка cross-tenant,
  role denial, grants, expiry, foreign references и secret redaction.

Это только **проектная основа**, НЕ серверный security perimeter.
См. [AUTHZ_RBAC_V1.ru.md](AUTHZ_RBAC_V1.ru.md) и
[CORE_METADATA_ADAPTER_V1.ru.md](CORE_METADATA_ADAPTER_V1.ru.md).

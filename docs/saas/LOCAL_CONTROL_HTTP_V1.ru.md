# SaaS Control HTTP v1 — локальная изолированная демонстрация (RU)

**Статус: SIMULATED / LOCAL-ONLY.** Это исполняемый HTTP-обработчик
синтетических tenant metadata для тестирования доверительных границ.
Он НЕ является production SaaS-бэкендом, SSO/OIDC провайдером,
действующей системой auth или адаптером к Core/CPA.

Ветка: `feature/saas-blueprint-tenant-egress-20261010`; Draft PR №3.
Код **не** импортируется React Router, Gateway, Railway и production
management.html. Сервер автоматически нигде не запускается.

## Что действительно реализовано

- Fetch API Request/Response обработчик `createControlHttpHandler`,
  без состояния и без скрытой публикации HTTP port.
- Только `GET /control-api/v1/tenants` — список доступных организаций,
  **не глобальный список всех tenant**.
- Только `GET /control-api/v1/tenants/{tenantId}/metadata/{collection}`,
  где collection — `tenant`, `projects`, `applications`,
  `client-keys`, `accounts`, `pools`, `egress`, `routing`.
- Внутренняя **короткоживущая непрозрачная синтетическая сессия**:
  256 случайных бит из WebCrypto, hash-at-rest, срок до 15 минут,
  явный revoke. Токен создаётся только локальным bootstrap/test.
  **НЕТ** login endpoint и реальных OAuth сессий.
- Из токена определяется только actor ID; членство tenant/роль
  загружаются из доверенного server-held каталога при каждом запросе,
  независимо от клиентских `X-Tenant-ID`, `X-Actor-ID`, `X-Role`.
- RBAC/tenant membership проверяются перед вызовом metadata adapter,
  и повторно перед ответом для защиты от гонок tenant-switch,
  отзыва сессии и отзыва membership.
- JSON DTO собираются по серверному whitelist: неизвестные поля
  исходных объектов отбрасываются, ошибки upstream обобщаются.
  `source=synthetic-simulation` всегда виден; подменённый
  `source=core-metadata-readonly` блокируется.
- Запросы помечены серверным correlation ID; `Cache-Control: no-store`,
  `Vary: Authorization`, `nosniff`, отсутствуют CORS, cookies
  и выдача HTML. POST/PUT/PATCH/DELETE/OPTIONS не поддерживаются.
- Все демонстрационные ресурсы — North Studio, Orbit Lab, платформа и
  вымышленные proxy.example.net. В реальный AI/Gateway/Core/VPN
  **не отправляется ни одного запроса**.

## Как запустить локально (по отдельному opt-in)

Из папки существующей feature-ветки на своём компьютере:

```bash
bun install --frozen-lockfile
SAAS_CONTROL_SYNTHETIC_SERVER=true bun scripts/saas-control-local.mjs
```

Скрипт запускается **только** при явном флаге, отказывается стартовать
с `NODE_ENV=production` или Railway environment и всегда привязывается
к **127.0.0.1:18551**. Не используйте reverse proxy, туннель наружу,
Railway deployment, настоящие API keys или OAuth.

Локальный терминал напечатает временный **синтетический** Bearer токен
для North Studio. Используйте его только в локальном тесте (не
передавайте в чаты, логи, облачные переменные или публичный URL):

```bash
curl -i -H "Authorization: Bearer <локальный_тестовый_токен>" \
  http://127.0.0.1:18551/control-api/v1/tenants/demo-north/metadata/accounts
```

Под Windows PowerShell: установите
`$env:SAAS_CONTROL_SYNTHETIC_SERVER='true'`, затем выполните
`bun scripts/saas-control-local.mjs`. Ctrl+C останавливает сервер;
состояние сессий хранится только в оперативной памяти процесса.

Сам read-only React SaaS UX-прототип по-прежнему запускается отдельно
с `VITE_ENABLE_SAAS_BLUEPRINT_DEMO=true bun run dev` и **не**
переходит автоматически на этот локальный HTTP-обработчик.

## Коды ошибок и ограничения

| Ответ | Причина | Внешняя форма |
| --- | --- | --- |
| 200 | Сессия, tenant membership, RBAC и DTO успешно проверены | JSON c `synthetic-simulation` |
| 401 | Нет синтетической сессии; токен истёк, отозван или не прошёл проверку; actor удалён | Generic UNAUTHENTICATED |
| 403 | Пользователь известен, но RBAC запрещает коллекцию / чужой Origin / tenant suspended | Generic FORBIDDEN или TENANT_UNAVAILABLE |
| 404 | Нет членства, чужой tenant или неправильный маршрут | Generic NOT_FOUND |
| 405 | Любой метод кроме GET для допустимого маршрута | Allow: GET |
| 503 | Ошибка, невозможный формат metadata, изменение исходной схемы, abort, ошибка backend | Generic SOURCE_UNAVAILABLE |

Нельзя считать `200` разрешением на настоящий AI-запрос: это только
демонстрационный read-only просмотр metadata.

## Тестируемые границы и что не завершено

`tests/saasControlHttpBoundary.test.ts` проверяет попытки
подмены identity headers, случайные/истёкшие/отозванные сессии,
tenant breakout, RBAC denied до обращения к адаптеру, grant
revocation, ошибочные ответы upstream, неподтверждённый source,
in-flight отзыв membership/token, отсутствие внешнего CORS и кэширования,
URL validation, read-only методы и **localhost-only synthetic TCP**.

Оставлено в статусе **SPEC/PROPOSED**, не выполнено:
подлинный SSO/OIDC и issuer verification, shared session store и
revocation across nodes, PostgreSQL/RLS, audit журнал, Vault,
tenant-aware cache invalidation in UI, pagination/backpressure,
rate limits и полная проверка реального Core metadata API.
Перед staging потребуется threat model, TLS/mTLS, schema validator,
связь с auth server и integration contract tests. Публиковать этот
локальный bootstrap как публичный SaaS endpoint **запрещено**.

См. [CONTROL_API_V1.ru.md](CONTROL_API_V1.ru.md),
[AUTHZ_RBAC_V1.ru.md](AUTHZ_RBAC_V1.ru.md),
[CORE_METADATA_ADAPTER_V1.ru.md](CORE_METADATA_ADAPTER_V1.ru.md).

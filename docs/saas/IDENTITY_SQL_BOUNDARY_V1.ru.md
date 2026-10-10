# Этап 2E — проверка access-token и граница SQL-запросов (RU)

**Статус: SIMULATED / CONTRACT VERIFIED на тестовых ключах и на
ephemeral PostgreSQL CI. Реальный SaaS OIDC, PostgreSQL pool,
audit и Core adapter: SPEC/PROPOSED.**

## Задача и ограничения

Проект по-прежнему использует архитектуру B — модульный монолит.
Этот этап не меняет SaaS demo, React Router, Gateway, Core, CPA
Key Policy, OAuth файлы, VPN или Railway production. Никакого
публичного authentication endpoint, новых реальных сессий либо
настоящих API keys нет.

Добавлены два независимых backend-порта, которые **не смонтированы**
в работающий сервис.

### 1. Проверяемое происхождение actor из JWT access-token

Файл: `src/features/saasBlueprint/controlApi/server/trustedAccessToken.ts`.

- Поддерживается только **RS256 API access-token** с `typ=at+jwt`,
  issuer с HTTPS, строго закреплёнными публичными RSA/SHA-256 ключами
  (`kid`), обязательным audience, subject, iat, exp и проверкой nbf.
- Максимальная длительность токена в контракте — 15 минут.
  Подпись должна подтверждаться WebCrypto; допускается 30 секунд
  положительного рассогласования только для `iat`.
- `alg=none`, другой `alg`, ID-token (`typ=JWT`),
  чужой issuer/audience, динамические `jwk/jku/x5u/crit`,
  неподтверждённый kid, неверная подпись и истёкший токен
  приводят к **отказу**. Никакой загрузки ключей по ссылкам из токена.
- `createVerifiedSubjectSessionBridge` получает только пару
  **issuer + subject** и просит доверенный server-side directory
  выдать внутренний actorId. `role`, `tenantId`, `actorId`
  из JWT или HTTP-заголовков **не используются как разрешения**.
- Серверный `httpHandler` сохраняет ранее реализованную проверку
  actor membership и tenant RBAC до чтения и после асинхронного чтения.

**Важное ограничение:** это строгий контракт конкретного формата JWT,
а не универсальная OIDC библиотека, полноценный login, token refresh,
JWKS rotation или реальный session/revocation store. Для будущего
production OIDC надо выбрать официального issuer, подтвердить
`iss/aud/typ`, настройки клиента, происхождение ключей и
периодическое безопасное обновление pinning. Нельзя использовать
`id_token` вместо access-token. OAuth BYOA здесь не реализуется.

### 2. Только параметризованные read-only SQL шаблоны

Файл: `src/features/saasBlueprint/controlApi/server/signedSqlBoundary.ts`.

В отдельный injectable `ScopedSqlPool` передаются уже доверенный
`AuthorizedReadScope` и `SignedTransactionIssuer` (пока fixture
HMAC). Один вызов делает:

1. Получить соединение из выделенного пула.
2. `BEGIN`, прочитать `txid_current()`.
3. Подписать actor/tenant/expiry/txid HMAC-SHA256, совпадающим по
   формату с SQL-миграцией 002. Ключ передаётся только из
   привилегированной зависимости; не существует endpoint для подписи.
4. Установить **пять** GUC через параметризованный `set_config`
   с `is_local=true`, затем `SET LOCAL ROLE saas_rls_reader`.
5. Выполнить один фиксированный `SELECT` из разрешённой
   `ControlCollection`. Значения tenant и limit **только в $1/$2**,
   категория определяет серверный шаблон; нет свободного SQL от клиента.
6. Отбрасывать неизвестные поля, отклонять чужой `tenant_id` и
   неправильный формат ответа.
7. `COMMIT` при успехе либо `ROLLBACK` и discard соединения при
   ошибке, включая abort, без текста внутренней ошибки в ответе.

Максимум 100 строк и TTL scope 60 секунд. `saas_rls_reader`
по-прежнему не имеет права читать приватный HMAC-ключ и таблицы
membership/grants напрямую. SQL сам проверяет RLS membership, owner,
grants и expiry. Важная техническая деталь: транзакция запускается
через `BEGIN`, а read-only операции ограничиваются ролью без DML:
`txid_current()` выделяет transaction ID. Это пока контракт пула,
а не интегрированный driver/connection string.

### Проверки

`tests/saasOidcIdentityBoundary.test.ts` использует новые
эфемерные RSA-ключи только в тестовом процессе и проверяет
валидную подпись, issuer, audience, отсутствие просрочки,
`typ`, попытки downgrade, несовпадающий kid и перевод
issuer+subject во внутренний actor directory.

`tests/saasScopedSqlBoundary.test.ts` проверяет фиксированные
SQL-тексты, placeholders, отсутствие раскрытия лишних полей,
ошибки/rollback, отмену запроса, discard соединения и
HMAC-совместимый формат.

`tests/sql/saas_scoped_queries.test.sql` на временном
PostgreSQL 16 проверяет `PREPARE/EXECUTE` с SQL-подобными
tenant-строками, то, что они остаются **данными**, а также
исчезновение signed transaction-local GUC при повторном
использовании того же PostgreSQL соединения.

Все результаты относятся только к fixture и временному CI.
SQL script запускается после SQL-тестов миграций 001/002,
без публичной базы и без production credentials.

### Оставшиеся обязательные гейты

- Выбрать и проверить настоящий OIDC issuer/JWKS rotation,
  revocation и session lifecycle; не принимать неподтверждённый JWT.
- Доверенное отображение issuer+subject в SaaS actor и
  server-side tenant membership/RBAC, аудит событий AuthZ.
- Отдельный драйвер PostgreSQL, connection pool c ограничениями,
  неблокирующим timeout, гарантированным очисткой соединения и
  отдельной read-only идентичностью; **не суперпользователь**.
- Синхронизация/ротация ключа HMAC между отдельным backend issuer
  и приватным DB verifier, без доступа браузера и SQL-reader.
- Настоящие проверки с драйвером на staging: isolation transactions,
  SQL injection/fuzzing, cancellation, concurrency, pool reuse,
  метрики и отказ при сетевом сбое.
- Подключение read-only metadata adapter к официально разрешённому
  источнику CLIProxyAPI на **изолированном staging** — только после
  отдельного согласования. Сейчас поля account auth/egress/billing
  в SQL-пилоте не являются реальными данными Core.

**Не включать этот код в production `management.html` и не
развёртывать его как публичный API.** Смотрите также:
[CONTROL_API_V1.ru.md](CONTROL_API_V1.ru.md),
[SIGNED_SCOPE_RLS_V1.ru.md](SIGNED_SCOPE_RLS_V1.ru.md) и
[CORE_METADATA_ADAPTER_V1.ru.md](CORE_METADATA_ADAPTER_V1.ru.md).

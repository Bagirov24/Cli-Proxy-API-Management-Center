# Реальный server-only pinned OIDC access-token trust — backend slice 03

**Статус: реализация парсера конфигурации и независимого RS256 verification port; не подключён к Railway/Gateway, нет реального входа пользователей или SSO.** Parent unified release-candidate Draft #25, SHA `cbe44877cdde4f28d82f7bf544ac57e1a5f9dc59`.

## Что даёт

`src/features/saasBlueprint/controlApi/server/operatorPinnedOidcAccessVerifier.ts` принимает только явно одобренные оператором значения `SAAS_OIDC_ISSUER`, `SAAS_OIDC_AUDIENCE`, `SAAS_OIDC_PINNED_PUBLIC_JWKS_JSON` через `pinnedOidcConfigFromServerEnvironment(process.env)`. Инициализация возвращает `AccessTokenVerifier`, совместимый с уже проверенными tenant read/write factories. Пример формы **публичного** keyset (подставить реальный открытый ключ своего одобренного IdP, не фиктивные значения):

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "issuer-approved-key-id",
      "alg": "RS256",
      "use": "sig",
      "n": "base64url-full-public-modulus",
      "e": "AQAB"
    }
  ]
}
```

Ключи поставляются **вне HTTP-запросов**, из контролируемой владельцем конфигурации. Максимум 4 публичных RSA ключа длиной 2048–4096 бит, `e=AQAB`, уникальные `kid` и modulus. Опциональный `key_ops` может быть строго `["verify"]`. Отвергаются `x5u/x5c/jku`, JWK private RSA `d,p,q`, HMAC/oct, unknown JSON fields, неканонический RSA modulus, случайная подмена `alg`. Ключи импортируются как **non-extractable public CryptoKey** с единственным правом `verify`. Нет OIDC Discovery/JWKS auto-fetch и нет fallback на mock issuer/ключи. Ошибки старта не содержат ни token, ни URL, ни параметры ключа.

Существующий `createPinnedAccessTokenVerifier` (проверен M1a–M1q) дополнительно требует:
- заголовок `typ=at+jwt` (обычный JWT/id token нельзя использовать как access token);
- `alg=RS256`, разрешённый `kid`, точную подпись, issuer/audience, `iat/exp/nbf`, срок токена не более 15 минут; запрещены встроенные `jku/jwk/x5u/x5c` и переопределения алгоритма;
- возвращает ТОЛЬКО `issuer,subject,expiresAtSeconds`. Actor, tenant, membership и роль **никогда** не копируются из клиентских claims: следующие server-only actor-directory и durable session/PG25 блокеры остаются обязательными.

## Смена JWKS (без динамических fallback)

1. Независимо проверить по доверенному каналу IdP источник и новые **публичные** RSA ключи/идентификаторы; проверить active issuer/resource audience, expiry договорённости и operator change ticket.
2. На staging выдать два одобренных ключа (A+B), прогнать real provider `at+jwt` и negative issuer/audience tests. Это ещё не production trust approval.
3. Только после подтверждения доставки токенов B и завершения окна A создать новый operator-approved config c ключом B без A. При выпуске verifier заново импортирует snapshot; старый `kid=A` перестаёт приниматься, нет автоматического fetch.
4. Для экстренного revoke немедленно остановить выдачу или загрузку новых токенов на внешнем IdP, убрать compromised kid, и отозвать связанные durable per-bearer сессии/PG epoch независимо; **смена открытого ключа сама по себе не отменяет уже открытые backend сессии**.
5. При ошибке config запуск нового сервиса отказывает закрыто, а не подхватывает synthetic JWT, последнюю динамическую JWKS или production CPA OAuth credentials.

## Всё ещё требуется до публичного SaaS API

- Выбрать/подключить реальный IdP и согласовать именно **JWT access token** `typ: at+jwt`, short TTL, fixed audience; некоторые провайдеры выдают opaque access tokens или не поддерживают этот формат — в этом случае **не ослаблять проверку**, а выбрать утверждённый другой boundary.
- Внешнее OIDC callback/state/PKCE/nonce, trust roots & rotation, браузерная cookie/CSRF модель либо BFF (в этом PR **нет** login endpoint, redirect или refresh token).
- Доверенный **durable** issuer+subject→actor mapping, БД memberships/revision, token-fingerprint→session UUID/epoch, revocation across replicas; новые интерфейсы не создают пользователей и не повышают роли.
- Отдельная постоянная PostgreSQL миграция, строго least-privilege signer и физическая quarantine при SQL uncertainty; независимый off-host WORM и COMMIT dispute workflow.
- Production source branch, rollback Core/`/data`, release workflow и Railway deployment gatings; pen test, code owner/security approval.

`tests/saasOperatorPinnedOidcAccessVerifier.test.ts` генерирует временные RSA ключи только внутри GitHub CI, проверяет настоящую подпись, смену A→A+B→B, неверные issuer/audience/typ/alg и строгий отказ при некорректном/JWK с private key. В тестах нет real provider secrets и нет сетевых запросов.

**Нет Railway writes, публичного слушателя, production keys, production PG, release update, merge/Ready, auto-retry/GC.** Это реальный компонент аутентификации, но не production SSO до независимой проверенной конфигурации.

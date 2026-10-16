# M1l — синтетический OIDC discovery/JWKS rollover и отзыв PG16 сессии (CI-only)

**STACKED DRAFT / НЕ PRODUCTION / НЕТ ГОТОВОГО OIDC/SSO.**
Основание — [M1k Draft PR №14](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/14),
проверенный перед ответвлением HEAD `288792c5` (4/4 SUCCESS).
Родительские Draft PR №3–14 не мержить и не менять.

## Новый ограниченный функционал

`scripts/saas-staging/m1l-synthetic-oidc-rotation.mjs` создаёт
проверяющий компонент **только** под явными
`GITHUB_ACTIONS=true` и `SAAS_EPHEMERAL_M1L_OIDC_CI=true`,
без Railway-переменных и без production NODE_ENV. Он выполняет
настоящие bounded HTTP GET к **строго закреплённым** URL на
`127.0.0.1:<ephemeral-port>/.well-known/openid-configuration`
и `/jwks`. Redirect, внешний hostname, username/password,
query, непредусмотренный путь и динамический `jku/x5u` из JWT
не используются. HTTPS issuer — только строковый pin, а не
реальный внешний HTTPS IdP.

Из discovery принимается ровно pinned `issuer`, заранее
известный `jwks_uri` и объявленный `RS256`.
JWKS должен иметь 1–3 RSA-2048/4096 public-only ключа:
`kty=RSA`, `alg=RS256`, `use=sig`, `key_ops=["verify"]`,
`e=AQAB`, уникальные доверенные `kid` и корректный публичный
modulus. Любые private-поля, `HS256`/`none`, повтор `kid`
с другим ключом, некорректный JSON, redirect, слишком большой
ответ или rollback ранее удалённого `kid` запрещены.

Только после полного успешного импорта создаётся новый pinned
`createPinnedAccessTokenVerifier`. Snapshot revision монотонен.
Активные токены проходят существующие `typ=at+jwt`,
подпись RS256, issuer, audience, subject, iat/exp/nbf.
Ключ удалён из набора — ещё не истёкший токен с этим `kid`
уже отклоняется. Неудачный refresh **карантинирует все** токены:
старый cached JWKS не применяется молча. Новый корректный
snapshot следующей ревизии может восстановить доступ.
Устройство явно не реализует offline pin при рестарте,
distributed CAS, TTL/cache, refresh-token lifecycle или
настоящий OIDC provider trust.

## Настоящий сквозной GitHub disposable PG16 тест

`scripts/saas-staging/verify-m1l-oidc-pg-ci.mjs` запускается
**шестым отдельным** процессом после полного M1a–M1k
adversarial acceptance на одноразовой
`127.0.0.1:5432/saas_ephemeral_test` с SQL025,
не переисполняя старые счётные фикстуры. Он создаёт два
временных loopback сервера — mock OIDC source и закрытый M1i
POST project HTTP adapter — и ephemeral RSA keypairs A/B.

Реальная цепочка:

1. Синтетический токен A подписан RSA-A; pinned JWKS=A;
   серверный fingerprint уже проверенного токена сопоставляет
   **только из CI registry** UUID/revision сессии A; никогда из
   JWT `sid`, `actorId`, `tenantId` или HTTP заголовков.
2. M1i transport → trusted issuer/subject directory →
   активная actor/membership роль → отдельный
   M1h Ed25519 witness fsync **до** PG-резервации →
   HMAC-signed native Bun.SQL transaction →
   SQL025 `FOR SHARE` для UUID/revision →
   M1d current tenant auth fence, M1c mandatory audit,
   M1g unique attempt UUID в **одном PG COMMIT**.
3. JWKS=A+B принимает старую A и новую B сессии;
   JWKS=B немедленно отказывает новым A-запросам.
   B остаётся разрешённой даже после отзыва A на PG стороне.
4. Атака на окно гонки: уже прошедший A HTTP request
   удерживается **после** bearer verifier и после fsync intent,
   но до PG. Issuer активирует B-only JWKS, privileged
   disposable fixture атомарно revokes A session и
   повышает revision/tenant epoch. Уже проверенный
   HTTP A-запрос затем **должен получить 404 от PG gate**:
   **0 project / 0 audit / 0 UUID binding**.
5. Неправильный issuer metadata, JWT неизвестного токена,
   попытка rollback старого `kid`, неподтверждённые подпись
   или список ключей — HTTP `401`, **без резервирования PG**.
   После валидного snapshot=B B продолжает работать.
6. Остановка M1h signer даёт `503` до DB reservation;
   автоматического retry, idempotent replay, mint/reissue
   или разрешения UNKNOWN COMMIT нет.

Отдельный SQL-файл
`tests/sql/saas_m1l_synthetic_oidc_pg_e2e.test.sql`
проверяет **пять** завершённых HTTP create (5 projects,
5 mandatory private audit, 5 unique UUID binding,
5 session proofs), ровно одну A revocation при одной B
active session, отсутствие ghost rows в заблокированных
операциях, прежние RLS/grants/M1d+M1k triggers и
idempotent replay SQL025.

`tests/saasM1lSyntheticOidcRotation.test.mjs` проверяет
A→A+B→B, чужой issuer, недопустимый JWKS endpoint, JWT
alg/typ/claims, дубликаты, ключевую подмену, truncated/oversize,
redirect, rollback `kid`, monotonic revision, quarantine и
manual valid recovery. В общем `bun test` тесты, требующие
network/CI flag, **пропускаются**; отдельный явно включённый
GitHub CI step обязан выполнить их без пропусков.

## Принципиальные ограничения

- Это mock, **не** реальное OIDC discovery/TLS/JWKS trust,
  OAuth authorization code flow/PKCE, redirect URI,
  refresh/revoke endpoint, logout, rotation policy настоящего
  IdP, социальный логин или продакшен SSO.
- JWT ключи ephemeral, server session registry живёт только
  в памяти того же GitHub CI. Реальное persistent
  issuer-key trust/backchannel logout и multi-replica session
  version coordination не реализованы.
- M1h Ed25519 witness и PG16 находятся на одном runner:
  **не** independent WORM/HSM и не внешний precommit
  durable root. UUID custom GUC не привязан отдельной
  криптографической подписью к токену/сессии.
- Race между проверкой JWT и PostgreSQL разобрана в
  синтетическом случае, но нет полноценной проверки
  network partition **DURING COMMIT**, production pool
  physical discard, мульти-региона, human UNKNOWN COMMIT
  adjudication, trusted high-water или exactly-once.
- Нет публичного backend listener, production migrations,
  tenant onboarding, CPA/BYOA/egress/pools,
  secret rotation, observability/DR, SLA или release approval.

## Merge и Railway

Слияние **default-off CI-пилотов** требует независимого
code-owner/security/operator review, проверок 4/4 на точном
финальном HEAD, формально подтверждённой последовательности
всех stacked PR и отдельного письменного merge approval.
Даже merge **не включает production SaaS**.

Срок ранее документированной тестовой Railway PKI:
**15 октября 2026, 13:33 UTC**. В sandbox ранее наблюдался
no-listener deployment, retained `synthetic-highwater-only`
volume; независимого negative TCP8443 probe не было.
M1l не изменяет Railway.

**Hard stops:** no Ready/merge/deploy, no SQL019 или
production PostgreSQL/volume/key, no Railway signer/journal,
no live Core/CPA/OAuth key issuance/reissue/delivery/GC,
no automatic retry/repair/UNKNOWN COMMIT reissue.
`gcPermitted=false`.

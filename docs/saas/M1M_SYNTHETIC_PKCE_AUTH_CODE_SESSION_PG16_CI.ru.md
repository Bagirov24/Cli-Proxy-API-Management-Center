# M1m — Authorization Code + PKCE S256 и серверная PG16-сессия (CI-only)

**STACKED DRAFT / НЕ REAL OIDC/SSO / NO PRODUCTION / NO RETRY.**

База: [M1l Draft PR №15](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/15)
на HEAD `c141b3a8` (4/4 SUCCESS), далее №14→№3. Родительские
PR остаются Draft, не мержились и не менялись.

## Малый вертикальный срез

Новый `scripts/saas-staging/m1m-synthetic-pkce-code-flow.mjs`
реализует **только на одноразовом GitHub runner** две роли:
серверный mock OAuth2 client и отдельный mock issuer. Обе фабрики
требуют явный `SAAS_EPHEMERAL_M1M_PKCE_CI=true`, GitHub Actions,
отсутствие Railway и production `NODE_ENV`.
Нет public login, callback route, живых пользователей,
TLS/OIDC token endpoint внешнего провайдера или cookies.

- Client `begin()` создаёт 32 случайных байта PKCE verifier и
  случайный `state`. В браузероподобную ссылку отправляется
  **только** `code_challenge=BASE64URL(SHA256(verifier))`,
  `code_challenge_method=S256`, `response_type=code`,
  pinned `client_id`, `redirect_uri`, `scope=openid`, `state`.
  PKCE verifier остаётся только в приватной памяти клиента.
- Mock issuer обслуживает реальные HTTP GET `/authorize` и
  POST `/token` только на закреплённом `127.0.0.1:<port>`.
  Выдаёт криптографически случайный одноразовый code,
  привязанный к S256 challenge, client_id и redirect URI;
  код расходуется **до** проверки PKCE. Plain challenge,
  redirect switch, неверный client, grant и двойное погашение
  отвергаются. Endpoint не поддерживает refresh token.
- Client `complete(callback)` допускает ровно закреплённый
  redirect path и параметры `code/state`, отклоняет дубликаты,
  фрагменты и чужой origin. Server-side `state` удаляется
  **до** обмена кодом и при ошибке issuer; нет повторной
  попытки из callback, даже при сетевой неопределённости.
  Есть лимит 8 ожидающих flows и срок 90 секунд в CI.
- Ответ `/token` ограничен 8 KB, проверяет ровно
  `access_token/token_type/ expires_in`, redirects/HTML
  отвергаются. Access token криптографически проверяется
  M1l pinned JWKS/RS256 (`typ=at+jwt`, aud, iss, exp, iat),
  затем `issuer+subject → actor` определяется **только**
  серверным trusted directory. JWT `role`, `actorId`, `sid`,
  `tenantId` рассматриваются как недостоверные данные.
- Только после проверки token и actor серверный
  `provisionSession` создаёт случайный UUID/revision
  в частной одноразовой таблице PostgreSQL16. Browser
  redirect содержит **code и state, но НЕ access token**;
  доступ к результату обмена имеет только CI server harness.

## Реальная цепочка в disposable PostgreSQL16

Отдельный **седьмой** вызов
`scripts/saas-staging/verify-m1-project-pg-e2e.mjs`
запускается только после полной приёмки M1a–M1l,
SQL025 и M1l JWKS rotation. Участвуют реальные ephemeral
loopback issuer + M1i project HTTP + Bun.SQL PostgreSQL16.

Три правильных независимых code exchanges одного issuer/actor
регистрируют три отдельные server-held PG16 session UUID:
A, B, C. Через настоящий HTTP bearer POST:

- A и B создают проекты с подписанными транзакциями:
  **project + mandatory private audit + M1g UUID** в одном COMMIT;
- Запрос от C проходит RS256 и HTTP authorization,
  отдельный M1h Ed25519 witness успевает `fsync` precommit
  intent, но PG connection ещё не резервируется. Admin
  disposable fixture отзывает C и повышает revision.
  Продолженный HTTP C получает **404 и 0/0/0**, потому что
  M1k `FOR SHARE` проверяет реальную current session
  после отзыва. Наличие precommit intent **не лицензирует retry**;
- После отзыва A прежний access token остаётся криптографически
  правильным, но подписанная PG16 session gate возвращает **404**.
  B при этом продолжает работу, третий проект фиксируется;
- Недоступный M1h signer даёт **503 до PG reservation**;
  никакой автоматической повторной выдачи или операции нет.

Проверяется **5 fsynced подписанных PRE-COMMIT попыток**,
из них **3 COMMIT** и **2 отклонены сессиями**; отдельный
no-PG offline verifier проверяет цепочку. Привилегированный SQL
`tests/sql/saas_m1m_pkce_code_pg_e2e.test.sql`
подтверждает 3 project/3 audit/3 distinct attempt UUID/
3 session-proof rows, сессию A revoked, B active, 0 ghost
rows от отменённых операций, прежние private FORCE-RLS
grants/triggers и idempotent replay SQL025.

`tests/saasM1mSyntheticPkceCode.test.mjs` отдельно проверяет
одноразовость кода и callback, CSRF state forgery,
code/state swap, параллельные callback, неверный S256 verifier,
ошибку issuer, expiry, подмену client/redirect/scope,
невалидные token/JWKS и лимит pending states. В обычном
`bun run verify` тесты opt-in пропускаются;
отдельный GitHub step с `SAAS_EPHEMERAL_M1M_PKCE_CI=true`
обязан исполнить их без пропусков. Нет изменения публичного
server/router/UI.

## Чего этот CI-тест НЕ доказывает

- **Не реальный OAuth/OIDC/SSO:** нет внешнего HTTPS issuer,
  полной схемы TLS trust, IdP consent, account provisioning,
  авторизационного сервера, работающего callback endpoint,
  CSRF cookie binding, PKCE browser flow/secure cookie flags,
  ID token signature/nonce/at_hash, backchannel logout,
  refresh-token rotation/revocation, distributed state store.
  Временный access token используется только server-side
  тестом; production web login пока отсутствует.
- **Не external WORM/COMMIT settlement:** M1h signer и PG
  находятся на одном ephemeral GitHub runner, ключ подписанта
  не HSM и key pin не durable. Сетевой разрыв **во время**
  COMMIT и operator adjudication остаются не проверены.
  **No exactly-once / auto retry.**
- **Не production API:** нет production migrations,
  безопасного физического pool discard для живой сети,
  реального OIDC session lifecycle, tenancy onboarding,
  CPA/BYOA/pools/egress/quota/billing, DR/observability.
- Любой merge — отдельный codeowner/security/operator review,
  явное письменное разрешение и последовательный merge
  Draft PR №3→№15→M1m. Слияние CI-only пилотов **не
  активирует SaaS**.

## Railway и hard stops

В последней read-only проверке Railway sandbox ранее был
`SUCCESS` no-listener, retained `synthetic-highwater-only`
volume в `/staging-highwater`. Экспирация synthetic TLS PKI:
**15 октября 2026 года, 13:33 UTC**. Без отдельного
negative TCP8443 probe отсутствие доступного порта не доказано;
M1m не делает Railway writes, не выпускает сертификаты
и не активирует listener.

**NO** merge/Ready/deploy, SQL019, production PostgreSQL,
Railway signer/journal/volume, настоящие CPA/Core/OAuth ключи,
mint/reissue/retry/repair/delivery/archive/GC.
`gcPermitted=false`, `authorizationGranted=false`.

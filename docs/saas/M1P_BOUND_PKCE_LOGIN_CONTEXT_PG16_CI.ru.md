# M1p — server-owned PKCE login context isolation + cancellation before PG16 enrollment

**STACKED DRAFT / CI ONLY / DEFAULT OFF / NOT A BROWSER LOGIN OR PRODUCTION LOGOUT.**
Parent: [M1o Draft PR #18](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/18), verified initial HEAD `e80c2c4476f777e53aff8ede10bdb7a504630f25`, 4/4 Actions SUCCESS. Parent PRs #3–18 are not modified, merged or promoted.

## Узкая закрываемая граница

В M1m–M1o server-owned PKCE verifier+state одноразовый, но M1m client использовал общую очередь pending callbacks для всех синтетических браузерных контекстов. В M1p новый опциональный `scripts/saas-staging/m1p-bound-pkce-login-context.mjs` создаёт **неугадываемый локальный object-reference context** для каждого начала входа; его M1m клиент и одноразовый state/verifier не разделяются с другим контекстом. Callback B в контексте A отвергается до запроса `/token` и **не уничтожает** легитимные состояния A/B. Начатый callback принадлежит ровно одной контекстной попытке: claim до первого await, параллельное завершение/replay отказывает. Не более одного ожидающего логина на контекст и 8 активных контекстов на клиент.

`cancelContext` терминально отменяет **только ещё не завершённый вход**. При отмене в паузе после настоящего pinned HTTPS OAuth token response и после доверенной RS256-проверки, но **до синхронной фикстурной регистрации PG16-сессии**, fail-closed guard запрещает создание сессии. OAuth authorization code может быть уже потрачен IdP — не переисполнять обмен и не повторять выдачу. Отмена B не останавливает зарегистрированную независимую PG-сессию A. Существующий M1k signed DB session revoke остаётся отдельным механизмом для уже завершённых входов.

Важно: в M1p регистратор сессии намеренно **синхронный и одноразовый**, без await между финальной проверкой context и `register` в том же event loop. Это не доказательство атомарного logout с асинхронным, удалённым persistent PG provisioning. После реального COMMIT успешной сессии её отмена требует отдельного PG revoker; `cancelContext` не пытается удалить/восстановить credentials и не подменяет signed M1k. Никакого cookies/CSRF браузерного binding, публичной OAuth callback route, durable anti-replay, distributed multi-instance store, браузерной SameSite/HttpOnly сессии и реального OIDC login тут нет.

## Независимые CI-подтверждения

- Opt-in `tests/saasM1pBoundPkceLoginContext.test.mjs` использует реальные ephemeral CA/SAN/SPKI HTTPS handshake, code+PKCE S256, pinned JWKS/RS256, два параллельных контекста A/B. Wrong-context callback не обменивает code и не сжигает допустимый callback; повтор не создаёт новую сессию. Проверяются недействительные ссылки объектов, malformed callback, terminal cancel, ограничение контекстов и отказ от async registrar.
- Особый race: real HTTPS `/token` успешно выдал bearer, `verifyAccessToken` принудительно задержан; оператор CI отменяет конкретный login context; после возобновления нет вызова registrar, token binding и PG-сессии, а code повторно не используется.
- Десятый **отдельный** disposable PostgreSQL16 прогон **после M1o** под opt-in `SAAS_EPHEMERAL_M1P_CONTEXT_CI=true`, с HTTPS mock leaf после явной M1o CA/SPKI epoch=2. Независимые реальные signed project writes с префиксом `m1p-` дают 3 project / 3 mandatory audit / 3 UUID binding, M1k session gate и C/A revocation (0/0/0 ghost), B сохраняет доступ, отказ M1h witness 503 с нулём новых PG reservations.
- Два явных `PASS M1p`: основной JavaScript HTTPS→PKCE→PostgreSQL16 путь и независимый `tests/sql/saas_m1p_bound_login_context_pg_e2e.test.sql` для committed data, session proofs, FORCE RLS/ACL, mandatory triggers и SQL025 replay. Требуются Main CI, disposable PostgreSQL16, Demo Build, Chromium QA на **одном точном финальном SHA**.

## Оставшиеся release blockers

CI контекст — process-local opaque object, а **не** cookie. Настоящие browser callback/cookie/SameSite/CSRF/nonce/ID token, logout/backchannel revoke, refresh-token rotation, cross-replica state, production signer/governance OIDC PKI, независимый WORM/HSM, UNKNOWN COMMIT DURING network partition, физический SQL pool discard, SaaS tenant onboarding, CPA/Gateway integration, юридическое и security/code-owner/операторское approvals остаются OPEN.

Railway sandbox test TLS PKI имеет отдельный срок **2026-10-15 13:33 UTC**. Текущая read-only проверка свидетельствует об успешном no-listener deployment, отсутствии public domain/TCP proxies и сохранённом `synthetic-highwater-only` volume. Независимой отрицательной проверки внутреннего TCP 8443 нет, поэтому задача не закрыта. Никакие действия по ротации/деактивации, Railway secrets, service, signer, journal и volume в M1p не выполняются.

STOP: no Ready/merge, production deploy/SQL019, real CPA/Core/OAuth credential issuance/reissue/restore/archive/GC, UNKNOWN COMMIT retry, Railway changes without explicit operator decision. `authorizationGranted=false`, `gcPermitted=false`.

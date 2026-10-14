# M1n — реальный HTTPS trust-boundary для синтетического OAuth/PKCE (CI-only)

**STACKED DRAFT / НЕ REAL IDP / НЕ PRODUCTION.**
Родитель: [M1m Draft PR №16](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/16),
проверенный HEAD `20637f4b` — 4/4 SUCCESS. Продолжение цепочки
Draft №15→№3. Ни один PR не мержится автоматически.

## Что действительно добавлено

В M1m сервер и тестовый IdP обменивались одноразовым кодом по
`http://127.0.0.1` с жёстко закреплённым issuer-идентификатором.
M1n переносит **только mock IdP trust path** на реальные TLS
соединения с самим GitHub runner — внешний IdP не используется.

`scripts/saas-staging/m1n-ephemeral-tls-fixture.mjs` в явном
`GITHUB_ACTIONS=true`, `SAAS_EPHEMERAL_M1M_PKCE_CI=true` и
`SAAS_EPHEMERAL_M1N_TLS_CI=true` генерирует в `os.tmpdir()`
OpenSSL ephemeral root CA, leaf для `DNS:localhost/IP:127.0.0.1`,
второй leaf от доверенной CA, независимую rogue CA и
сертификат с неверным SAN. Все private keys строго локальные,
действуют один день, не сохраняются в Git, Railway, registry
или persistent volume. После CI файлы уничтожаются.

`scripts/saas-staging/m1n-synthetic-https-trust.mjs` выполняет
настоящий Node HTTPS request только к literal
`https://127.0.0.1:<ephemeral-port>`, с
`rejectUnauthorized=true`, передачей ожидаемой CA,
`servername=localhost`, системной валидацией SAN и
**обязательной SHA-256 привязкой leaf SPKI** на каждом
новом TLS соединении. `agent:false` исключает скрытый
reuse socket. Строгий allowlist путей
`/.well-known/openid-configuration`, `/jwks`, `/authorize`,
`/token`. Нет DNS, внешнего host, HTTP downgrade,
подхвата JWT `jku/x5u`, общесистемного изменения trust
или `NODE_TLS_REJECT_UNAUTHORIZED=0`.

Защита deny-first: post token — только ограниченная
form-urlencoded PKCE, ответы ≤16 KiB, 4-секундный timeout,
без cookie/браузерного bearer в IdP request. OAuth `302`
**никогда не следует автоматически**; допускается только
фиксированный callback URI (не смонтированный), с ровно
`code` и `state`, без fragment и чужого origin. Смена
TLS leaf при той же CA требует **нового доверенного SPKI pin**,
а CA другого владельца и неверный SAN всегда отказывают.

После **успешной проверенной HTTPS загрузки**
discovery/JWKS с точным `issuer`, строго HTTPS `jwks_uri`,
`alg=RS256` и public-only RSA 2048–4096,
используется существующий pinned `at+jwt` verifier.
Mock OAuth client M1m использует транспорт только при
обоих GitHub CI flags; все прежние HTTP фикстуры
и старые отказы default-off сохраняются. Более широкий
fetch/HTTPS transport в runtime **не подключён**.

## Приёмка на уровне HTTPS и OAuth

`tests/saasM1nPinnedHttpsTrust.test.mjs` проверяет:
- доверенная CA + правильный SAN + правильный SPKI →
  реальный HTTPS GET discovery/JWKS и POST token,
  одноразовый PKCE authorization code с CSRF state;
- идентичная CA, но другой leaf/SPKI → TLS отказ **до**
  обработки HTTP; явное обновление SPKI pin допускает
  новый leaf (не происходит автоматически);
- чужая CA даже с заранее известным leaf SPKI →
  TLS handshake denied до ответа сервера;
- правильная CA/SPKI, но неверный SAN DNS → denied;
- HTTP downgrade/open redirect и callback fragment
  из OAuth ответа не исполняются;
- malicious `jwks_uri`, foreign issuer, URL SSRF,
  cookie/GET token и неверный callback → denied;
- без CI flags создание CA и HTTPS transport
  запрещено, обычный `bun run verify` выполняет только
  default-off тесты; отдельный GitHub step запускает все
  HTTPS adversarial tests.

## Реальная связка с disposable PostgreSQL16

**Восьмой** отдельный запуск существующего PG16 workflow
проходит после всех M1a–M1m тестов и SQL025.
Это тот же защищённый M1m E2E, но с отдельным префиксом
`m1n-`, с Node HTTPS mock issuer, pinned CA/SAN/SPKI
и независимым signer trust test. Никакой публичный
service/listener не включается. HTTPS применяется к
mock **issuer**, проектный API остаётся временным
loopback HTTP внутри disposable runner.

После HTTPS+PKCE валидный access token проверяется
по trusted pinned RS256 public key, server-side
`issuer+subject → actor`, и сервер регистрирует
UUID/revision сессии в **эфемерной** PostgreSQL16.
Далее настоящий project POST проходит через
M1h отдельно fsynced PRE-COMMIT Ed25519 witness,
M1k `FOR SHARE` session revision, подписанную M1d
tenant authorization, обязательный M1c private audit
и M1g UUID binding в **одном PG COMMIT**.

Как и M1m, создаются независимые A/B/C:
- A и B успешны, затем третья запись B успешна,
  ожидаются 3 project/3 audit/3 unique UUID/3
  linked PG session proofs;
- C проходит HTTPS+PKCE, bearer и HTTP до fsync,
  но session отзывается до резервирования PG —
  HTTP `404`, 0/0/0 (токен нельзя считать отзывом
  только по времени подписи);
- A отзывается после успешной записи, новая POST
  даёт 404, B продолжает работать;
- signer недоступен → HTTP `503` и **0**
  новых PG reservations, без retry.

`tests/sql/saas_m1n_pinned_https_idp_pg_e2e.test.sql`
независимо проверяет все counts, ACL/FORCE-RLS,
session-proof/Audit binding и replay SQL025.
Требуются отдельные `PASS M1n` на JavaScript
и на SQL приёмке, плюс четыре проверенных
GitHub Actions на **финальном M1n HEAD**.

## Чего мы НЕ доказали

- Нет **реального HTTPS IdP**: CA и сертификаты
  созданы внутри одного runner и доверены
  *по явному тестовому pin*, не через реальный
  PKI/CA lifecycle, OCSP/CRL, CT, mTLS или HSM.
  Для staging/production нужен выбранный оператором
  настоящий IdP и domain/TLS cert trust с отдельной
  авторизацией. **Не переиспользовать CI CA/leaf.**
- Нет настоящего браузерного OAuth callback/cookie,
  CSRF session binding, complete OIDC ID-token/nonce,
  refresh-token rotation, backchannel logout,
  durable distributed issuer JWKS/session store
  или реального login provisioning.
- Нет off-host independent WORM/high-water, защиты
  от DBA rollback, network partition **DURING COMMIT**,
  доверенного production pool discard или bounded
  manual UNKNOWN COMMIT adjudication. Нет exactly-once,
  безопасного auto-retry, реального CPA/egress/billing
  или production migration/backfill.
- CI-успех сам по себе не даёт права ни merge/Ready,
  ни apply SQL019, ни production release. Требуется
  отдельный независимый code-owner/security/operator
  review, проверка цепочки stacked PR и явное согласие.

## Railway TLS — отдельный hard stop

Ранее read-only Railway наблюдение подтвердило
`SUCCESS` no-listener deployment для retired sandbox
сервисa, сохранив `synthetic-highwater-only` volume.
Срок старой **Railway sandbox test PKI —
15 октября 2026 года, 13:33 UTC**.
Не получено независимое отрицательное доказательство
TCP 8443. **M1n не меняет Railway** и не ротирует
sandbox сертификаты: местная ephemeral CI CA
к Railway не относится.

NO merge/Ready/deploy, SQL019/production PG,
Railway signer/journal/volume, CPA/Core/OAuth keys,
mint/reissue/retry/repair/delivery/archive/GC.
`gcPermitted=false`, `authorizationGranted=false`.

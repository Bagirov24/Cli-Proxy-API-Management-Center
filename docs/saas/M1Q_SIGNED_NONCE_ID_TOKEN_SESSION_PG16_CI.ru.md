# M1q — synthetic signed OIDC ID token with per-login nonce → signed PG16

**CI-ONLY / STACKED DRAFT / NOT PRODUCTION.** Parent M1p Draft PR #19, exact verified HEAD `f2a33fed96b4312feb296be3babafd9e18951aff` (4/4 GitHub CI success). No parent PR mutation, merge or Railway writes.

## Узкая цель

M1p доказал per-login opaque state+PKCE и fail-closed отмену до регистрации PG16 session, но выдаваемый mock issuer access JWT ещё не сопровождался настоящей проверкой ID token nonce. M1q включается только одновременно с `GITHUB_ACTIONS=true`, `SAAS_EPHEMERAL_M1M_PKCE_CI`, `SAAS_EPHEMERAL_M1N_TLS_CI`, `SAAS_EPHEMERAL_M1O_TRUST_CI`, `SAAS_EPHEMERAL_M1P_CONTEXT_CI`, `SAAS_EPHEMERAL_M1Q_ID_TOKEN_CI`. На Railway/production/без всех flags механизм default-off.

Опциональный M1q flow добавляет отдельный CSPRNG nonce (43 base64url символа) к HTTPS `/authorize`, хранит nonce *только* во внутреннем одноразовом state записи, не возвращает nonce/verifier/ID token в callback. Из одноразового authorization code mock IdP подписывает **два различных JWT** одним transient RS256 private key: `at+jwt` access token с API audience; отдельный `typ=JWT` ID token с exact `{iss,aud:clientId,sub,nonce,iat,exp}`. Token endpoint возвращает `id_token` только при M1q opt-in. Код стирается до проверки PKCE/токенов, откат и auto-retry запрещены.

Новый `scripts/saas-staging/m1q-signed-id-token-nonce.mjs` загружает JWT verification-only RSA JWK **исключительно через M1n CA/SAN/SPKI-pinned HTTPS `/jwks`** после предыдущего pinned OIDC discovery/JWKS, без jku/x5u/DNS/refetch из JWT заголовков. Строго проверяются canonical base64url, header `alg=RS256,typ=JWT,kid`, exact claims, OIDC client audience, issuer, subject совпадающий с уже проверенным access JWT, one-use `nonce`, iat/exp bounded, криптографическая RSA подпись и отсутствие лишних claims. Только **после обоих независимых JWT proofs** можно вызвать server-only actor resolver и синхронный ephemeral PG16 registrar.

## Adversarial and PG16 acceptance

- `tests/saasM1qSignedIdTokenNonce.test.mjs`: реальный ephemeral HTTPS CA/SAN/SPKI, подписанные два JWT, параллельные login contexts, nonce A ≠ B, wrong-context callback, replay и double completion. Даже **валидно подписанные** подмены nonce, subject, client audience, issuer, expiry, iat, alg/kid, дополнительных claims и ошибочная signature не регистрируют ни одной новой сессии; code расходуется только раз, без retry. Подмена ID token A в коде B также блокируется по nonce. Missing/duplicate/invalid authorize nonce отвергается IdP до выдачи code.
- Одиннадцатый отдельный disposable GitHub PostgreSQL16 прогон **после неизменённых M1a–M1p** использует M1o explicit rotated ephemeral HTTPS SPKI, M1p per-context code+state, M1q signed ID token. Проверяет успешную real HTTP→signed M1k/M1d/M1c/M1g PG16 запись только после обоих verified tokens и отдельный mismatched expected nonce: one-shot code потрачен, **новая PG16 session не зарегистрирована**, никакой access token binding. Следующая signed PG16 часть сохраняет 3 projects/3 mandatory audits/3 attempt UUID, revocation C/A 0 ghost, B active, M1h witness 503/0 new PG reservations.
- Независимый SQL `tests/sql/saas_m1q_nonce_id_token_pg_e2e.test.sql`: реальные persisted session/project/audit/proofs, ACL/FORCE RLS/triggers, SQL025 replay, отсутствие ghost rows. Ожидаются **два независимых PASS M1q** в PG16 журнале и четыре GitHub Actions SUCCESS (Main CI, PG16, Demo Build, Chromium) **на одном финальном SHA**.

## Nonclaims and stop gates

Это **не реальный OIDC provider** и не полноценная OIDC Core/browser conformance suite. Нет browser callback, cookies HttpOnly/SameSite/CSRF, trust governance подписанной внешней PKI, authorization code consent, `auth_time`, `acr`, `amr`, `azp`, multi-audience OIDC, real userinfo/logout/backchannel, refresh rotation, distributed state, durable JWKS anti-rollback или multi-instance session enrollment. Синхронный registrar и pinned JWKS snapshot в одном GitHub runner не доказывают атомарный async remote-PG session provisioning или governance-operated signer. Отдельные JWT verifier snapshots без внешне закреплённой PKI-политики также не являются production trust. Off-host independent WORM/HSM, network failure DURING COMMIT settlement, production physical SQL pool discard, CPA/Core credentials/tenant onboarding, review/merge/deploy остаются запрещёнными.

**Railway TLS самостоятельный operator blocker.** Срок старой synthetic test PKI **2026-10-15 13:33 UTC**. Read-only: successful `RETIRED_MTLS_SANDBOX_NO_LISTENER` deployment, нет public domains или TCP proxies, сохранён volume `synthetic-highwater-only`; **нет независимого отрицательного TCP 8443 теста**. Не объявлять ротацию/retirement завершёнными без доказательств оператора. Ни сертификаты Railway, ни signer/journal/volume, ни variables не изменялись.

NO Ready/merge, SQL019/production PG, real user keys, Railway writes, unknown-COMMIT retry/reissue/repair/archive/GC. `authorizationGranted=false`; `gcPermitted=false`.

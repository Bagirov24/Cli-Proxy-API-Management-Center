# Stage 2G.4d.7w — удалённый Railway staging high-water: частично подтверждён, production НЕ готов

**Подтверждённое состояние 13 октября 2026:** настоящий Railway deployment `SUCCESS` для строго изолированного **синтетического** сервиса на отдельном удалённом Railway контейнере. **Это не независимый административный trust root**, не remote WORM, не подписанный PostgreSQL COMMIT и не готовность SaaS issuer к production. Второй клиент для mTLS end-to-end только **STAGED**: применение заблокировано обязательной проверкой 2FA Railway Dashboard. Ни один неисполненный тест не считается пройденным.

## Конкретный scope и фактические результаты

- GitHub Draft PR №3, ветка `feature/saas-blueprint-tenant-egress-20261010`, кодовый коммит `ba8503a5fa2d4899c4824656cbb8e2f42c324fdd`. Именно этот код закреплён за удалённым staging сервисом; ранее `4/4 GitHub Actions SUCCESS`, включая PG16, Main CI, Demo, Chromium.
- Railway project **`cpa-gateway-sandbox`** (`dba33407-7200-40e0-a9c8-08c43d41e5e4`), environment **`sandbox`** (`9ee1afb9-9b20-4c50-91ef-6f23e3c5f3ee`), а не другой существующий `cliproxyapi-personal / production`.
- Service **`saas-highwater-staging-only`** (`59f2edf7-a13c-4c22-bc9c-80e93b810509`), deployment **`885ee1a7-8ffb-462b-ae0e-b47a260d5ff6`**: `SUCCESS`, Railway runtime log `READY: sandbox-only synthetic high-water HTTPS/mTLS port 8443; head 0`, health `Online`, 1 running replica, 0 crash, 0 critical/warning.
- Volume **`synthetic-highwater-only`** (`2a4cb9b4-0dcb-4206-8c94-cdae8d78d980`), size 512 MB, attached solely at `/staging-highwater`. On-volume location `/staging-highwater/private-log` is private. Local file fsync does **not** prove independently protected WORM or tamper-resistant custody.
- Railway service source pinned to exact above GitHub SHA, entry `node scripts/saas-staging/archive-witness-railway-staging.mjs`. Guard checks exact sandbox project and environment, source audience `SYNTHETIC_NO_ISSUER`, no PG credentials; all key material is a test-only short-lived Railway variable **`SAAS_REMOTE_BOOTSTRAP_B64`**, **never** part of Git history, PR comments, or runtime logs.
- Staging TLS leaf certificate is synthetic and expires **2026-10-15 13:33:25 UTC**; it must be rotated or decommissioned. Test CA and synthetic key custody are NOT real independent governance.
- `0` Railway service/public custom domains and `0` public raw TCP proxies. Intended traffic is **private internal Railway network only**. No production/issuer/recipient callback wired.
- Remote authority signed head is revision **0** (empty after first deployment). Runtime readiness is **not** an mTLS handshake proof or positive append transaction; never state remote append is VERIFIED before actual cross-container requests.

## Second service and the 2FA blocker

A separate `saas-highwater-private-smoke` Railway Function (`713a802c-67ee-479e-a075-c1335992c540`) was **STAGED ONLY** in the SAME sandbox environment. It contains no real customer data and has no public domain; it is designed to perform one internal service-to-service TLS1.3/mTLS test using a short-lived synthetic client certificate and isolated Ed25519 witness/journal fixtures. The Function attempts (when actually deployed) to:

1. authenticate both sides over Railway private DNS and verify the pinned TLS server SPKI; check a missing client cert is denied;
2. `GET /v1/head` under mTLS, verify all authorization / reissue / retry / repair / delivery / GC flags are `false`;
3. append a signed synthetic **genesis**, verify Ed25519 external receipt; retry identical nonce and require the exact same receipt; altered nonce/stale `expected` DENY;
4. race two different signed successor requests against the same predecessor and require exactly one receipt plus a `409` for the losing fork;
5. if a previously signed head already exists after restart, inspect its signature **without** replaying new commitments; log success/failure without raw secrets.

**FACT:** pending Railway patch **`a5ecd073-44e3-4bd5-b19e-a38824b68ffc`** has only 5 staged changes (Function create and two service variables: `SAAS_SMOKE_SCOPE` and `SAAS_REMOTE_SMOKE_B64`), no deletion. Railway `accept-deploy` returned **"These staged changes require two-factor verification ... Apply them from the Railway dashboard"**. Do not retry via another API to bypass 2FA; **Function NOT deployed, no remote mTLS assertions run, status remains PENDING MANUAL 2FA**.

### Approved manual next step (requires account-holder action, NOT chat secrets)

Open [Railway sandbox project](https://railway.com/project/dba33407-7200-40e0-a9c8-08c43d41e5e4) → environment `sandbox` → staged changes → verify the **only pending** `saas-highwater-private-smoke` Function + its two variable *names* → use Railway Dashboard's **Apply / Deploy** and complete its normal account 2FA. Do **not** paste 2FA codes, secret variables, private keys or seed phrases into this chat. Do not apply production changes. After dashboard approval, inspect the Function deployment/logs: a `PASS 7w` log is evidence of actual private mTLS smoke test; absence of such logs is **NOT verified**. This is not a claim of background monitoring.

## Trust and release boundaries

- Both sandbox and current application production projects are in **one personal Railway workspace** (`bagirov24's Projects`). Runtime containers are separate, **but the same workspace administrator can change all keys, volumes and root pins**. No truly independent operator/organization, external WORM, HSM/KMS, immutable high-water or independently saved minimum has been introduced.
- One replica + one local volume is not cross-host consensus or durable anti-equivocation protection. No real two-host partition, cross-workspace failover, PITR/backup/restore drill or certificate revocation/rotation has been proven. Short-lived synthetic certificates will expire quickly.
- No fenced/atomic PG COMMIT→off-host receipt, WAL/LSN proof, issuer tenant/actor authorization, durable authenticated delivery/recipient ACK or production privacy/retention/security approval exists.
- No production Railway deployment or modification of existing `cliproxyapi-personal` services, no SQL 019/migration edits, no Core/Gateway/CPA/OAuth, real payloads, `/data`, `management.html`, merge/force push, issuer retry/reissue/UUID reuse/delete, automatic repair, archive, tombstone/quota resets or GC. **`gcPermitted=false`**.

**Release status:** `7w REMOTE SANDBOX SERVICE DEPLOYED`; `7w CROSS-CONTAINER mTLS TEST PENDING 2FA`; `INDEPENDENT OFF-HOST ROOT NOT VERIFIED`; `PRODUCTION BLOCKED`. No future completion is implied.

## Фактическое завершение staging mTLS smoke — 13 октября 2026 (обновление D-081)

**Эта секция заменяет прежнее утверждение выше о `PENDING MANUAL 2FA`.**
Владелец Railway подтвердил изменения через Dashboard 2FA; отдельный
`saas-highwater-private-smoke` реально запущен в том же `sandbox`.
Сначала тестовый клиент падал на неверном публичном authority pin.
Оператор выполнил read-only SSH-аудит реального контейнера
`saas-highwater-staging-only`: синтетический журнал содержал одну запись,
ревизию 1, `keyPairMatches=true` и `signatureValid=true` под фактическим
серверным ключом. Его SHA256 публичного SPKI:
`5c55326f3c90215556c8bdac77ecc9c6d152cdf1e59253492a208f5e18a16411`.
Это **operator-observed**, а не доказательство независимой key custody.
Сверенный публичный ключ закрепили в smoke Function, сохранив строгую
Ed25519 проверку; server signer, PG, volume, original log, certificate
и прочие секреты **не изменялись**.

**Финальный подтверждённый deployment:** smoke
`d3e4ee3d-5d74-4fb1-a28d-c9fd04e33c2f` — Railway `SUCCESS`, без
ожидающих staged изменений. Его runtime logs содержат:
- `PASS 7w: private-network HTTPS TLS1.3/mTLS head read with pinned server SPKI`;
- `PASS 7w: missing client certificate denied by actual remote authority`;
- `DIAG 7w: localEd25519=true, authoritySigBytes=64, cryptoVerifier=true, webVerifier=true, webStatus=completed`;
- `PASS 7w: retained signed remote head authenticated, revision=1`;
- `PASS 7w: two genuine remote competing signed publishers: exactly one successor, one fork denial`.

В том же коде после one-winner теста выполняется `GET /v1/head`
и проверяется точное равенство signed receipt с выигравшим ответом.
Таким образом **подтверждены** реальные private-network mTLS,
проверка retained head и monotonic `revision 1 → 2`, выбор
одного из двух competing signed successors (второй `409`).

**Пока НЕ проверены на отдельном Railway runtime:** идентичный повтор
того же nonce после потери ACK, реальный перезапуск high-water
с сохранением подписанной ревизии 2, torn record/rollback, network
partition, certificate rotation/revocation, external immutable minimum,
separately owned HSM/WORM. Эти случаи ранее моделировались в 7v CI,
но не являются доказанными remote staging. Сам runtime `SUCCESS`
не свидетельствует о durable/independent fsync или PG settlement.

**Production остаётся BLOCKED:** оба Railway сервиса принадлежат
одной personal workspace, нет независимого trust domain, HSM/WORM,
atomic/fenced PG COMMIT + WAL/PITR, tenant/actor issuer authorization,
recipient ACK, privacy/retention/security approvals. Синтетические
сертификаты истекают **2026-10-15 13:33 UTC** и должны быть
rotated/decommissioned. Ни SQL 019, ни production, ни merge,
retry/reissue/repair/delivery/archive/GC. `gcPermitted=false`.


## Как оператор настраивает 2FA и вручную подтверждает новый Railway patch

Для будущих работ используйте [подробный пошаговый Railway 2FA runbook](RAILWAY_2FA_OPERATOR_RUNBOOK.ru.md): `https://railway.com/account/security`
для personal TOTP/passkeys/recovery и `cpa-gateway-sandbox/sandbox`
`Staged Changes → Details → Deploy` для точечного source-only
изменения с interactive Dashboard 2FA. У аккаунта может уже быть
включён MFA: отсутствие баннера означает **нет ожидающего diff**,
а не необходимость создавать новое изменение.

**Обновление НЕ запускает новый smoke и не меняет подписи**:
исторические deployment ID/синтетические PASS остаются такими,
какими были доказаны D-081. Не включайте workspace-wide
`Require 2FA` без отдельного решения администратора.

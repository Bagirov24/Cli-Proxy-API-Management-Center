# SaaS production candidate — единый интеграционный срез

**Дата:** 14 октября 2026. **Статус:** единый кандидат для ревью, НЕ развёрнут и НЕ утверждён как production-safe.

## Что собрано

Изолированная ветка `integration/saas-production-candidate-20261014` создана из законченного backend POST/PATCH Draft PR #24, SHA `3a3136871778e6154254690854e3874f08626ab8`, который включает весь накопленный SaaS Blueprint/M1 (PR #21), рабочий read handler (PR #23) и защищённый write handler (PR #24). Затем точные проверенные файлы из release guard Draft PR #22 скопированы в этот кандидат:

- `.github/workflows/custom-management-panel.yml`: `contents: read`, verification-only `push`/`pull_request`/`workflow_dispatch`, **нет** `gh release upload --clobber`, `--latest`, release edit/create, GitHub token для публикации или автоматического deploy.
- `tests/customManagementReleaseGuard.test.mjs`: YAML contract тест, блокирующий случайное возвращение release write, лишних команд или write-permission.
- Ни один существующий PR #3–24 не переписан, не закрыт, не merged и не ретаргетирован. `custom-no-apikey-fun`, `main`, ветка `api-gateway` и Railway production source не изменены.

Этот isolated candidate предназначен для **единого CI и security/codeowner/ops review**, не для прямого слияния в production. Отдельные baseline PR прошли свои CI на собственных head, но **комбинированный final SHA должен иметь новый зелёный CI**.

## Подтверждённое состояние живых сервисов (read-only snapshot)

Railway project `cliproxyapi-personal` / environment `production` (снимок 2026-10-14):

- `cliproxyapi-core` — online, 1/1 реплика, источник `custom-no-apikey-fun`, старый успешный live commit `b1434a514608446e5965d6a93325e3dd620c6028`; постоянный volume `cliproxyapi-data` 512 MB смонтирован как `/data`.
- `api-gateway` — online, 1/1 реплика, отдельный источник `api-gateway`, старый успешный live commit `448ff457b0324887770871d60be6194a01df3102`.
- 0 активных staged patches / pending deployments / recent failures, но **это только точечный снимок, не гарантия отсутствия будущего autodeploy при push**.
- Нет live SaaS service, dedicated SaaS database, durable tenant identity/session authority, production witness или миграций.
- `cpa-gateway-sandbox` хранит отдельный синтетический highwater сервис и volume: НЕ использовать его как production SaaS database/audit.

## Stage gates — продвигаться по порядку, не обходя проверки

1. **Объединённая интеграция**: единый PR candidate против `integration/saas-ci-only-base-20261014`, точный head, green Main CI + disposable PostgreSQL16 + Chromium + Demo + verification-only Management, target unchanged. Это проверяет исходники и контракт, но не production безопасность.
2. **Независимое ревью**: назначенный отдельный от автора codeowner/security/ops reviewer подтверждает boundary, доверие OIDC, SQL SECURITY DEFINER/GRANT, server-only signer, физический PG connection quarantine, audit, deployment graph, отсутствие rollback/retry при UNKNOWN COMMIT. Ни успешные tests, ни универсальное согласие владельца **не подменяют внешнее техническое заключение**.
3. **Собственный staging контур**: отдельный SaaS service и PostgreSQL16, собственные least-privilege схемы и роли, безопасное хранение секретов. Никаких production CPA/Core/Gateway переменных, `/data` mounts или пользовательских токенов. Начать с приватного сервиса, без публичного Gateway route.
4. **Проверяемая identity**: оператор задаёт **конкретные** issuer, audience, допустимые JWKS public keys/ротацию, OAuth callback, защищённый tenant actor directory и связь validated token fingerprint ↔ durable session UUID/revision в БД. Default deny до этого; synthetic CI issuer/ключи не подходят. Запрещено доверять `role` или `tenantId` из client JWT без серверного сопоставления.
5. **Production SQL & transaction integrity**: независимые миграции/реплей со строгим `ON_ERROR_STOP`, RLS/ACL regression, транзакционный project+audit+attempt+session proof; реальные concurrency/revoke/restore/lost-ack/timeout tests в отдельном staging PostgreSQL. `staging/saas-rls/001–018,020–025` **не применять автоматически как production SQL**; SQL019 не запускать.
6. **Witness и UNKNOWN-COMMIT**: governance-operated вне процесса приложения durable signer/receipt и независимый off-host высоководный журнал; fail-closed расхождение или недоступность; _без_ automatic retry, reissue или GC. CI local fsync / fake remote highwater ещё не доказательство независимой среды.
7. **Изоляция и нагрузка**: HTTP ingress deny-by-default, explicit staging domain, auth rate limit, no CORS/cookies bypass, negative tenant-IDOR tests, OIDC/network redirects, TLS rotation, DDoS/timeouts, backup+restore proof. Production data-plane provider scheduler/egress/CPA Keys — отдельная стадия, не включать без network enforcement и Vault.
8. **Безопасный релиз**: установить ручной governance-controlled build/promotion process; текущий candidate intentionally НЕ публикует `management.html`. Проверить Railway auto-deploy на source branch; freeze/план окна, backup+rollback именно существующего Core + volume snapshot, canary → smoke → monitoring → gradual rollout. Не переопределять source `custom-no-apikey-fun`/Gateway без independent green gates.
9. **Отдельный PKI вопрос до 15.10.2026 13:33 UTC**: Railway sandbox synthetic TLS retirement: по read-only нет public-domain/TCP proxy, но это **не** независимый отрицательный probe `service.railway.internal:8443`; без доказательства оператора не считать close.
10. **Production acceptance**: внешняя независимая приёмка безопасности, staging-to-production diff и artifacts, SLO/alerts, backup-recovery drill, runbook revert/kill switch, проверка с реальными тестовыми tenant без эксплуатации чужих OAuth/CPA ключей.

## Safety invariants текущего кандидата

- **НЕ делаем** merge/push в `custom-no-apikey-fun` или `main`, Railway production deploy, изменение mounts/variables, live key rotation, GitHub Release publication и SQL019.
- Нет production-readable публичного SaaS HTTP port в коде (новые handlers — factory и disposable PG CI); это не «backend running in production».
- 503 после unacknowledged COMMIT означает **UNKNOWN**, а не доказанный ROLLBACK. Запрещён автоматический повтор; необходим внешний reconciliation proof.
- `authorizationGranted` исторических документов говорит об отдельном release gate и должен переоцениваться оператором после фактических независимых доказательств, а не механически менять на true из-за общей инструкции.
- Даже при общем разрешении на достижение production сохраняем отдельные stop-checks перед необратимыми действиями и ценность сохранения действующего CPA Core.

# Merge Readiness — интеграционный обзор SaaS CI-only цепочки (2026-10-14)

**Решение на момент снимка: REVIEW REQUIRED / NOT MERGE APPROVED / NOT PRODUCTION READY.**

Этот файл — пакет независимого интеграционного ревью, **не** новый M1r security stage и не авторизация на merge, deployment или смену секретов. Он подготовлен на отдельной ветке, унаследованной от финального M1q. Все родительские ветки/PR, Railway, GitHub Release и production остаются нетронутыми.

## 1. Точные refs и цель

| Объект | Зафиксированное значение |
| --- | --- |
| Source chain | Draft PR #3–#20, 18 открытых, все Draft / Not merged на момент проверки |
| Last source PR | [#20 M1q](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/20) |
| Source code SHA перед этим документом | `cf530511c6e97bc56025e69c0933c88a47489e04` |
| Root target branch | `custom-no-apikey-fun`, snapshot SHA `63c20dbef58e9a27195c9212e0117c8a464a31dc` |
| **Безопасная review base** | `integration/saas-ci-only-base-20261014`, точно от указанного `custom-no-apikey-fun` SHA |
| **Aggregate review head** | `integration/saas-aggregate-review-20261014`, точно от M1q SHA + только этот документ |
| Default branch | `main`; она и `custom-no-apikey-fun` разошлись (custom: 8 ahead / 10 behind относительно main) |
| Merge state | Никакой merge/Ready, reviewers не назначены, ни одного GitHub review submission/APPROVED для #3–#20 не обнаружено |

Это **один агрегированный review PR** относительно изолированной review base. Он охватывает весь diff без изменения существующих 18 Draft PR. Новый head SHA после добавления этого документа должен быть отдельно проверен в GitHub CI; зелёный CI на родительском M1q сам по себе не является новым интеграционным acceptance.

## 2. Объём ревью: cumulative diff M1q относительно custom-no-apikey-fun

GitHub compare показывает **421 коммит впереди / 0 позади**, **237 изменённых путей** до добавления данного документа. Категории **не являются утверждением о production-готовности**:

| Группа | Путей | Содержимое/угроза |
| --- | ---: | --- |
| `docs/saas/` | 72 | Architecture, decisions, roadmap, security gates, design/acceptance specs |
| `scripts/saas-staging/` | 46 | Ephemeral PG16/witness/JWKS/PKCE/HTTPS, **также** отдельные потенциальные сетевые staging listeners; проверить launch guards |
| `staging/saas-rls/` | 24 | SQL001–018, 020–025; **SQL019 отсутствует**, только disposable staging, не применять к production PG |
| `tests/sql/` | 35 | Independent RLS, audit, UUID/session, replay and rotation acceptance |
| `tests/` без `sql/` | 19 | Adversarial Bun/browser fixtures, CI-only |
| `src/features/saasBlueprint/` | 31 | Unmounted control boundaries + opt-in synthetic UI; проверить отсутствие production publication |
| Другие `src/` | 4 | `App.tsx`, `MainLayout.tsx`, `MainRoutes.tsx`, `vite-env.d.ts` |
| CI workflows | 4 | Main CI augmentation, ephemeral PostgreSQL, synthetic demo/Chromium; обязательный security review прав/actions |
| Остальные | 2 | `scripts/saas-control-local.mjs`, `vite.config.ts` — особо проверить переключатели сборки |
| **Всего** | **237** | Diff большой, непроверенный человеком как единое целое |

Root PR #3 индивидуально содержит **173 файла, 41 426 additions, 4 deletions** по GitHub PR metadata — его объем нельзя игнорировать, хотя многие строки документационные. У отдельных files GitHub compare статистика может быть неполной: не используйте частичные счетчики additions/deletions для автоматического допуска.

С точки зрения границ: default Vite build использует `SAAS_BLUEPRINT_DEMO_ENABLED=false` и alias на пустой `SaasDemoRouteDisabled`. Включение mock SaaS UI требует local development либо явного синтетического pull-request CI build, а отдельный неаутентифицированный preview route ещё требует `import.meta.env.DEV`. Настоящего SaaS backend и открытой production route в этой цепочке нет. **Тем не менее наличие guard в коде не заменяет аудит и регрессионные тесты.**

## 3. ОБНАРУЖЕННЫЙ hard blocker: automatic GitHub Release на custom-no-apikey-fun

**Не merge aggregate напрямую в `custom-no-apikey-fun`.** Существующий файл `.github/workflows/custom-management-panel.yml` в target-ветке содержит:

- `on.push.branches: custom-no-apikey-fun`, path filters включают `src/**`, `tests/**`, `vite.config.ts` и другие пути, которые затрагивает SaaS diff;
- `permissions: contents: write`;
- `gh release upload v8-custom-no-apikey-fun dist/management.html --clobber`, далее `gh release edit ... --latest`.

Таким образом direct merge способен **автоматически заменить опубликованный `management.html` и изменить GitHub Release**. Это операционный release side effect, даже если SaaS-примеры default-off. Допуск в `custom-no-apikey-fun` требует отдельного согласованного изменения release-workflow (например, ручная `workflow_dispatch` публикация) либо отдельного разрешения на публикацию после полного build/QA. **В рамках этого PR НЕ отключаем и НЕ вызываем release.**

На независимом `integration/saas-ci-only-base-20261014` такой `push` по имени ветки **не совпадает** с указанным trigger, поэтому эта review base позволяет выполнять review и будущий одобренный integration-only merge без существующего автоматического publish step. Однако отсутствие иных внешних branch watchers здесь не доказано.

## 3b. ВТОРОЙ hard blocker: Railway production Core отслеживает custom-no-apikey-fun

Read-only проверка Railway подтверждает:
- Project `cliproxyapi-personal` / environment **production** / service **`cliproxyapi-core`**: `config.source.repo=Bagirov24/Cli-Proxy-API-Management-Center`, `config.source.branch=custom-no-apikey-fun`; latest deployment status SUCCESS (2026-10-10). Source commit, записанный в Railway, исторический; это не подтверждение свежего тестирования предлагаемой ветки.
- Service `api-gateway` в том же project production отслеживает **другую** ветку `api-gateway`, latest deployment SUCCESS.
- Доступное read-only представление `describe_service` **не подтверждает, включён ли automatic redeploy** на push в tracked branch, и не позволяет считать branch push безопасным.

Пока оператор не проверил и не согласовал freeze/disable auto deploy и release workflow, **любой прямой merge/push в `custom-no-apikey-fun` запрещён**: это может привести не только к автоматическому изменению GitHub Release, но и к незапланированному Railway production Core redeploy. Текущая изолированная `integration/saas-ci-only-base-20261014` НЕ является source branch этих Railway production services. Никаких Railway production reads of secrets, changes, deploys или рестартов не выполнялось.

## 4. Критичные security-review поверхности

1. **CI and runtime separation:** `.github/workflows/*`, `vite.config.ts`, `src/App.tsx`, `src/router/MainRoutes.tsx`, `MainLayout.tsx`. Проверить production HTML неизменность, все default-off guards, отдельный synthetic browser path, отсутствие credentials в сборке.
2. **Potential listeners:** `scripts/saas-staging/archive-witness-railway-staging.mjs` содержит `server.listen(port,'0.0.0.0')`, но требует pinned sandbox/ephemeral guard; также проверить `archive-witness-offhost-mtls-server.mjs` и любые deployment entrypoints. Никакого автоматического включения listener как побочного эффекта merge.
3. **SQL:** `staging/saas-rls/001–018,020–025` действительно staging-only. Проверить FORCE RLS, privileges, SECURITY DEFINER, signed scope, audit, session revoke, order of migrations. Ни SQL019, ни prod migrations.
4. **Unknown COMMIT and high-water:** `scripts/saas-staging/archive-witness-*`, M1h signed intents, M1j/M1k HTTP→PG, local operators. Запретить automatic retry/reissue/repair/GC, пока нет DURING-COMMIT partition proof и независимого off-host WORM/HSM.
5. **Authentication:** M1l–M1q synthetic pinned IdP CA/SAN/SPKI, OIDC access & ID token/nonce, state+PKCE, session kill, trust epochs. Всё CI-only, нет browser login/cookie/logout, real externally-governed identity lifecycle и durable distributed session enrollment.
6. **Integration boundary:** `src/features/saasBlueprint/controlApi/server/`, private actor/tenant resolution, no public handler mounting, data-plane CPA/Gateway credentials and external network egress stay unchanged. В этот merge не добавлять новые publication switches.

Отдельные `CODEOWNERS` файлы не найдены в проверенных standard paths (`.github/CODEOWNERS`, root `CODEOWNERS`, `docs/CODEOWNERS`); это **не доказывает отсутствие других branch protections**. Текущая интеграция не выдаёт подтверждения branch rulesets. Review owner/security/operations назначаются оператором, не самим автором CI.

## 5. CI: наблюдаемые факты и необходимые новые доказательства

**Source M1q final SHA `cf530511c6e97bc56025e69c0933c88a47489e04` — 4/4 SUCCESS:**

- [Main CI 38583969876](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38583969876): 1845 PASS, 43 default-off SKIP, 0 FAIL; separate M1q 5 PASS.
- [Ephemeral PostgreSQL16 38583969852](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38583969852): 11 independent scenarios, two `PASS M1q`; previous M1a–M1p regression assertions preserved.
- [SaaS demo 38583969946](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38583969946): SUCCESS.
- [Chromium 38583969907](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38583969907): SUCCESS.

**Integration review PR acceptance is a NEW gate:** all four workflows must run and succeed on the **exact HEAD after this merge-readiness document**. Also verify the exact base SHA, no PR stack/feature changes and no GitHub Release publication. Independent review of the aggregate diff, default-off build, CI workflow permissions and sensitive network scripts remains required even after green CI.

## 6. Операционный Railway TLS blocker (отдельно от CI merge)

Read-only Railway `cpa-gateway-sandbox / sandbox / saas-highwater-staging-only`: live deployment `a5e9ccdc-b9ae-4392-945a-6d65b8c2c284` SUCCESS; `RETIRED_MTLS_SANDBOX_NO_LISTENER` is the configured start command; no public domains or TCP proxies, no staged changes; `synthetic-highwater-only` remains mounted at `/staging-highwater`.

Это **не независимый отрицательный TCP-тест internal port 8443**. Отдельный старый synthetic TLS certificate lifecycle deadline **2026-10-15 13:33 UTC** остаётся операторским блокером до проверки/ротации или доказанного retirement. Здесь не выполняем Railway writes/secret access/volume reset/PKI changes. Он не запрещает isolated review, но исключает production-ready и самостоятельную смену опубликованного артефакта.

## 7. Merge decision matrix

| Действие | Сейчас | Необходимые условия |
| --- | --- | --- |
| **Открыть Draft aggregate integration PR в isolated base** | **YES** | Только refs+документ, без merge или deploy |
| **Считать source 4/4 CI доказательством CI-only behaviour** | **YES, narrowly** | На зафиксированном M1q source SHA; это не review approval |
| **Сделать первый code merge в isolated integration branch** | **NO YET** | New 4/4 success на aggregate HEAD, независимое codeowner/security approval, allowlist/default-off review, отсутствие запретных сторонних actions |
| **Merge прямо в `custom-no-apikey-fun`** | **BLOCKED** | Разрешить auto-release workflow side effect И отдельно проверить/заморозить возможный Railway production Core autodeploy source branch; одобрить отдельными решениями release и deployment policy |
| **Merge в `main`** | **BLOCKED** | Сначала согласовать расхождения веток, отдельный fresh CI/security review против `main` |
| **Production deploy, real OAuth/CPA/keys/PG** | **BLOCKED** | Полноценная backend/identity/network/security/ops готовность, external audit/commit proof, Railway PKI, explicit approval |

**Выбор механизма после reviews:** для одного одобренного aggregate PR предпочтителен **squash merge только в isolated integration base**, затем повторная проверка конечного SHA. Старые #3–#20 не merge повторно: reconciliation/closure как superseded отдельным одобренным действием после доказанного equality tree. Альтернатива — последовательная bottom-up интеграция с отдельным retarget и повторными проверками, если code owners потребуют granular changesets. Решение пока не принято и merge не выполняется.

## 8. После code merge — настоящая SaaS реализация

Начать в новых, небольших vertical slice PR **на изолированной интеграционной базе**, не продолжая бесконечную последовательность M1r/M1s PoC: (1) server-only multi-tenant actor/session authority с trusted IdP в staging, (2) least-privilege PostgreSQL migration + real connection lifecycle/commit uncertainty, (3) protected tenant/project management HTTP endpoints с object-level RBAC и mandatory audit, (4) CPA/Gateway Vault-backed network/egress integrations с fail-closed, (5) frontend и эксплуатационные SLO/recovery и billing. Каждый этап проходит реальные integration tests с нулём случайных production secrets/traffic.

**Текущие запреты:** no Ready, no merge, no `custom-no-apikey-fun` push, no GitHub Release update, no Railway production Core redeploy, no SQL019/production PG, no Railway service/cert/signer/journal/volume writes, no live keys, no automatic UNKNOWN COMMIT retry/reissue/archive/GC. `authorizationGranted=false`, `gcPermitted=false`.

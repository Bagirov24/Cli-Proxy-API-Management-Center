# M1i — default-off HTTP write-adapter для проектов (CI-only)

**Статус: STACKED DRAFT / NOT MOUNTED / NOT PRODUCTION.**
Ветка M1i основана на [Draft M1h PR №11](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/11),
далее PR №10 → №3. M1h на исходном HEAD имел 4/4 SUCCESS.
Merge, Ready и deployment требуют отдельного разрешения; эта
функциональность **не** готова к включению в SaaS.

## Реализованный маленький вертикальный срез

Новый модуль
`src/features/saasBlueprint/controlApi/server/m1ProjectHttpHandler.ts`
обрабатывает настоящие стандартные `Request` / `Response` для
фиксированного пути:

` /control-api/v1/tenants/{tenantId}/metadata/projects/{projectId} `

- `POST` с точно `{"name":"..."}` — создание проекта;
- `PATCH` с `{"name":"...", "expectedVersion":N}` — CAS-переименование;
- `DELETE` с `{"expectedVersion":N}` — soft-disable с CAS.

Это **не смонтированный endpoint**: в приложении, Railway, CPA,
Gateway и production backend никто не вызывает фабрику handler и
нет HTTP listener. Она может быть сконструирована только при
`enabledForDisposableCi:true`, `GITHUB_ACTIONS=true`,
`SAAS_EPHEMERAL_M1_HTTP_CI=true` и отсутствии переменных Railway
и production `NODE_ENV`. Также разрешён только loopback Host
`127.0.0.1/localhost/` ::1, но не публичный hostname.

Транспорт отклоняет CORS/Origin cross-site, Cookie,
`Idempotency-Key`, client attempt/actor/tenant/role/correlation headers,
URL query/fragment, неверные HTTP методы и paths, неизвестные поля DTO,
неверный Content-Type, body больше 512 bytes, некорректный JSON,
unsafe имена, CAS версии и unsigned/expired/foreign bearer.
Никакого GET/list и изменения работы прежнего синтетического
read-only HTTP-handler. Ответы — только whitelisted JSON статусы,
без SQL, bearer, project name, внешних IDs или секретов,
с `no-store`, `nosniff`, no CORS, no cookies.

Bearer проходит через существующий
`createM1ProjectCommandBoundary` и
`createPinnedAccessTokenVerifier`: pinned RS256 `at+jwt`,
issuer/audience/kid/exp/iat проверяются криптографически.
Issuer/subject → actor определяется **только** server-side directory,
не из JWT body. Перед writer дважды проверяются verifier, actor,
tenant membership и роль; членство, проверяемое в PG, должно
переутверждаться *внутри* signed transaction при реальной интеграции.
Одни проверки TypeScript не обеспечивают гарантий COMMIT.

## CI приёмка

`tests/saasM1ProjectHttpBoundary.test.ts` содержит:
- настоящий ephemeral RS256 signer и server-side actor directory;
- POST/PATCH/DELETE, точный DTO, CAS, полную матрицу owner/admin/viewer/
  auditor, tenant isolation и revocation denial;
- Bearer подпись/expiry/issuer, SQL fail/unknown COMMIT → 503,
  AbortSignal до/во время записи, не более **одной** writer попытки;
- URL/body/Content-Length/Content-Type/роль/Origin/cookie/CORS/
  idempotency-key отрицательные сценарии;
- настоящий `Bun.serve` на `127.0.0.1` и `port:0` **только в CI**;
  после теста listener закрывается; никаких внешних сервисов.

Обычный `bun test` проверяет default-off factory и НЕ
активирует network adapter. Только отдельный job step в
`.github/workflows/ci.yml` временно запускает
`SAAS_EPHEMERAL_M1_HTTP_CI=true bun test tests/saasM1ProjectHttpBoundary.test.ts`,
после основной `bun run verify`. Синтетический writer в этих тестах —
внутрипроцессный mock; настоящая PostgreSQL16 работа M1a–M1h
проверяется независимым disposable PG workflow.
Этот тест **не** доказывает сквозной HTTP → подписанная
PG16 transaction → precommit Ed25519 journal; это отдельный gate.

## Что нужно до merge / production

**Merge ограниченных default-off CI-пилотов**: code-owner review,
security audit с проверкой отрицательных тестов и отсутствия импорта
в runtime, CI 4/4 SUCCESS на точном M1i HEAD, проверка
последовательности PR №3–11 и письменное approval на merge.
Merge не должен автоматически включать SaaS API.

**Production SaaS**: защищённый deployable backend, настоящий OIDC/SSO
и управление actor sessions/tenant membership, доверенный signer
и заранее защищённый UUID/operation intent до PG COMMIT,
атомарный signed Bun.SQL writer c connection-pool quarantine,
PostgreSQL production migration/backfill, независимый WORM/high-water,
операторская UNKNOWN COMMIT adjudication, сетевые partition tests,
интеграция CPA/BYOA/egress/pools, observability/DR и отдельный release.
**Никакого automatic retry, exactly-once claims или включения
реальных CPA ключей по факту тестового HTTP-handler.**

## Railway TLS — только read-only ранее подтверждено

В sandbox `cpa-gateway-sandbox` старый тестовый сервис
`saas-highwater-staging-only` был заменён no-listener deployment
`SUCCESS`, том `synthetic-highwater-only` сохранён. Это не
независимый negative TCP 8443 probe; M1i Railway не меняет.
Срок test PKI: **15 октября 2026 года, 13:33 UTC**.

**Hard stops:** no merge/Ready/deploy без approval, SQL019 запрещён,
production PostgreSQL/Railway signer/journal/volume не менять,
Core/CPA/UUID mint/reissue/retry/repair/delivery/archive/GC запрещены;
`gcPermitted=false`.

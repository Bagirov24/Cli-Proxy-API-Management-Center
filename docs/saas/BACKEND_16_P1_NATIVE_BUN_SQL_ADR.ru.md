# ADR Backend16 P1 — Native Bun.SQL как целевой PostgreSQL transport

- Дата решения: **2026-10-21**
- Инициатор выбора: владелец проекта
- **Статус: ARCHITECTURE_SELECTED_RELEASE_BLOCKED**
- Область решения: Backend16 server-side, private PostgreSQL16 read path
- Источник решения: выбор владельцем **варианта A — Native Bun.SQL**
- Связанные документы: [полная дорожная карта](BACKEND_16_DELIVERY_ROADMAP.ru.md),
  [Native Bun.SQL TLS E2E](BACKEND_16_NATIVE_BUN_SQL_TLS_E2E.md),
  [owner integration](BACKEND_16_OWNER_INTEGRATION.md)

## 1. Архитектурное решение

<!-- BEGIN BACKEND16 P1 RUNTIME DECISION -->
| Свойство | Принятое значение |
| --- | --- |
| Целевой physical PostgreSQL transport | `Native Bun.SQL` |
| Статус архитектуры | `ARCHITECTURE_SELECTED_RELEASE_BLOCKED` |
| Роль Node24 pg | `CI_ONLY_COMPARATOR_NOT_PRODUCTION_FALLBACK` |
| Одобренный stable runtime | `NONE` |
| Проверенный live operator trust | `LIVE_UNVERIFIED` |
| Release hard stop | `NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false` |
<!-- END BACKEND16 P1 RUNTIME DECISION -->

Вариант **A — Native Bun.SQL** выбран как единственное целевое направление
для будущего Backend16 staging/production runtime и Bun server-only build.
Выбор **не** означает, что текущий Bun.SQL безопасен, утверждён для
production, может подключиться к реальному PostgreSQL или что его
server-side factory разрешено включить. Все release/security gates
сохраняются отдельно и должны быть закрыты независимыми операторами.

**Node24 `pg@8.23.1` не является production fallback.** Существующие
независимые dual-lock / cross-runner, synthetic mTLS broker, immutable vault,
physical PostgreSQL16 exact-session RLS и Node peer TLS tests остаются
CI-only security comparator. Их запрещено удалять или делать expected-failure
ради выбора Native. Если выбранный Native runtime не проходит acceptance,
решение — `BLOCKED_RELEASE`, а не автоматическое переключение на Node.

## 2. Фактическая причина отсутствия runtime approval

Stable Bun `1.3.14` и `1.4.3` реально нарушали необходимые negative
TLS identity contracts на аутентифицированном PostgreSQL16 соединении:
custom `tls.checkServerIdentity` always-deny callback игнорировался,
а same-CA корректно подписанный wildcard SAN мог приниматься вместо
строгого exact `postgres.railway.internal`. Bun 1.3.14 дополнительно
принимал wrong-root CA; Bun 1.4.3 improved wrong-root refusal,
но не исправил callback/wildcard. Шифрование, `pg_stat_ssl.ssl=true`,
проверка изолированного callback или SSLRequest-only handshaking
не доказывают идентичность того самого SQL peer.

Независимый disposable CI-only upstream binary:
`@oven/bun-linux-x64@1.4.3-canary.20261019.1`,
CLI `1.4.4-canary.1+6bb5dc195`,
source revision
`6bb5dc1956505dd1113455f58d4757c924f3ad54`.
Загрузчик проверяет SHA512 **до** распаковки/выполнения и точную
revision. Это **не production package** и не разрешённый fallback
из основного `bun@1.3.14`. На 2026-10-21 upstream
[latest stable Bun release](https://github.com/oven-sh/bun/releases/tag/bun-v1.4.3)
— `bun-v1.4.3`; stable `bun-v1.4.4` не обнаружен.
Эта информация является датированным наблюдением, при выборе
будущего stable кандидата официальный upstream проверяется заново.

Исторический source checkpoint `main`:
`b0fd2b66fba5fc93c4e669ba4240fe38aef9c40e`.
На [disposable physical PG16/RLS CI #39486761812](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/39486761812)
исправленный canary дал
`B16_NATIVE_SQL_TLS_ALWAYS_DENY_CALLBACK_ENFORCED`,
`B16_NATIVE_SQL_TLS_WRONG_ROOT_DENIED`,
`B16_NATIVE_SQL_TLS_CA_SIGNED_WILDCARD_DENIED`.
Это **CI_ONLY_VERIFIED**, не live trust.

## 3. P1 — обязательный критерий выбора stable Native runtime

**Первый реализуемый P1/P2 safeguard:** [offline stable archive
preflight](BACKEND_16_P1_NATIVE_STABLE_PREFLIGHT.md) проверяет форму
неизменяемого stable metadata и SHA512 фактических байтов **без**
скачивания, распаковки или исполнения runtime. Он отвергает известные
небезопасные stable и CI-only canary, никогда не утверждает release;
тестовый `1.4.4` — вымышленный fixture, а не опубликованный binary.

**Нельзя утверждать версию заранее.** После публикации нового
поддерживаемого stable Bun runtime, отличный от CI-only canary,
нужен независимый exact-SHA кандидат, который:

1. Получен из отдельно рассмотренного официального дистрибутива,
   с неподвижными version, source revision, platform/architecture,
   SHA512 архива, manifest/lock/provenance и security review.
   Запрещены floating `stable`/`canary`, глобальная подмена PATH,
   automatic pin bumps и копирование CI canary в runtime package.
2. Исполняет **без изменения assertions** один и двухаргументные
   `new SQL(options)` и `new SQL(url, options)` с явным
   always-deny `checkServerIdentity`. Оба должны отказать ДО
   PostgreSQL authentication; callback обязан фактически сработать.
3. На одном и том же аутентифицированном (same-socket) PostgreSQL16
   backend PID
   подтверждает pinned root CA, exact DNS SAN, разрешённый
   `TLSv1.2/1.3` / `pg_stat_ssl.ssl=true` и оба tenant read flows.
   Нужна явная проверка отсутствия unauthorized physical LOGIN.
4. Фактически отказывает при неверном root CA, CA-valid wildcard
   `*.railway.internal`, CN-only и wrong-SAN, без
   `rejectUnauthorized:false`, `tls:'require'` / `tls:'disable'`,
   public endpoint fallback или ослабления SAN matcher.
5. Сохраняет exact-session/subject/binding grant RLS, per-principal
   fresh immutable secret version, credential revocation during broker
   wait, physical lock cancellation, quarantine после async error,
   нет повторного использования физического backend PID, COMMIT и
   корректную release/physical socket death семантику.
6. Проходит отдельный independent Native TLS probe, физический
   PG16 dual-tenant E2E, full disposable broker/vault/RLS chain,
   Main CI/build/lint/typecheck на **том же exact source+binary SHA**
   без skip, expected-failure и `continue-on-error`.
7. Получает независимый code/runtime/security review; отсутствие
   стабильного кандидата означает `BLOCKED_RELEASE` без обходных
   env flags или перехода на непроверенный transport.

**Промежуточный результат P1:** stable Native candidate +
воспроизводимые security tests + отдельный signed/approved ADR
implementation addendum. Текущий ADR фиксирует только выбор
архитектуры; runtime approval ещё НЕ получен.

## 4. P2 — следующая Bun server-only packaging boundary

Подготовить отдельную от React/Vite Management Center Bun server-only
сборку, **не заменяя** frontend `bun@1.3.14` и `bun.lock` в этом PR.
Нужны exact immutable runtime artifact hash, OS/arch pin, независимый
проверенный source+lock, SBOM, provenance, reproducible build,
review загрузочных скриптов и clean install/teardown без дополнительных
наборов credentials. Bundle не должен загружать `pg` как production
fallback, использовать root npm lockfile, публиковать tenant HTTP
listener или экспортировать Node pg в frontend.

Сохранить существующие Backend16 auth, broker/vault, exact SQL,
admission/RLS, secret transport, cancellation/discard и audit contracts.
Никаких параллельных старых combined runners #79, `SET ROLE`,
клиентских LOGIN, динамических `latest` secret version или
permanent SQL0008 reapply. P2 требует отдельный PR и review
артефакта, а не административного переключателя.

## 5. Незакрытые реальные этапы и управление изменениями

P3–P12 полной дорожной карты включают оператором закреплённый live
PostgreSQL verify-full CA/DNS, real mTLS broker и per-LOGIN IAM,
OIDC/current sessions, read-only installed SQL0008 catalog receipt,
off-host durable audit/high-water, PITR/restore, двух настоящих tenant,
rollback/canary и десять независимых role-bound signed attestations.
Вердикт release evidence verifier может быть только
`READY_FOR_INDEPENDENT_REVIEW`; `productionAuthorized:false`.
После этого для P13 необходимо **отдельное** разрешение на private
staging deployment. Ни архитектурный выбор, ни зелёный CI не
подразумевают разрешения на production.

Текущая staging factory обязана сохранять
`const NATIVE_SQL_TLS_PEER_AUTHENTICATION_VERIFIED=false;`;
изменять его в рамках этого выбора нельзя. Никаких Railway,
реальных IAM/credentials/volumes, deployment, GitHub Releases,
production Core/Gateway, `custom-no-apikey-fun` или replay SQL0008.

Пересмотр выбора Native Bun.SQL возможен только новым явным
владельческим архитектурным решением и отдельным independent review
с точным SHA; падение TLS теста, отсутствие stable release или
сдвиг npm graph не активируют Node fallback автоматически.

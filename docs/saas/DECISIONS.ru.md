# SaaS Blueprint B — решения и вопросы к дальнейшей разработке

**Статус записей: PROPOSED.** Это предложения, не окончательная
утверждённая production-архитектура. В рабочую ветку, релизы и Railway
ничего из перечисленного автоматически не переносится.

## Реестр архитектурных решений (ADR-lite)

| ID | Решение | Мотив и ограничение | Статус |
| --- | --- | --- | --- |
| D-001 | Модульный монолит SaaS Control + существующий Core/Gateway | Единый UX, независимые адаптеры, без переписывания inference engine | PROPOSED |
| D-002 | Tenant → Project → Application → CPA Key Binding | Клиентам необходимы собственные ключи, бюджеты, отчёты | PROPOSED |
| D-003 | BYOK прежде BYOA | Официальные API-ключи обычно имеют более ясные условия и учёт | PROPOSED |
| D-004 | OAuth только через разрешённый provider flow | Нет обхода ограничений, подмены браузера, антидетекта | PROPOSED |
| D-005 | Account Pool, Account и Egress требуют отдельных grants | Запрет неявного доступа ко всем аккаунтам общего пула | PROPOSED |
| D-006 | Fail-closed при ошибке egress, не direct | Трафик разных клиентов не утекает за пределы политики | PROPOSED |
| D-007 | Обычные Core access.api-keys не использовать для SaaS-клиентов | Не дать обойти CPA Key Policy | PROPOSED |
| D-008 | Static proxy validation ≠ network SSRF protection | DNS rebinding, IPv6, redirects, dial-time IP require network firewall | PROPOSED |
| D-009 | VPN Connector отдельный сервис/адаптер | Упростить поддержку нескольких VPN и не повышать риск для Core | PROPOSED |
| D-010 | UI не принимает решения о доступе | Backend / scheduler / egress firewall — источники enforcement | PROPOSED |
| D-011 | Read-only UX первым, write actions после backend | Не выдавать макет за готовую SaaS-функцию | PROPOSED |
| D-012 | Статус SIMULATED / OBSERVED / VERIFIED всегда виден | Пользователь не путает с реальными запросами и метриками | PROPOSED |
| D-013 | Vault для секретов, PostgreSQL только для metadata/usage | Защитить собственные и клиентские API/OAuth/egress secrets | PROPOSED |
| D-014 | Session/tenant-scoped RBAC + раздельный Admin / Client API | Management secret не должен становиться ключом всех арендаторов | PROPOSED |
| D-015 | Не смешивать estimated cost с actual provider invoice | Корректные SaaS-счета и финансы | PROPOSED |
| D-016 | Независимые выпуск и rollback UI / SaaS / Core / Gateway | Защита production OAuth, ключей и тома /data | PROPOSED |

## Что категорически нельзя потерять из будущего функционала

- [ ] Создание/управление SaaS tenants, проектами, приложениями и ролями.
- [ ] Подключение BYOK клиентов: ключ в Vault, модельный доступ, безопасная ротация.
- [ ] Подключение BYOA с провайдер-специфичной матрицей разрешений.
- [ ] Раздельные owned/shared аккаунты и группы; явные grants и отзыв доступа.
- [ ] Egress Registry: HTTP, HTTPS, SOCKS5, SOCKS5H, direct-explicit.
- [ ] VPN Connector: WireGuard/Tailscale/other разрешённый транспорт, optional.
- [ ] Network health, real exit IP, fail-closed, DNS/SSRF/IPv6, refresh/SSE/WS.
- [ ] Визуальная схема Tenant → App → CPA → Core → Account → Egress → AI.
- [ ] Реальный per-request trace + объяснения, replay, умеренная анимация.
- [ ] Input/output/cache/reasoning usage; latency/error/fallback.
- [ ] Расходы, бюджет, тарифы с version, estimated vs invoiced, дедупликация.
- [ ] Отдельные роли админа и клиентов, аудит, retention, резервирование.
- [ ] Понятный интерфейс RU+EN, mobile, keyboard, состояния ошибок.
- [ ] Доступность Core/CPA/Gateway, release pinning и архив миграций.
- [ ] Безопасный Account Connection Manager, системный OAuth browser + PKCE
      для официально поддерживаемых способов; не антидетект.

## Открытые технические вопросы (исследовать ДО enforcement)

| ID | Вопрос / эксперимент | Что подтвердит готовность |
| --- | --- | --- |
| Q-01 | Где после CPA scheduler безопасно перехватить выбранный credential? | Интеграционный тест, Core v8.0.23 и плагин v0.5.1 |
| Q-02 | Может ли один общий Core жёстко разделять tenant keys и pools? | Контрактные тесты или решение dedicated Core/tenant |
| Q-03 | Как связать выданный CPA key с tenant без копирования plaintext? | Официальный plugin management API/opaque ID |
| Q-04 | Какие provider OAuth flows разрешены для клиентского SaaS? | Provider capabilities registry с источником и датой |
| Q-05 | Как проверить реальный outbound IP для HTTP/SSE/WS/token refresh? | Staging egress tracing + firewall test |
| Q-06 | Как исключить SSRF через DNS rebinding, redirects, IPv6? | Protected DNS dialer/network ACL test |
| Q-07 | Где хранить Vault master keys и как делать ротацию? | Threat model + encrypted backups + restore test |
| Q-08 | Какие поля usage Core/CPA выдают достоверно? | Observability contract / golden request traces |
| Q-09 | Точные значения затрат vs подписной тариф? | Pricing provenance scheme, estimated≠actual |
| Q-10 | Нужен ли многопользовательский Portal в v1 или достаточно админа? | Решение по ролям и безопасному отдельному API |
| Q-11 | Поддерживает ли Railway выбранный VPN transport и sidecar networking? | Ограниченный стенд, без Core/prod/OAuth |
| Q-12 | Как минимизировать привязку к upstream CPA-плагину? | Порты/адаптеры + контрактные тесты версии |
| Q-13 | Как не допускать устаревший tenant state и grants в SPA? | Abort/invalidation tests при смене tenant |
| Q-14 | Нужны ли shared pools вообще для внешних клиентов? | Юридическая и продуктовая оценка, явный opt-in |

## Инструкция следующему разработчику / агенту

1. Начни с `docs/saas/README.ru.md`, затем прочитай
   `ARCHITECTURE.ru.md`, `UX_UI.ru.md` и этот реестр.
2. Не считай текущий `resolveSaasRoute` защитой production: он **симулятор**.
   Реальное решение требует authenticated context и network enforcement.
3. Любое новое требование сначала записывай в реестр с ID, scope, тестом,
   UX-состояниями, миграцией и планом отката.
4. Не редактируй напрямую файл Core `/data/config.yaml`,
   `/data/auths`, CPA policy state или Railway service ради макета.
5. Новые маршруты Management Center — только за feature flag с
   явно помеченными demo-данными и новой локализацией.
6. Сохраняй метаданные модели независимыми от React/UI,
   инфраструктуры и конкретного провайдера. Не вводи зависимость на
   transport в чистый policy resolver.
7. Новые плагины добавляй только когда не хватает стабильного существующего
   Core/CPA API; не ставь второй scheduler вместе с CPA Key Policy.
8. Перед любым merge проверь workflow выпуска management.html: merge в
   `custom-no-apikey-fun` может создать новый UI-release.
9. Обновляй `ROADMAP.ru.md` и статусы D-*/Q-* после доказанной проверки
   (тест + источник), а не после устного предположения.

## D-017 — отделять симуляцию от реального сетевого trace

**Статус: SIMULATED (реализовано только в read-only UX); enforcement — PROPOSED.** Семь узлов объясняют предполагаемый путь, но Gateway/Provider отмечены как схема, даже если чистый policy resolver вернул `ALLOW`. Никаких реальных запросов и secrets. Следующий этап: SaaS Control API/AuthZ/RBAC и read-only adapter на staging, только после отдельного контракта интеграции.

## D-019 — безопасный инспектор контекста (SIMULATED)

Отображаемые в схеме ссылки на пул, аккаунт и egress происходят **исключительно из разрешённого tenant-scoped представления**. Незнакомые/запрещённые ресурсы заменяются нейтральным unknown, но не выводятся в ошибках. UI отдельно показывает owner и `owned/shared`; `Gateway` и `AI Provider` не считаются проверенными узлами. Это решение реализовано только в демонстрационном UI и чистых тестах, а серверная AuthZ и сетевое enforcement остаются **PROPOSED**.

## D-020 — мобильная навигация без скрытых разделов (SIMULATED)

После **реального** Chromium screenshot QA принято решение показывать четыре раздела макета сеткой 2×2 при ширине до 740 px вместо горизонтальной полосы со скрытыми вкладками. Для клавиатуры стрелки Left/Right перемещают фокус внутри ряда, Up/Down — между рядами. Это не меняет навигацию Management Center или разрешения. На desktop вкладки остаются в один ряд.

## D-021 — автоматический browser smoke, не production acceptance

Скрипт `tests/browser/saas_demo_browser.py` и изолированный workflow тестируют синтетический standalone preview. Результат [SUCCESS #38075528744](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38075528744), четыре viewport/locale/theme комбинации и 20 PNG. Тест не содержит и не использует Core credentials, Railway deployment, VPN-конфигурации или реальные запросы. **Manual WCAG + staging оставлены PROPOSED; browser smoke — VERIFIED только в изолированном CI.**

## D-022 — проверка WCAG без production-зависимостей

**Статус: VERIFIED только в синтетическом browser CI.** Добавлен
axe-core 4.10.3 как временный инструмент GitHub runner; не включать
его в пользовательский `management.html` и не использовать live
credentials. Пять конфигураций × шесть состояний = 30 автоматических
аудитов, zero detected violations
([run #38078136183](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38078136183)).
Первым аудитом найден dark-theme hover `2,58:1`; исправлено.

**Ограничение:** `color-contrast: incomplete` встречается в каждом
скане для пяти повторяющихся элементов; не трактовать это как PASS.
Ручной WCAG/assistive technology review остаётся `PROPOSED`, включая
реальное 200/400% zoom. PR остаётся Draft; production не меняется.

## D-023 — Control API v1 scoped read-only contract (SPEC/SIMULATED)

Контракт SaaS Control HTTP в отдельном пространстве
`/control-api/v1/tenants/{tenantId}/metadata/{collection}`
не является Core Management API и не содержит write методов.
Чистая `readSyntheticTenantCollection` реализована **только для
тестирования DTO и tenant filters**, не аутентифицирует реального
пользователя и не обеспечивает server-side isolation. Внешние 404/403/503
имеют фиксированные generic messages без чужих ID. CPA key не является
SaaS Control credential. Источник `core-metadata-readonly` не
реализован. Статус: **SIMULATED prototype, backend SPEC**.

## D-024 — RBAC членство не заменяет grants (SPEC/SIMULATED)

Роли read-only v1: tenant-owner / tenant-admin / tenant-viewer /
tenant-auditor (последний видит только tenant/projects/applications).
Дублирующиеся или отозванные memberships блокируются. Каждый
Pool/Account/Egress требует собственной проверки owner + active grant +
expiry; grant на Pool не открывает Account и Egress, а Account не
раскрывает чужой Egress. Никаких write прав, global admin bypass и
implicit direct egress. Для реального backend требуется session
verification, scoped DB, RLS, audit и staging security tests.
См. [AUTHZ_RBAC_V1.ru.md](AUTHZ_RBAC_V1.ru.md).

## D-025 — local-only HTTP Control handler с синтетическими сессиями

**Статус: SIMULATED (локальный preview) / backend deployment PROPOSED.**
Функциональный `GET` обработчик построен как Fetch Request/Response
порт внутри модульного монолита; он не монтируется в production.
Actor определяется только по случайному opaque Bearer из короткоживущего
локального реестра, а membership загружается на серверной стороне
независимо от user headers. Проверка повторяется после async read,
чтобы отзыв сессии/роли не завершился выдачей устаревших metadata.

Server transport повторно собирает DTO по runtime allowlist, не
пропускает произвольные поля upstream. Только static error codes,
no-store, без CORS/cookies/write методов. Скрипт запуска требует
ручного флага и всегда слушает `127.0.0.1:18551`, отказывается
работать в production/Railway. Это **не production auth**: настоящие
OIDC, RLS, audit, Core metadata adapter и runtime enforcement
пока SPEC/PROPOSED. Никаких credentials и реального трафика.
Документация:
[LOCAL_CONTROL_HTTP_V1.ru.md](LOCAL_CONTROL_HTTP_V1.ru.md).

## D-026 — PostgreSQL tenant RLS как дополнительная граница (staging-only)

**Статус: VERIFIED только на синтетических SQL фикстурах / реальный
backend PROPOSED.** Для архитектуры B принят принцип отдельной
read-only роли без LOGIN/BYPASSRLS и строго разрешённого набора
SELECT-таблиц. Приватные membership/grants недоступны напрямую;
RLS policy требует активного tenant-scoped actor membership, RBAC,
активный tenant и отдельные grants на `pool/account/egress`.
Связи раскрываются только при двух самостоятельных разрешениях.

В `saas_rls` использованы transaction-local session GUC, но они
**не являются аутентифицированными claims** и могут быть подменены
пользователем SQL-соединения. Использовать только после настоящей
проверки актёра и строгой серверной привязки контекста; никогда не
публиковать reader SQL endpoint. Поэтому SQL пилот не подключается
к локальному HTTP handler и не выдаётся за production enforcement.
Полные acceptance условия:
[STAGING_POSTGRES_RLS_V1.ru.md](STAGING_POSTGRES_RLS_V1.ru.md).

## D-027 — HMAC scope привязан к транзакции (CI ONLY, не OIDC)

Первоначальные PostgreSQL GUC с actor/tenant легко подменяются.
С миграцией 002 каждое RLS чтение требует валидную HMAC-SHA256
подпись actor/tenant/expiry/transaction ID. Подпись не переносится
в новую транзакцию. Случайный ключ и привилегированная тестовая
функция подписания доступны **только в временной PostgreSQL CI**.
Это техническая проверка defence in depth, но не готовая
аутентификация: OIDC, safe signing, connection pool и SQL injection
gates остаются PROPOSED. Не подключать production и не выдавать
читателю произвольный SQL. См.
[SIGNED_SCOPE_RLS_V1.ru.md](SIGNED_SCOPE_RLS_V1.ru.md).

## D-028 — скрытие всего route при недоступном Pool

Для read-only Control API принят fail-closed контракт:
если Pool недоступен без отдельного grant, `RoutingBinding`
**не возвращается**. Нельзя выдавать ни чужой `poolId`, ни
частичную route-строку с `poolId: null`. SQL RLS и чистый
TypeScript projector теперь совпадают по этому правилу,
а runtime DTO sanitizer отвергает некорректный ответ адаптера.
Демо-схема продолжает показывать нейтральный DENY с рекомендацией,
но не идентификатор чужого ресурса. Статус — SIMULATED,
реальный enforcement / data-plane — PROPOSED.

## D-029 — pinned API access-token, не клиентская JWT-роль

**Статус: контракт реализован, security unit tests; OIDC provider SPEC.**
API принимает только криптографически подтверждённый RS256
`at+jwt` с pinned ключом, issuer, audience и коротким TTL.
От ID-token, незнакомых `kid`, динамических `jku/jwk`
и role/tenant из JWT как основания для прав отказано.
issuer+subject связывается с actorId **только через серверный directory**;
membership и RBAC всё равно проверяются отдельно.
Реальный issuer/rotation/authorization code flow/SSO не реализованы.

## D-030 — SQL: фиксированный template, параметр и scoped transaction

**Статус: TS mock tests + ephemeral PostgreSQL SQL CI; driver SPEC.**
Единственный SQL-port допускает whitelist коллекций и
фиксированный SELECT (tenant/limit — параметры), HMAC на
actor/tenant/expiry/txid, `SET LOCAL ROLE` и гарантию
COMMIT или ROLLBACK + discard соединения при failure.
SQL test подтверждает, что SQL-подобное значение в prepared
параметре не выполняется и GUC сбрасываются после rollback.
Это не даёт клиентам возможность передавать сырой SQL,
не заменяет защищённого OIDC issuer и не даёт доступ к Core.
[IDENTITY_SQL_BOUNDARY_V1.ru.md](IDENTITY_SQL_BOUNDARY_V1.ru.md).

## D-031 — Сначала native Bun.SQL, строго в CI (staging-only)

Не добавляем второй npm Postgres driver в обычный Management
Center: Bun.SQL уже входит в закреплённый Bun 1.3.14. Изолированный
тестовый adapter реализует `ScopedSqlPool`, привязывает все команды
к одному reserved connection, допускает только точные SQL шаблоны
и **передаёт значения через параметры**. При отмене, неудачной
транзакции либо повреждённом соединении требуется close/discard,
а не reuse в другом tenant. Используются ephemeral non-superuser
role и HMAC key из временной DB; запрет запуска в Railway/production.

Пилот не объявляет выбранный Bun.SQL готовым production pool:
наблюдаемое поведение ошибок, query cancellation, max=2
конкуренции и connection cleanup должно пройти CI и review.
См. [BUN_SQL_DRIVER_PILOT.ru.md](BUN_SQL_DRIVER_PILOT.ru.md).


## D-032 — pool poison не равен physical discard (2G / STAGING)

Нельзя считать `Promise.race` SQL timeout гарантированным запросом
PostgreSQL CANCEL или завершением сетевого соединения. В 2G.1
введён синхронный `quarantine`, чтобы ни один следующий tenant не
получил потенциально повреждённый shared pool, и отдельный
bounded cleanup; на Bun.SQL 1.3.14 весь тестовый pool закрывается
вместо недостаточно доказанного per-connection discard.

В 2G.1b на временном PG16 проверяем native `reserve`-abort,
query cancellation, серверный statement_timeout/rollback и чтение
через новый пул. **Даже успешный CI не заменяет** испытания
физического уничтожения отдельно повреждённой connection и
восстановления после network split. По документации `pg.Pool`
предоставляет `client.release(true)` как явный путь удаления
соединения; это кандидат на отдельный backend experiment,
**PROPOSED, без добавления dependency или runtime endpoint**.

**Наблюдение 2G.1b / PG16:** Bun 1.3.14 `Query.cancel()` завершился
ошибкой отмены только через 3002 мс при целевом budget 2500 мс.
Для `reserve({signal})` один из CI-тестов сработал по **собственному**
probe timer, поэтому нельзя утверждать, что драйвер отменил ожидание.
Эти исходы записываются как ограничения, а не успешная отмена.
Production SQL connector остаётся PROPOSED; допустим лишь новый
экземпляр pool после quarantine, с подтверждённой RLS-изоляцией.

**Подтверждение 2G.1b:** [ephemeral PostgreSQL CI #38261137458](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38261137458)
успешно подтвердил fail-closed quarantine и fresh-pool North/Orbit,
но native reserve abort не завершился до 1253 мс, а query cancel
занял 3001 мс. Указанные ограничения остаются в решении о запрете
production Bun pool, не оправдывают silent fallback и не ведут
к переключению на direct egress.

## D-033 — только server-held identity и двойная AuthZ-проверка (2G.2)

**Статус: IMPLEMENTED isolated contract / VERIFIED synthetic tests
([CI #38263480676](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38263480676),
SHA `2ceb572`); настоящий SaaS backend — PROPOSED.**

Pinned JWT API access-token с `typ=at+jwt` и pinned issuer/kid/audience
не предоставляет полномочий через role/tenant/actor claims. Internal
actor берётся только из server-held issuer+subject directory; актуальные
membership/RBAC валидируются до signed SQL и после SQL вместе с повторной
проверкой token+actor mapping. В ответах не раскрываются чужие
resource IDs, ошибки generic, незнакомый tenant = 404.
Client tenant switch обязан отменять предыдущий async read.

SQL fixture rows **не равны** полным ControlResource DTO; новый
`trustedSqlReadBoundary.ts` не публикуется через HTTP и не
подключается к UI. JWT replay до истечения TTL, реальный OIDC,
session revocation/storage consistency и end-to-end PG16 acceptance —
отдельные будущие работы. См.
[TRUSTED_SQL_READ_BOUNDARY_V1.ru.md](TRUSTED_SQL_READ_BOUNDARY_V1.ru.md).

## D-034 — Audit является серверной границей, не отладочным логом (2G.3)

**Статус: IMPLEMENTED / VERIFIED synthetic tests
([CI #38265951045](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38265951045),
SHA `1ea71978abd6abc33263fe460754d7f9dbdd1053`);
production audit ledger — PROPOSED.**

Для Blueprint B вводится обязательный `SecurityAuditRecorder` на
server-side `trustedSqlReadBoundary`: результат Allow/Deny/Error,
UTC timestamp, correlation ID, server-proven actor и tenant, код
причины из фиксированного набора, источник и маркировка
synthetic/staging. Денай/ошибка всегда имеют `tenantId=null`.
Запрещено копировать JWT, Authorization, ключи, proxy URI, SQL,
prompts и произвольные дополнительные поля. Событие
составляется вручную из ровно 11 атрибутов и передаётся
синхронному sink; проблемы sink приводят к generic 503,
а не пропуску записи и выдаче rows.

Инкремент сознательно **не выбирает долговременное хранилище** и
не включает логирование в production. Временный bounded ring
используется только в synthetic security tests. Жизненный цикл
production audit ledger, outbox, retention, расследование,
ACL, tamper evidence, async sinks и reliability — PROPOSED.
Детали: [SECURITY_AUDIT_V1.ru.md](SECURITY_AUDIT_V1.ru.md).

## D-035 — 2G.4a проверяет реальную RLS транзакцию, но не production identity

**Статус: IMPLEMENTED / VERIFIED ephemeral PG16 E2E
([PG16 #38269435054](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38269435054),
SHA `73066e2`); production identity/data plane — PROPOSED.**

Полный staging-only путь синтетического JWT → trusted actor map →
двойная membership/RBAC проверка → подписанный по txid SQL scope →
Bun.SQL 1.3.14 (NOINHERIT/NOBYPASSRLS) → PostgreSQL FORCE RLS →
санитизированные metadata rows → redacted audit проверяется в
новом `verify-trusted-pg-e2e.mjs`, а не только mock SQL port.
Тестовые SQL grants независимы на Pool/Account/Egress.
Все попытки использовать client actor/role, другое audience,
ID-token и чужие tenant запрещаются до SQL.

Только экспериментальная временная PostgreSQL получает
дополнительную grant fixture; никаких расширений live Core,
production ключей, egress-подключений или публичных API.
Схема не даёт atomic actor-store snapshot и не заменяет
production OIDC, session invalidation, durable audit и безопасный
physical discard SQL соединения. Suspended tenant activity gate
остаётся отдельным обязательным fail-closed требованием до SaaS backend.

Подробнее:
[E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md](E2E_POSTGRES_SECURITY_ACCEPTANCE_V1.ru.md).

## D-036 — видимость пустых строк не означает разрешённый SQL scope

**2G.4b: IMPLEMENTED / VERIFIED в isolated PG16 CI
([#38272959201](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38272959201),
SHA `12a3b5b`); production-согласование revocation — PROPOSED.** В staging
SQL boundary **нельзя** считать активный запрос разрешённым только
потому, что PostgreSQL RLS вернул пустой набор. До/после SELECT
обязателен signed DB read gate: active tenant, active membership,
совпадение role и collection capability. Отказ gate означает
generic 404+tenantless Deny audit; подтверждённый ROLLBACK позволяет
использовать безопасное соединение повторно. Недостоверный ответ gate
или cleanup — generic 503 и quarantine.

Не подключаем 003 migration к production, не предоставляем reader
прямой SELECT в private tables и не объявляем атомарность revocation
после COMMIT. См.
[TENANT_DB_AUTHZ_GATE_V1.ru.md](TENANT_DB_AUTHZ_GATE_V1.ru.md).

## D-037 — Post-COMMIT authorization/read-set recheck только в staging (2G.4c)

**Статус: IMPLEMENTED / VERIFIED ephemeral PG16 + synthetic unit
([PG16 #38275287696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38275287696),
код SHA `6b47e92`); production revocation linearizability PROPOSED.**

После первого signed DB COMMIT синтетический SaaS read boundary
выполняет вторую транзакцию с новым HMAC/txid, тем же verified actor,
tenant, ролью, collection и LIMIT. Любое расхождение в санитизированном
read set, а также DB gate Deny, скрывает все старые rows с generic
404 и tenantless `authorization-changed` audit. Unknown SQL errors,
aborts, failed cleanup остаются generic 503/quarantine. Никакого
caller-supplied SQL, production DB hook, public endpoint или credentials.

Ограничение: **два снимка не обеспечивают атомарную гарантию** между
последним COMMIT и HTTP response. Для production ещё нужен отдельный
revision/serialization/revocation consistency design. Синтетические
E2E привилегированные UPDATE выполняются только на disposable PG16.
Подробно: [POST_COMMIT_REVALIDATION_V1.ru.md](POST_COMMIT_REVALIDATION_V1.ru.md).


## D-038 — revision-сигнал не равен атомарному revocation barrier (2G.4d)

**IMPLEMENTED opt-in server-owned revision guard / SYNTHETIC acceptance;
GitHub verification pending. Production protocol remains SPEC/PROPOSED.**

Порт `ServerAuthorizationRevisionSource` и строгий BIGINT-text parser
созданы отдельно от UI/Core. Verified actor+tenant используются для
capture, после повторного signed SQL/COMMIT и RBAC проверяется текущая
server-owned revision; mismatch 404, storage failure 503. При Deny
tenant/resource/revision не попадают в ответ и audit. Caller/JWT
revision игнорируется. Без explicit `revisions` сохраняется прежнее
2G.4c, и это **не** production revocation enforcement.

Не добавляем 004 миграцию без атомарной writer-side invalidation.
Обязательные будущие решения: единое PostgreSQL truth для всех
instances, транзакционное повышение tenant revision при membership,
role/grant/status writes и отдельная доказанная линейризационная
семантика. Между последней revision проверкой и HTTP delivery гонка
сохраняется. См.
[AUTHORIZATION_REVISION_CONTRACT_V1.ru.md](AUTHORIZATION_REVISION_CONTRACT_V1.ru.md).


## D-039 — PostgreSQL tenant revision является транзакционным writer state, но не HTTP revocation barrier

**IMPLEMENTED / VERIFIED для staging-only PG16**
([PG16 #38284819774](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38284819774),
SHA `6ea4546a6953d10baa42f7dcdc6ec5495f9f9517`);
production SPEC.

После 2G.4d opt-in TS guard вводится отдельный узкий PostgreSQL 16
proof: private monotonic tenant epoch, триггеры membership/role/tenant
status/grants/resource catalog с row lock внутри транзакции изменения,
tombstone tenant ID и signed SQL `authorized_revision` без private
reader privileges. Временный CI writer имеет test-only привилегии;
production credentials не используются. Concurrency проверяет
distinct writers одной tenant revision и committed visibility.

Не объявляем endpoint готовым: последующий 2G.4d.3 подключает
TypeScript revision provider к signed SQL только в ephemeral PG16 E2E;
expiry времени не bump, final check/response race остаётся, нескольких
backend instances и производственного authoritative writer API нет. См.
[TRANSACTIONAL_AUTHORIZATION_REVISIONS_V1.ru.md](TRANSACTIONAL_AUTHORIZATION_REVISIONS_V1.ru.md).


## D-040 — revision reader должен использовать тот же подписанный DB trust boundary (2G.4d.3)

**IMPLEMENTED / VERIFIED** для ephemeral PG16, SHA `94f8d7a14c24573ff5397fbe1349e0d89fa7c91f`
([PostgreSQL #38286208002](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38286208002) и [Main CI #38286207826](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38286207826)); production SPEC.

Серверный trusted actor/tenant/role/collection фиксируется после
access-JWT и RBAC. Обе revision reads используют новую signed
PostgreSQL транзакцию через существующий non-superuser
`ScopedSqlPool`, fixed SQL, текущие DB gates, HMAC/txid и safe
rollback/quarantine. NULL/DB denial → generic 404; испорченный SQL,
connection error, abort → generic 503. Только immutable,
server-generated scope; пользовательские JWT/revision headers
не определяют privileges. Staging E2E проверяет revoke после второго
COMMIT без изменения project rows.

Production revocation linearization, физический discard Bun
connection и многоинстансовый invalidate остаются открытыми.
См. [SIGNED_REVISION_READER_V1.ru.md](SIGNED_REVISION_READER_V1.ru.md).

## D-041 — metadata projection и links обязаны инвалидировать tenant epoch (2G.4d.4a)

**IMPLEMENTED / VERIFIED** только в disposable PG16, SHA `9458db06a86cb0d355937292ce135a89f1926f96`
([PG16 #38287715026](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38287715026)); production SPEC.

Grant/status trigger в 004 недостаточен, если link/route/project/app/key
изменяется между двумя одинаковыми LIMITed metadata reads. 005
подключает PostgreSQL triggers к всем пяти таблицам и транзакционно
повышает private tenant epoch; для shared link берётся объединение
владельцев и tenants, получивших гранты на OLD и NEW endpoint.
Избыточная инвалидация безопаснее пропущенного revocation.
Истечение `expires_at` по времени без SQL-изменения всё ещё требует
отдельного временного guard. Production HTTP linearization не доказана.

## D-042 — время истечения grant должно быть отдельной частью auth state (2G.4d.4b)

**IMPLEMENTED / VERIFIED** в disposable PG16, SHA `f0a35b8433e057fae466974e744f48523243ef62`
([PG16 #38288157880](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288157880)); production SPEC.

PostgreSQL triggers не происходят в момент `expires_at`, поэтому
одного monotonic tenant epoch недостаточно. Signed DB state содержит
tenant epoch и ближайшую будущую границу истечения независимо выданных
grants; финальный guard сравнивает обе величины и текущие серверные
часы. NULL deadline означает отсутствие будущих сроков на текущий
DB snapshot, а не бесконечную авторизацию. Expiry → 404 +
tenantless audit; malformed SQL → 503/quarantine. Для production
всё ещё нужен надёжный clock authority и revocation barrier.

## D-043 — PostgreSQL `FOR SHARE` задаёт лишь кооперативный DB barrier, не гарантию доставки HTTP (2G.4d.4c)

**IMPLEMENTED / VERIFIED** в disposable PG16, SHA `9696e280cfee9c6ecd8475fd48afd10113632060`
([PG16 #38288803851](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38288803851)); production SPEC/PROPOSED.

Читающая signed DB транзакция получает `FOR SHARE` на private
tenant epoch после актуального RBAC и повторно проверяет полномочия.
Writer-side triggers UPDATE того же epoch блокируются до read COMMIT,
так что commit revocation нельзя обогнать внутри этого кооперативного
протокола. E2E использует независимые PostgreSQL reader/writer/observer,
но не реализует публичный response-send callback или подтверждение
доставки по сети. Производственный протокол должен ограничить срок
lease, определить семантику при отмене/краше и не создавать unbounded
locks на медленных клиентах.

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

## D-044 — publish только после signed scope и FOR SHARE, без асинхронного COMMIT callback

**IMPLEMENTED / VERIFIED synthetic and disposable PG16; production SPEC.**

Данные предварительно собираются внутренним trusted SQL read, но
отдельный publication port принимает только server-owned scope,
первоначальную ревизию и приватную `prepare` callback. Внутри
параметризованной signed PostgreSQL transaction сверяются epoch/expiry
под кооперативным `FOR SHARE`, DB capability проверяется ещё раз,
после чего допустим только синхронный локальный `commit` до DB COMMIT.
Отмена, истёкшая ревизия или SQL отказ не должны выполнять handoff.
Реальный PG16 доказал порядок local handoff → revoker COMMIT.
Асинхронный network delivery и невозвратные эффекты после ошибки
callback остаются вне доказанного контракта; не представлять как
production-ready HTTP. См.
[BOUNDED_PUBLICATION_HANDOFF_V1.ru.md](BOUNDED_PUBLICATION_HANDOFF_V1.ru.md).

## D-045 — trusted read→publication не должен отдавать DTO наружу до audit и signed epoch barrier (2G.4d.5b)

**IMPLEMENTED / VERIFIED synthetic + ephemeral PG16, production SPEC.**

В дополнение к D-044, stage 2G.4d.5b не доверяет внешнему
caller формирование actor/role/revision/scope. Server-only published
entrypoint повторно использует JWT→actor→RBAC и обе metadata reads,
сверяет одну и ту же server-owned revision до публикации, под lock
повторяет trusted identity и завершает синхронный audit перед
локальным handoff. Возвращает только безресурсный receipt.
Синхронность audit не равна durable audit; последний actor lookup
вне authoritative PG actor directory всё ещё гоняется с revoke,
а TCP delivery после callback не доказана. См.
[TRUSTED_PUBLICATION_LIFECYCLE_V1.ru.md](TRUSTED_PUBLICATION_LIFECYCLE_V1.ru.md).

## D-046 — actor-wide session revoke обязан менять PostgreSQL tenant epoch (2G.4d.6a)

**IMPLEMENTED / VERIFIED** ephemeral PG16 ([PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787));
production SPEC.

Подписанная роль+membership в PostgreSQL ещё не учитывала отзыв
активности actor, если синтетический directory продолжал выдавать
тот же actor ID. Private singleton `actor_session_state` теперь
обязателен для `scope_membership_matches` и при изменении ревизирует
каждый tenant, где есть membership actor. Это даёт атомарный
actor-wide kill switch под существующим `FOR SHARE`, но не
пер-токенный OIDC logout и не реальный production session store.

## D-047 — audit outbox записывается только при подписанном PG Allow и не содержит ресурсы (2G.4d.6b)

**IMPLEMENTED / VERIFIED** ephemeral PG16 ([PostgreSQL #38292965787](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38292965787));
production SPEC.

Изолированный PostgreSQL `009` хранит minimal metadata
actor/tenant/collection/correlation/revision после авторизованного
`FOR SHARE` в SQL transaction. Reader не может напрямую просматривать
или менять audit; rollback убирает staged events; duplicate correlation
не превращается в второй Allow. Это устойчиво только после COMMIT,
не означает доставки ответа. Atomic network publish/outbox,
tamper-evidence, retention and external identity audit remain SPEC.

## D-048 — actor logout запрещает даже direct signed RLS SELECT (2G.4d.6 hardening)

**IMPLEMENTED / VERIFIED** ephemeral PG16, SHA `bd96d7a038378fa30524914362013ebf06fd420f`, [PG16 #38293380854](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38293380854).

Отзыв actor не должен зависеть исключительно от добросовестного
выполнения TypeScript `SCOPED_READ_GATE_SQL`. Migration 008
обновляет RLS-предикаты `scope_tenant()` и `read_allowed()`:
HMAC-проверенный scope отозванного actor больше не видит private
tenant и SQL-проекции напрямую. Это одна actor-wide синтетическая
сессия, не token-bound OIDC revocation; release blocked.

## D-049 — verified bearer fingerprint является частью signed PG scope

**IMPLEMENTED / VERIFIED** (ephemeral code SHA
`772a29be5b855f31e65e28b30144adddbe776bb1`).

В opt-in token-bound режиме HMAC подписывает
actor/tenant/txid/expiry/SHA-256 полного ранее проверенного access
token; клиентские `jti`, actor ID и role НЕ являются authority.
Каждый SQL gate требует actor+fingerprint+active/expiry из закрытого
PostgreSQL registry. Поэтому revoke A повышает tenant epoch, не
отключая другой token B этого actor.

## D-050 — постоянная защита от actor-only downgrade и строгий порядок миграций

**IMPLEMENTED / VERIFIED** только disposable PG16.

Любой enrollment переводит actor в token-bound режим навсегда.
Private `token_bound_actor_tombstones` переживает удаление всех
токенов и actor ID recycling. Legacy 4-field HMAC допустим только
для никогда не enrolled synthetic actor; production rollout требует
независимого полного перевода без fallback. Миграция 010 должна
применяться ПОСЛЕ 006, поскольку replay более старой версии
перезаписывает token-aware expiry attestation. Production требует
монотонной migration registry, без out-of-order replay.

## D-051 — fingerprint одноразовый и необратимый (2G.4d.7a hardening)

**IMPLEMENTED / VERIFIED** только в disposable PG16, код
`38dc64e466a119000b0067e4f5e74217c96dabfb`,
[PG16 #38297886638](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38297886638).

Даже privileged fixture writer не должен восстанавливать
отозванный bearer. Private `token_fingerprint_tombstones` сохраняет
каждый зарегистрированный fingerprint после DELETE; повторный INSERT,
обход через actor reassignment, UPDATE `revoked→active` и продление
`expires_at` запрещены. Отзыв конкретного токена окончателен в
рамках этого staging DB. Срок хранения tombstones и резервное
восстановление в production ещё не спроектированы.

## D-052 — issuer/subject→actor не может изменять принадлежность после bootstrap (2G.4d.7b)

**IMPLEMENTED / VERIFIED** только synthetic+disposable PG16, code SHA
`cade8751232b8deff40143c1ed31a8ac800194a1`, [PG16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282).

Отдельный доверенный directory bootstrap закрепляет
`issuer+subject→actor` навсегда в private `issuer_subject_bindings`;
revoked status является терминальным, UPDATE actor/issuer/subject и
DELETE запрещены. `issuer_bound_actor_tombstones` защищает от
actor ID recycling и actor-only downgrade. Даже при активном
token fingerprint отзыв subject меняет tenant epoch и блокирует signed
RLS/receipt-only publication. Это не реальный OIDC identity provider.

## D-053 — private subject bootstrap и bearer provisioning имеют разные привилегии

**IMPLEMENTED / VERIFIED** только PG16, [Main CI #38300085289](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085289) (1 829 PASS),
[PG16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282), [Demo #38300085311](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085311), [Chromium #38300085300](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085300) — 4/4 SUCCESS.

NOLOGIN `saas_issuer_directory_admin` вызывает pin/revoke SUBJECT,
NOLOGIN `saas_issuer_provisioner` вызывает enroll/revoke отдельного
VERIFIED bearer. Они не могут читать таблицы друг друга или signer
secret, не выдаются `saas_ci_runner/saas_rls_reader`. Только
server-проверенный RS256 JWT + issuer/subject actor directory могут
породить immutable token fingerprint+expiry writer input. Production
secure issuer-driven enrollment, issuer subject pin policy и сервисные
учётные данные ещё SPEC.

## D-054 — при subject logout signed публикация обязана сериализоваться на tenant epoch

**IMPLEMENTED / VERIFIED** лишь для local ephemeral PG16, [PG16 #38300085282](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38300085282).

Writer issuer-subject revoke обязан ожидать reader `FOR SHARE`,
после COMMIT revoke прежняя signed session denied даже при ACTIVE
собственной token row. Не доказывает атомарность remote HTTP delivery
и не создаёт production tamper-evident audit.

## D-055 — audit observation не равна delivery ACK (2G.4d.7c)

**IMPLEMENTED / VERIFIED** только isolated PG16 на code SHA
`1aeeb218a68ca7f0c8094d51551802205b60f224`, [PG16 #38302392290](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392290).

В private migration 012 статус `reconciled_local` означает, что
выделенный PostgreSQL worker зафиксировал **наблюдение уже COMMITнутого
Allow audit event**, а не что клиент получил HTTP payload. Исходный
append-only audit 009 остаётся неизменным. Даже при отсутствии audit
event после ROLLBACK локальный handoff мог произойти до неуспешного
SQL COMMIT; это нельзя восстановить из таблицы. Remote ACK,
tamper-evident журнал и атомарный protocol пока SPEC.

## D-056 — fencing поколений и физический rollback worker (2G.4d.7c)

**IMPLEMENTED / VERIFIED** disposable PG16: [PG16 #38302392290](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392290), [Main CI #38302392363](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38302392363).

NOLOGIN `saas_audit_reconciler` имеет право вызвать только закрытые
claim/mark функции, а не читать private audit/events напрямую.
`FOR UPDATE SKIP LOCKED` обеспечивает эксклюзивную lease на
committed event; generation и случайный UUID защищают от stale worker.
Claim+history полностью откатываются при termination backend до
COMMIT; закоммиченная незавершённая lease восстанавливается после
clock-expiry. Terminal `reconciled_local` не допускает повторный
ACK и не обещает exactly-once network delivery. В production
требуется отдельный authenticated worker connection — privileged
superuser может видеть свои uncommitted события в рамках собственного
SQL transaction и обойти isolation fixture.

## D-057 — downstream intent рождается только в подписанной PG транзакции (2G.4d.7d)

**IMPLEMENTED / VERIFIED** только в disposable PostgreSQL16 на code SHA
`6b0bf3189c544cce21ccdfbaf58b7b2f72ba3214`; [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719).

Migration 013 AFTER INSERT trigger добавляет постоянный
`event_id+idempotency_key UUID` без payload в той же транзакции,
где signed Allow 009. При ROLLBACK пропадает и источник, и intent.
После `reconciled_local` другой worker может получить intent, но
само наличие intent НЕ подтверждает local handoff или remote delivery.
Исторические signed audit events backfill только как synthetic labels.
Legacy synchronous handoff перед failed COMMIT остаётся потенциально
необратимым; этот разрыв нельзя закрыть audit-only reconciling.

## D-058 — lost MOCK ACK повторяет тот же UUID, но другой lease fence

**IMPLEMENTED / VERIFIED** только isolated synthetic PG16, [PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719),
[Main #38304607776](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607776) (1 829 PASS), [Demo #38304607709](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607709), [Chromium #38304607769](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607769): **4/4 SUCCESS**.

NOLOGIN `saas_mock_delivery_worker` видит только event ID,
immutable idempotency UUID, generation, lease UUID и попытку; не может
читать metadata, signed secrets, private outbox или состояние таблиц.
После lease expiry + worker crash повтор использует ТОТ ЖЕ
idempotency UUID при новом generation/fence, чтобы simulated receiver
Map применил эффект один раз даже при потерянном ACK. Это НЕ
гарантия реального удалённого consumer dedup и не криптографическое
подтверждение HTTP клиента.

## D-059 — ограниченные retry и явный `retry_exhausted` вместо ложного ACK

**IMPLEMENTED / VERIFIED** disposable PG16 ([PostgreSQL16 #38304607719](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38304607719)).

Три короткие попытки claim, четвёртый scan записывает терминальный
`retry_exhausted`, без `mock_acked`. Stale/wrong-key/double ACK
отклоняются; rollback отметки не создаёт подтверждения. Реальный
dead-letter sink, secure scheduler, backpressure и операторская
эскалация пока SPEC.

## D-060 — adversarial pre-COMMIT effect без durable intent остаётся production blocker

**VERIFIED negative proof**, synthetic Bun + real PG16:
[PG16 #38305618718](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38305618718).

В подписанной транзакции до COMMIT создаётся 009 audit + 013 intent,
но отдельно моделируется немедленный локальный эффект. SQL затем
выполняет ROLLBACK: обе записи исчезают, а эффект уже произошёл.
Это НЕ исправлено retry/ACK моделью 013, потому что post-COMMIT
worker не видит отсутствующий intent. Production должен заново
спроектировать транспортный контракт и durable message payload;
отсутствие события НЕ доказывает отсутствие байтов у клиента.

## D-061 — локальная durable идемпотентность не равна сетевой exactly-once

014 хранит единственный синтетический receiver effect и receipt в одной
транзакции disposable PostgreSQL. Receiver NOLOGIN допускается только
через SECURITY DEFINER; повтор key возвращает сохранённый receipt без
повторного локального эффекта. Worker 013 может записать усиленный mock
ACK только с matching durable receipt и актуальным fence. Старый 013
key-only mock ACK сохранён для обратной совместимости тестов.
**VERIFIED:** [PG16 #38307286153](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38307286153) на `a8eabe5`.
**DECISION:** никакой вывод об exactly-once network delivery и никакое
ослабление pre-COMMIT blocker из этого не следуют.

## D-062 — не смешивать COMMIT намерения с внешним effect/ACK

В Stage 2G.4d.7e отдельный `syntheticCommittedIntent.ts`
использует старую signed-SQL проверку и 009/013 outbox, но
преднамеренно **не вызывает** прикладной callback до COMMIT.
Новый успешный результат сообщает только об уже подтверждённом
PostgreSQL COMMIT; `externalReceipt=not_attested`.
Если PostgreSQL закоммитил событие, но ответ COMMIT был потерян,
результат для producer остаётся **unknown / 503**, не false/failure
и не HTTP success. Recovery идёт через независимый staging worker,
не через повторный пользовательский request.

Это отдельный opt-in пилот. Контракт старого pre-COMMIT
`createTrustedSqlPublishedBoundary` не модифицирован,
его unsafe network semantics не считаются исправленными.
Реальная durable producer idempotency и внешние ACK — SPEC.

**VERIFIED on code commit `fa895296a6ce4062687d0ad0af77f26114d4ef03`:** [PG16 #38309259713](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259713), [Main CI #38309259929](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259929), [Demo #38309259856](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259856), [Chromium #38309259696](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38309259696) — all 4 SUCCESS. The final documentation commit requires its own independent Actions results; code verification does not imply production readiness.


## D-063 — UUID операции привязан к identity и shape; не является auth

015 использует глобальный случайный UUIDv4 только как ключ
идемпотентности. Каждое обращение заново проверяет JWT/actor/RBAC,
PG signed scope и current revision. Замена actor/tenant/role/
collection/limit не может получить «успех» по существующему ключу;
SQL отвечает FALSE, наружу — generic 404 без event ID.
`pg_advisory_xact_lock` сериализует конкурентные обращения
до проверки committed mapping. Только первое создаёт 009 audit
и 013 intent, остальным возвращается существующий связанный event
без нового audit.

Потерянный COMMIT reply возвращается generic 503; повтор с тем
же UUID способен найти уже committed operation. Новый UUID означает
НОВУЮ операцию и не предотвращает логическое дублирование. Это
staging-only synthetic contract, не public HTTP idempotency API.
См. [producer identity](PRODUCER_OPERATION_IDEMPOTENCY_V1.ru.md).

**CODE VERIFIED** on SHA `ca2503f2e22d30e64c32490c6f46bb7dd73b6dc1`:
[Main CI #38351833547](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833547),
[PostgreSQL16 #38351833550](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833550),
[Demo #38351833546](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833546),
[Chromium #38351833571](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38351833571) — **4/4 SUCCESS**.
The documentation commit must be checked independently on its own SHA.

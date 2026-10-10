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

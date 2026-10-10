# SaaS Blueprint B — поэтапная реализация и контроль качества

**Важно:** ни один пункт ниже сам по себе не даёт согласия на изменение
Railway production, клиентов, OAuth или прокси. Каждый этап — самостоятельный
PR с тестами, возможностью отката и указанием версии Core/CPA.

## Состояния работ

- `SPEC` — только документация и контракты;
- `SIMULATED` — тестируемое поведение на синтетических данных;
- `STAGING` — изолированная среда, синтетические аккаунты, сетевые тесты;
- `VERIFIED` — проверено в заданном окружении с логами и артефактами;
- `RELEASED` — опубликовано после отдельного согласования и rollout.

Не использовать `VERIFIED` или `RELEASED` на основании одних unit tests.

## Этап 0 — Blueprint и прототип policy resolver

**Сейчас:** `SPEC / SIMULATED`, отдельная GitHub-ветка.

- [x] Versioned TypeScript contracts без API-токенов и сетевых вызовов.
- [x] Типы Tenant, Project, Application, CPA binding, Account/Pool, Egress, Grant, Route.
- [x] Чистый decision resolver (allow/deny + стабильные коды причин).
- [x] Egress syntax/SSRF precheck, default deny для private IP.
- [x] Safe preview с только разрешёнными полями.
- [x] Документы: Architecture, UX/UI, Roadmap, Decisions.
- [ ] Зелёный CI для итоговой ветки и PR.
- [ ] Отдельное архитектурное ревью реального CPA scheduler/API contract.

Критерий: `bun run verify` зелёный; отсутствует импорт нового
модуля из production Router, нет изменение Core/Gateway, OAuth или `/data`.

## Этап 1 — Read-only SaaS UI

**Статус:** `SPEC`.

- [ ] UX wireframes и интерактивный **демо** экран с явно помеченными mock-данными.
- [ ] RU/EN microcopy всех denial reasons; локализации остальных языков.
- [ ] Router добавляет SaaS-раздел только за feature flag, без статуса «здоров».
- [ ] Списки аккаунтов и их метаданные из **read-only** adapter, без secret fields.
- [ ] Screens: loading/empty/error/no-permission/stale/disabled, mobile + keyboard.
- [ ] React component tests, a11y tests, screenshot visual regression при возможности.
- [ ] Backend API не меняется, кнопки без реального backend не вводят в заблуждение.

Гейт: UI показывает источник и время данных; переключение tenant не
показывает чужой state. Нет работающих изменений маршрутизации.

## Этап 2 — SaaS Control backend и безопасность

**Статус:** `SPEC`.

- [ ] Выбрать backend, схему PostgreSQL, миграции, индексы, RLS + tenant AuthZ.
- [ ] Отдельный tenant-scoped SSO/login, роли admin/owner/viewer.
- [ ] Реализовать Vault abstraction: key wrapping, rotation, audit, service identities.
- [ ] Получить официальный provider capabilities/approved auth modes registry.
- [ ] Версионированные `/v1/tenants`, `/v1/accounts`, `/v1/egress` API,
      server-side validation, error taxonomy, idempotency/ETag, pagination.
- [ ] Изоляция кэша и запросов; deny by default; журнал действий и grants.
- [ ] Staging без продакшен-ключей и OAuth.

Гейт: penetration testing tenant breakout, отсутствие чужих данных в API,
RBAC+RLS double enforcement, backup+restore dry run.

## Этап 3 — Проверяемый egress + BYOK

**Статус:** `SPEC`.

- [ ] Сеть: каталог HTTP/HTTPS/SOCKS5(H) профилей, операторский allow-list.
- [ ] DNS A/AAAA validation + network firewall + запрет CGNAT/private/metadata,
      DNS rebinding, SSRF через redirects/IPv6, credential exfiltration.
- [ ] Runtime connector обеспечивает fail-closed при proxy down, including
      retries, SSE, WebSocket и OAuth token refresh.
- [ ] Проверить фактически выбранную учётную запись **после** Core scheduler;
      никакого fallback на соседнего tenant или direct.
- [ ] BYOK: только собственный API ключ клиента в Vault, модельный allow-list.
- [ ] Тесты IP egress, reconnect, timeouts, 407, DNS failure, rate-limit.
- [ ] Определить, достаточна ли общая Core-инстанция; иначе выделенный Core.

Гейт: доказанная network-level изоляция; не один лишь allow от JS resolver.
Проверки без доступа к production токенам. Публичный Gateway не должен
передавать management endpoints.

## Этап 4 — BYOA и поддерживаемая авторизация

**Статус:** `SPEC`.

- [ ] Таблица provider/method/allowed_use + подтверждение действующих правил.
- [ ] Встроить системный OAuth/PKCE redirect там, где официально разрешено;
      без антидетекта/подмены браузера и обхода провайдерских блокировок.
- [ ] Refresh/revoke/401/403/429 + cooling + manual reconnect + audit.
- [ ] Не передавать подписные OAuth-токены третьим лицам; разграничить ownership.
- [ ] Интеграционные тесты подключения с аккаунтом, специально разрешённым
      для сценария, в staging.

Гейт: документированное разрешение провайдера и возможность отзыва токена.

## Этап 5 — Analytics, стоимость и Request Trace

**Статус:** `SPEC`.

- [ ] Подписанные события в безопасной схеме, masked references и provenance.
- [ ] Корреляция request_id → CPA policy → verified account → verified egress.
- [ ] Postgres retention, idempotency key, audit, aggregate + cost pricing version.
- [ ] Учитывать input/output/cache/reasoning, если реально доступны.
- [ ] Отделять estimated cost от invoiced/actual; не выдумывать цены/usage.
- [ ] UX timeline + replay, ограниченная анимация, reduced-motion.
- [ ] Проверить нагрузку без блокирования AI inference при сбоях аналитики.

Гейт: воспроизводимость расчётов, правильное tenant scope,
полная очистка/анонимизация по retention.

## Этап 6 — VPN Connector как опция

**Статус:** `SPEC`.

- [ ] Оценить Railway VM/network ограничения WireGuard/Tailscale/tunless egress.
- [ ] Реализовать отдельный connector (не исполнять VPN в Core и не смешивать
      Core secret volume с VPN secret store).
- [ ] Определить fixed exit IP, сеть и port, DNS/IPv6 поведение, health.
- [ ] Connector identity attestation, rotated secrets, egress route verification.
- [ ] Ротация конфигурации без потери критичных сессий; audit.
- [ ] Fail-closed тест при остановке VPN и отказах DNS, без direct fallback.
- [ ] Допустить только правомерные способы сетевого доступа; не обход
      блокировок провайдеров или региональных/лицензионных ограничений.

Гейт: demo environment и security review; feature flag остаётся OFF в production.

## Постоянные ворота для каждого релиза

- Отдельный PR, отдельный commit и lockfile-free change при отсутствии
  необходимости в зависимости.
- `bun run verify` зелёный; TypeScript строгий, unit tests + integration tests
  под соответствующий этап.
- API contract version и migrations; при breaking change — backward
  compatibility plan + automatic rollback.
- Нет ключей/tokens/паролей в Git, client UI, error messages и логах.
- Contract tests совместимости с конкретным CLIProxyAPI v8.0.23 и CPA v0.5.1
  до изменения pinned SHA Core.
- Gateway/Core/Management Center выпускаются отдельно; релиз статического
  `management.html` не повод для обновления Core.
- Production трафик, /data, OAuth и API ключи — неизменяемы во время Blueprint.
  Любые runtime изменения только после отдельного разрешения и backup.
- UX: понятно owner/status/route, mobile, keyboard, a11y, RU+EN, ошибок
  достаточно для восстановления без раскрытия посторонних ресурсов.
- Observability: trace reason code, version, tenant-scoped correlation,
  audit с redaction; владельцу ясно, где симуляция, а где реальные данные.

## Матрица рисков

| Риск | Минимальная защита | Что проверять |
| --- | --- | --- |
| Tenant A использует аккаунт B | owner + grant + post-scheduler enforcement | mismatch tests |
| Неисправный proxy ведёт напрямую | обязательный egress + firewall fail-closed | proxy down / reconnect |
| DNS hostname ведёт на metadata IP | strict DNS policy + firewall | A/AAAA/rebinding tests |
| OAuth или proxy-secret в trace | whitelist-only serialization + Vault | no-secrets tests |
| Подписка провайдера используется против правил | approved auth modes registry | provider review |
| UI показывает старый tenant | request invalidation, no cross-tenant cache | race tests |
| Usage посчитан дважды | idempotent event ledger | retry/dedup tests |
| Финансы выглядят точными без данных | provenance + estimated/actual separation | pricing tests |
| Случайный UI merge провоцирует live release | draft PR и отдельный release gate | GitHub workflow rules |

## Минимальная последовательность первого рабочего прототипа

1. Сохранить эти требования и CI в отдельной ветке (текущий шаг).
2. Проверить API Core и CPA plugins: откуда берутся account/egress метаданные
   без чтения секретов; отдельное ADR по точке enforcement.
3. Спроектировать wireframe и read-only mock UI под `/saas` за feature flag.
4. Спроектировать SaaS API/Vault/DB, только после этого обеспечить реальный
   account/egress enforcement на стенде.

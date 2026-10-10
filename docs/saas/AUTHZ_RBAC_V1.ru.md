# SaaS Control v1 — модель AuthZ/RBAC (RU)

**Статус: SPEC для настоящего SaaS; чистые функции и local HTTP handler SIMULATED.**
Есть только краткоживущая локальная синтетическая проверка session;
реальных OIDC/SSO, БД, PostgreSQL RLS и runtime enforcement нет.
TypeScript-модели **нельзя** считать механизмом безопасности существующего
Core или Gateway.

## 1. Где проходит доверительная граница

1. Отдельный SaaS authentication provider подтверждает пользователя и
   создаёт actorId. Нельзя формировать actor по X-Tenant-ID, X-User-ID,
   client-provided JWT payload или CPA key без проверки подписи/audience.
2. При каждом запросе backend определяет активное membership для tenant,
   запрошенного в URL. 0, 2 или более совпадающих memberships = deny.
   Отозванное membership = deny. Никакого глобального доступа платформы
   на основании одной метки «платформа».
3. Backend проверяет роль (RBAC action). Это **не** заменяет проверку
   владения каждым аккаунтом, пулом и egress профилем.
4. Для DB-запроса применяются tenant-scoped SQL predicates, индекс
   actor/tenant/permission и RLS как дополнительная защита. Проверка роли
   только в браузере недопустима.
5. Весь аудит пишет actor/tenant/resourceKind/action/decision/time и
   correlation ID, но не секреты, proxy URLs, auth header или raw prompt.

## 2. Матрица read-only v1

| Capability / коллекция | tenant-owner | tenant-admin | tenant-viewer | tenant-auditor |
| --- | :---: | :---: | :---: | :---: |
| tenant (metadata) | Да | Да | Да | Да |
| projects | Да | Да | Да | Да |
| applications | Да | Да | Да | Да |
| client-keys (CPA binding reference) | Да | Да | Да | Нет |
| accounts (без secrets) | Да | Да | Да | Нет |
| pools (отдельно от grants на accounts) | Да | Да | Да | Нет |
| egress (без proxy/VPN passwords) | Да | Да | Да | Нет |
| routing (read-only binding) | Да | Да | Да | Нет |
| Любое изменение, секреты, OAuth refresh, Vault, health probe | Нет | Нет | Нет | Нет |

Роли — начальная схема, **не production-политика**. Только read-only;
всем четырём ролям write запрещён до отдельного дизайна API, серверной
проверки, журналирования и подтверждённого rollout. В будущем platform
operator должен иметь отдельную административную область и
audited explicit tenant-assumption, а не универсальный обход tenant checks.

## 3. Два независимых уровня разрешений

**Уровень A: членство пользователя.** Actor имеет membership с
tenantId, role, status. При отсутствии membership backend не должен
раскрывать, существует ли tenant или чужой resource: общий 404.

**Уровень B: владение объектом.** Account, Pool и Egress имеют Owner
(tenant или platform) и привязанные AccessGrant. Собственный ресурс
может быть прочитан пользователем с RBAC-доступом. Чужой — только при
активном *специфическом* grant с совпадающими:

- resourceKind и resourceId;
- реальный владелец и granteeTenantId;
- status = active;
- действующий expiresAt; неверное или истёкшее значение = DENY.

Grant на Pool **не** раскрывает accountIds чужих аккаунтов. Grant на
Account **не** открывает Pool и Egress. Grant на Egress **не** разрешает
выполнять запрос: реальный сетевой маршрут обязан быть подтверждён
отдельным enforcement после Core scheduler. Direct нельзя включать
неявно ни при одном grant.

## 4. Redaction в read-only DTO

- Для foreign аккаунта/egress без grant нет карточки и нет подсказки,
  причины, ID или имени; детальный read должен отвечать общим 404.
- При разрешённом Account с недоступным Egress:
  egressProfileId = null (не выдавать ID запрещённого профиля).
- При доступном Pool с невидимыми Accounts:
  accountIds содержит только индивидуально разрешённые аккаунты.
- При своём RoutingBinding на недоступный Pool:
  poolId = null; статус и egressPolicy остаются синтетическими метаданными,
  не разрешением выполнить реальный запрос.
- Core-native access keys, OAuth tokens, Vault handles, session cookies,
  proxy userinfo/password, VPN private config, raw prompts и payload никогда
  не экспортируются.
- При unknown коллекции или чужом tenant — 404 без чужих идентификаторов.
  При RBAC недостатке на известном tenant — 403 без resource details.

## 5. Угрозы и будущие server-side проверки

| Угроза | Обязательная мера на staging | Статус |
| --- | --- | --- |
| Подмена tenantId через URL/header | Actor tenant-membership lookup + deny/no discovery | SPEC |
| Подмена actor/role в body | Только trusted auth session + policy layer | SPEC |
| IDOR чужого аккаунта | Scoped SQL/RLS + grant owner match | SPEC |
| Раскрытие pool member IDs | Независимая фильтрация каждого account | SIMULATED, backend SPEC |
| Раскрытие egress чужого аккаунта | Null refs + explicit grant | SIMULATED, backend SPEC |
| Окончившийся grant | Проверка expiry на серверных часах, кэш invalidation | SIMULATED, backend SPEC |
| Утечка через логи/ошибки | Whitelist DTO, generic deny response, audit redaction | SIMULATED, backend SPEC |
| Race при tenant switch | Abort, generation check, tenant-aware cache keys | SPEC |
| Подмена источника «live» | Server-issued provenance + correlation, no client override | SPEC |
| Падение proxy/VPN | Network firewall fail-closed, запрет fallback direct | SPEC |

При внедрении необходимо ужесточить время выдачи grants до строгого
RFC3339/UTC разбора (чистый прототип проверяет parseable timestamp +
expiry), определить clock skew/TTL и транзакционность отзыва. Нужны
contract tests с PostgreSQL/RLS, tenancy breakout tests и migration replay
в изолированном staging без production credential files.

## 6. Проверяемые функции

- authorizeTenantRead — матрица доступа, статус membership, deny on duplicate.
- mayViewTenantResource — владелец и отдельный grant на Pool/Account/Egress.
- readSyntheticTenantCollection — безопасное whitelist DTO после обеих
  проверок и фильтрации источника.
- listAccessibleTenants — только активные и неоднозначно не-дублирующиеся
  memberships.

Тесты: tests/saasControlApiV1.test.ts. Никаких HTTP routes или реальных
подключений к CLIProxyAPI нет. См. [CONTROL_API_V1.ru.md](CONTROL_API_V1.ru.md).

## Local-only synthetic session verification (итерация 2B)

Тестовый HTTP boundary принимает только короткоживущую 256-битную
opaque session, созданную на доверенном bootstrap без HTTP login.
Далее actor и membership проверяются в серверном каталоге,
не из заголовков/тела. После асинхронного read bearer/token и
actor membership повторно проверяются до выдачи данных.
Это устраняет ложную трактовку demo actor как настоящей SaaS роли,
но не заменяет production OIDC и revoke/audit в БД.
См. [LOCAL_CONTROL_HTTP_V1.ru.md](LOCAL_CONTROL_HTTP_V1.ru.md).


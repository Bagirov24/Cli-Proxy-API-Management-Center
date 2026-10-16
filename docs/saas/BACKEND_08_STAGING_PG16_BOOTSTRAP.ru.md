# Backend 08 — отдельная PostgreSQL16 staging и одноразовый migration bootstrap

**16 октября 2026. Статус:** новый SQL bootstrap и его доказательство — **только CI**; конфигурация PostgreSQL16 в Railway — **STAGED, не deployed**. Это не одобрение production, не постоянная миграция SQL001–027 и не запуск SaaS API.

## 1. Изолированный Railway-контур

| Ресурс | Значение | Действие |
| --- | --- | --- |
| Проект | \`cliproxyapi-saas-staging\`, \`a9703851-6eb1-406c-bb15-7d3a89359fb7\` | Только этот проект |
| Environment | \`staging\`, \`b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b\` | Не \`production\` |
| Backend | \`saas-control-api\`, \`a0ff5420-95e8-4fab-88f6-623f75dd03c6\` | Пустой, без GitHub source/deploy |
| PostgreSQL | \`Postgres\`, \`37f8f166-75a6-4617-b243-8e681181c16d\` | **STAGED** \`ghcr.io/railwayapp-templates/postgres-ssl:16\` |
| Том | \`postgres-volume\`, \`5a94361a-10c4-423a-a751-19271aa10fe6\` | **STAGED** \`/var/lib/postgresql/data\` |
| Patch | \`592ba6e1-76ad-48fb-b730-e24b730b8eaf\` | Не принимать автоматически |

Из шаблона PostgreSQL16 пришёл **публичный TCP proxy :5432**, что нарушало требование private-only. До какого-либо deploy отправлено **staged удаление** этого прокси. Текущая preview-конфигурация показывает \`networking.tcpProxies.5432 = null\` и не содержит service domains. Шаблон не отмечен Railway как verified. До применения patch необходимо независимо проверить источник образа/уязвимости, patch и сетевые ACL, затем отдельно разрешить выделение ресурса и расходы. Нельзя считать строку \`DATABASE_PUBLIC_URL\` в шаблоне доказательством отсутствия публичного маршрута: проверять **реальные** TCP proxies после применения.

**НЕ трогать** production \`cliproxyapi-personal\` (\`bd565370-7321-4dba-908a-412186b1b986\`), ветки \`custom-no-apikey-fun\` / \`api-gateway\`, живые credentials или том \`cliproxyapi-data\` в \`/data\`.

## 2. Новый bootstrap: только учёт миграций, без бизнес-таблиц

\`staging/saas-bootstrap/0001_ledger_only.sql\` создаёт **только** закрытую схему \`saas_bootstrap\`, таблицу \`schema_migrations\` с ID, SHA256 файла и SHA коммита, и блокирующий UPDATE/DELETE триггер. PostgreSQL16, точная БД \`saas_staging\` (или CI \`saas_staging_ci\`) и однократное выполнение обязательны. Наличие старой пилотной схемы \`saas_rls\`, \`saas_m1_*\` или уже существующей схемы \`saas_bootstrap\` — **STOP**. Роль мигратора для постоянной базы должна быть **не superuser**.

**Никаких** SQL001–027, SQL019, tenant/project data, issuance, secrets, RLS grants или автоматического старта миграций. Ledger trigger — лишь защита от случайного DML, не WORM и не независимое доказательство неизменности. Приложение не имеет доступа к миграционной схеме по умолчанию.

\`scripts/saas-staging/plan-staging-bootstrap.mjs --plan\` без подключений возвращает checksum, точные scope IDs и \`executionAuthorized=false\`. Опция \`--check-staging-context\` требует отдельный проект, environment, имя private host, ожидаемую БД и роль \`saas_schema_migrator\`, но только сверяет **строки окружения**; не подтверждает identity от Railway и никогда не выполняет SQL. Сервис API не импортирует скрипт и не запускает миграции.

## 3. Gate для оператора (пока НЕ выполнен)

1. **Approval:** независимое security/codeowner/ops одобрение образа PG16, приватной сети, расходов и работ в отдельном SaaS staging. До него не применять staged patch и не создавать публичные proxy/domain.
2. **Настоящая PostgreSQL16:** после явного разрешения проверять deployment \`SUCCESS\`, \`SHOW server_version_num\` = 16.x, состояние volume, TLS/доступность только из приватной сети и ноль публичных TCP proxies/domains. Проверка конфигурации до деплоя не является тестом сетевой доступности после него.
3. **Учётные записи:** вручную учредить отдельную БД \`saas_staging\` и непривилегированную роль владельца схемы \`saas_schema_migrator\` с минимумом прав для bootstrap; ни superuser, ни CPA Core/Gateway credential, ни runtime IAM/session/query роль не должны участвовать. Доступы/секреты только через operator-managed secrets, не git и не CI logs.
4. **Disaster recovery:** до любого постоянного DDL подтвердить включённые snapshot/retention/PITR и **проверить восстановление** в независимую БД, включая checksum/data consistency. Копия на том же хосте не заменяет off-host backup. Название «managed Postgres» само по себе не доказывает PITR или восстановление.
5. **Ручная миграция только после пункта 1–4:** получить reviewed SHA-256 именно \`0001_ledger_only.sql\`, \`source_commit\` (40 hex), проверить \`--plan\`, target IDs вне SQL и работу \`psql\` в контуре оператора; выставить \`PGOPTIONS="-c saas.staging_only=true"\` и передать \`-v bootstrap_sha256=<approved file hash> -v source_commit=<reviewed commit>\` в \`psql -X -v ON_ERROR_STOP=1 -d saas_staging -f staging/saas-bootstrap/0001_ledger_only.sql\`. **Не автоматизировать в startup/predeploy/CI against Railway.**
6. **Read-back:** сверить ровно одну запись в \`saas_bootstrap.schema_migrations\`, DDL, owned role, отсутствие grants runtime, pilot schema, автоматических public endpoints и отсутствие изменений production. При отсутствии ACK после COMMIT состояние **UNKNOWN**: не повторять «для надёжности», сначала reconcile по ledger, системным каталогам и независимому operator audit.

## 4. CI acceptance (одноразовая PostgreSQL16)

Workflow создаёт **новую отдельную \`saas_staging_ci\`** внутри GitHub Actions PostgreSQL16, без SQL001–027. Проверяет применение ledger, точный checksum, отказ от повторного bootstrap/запуска на pilot DB, запрет UPDATE, отсутствие runtime grants и pilot schemas. Создаёт schema-only-scope **custom-format dump с данными ledger**, восстанавливает в **другую одноразовую БД** \`saas_restore_ci\` и сравнивает исходную запись. Артефакт дампа удаляется на раннере; это **не** проверка Railway backup/PITR или операционного restore.

Все пять PR workflow должны быть зелёными на **одном точном HEAD**, включая Main CI, PostgreSQL16, read-only Management release guard, Demo Build и Chromium. Даже 5/5 не разрешает deploy постоянного staging без ops gate. Следующие этапы: отдельные runtime/login roles и audited migrations после проверки backups, затем SaaS API wiring только после реального external IdP, DB physical discard, off-host WORM и approval.

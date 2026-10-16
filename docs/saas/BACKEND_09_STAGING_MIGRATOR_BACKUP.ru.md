# Backend 09 — PostgreSQL16 staging развёрнута; изолированный migrator / backup gate

**16 октября 2026.** Текущее состояние, заменяет исторический pre-deploy snapshot в Backend08. Это **не production rollout** и ещё не установленная постоянная схема SaaS.

## Подтверждённые факты Railway (read-only после авторизованного apply)

| Ресурс / факт | Значение |
| --- | --- |
| Проект | \`cliproxyapi-saas-staging\`, \`a9703851-6eb1-406c-bb15-7d3a89359fb7\` |
| Environment | \`staging\`, \`b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b\` |
| PostgreSQL service | \`Postgres\`, \`37f8f166-75a6-4617-b243-8e681181c16d\` |
| Deployment | \`dcb8a17e-bc3e-4985-9663-e012e8048a97\` — \`SUCCESS\` |
| Версия по actual runtime log | \`PostgreSQL 16.15 (Debian 16.15-1.pgdg13+2)\` |
| Источник image | \`ghcr.io/railwayapp-templates/postgres-ssl:16\`; официальный публичный source \`railwayapp-templates/postgres-ssl\` (но конкретный community-шаблон не имел отметки verified) |
| Том | \`postgres-volume\`, \`5a94361a-10c4-423a-a751-19271aa10fe6\`, \`/var/lib/postgresql/data\` |
| Публичные TCP proxies / HTTP domains | 0 / 0 (проверено после deploy) |
| \`saas-control-api\` | source и deployment отсутствуют; API не открыт |
| Production \`cliproxyapi-personal\` | Core/Gateway Online; ветки, секреты, \`/data\`, deployments не изменялись |

**Не подтверждено:** реальный \`SHOW server_version_num\` по SQL, текущий \`POSTGRES_DB\` из самой БД, TLS chain/SAN pinning из клиента, PostgreSQL grant catalog, физическая безопасность inter-service connectivity, включение PITR, snapshot schedules, сохранность и восстановимость off-host backup. Railway deployment \`SUCCESS\` — не замена этим проверкам.

## Новое: операторский bootstrap роли (сначала CI, НЕ live staging)

\`staging/saas-bootstrap/0000_operator_migrator_role.sql\` разрешает одноразовый prebootstrap **только** в новой \`saas_staging\` или disposable \`saas_staging_ci\` при PostgreSQL16 и явно переданном \`saas.staging_only=true\`. Требует \`session_user=postgres\` и внешнего случайного 48–128-символьного hex-пароля; отсутствующий/слабый пароль запрещён.

Создаётся только \`saas_schema_migrator LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION\`. База получает \`REVOKE ALL ... FROM PUBLIC\`, migrator — только \`CONNECT, CREATE\` **в текущей allowlisted БД**; схема \`public\` закрывается для PUBLIC. Нет runtime, actor, session, signer или Core/Gateway grants. Повторное выполнение/неизвестный предыдущий COMMIT требует ручного reconciliation, не retry.

\`0001_ledger_only.sql\` затем выполняется только от \`saas_schema_migrator\`, отдельно от администратора. Он создаёт \`saas_bootstrap\` и одну миграционную запись, без пользовательских таблиц, токенов, production схем и SQL001–027. \`scripts/saas-staging/plan-staging-bootstrap.mjs --plan\` выводит SHA-256 обоих проверенных файлов и \`executionAuthorized=false\`; **планировщик не запускает SQL**.

В disposable GitHub CI PostgreSQL16 нужно проверить: создание 0000 как ephemeral operator, 0001 как настоящая непривилегированная role с паролем, реальные \`rol*\` флаги, отсутствие role membership и \`CREATE\` вне \`saas_staging_ci\`, ownership ledger у migrator, запрет PUBLIC/runtime CONNECT, невозможность replay обоих файлов, отказ в пилотной базе, затем независимые \`pg_dump -Fc\` и \`pg_restore\` с checksum. Никаких Railway credentials или migration calls в GitHub workflow.

## Следующий runtime gate: backup/PITR и ручной staging setup

1. Оператор открывает **только** staging Postgres → **Backups** в Railway, активирует PITR/continuous archiving или утверждённые snapshots в соответствии с правилами хранения. Документация: <https://docs.railway.com/volumes/point-in-time-recovery>. PITR использует \`pgBackRest\`, staging Railway bucket, WAL + base backups; перенос от конфигурации к фактической здоровой архивации **должен быть доказан**. Не выдавать включённый переключатель за действующий backup.
2. Убедиться в наличии первой base backup и доступного restore window. Провести **восстановление в независимую sibling staging-службу**, а не в живой Postgres. Проверить \`SHOW server_version_num\`, имя и checksum контрольных записей, WAL replay и отсутствие публичных proxies. Не считать тестовый GitHub \`pg_dump\` подтверждением Railway PITR.
3. Проверить \`saas_staging\` и owner изнутри **приватной** Railway сети. Для постоянных SQL использовать отдельный operator-controlled ephemeral runner, не \`saas-control-api\` и не GitHub Actions. Никаких публичных DB TCP-proxies, \`DATABASE_PUBLIC_URL\`, production credentials или \`Core/Gateway\` access.
4. Подготовить 64-hex секрет migrator во внешнем секретном хранилище; не помещать его в shell history, git, logs, chat, app env или CI. В operator-controlled SQL с \`PGOPTIONS="-c saas.staging_only=true"\` под \`postgres\` однократно применить \`0000_operator_migrator_role.sql\` с параметром \`migration_password\` — **только после backup+restore и security approval**.
5. От имени \`saas_schema_migrator\` проверить offline plan, hash, точный source commit, затем однократно выполнить \`0001_ledger_only.sql\` с \`bootstrap_sha256\`, \`source_commit\`, \`-X -v ON_ERROR_STOP=1\`. Доказать ownership/grants, отсутствие пилотных схем и только один receipt. Не включать автоматический preDeploy или on-startup runner.
6. Потеря ACK после \`COMMIT\` = **UNKNOWN**. STOP и ручная проверка live schema+receipt+external audit. Ни retries, ни repair/delete, ни повторной выдачи credentials/session.

## Ограничения

Staging database разрешено держать запущенной, но она **пока не разрешена** для реальных tenant credentials, OIDC issuer, SQL019, SQL001–027, внешних write routes или публичного SaaS. Отдельные tenant-scoped роли и RLS будут следующим проектным этапом ПОСЛЕ verified backup/restore и operator bootstrap. Не переносить CI-only \`saas_ci_runner\` и \`saas_identity_ci\` в Railway. External WORM и независимые security/ops approvals пока не подтверждены.

# M1f — ручной READ ONLY просмотр локальных доказательств UNKNOWN COMMIT

**Статус: STACKED DRAFT / CI-ONLY / NOT PRODUCTION / NO RETRY.**
Основание — Draft [PR №8 M1e](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/8)
поверх Draft PR №7 → №6 → №5 → №4 → №3. Никаких merge/Ready/deploy.

## Проблема

В M1e есть два реальных теста *до* COMMIT: PostgreSQL backend был
физически завершён и запрос был отменён; результатом стали 503,
карантин CI-пула, исчезнувшая PG session и **0 project / 0 private audit**.
Отдельно M1b проверяет потерянный локальный ACK *после* настоящего COMMIT:
тот же внешний **503**, но **1 project / 1 private audit**.
HTTP 503 не позволяет решить, была ли исходная запись подтверждена.
Неполное/отсутствующее локальное доказательство также может означать
незавершённую транзакцию, отставание реплики, подмену записей в общем DB,
неизвестный outcome. Нельзя автоматически делать replay, retry или reissue.

Существующая миграция `012_committed_local_audit_reconciliation_pilot.sql`
предназначена для **signed publication Allow events** и local publication
outbox, а не для project write. Повторно использовать её lease/ACK как
операторское доказательство project commit было бы ложным смешением
доменов. Поэтому M1f вводит только отдельную read-only **проекцию**
существующих таблиц M1c, без claim/reconciliation/lease или write APIs.

## Узкий контракт CI-only SQL023

`staging/saas-rls/023_m1_unknown_commit_readonly_review_pilot.sql`:

- Устанавливается только суперпользователем `postgres` на точно
  `saas_ephemeral_test` при `saas.staging_only=true`, требует M1d fenced
  trigger и обе FORCE RLS таблицы. Не переносится в production.
- Создаёт две раздельные NOLOGIN/NOINHERIT/NOBYPASSRLS роли:
  `saas_m1_review_owner` и `saas_m1_review_operator`.
  Owner может **только читать** `saas_m1_private.projects` и
  `saas_m1_private.project_write_audit_outbox` по явным
  SELECT policies FORCE RLS. Operator не получает SELECT ни на одну
  таблицу, только EXECUTE безопасной `SECURITY DEFINER` функции.
  Runner, M1 executor, reader и другие роли не получают ни schema USAGE,
  ни EXECUTE, ни signer/journal доступ.
- Функция `saas_m1_review.inspect_unknown_project_commit` принимает
  нормализованные tenant/project/operation/expected-version/expected-actor,
  выполняется **только в READ COMMITTED READ ONLY транзакции** и
  возвращает ограниченные поля: `evidence_code`, локальный `event_id`
  и текущую версию проекта **только если локальная пара подтверждена**.
  Не возвращает name, token, секрет, запрос, тело, raw SQL, actor ID
  или customer metadata.
- Требуется одна соответствующая audit строка, действующий project,
  matching operation и actor, project.version >= expected_version,
  **полная непрерывная цепочка audit версий 1..current project.version**.
  При mismatched actor/op/version, неполном журнале или orphan row —
  `INCONSISTENT_STOP` без выдачи данных.
- Если нет ни project, ни audit — `NO_LOCAL_EVIDENCE`. Это **НЕ**
  отрицательное доказательство и НЕ разрешение повторить операцию.

## Три кода результата и допустимое действие

| Код | Что реально наблюдалось | Следующее действие |
| --- | --- | --- |
| `LOCAL_PAIR_OBSERVED` | В одной snapshot видна полная локальная цепочка audit и matching project/version/actor/op | Ручное сравнение с внешней заявкой. **Нет доказательства**, что именно потерянный исходный запрос породил эти строки: нет immutable operation ID |
| `NO_LOCAL_EVIDENCE` | В локальной snapshot нет ни project, ни audit | **STOP**. Нельзя делать вывод «не был COMMIT», нельзя retry; эскалировать на ручное расследование |
| `INCONSISTENT_STOP` | Есть конфликтующие, неполные или несоответствующие локальные данные | **STOP**. Сохранить доказательства, security review, запретить дальнейшие write/reissue |

Даже `LOCAL_PAIR_OBSERVED` не означает независимый WORM, external receipt,
causality proof, safe retry или production approval. Таблица и проект
находятся в **одном PostgreSQL trust domain**, где DBA/snapshot могут
откатить/изменить оба источника. Read-only snapshot не защищает от
будущей ревокации, реплик, network partition во время COMMIT.
Для operator signoff необходимы независимые доказательства, привязка
попытки к durable operation ID, отдельное управление правами и протокол
письменного решения.

## Реальная проверка в disposable PostgreSQL16 CI

После E2E M1b + M1e и проверок M1c/M1d запускается SQL023,
затем `tests/sql/saas_m1_unknown_commit_readonly_review.test.sql`:

1. `m1b-lost-ack`: после реального COMMIT и потери ACK — 1 project/1 audit,
   `LOCAL_PAIR_OBSERVED`. Это не подтверждение конкретного HTTP-запроса.
2. `m1e-physical-loss` и `m1e-aborted`: физическая потеря backend
   и отмена до COMMIT — `NO_LOCAL_EVIDENCE`, никогда не `safe_retry`.
3. Для forged/mismatched actor, operation и версии — `INCONSISTENT_STOP`.
   Для старого create/rename, впоследствии disabled проекта, проверяется
   полная audit history и положительное наблюдение без предположения,
   что project.version неизменна.
4. Невозможность вызова из READ WRITE, отсутствие SELECT/EXECUTE у
   CI runner, project executor и readonly operator; повторная SQL023
   не меняет project/audit/версии.

## Railway TLS — отдельный приоритет

Для `cpa-gateway-sandbox/sandbox` ранее read-only наблюдением
подтверждены: новый deployment `a5e9ccdc-b9ae-4392-945a-6d65b8c2c284`
имеет `SUCCESS`, прежний mTLS deployment `REMOVED`, активный Start
Command — безопасный без listener, существующий постоянный том
`synthetic-highwater-only` сохранён. Это **не является независимым
TCP-отрицательным тестом порта 8443** и не повод менять содержимое тома.
Документированный PKI expiry: **15 октября 2026, 13:33 UTC**.

## Hard stops

SQL019, Railway signer/journal/volume, production PostgreSQL, HTTP public
endpoints, Core/CPA/OAuth credentials, automatic retry/reissue/reuse/repair,
UUID mint, external delivery, archive/GC запрещены.
`gcPermitted=false`. Любая будущая production процедура требует
независимого audit evidence, operation ID/idempotency contract,
сессионной авторизации, ручного security/code-owner review и explicit
human release approval.
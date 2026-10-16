# M1d — транзакционный fence project write против tenant revoke (PG16 CI only)

**Статус:** STACKED DRAFT / NO PRODUCTION / NO MERGE APPROVAL.
База — незамерженный [M1c PR №6](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/pull/6),
последовательно поверх M1b PR №5, M1a PR №4, M0 PR №3.
Работа в ветке M1d не меняет их HEAD и не даёт разрешения на релиз.

## Угроза, которую закрываем только внутри одного PostgreSQL

В M1c write функции проверяли signed actor/tenant/membership и
записывали обязательный audit event, но **не удерживали
tenant authorization epoch lock** до завершения COMMIT. Поэтому конкурирующая
транзакция revocation могла зафиксироваться между проверкой роли и
project COMMIT. Это не обязательно оставляло проект без аудита,
но оставляло риск нарушения порядка авторизации.

В существующем M0 уже есть две части механизма:

- Миграция `004` содержит приватную таблицу
  `saas_rls_private.tenant_authorization_revisions`. Триггеры изменения
  tenant status и membership выполняют `UPDATE` ревизии до COMMIT.
  Миграция `008` аналогично инкрементирует tenant epochs при actor-wide
  session revocation.
- Миграция `007` содержит
  `saas_rls.acquire_authorized_read_barrier(tenant,actor,role,collection)`:
  только при signed transaction scope, действующем tenant, membership
  и actor state в `READ COMMITTED` получает `SELECT FOR SHARE` на ту же
  приватную строку ревизии, а **после ожидания блокировки** снова проверяет
  авторизацию.

**В M1d не создаётся второй источник полномочий.**
SQL `022_m1_project_authorization_fence_pilot.sql` — узкий CI-only шаг.
Он оставляет существующие публичные `saas_m1_api.create_project` /
`rename_project` / `disable_project` без изменений, но заменяет
private AFTER ROW audit trigger на `append_project_write_audit_fenced`.
Триггер удерживает подписанную shared-lock строку ревизии tenant,
затем вставляет M1c audit событие в той же транзакции. Успешная
subtransaction функции сохраняет lock до COMMIT/ROLLBACK внешней
транзакции. Ошибка locked-scope / audit UNIQUE / RLS делает mutation
ложной и откатывает provisional project row.

Для доступа к existing signed barrier только NOLOGIN
`saas_m1_audit_owner` получает `EXECUTE`; ему не выдаются private
epoch table SELECT, signer keys, project UPDATE, HTTP или actor JWT.
Private outbox сохраняет FORCE RLS и append-only SQL, без secret payload.

## Проверяемые порядки событий

`scripts/saas-staging/verify-m1-project-revoke-fence.sh` исполняется
**только** в GitHub Actions на `127.0.0.1:5432/saas_ephemeral_test`
при явном `SAAS_EPHEMERAL_M1_FENCE_CI=true`. Это две физически
различные psql fixture sessions, встроенная PostgreSQL блокировка
наблюдается через `pg_stat_activity.wait_event_type='Lock'`;
фиксированный synthetic actor подписывается только приватной
CI fixture функцией; затем `SET LOCAL ROLE saas_m1_project_executor`.

1. **WRITE → REVOKE:** signed project write получает FOR SHARE,
   write+audit готовы, но transaction удерживается открытой.
   Конкурирующий `UPDATE memberships status='revoked'` блокируется
   на изменении той же tenant epoch строки. Сначала project+audit
   COMMIT, затем revocation COMMIT. У проекта один audit event.
2. **REVOKE → WRITE:** первая транзакция обновляет membership и
   удерживает revision lock. Второй подписанный write может видеть
   предыдущий committed membership до взятия lock, но вынужден
   ждать, после COMMIT revocation перечитывает авторизацию и
   возвращает DENY. Нет ни project, ни audit event.
3. **TENANT SUSPEND → WRITE:** параллельное suspended tenant меняет
   тот же epoch и блокирует следующую signed project mutation.
   После commit suspension нет ни project, ни audit.
4. Утверждаются `READ COMMITTED` только, отказ при
   `REPEATABLE READ`, unsigned scope denial, отсутствие прямых
   table/signer полномочий, replay SQL022 с сохранением всех событий.
5. Старый SQL021 при ошибочном replay **после** SQL022 должен
   fail closed, а не восстановить не-fenced trigger. Guard внутри
   SQL021 явно запрещает переигрывание при наличии M1d функции,
   CI проверяет это негативным запуском.

Тесты из M1a–M1c и настоящий M1b native Bun.SQL RS256/E2E
продолжают запускаться в том же disposable CI job.
**Существенное ограничение:** конкурентный сценарий использует
привилегированные fixture-only psql процессы для signed scope,
а не работающий настоящий OIDC/production driver.

## Что всё ещё НЕ доказано

- Блокировки работают только для *сотрудничающих* PostgreSQL
  trigger/update путей на **одном авторитетном PG primary**. Это
  не внешний глобальный fence, не борьба с DB superuser/DDL,
  независимый WORM, rollback snapshot или split-brain.
- Настоящий identity provider / durable token-bound revocation,
  выдача production session и cross-replica actor mapping отсутствуют.
  TTL JWT и сессия вне PG могут измениться независимо от lock.
- Защита не устраняет UNKNOWN COMMIT, потерю ACK, safe retry,
  exactly-once, полноценный idempotency ledger, безопасный
  сетевой pool discard или real network cancellation.
  **Автоматические retry/reissue/repair по-прежнему запрещены.**
- PostgreSQL COMMIT гарантирует транзакционный порядок, **не**
  порядок ответа клиенту/внешнему подписанту, WORM или доставке.
  Сохранённая M1c audit строка принадлежит тому же DB trust domain.
- M1d не добавляет HTTP/API route, живые tenant credentials,
  Core/CPA/Gateway, OAuth, Vault, VPN или production migration.

## Следующий независимый milestone

Перед private Control API и любыми не-синтетическими write
потребуются durable issuer+subject session store, end-to-end
authorization epoch fencing, независимый append-only audit,
physical PG connection discard/timeout/partition proof,
операторская процедура UNKNOWN COMMIT, полноценные security
review / code-owner review и explicit release authorization.

**Hard stops:** PR остаётся Draft, не мержить и не деплоить.
Не менять Railway signer/journal/volume, production PostgreSQL,
SQL019, реальную выдачу/повтор/удаление UUID или CPA keys,
retry/reissue/repair/delivery/archive/GC. `gcPermitted=false`.
По существующему runbook тестовые Railway mTLS сертификаты
истекают **2026-10-15 13:33 UTC**; M1d их не ротирует.
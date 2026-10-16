# Stage 2G.4d.7x — Railway read-only high-water evidence, certificate expiry and safe rotation

**13 октября 2026. Staging ONLY.** Это инструкция по проверке
синтетического high-water и предупреждению об истечении короткоживущей
test PKI. Это НЕ отдельное управление оператором, не HSM/WORM,
не production release и не разрешение повторной выдачи UUID.

## 1. Реальный remote smoke после перезапуска клиента

Railway project: `cpa-gateway-sandbox`, id
`dba33407-7200-40e0-a9c8-08c43d41e5e4`.
Environment: `sandbox`, id
`9ee1afb9-9b20-4c50-91ef-6f23e3c5f3ee`.

- **Authority:** `saas-highwater-staging-only`, deployment
  `885ee1a7-8ffb-462b-ae0e-b47a260d5ff6`: `SUCCESS`, один экземпляр,
  постоянный private volume `synthetic-highwater-only` 512 МБ.
  **Authority не перезапускался и signer/journal/том не менялся.**
- **Stateless smoke:** `saas-highwater-private-smoke`, deployment
  `d3e4ee3d-5d74-4fb1-a28d-c9fd04e33c2f`, без тома.
  Только он был перезапущен **in place**, без rebuild, через штатный
  Railway restart-service. Номер deployment остался прежним.
- **Новый runtime log (19:21:28 UTC):** `PASS 7w:
  private-network HTTPS TLS1.3/mTLS head read with pinned server SPKI`;
  `PASS 7w: missing client certificate denied by actual remote authority`;
  `DIAG 7w: localEd25519=true, authoritySigBytes=64,
  cryptoVerifier=true, webVerifier=true, webStatus=completed`;
  `PASS 7w: retained signed remote head authenticated, revision=2`.
- Ветка кода smoke при `revision === 2` завершается **до append**,
  не выпускает новый nonce или UUID, не переписывает подписанный журнал.
  Оба сервиса после перезапуска `Online`, 1/1 running.

**Точная граница доказательства:** другой клиентский процесс прочитал
существующую remote signed revision 2. **Это НЕ remote authority restart
with retained volume:** отдельная проверка fsync/restart/lost ACK у
сервера с прикреплённым томом всё ещё НЕ выполнена.
Railway restart-service для сервиса с томом требует **явного разрешения
пользователя** после согласования возможного простоя и проверки
дополнительного read-only retained minimum; автоматический restart,
redeploy или restart через изменение настроек нельзя использовать
как обход этого требования.

## 2. CI-only проверка без доступа к Railway

`scripts/saas-staging/audit-railway-highwater-readonly.mjs` —
новый read-only аудит для *двух отдельных режимов*:

1. `--selftest` работает **только** на эпизодическом GitHub Actions
   PostgreSQL16 runner с `GITHUB_ACTIONS=true` и специальным CI guard.
   Создаёт временные test CA/server/client certificates и три
   Ed25519 signing keypairs **в /tmp**, создаёт 2 строки synthetic
   append-journal и после завершения удаляет временный каталог.
   Никаких реальных Railway secrets/issuer/payloads/PG writes.
2. `--railway-sandbox <authority-public-SPKI-SHA256> <minimum-revision>` —
   операторский **только read-only** audit для заранее разрешённого
   Railway high-water контейнера. Этот файл сейчас присутствует **в
   GitHub Draft PR, но НЕ установлен в работающий Railway deployment**
   с pinned старым SHA. Нельзя считать live запуск сделанным.
   Доставка аудитора на staging host/sidecar требует отдельного
   согласованного шага. Исполнять его на production запрещено.

На CI audit проверяет подписи Ed25519 witness, journal и внешнего
authority; связность nonce, точный expected predecessor, seq 1→2,
монотонность и digest projection, signer SPKI pin, уникальность nonce,
внешнюю policy marker SHA256 и финальный перевод строки JSONL. Любое
искажение, torn record, stale/fork, дублирование nonce, неверный pin,
незаявленная смена TLS SPKI или уменьшение ниже независимо переданного
`minimum-revision` приводит к отказу.

**Никогда не** передавайте в CLI выводе Bootstrap/private keys/`printenv`.
Аудитор читает PEM-сертификаты и **только public authority/witness/
journal keys** из уже существующего staging bootstrap, но не
экспортирует и не печатает секреты. В stdout лишь контрольные
публичные fingerprints, периоды сертификатов, signed revision/digest
и `gcPermitted=false`. Отсутствие независимого retained minimum
вне Railway нельзя заменить тем, что оператор передаёт число `2`.

## 3. Предупреждение о тестовых TLS-сертификатах

Истекают **15 октября 2026, 13:33 UTC** — это сертификаты тестового
staging, а не производственная CA.

- Новый аудитор проверяет валидность CA, подпись server и client
  сертификатов этой CA, `DNS:staging-highwater.internal.invalid`,
  server SPKI pin, `notBefore`/`notAfter`. За **48 часов до истечения**
  помечает `certificateStatus=rotation-required`; просрочка,
  неправильная цепочка или сертификат с будущим `notBefore` — не
  `valid`. Режим railway возвращает ненулевой код для проблемного
  срока, но сам файл/том/сертификаты не меняет.
- Поскольку существующий on-volume policy marker включает server
  **и client SPKI fingerprints, authority/witness/journal roots,
  logId и epoch**, простая замена TLS/CA-сертификатов на старом
  volume **не является разрешённой live rotation**.
  Особенно нельзя переписывать marker или переносить signed head
  к новому signer для «зелёного статуса».
- Отдельный clock alert **не доказывает**, что сервер уже защищён от
  rollback/двойной выдачи. Нельзя считать `Online` действительным
  mTLS после истечения: TLS-клиенты должны отклонить просроченный
  сертификат; smoke может перейти в `CRASHED`/fail-closed.

### Безопасный план до даты истечения

1. Зафиксировать read-only итог: policy SHA256, signed revision,
   receipt SHA256 и CA/server/client notAfter в независимом от
   Railway месте под контролем согласованного оператора;
   не записывать секреты, PII или приватные UUID.
2. Запретить новые POST/append на старом синтетическом log.
   **Никаких retry/reissue/repair/recipient delivery/GC.**
3. Выбрать **либо** остановить и сохранить старый staging с
   volume для аудита, **либо** с отдельным разрешением запустить
   **новый** sandbox proof domain (новый `logId`, новые issuer key
   и TLS/CA certs, новый пустой volume/epoch c новым contract pin).
   Это **новый synthetic log**, а НЕ продолжение старого.
4. Перед live привязкой клиента согласовать out-of-band
   independent signer pin, отдельное хранение retained minimum,
   разграничение администраторов и ключей. Настройку нового
   proof domain и затрат на Railway согласовать до deploy.
5. Выполнить manual Railway 2FA для каждого согласованного
   staged change, затем проверить actual TLS/mTLS, signer receipt,
   replay-fork-denial, restart/partition drills на новом scope.
   См. [Railway 2FA руководство](RAILWAY_2FA_OPERATOR_RUNBOOK.ru.md).
6. Security/operator signoff обязателен **до** любого включения
   production, issuer/tenant authorizations, PG settlement,
   recipient ACK или garbage collection.

**Не предлагать** автоматический overwrite PKI, root pin или
volume marker. Если old scope истечёт до rotation approval —
оставить его в карантине и запретить новые операции. Подписанные
строки остаются доказательством только при independently
сохранённом доверенном root; не сбрасывать журнал ради «SUCCESS».

## 4. Remaining production blockers

- Один personal Railway workspace: отсутствие независимого оператора,
  WORM/HSM/KMS и отдельно хранимого trusted minimum.
- Не доказаны remote server restart after fsync, lost ACK exact
  nonce replay, torn record/restore/failover/partition.
- Нет fenced atomic PG16 COMMIT→authority receipt/WAL/PITR,
  issuer actor/tenant identity, durable authenticated recipient ACK,
  privacy/retention/security approval.
- Нет разрешения на production deploy, merge, SQL019, migrations,
  UUID reuse/reissue/retry/delete, automated repair, delivery,
  archive or GC; `gcPermitted=false`.

**Результат:** `7x STATELESS-CLIENT-RESTART SIGNED REV2 VERIFIED`;
`7x OFFLINE PUBLIC-PKI + JOURNAL-AUDIT CI`;
`SERVER-VOLUME RESTART / REAL ROTATION PENDING OPERATOR APPROVAL`;
`INDEPENDENT OFF-HOST CUSTODY NOT VERIFIED`.

## 5. Stage 7y — перезапуск authority с томом РАЗРЕШЁН и выполнен 13.10.2026

**Эта секция заменяет исторический статус выше**: после явного разрешения
владельца перезапущен `saas-highwater-staging-only` in-place на
`cpa-gateway-sandbox/sandbox`. Это тот же deployment
`885ee1a7-8ffb-462b-ae0e-b47a260d5ff6`, без rebuild/redeploy,
смены signer, TLS или изменения конфигурации/журнала.

**Preflight:** оба сервиса `SUCCESS / Online`, staged changes 0;
private volume `synthetic-highwater-only`, id
`2a4cb9b4-0dcb-4206-8c94-cdae8d78d980`, 512 MB,
mount `/staging-highwater`; нет public domains или TCP proxies.
Предыдущий проверенный external signed minimum — `revision=2`
под operator-inspected Ed25519 SPKI SHA256
`5c55326f3c90215556c8bdac77ecc9c6d152cdf1e59253492a208f5e18a16411`.

**Новый authority startup log:** `2026-10-13T19:42:53.512Z`
повторный mount того же Railway volume path. В
`2026-10-13T19:42:56.094Z`: `READY: sandbox-only synthetic
high-water HTTPS/mTLS port 8443; head 2`.
Согласно исходному коду `store()` проверяет policy marker,
целостность и подписанную последовательность до `server.listen`.
Это доказательство восстановления retained signed head при реальном
**перезапуске процесса сервера** с persistent volume; не WORM или
cross-host DR.

**Отдельная внешняя проверка:** после authority restart in-place
перезапущен stateless `saas-highwater-private-smoke`,
deployment `d3e4ee3d-5d74-4fb1-a28d-c9fd04e33c2f`.
В **новых** логах `2026-10-13T19:43:29Z`:
- `PASS 7w: retained signed remote head authenticated, revision=2`;
- `PASS 7w: private-network HTTPS TLS1.3/mTLS head read with pinned server SPKI`;
- `PASS 7w: missing client certificate denied by actual remote authority`;
- `DIAG 7w: localEd25519=true, authoritySigBytes=64, cryptoVerifier=true, webVerifier=true, webStatus=completed`.

Ветка клиента при signed `revision===2` возвращается **до append**,
ничего не пишет в журнал. Оба сервиса остались `Online 1/1`,
без staged patch и ошибок.

**Точная граница:** `AUTHORITY PROCESS RESTART + RETAINED SIGNED REV2
REMOTE VERIFIED`. Не доказаны lost-ACK after fsync / exact nonce
replay, torn file/host crash, independent external retained minimum,
rollback защиты от общего администратора, backup/restore/partition,
WORM/HSM, CA revocation/rotation или PG COMMIT fencing.
Тестовые сертификаты истекают `2026-10-15 13:33 UTC`.
Production/issuer/repair/GC остаются `BLOCKED`;
`gcPermitted=false`.

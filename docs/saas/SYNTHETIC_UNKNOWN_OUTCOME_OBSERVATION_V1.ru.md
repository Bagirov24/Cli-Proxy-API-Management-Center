# Stage 2G.4d.7r — наблюдение UNKNOWN PostgreSQL COMMIT и signed IPC publication

**Статус:** staging-only, disposable GitHub Actions PostgreSQL 16; реализация **не** является recovery API, производственным settlement, независимым trust root или разрешением повторного выпуска. Отдельные 7q witness и high-water по-прежнему работают на **одном CI runner** с общим владельцем файлов и ключей. Никакого GC, архива и production.

## Задача и минимальное решение

7m имел offline proof для старых локальных реплик, 7o дал ограниченный подписанный источник UUID, 7p проверяет его внутри witness, а 7q добавил отдельную подпись локального high-water перед положительным IPC ACK. Но COMMIT может быть неизвестен вызывающей стороне: она теряет связь *до* COMMIT, *после* COMMIT, после witness fsync или после обеих fsync-публикаций. Из одной сетевой ошибки нельзя сделать вывод, что исходный UUID отсутствует либо безопасен для reissue.

7r добавляет **только read-only** `scripts/saas-staging/archive-witness-unknown-observer.mjs`. Процесс запускается в CI **без PostgreSQL credentials**, не вызывает SQL, не слушает порт, не отправляет запросы по сети, не меняет witness или journal и не записывает результат в БД. Он получает независимо закреплённые на этапе CI:
- **три отдельные публичные Ed25519 root**: restricted PostgreSQL projector, Unix witness и локальный high-water;
- свежий `challenge-pg` от witness (nonce + `expected`), подписанный результат `REPEATABLE READ READ ONLY` чтения обоих 015/016 UUID-реестров с фиксированным source DB и PG snapshot descriptor;
- текущий signed witness checkpoint, его непосредственный signed predecessor (либо null для genesis), отдельно подписанный high-water receipt и pinned latest head;
- untrusted *prepared* commitment `{protocol, kind, commitment, baselineHead}`, без исходного UUID, tenant/actor, секрета, payload, JWT, токена или credential.

Offline verifier строго проверяет размеры/формат/equality, каноничность commitment проекции, nonce и точное совпадение signed PG `expected` с **текущим** pinned head, PostgreSQL projector signature, witness Ed25519 signature/digest/sequence/predecessor, покрытие старого UUID-набора свежим PG source и отдельно подписанный high-water receipt с соответствующим witness fingerprint. Он не принимает caller-supplied PG UUID JSON вместо подписи, произвольный issuer role, неверный prepared predecessor и дополнительные свойства.

## Три наблюдательных статуса — все с обязательным DENY на действие

| Статус | Что доказано только локально | Что **НЕ** доказано |
| --- | --- | --- |
| `NOT_OBSERVED_IN_ONE_SNAPSHOT_UNKNOWN` | Подписанный UUID snapshot, текущий witness и journal согласуются; prepared commitment в этом snapshot не наблюдается | Отсутствие COMMIT в другом времени/реплике, безопасность новой выдачи UUID |
| `PG_SNAPSHOT_ONLY_UNWITNESSED` | Свежий подписанный PG snapshot видит **ровно один** подготовленный UUID commitment после текущего head, но witness и journal подписали лишь старый head | Что UUID был опубликован/доставлен, что можно автоматически чинить head или повторять операцию |
| `DUAL_LOCAL_SIGNED_IDENTITY_OBSERVED` | При прямом successor подготовленный UUID — ровно одно изменение, подписан witness и отдельно подписан local high-water, а свежий PG snapshot *точно* совпадает с projection | Независимый внешний settlement, actor authorization, durable recipient ACK, безопасность переиздания/отправки |

Для ВСЕХ успешных JSON-результатов фиксированы `authorizationGranted=false`, `reissuePermitted=false`, `retryPermitted=false`, `deliveryPermitted=false`, `gcPermitted=false`. Название статуса — исключительно **наблюдение идентичности**, не решение о маршрутизации/ретрае/GC. Неверные подписи, missing chain predecessor, неправильный nonce, подменённый journal, source rollback, unrelated или multiple UUID COMMIT, replay/candidate smuggling, неверный pinned head — процесс выходит с ошибкой `RECONCILIATION DENIED`, без положительного JSON.

Важно: подпись snapshot принадлежит доверенному **CI-процессу projector**, а не самому PostgreSQL/WAL. Свежесть nonce верифицируется относительно file-pin и challenge в этом запуске, а **глобальная долговечная anti-replay защита** вне runner НЕ реализована.

## Physical + adversarial GitHub Actions acceptance

Отдельный шаг ephemeral PG16 повторно использует ранее проверенную 7q harness с `SAAS_EPHEMERAL_UNKNOWN_OBSERVATION_CI=true` и **другими** синтетическими fixture UUID, не заменяя и не пропуская 7q и 7l–7p.

1. `psql` session делает INSERT, спит **до COMMIT**, после чего PostgreSQL backend физически прекращается. Независимый reader подтверждает rollback; signed source без UUID приводит к `NOT_OBSERVED_IN_ONE_SNAPSHOT_UNKNOWN`, а не к reissue.
2. Другая реальная `psql` session исполняет COMMIT **перед** `pg_sleep`, backend убит до окончания ответа. Независимый reader видит исходный UUID; свежий ограниченный PG source + старый signed witness/journal даёт `PG_SNAPSHOT_ONLY_UNWITNESSED`. Утрата journal доступности ничего не публикует.
3. После реального source-attested `append-pg` с двумя local fsync и **потери IPC ACK** исходный request ID возвращает тот же подписанный receipt после рестарта. Новая challenge-bound source attestation вместе с прямым signed successor и journal receipt даёт `DUAL_LOCAL_SIGNED_IDENTITY_OBSERVED`, но по-прежнему **нет** reissue/delivery/GC полномочий.
4. Adversarial: изменённый signed PG projection, wrong nonce, wrong projector/witness/journal pubkeys, forged pinned digest, journal receipt, source replay с другим head, отсутствие прямого predecessor, изменённый/чужой prepared commitment, лишнее поле, попытка дать offline verifier `PGHOST` — DENY.
5. Физические окна SIGKILL после witness fsync, но до journal advance, после journal checkpoint fsync, но до journal head, single-party rollback и replay старого head с сохранённым более новым trusted pin — DENY. Два физических **разных** COMMIT после одного signed head не могут быть представлены одним кандидатом.
6. До и после тестов нет новых 009/013 эффекта/receiver ACK от observer, нет сырого UUID, actor/tenant в JSON, `gc_permitted=false`.

## Открытые release gates

НЕТ independent off-host/WORM durable high-water, независимых операторов/key custody, настоящего PG WAL/LSN COMMIT certificate, atomic/fenced PostgreSQL→external witness transaction, способа безопасно reconcile реальный journal-orphan после crash, consensus/network partition/PITR/failover, долговечной anti-replay записи, production issuer tenant/actor authorization, внешнего authenticated recipient ACK, payload escrow или privacy-approved retention/GC. Даже статус `DUAL_LOCAL_SIGNED_IDENTITY_OBSERVED` **не разрешает** новый UUID или повторную доставку.

Никаких изменений migrations 008–018/019, production API, Railway, Core/Gateway/CPA/OAuth, реальных credentials, `/data`, `management.html`, proxy/VPN/egress или живого AI traffic. Никакого merge, force push, tombstone UPDATE/DELETE/TRUNCATE, UUID reuse, capacity reset, GC. **Всегда `gcPermitted=false`.**

**CODE VERIFIED:** commit `602398c83565f6705a136e6c4aaee5fecccd4599`, **4/4 SUCCESS**:
[Main CI #38388287338](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38388287338),
[Ephemeral PG16 #38388287221](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38388287221),
[Demo #38388287234](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38388287234),
[Chromium #38388287459](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38388287459).
В PG16 job log присутствуют отдельные 7r PASS для physical pre-/post-COMMIT disconnection, source-only vs dual-local observation, forged roots/replay, rollback, crash и multi-COMMIT. Исторические 7l–7q тесты также SUCCESS. Финальный documentation SHA требует отдельные 4/4 Actions.

# Stage 2G.4d.7q — локальный signed high-water fence для IPC witness

**Статус:** IMPLEMENTED staging-only / disposable PostgreSQL16 CI. Не независимый production witness, не WORM и не атомарный PostgreSQL settlement.

## Инкремент после 7p

В защищённом режиме 7p witness подписывает PostgreSQL-backed snapshot, но всю свою историю и pinned head хранит локально. Отдельный `archive-witness-highwater-ipc.mjs` в 7q выполняется **в другом Node-процессе на том же CI runner**, имеет свой test-only Ed25519 key и отдельный fsync-журнал, защищённый Unix-сокет, но **общего OS-оператора и диск**. Он принимает только `advance` с настоящей подписью доверенного witness, проверяет монотонную sequence, exact predecessor, отсутствие потерянных UUID commitments и ровно один новый commitment за successor. Его `status` и `advance` возвращают подписанную high-water квитанцию.

Witness отдельно закрепляет journal public-key fingerprint, а journal — witness public-key fingerprint. Привязка журнала допускается только к **пустому** witness без checkpoint, иначе DENY. Снижение режима на уже закреплённом witness, подмена ключа или журнала, несоответствие local head и signed high-water (в любую сторону) блокирует запуск и обработку `head`, `check`, `challenge-pg`, `append-pg`.

Каждый успешный protected `append-pg` проходит последовательность:

1. Реальный source proof 7o/7p проверен witness: server-issued nonce, expected predecessor, source DB, Ed25519 подпись и канонический digest.
2. Witness подписывает и fsync checkpoint, receipt и local head.
3. **До позитивного IPC ACK** он передаёт signed checkpoint другому локальному журналу, получает и проверяет **отдельно подписанный** exact high-water head.
4. При потере ACK **после двух fsync** идентичный request ID, predecessor и PG proof восстанавливают тот же signed receipt. Смена proof/replay нового ID/fork не порождает другую запись.

Действительно **нет** cross-process атомарной транзакции. Если witness fsync произошёл, а journal advance не был записан, при старте фиксируется divergence и процесс отказывает в любых новых свидетельствах; автоматического repair, нового UUID и GC **нет**. Если journal checkpoint fsync произошёл, а journal head не обновлён, journal обнаруживает orphan и отказывается стартовать. Оба случая требуют отдельного доверенного reconciliation-протокола (SPEC), а не бесконтрольного retry. Частичный откат любой стороны обнаруживается лишь пока вторая сторона и pinned ключи сохраняют более новый trusted head.

## Adversarial PostgreSQL16 CI

`verify-archive-witness-ipc-highwater.mjs` использует реальный COMMIT синтетических UUID в disposable PG16 и отдельный `REPEATABLE READ READ ONLY` projector с SELECT только `operation_id`. Проверяются: доступ к tenant/actor/secret DENY; первый signed genesis; journal down при committed UUID; потеря ACK после обеих фиксаций и replay без нового successor; rollback одного из двух локальных хранилищ; crash witness после local head, но до journal advance; crash journal после checkpoint fsync, но до публикации journal head; подмена pinned key и отключение journal; неизменность 009/013 audit/intent, отсутствие raw UUID в receipt, `gcPermitted=false`.

Проверка **совместного** отката обоих хранилищ показывает остающуюся уязвимость: клон witness и journal + потерянный caller trusted pin может выглядеть согласованно, хотя актуальный head новее. Не утверждается независимая внешняя защита от rollback.

## Открытые production gates

- Независимые хосты/операторы, durable/WORM high-water, внешнее время/монотонность, независимая key custody/rotation и долговечные nonce/pins.
- Fenced/atomic settlement PostgreSQL COMMIT ↔ внешний witness и исследованное восстановление UNKNOWN/partial acknowledgements, WAL/PITR/replica promotion/partition.
- Аутентифицированный tenant/actor/issuer и реальная OAuth/OIDC authorization/revocation.
- Durable payload transport, post-COMMIT dispatch, authenticated recipient ACK, production monitoring, security review и отдельное release approval.
- Доказательства безопасного non-reuse/архива/retention; `gcPermitted=false`, lifetime caps неизменны.

Никакой migration 019, изменения migrations 008–018, production API, Railway deploy, Core/Gateway/CPA/OAuth, `/data`, `management.html`, реального payload или UUID удаления/повторного использования.

**CODE VERIFIED:** `565b35f6d1fcdd6cc040c7f2bb423fd7dbbbf680`, **4/4 Actions SUCCESS** после исправления именного конфликта с 7l: исходная проверка 7l восстановлена без ослабления assertions, 7q проверяется **отдельно** как `verify-archive-witness-ipc-highwater.mjs`.

- [Main CI #38386162573](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38386162573) — SUCCESS.
- [Ephemeral PostgreSQL16 #38386162749](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38386162749) — SUCCESS, включая 7l, 7m, 7n, 7o, 7p и 7q.
- [Demo #38386162613](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38386162613) — SUCCESS.
- [Chromium #38386162486](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38386162486) — SUCCESS.

Первый 7q кодовый commit `e85146d4` не VERIFIED: прежнее имя теста 7l было занято новым скриптом, отчего прежний workflow шаг ошибочно провалился. Исправлено последовательным коммитом `565b35f6` с восстановлением старого файла. Финальный документационный SHA требует отдельной проверки 4/4.

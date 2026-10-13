# Stage 2G.4d.7v — реальный mTLS-транспорт для synthetic high-water (только CI)

**Область:** исполняемый HTTPS/TLS1.3 + mTLS прототип, а НЕ настоящая независимая off-host инфраструктура, не production issuer, не WORM, не готовый WAL/PG settlement. Все TLS и Ed25519 ключи, журнал и клиенты по-прежнему живут в одной disposable GitHub Actions машине. Режим жёстко ограничен `GITHUB_ACTIONS=true`, `SAAS_EPHEMERAL_EXTERNAL_TRANSPORT_CI=true`, `SAAS_EPHEMERAL_WITNESS_OFFLINE=true`, Unix/temp private paths, `127.0.0.1`; PG*/RAILWAY*/DATABASE_URL запрещены.

## Минимальный исполняемый протокол

`archive-witness-offhost-mtls-server.mjs` принимает сертификат CA, leaf-сертификат и TLS key сервера, pinned клиентский сертификат, authority Ed25519 signing key, отдельные pinned публичные witness/journal корни и policy `{protocol,audience,logId,epoch:1,authorityFingerprint,witnessFingerprint,journalFingerprint,clientFingerprint,serverFingerprint}`. TLS handshake требует валидную цепочку CA, сертификат клиента и точное совпадение SPKI fingerprint клиента; клиент в тесте также проверяет серверный SPKI. Не доверяем только CN/SAN или принадлежности сертификата общему CA.

**`POST /v1/append`:** строго `{protocol:'saas-synthetic-offhost-mtls-append-v1',nonce,expected,envelope,journalReceipt}`, без сырого operation UUID, actor, payload или прав выпуска. Witness envelope обязан иметь действительную Ed25519-подпись и монотонный predecessor; journal receipt — собственную Ed25519-подпись на **точно том же** head. Для продолжения нужен **полный ранее подписанный** receipt в `expected`; строго один новый UUID commitment без удаления старых. Stale expected, fork, повторный nonce с иной payload, неизвестные поля, неподписанный/подменённый journal и signer DENY.

**Хранилище:** приватный append-only `signed-append.jsonl`, строка `{protocol,request,receipt}` с полным подписанным `saas-synthetic-offhost-highwater-receipt-v1`. Файл fsync до положительного HTTP ACK; на старте весь ряд чекпоинтов, predecessor, signatures, nonce index и последовательность валидируются заново. Идентичный `nonce` + **та же** payload восстанавливает тот же receipt после потерянного ACK без дополнительного UUID; тот же nonce + другая payload DENY. Повреждённая/неполная последняя запись после SIGKILL = startup DENY, **без авто-truncate/repair**. Это single-process журнал, не распределённый consensus/fencing и не гарантия защиты от привилегированного локального оператора.

**`GET /v1/head`:** только под тем же mTLS; возвращает текущий signed receipt без authority/retry/reissue/delivery/repair/GC. Никаких других endpoint.

## Adversarial acceptance

Отдельный скрипт `verify-archive-witness-offhost-mtls.mjs` создаёт ephemeral CA/certs через OpenSSL, использует настоящий HTTPS/TLS1.3 между Node-процессами на loopback; проверяет CA chain **и** точный SPKI pin, неразрешённый client cert, отсутствие сертификата, неправильный server pin, forged witness/journal, чужой nonce, прежний expected, конкурирующих publishers. После fsync насильно убивает signer до ACK, перезапускает процесс и сравнивает исходный receipt бит-в-бит. Также проверяет tampered log, wrong authority private key, частичную запись/split и отказ на startup без самовосстановления. CI старых 7l–7u сохранён.

## Открытые production gates

1. Настоящий другой хост/оператор и независимые TLS/key custody, HSM/KMS, immutability/WORM, monotonic nonce/revision, anti-equivocation, аудит и **за пределами runner** сохранённый minimum head.
2. Authenticated transport в отдельных сетях, CA rotation/revocation, failover/partition/quorum, реальная disaster recovery/backup и fenced leadership — loopback тесты этого НЕ доказывают.
3. PostgreSQL WAL/LSN commit evidence, atomic/fenced PG→external high-water settlement, PITR/replica promotion/UNKNOWN, независимая actor/issuer authorization и durable signed recipient ACK.
4. Privacy/retention/security/legal approval; никакой producer retry/UUID reuse/delete, tombstone GC, archive, migration 019, production deployment или изменение существующего Core/Gateway/CPA/OAuth.

**CODE VERIFIED:** `994610224dc655264a7603e3a88db6c77cacad19`, **4/4 GitHub Actions SUCCESS**:
[Main CI #38399841822](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38399841822),
[Ephemeral PG16 #38399841833](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38399841833),
[Demo #38399842133](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38399842133),
[Chromium #38399841981](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38399841981).
PG16 job log сообщает 4 отдельных `PASS 7v` (mTLS/client pin, fsync/SIGKILL/replay, конкурирующие publishers, torn/tampered журнал) и explicit `LIMITATION 7v`. Исторические 7l–7u проверки сохранены.

**FINAL DOCS SHA требует отдельные 4/4 Actions SUCCESS.** `gcPermitted=false` всегда; PR OPEN/DRAFT/NOT MERGED.

# Stage 2G.4d.7t — контракт независимого off-host high-water (SPEC) и проверка wire-format (CI)

**Итог по границам:** описан будущий действительно независимый off-host witness/anchor service. **В этом коммите внешняя служба НЕ создана и НЕ подключена**. Реализована только offline проверка подписанного формата receipts и adversarial acceptance с **синтетическим signing fixture на ТОМ ЖЕ disposable CI runner**. Поэтому это `IMPLEMENTED CONTRACT CONFORMANCE / SPEC REMOTE TRUST`, но не deployment, внешняя durability, двухфакторный оператор или production settlement. Последовательные шаги 7o–7s сохраняются.

## 1. Зачем нужен другой trust domain

7p проверяет подписанную PostgreSQL projection внутри локального witness; 7q добавляет отдельный процесс high-water, но обе истории лежат на одном runner. 7r читает evidence после неизвестного COMMIT, не выдавая разрешений. 7s добавляет третий reviewer-pin, но **сценарий совместного отката** reviewer pin + witness + journal доказывает, что новый ключ внутри того же OS не даёт внешней защитной границы.

Реальное следующее решение должно иметь: иной администратор/учётную запись/поставщика, отдельную криптографическую key custody, независимо сохраняемый и неоткатываемый high-water, доказательство append-only monotonicity, контроль разделения полномочий и физически независимый канал контроля. **Ни одна из этих гарантий не следует из Ed25519 подписи в CI**.

## 2. Роли и независимые root of trust — будущее production REQUIREMENT, сейчас SPEC

| Роль | Данные и власть | Доверие |
| --- | --- | --- |
| PostgreSQL issuer | фиксирует UUID операции на COMMIT; состояние может быть UNKNOWN для caller | Никакой COMMIT ≠ внешний ACK |
| Read-only PG projector (7o) | подписывает только commitment set и PG snapshot в challenge-bound attestation | Не authentic WAL/LSN commit certificate |
| Signed IPC witness (7p) | удостоверяет append/sequence/previous/digest одного UUID commitment | Не имеет прав SQL/PG |
| Signed local journal (7q) | подтверждает head witness после локального fsync | Тот же runner и системный оператор |
| Manual reviewer (7s) | читает evidence и сохраняет отдельный подписанный pin | Пока только локальный CI |
| **Внешняя authority (7t SPEC)** | в собственном trust domain выполняет authenticated compare-and-append; **после** durable append выпускает подписанный head receipt | Требует независимой key custody, WORM/immutable append storage, external monotonic counter, independently retained client minimum и операторской верификации; **НЕ реализована** |

### Out-of-band bootstrap, MUST

До любого append клиент и независимый оператор согласуют **неизменяемую policy** с `logId`, `epoch`, `authorityFingerprint`, `witnessFingerprint`, `journalFingerprint`, закреплёнными **вне** локального witness и PostgreSQL. Клиент сохраняет подписанный **minimum external receipt**, который автор локальной истории не может перезаписать. Ротация ключа/epoch требует отдельной взаимно подтверждённой операторской процедуры и chain-of-custody. Реплика, копия runner и PR docs не являются внешним pin.

### Authenticated compare-and-append, MUST для реальной внешней службы

1. Клиент передаёт `logId`, `epoch`, ожидаемый signed external receipt и свежий nonce/request ID, а также **оба** подписанных свидетельства локального witness+high-water, их public root и предшественника. Настоящая удалённая сторона должна проверять полномочия caller/mTLS/OIDC service identity **в собственном** trust domain. CI **этого не тестирует**.
2. Удалённая сторона атомарно сравнивает `expectedRevision`, `expectedDigest` с собственным durable last head. При stale expected, повторном nonce с другой payload, fork, gap, incongruent journal/witness, дубле UUID, неверной подписи или недоступном storage — **DENY / UNKNOWN**. Новый append может содержать лишь **один** новый hashed UUID commitment при сохранении предыдущего множества, кроме genesis.
3. **Только после** независимой durable записи неизменяемого receipt и монотонного counter внешняя authority подписывает receipt. Crash/partition до подтверждённого durably written receipt не должен давать оператору основание выдать или повторить UUID. Оператор хранит revision counter/nonce/idempotency mapping и append log так, чтобы восстановление/сбой не допускали отката.
4. Консумент проверяет external receipt, цепочку predecessor и собственный **independently retained minimum**; отвечает лишь `MANUAL_REVIEW_REQUIRED`. Даже получение корректного remote ACK само по себе не подтверждает PostgreSQL issuer actor, весь WAL/PITR/replica promotion, доставку получателю или возможность GC. Передача producer разрешений требует отдельного fenced/atomic settlement протокола и security sign-off.

## 3. Предлагаемый wire-format, покрытый 7t CI

Версии имён:
- `saas-synthetic-offhost-policy-v1` / audience `disposable-ci-offhost-conformance-only`;
- `saas-synthetic-offhost-nonce-challenge-v1` (fresh client nonce из 16 случайных байт в hex);
- `saas-synthetic-offhost-highwater-receipt-v1`;
- `saas-synthetic-offhost-inspection-bundle-v1`.

**Pinned policy** (в реальной версии хранится out of band): `{protocol,audience,logId,epoch,authorityFingerprint,witnessFingerprint,journalFingerprint}`, где `epoch=1` в фиксированной CI proof-version и root fingerprints вычислены как SHA-256 DER/SPKI.

**Signer record**: `{data,signature}` с Ed25519 domain separation `receiptProtocol + "\\n" + JSON.stringify(data)`. Точное `data`:

```json
{
  "protocol": "saas-synthetic-offhost-highwater-receipt-v1",
  "audience": "disposable-ci-offhost-conformance-only",
  "logId": "<32 hex>",
  "epoch": 1,
  "revision": 2,
  "head": {"sequence": 2, "digest": "<64 hex>"},
  "previousReceiptDigest": "<64 hex SHA256(JSON signed previous receipt)>",
  "witnessFingerprint": "<64 hex>",
  "journalFingerprint": "<64 hex>",
  "journalReceiptDigest": "<64 hex SHA256(JSON signed local journal receipt)>",
  "challengeNonce": "<32 hex>"
}
```

Genesis: `revision=sequence=1`, `previousReceiptDigest=null`, witness `previous=null`. Последовательный append: `revision` ровно +1, head содержит единственный новый UUID commitment, `previousReceiptDigest` ссылается на **полный подписанный** предыдущий receipt, а текущий witness `previous` соответствует хешу предыдущего подписанного envelope. External receipt подписывает `journalReceiptDigest` и pin signer keys; несоответствие между внешним, локальным witness и journal **не замалчивается**.

В CI `archive-witness-offhost-contract-verify.mjs` получает три явно закреплённых публичных ключа, policy, свежий challenge, внешний evidence bundle, отдельно **retained** minimum receipt и аргументы `--strict-review --no-gc`. Он:
- валидирует точную структуру, аудиторию, `logId`, `epoch`, Ed25519 подпись, nonce, signer fingerprints;
- проверяет Genesis/direct signed predecessor с отсутствием gap/fork, SHA256 связность, `verifyCheckpoint`, сохранение UUID sets и один добавленный commitment;
- сверяет signed external receipt с witness envelope и journal receipt, а также отдельно retained minimum (тот же counter/digest или предыдущий подписанный root для одного нового шага);
- независимо проверяет подписи локальных witness/journal, сравнивает их heads с внешним;
- при неверном key/epoch/nonce, забытом predecessor, подмене journal receipt, rollback ниже сохранённого minimum, same-revision equivocation, незакреплённой policy и утраченных доказательствах возвращает `OFFHOST CONTRACT DENIED`, без positive JSON.

**Лимит конформанс-кода:** для простоты CI требует `revision === witness sequence`, один прямой predecessor и `epoch=1`; переход epoch, длинный offline catch-up с цепочкой Merkle/consistency proof, quorum/WORM, приватный nonce-ledger, remote auth/TTL и реальная network delivery остаются **неподдержанными**.

## 4. Только ручные observation statuses

| Статус | Узкая интерпретация |
| --- | --- |
| `SIGNED_EXTERNAL_CONTRACT_MATCH_REVIEW_ONLY` | Подписанные внешние и локальные head/receipt согласуются с retained minimum, **но это всё ещё симуляция** |
| `LOCALS_BEHIND_PRESERVED_EXTERNAL_HEAD_REVIEW` | Локальные witness и journal согласованно **позади** retained внешнего receipt — возможен совместный rollback |
| `EXTERNAL_HIGHWATER_LAG_REVIEW` | Локальные подписанные heads ушли дальше externally signed receipt — нет внешнего подтверждения |
| `LOCAL_SIGNED_SPLIT_MANUAL_REVIEW` | Локальные witness и journal разошлись |
| `SIGNED_FORK_CONFLICT_MANUAL_REVIEW` | С тем же счётчиком подписаны конфликтующие head digests |

ВСЕ успешные ответы: `manualReviewRequired=true`, `signedWireContractVerified=true`, но `actualOffHostCustodyVerified=false`, `independentDurabilityVerified=false`, `authenticSourceCommitVerified=false`, `automaticRecoveryPermitted=false`, `authorizationGranted=false`, `retryPermitted=false`, `reissuePermitted=false`, `deliveryPermitted=false`, `repairPermitted=false`, `gcPermitted=false`. Ни один статус не является endpoint или правом перейти в production.

## 5. Adversarial CI matrix

Новый отдельный `7t` step запускает реальные PG16 physical pre/post COMMIT disconnect, signer 7o, witness 7p, local journal 7q, observer 7r, reviewer 7s, используя новые synthetic fixture UUID; он **не заменяет** предыдущие шаги. Дополнительно:
- подписанные synthetic external genesis → один прямой signed successor после lost ACK; обязательная проверка source/journal/witness/receipt continuity и non-authorizing result;
- чужой authority/journal/witness key, неправильный `epoch`/`logId`, nonce replay, forged digest, отсутствующий predecessor/receipt, дополнительные поля, swap public roots, PG credentials в offline verifier → DENY;
- signed старый receipt при новом retained minimum → DENY; signed same-revision альтернативный receipt, выпущенный malicious mock с правильным key, но не равный retained root → DENY (объективно требует отдельно сохранённого внешнего minimum);
- совместный rollback двух локальных историй с **сохранённым** более новым synthetic external receipt обнаруживается; если также откатить retained minimum, криптографическое self-consistency всё ещё может выглядеть легитимным — **критический production blocker**;
- при witness crash после fsync но до journal advance, либо journal crash перед head publication, local split классифицируется как ручной инцидент; без автоматического изменения записей;
- локальный successor впереди external receipt остаётся `EXTERNAL_HIGHWATER_LAG_REVIEW`, а не новыми правами issuer/delivery.

## 6. Production readiness: строго открытые gates

1. Действительно независимый off-host operator, аккаунт, HSM/kms key custody, locked immutable/WORM log, защищённая монотонность/nonce ledger, audit/gossip против signed equivocation. CI *не доказал* ни одного.
2. Настоящая authenticated transport identity, mTLS/OIDC, durable signed log query, независимо закреплённый и доступный client minimum даже после PITR/restore, проверяемая ротация root/epoch, independent backup and disaster drills.
3. PostgreSQL COMMIT identity / WAL/LSN fencing, разрешение UNKNOWN/partial writes, replica promotion/PITR/net partitions без UUID reuse/ghost commits, независимо одобренные runbooks для orphan journal и человеческого инцидента.
4. Production issuer-scoped tenant/actor auth, producer replay prevention, durable outbound signed recipient ACK и отдельное risk/security/legal/privacy/retention release approval.

**Никакого изменения SQL migrations 008–018/019, Railway, Core/Gateway/CPA/OAuth, management.html, /data, реальных secrets, producer endpoint, внешней доставки, UUID deletion/reissue, archive или GC; `gcPermitted=false`. Draft PR не merge.**

**CODE VERIFIED:** `264df12e6717d24bec7f5695c0a323411556aca6`, **4/4 SUCCESS**:
[Main CI #38394337819](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38394337819),
[Ephemeral PG16 #38394337902](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38394337902),
[Demo #38394337739](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38394337739),
[Chromium #38394337879](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center/actions/runs/38394337879).
Main CI: 1 829 tests PASS, 0 FAIL. PG16 содержит отдельные PASS для external genesis, signed successor после lost ACK, root/nonce/epoch/log/fork/replay DENY, сохранённого minimum при совместном rollback, локального split и journal orphan; log содержит explicit LIMITATION, что external signer смоделирован в одном runner.

**Final documentation SHA:** требует отдельного 4/4 SUCCESS. Только после этого статус `7t WIRE CONFORMANCE VERIFIED`, никогда `PRODUCTION OFFHOST VERIFIED`.

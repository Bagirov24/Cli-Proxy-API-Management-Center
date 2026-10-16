# M1o — явные монотонные эпохи HTTPS CA/SPKI для синтетического IdP

**CI-ONLY / STACKED DRAFT / NOT PRODUCTION.** Родитель — Draft PR #17 (M1n), проверенный исходный HEAD f6f366214b8091b22bba087516033d76d7ec7d4c.

## Узкая security boundary

Новый CI-only m1o-explicit-trust-rotation.mjs хранит единственную активную CA/SPKI policy, version=1, затем требует явную CAS expectedRevision и ровно следующий номер. Нет silent fallback, одновременного доверия двум pins, rollback к уже использованной CA/SPKI паре, принятия старого transport handle или ротации во время in-flight HTTPS-запроса. Старый transport отказывает **до сетевого соединения**. Реальная проверка M1n CA chain, SAN localhost и leaf SPKI перед отправкой OAuth HTTP bytes остаётся обязательной.

## Проверки

- Opt-in tests/saasM1oExplicitTrustRotation.test.mjs: настоящий HTTPS с новым leaf той же CA, запрет старого pin до HTTP, явное обновление CAS, stale writer, skipped revision, duplicate, retired pin, wrong CA, wrong SAN, invalid CA, in-flight race, default-off.
- Девятый отдельный GitHub PG16 запуск после неизменённого M1n: HTTPS mock меняет leaf только после успешного явного CA/SPKI epoch=2; PKCE/state, pinned JWT и подписанный M1k/M1d/M1c/M1g путь создают ровно 3 проекта / 3 аудита / 3 UUID binding. Отозванные сессии A/C дают 0 ghost-строк, B остаётся активной; signer 503 не резервирует новую PG транзакцию.
- Независимый SQL tests/sql/saas_m1o_explicit_https_trust_epoch_pg_e2e.test.sql проверяет сохранённые строки, session proofs, least privilege/FORCE RLS/triggers и безопасный SQL025 replay.
- Требуются отдельные PASS M1o из E2E и SQL плюс четыре GitHub Actions SUCCESS на точном финальном SHA.

## НЕ доказано

Ephemeral in-memory policy НЕ является governance-signed управлением trust anchors, durable rollback protection или реальным IdP PKI lifecycle. После перезапуска история retired pins теряется. Нет browser cookie/callback, refresh, real logout, remote WORM/HSM, committed outcome settlement DURING COMMIT network partition, production actor directory, CPA integration или права на merge.

## Railway TLS — отдельный операторский hard stop

Срок 2026-10-15 13:33 UTC. Read-only Railway подтверждает SUCCESS no-listener startCommand, отсутствие public domains/TCP proxy, сохранённый volume synthetic-highwater-only. Независимого отрицательного TCP 8443 доказательства нет. Ни M1o, ни CI CA/leaf не ротируют Railway. Для изменения состояния Railway необходимо отдельное явное решение оператора.

Запрещены merge/Ready, SQL019/production PostgreSQL, Railway service/volume/signer/journal/key writes, credentials issuance/reissue, UNKNOWN COMMIT retry, archive/GC. authorizationGranted=false; gcPermitted=false.

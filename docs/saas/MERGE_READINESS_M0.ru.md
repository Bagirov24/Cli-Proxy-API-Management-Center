# Stage M0 — checklist безопасного merge Draft PR №3 (без выпуска SaaS)

> **Статус: REVIEW REQUIRED / NO MERGE AUTHORIZATION.**
> PR №3 объединяет архитектуру, синтетические contracts/fixtures,
> opt-in UI и изолированные CI-пилоты. Merge в `custom-no-apikey-fun`
> допускается только после отдельного одобрения владельца ветки и
> security review, без production deploy и включения реальной выдачи.

## 1. Что войдёт в ограниченный M0 merge

- Спецификации tenant/project/application/account/pool/egress/grant,
  безопасный synthetic policy resolver и UI demo.
- Изолированный `/saas-demo-preview` (только локальный DEV),
  opt-in `/saas-demo` под существующей авторизацией (в development
  или синтетической PR build). Настоящей tenant authorization/Core
  integration это **не** добавляет.
- Контракты read-only Control API, RBAC/RLS SQL, подписанного SQL
  scope, synthetic publisher/commit lifecycle, high-water receipt.
  Их исполняемые пилоты — на временном GitHub PostgreSQL16 или
  отдельном синтетическом Railway sandbox, а НЕ в production.
- Тесты и runbooks. **Ни новых внешних API endpoints,
  ни автоматической выдачи, reissue/retry/repair/delivery/GC.**

## 2. Fail-closed build isolation (реализовано в M0)

**Риск до hardening:** одной переменной
`VITE_ENABLE_SAAS_BLUEPRINT_DEMO=true` было достаточно,
чтобы сборка включила synthetic demo route и fixtures даже при
ошибочной установке переменной в выпускном build job.

**Новый guard в `vite.config.ts`:**
1. `VITE_ENABLE_SAAS_BLUEPRINT_DEMO` отсутствует —
   собирается обычная UI-сборка с
   `SaasDemoRouteDisabled.tsx`; synthetic fixture marker
   `saas-demo-tenant` в `dist/index.html` **отсутствует**.
2. `VITE_ENABLE_SAAS_BLUEPRINT_DEMO=true` +
   `vite serve` в `development` —
   разрешён локальный dev preview. Это не protection against a
   user intentionally exposing their development server to a network.
3. `VITE_ENABLE_SAAS_BLUEPRINT_DEMO=true` +
   `vite build` —
   обычная сборка **останавливается ошибкой**
   `SAAS BLUEPRINT DEMO DENIED`.
4. Единственный допустимый опциональный bundle для review —
   **синтетический pull_request CI**:
   `GITHUB_ACTIONS=true`,
   `GITHUB_EVENT_NAME=pull_request`,
   `SAAS_BLUEPRINT_SYNTHETIC_CI_BUILD=true`,
   `VITE_ENABLE_SAAS_BLUEPRINT_DEMO=true`.
   Его build job не публикует и не развёртывает artifact,
   не имеет Railway/Core/PG credentials.
5. `.github/workflows/saas-blueprint-demo-ci.yml`
   действительно выполняет **три** check:
   expected DENY для обычной release build с ошибочным opt-in;
   default-off artifact без synthetic fixture marker;
   isolated PR preview с marker (положительный контроль).
   `tests/saasBlueprintDemo.test.ts` закрепляет guard.

**Важно:** переменные окружения процесса build — не
криптографические аттестации. Guard уменьшает риск случайной
публикации, но не заменяет GitHub protected environments,
approval, signed provenance, review и запрет публикации
CI preview artifact. Не разрешать выпуск SaaS demo в production.

## 3. Обязательные критерии перед изменением Draft → Ready

- [x] **Кодовая изоляция:** build fail-closed при ошибочном
  opt-in; demo route/fixture отключён в default bundle.
- [x] **Тестовый контур:** CI-only PostgreSQL16 RLS/issuer
  contracts и отдельный private Railway high-water mTLS,
  без production credentials / DB / issuer.
- [x] **Удалённая проверка восстановления:** Stage 7y,
  restart volume-owning authority + signed revision 2
  reauthenticated new mTLS smoke process. Это НЕ WORM/DR.
- [ ] **CODE OWNER REVIEW:** вручную просмотреть целиком diff
  большого PR: любые изменения production UI, Vite alias,
  workflows, SQL, scripts и изменения в общем роутинге;
  выдать approve или блокирующие замечания.
- [ ] **SECURITY REVIEW:** threat model для будущего
  authentication/issuer/tenant fencing, секретов, SSRF/DNS,
  signed journal, audit и supply chain; проверить отсутствие
  скрытых production hooks.
- [ ] **RELEASE PIPELINE CHECK:** убедиться, что normal
  `custom-no-apikey-fun` build не задаёт запрещённый
  `VITE_ENABLE_SAAS_BLUEPRINT_DEMO`, и что никакой
  preview bundle не копируется в production `management.html`.
- [ ] **FINAL CI:** 4/4 проверок SUCCESS **на финальном SHA**
  после всех замечаний; Main CI Bun tests/TS/ESLint/Vite,
  PG16 ephemeral, synthetic Browser QA, Demo Build.
- [ ] **EXPLICIT MERGE APPROVAL:** owner выбирает точный SHA,
  сужает scope/разделяет PR при необходимости, снимает Draft
  и разрешает merge. `mergeable=true` означает отсутствие
  текущего технического конфликта, а НЕ security approval.

## 4. Не включать в M0 merge, реализовать отдельными PR

1. **M1 Identity and Control Plane:** live OIDC/SSO,
   server-side sessions/revocation, membership/RBAC,
   tenant-scoped resource CRUD, admin UI.
2. **M2 Data Plane:** production-grade PostgreSQL
   migrations, RLS, verified pool quarantine/reset/cancel,
   Core metadata read adapter, tenant-safe routing on every
   request after scheduler, proper CPA key semantics.
3. **M3 Secrets/Network:** BYOK/BYOA Vault/KMS,
   provider capability validation, HTTP/SOCKS5/VPN
   egress with DNS/SSRF/firewall/least privilege.
4. **M4 Durable settlement:** genuine *independent* operator
   / signer + HSM/WORM retained high-water, fenced PG COMMIT,
   issuer actor authorization, manual orphan reconciliation,
   recipient delivery ACK, restore/failover/partition drills.
5. **M5 Operations:** audit trail/observability, billing
   and quotas, retention/security/legal sign-off, deployment
   monitoring, backup/rollback and staged rollout.

**Urgent staging maintenance:** синтетические TLS certificates
истекают **2026-10-15 13:33 UTC**; сохранить старый signed volume
и рут, согласовать изолированный новый logId/keys/volume либо
деактивировать старый sandbox. Не менять policy marker in-place.

## 5. Что запрещено даже после ограниченного merge

Никаких production migrations (включая SQL019), PG/IAM/issuer,
автоматической выдачи или повторного использования UUID,
retry/reissue/repair, внешней доставки, архивирования/GC,
merge без отдельного согласования, force-push или
сброса подписанного volume/high-water.
`gcPermitted=false`; `authorizationGranted=false`.
См. [production gates](PRODUCTION_READINESS_GATES_V1.ru.md),
[Stage 7x/7y PKI/DR](RAILWAY_HIGHWATER_AUDIT_7X.ru.md) и
[Railway 2FA](RAILWAY_2FA_OPERATOR_RUNBOOK.ru.md).

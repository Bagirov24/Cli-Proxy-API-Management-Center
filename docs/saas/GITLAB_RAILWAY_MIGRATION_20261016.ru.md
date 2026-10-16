# GitLab.com → Railway: миграция без собственного сервера

**Дата:** 16 октября 2026 · **Статус:** GitLab.com аккаунт подключён и подтверждён; GitHub оригинал сохранён; реальный импорт GitLab и PostgreSQL16 CI ещё не завершены. Никакого production deploy.

## Проверенные доступы и исходники

- GitLab OAuth-connected account: `Bagirov24`, active, user can_create_project=true. GitLab connector поддерживает файлы/ветки/MR/pipelines уже существующего проекта, **не предлагает create project/import GitHub**. Нельзя утверждать, что перенос сделан, пока GitLab Project ID и Git SHA не проверены после импорта.
- GitHub `Bagirov24/Cli-Proxy-API-Management-Center`: доступ admin/push, default `main`, public. Последний подтверждённый существующий **Draft PR #27**: `feature/saas-durable-identity-session-pg16-20261015`, SHA `1658f5932c8bdaf5d91494b82601f709eddda78a`, open/not merged, base Draft #26.
- Migration bootstrap branch: `feature/gitlab-com-railway-migration-bootstrap-20261016` создан исключительно из head #27; **.gitlab-ci.yml** готов для GitLab-hosted runners, но ещё не проходил GitLab lint/CI; parent PR27 GitHub Actions не работал.
- Railway `cliproxyapi-personal` и `cpa-gateway-sandbox` доступны. Production `cliproxyapi-core` и `api-gateway` по-прежнему остаются на **GitHub** ветках `custom-no-apikey-fun` и `api-gateway`. Не менять source/mounts/`/data` при импорте.

## Одно действие владельца GitLab (через UI)

1. Войдите в [GitLab.com](https://gitlab.com/) под `Bagirov24`. Откройте [официальный импорт из GitHub](https://docs.gitlab.com/user/project/import/github/): **Create new → New project/repository → Import project → GitHub → Authorize with GitHub**. Авторизация через GitHub OAuth предпочтительнее ручного PAT. Не присылайте токены, пароли или cookies в чат.
2. Выберите **только** `Bagirov24/Cli-Proxy-API-Management-Center`. Namespace `Bagirov24`. Для совместимости с bootstrap CI оставьте ровно **`Cli-Proxy-API-Management-Center`** в названии/slug. Не жмите Import all.
3. Сохраните историю Git, все  branches/tags, pull requests→merge requests, issues, события/комментарии. Дополнительные Markdown attachments — по необходимости; не импортируйте автоматически лишних collaborators/permissions без ревью, чтобы не раздать лишний доступ и не создать неожиданные платные места.
4. В интерфейсе дождитесь `Complete`. При `Partially completed` проверьте список errors. GitLab может не перенести все approvals/branch-protection/status checks в точности; **проверка импортированной безопасности обязательна**.
5. После появления проекта проверьте его адрес: `https://gitlab.com/Bagirov24/Cli-Proxy-API-Management-Center`. Сообщите только эту ссылку (без секретов) — подключённый GitLab-коннектор затем сможет прочитать project ID, ветки, MR и pipelines. Если фактический slug отличается, обновить `CI_PROJECT_PATH` в bootstrap YAML перед запуском.

## После импорта — проверки, которые выполним через GitLab

1. Сопоставить коммиты GitLab/GitHub: точный HEAD у PR #27 `1658f5932c8bdaf5d91494b82601f709eddda78a`; bootstrap HEAD и его отдельные коммиты; все предыдущие ветки PR #21–26, контроль `main`, `custom-no-apikey-fun`, `api-gateway`, tags, MRs. Сохранять `main` и исходные branch protections, по умолчанию прямые push/force push в protected ветки запрещать.
2. Открыть **Draft GitLab MR** из `feature/gitlab-com-railway-migration-bootstrap-20261016` в `feature/saas-durable-identity-session-pg16-20261015` (не в `main`), без squash или auto-merge. GitLab-hosted runners доступны без VPS; расходуется quota compute minutes аккаунта.
3. `.gitlab-ci.yml` на bootstrap-ветке запускает **Main verify** (`bun run verify`), **read-only Release guard**, **default-off Demo Build**, **Chromium/WCAG synthetic local browser** и **SQL026 source unit tests**. Команды не содержат Railway deploy или GitHub Release публикации; synthetic demo default-off.
4. **ВНИМАНИЕ — GitLab pipeline намеренно BLOCKED:** `pg16_required_port` — blocking manual `allow_failure:false`, нажатие пока приводит к отказу. Это не фиктивный PASS, а сигнал, что длинный GitHub-only PostgreSQL16 acceptance в 1371 строк нельзя запускать через поддельное `GITHUB_ACTIONS=true`. Нужно адаптировать все встроенные CI-only guards под настоящий `GITLAB_CI=true` и изолированный Postgres16 на `127.0.0.1`/`saas_ephemeral_test`, не снимая ограничения production, и **запустить все SQL001–026 plus backend04 E2E** на одном SHA. Только затем заменить блокирующую заглушку полноценной job.
5. В GitLab **Settings → Merge requests** включить *Pipelines must succeed* и отключить авто-merge незавершённых Draft. Защитить production/staging branches, настроить codeowner approval и secrets masking. Возможно потребуются платные возможности GitLab для некоторых approval rules; не считать их активными без проверки.
6. Перенос завершён только после независимых 5/5 jobs включая **реальный** ephemeral PostgreSQL16 CI на одном final GitLab SHA, security/codeowner/ops review, ручного release freeze и подтверждённых backups/rollback.

## Railway — безопасная интеграция GitLab CI, не сейчас

Railway `connect_service_source` умеет подключать **GitHub** или Docker image, но не прямой GitLab Git source. Возможные пути: **GitLab Container Registry** + Railway image source (для приватного registry оператор отдельно настраивает credentials) или **GitLab CI → Railway CLI** с окружение-ограниченным Railway Project Token. Документация: [Railway CLI deployments](https://docs.railway.com/cli/deploying), [private container registry](https://docs.railway.com/guides/private-container-registry).

Когда SaaS staging разработан и защищён, создайте ОТДЕЛЬНЫЕ staging-only Railway project/environment/service и PostgreSQL16. Установите scoped, protected+masked+hidden `RAILWAY_TOKEN` **только в staging deployment environment**, не в общие CI jobs и никогда на MR из forks. Публикация staging `railway up --project <staging-project-id> --environment <staging-env> --service <private-saas-service> --ci` выполняется **manual/protected после зелёного CI**, без доступа к production Core, Gateway, mounts и секретам. Уточнить синтаксис и permissions Project Token перед установкой.

Отдельно не закрыты: настоящий одобренный IdP issuer/audience/JWKS, PostgreSQL physical quarantine, cross-replica revocation, off-host WORM и UNKNOWN COMMIT reconciliation, production migrations (staging SQL001..026 НЕ утверждены как production), standalone private tenant backend mount, pen-test/restore/DR. Старый sandbox synthetic TLS expiry **2026-10-15 13:33 UTC** уже в прошлом; единственный ECONNREFUSED probe от 14 октября подтверждает конкретный момент, не итог ротации/удаления сертификата.

**Никакой прямой push/merge в `custom-no-apikey-fun`/Railway Core, GitHub Release write, SQL019, live OAuth/CPA keys, auto-reissue/retry/GC.**

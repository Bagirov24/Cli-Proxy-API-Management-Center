# Railway 2FA/MFA для оператора SaaS staging — подробная инструкция (Windows, 2026-10-13)

> **Область действия:** аккаунт Railway и ручное подтверждение изменений
> только в проекте `cpa-gateway-sandbox`, окружение `sandbox`.
> Эта инструкция НЕ разрешает production, новый issuer, доступ к PG,
> замену key material, восстановление/очистку signed journal,
> повторную выдачу UUID, автоматические retry/repair/delivery или GC.
> `gcPermitted=false`. Никакого обхода подтверждений через CLI/API.

## 0. Три разных механизма — не путать

| Механизм | Для чего | Где находится |
| --- | --- | --- |
| **2FA/MFA Railway-аккаунта** | Защитить вход в аккаунт и подтверждать чувствительные операции | [Account Security Settings](https://railway.com/account/security) |
| **Ручное применение `Staged Changes`** | Проверить diff и применить конкретное изменение через Dashboard; при запросе Railway выполнить 2FA | [Railway sandbox](https://railway.com/project/dba33407-7200-40e0-a9c8-08c43d41e5e4) → `sandbox` → баннер изменений |
| **TLS 1.3/mTLS сервисов** | Сервер и автоматический тестовый клиент проверяют сертификаты друг друга | Только внутренний staging-транспорт `saas-highwater-*` |

**SSH passphrase** (например, при запросе `Enter passphrase for key ...\.ssh\railway_electerm`)
защищает локальный SSH-ключ. Она **не является** одноразовым кодом Railway 2FA.
`GitHub 2FA`, `Railway 2FA` и `mTLS` — разные контуры авторизации.

**Как понять, нужна ли операция сейчас:** на 13 октября 2026 года оба
`saas-highwater-staging-only` и `saas-highwater-private-smoke` показывали
`SUCCESS`, ожидающих изменений `0`. В этом состоянии нечего нажимать
`Deploy/Apply`. Не создавайте фиктивный patch ради проверки 2FA.

## 1. Включить 2FA для личного Railway-аккаунта (Authenticator App / TOTP)

Это самостоятельная настройка **аккаунта**, а не сервиса; её выполняет
только владелец в своём браузере, не агент и не Railway MCP.

1. Откройте **https://railway.com/account/security** в браузере и
   убедитесь, что домен точно `railway.com` и установлено HTTPS.
   При необходимости войдите в свой аккаунт Railway.
2. Найдите раздел с двухфакторной аутентификацией. Если показана кнопка
   **Set up two-factor authentication**, нажмите её.
   Если 2FA уже включена и доступны операции управления/восстановления,
   не настраивайте новый метод без необходимости.
3. На телефоне откройте надёжное приложение-аутентификатор:
   например **Google Authenticator**, **Authy** или **1Password**.
   Выберите добавление нового аккаунта или сканирование QR-кода.
4. Отсканируйте QR **непосредственно на экране Railway**.
   Не пересылайте QR, TOTP setup/seed, скриншот с QR или секрет вручную
   в ChatGPT, GitHub PR, Slack, issue, лог либо сервисные Variables.
   Если мобильная камера недоступна, воспользуйтесь ручным вводом
   setup key **только если сам Railway предлагает такой способ**.
5. Приложение начнёт выдавать короткоживущие одноразовые коды TOTP
   (как правило, шесть цифр). Введите **актуальный код** в окне
   Railway и подтвердите подключение. Не передавайте этот код кому-либо.
6. Дождитесь явного подтверждения, что 2FA настроена.
   До этого момента QR на экране не означает завершённую настройку.
7. После включения Railway выдаст **recovery codes**. Сохраните весь
   набор в защищённом менеджере паролей / отдельном офлайн-хранилище.
   **Каждый recovery code одноразовый.** Не помещайте их в репозиторий,
   Railway Variables, скриншоты, облачные логи или этот чат.
   Убедитесь, что запасные коды доступны, даже если телефон потерян.
8. Откройте [Account Security Settings](https://railway.com/account/security)
   снова и проверьте статус метода. Для контрольного входа используйте
   отдельное окно браузера (не уничтожайте единственную активную сессию),
   не демонстрируйте и не публикуйте коды.
9. При замене телефона сначала перенесите/проверьте аутентификатор,
   пока старый метод ещё доступен; при необходимости управляйте
   recovery codes в тех же настройках.

**Важно:** не отключайте действующую 2FA только ради того, чтобы увидеть
кнопку `Set up...`. Не выполняйте настройку от лица другого человека.

## 2. Дополнительно — Passkey (например, Windows Hello)

Railway также поддерживает **passkey** — устойчивую к фишингу проверку
через устройство, биометрию или локальный PIN. Это **альтернативный
поддерживаемый Railway способ MFA**, а не SSH-ключ и не TLS-сертификат.

1. Войдите в [Account Security Settings](https://railway.com/account/security).
2. Нажмите **Add Passkey** (если доступно вашему аккаунту/устройству).
3. Если используете Windows 10/11, браузер может открыть диалог
   **Windows Hello**, предложив PIN, отпечаток либо другое
   доступное средство проверки. Следуйте **только** диалогу ОС/браузера.
4. Завершите регистрацию и убедитесь, что passkey появился в
   настройках Railway. При необходимости добавьте резервный
   доверенный способ доступа к аккаунту.
5. Для удаления/смены passkey пользуйтесь настройками Railway,
   а не настройками сервиса `saas-highwater-private-smoke`.

**Не делайте:** не сохраняйте passkey или закрытые ключи в GitHub,
не экспортируйте секретные данные из менеджера паролей в чат.
Вариант окна зависит от браузера и поддержки Windows Hello.

## 3. Отдельно для команды: требование 2FA всем участникам workspace

Это **другая настройка**, не обязательная для описанного staging-пилота.
Официальная возможность `2FA Enforcement` доступна **на Pro и выше**.

1. Доступ должен иметь **администратор workspace**, у которого
   **уже включена личная 2FA**.
2. Откройте [Workspace People Settings](https://railway.com/workspace/people).
3. Найдите переключатель **Require 2FA**.
4. **Прежде чем включать**, согласуйте последствия с владельцами
   workspace: требование вступает в силу **сразу**, участники без
   MFA не смогут работать с ресурсами до настройки метода.
5. Включайте `Require 2FA` **только по явному решению workspace admin**,
   после проверки плана и способов восстановления доступа.
   Не переключайте его как тест в общем рабочем workspace.
6. После включения проверьте доступ одного авторизованного участника.
   Токены API/CI продолжают работать **без интерактивной 2FA**:
   enforcement не защищает автоматически похищенные API tokens.
   Требуются отдельная ротация, минимальные scopes и аудит токенов.

Workspace policy сама по себе НЕ создаёт независимого off-host
оператора, HSM, WORM, отдельный retained minimum или release security signoff.

## 4. Ручное подтверждение `Staged Changes` через Railway Dashboard

**Только если действительно появился согласованный staging diff.**
Проверка 2FA при применении — **не отдельная установка 2FA**.
Railway может потребовать интерактивное подтверждение действия,
которое не поддерживается через текущую MCP/API OAuth-сессию.

1. Откройте проект:
   **https://railway.com/project/dba33407-7200-40e0-a9c8-08c43d41e5e4**
   и удостоверьтесь, что название — **`cpa-gateway-sandbox`**.
2. В переключателе окружений выберите **`sandbox`**, НЕ `production`.
   Контрольный environment ID:
   `9ee1afb9-9b20-4c50-91ef-6f23e3c5f3ee`.
3. Вернитесь на **canvas проекта** (экран с карточками сервисов).
   ВНИМАНИЕ: вкладка сервиса **Variables** содержит переменные и
   секреты, **не** настройку Railway 2FA и **не** общую панель diff.
4. Если ожидающие изменения имеются, Railway показывает их количество
   в баннере; новые/изменённые объекты могут подсвечиваться фиолетовым.
   Откройте баннер через **Details** (в некоторых версиях интерфейса
   надписи могут отличаться: `Staged Changes` / `Review Changes`).
5. Просмотрите **полный список изменений** и diff старых/новых значений.
   Для точечного smoke-теста допустим только заранее согласованный:
   **`saas-highwater-private-smoke → Source Code`**.
   Проверьте, что **нет** правок `saas-highwater-staging-only`,
   volume, secrets, domain/TCP proxy, `cliproxyapi-personal`,
   `api-gateway`, `cliproxyapi-core`, PG, migrations или production.
   Любой неожиданный компонент — **STOP, ничего не применять**.
6. Убедитесь, что операция **не destructive**, число и состав
   изменений совпадают с согласованным отчётом; агент/оператор
   должен предварительно назвать patch ID и scope.
   Не полагайтесь на зелёный статус старого deployment.
7. Нажмите **Deploy** (иногда `Apply` — название может отличаться).
   Это применяет **весь staged changeset**, не один произвольный файл.
   **НЕ удерживайте Alt**: Alt+Deploy может сохранить diff без деплоя.
8. Если Railway запросит дополнительную проверку, используйте свой
   **TOTP** или доступный в вашем аккаунте Railway способ MFA.
   Код вводится **только на сайте Railway в браузере**.
   Не передавайте код в чат и не пытайтесь проводить через API/MCP,
   project token, CLI флаг или обходной вызов GraphQL.
9. Дождитесь завершения публикации. Надпись `Deploying`/`Building`
   не означает успешное выполнение; итог — статус **SUCCESS**
   именно у **нового** deployment.
10. Откройте `saas-highwater-private-smoke → Deployments → Logs`.
    Посмотрите **самую новую** версию и проверяйте **конкретные**
    строки `PASS/FAIL`. Status `SUCCESS` сам по себе не доказывает
    результат криптографического теста.
11. Если `Staged Changes` **не показываются**, то применять нечего:
    **не** нажимайте `Restart`, не меняйте `Variables` и
    не создавайте фиктивный diff только ради запроса 2FA.
    Сначала уточните состояние и deployment через read-only проверку.
12. После теста достаточно передать оператору **не секретный**
    итог: `sandbox`, имя сервиса, deployment ID/status, названия
    успешных/ошибочных проверок. **Никаких кодов и закрытых ключей**.

## 5. Как самостоятельно проверить результат после `Deploy`

Контрольные объекты **только staging**:

| Объект | Что увидеть |
| --- | --- |
| `saas-highwater-staging-only` | Основной high-water сервис Online/SUCCESS. Его подписанный журнал и 512 MB volume не сбрасываются. |
| `saas-highwater-private-smoke` | Новейший deployment SUCCESS после вашей операции. |
| `Staged Changes` | Нет ожидающей правки, если согласованный патч применился и других изменений не было. |
| `Deployments → Logs` | `PASS 7w: private-network HTTPS TLS1.3/mTLS head read with pinned server SPKI` |
| `Deployments → Logs` | `PASS 7w: missing client certificate denied by actual remote authority` |
| `Deployments → Logs` | `DIAG 7w: ... cryptoVerifier=true, webVerifier=true` |
| `Deployments → Logs` | `PASS 7w: retained signed remote head authenticated, revision=1` |
| `Deployments → Logs` | `PASS 7w: two genuine remote competing signed publishers: exactly one successor, one fork denial` |

**Историческое подтверждение, не новый запуск:** на 13 октября 2026
staging-smoke deployment `d3e4ee3d-5d74-4fb1-a28d-c9fd04e33c2f`
имел `SUCCESS` и вышеприведённые PASS-логи; high-water deployment
`885ee1a7-8ffb-462b-ae0e-b47a260d5ff6` тоже `SUCCESS`.
Новые действия должны иметь **собственные** ID/логи и не могут
считаться прошедшими по старым логам.

## 6. Windows PowerShell, SSH и другие частые проблемы

| Симптом | Почему | Безопасное действие |
| --- | --- | --- |
| `railway ssh \\`, затем `--project` выдаёт ParserError | `\\` — не перенос строки в PowerShell | Вставьте команду целиком в **одной строке**, пример ниже |
| `No linked project found` | Команда SSH была запущена без полных аргументов в отдельной строке | Используйте `--project`, `--environment` и `--service` вместе; не выполняйте флаги по отдельности |
| `Enter passphrase for key ... .ssh` | Это шифрование локального SSH-ключа | Вводите свою passphrase локально; это не TOTP Railway |
| Не находится `Set up two-factor authentication` | Возможно, 2FA уже включена или открыт не раздел аккаунта | Сначала проверьте `https://railway.com/account/security`, а не `Variables` |
| Неверный TOTP-код | Срок действия кода истёк, выбрана не та запись или часы телефона не синхронизированы | Введите новый код своего Railway-аккаунта; включите автоматическое время, не передавайте код никому |
| Телефон потерян | Нет доступа к TOTP | Воспользуйтесь **своими одноразовыми recovery codes** из безопасного хранилища; если их нет, используйте штатный процесс восстановления Railway Support |
| Нет баннера `Staged Changes` | Нет ожидающего changeset | Не создавайте новый; проверьте deployed status и логи |
| MCP говорит `two-factor verification ... Apply ... Railway dashboard` | Операция требует human approval, недоступного через OAuth/API token | В браузере проверьте `sandbox`, точный diff и штатный `Deploy` с 2FA; **не обходите** |
| Сервис `CRASHED` после Deploy | Деплой выполнялся, но код/тест упал | Откройте логи **нового** deployment, не заменяйте ключи и не сбрасывайте журнал автоматически |
| `SUCCESS`, но нет ожидаемых `PASS` | Запущенная программа/тест не доказала нужный сценарий | Уточните commit/deployment и недостающую проверку, не маркируйте VERIFIED |

Для Windows PowerShell используйте **одну строку**; эту команду
следует выполнять на локальном компьютере, НЕ внутри SSH-сессии:

```powershell
railway ssh --project dba33407-7200-40e0-a9c8-08c43d41e5e4 --environment sandbox --service saas-highwater-staging-only
```

После успешного SSH prompt вида `root@...:/app#` означает Linux shell
в **staging контейнере**, а не PowerShell. Для TOTP setup SSH **не нужен**.
Из контейнера нельзя и не нужно получать коды/секреты Railway 2FA.

## 7. Ограничения безопасности и срок действия тестовой PKI

- Нельзя отправлять третьим лицам: 2FA/TOTP OTP, recovery codes,
  QR enrollment, seed, приватный passkey/SSH key, `SAAS_REMOTE_BOOTSTRAP_B64`,
  `SAAS_REMOTE_SMOKE_B64`, реальные secrets/переменные, закрытые
  сертификатные ключи или output `printenv`.
- Технический `PASS` синтетического mTLS-теста **не равен**
  реальному независимому off-host root: оба Railway сервиса
  управляются **одной personal workspace**, без внешнего HSM/WORM,
  независимо сохраняемого minimum и независимого оператора.
- Синтетические TLS-сертификаты текущего staging-пилота истекают
  **15 октября 2026, 13:33 UTC**. Это отдельный blocker:
  согласуйте ротацию/выведение из эксплуатации до истечения.
  Никакого продления путём повторного использования старых ключей
  или сброса signed journal без security review.
- Пока не проверены удалённые lost-ACK/restart/failover/restore,
  fenced PostgreSQL COMMIT→high-water, tenant/actor issuer,
  recipient ACK, security/privacy/retention signoff.
- Флаги остаются `authorizationGranted=false`,
  `reissuePermitted=false`, `retryPermitted=false`,
  `repairPermitted=false`, `deliveryPermitted=false`,
  `gcPermitted=false`. Нет production deploy, SQL 019,
  UUID reissue/reuse/delete, archive, автоматического repair/GC
  или merge Draft PR.

## 8. Короткий чек-лист перед подтверждением

- [ ] Я вошёл на `railway.com` в **свой** аккаунт с защищённым MFA.
- [ ] Recovery codes хранятся отдельно, вне GitHub/чатов/Variables.
- [ ] В проекте `cpa-gateway-sandbox` выбран **sandbox**.
- [ ] Я проверил ВСЕ компоненты staged diff, нет посторонних правок.
- [ ] При согласованном source-only smoke update нет production,
      volumes, secrets, ключей или сетевых изменений.
- [ ] Я нажал штатную `Deploy`, выполнил свою 2FA без передачи OTP.
- [ ] Новый deployment завершился `SUCCESS` и его логи содержат
      конкретные `PASS`; иначе `NOT VERIFIED`.
- [ ] Все production/security gates по-прежнему `BLOCKED`.

## Официальные источники Railway

1. [Multi-Factor Authentication](https://docs.railway.com/access/multi-factor-authentication) — authenticator app/TOTP, recovery codes, passkeys и управление.
2. [Account Security Settings](https://railway.com/account/security) — настоящая страница настройки.
3. [Two-Factor Authentication Enforcement](https://docs.railway.com/access/two-factor-enforcement) — workspace `Require 2FA` (Pro+).
4. [Staged Changes](https://docs.railway.com/deployments/staged-changes) — `Details`, полный diff и `Deploy`.
5. [Railway SSH CLI](https://docs.railway.com/cli/ssh) — явный проект/окружение/сервис.

**Документ описывает инструкцию, а не включение MFA за пользователя.**
Статус 2FA конкретного аккаунта не доступен из Railway OAuth API.
Настройку MFA и интерактивный ввод кода выполняет **только владелец**.

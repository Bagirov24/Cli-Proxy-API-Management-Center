# Системный дизайн проекта: CLIProxyAPI + CPA Key Policy + API Gateway

> **As-built, 10.10.2026.** Документ описывает проверенную production-архитектуру, а не предложение по будущей реализации. Здесь нет настоящих ключей, OAuth-токенов или содержимого тома `/data`.

## 1. Состав и границы системы

Система объединяет три компонента, исходники которых находятся в репозитории [Cli-Proxy-API-Management-Center](https://github.com/Bagirov24/Cli-Proxy-API-Management-Center):

1. **Management Center** (ветка `main`) — React/TypeScript/Vite, собирается в один `management.html` и работает с Management API v8 Core. Это **не** публичный API Gateway и **не** отдельный сетевой прокси.
2. **API Gateway** (ветка `api-gateway`) — Caddy 2.11.7 с модулем `cpa_key_guard` и закреплённым сторонним модулем `mholt/caddy-ratelimit`. Публичная точка входа только для клиентских API.
3. **CLIProxyAPI Core + CPA Key Policy** (ветка `custom-no-apikey-fun`, образ `integrations/cpa-key-policy/Dockerfile.ru`) — CLIProxyAPI v8.0.23 и нативный плагин CPA Key Policy v0.5.1. Core отвечает за фактическую авторизацию, модели, OAuth-аккаунты и маршрутизацию к провайдерам.

В Railway проект `cliproxyapi-personal`, окружение `production` содержит **два работающих сервиса**: `api-gateway` и `cliproxyapi-core`. Второй сервис **не имеет публичного домена**; постоянный том `/data` прикреплён **только к Core**. Telegram-боты и внешние приложения являются клиентами Gateway, а не сервисами внутри этого production-проекта.

## 2. Общая архитектура (текущая система)

~~~mermaid
flowchart LR
  subgraph USERS["Внешние клиенты и администратор"]
    bot["Telegram-боты<br/>и API-клиенты"]
    admin["Администратор"]
    tunnel["Локальный туннель<br/>Electerm :18317"]
    admin --> tunnel
  end

  subgraph PRODUCTION["Railway — cliproxyapi-personal / production"]
    edge["Railway Public Edge<br/>HTTPS / X-Real-IP"]

    subgraph GATEWAY["api-gateway — Caddy :8080"]
      allow["Белый список<br/>маршрутов и методов"]
      limit["rate_limit<br/>180 запросов/мин/IP"]
      guard["cpa_key_guard<br/>формат Bearer cpa_..."]
      reverse["Ограничение тела 16 MiB<br/>reverse_proxy / SSE"]
      allow --> limit --> guard --> reverse
    end

    subgraph PRIVATE["cliproxyapi-core — приватный :8317"]
      core["CLIProxyAPI v8.0.23<br/>API + Management API"]
      policy["CPA Key Policy v0.5.1<br/>ключи / RPM / модели"]
      routing["Выбор провайдера<br/>OAuth / алиасы / аккаунты"]
      ui["Management Center<br/>management.html"]
      pluginui["Интерфейс CPA Key Policy<br/>ресурсы плагина"]
      core --> policy --> routing
      ui --> core
      pluginui --> policy
    end

    data[("Railway Volume /data<br/>config.yaml / auths<br/>cpa-key-policy-state.json")]
    edge --> allow
    reverse -->|"Railway private network :8317"| core
    core <--> data
    policy <--> data
  end

  upstream["Внешние AI-провайдеры<br/>по API / OAuth"]
  bot -->|HTTPS| edge
  tunnel -.->|"закрытый доступ"| ui
  tunnel -.->|"закрытый доступ"| pluginui
  routing -->|HTTPS| upstream
~~~

**Границы доверия.** Публично доступен только Railway Edge/Gateway. Административная панель и управление CPA-плагином доступны через приватный туннель к Core. Публичный Gateway **не** публикует `/management.html`, OAuth callback, Management API или служебные ресурсы плагина.

## 3. Точки входа и управление

| Объект | Адрес / путь | Доступ |
| --- | --- | --- |
| Публичный Gateway | `https://api-gateway-production-7977.up.railway.app` | HTTPS из интернета, только allowlist |
| Проверка живости Gateway | `GET /healthz` | Публично, `200 ok`, без Core |
| Chat Completions | `POST /v1/chat/completions` | Только корректная форма CPA Bearer + авторизация Core |
| Responses | `POST /v1/responses` | То же |
| Каталог моделей | `GET /v1/models` | То же, может быть выключен политикой конкретного CPA-ключа |
| Core | `http://cliproxyapi-core.railway.internal:8317` | Только приватная сеть Railway |
| Management Center | `http://127.0.0.1:18317/management.html` | При работающем локальном SSH-туннеле Electerm |
| CPA Key Policy UI | `http://127.0.0.1:18317/v0/resource/plugins/cpa-key-policy/index.html` | Тот же приватный туннель, авторизация управления |
| Настройки Gateway | [Railway → api-gateway](https://railway.com/project/bd565370-7321-4dba-908a-412186b1b986/service/23992044-f1fb-42f9-a9e4-bab33621de17?environmentId=1ae8fb62-814e-4a37-bdde-383b9f8a8740) | Веб-интерфейс Railway |
| Правила Gateway | [Caddyfile](../integrations/api-gateway/Caddyfile) | Код в GitHub, изменения требуют нового Gateway deploy |

Порт `18317` — локальное перенаправление к приватному Core, **не** отдельный открытый интернет-порт. Доступ к Management Center и CPA UI требует соответствующей авторизации Core/плагина.

## 4. Обработка клиентского запроса

~~~mermaid
sequenceDiagram
  autonumber
  participant B as Бот / клиент
  participant E as Railway Edge
  participant G as Caddy Gateway
  participant C as Core + CPA Key Policy
  participant P as AI-провайдер

  B->>E: HTTPS POST /v1/chat/completions
  Note over B,E: Authorization: Bearer cpa_... (настоящий ключ не логировать)
  E->>G: Передаёт запрос и выставляет X-Real-IP
  G->>G: Проверка allowlist, затем лимит 180 RPM/IP
  alt Лимит IP превышен
    G-->>B: 429 / Retry-After (через Edge)
  else Некорректный формат ключа
    G->>G: cpa_key_guard
    G-->>B: 401 (через Edge)
  else Форма корректна
    G->>C: Приватный reverse proxy
    C->>C: Проверка ключа, модели, лимита и правил аккаунтов
    alt Ключ / политика запрещает запрос
      C-->>B: 401 / другая ошибка политики (через Gateway)
    else Запрос разрешён
      C->>P: Запрос к выбранному AI-провайдеру
      P-->>C: Ответ или SSE-события
      C-->>G: HTTP / SSE
      G-->>B: HTTP / SSE через Railway Edge
    end
  end
~~~

**Разделение ролей:**
- `cpa_key_guard` проверяет **только синтаксис** одного `Authorization: Bearer cpa_` + 43 символа Base64URL и исключает неоднозначные альтернативные способы передачи ключей.
- `rate_limit` (сначала по порядку обработки Gateway) ограничивает запросы по IP, используя `X-Real-IP` с публичного Railway Edge; по умолчанию `180 / 60 с`, настройка `EDGE_IP_RPM`. Лимит **не** заменяет RPM отдельного CPA-ключа.
- CPA Key Policy внутри Core проверяет подлинность ключа, доступность моделей, аккаунты и индивидуальные лимиты. Обычные нативные ключи Core могут обходить CPA Policy, поэтому **не выдавайте их внешним клиентам Gateway**.
- По умолчанию вся неизвестная публичная маршрутизация получает `404`. Размер тела — до 16 MiB, заголовков — до 16 KiB.
- SSE передаётся потоково без буферизации со стороны Caddy; в изолированном публичном Railway-тесте интервал двух событий соответствовал исходной задержке ~1,2 с.

## 5. Хранение данных и работа с секретами

~~~mermaid
flowchart TB
  core["CLIProxyAPI Core + CPA Policy"]
  volume[("Railway persistent volume /data")]
  config["config.yaml<br/>конфигурация Core и плагинов"]
  auth["auths/<br/>локальные OAuth-данные"]
  state["cpa-key-policy-state.json<br/>CPA-ключи / правила / статистика"]
  repo["GitHub — только исходный код<br/>и синтетические тесты"]
  core <--> volume
  volume --- config
  volume --- auth
  volume --- state
  repo -.->|"образ и конфигурационные примеры;<br/>не значения секретов"| core
~~~

- `/data` монтируется в Core и переживает пересборку образа. Gateway не имеет собственного постоянного тома.
- Нельзя заменять, удалять или публиковать `/data/config.yaml`, `/data/auths` и `/data/cpa-key-policy-state.json` при работе над Gateway.
- В репозиторий, CI-логи, диаграммы и тесты нельзя помещать реальные management keys, CPA-ключи, OAuth-данные или нативные ключи Core.

## 6. Репозиторий, CI и поставка

~~~mermaid
flowchart LR
  subgraph GIT["GitHub — Cli-Proxy-API-Management-Center"]
    frontend["main<br/>React 19 / TypeScript / Vite<br/>Management Center"]
    gwsource["api-gateway<br/>Caddyfile / Dockerfile<br/>guard / tests"]
    coresrc["custom-no-apikey-fun<br/>Dockerfile.ru<br/>CPA Policy RU/EN overlay"]
    ci["GitHub Actions<br/>Go tests, Docker, HTTP/SSE"]
    ciCore["GitHub Actions<br/>сборка плагина / Core"]
    uiArtifact["Однофайловый UI<br/>management.html"]
    frontend --> uiArtifact
    gwsource --> ci
    coresrc --> ciCore
  end
  subgraph RAILWAY["Railway production — только явный выпуск"]
    gwLive["api-gateway<br/>закреплённый commit SHA"]
    coreLive["cliproxyapi-core<br/>образ с CPA-плагином"]
  end
  ci -->|"проверка, затем согласованный deploy"| gwLive
  ciCore -->|"проверка, затем согласованный deploy"| coreLive
  uiArtifact -.->|"UI используется при приватном<br/>управлении Core"| coreLive
~~~

**Версии проверенного выпуска Gateway:**
- Production SHA: `448ff457b0324887770871d60be6194a01df3102`.
- Deployment: `b1cc80f9-3427-4a88-87c7-187ecf87a1b0`, Railway `SUCCESS`.
- Предыдущий Gateway для отката: SHA `895aa755e48665b34ec735ff155dff8daa72cdc9`, deployment `93a1b2e5-062e-4c85-983a-267d54861efa`.
- Core развёрнут независимо от Gateway на основе `integrations/cpa-key-policy/Dockerfile.ru`; изменение Gateway **не** означает изменение Core.

**Сборочные материалы:** [Gateway](../integrations/api-gateway/README.md) · [CPA Key Policy](../integrations/cpa-key-policy/README.ru.md) · [корневой README на русском](../README_RU.md).

## 7. Масштабирование, отказоустойчивость, риски

| Аспект | Текущее состояние / ограничение |
| --- | --- |
| Gateway | Одна реплика. Нет гарантии бесперебойной работы при аварии единственной реплики. |
| Core | Одна реплика с постоянным томом `/data`. |
| Rate limiting | Счётчики per-IP находятся в памяти Caddy, **не** являются распределёнными. Больше одной реплики требует пересмотра схемы. |
| Доверие к IP | Подмена `X-Real-IP` протестирована на **публичном** Railway Edge; приватные обходные пути не должны открываться. |
| DDoS | Лимит RPM/IP — не полноценная защита от распределённого DDoS. |
| Данные | Секреты и OAuth на постоянном томе. Нужен отдельный проверенный план резервного копирования и восстановления (в репозитории нет резервных копий). |
| Мониторинг | Railway Logs/Metrics/Deployments. В Caddy отключены детализированные метрики per-IP во избежание высокой кардинальности. |
| Изменения | Сначала PR и CI, затем отдельное подтверждение production-развёртывания. |
| Подтверждение работы | Изолированные 200/401/404/429/SSE-тесты пройдены; после production deploy пользователь отдельно получил HTTP 200 с настоящим CPA-ключом через Electerm и Gateway. |

## 8. Операционные правила

1. Изменения Gateway, Management Center и Core выполняйте в отдельных ветках и выпускайте раздельно.
2. Для Gateway меняйте `EDGE_IP_RPM` или `Caddyfile` только с учётом повторного развёртывания. Значение по умолчанию — **180 RPM/IP**.
3. После Gateway deploy проверяйте `GET /healthz`, разрешённые и запрещённые маршруты, `401/404` и локальный запрос с существующим CPA-ключом (значение ключа не публиковать).
4. Не выполняйте нагрузочный тест на production ради получения `429` — это проверялось на отдельном изолированном стенде.
5. В случае аварии Gateway используйте сохранённое предыдущее развёртывание; убедитесь, что закреплённый исходный SHA согласован с откатом.
6. **Никогда** не пересоздавайте Core или том `/data` как часть исправления Gateway без отдельного явного согласования.

> Эта архитектура отражает проверенное состояние на дату документа. Текущий перечень подключённых AI-аккаунтов и модели сознательно не перечислены — это изменяемая приватная конфигурация Core.

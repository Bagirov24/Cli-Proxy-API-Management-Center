# CPA API Gateway (Railway production)

Этот каталог — **исходный код публичного API Gateway** для Telegram-ботов на базе Caddy. Рабочая ветка: `api-gateway`. Публичный Gateway проксирует только разрешённые API-запросы во внутренний CLIProxyAPI Core; управление Core, OAuth и CPA Key Policy через публичный домен **не открывается**.

## Структура репозитория

| Файл | Назначение |
| --- | --- |
| [Caddyfile](Caddyfile) | Публичные маршруты, защита, лимиты, reverse proxy |
| [Dockerfile](Dockerfile) | Сборка Caddy 2.11.7 с дополнительными модулями |
| [guard/guard.go](guard/guard.go) | Caddy-модуль `http.handlers.cpa_key_guard` |
| [guard/policy/policy.go](guard/policy/policy.go) | Правила строгой проверки формы заголовка авторизации |
| [guard/policy/policy_test.go](guard/policy/policy_test.go) | Автономные Go-тесты правил |
| [review-tests/](review-tests/) | Имитация Core и изолированные HTTP/SSE/429-тесты |
| [security review CI](../../.github/workflows/api-gateway-security-review.yml) | Проверки Docker-сборки, модулей и mock Core |
| [основной CI](../../.github/workflows/ci.yml) | Проверка проекта и сборка Gateway для PR |

## Сетевая схема

```text
Telegram bots / API clients
         | HTTPS
         v
Railway public Edge
         |
         v
api-gateway :8080 (Caddy + cpa_key_guard + rate_limit)
         | Railway private network
         v
cliproxyapi-core.railway.internal:8317
         |
         v
CPA Key Policy / model rules / provider authorization
```

Публичный домен: `https://api-gateway-production-7977.up.railway.app`.

Разрешённые маршруты:

| Метод | Путь | Ответ |
| --- | --- | --- |
| GET | `/healthz` | `200 ok`, не проходит в Core |
| POST | `/v1/chat/completions` | Передаётся в Core после проверок |
| POST | `/v1/responses` | Передаётся в Core после проверок |
| GET | `/v1/models` | Передаётся в Core после проверок, если разрешено политикой ключа |
| Любой другой | Любой другой путь или неверный метод | `404` |

## Авторизация и защита

- Gateway принимает **ровно один** заголовок `Authorization: Bearer cpa_...` с 43 символами Base64URL после `cpa_`. Некорректная форма, отсутствие заголовка, его дублирование, альтернативные заголовки API-ключа и учетные данные в query string отклоняются с `401`.
- `cpa_key_guard` проверяет **только форму**. Наличие ключа, модель, allowlist и индивидуальный RPM всегда проверяет **Core/CPA Key Policy**. Не используйте нативные ключи Core в публичных запросах.
- `rate_limit` ограничивает трафик отдельно по `X-Real-IP` (публичный Railway Edge заменяет подставленный заголовок клиента). По умолчанию **180 запросов / 60 секунд / IP**. Превышение даёт `429` и `Retry-After`. Общего счётчика для всех пользователей нет.
- Размер тела запроса ограничен **16 MiB**; заголовков — 16 KiB. SSE идёт без буферизации со стороны Gateway. Admin API Caddy выключен.
- Публичная проверка Railway Edge с подменой `X-Real-IP` и SSE успешно пройдена с синтетическим Core; это **не** доказывает устойчивость к DDoS или поведение на всех возможных сетевых путях.
- Rate-limit хранится **в памяти одной реплики**. При масштабировании на несколько реплик он не становится общим; до масштабирования нужна отдельная архитектура распределённых лимитов. Не выставляйте приватный порт Gateway для обхода публичного Railway Edge.

## Графическое управление

В [Railway — production Gateway](https://railway.com/project/bd565370-7321-4dba-908a-412186b1b986/service/23992044-f1fb-42f9-a9e4-bab33621de17?environmentId=1ae8fb62-814e-4a37-bdde-383b9f8a8740):

- **Variables**: `EDGE_IP_RPM` — необязательное переопределение лимита, целое положительное число (в Caddyfile: `{$EDGE_IP_RPM:180}`).
- **Deployments**: сборки, статусы и откат.
- **Logs / Metrics**: ошибки, запросы, производительность.
- **Settings**: домен, healthcheck `/healthz`, Dockerfile.

Изменение `EDGE_IP_RPM` требует применения нового развёртывания. В production переменная обычно не задана: действует значение **180** из файла. Публичной веб-админки самого Caddy **нет и быть не должно**. CPA-ключами управляют отдельно через приватный интерфейс CPA Key Policy, доступный через SSH-туннель.

## Процесс обновления

1. Подготовьте правки отдельной веткой и PR в `api-gateway`; не правьте production Core.
2. Дождитесь успешного CI: Go policy, custom Caddy Docker build, `caddy adapt --validate`, mock-only тесты HTTP `200/401/404/429` и SSE.
3. Зафиксируйте проверенный commit SHA, затем **явно** обновите источник только сервиса `api-gateway` в Railway. Production service может быть **закреплён за конкретным SHA**: простой push в ветку не гарантирует новый deploy.
4. Дождитесь Railway `SUCCESS` и работоспособности `GET /healthz`. Проверьте недопустимые маршруты (`404`) и запрос без CPA-ключа (`401`).
5. Один функциональный тест с **собственным** действующим CPA-ключом запускайте локально со скрытым вводом (`getpass`). Никогда не передавайте настоящий ключ в GitHub Actions, GitHub, документацию или чат. Не делайте 181 запрос в production ради теста лимита.
6. Контролируйте `5xx`, `429` и задержки через Railway после выпуска.

### Идентификаторы выпуска и откат

- **Начальный выпуск защиты Gateway:** commit `448ff457b0324887770871d60be6194a01df3102`, deployment `b1cc80f9-3427-4a88-87c7-187ecf87a1b0`.
- **Предыдущая версия для экстренного отката:** commit `895aa755e48665b34ec735ff155dff8daa72cdc9`, deployment `93a1b2e5-062e-4c85-983a-267d54861efa`. В ней **нет** нового ограничителя IP и защиты формата CPA.
- При аварии используйте **Railway → Deployments → Rollback** только для `api-gateway`. После этого проверьте закреплённый SHA источника: иначе последующий deploy может вернуть новую версию. Подтвердите восстановление `GET /healthz` и локальным тестом. Не меняйте `cliproxyapi-core`, OAuth, CPA-ключи или том `/data`.

## Воспроизводимость

Dockerfile использует `caddy:2.11.7-builder-alpine` / `caddy:2.11.7-alpine`, модуль `github.com/mholt/caddy-ratelimit` с закреплённым revision `5625512f24f6f59d6f64fb3aafe5eecff0b286db` и локальный `cpa_key_guard`. Проверки собирают Gateway против **синтетического** Core, без production-секретов и без запросов к настоящему Core.

Изменения этого README и иных комментариев в репозитории **не изменяют работающий Gateway**, пока новая версия явно не развёрнута в Railway.

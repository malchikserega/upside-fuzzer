# Руководство по настройке фаззинга Bitwarden с нуля

В этом документе подробно описаны все шаги, необходимые для подготовки локального окружения Bitwarden, интеграции инструментирования (C# AST) и запуска смарт-фаззера UpsideFuzzer.

---

## 1. Подготовка исходного кода и окружения

Предполагается, что вы находитесь в корневой директории платформы `upside-fuzzer` и у вас есть папка `bitwarden_prep`, содержащая исходный код `bitwarden/server`.

### Требования:
- Установленный **Docker** и **Docker Compose**.
- Установленный **Python 3**.
- Настроенный скрипт компиляции RESTler (`compile-grammar.sh`).

---

## 2. Интеграция C# инструментирования

Чтобы фаззер получал обратную связь (Code Coverage), необходимо внедрить код сбора покрытия в исходный код API Bitwarden.
В проекте `upside-fuzzer` используется инструмент на основе Roslyn (находится в директории `instrumentor`), который модифицирует исходники перед компиляцией в Docker-образе.

### 2.1 Изменение Dockerfile
В `bitwarden_prep` мы используем `Dockerfile.instrumented` вместо стандартного. В него добавлены следующие шаги (на этапе сборки C# проекта):
1. Копирование утилиты `instrumentor` внутрь сборочного контейнера.
2. Выполнение команды `dotnet run` для инструментации кода (инжектирование блоков `try/finally` с вызовом `Coverage.Hit(...)`).
3. Добавление зависимости `HttpExtensions.dll`, которая реализует Shared Memory (SHM) для передачи покрытия фаззеру.

### 2.2 Настройка Docker Compose
Вместо базового `docker-compose.yml` используется `docker-compose.instrumented.yml`:
- У сервисов `api` и `identity` изменен `build.dockerfile` на `Dockerfile.instrumented`.
- Отключены healthcheck'и на основе `curl`, так как инструменты отладки удалены из продакшен образов Bitwarden.
- Добавлен Shared Memory volume `coverage_shm:/coverage_shm` для быстрой передачи битового массива покрытия между API и фаззером.

---

## 3. Генерация грамматики для фаззера

UpsideFuzzer (Void) требует грамматику API (файл `grammar.py`), сгенерированную на базе OpenAPI/Swagger спецификации.

### Шаг 3.1: Запуск API для экспорта спецификации
Сначала нужно поднять БД и сам API, чтобы скачать Swagger JSON:
```bash
cd bitwarden_prep
docker compose -f docker-compose.instrumented.yml up mssql migrator identity api -d
```

Дождитесь запуска API (обычно на порту `4000`), затем скачайте внутреннюю спецификацию:
```bash
curl -s http://localhost:4000/specs/internal/swagger.json > internal_swagger.json
```

### Шаг 3.2: Санитизация Swagger'а
В Bitwarden используются сложные вложенные структуры объектов в query-параметрах. Компилятор RESTler (Microsoft) не поддерживает `deepObject` или параметры со ссылками `$ref`.
Используйте Python-скрипт `sanitize_swagger.py` (уже есть в папке `bitwarden_prep`):
```bash
python3 sanitize_swagger.py internal_swagger.json
```
Этот скрипт очистит JSON от неподдерживаемых конструкций.

### Шаг 3.3: Компиляция грамматики
Перейдите в корень проекта и скомпилируйте `grammar.py`:
```bash
cd ..
./compile-grammar.sh bitwarden_prep/internal_swagger.json
```
Убедитесь, что скрипт успешно завершился. Скопируйте результаты в директорию с грамматиками:
```bash
mkdir -p grammars/bitwarden
cp restler_output/Compile/grammar.py restler_output/Compile/dict.json grammars/bitwarden/
```

---

## 4. Настройка аутентификации

Bitwarden требует строгой валидации паролей и двушаговую регистрацию. Мы автоматизировали этот процесс скриптом `get_apikey.py`.

```bash
cd bitwarden_prep
python3 get_apikey.py
```
**Что делает скрипт:**
1. Отправляет запрос `/accounts/register/send-verification-email` (первый шаг).
2. Забирает токен подтверждения из ответа API.
3. Завершает регистрацию `/accounts/register/finish` (с параметрами `kdfIterations: 600000`).
4. Запрашивает OAuth Access Token `/connect/token` (обязательно с заголовками `Bitwarden-Client-Version` и `Device-Type`).
5. Создает файл `fuzzer.env` с auth-материалом для фаззера.

Void сейчас понимает все основные варианты auth без дополнительных конвертаций:
- `AUTH_TOKEN` — raw JWT или вставленный `Bearer ...` токен; префикс `Bearer` будет безопасно удален.
- `AUTH_HEADERS_JSON` — JSON-объект заголовков, например `{"Authorization":"Bearer ..."}`.
- `AUTH_HEADER` — legacy shortcut вида `Header-Name: value`, например `Authorization: Bearer ...`; используйте только если helper script сгенерировал именно его.
- `AUTH_COOKIE` — значение заголовка `Cookie` для cookie-based сессии.

Для обычного single-user прогона оставьте `fuzzer.env` как есть: `docker-compose.instrumented.yml` подключает его через `env_file`.

Для access-control fuzzing лучше создать явный identity-файл и запускать Void с `-auth-file`. Пример для cookie-сессии:

```bash
cd bitwarden_prep
python3 - <<'PY'
import json
from pathlib import Path

env = {}
for line in Path("fuzzer.env").read_text().splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.split("=", 1)
        env[k] = v.strip().strip('"').strip("'")

identities = [{"name": "guest", "weight": 0.2}]
if env.get("AUTH_TOKEN"):
    identities.insert(0, {"name": "bitwarden-user", "jwt": env["AUTH_TOKEN"], "weight": 2.0})
elif env.get("AUTH_COOKIE"):
    identities.insert(0, {"name": "bitwarden-cookie-user", "cookie": env["AUTH_COOKIE"], "weight": 2.0})
elif env.get("AUTH_HEADERS_JSON"):
    identities.insert(0, {"name": "bitwarden-header-user", "headers": json.loads(env["AUTH_HEADERS_JSON"]), "weight": 2.0})
elif env.get("AUTH_HEADER"):
    name, value = env["AUTH_HEADER"].split(":", 1)
    identities.insert(0, {"name": "bitwarden-header-user", "headers": {name.strip(): value.strip()}, "weight": 2.0})
else:
    raise SystemExit("No supported auth value found in fuzzer.env")

Path("auth.identities.json").write_text(json.dumps({"version": "1", "identities": identities}, indent=2))
PY
```

---

## 5. Наполнение базы тестовыми данными

Для того чтобы фаззер мог эффективно находить уязвимости в бизнес-логике, база данных должна содержать реальные объекты (папки, пароли/шифры, отправки). В противном случае большинство запросов на изменение (`PUT`, `DELETE`) будут завершаться с ошибкой 404 (Not Found).

Мы автоматизировали этот процесс с помощью скрипта `populate_data.py`. Скрипт генерирует фейковые зашифрованные данные, соответствующие строгим требованиям валидации Bitwarden (правильные base64 IV и Ciphertext).

Для access-control fuzzing лучше наполнять стенд под несколькими пользователями. Тогда в базе появляются объекты разных владельцев, а Void во время multi-auth fuzzing может эффективнее находить IDOR, cross-user и cross-tenant ошибки.

**Как запустить:**
Если у вас есть `auth.identities.json`, выполните:
```bash
cd bitwarden_prep
python3 populate_data.py --auth-file auth.identities.json
```

Если identity-файла нет, скрипт сохранит старое поведение и возьмет single-user auth из `fuzzer.env`:
```bash
cd bitwarden_prep
python3 populate_data.py
```

Скрипт создаст:
- Фейковые папки (Folders) для каждого authenticated identity
- Фейковые записи (Ciphers), привязанные к папкам этого identity
- Фейковые отправки (Sends)
- `populated-objects.json` с созданными object IDs, сгруппированными по identity

Guest/anonymous identities автоматически пропускаются, потому что они не могут создавать vault objects. Секреты и токены в `populated-objects.json` не сохраняются.

Полезные опции:
```bash
python3 populate_data.py --auth-file auth.identities.json --identity bitwarden-admin
python3 populate_data.py --auth-file auth.identities.json --folders 5 --ciphers 30 --sends 10
python3 populate_data.py --auth-file auth.identities.json --dry-run
```

---

## 6. Запуск фаззера (Void)

В `docker-compose.instrumented.yml` уже прописан профиль фаззера. Обратите внимание на настройки volume:
- `../grammars/bitwarden:/grammar` — грамматика и `templates.export.json`. Если шаблоны уже сгенерированы, можно монтировать read-only; если нужно экспортировать заново, оставьте write-доступ.
- `../crashes:/fuzzer/crashes` — папка для сохранения найденных крашей и отчетов.

### Сборка и старт через `fuzzer.env`
```bash
# Собираем и запускаем сервис smartfuzzer
docker compose -f docker-compose.instrumented.yml --profile fuzz up smartfuzzer --build -d
```

### Рекомендуемый security-прогон с `-auth-file`

Если вы создали `bitwarden_prep/auth.identities.json`, можно запустить одноразовый прогон с явными флагами:

```bash
docker compose -f docker-compose.instrumented.yml --profile fuzz run --build --rm \
  -v "$PWD/src:/src:ro" \
  -v "$PWD/auth.identities.json:/auth/auth.identities.json:ro" \
  smartfuzzer \
  -grammar /grammar \
  -dict /grammar/dict.security.json \
  -templates-json /grammar/templates.export.json \
  -src /src \
  -auth-file /auth/auth.identities.json \
  -identity-mode weighted \
  -identity-include-guest=true \
  -direct-shm \
  -shm-path /coverage_shm/bitmap \
  -shm-read-mode file \
  -coverage-bitmap-size 262144 \
  -time-budget 30 \
  -concurrency 16 \
  -min-concurrency 8 \
  -max-concurrency 40 \
  -request-timeout 4.0 \
  -coverage-interval 4 \
  -sequence-prob 0.45 \
  -sequence-max-depth 5 \
  -sequence-fanout 8 \
  -race-prob 0.08 \
  -race-burst 3 \
  -skip-endpoint-on-500 \
  -skip-on-crash \
  -no-ui
```

### Просмотр логов и интерфейса фаззера
Фаззер имеет продвинутый терминальный интерфейс. Подключитесь к логам, чтобы наблюдать за процессом в реальном времени:
```bash
docker logs -f bitwarden_prep-smartfuzzer-1
```
Вы должны увидеть, как метрики `edges`, `corpus` и `crashes` начинают увеличиваться.

---

## 7. Анализ найденных уязвимостей

Все 500-е ошибки (краши) автоматически триажируются и сохраняются в папку `crashes` на вашей хост-машине.
- **`unique-crashes-*.jsonl`**: Уникальные сгруппированные баги.
- **`pocs/`**: Готовые bash-скрипты с `curl`-запросами для локального воспроизведения найденного краша.

> ⚠️ Важное замечание по безопасности: Использование фаззера и анализ уязвимостей (включая RCE и DDoS вектора) должны проводиться строго в легитимных рамках, на собственных тестовых стендах, в рамках санкционированных исследований.

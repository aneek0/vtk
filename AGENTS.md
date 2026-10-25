# VLESS Toolkit (vtk)

## Что это

Универсальный тулкит для работы с прокси-ссылками и подписками.
Парсинг, валидация, конвертация между форматами.
Три интерфейса — Telegram bot, веб (FastAPI), CLI — одна общая логика.

## Поддерживаемые протоколы

- `vless://`, `vmess://`, `trojan://`, `ss://`, `ssr://`
- `hysteria2://` — парсинг с sni/alpn/obfs
- `socks://` — с аутентификацией и без
- `happ://crypt*` — авто-дешифровка встроенным офлайн-дешифратором (все RSA-ключи вшиты)
- `incy://crypt*` — авто-дешифровка встроенным офлайн-дешифратором (AES-256-GCM, keymat вшит)

## Форматы вывода

- **singbox** — sing-box JSON (outbounds array)
- **mihomo** — mihomo/clash-meta YAML (только proxies)
- **flclash** — полный FlClash YAML (mixed-port, proxy-groups, rules, dns)
- **txt** — список share-ссылок

## Быстрый старт

```bash
git clone <repo-url> && cd vtk
uv sync --all-extras
```

### Переменные окружения

| Переменная | Описание |
|---|---|
| `VTK_BOT_TOKEN` | Токен Telegram бота |

### CLI

```bash
uv run vtk check vless://...                        # валидация
uv run vtk parse vless://...                       # парсинг с выводом полей
uv run vtk convert vless://... -f singbox           # конвертация
uv run vtk sub https://sub.url -f flclash            # подписка
uv run vtk batch links.txt -f mihomo                 # пакетно
uv run vtk extract config.json                       # извлечь ссылки
uv run vtk settings show                             # настройки
```

### Бот

```bash
export VTK_BOT_TOKEN=xxx
uv run python -m bot.main
```

Команды: `/start`, `/help`, `/settings`, `/proxy`

Фичи:
- Автоопределение типа входа (ссылка / URL подписки / конфиг / TXT)
- Inline keyboard для настройки формата по типу входа
- Загрузка файлов (документы обрабатываются как текст)
- Rate limit (3 msg/sec на пользователя)
- Авто-дешифровка `happ://crypt*`
- Авто-дешифровка `incy://crypt*`

### Веб

```bash
uv run python -m web.main
# http://localhost:9000
```

HTML-форма + JSON API:
- `GET /api/convert?input=...&format=singbox` — конвертация
- `GET /api/extract?input=...` — конфиг → share-ссылки
- `GET /api/check?link=...` — валидация одной ссылки

## Структура

```
core/
  logic.py       — парсинг ссылок, fix_link(), process_input/render_nodes, fetch subscriptions
  share.py       — render_link(): единственный рендерер Node → share-ссылка
  input.py       — InputKind/classify/settings_key/default_format (какой формат по умолчанию)
  formats.py     — реестр форматов: FormatSpec (label/extension/default_for) + SECTIONS
  converters.py  — singbox / mihomo / flclash / xray / txt output
  decryptors.py  — реестр дешифраторов happ/incy (Decryptor, DECRYPTORS, decrypt_input)
  _b64.py        — общие base64url-хелперы
  net.py         — единая политика fetch: TLS verify, лимит редиректов, SSRF-гвард
  errors.py      — DecryptError (общий для happ/incy)
  fingerprint.py — device fingerprint: parse/generate params, app-link parse, random, get_proxy_base
  reverse.py     — обратная конвертация (config → share links)
  settings.py    — настройки пользователя (атомарная запись, включая proxy device)
  happ.py        — happ://crypt* офлайн-дешифратор (все RSA-ключи вшиты)
  incy.py        — incy://crypt* офлайн-дешифратор (AES-256-GCM, keymat вшит)
bot/       — Telegram bot (aiogram 3): /settings, /proxy, меню device, импорт app-link; state.py — PendingStore
web/       — FastAPI: /convert, /proxy (/p/<params>/<url>), /api/device/random, HTML
cli/       — CLI (argparse, не typer)
```

## Ключевые возможности core API

### fix_link()
Нормализует прокси-ссылки для совместимости (например, podkop):
- `&` → `?` в начале query (authority/query/fragment разбираются явно,
  фрагмент без query не ломает порт)
- Добавляет `type=raw` если нет (vless), невалидный `type` → `raw`
- Убирает известные спам-параметры
- `packet-encoding=` → `packetEncoding=`

`parse_link` превращает `ValueError` от `urllib.parse` (например, порт вне
диапазона) в `ParseError`, поэтому битая строка не валит батч.

### Сериализация (round-trip)
Единственный рендерер — `core.share.render_link(node)` (обратен парсерам):
```python
from core.share import render_link
node = parse_vless(link)
link2 = render_link(node)  # round-trip
```

### Дефолтный формат
`core.input.classify(text)` → `InputKind`; `default_format(kind, settings,
node_count)` выбирает поле настроек (`settings_key()`), причём батч из
нескольких ссылок — это `node_count > 1`, независимо от протоколов.
`core.formats` хранит подписи/расширения/меню форматов.

### Стриминговый парсер
Для больших входов использовать `iter_parse_text()` (генератор) вместо `parse_text_input()`.

`extract_country(name)` определяет страну по флагу-эмодзи (в любом месте имени)
или текстовым паттернам. Используется в `group_by_country`: сортировка нод по
странам во всех форматах + per-country группы во FlClash.

### Производительность
Горячие пути оптимизированы (замеры на 5 000 ссылок, cpython 3.13):
- YAML-вывод (mihomo/flclash) идёт через libyaml `CSafeDumper` (`converters._yaml_dump`)
  с пост-обработкой `\U00XXXXXXX`-эскейпов обратно в литеральные эмодзи —
  в ~4 раза быстрее чистого Python-эмиттера PyYAML; при отсутствии libyaml
  автоматический фолбэк на чистый дампер.
- `extract_country` — таблицы `_FLAG_MAP` / `_COUNTRY_TEXT_PATTERNS` на уровне
  модуля (компилируются один раз).
- RSA-ключи happ (crypt1–5) импортируются один раз и кэшируются
  (`happdecrypt._key_cache`): импорт RSA-ключа ~10–30 мс, кэш убирает
  повторные импорты при нескольких ссылках.
- `parse_text_input` не вызывает `fix_link` отдельно: нормализация выполняется
  внутри `parse_vless`/`parse_trojan`.
- JSON-вывод (singbox/xray) — через orjson при наличии.

## Настройки

Хранятся в `~/.config/vtk/settings.json`. Для каждого типа входа свой формат:
`sub_format`, `link_format`, `config_format`, `txt_format`, `group_by_country`.

### Device fingerprint (proxy device headers)
Отдельная группа настроек для подстановки device-заголовков (User-Agent, X-Hwid,
X-Device-Os/Model, Accept-Language) в запросы подписок:
`proxy_headers_on` (отправлять только если включено), `proxy_os`, `proxy_ua`,
`proxy_ver`, `proxy_model`, `proxy_locale`, `proxy_hwid`, `proxy_hwid_on`.

Базовый хост для passthrough-ссылок `/p/<params>/<url>` задаётся через
переменную окружения `VTK_PROXY_BASE` (по умолчанию `https://vtk.aneeko.qzz.io`).

Вся логика device-отпечатка — в `core/fingerprint.py` (единственный источник
истины, переиспользуется ботом, вебом и `/api/device/random`).

### Импорт из веб-ссылки
Бот умеет принимать ссылку вида
`https://host/p/android,ver=3.8.13,model=OnePlus%20Open,ua=Happ/3.26.0,locale=ja_JP,hwid=8ddcfe6b6b55/https://sub...`
(`core.fingerprint.parse_app_proxy_url`, host-agnostic) и переписывать
device-настройки, включая `proxy_headers_on`.

## Инварианты

- Один путь обработки: `core.logic.process_input` (decrypt → classify →
  fetch/parse → convert → `render_nodes`). Бот, веб и CLI не вызывают
  `decrypt_text` сами и не фильтруют ноды по протоколу вручную.
- Рендер share-ссылок — только `core/share.render_link`; `to_txt`, список
  серверов в вебе и выгрузки файлов используют его (у каждого протокола
  рендерер обратен своему парсеру).
- Классификация входа — только `core/input.py`; подписи форматов, расширения
  файлов и меню/`<select>` — только `core/formats.py`.
- Все сетевые запросы идут через `core.net.fetch`: TLS-проверка включена
  (отключается только `insecure_tls` в настройках), редиректы ≤ 3, на каждом
  хопе — SSRF-гвард (приватные/loopback адреса отклоняются, обход —
  `VTK_ALLOW_PRIVATE_URLS=1`).
- Расшифровка: `core/decryptors.py` (`DECRYPTORS`, единый `decrypt_input`);
  `happ://`/`incy://` бросают `core.errors.DecryptError`, per-link ошибки не
  валят батч, другие исключения — валят (это баги).
- Настройки пишутся атомарно (`tmp` + `os.replace`, режим 0600) и читаются
  поключево: битое значение отбрасывается, остальные сохраняются.
- Device fingerprint — только `core/fingerprint.py`.
- Словарь терминов — `GLOSSARY.md`, решения — `docs/adr/`.

## Тесты

```bash
uv run pytest -q
```

Покрытие: fix_link, все парсеры, все конвертеры, round-trip, извлечение страны,
обработка ошибок, device fingerprint (`test_fingerprint.py`), web-роуты с
моком httpx (`test_web_routes.py`).

## Разработка

```bash
uv sync --all-extras            # runtime + dev (pytest, ruff)
uv run pytest -q                # тесты
uv run ruff check .             # линтер (конфиг в pyproject.toml)
uvx pre-commit run --all-files  # pre-commit hook (ruff)
```

CI: GitHub Actions (ruff + pytest 3.10/3.13 + pip-audit), Dependabot (pip,
github-actions). Зависимости — два extras: `[bot]` (aiogram) и `[web]`
(fastapi/uvicorn/python-multipart/jinja2); core: httpx/pycryptodome/cryptography/pyyaml.
`requirements.txt` удалён — используется `uv.lock`.

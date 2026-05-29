# VLESS Toolkit (vtk)

## Что это

Универсальный тулкит для работы с прокси-ссылками и подписками.
Парсинг, валидация, конвертация между форматами.
Три интерфейса — Telegram bot, веб (FastAPI), CLI — одна общая логика.

## Поддерживаемые протоколы

- `vless://`, `vmess://`, `trojan://`, `ss://`, `ssr://`
- `hysteria2://` — парсинг с sni/alpn/obfs
- `socks://` — с аутентификацией и без
- `happ://crypt*` — авто-дешифровка через [Happy Decoder API](https://happy-decoder.cc/api)

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
| `VTK_HAPP_KEY` | API-ключ Happy Decoder (опционально, без него — демо 5 req/min) |

### CLI

```bash
uv run vtk check vless://...                        # валидация
uv run vtk parse-cmd vless://...                     # парсинг с выводом полей
uv run vtk convert-cmd -l vless://... -f singbox     # конвертация
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

Команды: `/start`, `/help`, `/settings`, `/happkey`

Фичи:
- Автоопределение типа входа (ссылка / URL подписки / конфиг / TXT)
- Inline keyboard для настройки формата по типу входа
- Загрузка файлов (документы обрабатываются как текст)
- Rate limit (3 msg/sec на пользователя)
- Авто-дешифровка `happ://crypt*`

### Веб

```bash
uv run python -m web.main
# http://localhost:8080
```

HTML-форма + JSON API:
- `GET /api/convert?input=...&format=singbox` — конвертация
- `GET /api/extract?input=...` — конфиг → share-ссылки
- `GET /api/check?link=...` — валидация одной ссылки

## Структура

```
core/      — общая бизнес-логика
  logic.py       — парсинг ссылок, fix_link(), загрузка подписок, extract_country()
  converters.py  — генерация форматов вывода
  reverse.py     — обратная конвертация (config → share links)
  settings.py    — настройки пользователя
  happ.py        — интеграция с Happy Decoder API
bot/       — Telegram bot (aiogram 3)
web/       — FastAPI + HTML + JSON API
cli/       — CLI (typer)
```

## Ключевые возможности core API

### fix_link()
Нормализует прокси-ссылки для совместимости (например, podkop):
- `&` → `?` в начале query
- Добавляет `type=tcp` если нет (vless)
- `packet-encoding=` → `packetEncoding=`

### Сериализация (round-trip)
Каждый протокол имеет метод `to_*_link()`:
```python
node = parse_vless(link)
link2 = node.to_vless_link()  # round-trip
```

### Стриминговый парсер
Для больших входов использовать `iter_parse_text()` (генератор) вместо `parse_text_input()`.

### Извлечение страны
`extract_country(name)` определяет страну по флагу-эмодзи или текстовым паттернам. Используется в FlClash `group_by_country` для создания групп по странам.

## Настройки

Хранятся в `~/.config/vtk/settings.json`. Для каждого типа входа свой формат:
`sub_format`, `link_format`, `config_format`, `txt_format`, `group_by_country`.

## Тесты

```bash
pytest tests/
```

Покрытие: fix_link, все парсеры, все конвертеры, round-trip, извлечение страны, обработка ошибок.

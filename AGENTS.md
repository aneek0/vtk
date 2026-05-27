# VLESS Toolkit (vtk)

## Что это

Универсальный тулкит для работы с прокси-ссылками и подписками.
Парсинг, валидация, конвертация между форматами.
Три интерфейса — Telegram bot, веб (FastAPI), CLI — одна общая логика.

## Поддерживаемые протоколы

- `vless://`, `vmess://`, `trojan://`, `ss://`, `ssr://`
- `happ://crypt*` — авто-дешифровка через [Happy Decoder API](https://happy-decoder.cc/api)

## Форматы вывода

- **singbox** — sing-box JSON
- **mihomo** — mihomo/clash-meta YAML (только proxies)
- **flclash** — полный FlClash YAML (proxies + proxy-groups + rules)
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
uv run vtk check vless://...                    # валидация
uv run vtk parse vless://...                     # парсинг
uv run vtk convert -l vless://... -f singbox     # конвертация
uv run vtk sub https://sub.url -f flclash        # подписка
uv run vtk batch links.txt -f mihomo             # пакетно
uv run vtk extract config.json                   # извлечь ссылки
uv run vtk settings show                         # настройки
```

### Бот

```bash
export VTK_BOT_TOKEN=xxx
uv run python -m bot.main
```

Команды: `/start`, `/help`, `/settings`, `/happkey`

### Веб

```bash
uv run python -m web.main
# http://localhost:8080
```

## Структура

```
core/      — общая бизнес-логика
  logic.py       — парсинг ссылок, загрузка подписок
  converters.py  — генерация форматов вывода
  reverse.py     — обратная конвертация (config → share links)
  settings.py    — настройки пользователя
  happ.py        — интеграция с Happy Decoder API
bot/       — Telegram bot (aiogram 3)
web/       — FastAPI + HTML + JSON API
cli/       — CLI (typer)
```

## Настройки

Хранятся в `~/.config/vtk/settings.json`. Для каждого типа входа свой формат:
`sub_format`, `link_format`, `config_format`, `txt_format`.

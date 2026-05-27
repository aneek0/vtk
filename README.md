# VLESS Toolkit (vtk)

Parse, validate, and convert proxy links & subscriptions between formats.
Three interfaces — Telegram bot, web (FastAPI), CLI — sharing one core.

## Supported protocols

- `vless://`
- `vmess://`
- `trojan://`
- `ss://` (SIP002 + legacy)
- `ssr://`
- `happ://crypt*` (auto-decrypted via [Happy Decoder API](https://happy-decoder.cc/api))

## Supported output formats

| Format | Description |
|--------|-------------|
| `singbox` | sing-box JSON config |
| `mihomo` | mihomo/clash-meta YAML proxy list |
| `flclash` | Full FlClash YAML config (with proxy-groups & rules) |
| `txt` | Plain text — one share link per line |

## Quick start

```bash
git clone <repo-url> && cd vtk
uv sync --all-extras
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `VTK_BOT_TOKEN` | Telegram bot token (for bot interface) |
| `VTK_HAPP_KEY` | Happy Decoder API key (optional, falls back to demo) |

### CLI

```bash
uv run vtk check vless://...
uv run vtk parse vless://...
uv run vtk convert --link vless://... --format singbox
uv run vtk sub https://example.com/sub --format flclash --output config.yaml
uv run vtk batch links.txt --format mihomo --output config.yaml
uv run vtk extract config.json --output links.txt
uv run vtk settings show
uv run vtk settings set sub_format flclash
```

### Bot

```bash
export VTK_BOT_TOKEN=xxx
uv run python -m bot.main
```

Commands: `/start`, `/help`, `/settings`, `/happkey`

### Web

```bash
uv run python -m web.main
# http://localhost:8080
```

## Project structure

```
core/
  __init__.py    — exports
  logic.py       — parse links, fetch subscriptions
  converters.py  — singbox / mihomo / flclash / txt output
  reverse.py     — config → share links (sing-box / mihomo)
  settings.py    — per-input-type format defaults
  happ.py        — Happy Decoder API integration
bot/             — Telegram bot (aiogram 3)
web/             — FastAPI + HTML form + JSON API
cli/             — CLI (typer)
```

## Settings

Stored in `~/.config/vtk/settings.json`. Each input type has its own default
output format: `sub_format`, `link_format`, `config_format`, `txt_format`.

# VLESS Toolkit (vtk)

Parse, validate, and convert proxy links & subscriptions between formats.
Three interfaces — Telegram bot, web (FastAPI), CLI — sharing one core.

## Supported protocols

- `vless://`
- `vmess://`
- `trojan://`
- `ss://` (SIP002 + legacy)
- `ssr://`
- `hysteria2://`
- `socks://`
- `happ://crypt*` (auto-decrypted via [Happy Decoder API](https://happy-decoder.cc/api))

## Supported output formats

| Format    | Description                                                  |
|-----------|--------------------------------------------------------------|
| `singbox` | sing-box JSON config (outbounds array)                       |
| `mihomo`  | mihomo/clash-meta YAML proxy list                            |
| `flclash` | Full FlClash YAML config (mixed-port, proxy-groups & rules)  |
| `txt`     | Plain text — one share link per line                         |

## Quick start

```bash
git clone <repo-url> && cd vtk
uv sync --all-extras
```

### Environment variables

| Variable      | Description                                                    |
|---------------|----------------------------------------------------------------|
| `VTK_BOT_TOKEN` | Telegram bot token (for bot interface)                       |
| `VTK_HAPP_KEY`  | Happy Decoder API key (optional, falls back to demo 5 req/min) |

### CLI

```bash
uv run vtk check vless://...                            # validate link
uv run vtk parse-cmd vless://...                         # parse & display fields
uv run vtk convert-cmd -l vless://... -f singbox         # convert single link
uv run vtk sub https://example.com/sub -f flclash        # fetch subscription
uv run vtk batch links.txt -f mihomo                     # batch convert file
uv run vtk extract config.json                           # config → share links
uv run vtk settings show                                 # show settings
uv run vtk settings set sub_format flclash               # change setting
```

### Bot

```bash
export VTK_BOT_TOKEN=xxx
uv run python -m bot.main
```

Commands: `/start`, `/help`, `/settings`, `/happkey`

Features:
- Auto-detects input type (link / subscription URL / config / TXT)
- Inline keyboard for per-type output format settings
- File upload support (documents processed same as text)
- Rate limiting (3 msg/sec per user)
- `happ://crypt*` auto-decryption

### Web

```bash
uv run python -m web.main
# http://localhost:8080
```

HTML form + JSON API endpoints:
- `GET /api/convert?input=...&format=singbox` — convert
- `GET /api/extract?input=...` — config → share links
- `GET /api/check?link=...` — validate single link

## Project structure

```
core/
  __init__.py    — exports
  logic.py       — parse links, fix_link(), fetch subscriptions, extract_country()
  converters.py  — singbox / mihomo / flclash / txt output
  reverse.py     — config → share links (sing-box / mihomo YAML)
  settings.py    — per-input-type format defaults
  happ.py        — Happy Decoder API integration
bot/             — Telegram bot (aiogram 3)
web/             — FastAPI + HTML form + JSON API
cli/             — CLI (typer)
```

## Core API highlights

### fix_link()
Normalizes proxy links for compatibility (e.g. podkop):
- Converts `&` → `?` at query start
- Adds `type=tcp` if missing (vless)
- Normalizes `packet-encoding=` → `packetEncoding=`

### Node round-trip
Each protocol has a `to_*_link()` method for serialization:
```python
node = parse_vless(link)
link2 = node.to_vless_link()  # round-trip
```

### Streaming parser
For large inputs, use `iter_parse_text()` (generator) instead of `parse_text_input()`.

### Country extraction
`extract_country(name)` detects country from flag emoji or text patterns in node names. Used by FlClash `group_by_country` to create per-country proxy groups.

## Settings

Stored in `~/.config/vtk/settings.json`. Each input type has its own default
output format: `sub_format`, `link_format`, `config_format`, `txt_format`.

```json
{
  "sub_format": "mihomo",
  "link_format": "singbox",
  "config_format": "txt",
  "txt_format": "mihomo",
  "tag_prefix": "",
  "timeout": 15,
  "happ_key": "",
  "group_by_country": false
}
```

## Tests

```bash
pytest tests/
```

Covers: fix_link normalization, all protocol parsers, all converters, round-trip, country extraction, error handling.

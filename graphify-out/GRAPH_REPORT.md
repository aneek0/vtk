# Graph Report - .  (2026-06-29)

## Corpus Check
- Corpus is ~16,872 words - fits in a single context window. You may not need a graph.

## Summary
- 382 nodes · 919 edges · 16 communities (14 shown, 2 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 73 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Protocol Adapters|Protocol Adapters]]
- [[_COMMUNITY_CLI & Core Logic|CLI & Core Logic]]
- [[_COMMUNITY_Telegram Bot|Telegram Bot]]
- [[_COMMUNITY_Happy Decoder API|Happy Decoder API]]
- [[_COMMUNITY_Crypt Decryption|Crypt Decryption]]
- [[_COMMUNITY_Documentation|Documentation]]
- [[_COMMUNITY_Converters & Tests|Converters & Tests]]
- [[_COMMUNITY_Link Normalization|Link Normalization]]
- [[_COMMUNITY_TXT Extraction|TXT Extraction]]
- [[_COMMUNITY_Country Extraction|Country Extraction]]
- [[_COMMUNITY_Test Fixtures|Test Fixtures]]
- [[_COMMUNITY_Package|Package]]

## God Nodes (most connected - your core abstractions)
1. `ParseError` - 62 edges
2. `Node` - 48 edges
3. `Node` - 40 edges
4. `Format` - 37 edges
5. `convert()` - 32 edges
6. `load_settings()` - 25 edges
7. `parse_vless()` - 22 edges
8. `parse_text_input()` - 20 edges
9. `from_config()` - 19 edges
10. `ProtocolAdapter` - 18 edges

## Surprising Connections (you probably didn't know these)
- `Format` --uses--> `ParseError`  [INFERRED]
  bot/main.py → core/logic.py
- `InlineKeyboardMarkup` --uses--> `ParseError`  [INFERRED]
  bot/main.py → core/logic.py
- `Message` --uses--> `ParseError`  [INFERRED]
  bot/main.py → core/logic.py
- `CallbackQuery` --uses--> `ParseError`  [INFERRED]
  bot/main.py → core/logic.py
- `Bot` --uses--> `ParseError`  [INFERRED]
  bot/main.py → core/logic.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Three Interfaces Share Core** — agents_cli, agents_bot, agents_web, agents_core_modules [EXTRACTED 1.00]

## Communities (16 total, 2 thin omitted)

### Community 0 - "Protocol Adapters"
Cohesion: 0.05
Nodes (49): ABC, _base_clash_dict(), _base_singbox_dict(), _build_proxy_groups(), _build_xray_stream(), _fill_clash_tls(), _fill_clash_transport(), _fill_singbox_tls() (+41 more)

### Community 1 - "CLI & Core Logic"
Cohesion: 0.06
Nodes (57): cmd_check(), cmd_parse(), _b64decode(), _b64encode(), _clean_name(), _get(), iter_parse_text(), Node (+49 more)

### Community 2 - "Telegram Bot"
Cohesion: 0.07
Nodes (67): Bot, cb_back(), cb_section(), cb_set_format(), cb_toggle_passthrough(), _check_rate_limit(), cmd_happkey(), cmd_help() (+59 more)

### Community 3 - "Happy Decoder API"
Cohesion: 0.06
Nodes (47): BaseModel, _builtin_decrypt(), _check_rate_limit(), decrypt_link(), decrypt_text(), fetch_sub_with_decrypt(), fetch_sub_with_decrypt_builtin(), _get_client_ip() (+39 more)

### Community 4 - "Crypt Decryption"
Cohesion: 0.10
Nodes (27): _b64_decode_urlsafe(), _block_pair_swap(), _decrypt_crypt1to4(), _decrypt_crypt5(), decrypt_link(), decrypt_text(), is_happ(), _load_crypt5_keys() (+19 more)

### Community 5 - "Documentation"
Cohesion: 0.09
Nodes (23): Telegram Bot (aiogram), CLI Interface (typer), Core Modules, extract_country() Function, fix_link() Normalization, FlClash YAML Format, Happy Decoder Integration, Hysteria2 Protocol (+15 more)

### Community 6 - "Converters & Tests"
Cohesion: 0.21
Nodes (5): convert(), Convert nodes to the specified format.      Args:         nodes: List of parsed, parse_vless(), TestConverters, TestParseVless

### Community 7 - "Link Normalization"
Cohesion: 0.24
Nodes (5): fix_link(), Normalize a proxy link to standard format.      Fixes:     - vless/trojan: adds, Clean a single query param value from junk characters., _sanitize_value(), TestFixLink

### Community 8 - "TXT Extraction"
Cohesion: 0.40
Nodes (5): cmd_extract(), Generate a list of share links (one per node)., to_txt(), api_extract(), Extract share links from a config.

### Community 9 - "Country Extraction"
Cohesion: 0.50
Nodes (3): extract_country(), Extract country from node name using emoji flags or text patterns.      Returns, TestExtractCountry

## Knowledge Gaps
- **18 isolated node(s):** `vtk`, `VLESS Protocol`, `VMess Protocol`, `Trojan Protocol`, `Shadowsocks Protocol` (+13 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ParseError` connect `CLI & Core Logic` to `Protocol Adapters`, `Telegram Bot`, `Happy Decoder API`, `Converters & Tests`, `Link Normalization`, `Country Extraction`?**
  _High betweenness centrality (0.175) - this node is a cross-community bridge._
- **Why does `_load_crypt5_keys()` connect `Crypt Decryption` to `Happy Decoder API`?**
  _High betweenness centrality (0.086) - this node is a cross-community bridge._
- **Why does `Node` connect `Protocol Adapters` to `TXT Extraction`, `CLI & Core Logic`, `Converters & Tests`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Are the 30 inferred relationships involving `ParseError` (e.g. with `Bot` and `Format`) actually correct?**
  _`ParseError` has 30 INFERRED edges - model-reasoned connections that need verification._
- **Are the 22 inferred relationships involving `Node` (e.g. with `Format` and `Hysteria2Adapter`) actually correct?**
  _`Node` has 22 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `Node` (e.g. with `Node` and `ParseError`) actually correct?**
  _`Node` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 22 inferred relationships involving `Format` (e.g. with `Bot` and `Format`) actually correct?**
  _`Format` has 22 INFERRED edges - model-reasoned connections that need verification._
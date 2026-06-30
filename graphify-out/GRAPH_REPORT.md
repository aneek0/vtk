# Graph Report - vtk  (2026-06-30)

## Corpus Check
- 21 files · ~17,158 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 398 nodes · 930 edges · 23 communities (20 shown, 3 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 72 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `62d46347`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 20|Community 20]]

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

## Communities (23 total, 3 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.06
Nodes (60): cmd_check(), cmd_parse(), _b64decode(), _b64encode(), _clean_name(), extract_country(), _fix_ss_2022_key(), _get() (+52 more)

### Community 1 - "Community 1"
Cohesion: 0.07
Nodes (70): Bot, cb_back(), cb_section(), cb_set_format(), cb_toggle_passthrough(), _check_rate_limit(), cmd_happkey(), cmd_help() (+62 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (49): BaseModel, _builtin_decrypt(), _check_rate_limit(), decrypt_link(), decrypt_text(), fetch_sub_with_decrypt(), fetch_sub_with_decrypt_builtin(), _get_client_ip() (+41 more)

### Community 3 - "Community 3"
Cohesion: 0.10
Nodes (25): _b64_decode_urlsafe(), _block_pair_swap(), _decrypt_crypt1to4(), _decrypt_crypt5(), decrypt_text(), is_happ(), _load_crypt5_keys(), _load_pkcs1_key() (+17 more)

### Community 4 - "Community 4"
Cohesion: 0.21
Nodes (5): convert(), Convert nodes to the specified format.      Args:         nodes: List of parsed, parse_vless(), TestConverters, TestParseVless

### Community 5 - "Community 5"
Cohesion: 0.11
Nodes (17): Bot, CLI, Core API highlights, Country extraction, Environment variables, Node round-trip, Node validation, Project structure (+9 more)

### Community 6 - "Community 6"
Cohesion: 0.11
Nodes (16): CLI, VLESS Toolkit (vtk), Бот, Быстрый старт, Веб, Извлечение страны, Ключевые возможности core API, Настройки (+8 more)

### Community 7 - "Community 7"
Cohesion: 0.17
Nodes (8): _base_clash_dict(), _fill_clash_tls(), Hysteria2Adapter, Node, Base dict with common Clash fields., Add TLS/reality options to a Clash proxy dict., Convert node to Clash/mihomo dict format., SSAdapter

### Community 8 - "Community 8"
Cohesion: 0.17
Nodes (14): _build_xray_stream(), get_adapter(), _json_dumps(), _json_loads(), _node_to_xray_outbound(), Converters: sing-box JSON, mihomo YAML, FlClash YAML, plain txt.  Architecture (, Register all protocol adapters., Get adapter for a protocol type. (+6 more)

### Community 9 - "Community 9"
Cohesion: 0.24
Nodes (5): fix_link(), Normalize a proxy link to standard format.      Fixes:     - vless/trojan: adds, Clean a single query param value from junk characters., _sanitize_value(), TestFixLink

### Community 10 - "Community 10"
Cohesion: 0.20
Nodes (6): ABC, ProtocolAdapter, Base adapter — each protocol implements format-specific generation., Convert node to sing-box dict format., Convert node back to share link., VLESSAdapter

### Community 11 - "Community 11"
Cohesion: 0.20
Nodes (4): _fill_clash_transport(), Add transport options to a Clash proxy dict., TrojanAdapter, VMessAdapter

### Community 12 - "Community 12"
Cohesion: 0.22
Nodes (6): _node_to_dict(), Universal node-to-dispenser: calls the right adapter for the format.      Args:, Generate a complete FlClash/mihomo config file.      Uses dict-based approach (l, Convert node to mihomo-specific dict format., SSRAdapter, to_flclash()

### Community 13 - "Community 13"
Cohesion: 0.28
Nodes (6): _base_singbox_dict(), _fill_singbox_tls(), _fill_singbox_transport(), Base dict with common sing-box fields., Add transport options to a sing-box proxy dict., Add TLS/reality options to a sing-box proxy dict.

### Community 14 - "Community 14"
Cohesion: 0.40
Nodes (5): cmd_extract(), Generate a list of share links (one per node)., to_txt(), api_extract(), Extract share links from a config.

### Community 15 - "Community 15"
Cohesion: 0.50
Nodes (4): _build_proxy_groups(), Generate mihomo YAML (proxies only by default).      Args:         nodes: parsed, Build proxy-groups for mihomo format.      Uses native YAML arrays for proxies (, to_mihomo()

## Knowledge Gaps
- **28 isolated node(s):** `vtk`, `Что это`, `Поддерживаемые протоколы`, `Форматы вывода`, `Переменные окружения` (+23 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ParseError` connect `Community 0` to `Community 1`, `Community 2`, `Community 4`, `Community 7`, `Community 8`, `Community 9`, `Community 10`, `Community 11`, `Community 12`, `Community 15`, `Community 16`?**
  _High betweenness centrality (0.165) - this node is a cross-community bridge._
- **Why does `_load_crypt5_keys()` connect `Community 3` to `Community 2`?**
  _High betweenness centrality (0.081) - this node is a cross-community bridge._
- **Why does `Node` connect `Community 7` to `Community 0`, `Community 4`, `Community 8`, `Community 10`, `Community 11`, `Community 12`, `Community 13`, `Community 14`, `Community 15`, `Community 16`?**
  _High betweenness centrality (0.075) - this node is a cross-community bridge._
- **Are the 30 inferred relationships involving `ParseError` (e.g. with `Bot` and `Format`) actually correct?**
  _`ParseError` has 30 INFERRED edges - model-reasoned connections that need verification._
- **Are the 22 inferred relationships involving `Node` (e.g. with `Format` and `Hysteria2Adapter`) actually correct?**
  _`Node` has 22 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `Node` (e.g. with `Node` and `ParseError`) actually correct?**
  _`Node` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 22 inferred relationships involving `Format` (e.g. with `Bot` and `Format`) actually correct?**
  _`Format` has 22 INFERRED edges - model-reasoned connections that need verification._
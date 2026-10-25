# Glossary

Terms used by vtk in code, docs and issues. One meaning per term.

## Share link
A `scheme://...` URI that encodes one proxy endpoint (`vless`, `vmess`,
`trojan`, `ss`, `ssr`, `hysteria2`, `socks`). Parsed into a **Node**.

## Node
`core.logic.Node` — the protocol-neutral record of one proxy endpoint: address,
port, transport, security, credentials, display name. Everything between parsing
and rendering speaks Node.

## Subscription
An HTTP(S) URL whose response is a list of share links, usually base64-wrapped.
Fetched through `core.net.fetch`; its metadata (title, traffic counters, expiry)
comes from the response headers, not the body.

## Input kind
`link` | `sub` | `config`, decided by `core.input.classify` **after**
decryption. `InputKind` selects the settings field
(`core.input.settings_key`) whose format is the default output; a link batch
(more than one parsed node) uses `txt_format` instead of `link_format`
(`core.input.default_format`).

## Format
A target config dialect: `singbox` (JSON), `mihomo` / `flclash` (YAML), `xray`,
`txt` (share links). Not the same as the input kind.

## Format registry
`core/formats.py` — one `FormatSpec` per format (label, file extension, which
input kinds may default to it) and one `Section` per settings field. Every
menu, `<select>`, download filename and "valid: …" error message reads it.

## Passthrough
`/p/<device-params>/<subscription-url>` — a proxy URL that carries a device
fingerprint and the real subscription URL. Fetching it returns the subscription
as if the chosen device had requested it.

## Device fingerprint
The header set (`User-Agent`, `X-Hwid`, `X-Device-Os`, `X-Ver-Os`,
`X-Device-Model`, `Accept-Language`) a client would send. Owned by
`core/fingerprint.py`; never re-implemented in a frontend.

## Decryptor
Offline decoder for `happ://crypt*` (RSA/AES-GCM) and `incy://crypt1`
(AES-256-GCM) wrappers, registered in `core/decryptors.py` behind one
`Decryptor` interface (`is_`, `decrypt_link`, `decrypt_text`, `supported`).
`decrypt_input` applies all of them and swallows per-link `DecryptError`s, so a
failed link is left as-is and the rest of the batch still converts. The web
`/api/<scheme>/*` routes are generated from the registry.

## Share-link codec
`core/share.py` — `render_link(node)` turns a Node back into a share link and is
the only renderer; `to_txt`, the web server list and file exports all use it.
Each renderer must stay inverse to its parser.

## fix_link
Normalization pass that makes third-party clients (podkop, Happ) accept a link:
`&`→`?`, default `type=raw`, invalid transports → `raw`, spam parameters
dropped, `packet-encoding`→`packetEncoding`. Runs on an explicit
authority/query/fragment split, so a fragment never lands inside the port.

## process_input
The single entry point (`core.logic.process_input`) that runs
decrypt → classify → fetch/parse → convert. Bots, web routes and the CLI call it
instead of assembling their own pipeline.

## render_nodes
`core.logic.render_nodes` — filter by protocol, sort, convert and shape an
already-parsed node list into the front-end result dict. `process_input` ends
here; callers that already hold nodes (the bot's protocol picker) call it
directly instead of refetching. Its result carries `parsed`, the unfiltered
nodes, for exactly that re-render.

## PendingConversion
`bot.state.PendingConversion` — a parsed batch waiting for the user to pick a
protocol. Stored in `PendingStore`, keyed by `(chat_id, message_id)` of the
message carrying the keyboard, with a TTL.

## Trust boundary
Where untrusted data enters: user input strings, subscription URLs, upstream
responses. Network policy (`core/net.py`), decryption and settings parsing sit
on it; each has exactly one implementation.

## Country
Country code (`RU`, `DE`, …) extracted from a node name by
`core.logic.extract_country` — flag emoji anywhere in the name, else text
patterns. No match → `Other`.

## Group by country
The `group_by_country` setting. When on, `convert()` sorts nodes by country
(all formats; `Other` last, stable within a country) and, for FlClash output
only, additionally builds per-country `url-test` proxy-groups.

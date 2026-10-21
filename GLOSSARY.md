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

## Input type
`link` | `sub` | `config`, decided by `_detect_input_type` **after** decryption.
It selects the default output format from settings.

## Format
A target config dialect: `singbox` (JSON), `mihomo` / `flclash` (YAML), `xray`,
`txt` (share links). Not the same as the input type.

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
(AES-256-GCM) wrappers. Failures raise `DecryptError`; a failed link is left
as-is so the rest of the batch still converts.

## fix_link
Normalization pass that makes third-party clients (podkop, Happ) accept a link:
`&`→`?`, default `type=raw`, `packet-encoding`→`packetEncoding`.

## process_input
The single entry point (`core.logic.process_input`) that runs
decrypt → detect → fetch/parse → convert. Bots, web routes and the CLI call it
instead of assembling their own pipeline.

## Trust boundary
Where untrusted data enters: user input strings, subscription URLs, upstream
responses. Network policy (`core/net.py`), decryption and settings parsing sit
on it; each has exactly one implementation.

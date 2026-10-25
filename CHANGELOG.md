# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-10-25

### Fixed
- `fix_link` no longer corrupts a link that has a fragment but no query
  (`vless://uuid@host:443#name` became `…:443&type=raw#name`, so the port parsed
  as `443&type=raw` and the whole request failed). Query handling now works on
  an explicit authority/query/fragment split.
- A malformed link can no longer abort a batch: `urllib.parse` `ValueError`s
  (e.g. out-of-range ports) are converted to `ParseError` in `parse_link`.
- Default format for a batch of links is decided by the parsed node count, not
  by matching a hardcoded prefix list — batches of `hysteria2`/`socks`/`ssr`
  links now honour `txt_format` like `vless` batches do.
- `txt` output and the web server list now emit a working share link for every
  protocol: `vmess` (base64 JSON), `ssr` (full payload) and `socks`
  (base64 userinfo) were rendered as `vmess://host:port`, `ssr://host:port`
  and `socks://<user>:<pass>@host` — or dropped entirely.
- Bot protocol picker re-renders the batch it already parsed instead of
  refetching the subscription; the callback now names no hash of the input, and
  state is keyed by the message carrying the keyboard.
- `vtk --version` reports the installed package version (was hardcoded to
  `0.1.0` since the first release).

### Changed
- Share-link rendering has one owner, `core/share.py` (`render_link`);
  `Node.to_*_link`/`to_link` and the adapters' `to_link` copies are gone.
- Input classification (`core/input.py`: `classify`, `settings_key`,
  `default_format`) and the format registry (`core/formats.py`:
  `FormatSpec`/`SECTIONS`) replace the copies that lived in the bot, CLI, web
  routes and the HTML template.
- `core/decryptors.py` owns the `happ`/`incy` decryptors behind one
  `Decryptor` interface; `/api/<scheme>/*` routes are generated from it and
  `/p/` decrypts both schemes (previously only `happ`).
- Base64 helpers moved to `core/_b64.py`.
- Web `/api/convert` GET and POST share one request builder, so both validate
  the format and reject empty input identically.


## [1.2.0] - 2026-10-24

### Added
- New output format `xray` — full Xray-core JSON client config (inbounds,
  routing with leastLoad balancer, observatory, direct/block fallbacks).
  Schema verified against Xray-core sources: `shadowsocks` protocol naming,
  `hysteria` v2 flat client config with auth in `streamSettings`, VMess user
  without `alterId`, mandatory `pingConfig` in `burstObservatory`.
- `group_by_country` now sorts nodes by country (flag emoji anywhere in the
  server name) in **all** output formats — `Other` last, stable within a
  country — in addition to per-country FlClash proxy groups. Toggle in bot
  settings, web convert form, CLI `settings`.

### Security
- TLS verification is on for every subscription fetch; `insecure_tls` setting
  is the explicit opt-out (previously `verify=False` everywhere).
- `/p/<params>/<url>` rejects non-http(s) targets and hosts resolving to
  loopback / LAN / link-local addresses on every redirect hop (SSRF guard in
  `core/net.py`); `VTK_ALLOW_PRIVATE_URLS=1` opts out for LAN subscriptions.
  `198.18.0.0/15` (sing-box/mihomo fakeip) stays allowed.
- `X-Forwarded-For` is honored only from a loopback reverse proxy, so clients
  can no longer pick their own rate-limit bucket.
- Detail keys in the web UI are HTML-escaped (stored-XSS vector).

### Fixed
- A single invalid setting no longer resets the whole settings file; settings
  are written atomically with mode 0600.
- `/p/` maps upstream HTTP errors to 502 and respects `Settings.timeout`.
- Rate limiter prunes stale entries instead of clearing all clients.
- CLI interactive mode goes through `process_input` (gains happ/incy
  decryption and identical detection behavior).

### Changed
- Decryption failures raise `core.errors.DecryptError`; unexpected decryptor
  errors are no longer swallowed.
- Removed the duplicate device-fingerprint generator from the web route and the
  stale `docs/REFACTOR_PLAN.md`; added `GLOSSARY.md` and `docs/adr/`.
- Web UI rebuilt in the Material 3 dark design language of vpn.akres.fun:
  self-hosted Unbounded / Onest / Google Sans Code fonts, hero + underlined
  tabs, docked top bar, MD3 fields, switches and buttons. The home-grown
  `<select>` dropdown is gone; native selects are styled instead.


## [1.0.0] - 2026-10-06

Stable release: feature set, packaging and CI complete; API surface
(`process_input`, parsers, converters, decryptors) considered frozen.

### Changed
- Version bump 0.2.0 → 1.0.0 (no functional changes).

## [0.2.0] - 2026-10-05

### Added
- `incy://crypt*` offline decryptor (AES-256-GCM, keymat bundled in `data/`).
- `happ://crypt5` support (RSA keymat bundled in `data/`).
- Xray JSON output format (`xray`): full client config with routing, DNS,
  inbounds and burst observatory.
- FlClash output: `group_by_country` per-country proxy groups.
- Proxy device fingerprint: User-Agent / X-Hwid / X-Device-* headers for
  subscription fetches (`core/fingerprint.py`), bot `/proxy` menu, web
  `/api/device/random`, passthrough app-links `/p/<params>/<url>`.
- Unified `process_input()` entry point shared by bot, web and CLI.
- Web: rate limiting, `/p/<params>/<url>` passthrough proxy, base64 body
  auto-detection.
- Bot: file upload handling, rate limit (3 msg/sec per user), inline settings
  keyboards.
- Infra: ruff (E/F/W/I/UP/B/SIM/RUF/C4/PERF) clean, pre-commit hook, GitHub
  Actions CI (ruff + pytest on 3.10/3.13 + pip-audit), Dependabot, CODEOWNERS.
- Packaging: setuptools wheel with bundled `data/` keymat and web
  templates/static; Docker image recipe.

### Changed
- Dependencies restructured into two optional extras: `[bot]` (aiogram) and
  `[web]` (fastapi, uvicorn, python-multipart, jinja2); core keeps
  httpx/pycryptodome/cryptography/pyyaml. `requirements.txt` removed in favor
  of `uv.lock`.
- Performance: libyaml (`CSafeDumper`) YAML output (~4x), RSA key import
  caching in the happ decryptor, module-level country tables (~4.3x overall
  on the 5k-link pipeline).
- VMess link serialization now builds JSON via a dict (fixes broken names
  with quotes/newlines).
- Web default port documented as 9000 (actual `web/main.py` behavior).

### Fixed
- `web/routes/proxy.py`: NameError on the `base64` module (broken import
  alias) — base64 subscription decoding and base64 output format 500-ed.
- `web/routes/convert.py`: dead settings call removed; device headers now
  applied in both POST and GET paths.
- Reverse conversion: unused `encryption` variable, exception chaining.

## [0.1.0] - 2026-05-27

### Added
- Initial release: vless/vmess/trojan/ss/ssr/hysteria2/socks/happ parsers,
  singbox/mihomo/flclash/txt converters, reverse conversion from sing-box
  JSON / mihomo YAML, Telegram bot, FastAPI web UI, CLI, per-input-type
  settings.

# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

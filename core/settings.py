"""Settings — default behavior per input type."""

import contextlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, fields
from pathlib import Path

from .converters import Format

logger = logging.getLogger(__name__)

DEFAULT_SETTINGS_PATH = os.path.expanduser("~/.config/vtk/settings.json")

# Fields stored as Format enum values rather than plain strings.
_FORMAT_KEYS = frozenset(
    {"sub_format", "link_format", "config_format", "txt_format", "web_default_format"}
)


@dataclass
class Settings:
    """User preferences.

    Each input type (subscription, link, config, txt) has its own default
    output format. When the bot detects the input type, it uses the
    corresponding format.
    """

    # Output format per input type
    sub_format: Format = Format.MIHOMO      # subscription URL → this format
    link_format: Format = Format.SINGBOX    # single/multi link → this format
    config_format: Format = Format.TXT      # JSON/YAML config → this format
    txt_format: Format = Format.MIHOMO      # txt file with links → this format

    # Web UI default format
    web_default_format: Format = Format.SINGBOX  # used in HTML form default selection

    # Tag prefix for generated configs
    tag_prefix: str = ""

    # Subscription fetch timeout
    timeout: int = 15

    # Skip TLS certificate verification when fetching subscriptions
    insecure_tls: bool = False

    # Sort nodes by country (all formats) + per-country FlClash proxy-groups
    group_by_country: bool = False

    # Subscription output mode
    sub_passthrough: bool = False  # return proxy URL (happy-decoder.cc/p/<url>) instead of parsed config

    # Proxy device fingerprint (for subscriptions fetched with device headers)
    proxy_headers_on: bool = False  # send device headers only when explicitly enabled
    proxy_os: str = "android"
    proxy_ua: str = ""
    proxy_ver: str = ""
    proxy_model: str = ""
    proxy_locale: str = ""
    proxy_hwid: str = ""
    proxy_hwid_on: bool = True  # include X-Hwid when proxy headers are sent


def _coerce(key: str, value):
    """Convert one stored value; raise ValueError when it cannot be used."""
    if key in _FORMAT_KEYS:
        return value if isinstance(value, Format) else Format(value)
    if key == "timeout":
        return int(value)
    return value


def load_settings(path: str = "") -> Settings:
    path = path or DEFAULT_SETTINGS_PATH
    f = Path(path)
    if not f.exists():
        return Settings()
    try:
        data = json.loads(f.read_text())
    except (OSError, json.JSONDecodeError):
        return Settings()
    if not isinstance(data, dict):
        return Settings()

    known = {field.name for field in fields(Settings)}
    values = {}
    for key, value in data.items():
        if key not in known:
            continue
        try:
            values[key] = _coerce(key, value)
        except (TypeError, ValueError):
            # One bad key must not discard the rest of the file.
            logger.warning("settings: ignoring invalid %s=%r", key, value)
    return Settings(**values)


def save_settings(settings: Settings, path: str = "") -> None:
    path = path or DEFAULT_SETTINGS_PATH
    f = Path(path)
    f.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    for field in fields(settings):
        val = getattr(settings, field.name)
        data[field.name] = val.value if isinstance(val, Format) else val

    # Write-then-rename: a crash mid-write leaves the previous file intact.
    fd, tmp = tempfile.mkstemp(dir=f.parent, prefix=".settings-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)  # contains the proxy HWID
        os.replace(tmp, f)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise

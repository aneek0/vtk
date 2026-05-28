"""Settings — default behavior per input type."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .converters import Format


DEFAULT_SETTINGS_PATH = os.path.expanduser("~/.config/vtk/settings.json")


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

    # Tag prefix for generated configs
    tag_prefix: str = ""

    # Subscription fetch timeout
    timeout: int = 15

    # Happy Decoder API key (empty = use demo key)
    happ_key: str = ""

    # Group FlClash proxy-groups by country (from node name emoji)
    group_by_country: bool = False


def load_settings(path: str = "") -> Settings:
    path = path or DEFAULT_SETTINGS_PATH
    f = Path(path)
    if not f.exists():
        return Settings()
    try:
        data = json.loads(f.read_text())
        known = {f.name for f in Settings.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        # Convert string → Format enum
        for key in ("sub_format", "link_format", "config_format", "txt_format"):
            if key in filtered and isinstance(filtered[key], str):
                filtered[key] = Format(filtered[key])
        return Settings(**filtered)
    except (json.JSONDecodeError, ValueError, KeyError):
        return Settings()


def save_settings(settings: Settings, path: str = "") -> None:
    path = path or DEFAULT_SETTINGS_PATH
    f = Path(path)
    f.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    for key in ("sub_format", "link_format", "config_format", "txt_format"):
        val = getattr(settings, key)
        data[key] = val.value if isinstance(val, Format) else val
    data["tag_prefix"] = settings.tag_prefix
    data["timeout"] = settings.timeout
    data["happ_key"] = settings.happ_key
    data["group_by_country"] = settings.group_by_country
    f.write_text(json.dumps(data, indent=2, ensure_ascii=False))

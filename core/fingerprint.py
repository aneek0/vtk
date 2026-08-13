"""Device fingerprinting for proxy subscriptions.

Single source of truth shared by the web (proxy + convert tabs) and the bot.
Mirrors the behavior previously inline in web/routes/proxy.py, plus helpers to
build/parse the `/p/<params>/<url>` app-link format and to randomize a device.

Device params (comma-separated `key=value`, first bare token = OS):
    android,ver=3.8.13,model=OnePlus Open,ua=Happ/3.26.0,locale=ja_JP,hwid=8ddcfe6b6b55
"""

import hashlib
import os
import random
import re
from urllib.parse import unquote

# Default base URL for passthrough / app-link generation. Override via env.
_ENV_PROXY_BASE = "VTK_PROXY_BASE"


# ---------------------------------------------------------------------------
# Shared random pools (one source for web + bot)
# ---------------------------------------------------------------------------

RANDOM_AGENTS = [
    "Happ/3.24.1", "Happ/3.23.0", "Happ/3.22.0", "Happ/3.21.0", "Happ/3.20.2",
    "Happ/3.19.0", "Happ/3.18.2", "Happ/3.17.0", "Happ/3.16.0", "Happ/3.15.1",
    "Happ/3.14.0", "Happ/4.0.0", "Happ/4.0.1", "Happ/4.1.0", "Happ/3.25.0",
    "Happ/3.26.0",
]

IOS_MODELS = [
    "iPhone 16 Pro Max", "iPhone 16 Pro", "iPhone 16 Plus", "iPhone 16",
    "iPhone 15 Pro Max", "iPhone 15 Pro", "iPhone 15 Plus", "iPhone 15",
    "iPhone 14 Pro Max", "iPhone 14 Pro", "iPhone 14 Plus", "iPhone 14",
    "iPhone 13 Pro Max", "iPhone 13 Pro", "iPhone 13", "iPhone SE (3rd gen)",
    "iPad Pro 13 (M4)", "iPad Pro 11 (M4)", "iPad Air (M2)",
]

ANDROID_MODELS = [
    "Pixel 9 Pro XL", "Pixel 9 Pro", "Pixel 9", "Pixel 8 Pro", "Pixel 8", "Pixel 7 Pro", "Pixel 7",
    "Samsung Galaxy S25 Ultra", "Samsung Galaxy S25+", "Samsung Galaxy S25",
    "Samsung Galaxy S24 Ultra", "Samsung Galaxy S24+", "Samsung Galaxy S24",
    "Samsung Galaxy Z Fold6", "Samsung Galaxy Z Flip6",
    "OnePlus 13", "OnePlus 12", "OnePlus Open", "OnePlus 11",
    "Xiaomi 14 Pro", "Xiaomi 14", "Xiaomi 13T Pro",
    "Nothing Phone (3)", "Nothing Phone (2a)",
    "Xperia 1 VI", "Xperia 5 V",
    "Motorola Edge 50 Ultra", "Motorola Edge 50 Pro",
    "Huawei P60 Pro", "Huawei Mate 60 Pro",
    "Asus ROG Phone 9", "Asus Zenfone 12",
    "Google Pixel Fold", "Google Pixel Tablet",
]

LOCALES = [
    "en_US", "ru_RU", "de_DE", "fr_FR", "es_ES", "pt_BR", "zh_CN", "ja_JP",
    "ko_KR", "it_IT", "tr_TR", "pl_PL", "uk_UA", "ar_SA", "nl_NL", "sv_SE",
]

_DEFAULT_UA = "Happ/3.17.0"


def _pick(seq):
    return random.choice(seq)


def parse_device_params(param_str: str) -> dict:
    """Parse `android,ver=1,model=X,ua=Y,locale=ru_RU,hwid=Z` -> dict (lowercased keys)."""
    params = {}
    for part in param_str.split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            params[k.strip().lower()] = unquote(v.strip())
        elif part:
            params["os"] = part.lower()
    return params


def generate_device_fingerprint(
    ua: str, hwid: str, os_name: str, ver: str, model: str, locale: str
) -> dict:
    """Build request headers from device params (mirrors web/routes/proxy.py)."""
    headers: dict[str, str] = {}
    headers["User-Agent"] = ua or _DEFAULT_UA
    if hwid:
        headers["X-Hwid"] = "hd-" + hashlib.md5(hwid.encode()).hexdigest()[:12]

    os_name = (os_name or "").lower()
    if os_name == "ios":
        major = ver.split(".")[0] if ver else str(_pick(["17", "18", "16", "15"]))
        headers["X-Device-Os"] = "iOS"
        headers["X-Ver-Os"] = major
        headers["X-Device-Model"] = model or _pick(IOS_MODELS)
    elif os_name == "android":
        major = ver.split(".")[0] if ver else str(_pick(["14", "13", "12", "11"]))
        headers["X-Device-Os"] = "Android"
        headers["X-Ver-Os"] = major
        headers["X-Device-Model"] = model or _pick(ANDROID_MODELS)
    else:
        headers["X-Device-Os"] = os_name or "iOS"
        headers["X-Ver-Os"] = ver or "18"
        headers["X-Device-Model"] = model or "iPhone 16"

    headers["Accept-Language"] = locale.replace("_", "-") if locale else "en-US,en;q=0.9"
    return headers


def to_params_string(params: dict) -> str:
    """Render device params dict back to `/p/` param string (OS first, then key=val)."""
    parts = []
    os_name = params.get("os", "")
    if os_name:
        parts.append(os_name)
    for key in ("ver", "model", "ua", "locale", "hwid"):
        val = params.get(key)
        if val:
            parts.append(f"{key}={val}")
    return ",".join(parts) if parts else "android"


def random_device() -> dict:
    """Generate a random device fingerprint params dict."""
    os_name = _pick(["ios", "android"])
    return {
        "os": os_name,
        "ua": _pick(RANDOM_AGENTS),
        "ver": f"{random.randint(15, 18)}.{random.randint(0, 3)}.{random.randint(0, 10)}",
        "model": _pick(IOS_MODELS if os_name == "ios" else ANDROID_MODELS),
        "locale": _pick(LOCALES),
        "hwid": hashlib.md5(str(random.random()).encode()).hexdigest()[:12],
    }


def get_proxy_base() -> str:
    """Base URL for passthrough / app-link generation (env-overridable)."""
    base = os.environ.get(_ENV_PROXY_BASE, "https://vtk.aneeko.qzz.io").strip()
    if not base:
        base = "https://vtk.aneeko.qzz.io"
    if "://" not in base:
        base = "https://" + base
    return base.rstrip("/")


def parse_app_proxy_url(full_url: str) -> dict | None:
    """Host-agnostic parse of a `/p/<params>/<http-url>` app-link.

    Returns {"target_url": str, "params": dict} or None if not an app-link.
    """
    raw = full_url.strip()
    idx = raw.find("/p/")
    if idx == -1:
        return None
    # rest = "<params>/<http-url>" (params may be empty)
    rest = raw[idx + 3:]
    match = re.search(r"(https?://)", rest)
    if not match:
        return None
    params_str = rest[:match.start()].rstrip("/")
    target_url = rest[match.start():]
    params = parse_device_params(params_str) if params_str else {}
    return {"target_url": target_url, "params": params}

import base64 as _base64
import httpx
import re
import time
from urllib.parse import unquote

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from core.fingerprint import (
    parse_device_params,
    generate_device_fingerprint,
)
from core.happ import _get_client_ip

router = APIRouter()


# ---------------------------------------------------------------------------
# Per-client rate limit: at most 1 request per second (per IP), in-memory.
# ---------------------------------------------------------------------------

_PROXY_RATE_LIMITS: dict[str, float] = {}  # ip -> last allowed monotonic time
_PROXY_MIN_INTERVAL = 1.0  # seconds between successive requests
_PROXY_RATE_MAX_ENTRIES = 4096


def _proxy_rate_limited(ip: str) -> bool:
    """Return True if the request should be rejected (rate limited).

    Enforces at most one request per ``_PROXY_MIN_INTERVAL`` seconds per IP.
    The limiter state is bounded to avoid unbounded memory growth.
    """
    now = time.monotonic()
    last = _PROXY_RATE_LIMITS.get(ip)
    if last is not None and (now - last) < _PROXY_MIN_INTERVAL:
        return True
    _PROXY_RATE_LIMITS[ip] = now
    if len(_PROXY_RATE_LIMITS) > _PROXY_RATE_MAX_ENTRIES:
        _PROXY_RATE_LIMITS.clear()
    return False


@router.get("/p/{url:path}")
async def api_proxy(
    url: str,
    request: Request,
    format: str = Query("as_is", help="Output format: as_is, json, txt, base64, mihomo"),
    hwid_off: str = Query("", help="Set to '1' to disable HWID"),
    seed_random: str = Query("", help="Set to '1' for random seed"),
):
    client_ip = _get_client_ip(request)
    if _proxy_rate_limited(client_ip):
        return JSONResponse(
            {"error": "Rate limit exceeded. Maximum 1 request per second."},
            status_code=429,
            headers={"Retry-After": "1"},
        )

    from core.happ import decrypt_text
    from core.logic import parse_subscription_text, ParseError
    from core.converters import convert, Format

    raw_path = unquote(url)
    match = re.search(r"(https?://)", raw_path)
    if not match:
        return JSONResponse(
            {"error": f"Invalid URL format: {raw_path}. Expected /p/<params>/<http-url>"},
            status_code=400,
        )
    split_pos = match.start()
    device_part = raw_path[:split_pos].rstrip("/")
    target_url = raw_path[split_pos:]

    device_params = parse_device_params(device_part) if device_part else {}
    ua = device_params.get("ua", "")
    hwid = device_params.get("hwid", "")
    os_name = device_params.get("os", "")
    ver = device_params.get("ver", "")
    model = device_params.get("model", "")
    locale = device_params.get("locale", "")

    if not target_url.startswith(("http://", "https://")):
        return JSONResponse({"error": f"Invalid subscription URL: {target_url}"}, status_code=400)

    if seed_random == "1":
        d = _random_device()
        ua = ua or d["ua"]
        hwid = hwid or d["hwid"]
        os_name = os_name or d["os"]
        ver = ver or d["ver"]
        model = model or d["model"]
        locale = locale or d["locale"]

    fingerprint = generate_device_fingerprint(ua, hwid, os_name, ver, model, locale)
    headers = {"User-Agent": fingerprint["User-Agent"]}
    if hwid_off != "1" and "X-Hwid" in fingerprint:
        headers["X-Hwid"] = fingerprint["X-Hwid"]
    headers["X-Device-Os"] = fingerprint["X-Device-Os"]
    headers["X-Ver-Os"] = fingerprint["X-Ver-Os"]
    headers["X-Device-Model"] = fingerprint["X-Device-Model"]
    headers["Accept-Language"] = fingerprint["Accept-Language"]

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            output_format = format.lower().replace("-", "_")
            resp = await client.get(target_url, headers=headers)
            resp.raise_for_status()
            content = resp.text
    except Exception as e:
        return JSONResponse({"error": f"Failed to fetch {target_url}: {e}"}, status_code=502)

    content = decrypt_text(content)

    stripped = content.strip()
    if stripped and not stripped.startswith(("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "socks://", "http://", "https://", "{", "- name:", "#")):
        try:
            decoded = base64.b64decode(stripped).decode("utf-8", errors="ignore")
            if decoded and len(decoded) > 10:
                content = decoded
        except Exception:
            pass

    if output_format == "as_is":
        return PlainTextResponse(content)

    format_map = {
        "json": Format.SINGBOX, "txt": Format.TXT, "base64": Format.TXT,
        "mihomo": Format.MIHOMO, "clash": Format.MIHOMO,
        "singbox": Format.SINGBOX, "flclash": Format.FLCLASH, "xray": Format.XRAY,
    }
    fmt = format_map.get(output_format, Format.TXT)
    try:
        nodes = parse_subscription_text(content)
        nodes = [n for n in nodes if n.protocol != "error"]
        if nodes:
            result = convert(nodes, fmt)
            if output_format == "base64":
                result = base64.b64encode(result.encode()).decode()
            return PlainTextResponse(result)
        elif output_format == "base64":
            return PlainTextResponse(base64.b64encode(content.encode()).decode())
        else:
            return JSONResponse({"error": "No valid proxy links found in subscription"}, status_code=400)
    except ParseError as e:
        return JSONResponse({"error": f"Parse error: {e}"}, status_code=400)


def _random_device() -> dict:
    import random
    import hashlib
    from core.fingerprint import RANDOM_AGENTS, IOS_MODELS, ANDROID_MODELS, LOCALES

    os_name = random.choice(["ios", "android"])
    return {
        "os": os_name,
        "ua": random.choice(RANDOM_AGENTS),
        "ver": f"{random.randint(15, 18)}.{random.randint(0, 3)}.{random.randint(0, 10)}",
        "model": random.choice(IOS_MODELS if os_name == "ios" else ANDROID_MODELS),
        "locale": random.choice(LOCALES),
        "hwid": hashlib.md5(str(random.random()).encode()).hexdigest()[:12],
    }
